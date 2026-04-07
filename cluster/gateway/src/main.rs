//! Edge Gateway binary — adapter-facing HTTP/WSS service (D3)
//!
//! Accepts evidence receipts, serves TRUSTMARK queries, bridges to NATS.
//! All adapter communication goes through this gateway.
//!
//! In `--embedded` mode, runs the Mesh Relay screener, TRUSTMARK Engine,
//! and Botawiki Service as background tokio tasks — all in one process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Extension, Router, middleware,
    routing::{get, post},
};
use clap::Parser;
use serde::Deserialize;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use aegis_gateway::auth;
use aegis_gateway::botawiki::BotawikiStore;
use aegis_gateway::mesh_routes::{self, RelayLog, RelayStats};
use aegis_gateway::nats_bridge::{NatsBridge, TrustmarkCache};
use aegis_gateway::routes;
use aegis_gateway::store::MemoryStore;
use aegis_gateway::ws::{self, GatewayWsState};
use aegis_gateway::ws::{DeadDropStore, WssConnectionRegistry};

/// Gateway configuration loaded from TOML file.
#[derive(Debug, Deserialize)]
struct GatewayConfig {
    /// Socket address to listen on (default: "0.0.0.0:8080")
    #[serde(default = "default_listen_addr")]
    listen_addr: String,

    /// NATS server URL (optional — Gateway runs without NATS for local/test)
    #[serde(default)]
    nats_url: Option<String>,

    /// Embedded mode: run Mesh Relay, TRUSTMARK Engine, and Botawiki in-process
    #[serde(default)]
    embedded: bool,

    /// Path to PromptGuard ONNX model directory (used in embedded mode for Mesh Relay Layer 2)
    #[serde(default)]
    prompt_guard_model_dir: Option<String>,

    /// OpenAI-compatible SLM server URL (used in embedded mode for Mesh Relay Layer 3)
    #[serde(default)]
    slm_server_url: Option<String>,

    /// SLM model name (used in embedded mode for Mesh Relay Layer 3)
    #[serde(default)]
    slm_model: Option<String>,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8080".to_string()
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            nats_url: None,
            embedded: false,
            prompt_guard_model_dir: None,
            slm_server_url: None,
            slm_model: None,
        }
    }
}

/// Aegis Edge Gateway
#[derive(Parser)]
#[command(
    name = "aegis-gateway",
    version,
    about = "Aegis Edge Gateway — adapter-facing HTTP/WSS service"
)]
struct Cli {
    /// Path to gateway configuration TOML file
    #[arg(short, long, default_value = "gateway_config.toml")]
    config: PathBuf,

    /// Run all cluster services in one process (Mesh Relay + TRUSTMARK Engine + Botawiki)
    #[arg(long)]
    embedded: bool,
}

/// GET /health — lightweight health check, no auth required.
async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok"
    }))
}

/// Load configuration from TOML file. Falls back to defaults if file not found.
fn load_config(path: &PathBuf) -> GatewayConfig {
    match std::fs::read_to_string(path) {
        Ok(contents) => match toml::from_str::<GatewayConfig>(&contents) {
            Ok(config) => config,
            Err(e) => {
                eprintln!(
                    "warning: failed to parse config {}: {e}, using defaults",
                    path.display()
                );
                GatewayConfig::default()
            }
        },
        Err(_) => {
            eprintln!(
                "info: config file {} not found, using defaults",
                path.display()
            );
            GatewayConfig::default()
        }
    }
}

/// Wait for SIGTERM or Ctrl-C for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for ctrl_c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received Ctrl-C, shutting down"),
        () = terminate => info!("received SIGTERM, shutting down"),
    }
}

/// Start embedded cluster services as background tokio tasks.
///
/// Spawns Mesh Relay, TRUSTMARK Engine, and Botawiki Service — all sharing
/// the same NATS connection. Returns a summary of what was started.
fn start_embedded_services(
    client: &async_nats::Client,
    config: &GatewayConfig,
) -> Vec<&'static str> {
    let mut started = Vec::new();

    // Mesh Relay screening task
    let engines = Arc::new(aegis_mesh::screening::ScreeningEngines::new(
        config
            .prompt_guard_model_dir
            .as_deref()
            .map(std::path::Path::new),
        config.slm_server_url.as_deref(),
        config.slm_model.as_deref(),
    ));
    let relay_client = client.clone();
    tokio::spawn(async move {
        aegis_mesh::relay::run_relay_processor(relay_client, engines).await;
    });
    started.push("Mesh Relay");

    // TRUSTMARK Engine task
    let trustmark_client = client.clone();
    tokio::spawn(async move {
        aegis_trustmark::cluster_scoring::run_trustmark_engine(trustmark_client).await;
    });
    started.push("TRUSTMARK Engine");

    // Botawiki Service task
    let botawiki_client = client.clone();
    tokio::spawn(async move {
        aegis_botawiki::run_botawiki_service(botawiki_client).await;
    });
    started.push("Botawiki Service");

    started
}

/// Print the embedded cluster startup banner.
fn print_embedded_banner(addr: &SocketAddr, nats_url: &str, config: &GatewayConfig) {
    let version = env!("CARGO_PKG_VERSION");

    let mut screening_layers = vec!["heuristic"];
    if config.prompt_guard_model_dir.is_some() {
        screening_layers.push("classifier");
    }
    if config.slm_server_url.is_some() {
        screening_layers.push("SLM");
    }
    let layers = screening_layers.join(" + ");

    eprintln!();
    eprintln!("Aegis Gateway v{version} — embedded cluster mode");
    eprintln!("  Gateway:          {addr} ✓");
    eprintln!("  NATS:             {nats_url} ✓");
    eprintln!("  Mesh Relay:       embedded ✓ ({layers})");
    eprintln!("  TRUSTMARK Engine: embedded ✓");
    eprintln!("  Botawiki Service: embedded ✓");
    eprintln!("Ready. Adapters connect to https://{addr}");
    eprintln!();
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_gateway=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let mut config = load_config(&cli.config);

    // CLI flag overrides config file
    if cli.embedded {
        config.embedded = true;
    }

    // Evidence store (in-memory for now; swap with PostgresStore in production)
    let evidence_store = MemoryStore::new();

    // TRUSTMARK cache (populated by NATS subscription, used by GET /trustmark)
    let trustmark_cache = Arc::new(TrustmarkCache::new());

    // Optional NATS bridge
    let nats_bridge: Option<Arc<NatsBridge>> = match &config.nats_url {
        Some(url) => match NatsBridge::connect(url).await {
            Ok(bridge) => {
                let bridge = Arc::new(bridge);
                info!("NATS bridge connected");

                // TRUSTMARK recomputation from evidence.new has been extracted to
                // the aegis-trustmark-engine service (Phase 2). The Gateway no
                // longer subscribes to evidence.new for inline recomputation.

                // Start trustmark cache subscriber (updates local cache on score changes)
                if let Err(e) = bridge.subscribe_trustmark(trustmark_cache.clone()).await {
                    tracing::warn!("failed to subscribe to trustmark.updated: {e}");
                }

                // Set up JetStream durable streams
                if let Err(e) = bridge.setup_jetstream().await {
                    tracing::warn!("JetStream setup failed: {e}, streams may not be durable");
                }

                // Embedded mode: start all cluster services in-process
                if config.embedded {
                    let started = start_embedded_services(bridge.client(), &config);
                    for svc in &started {
                        info!("embedded service started: {svc}");
                    }
                }

                Some(bridge)
            }
            Err(e) => {
                if config.embedded {
                    eprintln!(
                        "error: embedded mode requires NATS — failed to connect to {url}: {e}"
                    );
                    std::process::exit(1);
                }
                tracing::warn!("failed to connect to NATS at {url}: {e}, running without NATS");
                None
            }
        },
        None => {
            if config.embedded {
                eprintln!("error: embedded mode requires nats_url in config");
                std::process::exit(1);
            }
            info!("no nats_url configured, running without NATS");
            None
        }
    };

    // Mesh shared state
    let wss_registry = Arc::new(WssConnectionRegistry::new());
    let dead_drop_store = Arc::new(DeadDropStore::new());
    let botawiki_store = Arc::new(BotawikiStore::new());
    let relay_stats = Arc::new(RelayStats::new());
    let relay_log = Arc::new(RelayLog::new());

    // Replay MESH stream to rebuild in-memory state from NATS
    if let Some(bridge) = &nats_bridge {
        match bridge
            .replay_mesh_stream(
                botawiki_store.clone(),
                relay_log.clone(),
                dead_drop_store.clone(),
                Some(evidence_store.clone()),
                Some(trustmark_cache.clone()),
            )
            .await
        {
            Ok(count) => tracing::info!(count, "mesh state restored from NATS"),
            Err(e) => tracing::warn!("mesh replay failed: {e}"),
        }
    }

    // Subscribe to Mesh Relay delivery/quarantine notifications
    if let Some(bridge) = &nats_bridge
        && let Err(e) = bridge
            .subscribe_relay_delivery(
                wss_registry.clone(),
                dead_drop_store.clone(),
                relay_stats.clone(),
                relay_log.clone(),
                Some(Arc::clone(bridge)),
            )
            .await
    {
        tracing::warn!("failed to subscribe to relay delivery: {e}");
    }

    // Replay protection (in-memory, inline cleanup)
    let replay_protection = Arc::new(auth::ReplayProtection::new());

    // Tier-based rate limiter (in-memory token buckets per bot)
    let tier_rate_limiter = Arc::new(aegis_gateway::rate_limit::TierRateLimiter::new());

    // Authenticated routes (auth middleware applied)
    let authed_routes = Router::new()
        .route("/evidence", post(routes::post_evidence::<MemoryStore>))
        .route(
            "/evidence/batch",
            post(routes::post_evidence_batch::<MemoryStore>),
        )
        .route(
            "/trustmark/{bot_id}",
            get(routes::get_trustmark::<MemoryStore>),
        )
        .route("/mesh/send", post(routes::mesh_send::<MemoryStore>))
        .route("/botawiki/claim", post(routes::botawiki_submit_claim))
        .route("/botawiki/vote", post(routes::botawiki_vote))
        .route("/botawiki/query", get(routes::botawiki_query))
        .layer(Extension(evidence_store))
        .layer(Extension(nats_bridge))
        .layer(middleware::from_fn(auth::auth_middleware))
        .layer(Extension(replay_protection))
        .layer(Extension(tier_rate_limiter))
        .layer(Extension(trustmark_cache.clone()))
        .layer(Extension(wss_registry.clone()))
        .layer(Extension(dead_drop_store.clone()))
        .layer(Extension(botawiki_store.clone()))
        .layer(Extension(relay_stats.clone()))
        .layer(Extension(relay_log.clone()));

    // Public mesh status routes (no auth required)
    let mesh_routes = Router::new()
        .route("/mesh/status", get(mesh_routes::mesh_status))
        .route("/mesh/peers", get(mesh_routes::mesh_peers))
        .route("/mesh/peers/{bot_id}", get(mesh_routes::mesh_peer_detail))
        .route("/mesh/relay/stats", get(mesh_routes::mesh_relay_stats))
        .route("/mesh/relay/log", get(mesh_routes::mesh_relay_log))
        .route("/mesh/claims", get(mesh_routes::mesh_claims))
        .route("/mesh/dead-drops", get(mesh_routes::mesh_dead_drops))
        .route(
            "/mesh/dead-drops/{bot_id}",
            get(mesh_routes::mesh_dead_drop_detail),
        )
        .route("/botawiki/claims/all", get(mesh_routes::botawiki_list_all))
        .layer(Extension(wss_registry.clone()))
        .layer(Extension(trustmark_cache.clone()))
        .layer(Extension(relay_stats.clone()))
        .layer(Extension(relay_log))
        .layer(Extension(botawiki_store))
        .layer(Extension(dead_drop_store.clone()));

    // Clone relay_stats for WSS handler (dead-drop delivery counter)
    let relay_stats_for_ws = relay_stats;

    // CORS — allow dashboard on any origin to fetch mesh status
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // WSS route (challenge-response auth handled internally in ws.rs)
    let ws_state = Arc::new(GatewayWsState {
        wss_registry,
        dead_drop_store,
        relay_stats: relay_stats_for_ws,
        trustmark_cache,
    });
    let ws_routes = Router::new()
        .route("/ws", get(ws::ws_upgrade))
        .with_state(ws_state);

    // Public routes (no auth) merged with authenticated routes
    let app = Router::new()
        .route("/health", get(health))
        .merge(ws_routes)
        .merge(mesh_routes)
        .merge(authed_routes)
        .layer(cors);

    let addr: SocketAddr = config.listen_addr.parse().unwrap_or_else(|e| {
        eprintln!(
            "invalid listen_addr '{}': {e}, defaulting to 0.0.0.0:8080",
            config.listen_addr
        );
        "0.0.0.0:8080".parse().unwrap()
    });

    if config.embedded {
        print_embedded_banner(&addr, config.nats_url.as_deref().unwrap_or("n/a"), &config);
    } else {
        info!(
            "Aegis Gateway v{} starting on {}",
            env!("CARGO_PKG_VERSION"),
            addr
        );
    }

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    info!("gateway shut down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok() {
        let app = Router::new().route("/health", get(health));
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[test]
    fn default_config_values() {
        let config = GatewayConfig::default();
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert!(config.nats_url.is_none());
        assert!(!config.embedded);
    }

    #[test]
    fn parse_config_from_toml() {
        let toml_str = r#"listen_addr = "127.0.0.1:9090""#;
        let config: GatewayConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:9090");
        assert!(config.nats_url.is_none());
        assert!(!config.embedded);
    }

    #[test]
    fn parse_config_with_nats_url() {
        let toml_str = r#"
listen_addr = "127.0.0.1:9090"
nats_url = "nats://localhost:4222"
"#;
        let config: GatewayConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:9090");
        assert_eq!(config.nats_url.as_deref(), Some("nats://localhost:4222"));
    }

    #[test]
    fn parse_config_without_nats_url_defaults_to_none() {
        let toml_str = r#"listen_addr = "0.0.0.0:8080""#;
        let config: GatewayConfig = toml::from_str(toml_str).unwrap();
        assert!(config.nats_url.is_none());
    }

    #[test]
    fn load_missing_config_returns_defaults() {
        let path = PathBuf::from("/nonexistent/gateway_config.toml");
        let config = load_config(&path);
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert!(config.nats_url.is_none());
    }

    #[test]
    fn parse_embedded_config() {
        let toml_str = r#"
listen_addr = "127.0.0.1:9090"
nats_url = "nats://localhost:4222"
embedded = true
slm_server_url = "http://localhost:1234"
slm_model = "qwen/qwen3-30b-a3b"
"#;
        let config: GatewayConfig = toml::from_str(toml_str).unwrap();
        assert!(config.embedded);
        assert_eq!(
            config.slm_server_url.as_deref(),
            Some("http://localhost:1234")
        );
        assert_eq!(config.slm_model.as_deref(), Some("qwen/qwen3-30b-a3b"));
    }

    #[test]
    fn embedded_defaults_to_false() {
        let toml_str = r#"listen_addr = "0.0.0.0:8080""#;
        let config: GatewayConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.embedded);
    }
}
