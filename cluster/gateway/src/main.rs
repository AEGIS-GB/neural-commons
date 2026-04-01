//! Edge Gateway binary — adapter-facing HTTP/WSS service (D3)
//!
//! Accepts evidence receipts, serves TRUSTMARK queries, bridges to NATS.
//! All adapter communication goes through this gateway.

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::{Router, middleware, routing::get};
use clap::Parser;
use serde::Deserialize;
use tokio::signal;
use tracing::info;

use aegis_gateway::auth;

/// Gateway configuration loaded from TOML file.
#[derive(Debug, Deserialize)]
struct GatewayConfig {
    /// Socket address to listen on (default: "0.0.0.0:8080")
    #[serde(default = "default_listen_addr")]
    listen_addr: String,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8080".to_string()
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_gateway=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = load_config(&cli.config);

    // Authenticated routes (auth middleware applied)
    let authed_routes = Router::new()
        // Future: POST /evidence, POST /evidence/batch, GET /trustmark/:bot_id
        .layer(middleware::from_fn(auth::auth_middleware));

    // Public routes (no auth) merged with authenticated routes
    let app = Router::new()
        .route("/health", get(health))
        .merge(authed_routes);

    let addr: SocketAddr = config.listen_addr.parse().unwrap_or_else(|e| {
        eprintln!(
            "invalid listen_addr '{}': {e}, defaulting to 0.0.0.0:8080",
            config.listen_addr
        );
        "0.0.0.0:8080".parse().unwrap()
    });

    info!(
        "Aegis Gateway v{} starting on {}",
        env!("CARGO_PKG_VERSION"),
        addr
    );

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
    }

    #[test]
    fn parse_config_from_toml() {
        let toml_str = r#"listen_addr = "127.0.0.1:9090""#;
        let config: GatewayConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:9090");
    }

    #[test]
    fn load_missing_config_returns_defaults() {
        let path = PathBuf::from("/nonexistent/gateway_config.toml");
        let config = load_config(&path);
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
    }
}
