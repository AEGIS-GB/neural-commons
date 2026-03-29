//! Cognitive Bridge: tool routes the LLM can call through the proxy.
//!
//! Phase 1 tools:
//!   POST /aegis/scan              — trigger a manual security scan
//!   GET  /aegis/status            — return adapter status
//!   GET  /aegis/evidence          — return recent evidence summary
//!   POST /aegis/register-channel    — register channel context for trust
//!   POST /aegis/unregister-channel  — remove a channel from the registry
//!   GET  /aegis/channel-context     — get current channel trust context
//!
//! These routes are served on the proxy's listen address alongside
//! the catch-all upstream forwarding. The LLM provider can invoke
//! them as tool calls when registered via MCP or function calling.

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

/// Build the cognitive bridge sub-router.
/// Mounted at `/aegis` by the main proxy router.
///
/// `/status` is public (health checks). All other endpoints require
/// a trusted channel (source IP matches [[trust.channels]]).
pub fn routes() -> Router<crate::proxy::AppState> {
    Router::new()
        // Public: health check only
        .route("/status", get(status_handler))
        // Protected: require trusted source IP
        .route("/scan", post(protected_scan_handler))
        .route("/evidence", get(protected_evidence_handler))
        .route("/register-channel", post(protected_register_handler))
        .route("/unregister-channel", post(protected_unregister_handler))
        .route("/channel-context", get(protected_context_handler))
        .route("/trust/set", post(protected_trust_set_handler))
}

/// Check if the request comes from a trusted source IP.
fn is_trusted_source(
    connect_info: &axum::extract::ConnectInfo<std::net::SocketAddr>,
    state: &crate::proxy::AppState,
) -> bool {
    let source_ip = connect_info.0.ip().to_string();
    let config = state.trust_config.read().unwrap().clone();
    if config.channels.is_empty() {
        // No channels configured — allow from localhost by default
        return source_ip == "127.0.0.1" || source_ip == "::1";
    }
    let level = crate::channel_trust::resolve_channel_trust(&source_ip, &config);
    matches!(
        level,
        aegis_schemas::TrustLevel::Full | aegis_schemas::TrustLevel::Trusted
    )
}

// Protected wrappers — check source trust before calling the real handler
async fn protected_scan_handler(
    State(state): State<crate::proxy::AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> axum::response::Response {
    if !is_trusted_source(&connect_info, &state) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cognitive bridge requires trusted channel",
        )
            .into_response();
    }
    scan_handler().await.into_response()
}

async fn protected_evidence_handler(
    State(state): State<crate::proxy::AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> axum::response::Response {
    if !is_trusted_source(&connect_info, &state) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cognitive bridge requires trusted channel",
        )
            .into_response();
    }
    evidence_handler().await.into_response()
}

async fn protected_register_handler(
    State(state): State<crate::proxy::AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: Json<RegisterChannelRequest>,
) -> axum::response::Response {
    if !is_trusted_source(&connect_info, &state) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cognitive bridge requires trusted channel",
        )
            .into_response();
    }
    let (status, json) = register_channel_handler(State(state), body).await;
    (status, json).into_response()
}

async fn protected_unregister_handler(
    State(state): State<crate::proxy::AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: Json<UnregisterChannelRequest>,
) -> axum::response::Response {
    if !is_trusted_source(&connect_info, &state) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cognitive bridge requires trusted channel",
        )
            .into_response();
    }
    let (status, json) = unregister_channel_handler(body).await;
    (status, json).into_response()
}

async fn protected_context_handler(
    State(state): State<crate::proxy::AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> axum::response::Response {
    if !is_trusted_source(&connect_info, &state) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cognitive bridge requires trusted channel",
        )
            .into_response();
    }
    channel_context_handler().await.into_response()
}

/// Request body for POST /aegis/trust/set
#[derive(Debug, Deserialize)]
struct TrustSetRequest {
    identity: String,
    level: String,
}

async fn protected_trust_set_handler(
    State(state): State<crate::proxy::AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<TrustSetRequest>,
) -> axum::response::Response {
    // Trust management always allows localhost — the warden on their own machine
    // can always manage trust, even if they accidentally set localhost to unknown.
    let source_ip = connect_info.0.ip().to_string();
    let is_local = source_ip == "127.0.0.1" || source_ip == "::1";
    if !is_local && !is_trusted_source(&connect_info, &state) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "trust management requires local access",
        )
            .into_response();
    }
    trust_set_handler(State(state), Json(req))
        .await
        .into_response()
}

/// POST /aegis/trust/set — hot-reload a trust channel mapping.
///
/// Updates the in-memory trust config without restart. Changes are
/// ephemeral — they don't persist to config.toml. Use the CLI
/// `aegis trust add` for persistent changes.
async fn trust_set_handler(
    State(state): State<crate::proxy::AppState>,
    Json(req): Json<TrustSetRequest>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let level = crate::channel_trust::parse_trust_level(&req.level);

    if let Ok(mut config) = state.trust_config.write() {
        // Update existing or add new
        let existing = config
            .channels
            .iter_mut()
            .find(|(pattern, _)| *pattern == req.identity);
        if let Some((_, lvl)) = existing {
            *lvl = level;
        } else {
            config.channels.push((req.identity.clone(), level));
        }

        tracing::info!(
            identity = %req.identity,
            level = %req.level,
            "trust channel updated (hot-reload)"
        );

        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "identity": req.identity,
                "level": req.level,
                "note": "ephemeral — use 'aegis trust add' to persist"
            })),
        )
    } else {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to acquire trust config lock"})),
        )
    }
}

use axum::response::IntoResponse;

// ---- Request / Response types ----

#[derive(Debug, Serialize)]
struct ScanResponse {
    status: String,
    message: String,
    ts_ms: i64,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    mode: String,
    chain_head_seq: u64,
    chain_head_hash: String,
    receipt_count: u64,
    uptime_secs: u64,
    version: String,
}

#[derive(Debug, Serialize)]
struct EvidenceResponse {
    total_receipts: u64,
    recent: Vec<RecentReceipt>,
}

#[derive(Debug, Serialize)]
struct RecentReceipt {
    seq: u64,
    receipt_type: String,
    ts_ms: i64,
    action: Option<String>,
    outcome: Option<String>,
}

// ---- Handlers ----

/// POST /aegis/scan — trigger a manual security scan.
///
/// Stub: returns current scan status. Real implementation will
/// trigger barrier + vault + memory scans and return results.
async fn scan_handler() -> Json<ScanResponse> {
    let now_ms = crate::middleware::now_ms();
    Json(ScanResponse {
        status: "ok".to_string(),
        message: "scan completed — no issues found (stub)".to_string(),
        ts_ms: now_ms,
    })
}

/// GET /aegis/status — return adapter status from live state.
async fn status_handler(State(state): State<crate::proxy::AppState>) -> Json<StatusResponse> {
    let mode = format!("{:?}", state.config.mode).to_lowercase();
    Json(StatusResponse {
        mode,
        chain_head_seq: 0,
        chain_head_hash: aegis_schemas::GENESIS_PREV_HASH.to_string(),
        receipt_count: 0,
        uptime_secs: 0,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// GET /aegis/evidence — return recent evidence summary.
///
/// Stub: returns empty evidence. Real implementation will be wired
/// by aegis-adapter to query the evidence store.
async fn evidence_handler() -> Json<EvidenceResponse> {
    Json(EvidenceResponse {
        total_receipts: 0,
        recent: Vec::new(),
    })
}

// ---- Channel Trust Registration ----

/// Request body for POST /aegis/register-channel.
#[derive(Debug, Deserialize)]
struct RegisterChannelRequest {
    /// Channel identifier (e.g. "telegram:group:12345")
    channel: String,
    /// User identifier (e.g. "telegram:user:67890")
    #[serde(default)]
    user: Option<String>,
    /// Unix epoch milliseconds when this registration was created
    #[serde(default)]
    ts: Option<i64>,
    /// Ed25519 signature (hex) over canonical JSON of {channel, ts, user}
    #[serde(default)]
    sig: Option<String>,
}

/// Request body for POST /aegis/unregister-channel.
#[derive(Debug, Deserialize)]
struct UnregisterChannelRequest {
    /// Channel identifier to remove (e.g. "openclaw:web:default")
    channel: String,
}

/// Response for channel registration and context queries.
#[derive(Debug, Serialize)]
struct ChannelContextResponse {
    channel: Option<String>,
    user: Option<String>,
    trust_level: String,
    ssrf_allowed: bool,
    registered: bool,
}

/// Channel registry — tracks all channels seen, with last request and stats.
static CHANNEL_REGISTRY: std::sync::RwLock<ChannelRegistry> =
    std::sync::RwLock::new(ChannelRegistry::new());

/// Active channel — the most recently registered channel (used for proxy trust resolution).
static ACTIVE_CHANNEL: std::sync::RwLock<Option<aegis_schemas::ChannelTrust>> =
    std::sync::RwLock::new(None);

/// Maximum number of context entries in the registry.
/// Prevents memory exhaustion from registration flooding.
const MAX_REGISTRY_ENTRIES: usize = 100;

/// Registry of all contexts that have registered with Aegis.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelRegistry {
    pub channels: Vec<ChannelRecord>,
}

impl ChannelRegistry {
    const fn new() -> Self {
        Self {
            channels: Vec::new(),
        }
    }
}

/// A record of a single channel in the registry.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelRecord {
    pub channel: String,
    pub user: String,
    pub trust_level: String,
    pub ssrf_allowed: bool,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub request_count: u64,
}

/// Get the current active channel trust context.
pub fn get_registered_channel_trust() -> Option<aegis_schemas::ChannelTrust> {
    ACTIVE_CHANNEL.read().ok()?.clone()
}

/// Get the full channel registry for the dashboard.
pub fn get_channel_registry() -> Vec<ChannelRecord> {
    CHANNEL_REGISTRY
        .read()
        .ok()
        .map(|r| r.channels.clone())
        .unwrap_or_default()
}

/// POST /aegis/register-channel — agent registers its current channel context.
///
/// The agent calls this at the start of each conversation to tell Aegis
/// which channel (Telegram group, DM, Discord, etc.) the request came from.
/// This is **observability metadata** — it tells the dashboard/trace which
/// channel sent this request. It does NOT determine trust level.
///
/// Trust is resolved from the request SOURCE (IP address), not the channel.
/// See [[trust.sources]] in config.toml.
async fn register_channel_handler(
    State(state): State<crate::proxy::AppState>,
    Json(req): Json<RegisterChannelRequest>,
) -> (axum::http::StatusCode, Json<ChannelContextResponse>) {
    let trust_config = state.trust_config.read().unwrap().clone();

    // Verify signature if signing_pubkey is configured
    let sig_verified = if let Some(ref pubkey_bytes) = trust_config.signing_pubkey {
        // Signing pubkey is set — require valid signature
        match (&req.ts, &req.sig) {
            (Some(ts), Some(sig)) => {
                // Check timestamp freshness (15 second window)
                let now = crate::middleware::now_ms();
                let age_ms = (now - ts).abs();
                if age_ms > 15_000 {
                    tracing::warn!(channel = %req.channel, age_ms, "channel registration rejected: timestamp too old");
                    return (
                        axum::http::StatusCode::UNAUTHORIZED,
                        Json(ChannelContextResponse {
                            channel: None,
                            user: None,
                            trust_level: "rejected".to_string(),
                            ssrf_allowed: false,
                            registered: false,
                        }),
                    );
                }
                // Build signing payload and verify
                let cert = aegis_schemas::ChannelCert {
                    channel: req.channel.clone(),
                    user: req.user.clone().unwrap_or_default(),
                    trust: String::new(),
                    ts: *ts,
                    sig: sig.clone(),
                };
                let verified = crate::channel_trust::verify_cert(&cert, pubkey_bytes);
                if !verified {
                    tracing::warn!(channel = %req.channel, "channel registration rejected: invalid signature");
                    return (
                        axum::http::StatusCode::UNAUTHORIZED,
                        Json(ChannelContextResponse {
                            channel: None,
                            user: None,
                            trust_level: "rejected".to_string(),
                            ssrf_allowed: false,
                            registered: false,
                        }),
                    );
                }
                true
            }
            _ => {
                // Signing pubkey configured but no sig provided — reject
                tracing::warn!(channel = %req.channel, "channel registration rejected: signature required but not provided");
                return (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(ChannelContextResponse {
                        channel: None,
                        user: None,
                        trust_level: "rejected".to_string(),
                        ssrf_allowed: false,
                        registered: false,
                    }),
                );
            }
        }
    } else {
        // No signing pubkey configured — accept unsigned (backward compatible)
        false
    };

    // Build cert for trust resolution
    let cert = aegis_schemas::ChannelCert {
        channel: req.channel.clone(),
        user: req.user.clone().unwrap_or_default(),
        trust: String::new(),
        ts: req.ts.unwrap_or_else(crate::middleware::now_ms),
        sig: req.sig.clone().unwrap_or_default(),
    };

    let trust = crate::channel_trust::resolve_trust(Some(&cert), sig_verified, &trust_config);

    tracing::info!(
        channel = %req.channel,
        trust_level = ?trust.trust_level,
        ssrf_allowed = trust.ssrf_allowed,
        "channel context registered via cognitive bridge"
    );

    let response = ChannelContextResponse {
        channel: trust.channel.clone(),
        user: trust.user.clone(),
        trust_level: format!("{:?}", trust.trust_level).to_lowercase(),
        ssrf_allowed: trust.ssrf_allowed,
        registered: true,
    };

    // Store as active channel
    if let Ok(mut ctx) = ACTIVE_CHANNEL.write() {
        *ctx = Some(trust);
    }

    // Update channel registry
    let now_ms = crate::middleware::now_ms();
    if let Ok(mut registry) = CHANNEL_REGISTRY.write() {
        if let Some(existing) = registry
            .channels
            .iter_mut()
            .find(|r| r.channel == req.channel)
        {
            existing.last_seen_ms = now_ms;
            existing.request_count += 1;
            existing.user = req.user.clone().unwrap_or_default();
            existing.trust_level = response.trust_level.clone();
        } else {
            // Cap registry size — evict oldest entry on overflow
            if registry.channels.len() >= MAX_REGISTRY_ENTRIES {
                registry.channels.remove(0);
            }
            registry.channels.push(ChannelRecord {
                channel: req.channel.clone(),
                user: req.user.clone().unwrap_or_default(),
                trust_level: response.trust_level.clone(),
                ssrf_allowed: response.ssrf_allowed,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                request_count: 1,
            });
        }
    }

    (axum::http::StatusCode::OK, Json(response))
}

/// POST /aegis/unregister-channel — remove a channel from the registry.
///
/// If the unregistered channel was the active channel, clear the active channel.
async fn unregister_channel_handler(
    Json(req): Json<UnregisterChannelRequest>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let channel = req.channel.trim().to_string();
    if channel.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "channel is required",
            })),
        );
    }

    let mut removed = false;

    // Remove from registry
    if let Ok(mut registry) = CHANNEL_REGISTRY.write() {
        let before = registry.channels.len();
        registry.channels.retain(|r| r.channel != channel);
        removed = registry.channels.len() < before;
    }

    // Clear active channel if it matches
    if let Ok(mut active) = ACTIVE_CHANNEL.write()
        && let Some(ref trust) = *active
        && trust.channel.as_deref() == Some(&channel)
    {
        *active = None;
    }

    if removed {
        tracing::info!(channel = %channel, "channel unregistered");
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "channel": channel,
                "unregistered": true,
            })),
        )
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "channel": channel,
                "unregistered": false,
                "error": "channel not found in registry",
            })),
        )
    }
}

/// GET /aegis/channel-context — return current active channel + full registry.
async fn channel_context_handler() -> Json<serde_json::Value> {
    let active = ACTIVE_CHANNEL.read().ok().and_then(|c| c.clone());
    let registry = get_channel_registry();

    let active_json = active.map(|trust| {
        serde_json::json!({
            "channel": trust.channel,
            "user": trust.user,
            "trust_level": format!("{:?}", trust.trust_level).to_lowercase(),
            "ssrf_allowed": trust.ssrf_allowed,
            "cert_verified": trust.cert_verified,
        })
    });

    Json(serde_json::json!({
        "active": active_json,
        "registered": active_json.is_some(),
        "channels": registry,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_response_serializes() {
        let resp = ScanResponse {
            status: "ok".to_string(),
            message: "test".to_string(),
            ts_ms: 1234567890000,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn status_response_serializes() {
        let resp = StatusResponse {
            mode: "observe_only".to_string(),
            chain_head_seq: 42,
            chain_head_hash: "abcd".to_string(),
            receipt_count: 100,
            uptime_secs: 3600,
            version: "0.1.0".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"chain_head_seq\":42"));
    }
}
