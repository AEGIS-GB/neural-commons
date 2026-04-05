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

use std::collections::VecDeque;
use std::sync::RwLock;

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
        .route("/peer/{bot_id}/trust", get(protected_peer_trust_handler))
        .route("/mesh/peers", get(protected_mesh_peers_handler))
        .route("/mesh/status", get(protected_mesh_status_handler))
        .route("/botawiki/search", get(protected_botawiki_search_handler))
        .route("/relay/inbox", get(protected_relay_inbox_handler))
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

/// Active channel — the most recently registered channel.
///
/// DEPRECATED: This global is a race condition under concurrent load.
/// Per-request trust is carried in `RequestInfo::channel_trust` and stamped
/// onto SLM verdicts by the `stamp_trust` closure in proxy.rs.
/// New code should NOT read from this global.
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
///
/// DEPRECATED: This reads from a global that races under concurrent load.
/// Use `RequestInfo::channel_trust` instead — it carries per-request context.
#[deprecated(note = "Use per-request RequestInfo::channel_trust instead")]
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

    // NOTE: Previously wrote to ACTIVE_CHANNEL here, but that global races
    // under concurrent load. Per-request trust is carried in RequestInfo::channel_trust.
    // The channel registry below is still maintained for observability (dashboard).

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

// ---- Relay Inbox ----

/// Incoming relay message for the agent to read.
#[derive(Debug, Clone, Serialize)]
pub struct RelayMessage {
    pub from: String,
    pub body: String,
    pub ts_ms: u64,
    pub read: bool,
}

/// Bounded inbox for incoming relay messages.
pub struct RelayInbox {
    messages: RwLock<VecDeque<RelayMessage>>,
    capacity: usize,
}

impl RelayInbox {
    pub fn new(capacity: usize) -> Self {
        Self {
            messages: RwLock::new(VecDeque::new()),
            capacity,
        }
    }

    pub fn push(&self, msg: RelayMessage) {
        let mut msgs = self.messages.write().unwrap();
        if msgs.len() >= self.capacity {
            msgs.pop_front();
        }
        msgs.push_back(msg);
    }

    pub fn list(&self) -> Vec<RelayMessage> {
        self.messages.read().unwrap().iter().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.messages.read().unwrap().len()
    }

    pub fn mark_all_read(&self) {
        let mut msgs = self.messages.write().unwrap();
        for msg in msgs.iter_mut() {
            msg.read = true;
        }
    }
}

// ---- Gateway proxy helper ----

/// Fetch from the Gateway API. Returns None if gateway_url is not configured or request fails.
async fn gateway_fetch(state: &crate::proxy::AppState, path: &str) -> Option<serde_json::Value> {
    let gateway_url = state.gateway_url.as_ref()?;
    let url = format!("{}{}", gateway_url, path);
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?
        .get(&url)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()
}

// ---- Protected mesh/peer/botawiki/relay handlers ----

async fn protected_peer_trust_handler(
    State(state): State<crate::proxy::AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::Path(bot_id): axum::extract::Path<String>,
) -> axum::response::Response {
    if !is_trusted_source(&connect_info, &state) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cognitive bridge requires trusted channel",
        )
            .into_response();
    }
    peer_trust_handler(State(state), axum::extract::Path(bot_id))
        .await
        .into_response()
}

async fn protected_mesh_peers_handler(
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
    mesh_peers_handler(State(state)).await.into_response()
}

async fn protected_mesh_status_handler(
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
    mesh_status_handler(State(state)).await.into_response()
}

#[derive(Debug, Deserialize)]
struct BotawikiSearchQuery {
    ns: Option<String>,
}

async fn protected_botawiki_search_handler(
    State(state): State<crate::proxy::AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    query: axum::extract::Query<BotawikiSearchQuery>,
) -> axum::response::Response {
    if !is_trusted_source(&connect_info, &state) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cognitive bridge requires trusted channel",
        )
            .into_response();
    }
    botawiki_search_handler(State(state), query)
        .await
        .into_response()
}

async fn protected_relay_inbox_handler(
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
    relay_inbox_handler(State(state)).await.into_response()
}

// ---- Actual mesh/peer/botawiki/relay handlers ----

/// GET /aegis/peer/{bot_id}/trust — proxies to Gateway /mesh/peers/{bot_id}
async fn peer_trust_handler(
    State(state): State<crate::proxy::AppState>,
    axum::extract::Path(bot_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    match gateway_fetch(&state, &format!("/mesh/peers/{bot_id}")).await {
        Some(data) if data.get("error").is_some() => {
            // Gateway returned an error (bot not in mesh) — reframe as "not in mesh"
            Json(serde_json::json!({
                "status": "not_in_mesh",
                "bot_id": bot_id,
                "message": "This bot has no Aegis mesh identity. Trust data unavailable. This does not mean the bot is untrustworthy — it means they have not joined the Aegis mesh yet.",
                "recommendation": "Proceed with caution. Evaluate based on other signals (platform reputation, message content, interaction history)."
            }))
        }
        Some(data) => Json(data),
        None => Json(serde_json::json!({
            "status": "gateway_unreachable",
            "bot_id": bot_id,
            "message": "Cannot reach the Aegis Gateway to check trust. The Gateway may be down.",
            "recommendation": "Retry later. Do not assume trust or distrust."
        })),
    }
}

/// GET /aegis/mesh/peers — proxies to Gateway /mesh/peers
async fn mesh_peers_handler(
    State(state): State<crate::proxy::AppState>,
) -> Json<serde_json::Value> {
    match gateway_fetch(&state, "/mesh/peers").await {
        Some(data) => Json(data),
        None => Json(serde_json::json!({"error": "gateway unreachable", "peers": []})),
    }
}

/// GET /aegis/mesh/status — proxies to Gateway /mesh/status
async fn mesh_status_handler(
    State(state): State<crate::proxy::AppState>,
) -> Json<serde_json::Value> {
    match gateway_fetch(&state, "/mesh/status").await {
        Some(data) => Json(data),
        None => Json(serde_json::json!({"error": "gateway unreachable"})),
    }
}

/// GET /aegis/botawiki/search?ns=... — fetches all claims and filters by namespace.
/// Uses the public /botawiki/claims/all endpoint (no auth required).
async fn botawiki_search_handler(
    State(state): State<crate::proxy::AppState>,
    axum::extract::Query(query): axum::extract::Query<BotawikiSearchQuery>,
) -> Json<serde_json::Value> {
    let ns = query.ns.unwrap_or_default();
    match gateway_fetch(&state, "/botawiki/claims/all").await {
        Some(data) => {
            // Filter claims by namespace prefix
            let claims = data
                .get("claims")
                .and_then(|c| c.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|c| {
                            ns.is_empty()
                                || c.get("namespace")
                                    .and_then(|n| n.as_str())
                                    .map(|n| n.starts_with(&ns))
                                    .unwrap_or(false)
                        })
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Json(serde_json::json!({
                "results": claims,
                "count": claims.len(),
                "namespace_filter": ns,
            }))
        }
        None => {
            Json(serde_json::json!({"error": "gateway unreachable", "results": [], "count": 0}))
        }
    }
}

/// GET /aegis/relay/inbox — return messages from the relay inbox.
async fn relay_inbox_handler(
    State(state): State<crate::proxy::AppState>,
) -> Json<serde_json::Value> {
    let messages = state.relay_inbox.list();
    let count = messages.len();
    // Mark as read after fetching
    state.relay_inbox.mark_all_read();
    Json(serde_json::json!({
        "messages": messages,
        "count": count,
    }))
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

    #[test]
    fn relay_inbox_push_and_list() {
        let inbox = RelayInbox::new(10);
        inbox.push(RelayMessage {
            from: "peer-a".to_string(),
            body: "hello".to_string(),
            ts_ms: 1000,
            read: false,
        });
        inbox.push(RelayMessage {
            from: "peer-b".to_string(),
            body: "world".to_string(),
            ts_ms: 2000,
            read: false,
        });
        inbox.push(RelayMessage {
            from: "peer-c".to_string(),
            body: "!".to_string(),
            ts_ms: 3000,
            read: false,
        });
        let msgs = inbox.list();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].from, "peer-a");
        assert_eq!(msgs[1].from, "peer-b");
        assert_eq!(msgs[2].from, "peer-c");
    }

    #[test]
    fn relay_inbox_capacity() {
        let inbox = RelayInbox::new(2);
        inbox.push(RelayMessage {
            from: "a".to_string(),
            body: "1".to_string(),
            ts_ms: 1,
            read: false,
        });
        inbox.push(RelayMessage {
            from: "b".to_string(),
            body: "2".to_string(),
            ts_ms: 2,
            read: false,
        });
        inbox.push(RelayMessage {
            from: "c".to_string(),
            body: "3".to_string(),
            ts_ms: 3,
            read: false,
        });
        let msgs = inbox.list();
        assert_eq!(msgs.len(), 2);
        // Oldest ("a") should have been evicted
        assert_eq!(msgs[0].from, "b");
        assert_eq!(msgs[1].from, "c");
    }

    #[test]
    fn relay_inbox_mark_read() {
        let inbox = RelayInbox::new(10);
        inbox.push(RelayMessage {
            from: "x".to_string(),
            body: "msg".to_string(),
            ts_ms: 100,
            read: false,
        });
        inbox.push(RelayMessage {
            from: "y".to_string(),
            body: "msg2".to_string(),
            ts_ms: 200,
            read: false,
        });
        assert!(inbox.list().iter().all(|m| !m.read));
        inbox.mark_all_read();
        assert!(inbox.list().iter().all(|m| m.read));
    }

    #[test]
    fn relay_message_serializes() {
        let msg = RelayMessage {
            from: "peer-abc".to_string(),
            body: "test payload".to_string(),
            ts_ms: 1234567890,
            read: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"from\":\"peer-abc\""));
        assert!(json.contains("\"body\":\"test payload\""));
        assert!(json.contains("\"ts_ms\":1234567890"));
        assert!(json.contains("\"read\":false"));
    }
}
