//! Cognitive Bridge: tool routes the LLM can call through the proxy.
//!
//! Phase 1 tools:
//!   POST /aegis/scan              — trigger a manual security scan
//!   GET  /aegis/status            — return adapter status
//!   GET  /aegis/evidence          — return recent evidence summary
//!   POST /aegis/register-channel  — register channel context for trust
//!   GET  /aegis/channel-context   — get current channel trust context
//!
//! These routes are served on the proxy's listen address alongside
//! the catch-all upstream forwarding. The LLM provider can invoke
//! them as tool calls when registered via MCP or function calling.

use axum::{extract::State, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Build the cognitive bridge sub-router.
/// Mounted at `/aegis` by the main proxy router.
pub fn routes() -> Router<crate::proxy::AppState> {
    Router::new()
        .route("/scan", post(scan_handler))
        .route("/status", get(status_handler))
        .route("/evidence", get(evidence_handler))
        .route("/register-channel", post(register_channel_handler))
        .route("/channel-context", get(channel_context_handler))
}

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

/// GET /aegis/status — return adapter status.
///
/// Stub: returns mock status. Real implementation will be wired
/// by aegis-adapter to read from the evidence recorder.
async fn status_handler() -> Json<StatusResponse> {
    Json(StatusResponse {
        mode: "observe_only".to_string(),
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

/// Global channel context — set by register-channel, read by proxy for trust.
/// Uses a simple RwLock since registration is rare and reads are frequent.
static CHANNEL_CONTEXT: std::sync::RwLock<Option<aegis_schemas::ChannelTrust>> =
    std::sync::RwLock::new(None);

/// Get the current registered channel trust context.
/// Called by the proxy to resolve trust when no X-Aegis-Channel-Cert header is present.
pub fn get_registered_channel_trust() -> Option<aegis_schemas::ChannelTrust> {
    CHANNEL_CONTEXT.read().ok()?.clone()
}

/// POST /aegis/register-channel — agent registers its current channel context.
///
/// The agent calls this at the start of each conversation to tell Aegis
/// which channel (Telegram group, DM, Discord, etc.) the request came from.
/// Aegis resolves the trust level from its [trust] config — the agent cannot
/// claim a trust level, only report which channel it's on.
async fn register_channel_handler(
    State(state): State<crate::proxy::AppState>,
    Json(req): Json<RegisterChannelRequest>,
) -> Json<ChannelContextResponse> {
    // Resolve trust from config based on channel pattern
    let trust_config = state.trust_config.as_ref().cloned().unwrap_or_default();

    // Build a minimal cert for trust resolution
    let cert = aegis_schemas::ChannelCert {
        channel: req.channel.clone(),
        user: req.user.clone().unwrap_or_default(),
        trust: String::new(), // agent doesn't claim trust
        ts: crate::middleware::now_ms(),
        sig: String::new(),
    };

    let trust = crate::channel_trust::resolve_trust(
        Some(&cert),
        false, // not signature-verified (came via tool call)
        &trust_config,
    );

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

    // Store the context globally
    if let Ok(mut ctx) = CHANNEL_CONTEXT.write() {
        *ctx = Some(trust);
    }

    Json(response)
}

/// GET /aegis/channel-context — return current registered channel trust.
async fn channel_context_handler() -> Json<ChannelContextResponse> {
    let ctx = CHANNEL_CONTEXT.read().ok().and_then(|c| c.clone());
    match ctx {
        Some(trust) => Json(ChannelContextResponse {
            channel: trust.channel,
            user: trust.user,
            trust_level: format!("{:?}", trust.trust_level).to_lowercase(),
            ssrf_allowed: trust.ssrf_allowed,
            registered: true,
        }),
        None => Json(ChannelContextResponse {
            channel: None,
            user: None,
            trust_level: "unknown".to_string(),
            ssrf_allowed: false,
            registered: false,
        }),
    }
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
