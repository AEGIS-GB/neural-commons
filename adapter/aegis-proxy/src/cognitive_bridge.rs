//! Cognitive Bridge: tool routes the LLM can call through the proxy.
//!
//! Phase 1 tools:
//!   POST /aegis/scan    — trigger a manual security scan
//!   GET  /aegis/status  — return adapter status
//!   GET  /aegis/evidence — return recent evidence summary
//!
//! These routes are served on the proxy's listen address alongside
//! the catch-all upstream forwarding. The LLM provider can invoke
//! them as tool calls when registered via MCP or function calling.

use axum::{routing::{get, post}, Json, Router};
use serde::Serialize;

/// Build the cognitive bridge sub-router.
/// Mounted at `/aegis` by the main proxy router.
pub fn routes() -> Router<crate::proxy::AppState> {
    Router::new()
        .route("/scan", post(scan_handler))
        .route("/status", get(status_handler))
        .route("/evidence", get(evidence_handler))
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
