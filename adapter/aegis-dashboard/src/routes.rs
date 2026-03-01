//! Dashboard HTTP routes
//!
//! Serves the embedded HTML dashboard and JSON API endpoints.
//! Polling-based refresh at 2s intervals (D12).
//!
//! Routes:
//!   GET /dashboard       — serve the main HTML page
//!   GET /dashboard/api/status  — JSON status for polling
//!   GET /dashboard/api/evidence — recent evidence summary
//!   GET /dashboard/api/memory  — memory health status

use axum::{routing::get, Json, Router};
use serde::Serialize;

/// Build the dashboard sub-router.
/// Mounted at `/dashboard` by the main proxy router.
pub fn routes() -> Router {
    Router::new()
        .route("/", get(dashboard_html))
        .route("/api/status", get(api_status))
        .route("/api/evidence", get(api_evidence))
        .route("/api/memory", get(api_memory))
}

// ---- Response types ----

#[derive(Debug, Serialize)]
struct DashboardStatus {
    mode: String,
    uptime_secs: u64,
    receipt_count: u64,
    vault_secrets: u64,
    memory_files_tracked: u64,
    health: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct EvidenceSummary {
    total_receipts: u64,
    chain_head_seq: u64,
    last_receipt_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
struct MemoryHealth {
    tracked_files: u64,
    changes_detected: u64,
    last_scan_ms: Option<i64>,
    unacknowledged_changes: u64,
}

// ---- Handlers ----

/// GET /dashboard — serve the main HTML page.
/// The full HTML is embedded via `assets` module.
async fn dashboard_html() -> axum::response::Html<&'static str> {
    axum::response::Html(super::assets::DASHBOARD_HTML)
}

/// GET /dashboard/api/status — current adapter status.
async fn api_status() -> Json<DashboardStatus> {
    // Stub: real implementation wired by aegis-adapter
    Json(DashboardStatus {
        mode: "observe_only".to_string(),
        uptime_secs: 0,
        receipt_count: 0,
        vault_secrets: 0,
        memory_files_tracked: 0,
        health: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// GET /dashboard/api/evidence — recent evidence summary.
async fn api_evidence() -> Json<EvidenceSummary> {
    Json(EvidenceSummary {
        total_receipts: 0,
        chain_head_seq: 0,
        last_receipt_ms: None,
    })
}

/// GET /dashboard/api/memory — memory health status.
async fn api_memory() -> Json<MemoryHealth> {
    Json(MemoryHealth {
        tracked_files: 0,
        changes_detected: 0,
        last_scan_ms: None,
        unacknowledged_changes: 0,
    })
}
