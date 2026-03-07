//! Dashboard HTTP routes
//!
//! Serves the embedded HTML dashboard and JSON API endpoints.
//! General polling: recursive setTimeout at 2s intervals (D12).
//! Emergency Alerts: SSE push via /api/alerts/stream (D12).
//!
//! Routes:
//!   GET /dashboard                    — serve the main HTML page
//!   GET /dashboard/api/status         — JSON status for polling
//!   GET /dashboard/api/evidence       — recent evidence summary
//!   GET /dashboard/api/memory         — memory health status
//!   GET /dashboard/api/alerts         — recent critical alerts (REST fallback)
//!   GET /dashboard/api/alerts/stream  — SSE stream for critical alert push

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use aegis_evidence::EvidenceRecorder;
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Json, Router,
};
use futures::Stream;
use serde::Serialize;
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

// ── Shared alert type ────────────────────────────────────────────────────────

/// A critical alert pushed to all connected dashboard SSE clients.
///
/// Produced by the write barrier (Structural writes) and SLM (parse failures).
/// Delivered via broadcast channel → SSE stream. Also queryable via REST fallback.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardAlert {
    /// Unix timestamp milliseconds when the alert was generated.
    pub ts_ms: u64,
    /// Short machine-readable kind: "structural_write" | "slm_parse_failure" | "chain_break"
    pub kind: String,
    /// Human-readable one-line description.
    pub message: String,
    /// Receipt sequence number that triggered this alert (links to Evidence tab).
    pub receipt_seq: u64,
}

// ── Shared state ─────────────────────────────────────────────────────────────

/// State shared across all dashboard route handlers.
///
/// Constructed in aegis-adapter/src/server.rs and passed to `routes()`.
/// Avoids a circular dependency: aegis-dashboard does not import aegis-adapter.
pub struct DashboardSharedState {
    /// Broadcast sender for critical alerts. SSE handler calls `.subscribe()`.
    pub alert_tx: broadcast::Sender<DashboardAlert>,
    /// Evidence recorder — provides receipt_count and chain_head_seq.
    pub evidence: Arc<EvidenceRecorder>,
    /// Callback returning the current mode string.
    /// Stored as a closure so aegis-dashboard does not depend on aegis-adapter.
    pub mode_fn: Arc<dyn Fn() -> &'static str + Send + Sync>,
    /// Adapter start time for uptime calculation.
    pub start_time: Instant,
}

// ── Router ───────────────────────────────────────────────────────────────────

/// Build the dashboard sub-router.
/// Mounted at `/dashboard` by the main proxy router.
pub fn routes(state: Arc<DashboardSharedState>) -> Router {
    Router::new()
        .route("/", get(dashboard_html))
        .route("/api/status", get(api_status))
        .route("/api/evidence", get(api_evidence))
        .route("/api/memory", get(api_memory))
        .route("/api/alerts", get(api_alerts))
        .route("/api/alerts/stream", get(api_alerts_stream))
        .with_state(state)
}

// ── Response types ────────────────────────────────────────────────────────────

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

// ── Handlers ─────────────────────────────────────────────────────────────────

/// GET /dashboard — serve the main HTML page.
async fn dashboard_html() -> axum::response::Html<&'static str> {
    axum::response::Html(super::assets::DASHBOARD_HTML)
}

/// GET /dashboard/api/status — current adapter status.
async fn api_status(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<DashboardStatus> {
    let chain_head = state.evidence.chain_head();
    Json(DashboardStatus {
        mode: (state.mode_fn)().to_string(),
        uptime_secs: state.start_time.elapsed().as_secs(),
        receipt_count: chain_head.receipt_count,
        vault_secrets: 0,
        memory_files_tracked: 0,
        health: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// GET /dashboard/api/evidence — recent evidence summary.
async fn api_evidence(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<EvidenceSummary> {
    let chain_head = state.evidence.chain_head();
    Json(EvidenceSummary {
        total_receipts: chain_head.receipt_count,
        chain_head_seq: chain_head.head_seq,
        last_receipt_ms: None,
    })
}

/// GET /dashboard/api/memory — memory health status.
/// Stub — real values wired in Phase 1b when aegis-memory is connected.
async fn api_memory(
    State(_state): State<Arc<DashboardSharedState>>,
) -> Json<MemoryHealth> {
    Json(MemoryHealth {
        tracked_files: 0,
        changes_detected: 0,
        last_scan_ms: None,
        unacknowledged_changes: 0,
    })
}

/// GET /dashboard/api/alerts — recent critical alerts (REST fallback).
///
/// Returns the last batch of alerts as a JSON list. This is the 5s fallback
/// poll used by the JS client to catch anything missed during SSE reconnect gaps.
/// Stub — real implementation queries SQLite for last 10 critical receipts.
async fn api_alerts(
    State(_state): State<Arc<DashboardSharedState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "alerts": [], "total": 0 }))
}

/// GET /dashboard/api/alerts/stream — SSE stream for critical alert push.
///
/// Server-Sent Events stream that pushes immediately when a Structural write
/// barrier fires, an SLM parse fails, or any `is_critical()` event occurs.
///
/// The browser's native `EventSource` reconnects automatically on drop.
/// A keepalive comment is sent every 15s to satisfy any TCP idle timeouts.
///
/// Why SSE here and not polling:
///   This dashboard is localhost-only (127.0.0.1). There is no proxy on the
///   loopback interface. The corporate-proxy problem that kills SSE for remote
///   servers does not exist here. See D12 in DECISIONS.md.
async fn api_alerts_stream(
    State(state): State<Arc<DashboardSharedState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.alert_tx.subscribe();
    let broadcast_stream = BroadcastStream::new(rx);

    let event_stream = broadcast_stream.filter_map(|msg| match msg {
        Ok(alert) => serde_json::to_string(&alert)
            .ok()
            .map(|json| Ok(Event::default().data(json))),
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
            // Receiver fell behind — send a gap notice so the JS fallback poll catches up.
            Some(Ok(Event::default()
                .comment(format!("lagged: missed {n} alerts, fallback poll will catch up"))))
        }
    });

    Sse::new(event_stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keepalive"),
    )
}
