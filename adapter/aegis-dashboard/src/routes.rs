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
    /// Callback returning which switchable checks are currently in observe mode (D30).
    /// Empty vec = all checks enforced = no banner needed.
    pub observe_mode_checks_fn: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
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
        .route("/api/vault", get(api_vault))
        .route("/api/access", get(api_access))
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
    /// Which switchable checks are currently in observe mode (D30).
    /// Empty vec = all checks enforced = no amber banner needed.
    observe_mode_checks: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EvidenceSummary {
    total_receipts: u64,
    chain_head_seq: u64,
    last_receipt_ms: Option<i64>,
    recent_receipts: Vec<ReceiptEntry>,
}

#[derive(Debug, Serialize)]
struct ReceiptEntry {
    seq: u64,
    ts_ms: i64,
    receipt_type: String,
    action: Option<String>,
    outcome: Option<String>,
}

#[derive(Debug, Serialize)]
struct MemoryHealth {
    tracked_files: u64,
    changes_detected: u64,
    last_scan_ms: Option<i64>,
    unacknowledged_changes: u64,
}

#[derive(Debug, Serialize)]
struct VaultSummary {
    total_secrets: u64,
    by_type: std::collections::HashMap<String, u64>,
    recent_findings: Vec<VaultFinding>,
}

#[derive(Debug, Serialize)]
struct VaultFinding {
    credential_type: String,
    masked_preview: String,
    detected_at_ms: i64,
}

#[derive(Debug, Serialize)]
struct AccessLog {
    total_requests: u64,
    entries: Vec<AccessEntry>,
}

#[derive(Debug, Serialize)]
struct AccessEntry {
    seq: u64,
    ts_ms: i64,
    method: String,
    path: String,
    status: Option<u16>,
    duration_ms: Option<u64>,
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
        observe_mode_checks: (state.observe_mode_checks_fn)(),
    })
}

/// GET /dashboard/api/evidence — recent evidence summary with individual receipts.
async fn api_evidence(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<EvidenceSummary> {
    let chain_head = state.evidence.chain_head();

    let mut last_receipt_ms = None;
    let mut recent_receipts = Vec::new();

    let start_seq = chain_head.head_seq.saturating_sub(50).max(1);
    if let Ok(receipts) = state.evidence.export(Some(start_seq), None) {
        if let Some(last) = receipts.last() {
            last_receipt_ms = Some(last.core.ts_ms);
        }
        for receipt in receipts.iter().rev() {
            recent_receipts.push(ReceiptEntry {
                seq: receipt.core.seq,
                ts_ms: receipt.core.ts_ms,
                receipt_type: format!("{:?}", receipt.core.receipt_type),
                action: receipt.context.action.clone(),
                outcome: receipt.context.outcome.clone(),
            });
        }
    }

    Json(EvidenceSummary {
        total_receipts: chain_head.receipt_count,
        chain_head_seq: chain_head.head_seq,
        last_receipt_ms,
        recent_receipts,
    })
}

/// GET /dashboard/api/memory — memory health status.
/// Queries MemoryIntegrity receipts from the evidence chain.
async fn api_memory(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<MemoryHealth> {
    let chain_head = state.evidence.chain_head();
    let mut tracked: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut changes_detected: u64 = 0;
    let mut last_scan_ms: Option<i64> = None;

    let start_seq = chain_head.head_seq.saturating_sub(200).max(1);
    if let Ok(receipts) = state.evidence.export(Some(start_seq), None) {
        for receipt in &receipts {
            if receipt.core.receipt_type != aegis_schemas::ReceiptType::MemoryIntegrity {
                continue;
            }
            if let Some(action) = &receipt.context.action {
                let path = action.replace("memory_change ", "").replace("memory_deleted ", "");
                tracked.insert(path);
            }
            changes_detected += 1;
            last_scan_ms = Some(receipt.core.ts_ms);
        }
    }

    Json(MemoryHealth {
        tracked_files: tracked.len() as u64,
        changes_detected,
        last_scan_ms,
        unacknowledged_changes: changes_detected,
    })
}

/// GET /dashboard/api/vault — vault credential summary.
///
/// Returns detected secrets (masked) from evidence chain receipts.
/// Queries the evidence chain for ApiCall receipts whose outcome
/// mentions vault credential detections.
async fn api_vault(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<VaultSummary> {
    let chain_head = state.evidence.chain_head();
    let mut by_type = std::collections::HashMap::new();
    let mut recent_findings = Vec::new();

    // Query recent receipts for vault-related entries
    let start_seq = chain_head.head_seq.saturating_sub(200).max(1);
    if let Ok(receipts) = state.evidence.export(Some(start_seq), None) {
        for receipt in &receipts {
            // Look for ApiCall receipts that contain vault detection info in outcome
            let outcome = receipt.context.outcome.as_deref().unwrap_or("");
            if outcome.contains("vault") || outcome.contains("credential") {
                if let Some(action) = &receipt.context.action {
                    // Parse credential type from action/outcome
                    let cred_type = if outcome.contains("bearer_token") {
                        "bearer_token"
                    } else if outcome.contains("api_key") {
                        "api_key"
                    } else {
                        "unknown"
                    };
                    *by_type.entry(cred_type.to_string()).or_insert(0u64) += 1;
                    if recent_findings.len() < 20 {
                        recent_findings.push(VaultFinding {
                            credential_type: cred_type.to_string(),
                            masked_preview: action.chars().take(40).collect(),
                            detected_at_ms: receipt.core.ts_ms,
                        });
                    }
                }
            }

            // Also match VaultDetection receipt type
            if receipt.core.receipt_type == aegis_schemas::ReceiptType::VaultDetection {
                let cred_type = receipt.context.action.as_deref().unwrap_or("unknown");
                *by_type.entry(cred_type.to_string()).or_insert(0u64) += 1;
                if recent_findings.len() < 20 {
                    recent_findings.push(VaultFinding {
                        credential_type: cred_type.to_string(),
                        masked_preview: receipt.context.outcome.as_deref()
                            .unwrap_or("detected").to_string(),
                        detected_at_ms: receipt.core.ts_ms,
                    });
                }
            }
        }
    }

    let total_secrets: u64 = by_type.values().sum();

    Json(VaultSummary {
        total_secrets,
        by_type,
        recent_findings,
    })
}

/// GET /dashboard/api/access — recent API call log.
///
/// Returns the last 50 API call entries from the evidence chain.
async fn api_access(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<AccessLog> {
    let chain_head = state.evidence.chain_head();
    let mut entries = Vec::new();

    // Query recent receipts for ApiCall entries
    let start_seq = chain_head.head_seq.saturating_sub(100).max(1);
    if let Ok(receipts) = state.evidence.export(Some(start_seq), None) {
        for receipt in &receipts {
            if receipt.core.receipt_type != aegis_schemas::ReceiptType::ApiCall {
                continue;
            }

            let action = receipt.context.action.as_deref().unwrap_or("");
            let outcome = receipt.context.outcome.as_deref().unwrap_or("");

            // Parse method and path from action string (e.g. "POST /v1/messages")
            let mut parts = action.splitn(2, ' ');
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();

            // Parse status and duration from outcome string
            // (e.g. "status=200 body=1024B duration=150ms")
            let status = outcome.split_whitespace()
                .find(|s| s.starts_with("status="))
                .and_then(|s| s.strip_prefix("status="))
                .and_then(|s| s.parse::<u16>().ok());

            let duration_ms = outcome.split_whitespace()
                .find(|s| s.starts_with("duration="))
                .and_then(|s| s.strip_prefix("duration="))
                .and_then(|s| s.strip_suffix("ms"))
                .and_then(|s| s.parse::<u64>().ok());

            entries.push(AccessEntry {
                seq: receipt.core.seq,
                ts_ms: receipt.core.ts_ms,
                method,
                path,
                status,
                duration_ms,
            });

            if entries.len() >= 50 {
                break;
            }
        }
    }

    // Count total ApiCall receipts
    let total_requests = entries.len() as u64;

    Json(AccessLog {
        total_requests,
        entries,
    })
}

/// GET /dashboard/api/alerts — recent critical alerts (REST fallback).
///
/// Returns the last batch of alerts as a JSON list. This is the 5s fallback
/// poll used by the JS client to catch anything missed during SSE reconnect gaps.
/// Queries the evidence chain for WriteBarrier, MemoryIntegrity, and SlmParseFailure receipts.
async fn api_alerts(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<serde_json::Value> {
    let chain_head = state.evidence.chain_head();
    let mut alerts: Vec<DashboardAlert> = Vec::new();

    let start_seq = chain_head.head_seq.saturating_sub(200).max(1);
    if let Ok(receipts) = state.evidence.export(Some(start_seq), None) {
        for receipt in receipts.iter().rev() {
            let kind = match receipt.core.receipt_type {
                aegis_schemas::ReceiptType::WriteBarrier => "structural_write",
                aegis_schemas::ReceiptType::MemoryIntegrity => "memory_injection",
                _ => continue,
            };

            let message = match (&receipt.context.action, &receipt.context.outcome) {
                (Some(action), Some(outcome)) => format!("{action} — {outcome}"),
                (Some(action), None) => action.clone(),
                (None, Some(outcome)) => outcome.clone(),
                (None, None) => "alert".to_string(),
            };

            alerts.push(DashboardAlert {
                ts_ms: receipt.core.ts_ms as u64,
                kind: kind.to_string(),
                message,
                receipt_seq: receipt.core.seq,
            });

            if alerts.len() >= 20 {
                break;
            }
        }
    }

    let total = alerts.len() as u64;
    Json(serde_json::json!({ "alerts": alerts, "total": total }))
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
