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
    extract::{Path, State},
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Json, Router,
};
use futures::Stream;
use serde::Serialize;
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::traffic::TrafficStore;

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
    /// In-memory traffic inspector ring buffer.
    pub traffic: Arc<TrafficStore>,
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
        .route("/api/slm", get(api_slm))
        .route("/api/traffic", get(api_traffic))
        .route("/api/traffic/{id}", get(api_traffic_detail))
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
    id: String,
    ts_ms: i64,
    receipt_type: String,
    prev_hash: String,
    payload_hash: String,
    action: Option<String>,
    subject: Option<String>,
    trigger: Option<String>,
    outcome: Option<String>,
    enforcement_mode: Option<String>,
}

#[derive(Debug, Serialize)]
struct MemoryHealth {
    tracked_files: u64,
    changes_detected: u64,
    last_scan_ms: Option<i64>,
    unacknowledged_changes: u64,
    files: Vec<MemoryFileEntry>,
}

#[derive(Debug, Serialize)]
struct MemoryFileEntry {
    path: String,
    last_event: String,
    last_event_ms: i64,
    verdict: String,
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

// ── SLM response types ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct SlmOverview {
    total_screenings: u64,
    verdict_counts: VerdictCounts,
    timing_stats: TimingStats,
    recent_screenings: Vec<SlmScreeningEntry>,
}

#[derive(Debug, Serialize)]
struct VerdictCounts {
    admit: u64,
    quarantine: u64,
    reject: u64,
}

#[derive(Debug, Serialize)]
struct TimingStats {
    avg_ms: u64,
    p95_ms: u64,
    max_ms: u64,
}

#[derive(Debug, Serialize)]
struct SlmScreeningEntry {
    seq: u64,
    ts_ms: i64,
    action: String,
    threat_score: u32,
    intent: String,
    screening_ms: u64,
    engine: String,
    annotation_count: u32,
    pass_a_ms: Option<u64>,
    pass_b_ms: Option<u64>,
    classifier_ms: Option<u64>,
    confidence: Option<u32>,
    dimensions: Option<SlmDimensionsEntry>,
    screened_text: Option<String>,
    reason: Option<String>,
    explanation: Option<String>,
    annotations: Option<Vec<SlmAnnotationEntryApi>>,
    holster_profile: Option<String>,
    holster_action: Option<String>,
    threshold_exceeded: Option<bool>,
    escalated: Option<bool>,
    channel: Option<String>,
    channel_user: Option<String>,
    channel_trust_level: Option<String>,
}

#[derive(Debug, Serialize)]
struct SlmDimensionsEntry {
    injection: u32,
    manipulation: u32,
    exfiltration: u32,
    persistence: u32,
    evasion: u32,
}

#[derive(Debug, Serialize)]
struct SlmAnnotationEntryApi {
    pattern: String,
    excerpt: String,
    severity: u32,
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
                id: receipt.core.id.to_string(),
                ts_ms: receipt.core.ts_ms,
                receipt_type: format!("{:?}", receipt.core.receipt_type),
                prev_hash: receipt.core.prev_hash.clone(),
                payload_hash: receipt.core.payload_hash.clone(),
                action: receipt.context.action.clone(),
                subject: receipt.context.subject.clone(),
                trigger: receipt.context.trigger.clone(),
                outcome: receipt.context.outcome.clone(),
                enforcement_mode: receipt.context.enforcement_mode.clone(),
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
    let mut file_map: std::collections::HashMap<String, MemoryFileEntry> = std::collections::HashMap::new();
    let mut changes_detected: u64 = 0;
    let mut last_scan_ms: Option<i64> = None;

    let start_seq = chain_head.head_seq.saturating_sub(500).max(1);
    if let Ok(receipts) = state.evidence.export(Some(start_seq), None) {
        for receipt in &receipts {
            if receipt.core.receipt_type != aegis_schemas::ReceiptType::MemoryIntegrity {
                continue;
            }
            let action = receipt.context.action.as_deref().unwrap_or("");
            let outcome = receipt.context.outcome.as_deref().unwrap_or("");

            let (event_type, path) = if action.starts_with("memory_change ") {
                ("changed", action.strip_prefix("memory_change ").unwrap_or(action))
            } else if action.starts_with("memory_deleted ") {
                ("deleted", action.strip_prefix("memory_deleted ").unwrap_or(action))
            } else if action.starts_with("memory_appeared ") {
                ("appeared", action.strip_prefix("memory_appeared ").unwrap_or(action))
            } else if action.starts_with("memory_tracked ") {
                ("tracked", action.strip_prefix("memory_tracked ").unwrap_or(action))
            } else {
                ("unknown", action)
            };

            let verdict = if outcome.contains("Blocked") {
                "Blocked"
            } else if outcome.contains("Clean") {
                "Clean"
            } else if outcome.contains("deleted") {
                "Deleted"
            } else if outcome.starts_with("hash=") {
                "Tracked"
            } else {
                outcome
            };

            file_map.insert(path.to_string(), MemoryFileEntry {
                path: path.to_string(),
                last_event: event_type.to_string(),
                last_event_ms: receipt.core.ts_ms,
                verdict: verdict.to_string(),
            });

            changes_detected += 1;
            last_scan_ms = Some(receipt.core.ts_ms);
        }
    }

    let files: Vec<MemoryFileEntry> = file_map.into_values().collect();
    let tracked_files = files.len() as u64;

    Json(MemoryHealth {
        tracked_files,
        changes_detected,
        last_scan_ms,
        unacknowledged_changes: changes_detected,
        files,
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
            if receipt.core.receipt_type != aegis_schemas::ReceiptType::VaultDetection {
                continue;
            }

            let outcome = receipt.context.outcome.as_deref().unwrap_or("");
            let action = receipt.context.action.as_deref().unwrap_or("");

            // Parse credential types from outcome: "credentials detected (count=1, types=aws_key:AKIA****MPLE)"
            let types_str = outcome.split("types=").nth(1).unwrap_or("");
            // Each entry is "type:masked", comma-separated
            for entry in types_str.split(", ") {
                let mut parts = entry.splitn(2, ':');
                let cred_type = parts.next().unwrap_or("unknown").trim_end_matches(')');
                let masked = parts.next().unwrap_or("****").trim_end_matches(')');

                if cred_type.is_empty() {
                    continue;
                }

                *by_type.entry(cred_type.to_string()).or_insert(0u64) += 1;
                if recent_findings.len() < 20 {
                    recent_findings.push(VaultFinding {
                        credential_type: cred_type.to_string(),
                        masked_preview: format!("{} [{}]", masked, action),
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
                aegis_schemas::ReceiptType::SlmAnalysis => {
                    // Only include quarantine/reject as alerts
                    let action = receipt.context.detail.as_ref()
                        .and_then(|d| d.get("action"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("admit");
                    match action {
                        "quarantine" => "slm_quarantine",
                        "reject" => "slm_reject",
                        _ => continue,
                    }
                }
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

/// GET /dashboard/api/slm — SLM screening overview.
///
/// Returns screening statistics, verdict distribution, timing stats,
/// and recent screening entries from the evidence chain.
async fn api_slm(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<SlmOverview> {
    let chain_head = state.evidence.chain_head();
    let mut entries = Vec::new();
    let mut timing_values = Vec::new();
    let mut counts = VerdictCounts { admit: 0, quarantine: 0, reject: 0 };

    let start_seq = chain_head.head_seq.saturating_sub(500).max(1);
    if let Ok(receipts) = state.evidence.export(Some(start_seq), None) {
        for receipt in receipts.iter().rev() {
            if receipt.core.receipt_type != aegis_schemas::ReceiptType::SlmAnalysis {
                continue;
            }

            let detail = receipt.context.detail.as_ref();
            let action = detail
                .and_then(|d| d.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("admit")
                .to_string();
            let threat_score = detail
                .and_then(|d| d.get("threat_score"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let intent = detail
                .and_then(|d| d.get("intent"))
                .and_then(|v| v.as_str())
                .unwrap_or("benign")
                .to_string();
            let screening_ms = detail
                .and_then(|d| d.get("screening_ms"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let engine = detail
                .and_then(|d| d.get("engine"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let annotation_count = detail
                .and_then(|d| d.get("annotation_count"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            match action.as_str() {
                "admit" => counts.admit += 1,
                "quarantine" => counts.quarantine += 1,
                "reject" => counts.reject += 1,
                _ => counts.admit += 1,
            }

            timing_values.push(screening_ms);

            if entries.len() < 50 {
                let pass_a_ms = detail
                    .and_then(|d| d.get("pass_a_ms"))
                    .and_then(|v| v.as_u64());
                let pass_b_ms = detail
                    .and_then(|d| d.get("pass_b_ms"))
                    .and_then(|v| v.as_u64());
                let classifier_ms = detail
                    .and_then(|d| d.get("classifier_ms"))
                    .and_then(|v| v.as_u64());
                let confidence = detail
                    .and_then(|d| d.get("confidence"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let dimensions = detail
                    .and_then(|d| d.get("dimensions"))
                    .and_then(|d| {
                        Some(SlmDimensionsEntry {
                            injection: d.get("injection")?.as_u64()? as u32,
                            manipulation: d.get("manipulation")?.as_u64()? as u32,
                            exfiltration: d.get("exfiltration")?.as_u64()? as u32,
                            persistence: d.get("persistence")?.as_u64()? as u32,
                            evasion: d.get("evasion")?.as_u64()? as u32,
                        })
                    });
                let screened_text = detail
                    .and_then(|d| d.get("screened_text"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let reason = detail
                    .and_then(|d| d.get("reason"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let explanation = detail
                    .and_then(|d| d.get("explanation"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let annotations = detail
                    .and_then(|d| d.get("annotations"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|a| {
                                Some(SlmAnnotationEntryApi {
                                    pattern: a.get("pattern")?.as_str()?.to_string(),
                                    excerpt: a.get("excerpt")?.as_str()?.to_string(),
                                    severity: a.get("severity")?.as_u64()? as u32,
                                })
                            })
                            .collect()
                    });
                let holster_profile = detail
                    .and_then(|d| d.get("holster_profile"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let holster_action = detail
                    .and_then(|d| d.get("holster_action"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let threshold_exceeded = detail
                    .and_then(|d| d.get("threshold_exceeded"))
                    .and_then(|v| v.as_bool());
                let escalated = detail
                    .and_then(|d| d.get("escalated"))
                    .and_then(|v| v.as_bool());
                let channel = detail
                    .and_then(|d| d.get("channel"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let channel_user = detail
                    .and_then(|d| d.get("channel_user"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let channel_trust_level = detail
                    .and_then(|d| d.get("channel_trust_level"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                entries.push(SlmScreeningEntry {
                    seq: receipt.core.seq,
                    ts_ms: receipt.core.ts_ms,
                    action: action.clone(),
                    threat_score,
                    intent,
                    screening_ms,
                    engine,
                    annotation_count,
                    pass_a_ms,
                    pass_b_ms,
                    classifier_ms,
                    confidence,
                    dimensions,
                    screened_text,
                    reason,
                    explanation,
                    annotations,
                    holster_profile,
                    holster_action,
                    threshold_exceeded,
                    escalated,
                    channel,
                    channel_user,
                    channel_trust_level,
                });
            }
        }
    }

    let total = counts.admit + counts.quarantine + counts.reject;

    // Compute timing stats
    let timing_stats = if timing_values.is_empty() {
        TimingStats { avg_ms: 0, p95_ms: 0, max_ms: 0 }
    } else {
        timing_values.sort_unstable();
        let avg = timing_values.iter().sum::<u64>() / timing_values.len() as u64;
        let p95_idx = (timing_values.len() as f64 * 0.95) as usize;
        let p95 = timing_values.get(p95_idx.min(timing_values.len() - 1)).copied().unwrap_or(0);
        let max = timing_values.last().copied().unwrap_or(0);
        TimingStats { avg_ms: avg, p95_ms: p95, max_ms: max }
    };

    Json(SlmOverview {
        total_screenings: total,
        verdict_counts: counts,
        timing_stats,
        recent_screenings: entries,
    })
}

/// GET /dashboard/api/traffic — recent traffic entries (summary, no bodies).
async fn api_traffic(
    State(state): State<Arc<DashboardSharedState>>,
) -> Json<serde_json::Value> {
    let entries = state.traffic.list();
    let summary: Vec<serde_json::Value> = entries.iter().rev().map(|e| {
        serde_json::json!({
            "id": e.id,
            "ts_ms": e.ts_ms,
            "method": e.method,
            "path": e.path,
            "status": e.status,
            "request_size": e.request_size,
            "response_size": e.response_size,
            "duration_ms": e.duration_ms,
            "is_streaming": e.is_streaming,
            "slm_duration_ms": e.slm_duration_ms,
            "slm_verdict": e.slm_verdict,
            "slm_threat_score": e.slm_threat_score,
        })
    }).collect();

    Json(serde_json::json!({
        "total": entries.len(),
        "entries": summary,
    }))
}

/// GET /dashboard/api/traffic/:id — full traffic entry with bodies.
async fn api_traffic_detail(
    State(state): State<Arc<DashboardSharedState>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match state.traffic.get(id) {
        Some(entry) => {
            // Try to parse as chat messages for chat view
            let chat_messages = parse_chat_messages(&entry.request_body, &entry.response_body);
            Json(serde_json::json!({
                "entry": entry,
                "chat": chat_messages,
            }))
        }
        None => Json(serde_json::json!({"error": "not found"})),
    }
}

/// Parse OpenAI-compatible request/response into chat message list.
///
/// Supports two formats:
/// - `/v1/chat/completions`: request has `messages[]`, response has `choices[].message`
/// - `/v1/responses` (SSE): request has `input[]`, response is SSE events with
///   `response.output_text.delta` tokens and a `response.completed` event
fn parse_chat_messages(req_body: &str, resp_body: &str) -> Vec<serde_json::Value> {
    let mut messages = Vec::new();

    // Parse request messages — try "messages" (chat completions) then "input" (responses API)
    if let Ok(req) = serde_json::from_str::<serde_json::Value>(req_body) {
        let msgs = req.get("messages").and_then(|m| m.as_array())
            .or_else(|| req.get("input").and_then(|m| m.as_array()));
        if let Some(msgs) = msgs {
            for msg in msgs {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("unknown");
                let content = extract_content(msg);
                if !content.is_empty() {
                    messages.push(serde_json::json!({
                        "role": role,
                        "content": content,
                        "source": "request",
                    }));
                }
            }
        }
    }

    // Parse response — try JSON first, then SSE
    let mut got_response = false;
    if let Ok(resp) = serde_json::from_str::<serde_json::Value>(resp_body) {
        // Chat completions format: choices[].message
        if let Some(choices) = resp.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                if let Some(msg) = choice.get("message") {
                    let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("assistant");
                    let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
                    messages.push(serde_json::json!({
                        "role": role,
                        "content": content,
                        "source": "response",
                    }));
                    got_response = true;
                }
            }
        }
        // Responses API JSON format: output[].content[].text
        if !got_response {
            if let Some(text) = extract_responses_api_text(&resp) {
                if !text.is_empty() {
                    messages.push(serde_json::json!({
                        "role": "assistant",
                        "content": text,
                        "source": "response",
                    }));
                    got_response = true;
                }
            }
        }
    }

    // SSE format: parse event stream for response.completed or reassemble deltas
    if !got_response {
        if let Some(text) = parse_sse_response_text(resp_body) {
            if !text.is_empty() {
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": text,
                    "source": "response",
                }));
            }
        }
    }

    messages
}

/// Extract assistant text from a Responses API JSON object.
/// Format: `{ "output": [{ "type": "message", "content": [{ "type": "output_text", "text": "..." }] }] }`
fn extract_responses_api_text(resp: &serde_json::Value) -> Option<String> {
    let output = resp.get("output")?.as_array()?;
    let mut text = String::new();
    for item in output {
        if item.get("type").and_then(|t| t.as_str()) == Some("message") {
            if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
                for part in content {
                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                        text.push_str(t);
                    }
                }
            }
        }
    }
    if text.is_empty() { None } else { Some(text) }
}

/// Extract text content from a message object.
/// Handles both `"content": "string"` and `"content": [{"type": "text", "text": "..."}]`.
fn extract_content(msg: &serde_json::Value) -> String {
    if let Some(s) = msg.get("content").and_then(|c| c.as_str()) {
        return s.to_string();
    }
    if let Some(arr) = msg.get("content").and_then(|c| c.as_array()) {
        let parts: Vec<&str> = arr.iter()
            .filter_map(|item| {
                if item.get("type").and_then(|t| t.as_str()) == Some("text") {
                    item.get("text").and_then(|t| t.as_str())
                } else if item.get("type").and_then(|t| t.as_str()) == Some("input_text") {
                    item.get("text").and_then(|t| t.as_str())
                } else {
                    None
                }
            })
            .collect();
        if !parts.is_empty() {
            return parts.join("");
        }
    }
    String::new()
}

/// Parse SSE event stream from /v1/responses to extract the assistant's output text.
///
/// Strategy: look for `response.completed` event first (has the full text).
/// If not found (stream truncated), reassemble from `response.output_text.delta` events.
fn parse_sse_response_text(sse_body: &str) -> Option<String> {
    // First pass: look for response.completed with full output
    for line in sse_body.lines() {
        let data = match line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:")) {
            Some(d) => d,
            None => continue,
        };
        if let Ok(evt) = serde_json::from_str::<serde_json::Value>(data) {
            if evt.get("type").and_then(|t| t.as_str()) == Some("response.completed") {
                if let Some(text) = extract_responses_api_text(
                    evt.get("response").unwrap_or(&serde_json::Value::Null)
                ) {
                    return Some(text);
                }
            }
        }
    }

    // Second pass: reassemble from delta events (if response.completed was truncated)
    let mut text = String::new();
    for line in sse_body.lines() {
        let data = match line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:")) {
            Some(d) => d,
            None => continue,
        };
        if let Ok(evt) = serde_json::from_str::<serde_json::Value>(data) {
            if evt.get("type").and_then(|t| t.as_str()) == Some("response.output_text.delta") {
                if let Some(delta) = evt.get("delta").and_then(|d| d.as_str()) {
                    text.push_str(delta);
                }
            }
        }
    }

    if text.is_empty() { None } else { Some(text) }
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
