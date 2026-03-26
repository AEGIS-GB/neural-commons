//! In-memory traffic inspector — ephemeral ring buffer of recent requests.
//!
//! Stores the last 200 request/response pairs for debugging and analysis.
//! Data is never persisted to disk — it lives only in memory and is lost on restart.

use std::collections::VecDeque;
use std::sync::RwLock;
use serde::Serialize;

/// A single captured request/response pair.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficEntry {
    /// Auto-incrementing ID within this process lifetime.
    pub id: u64,
    /// Unix timestamp milliseconds.
    pub ts_ms: i64,
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Request path (e.g. /v1/chat/completions).
    pub path: String,
    /// HTTP status code of the response.
    pub status: u16,
    /// Request body (UTF-8 text, truncated to 256KB).
    pub request_body: String,
    /// Response body (UTF-8 text, truncated to 256KB).
    pub response_body: String,
    /// Request body size in bytes (original, before truncation).
    pub request_size: usize,
    /// Response body size in bytes (original, before truncation).
    pub response_size: usize,
    /// Round-trip duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the response was streamed (SSE).
    pub is_streaming: bool,
    /// SLM screening duration in milliseconds (None if SLM not run).
    pub slm_duration_ms: Option<u64>,
    /// SLM verdict: "admit", "quarantine", or "reject" (None if not run).
    pub slm_verdict: Option<String>,
    /// SLM threat score in basis points 0–10000 (None if not run).
    pub slm_threat_score: Option<u32>,
    /// Channel identifier (e.g. "telegram:direct:123", "openclaw:web:session1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Channel trust level (e.g. "full", "trusted", "unknown").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    /// LLM model used (e.g. "gpt-4o-mini").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

const MAX_BODY_CAPTURE: usize = 256 * 1024; // 256KB per body — large enough for streaming responses with tool schemas

/// In-memory ring buffer for traffic inspection.
pub struct TrafficStore {
    entries: RwLock<VecDeque<TrafficEntry>>,
    max_entries: usize,
    next_id: RwLock<u64>,
}

impl TrafficStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_entries)),
            max_entries,
            next_id: RwLock::new(1),
        }
    }

    /// Record a request/response pair with full context.
    pub fn record(
        &self,
        method: &str,
        path: &str,
        status: u16,
        req_body: &[u8],
        resp_body: &[u8],
        duration_ms: u64,
        is_streaming: bool,
        slm_duration_ms: Option<u64>,
        slm_verdict: Option<&str>,
        slm_threat_score: Option<u32>,
        channel: Option<&str>,
        trust_level: Option<&str>,
        model: Option<&str>,
    ) {
        let req_str = String::from_utf8_lossy(
            &req_body[..req_body.len().min(MAX_BODY_CAPTURE)]
        ).into_owned();
        let resp_str = String::from_utf8_lossy(
            &resp_body[..resp_body.len().min(MAX_BODY_CAPTURE)]
        ).into_owned();

        let id = {
            let mut next = self.next_id.write().unwrap();
            let id = *next;
            *next += 1;
            id
        };

        let entry = TrafficEntry {
            id,
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            method: method.to_string(),
            path: path.to_string(),
            status,
            request_body: req_str,
            response_body: resp_str,
            request_size: req_body.len(),
            response_size: resp_body.len(),
            duration_ms,
            is_streaming,
            slm_duration_ms,
            slm_verdict: slm_verdict.map(|s| s.to_string()),
            slm_threat_score,
            channel: channel.map(|s| s.to_string()),
            trust_level: trust_level.map(|s| s.to_string()),
            model: model.map(|s| s.to_string()),
        };

        let mut entries = self.entries.write().unwrap();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Get all entries (most recent last).
    pub fn list(&self) -> Vec<TrafficEntry> {
        self.entries.read().unwrap().iter().cloned().collect()
    }

    /// Get a single entry by ID.
    pub fn get(&self, id: u64) -> Option<TrafficEntry> {
        self.entries.read().unwrap().iter().find(|e| e.id == id).cloned()
    }

    /// Update the SLM verdict on an existing entry (used for deferred/async SLM on trusted channels).
    pub fn update_slm(&self, id: u64, duration_ms: u64, verdict: &str, threat_score: u32) {
        if let Ok(mut entries) = self.entries.write() {
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.slm_duration_ms = Some(duration_ms);
                entry.slm_verdict = Some(verdict.to_string());
                entry.slm_threat_score = Some(threat_score);
            }
        }
    }

    /// Get current entry count.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Get the ID of the most recently recorded entry.
    pub fn last_id(&self) -> Option<u64> {
        self.entries.read().ok()?.back().map(|e| e.id)
    }
}
