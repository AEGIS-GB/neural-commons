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
    /// Request body (UTF-8 text, truncated to 32KB).
    pub request_body: String,
    /// Response body (UTF-8 text, truncated to 32KB).
    pub response_body: String,
    /// Request body size in bytes (original, before truncation).
    pub request_size: usize,
    /// Response body size in bytes (original, before truncation).
    pub response_size: usize,
    /// Round-trip duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the response was streamed (SSE).
    pub is_streaming: bool,
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

    /// Record a request/response pair.
    pub fn record(
        &self,
        method: &str,
        path: &str,
        status: u16,
        req_body: &[u8],
        resp_body: &[u8],
        duration_ms: u64,
        is_streaming: bool,
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

    /// Get current entry count.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}
