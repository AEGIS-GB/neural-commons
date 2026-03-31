//! Request pipeline state — tracks every step of request processing.
//!
//! A single PipelineState is created at request arrival and carries
//! the results of each screening layer. At request completion, it
//! produces both evidence receipts and traffic entries from a single
//! source of truth.

use uuid::Uuid;

/// Result of a vault scan (request or response direction).
#[derive(Debug, Clone)]
pub struct VaultStepResult {
    pub direction: String,          // "request" or "response"
    pub secrets_found: Vec<String>, // e.g., ["api_key:sk-a****xyz", "bearer:eyJ****"]
}

/// Result of the barrier check.
#[derive(Debug, Clone)]
pub struct BarrierStepResult {
    pub decision: String, // "allow", "warn", "block"
    pub reason: Option<String>,
}

/// Result of an SLM screening pass.
#[derive(Debug, Clone)]
pub struct SlmStepResult {
    pub layer: String,    // "fast" or "deep"
    pub decision: String, // "admit", "quarantine", "reject"
    pub verdict: Option<super::middleware::SlmVerdict>,
}

/// Result of DLP/PII screening on the response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DlpStepResult {
    pub redactions: u32,
    pub detail: Option<serde_json::Value>,
}

/// Final outcome of the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineOutcome {
    /// Request forwarded, response returned to agent
    Forwarded,
    /// Request blocked by barrier/SLM/vault (status code)
    Blocked(u16),
    /// Error during processing
    Error(String),
}

/// Tracks the full lifecycle of a single proxied request.
///
/// Created once at request arrival with a unique `request_id`.
/// Each screening step writes its result into the corresponding field.
/// At completion, the pipeline can produce evidence receipts and a
/// traffic entry from this single source of truth.
#[derive(Debug, Clone)]
pub struct PipelineState {
    /// Unique identifier for this request (UUID v7, time-ordered).
    /// Links TrafficEntry <-> Receipt(s) for the same HTTP request.
    pub request_id: Uuid,

    /// Unix epoch milliseconds when the request arrived.
    pub arrived_at_ms: i64,

    /// HTTP method.
    pub method: String,

    /// Request path.
    pub path: String,

    /// Source IP address.
    pub source_ip: String,

    // -- Step results (None = step not yet run) --
    /// Vault scan result (request direction).
    pub vault_request: Option<VaultStepResult>,

    /// Vault scan result (response direction).
    pub vault_response: Option<VaultStepResult>,

    /// Barrier check result.
    pub barrier: Option<BarrierStepResult>,

    /// SLM fast layer result.
    pub slm_fast: Option<SlmStepResult>,

    /// SLM deep layer result.
    pub slm_deep: Option<SlmStepResult>,

    /// Whether metaprompt hardening was injected.
    pub metaprompt_injected: bool,

    /// Whether system messages were stripped from the body.
    pub body_stripped: bool,

    /// DLP/PII screening result (response).
    pub dlp: Option<DlpStepResult>,

    /// Response status code (None if not yet received).
    pub response_status: Option<u16>,

    /// Response duration in milliseconds.
    pub response_duration_ms: Option<u64>,

    /// Final pipeline outcome.
    pub outcome: PipelineOutcome,
}

impl PipelineState {
    /// Create a new pipeline state for an incoming request.
    pub fn new(method: &str, path: &str, source_ip: &str) -> Self {
        Self {
            request_id: Uuid::now_v7(),
            arrived_at_ms: now_ms(),
            method: method.to_string(),
            path: path.to_string(),
            source_ip: source_ip.to_string(),
            vault_request: None,
            vault_response: None,
            barrier: None,
            slm_fast: None,
            slm_deep: None,
            metaprompt_injected: false,
            body_stripped: false,
            dlp: None,
            response_status: None,
            response_duration_ms: None,
            outcome: PipelineOutcome::Forwarded,
        }
    }

    /// Whether any screening step blocked the request.
    pub fn is_blocked(&self) -> bool {
        matches!(self.outcome, PipelineOutcome::Blocked(_))
    }

    /// The request_id as a string for storage.
    pub fn request_id_str(&self) -> String {
        self.request_id.to_string()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pipeline_has_unique_id() {
        let p1 = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        let p2 = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        assert_ne!(p1.request_id, p2.request_id);
    }

    #[test]
    fn new_pipeline_defaults() {
        let p = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        assert!(p.vault_request.is_none());
        assert!(p.barrier.is_none());
        assert!(p.slm_fast.is_none());
        assert!(p.slm_deep.is_none());
        assert!(p.dlp.is_none());
        assert!(!p.metaprompt_injected);
        assert!(!p.body_stripped);
        assert!(!p.is_blocked());
        assert_eq!(p.outcome, PipelineOutcome::Forwarded);
    }

    #[test]
    fn blocked_pipeline() {
        let mut p = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        p.outcome = PipelineOutcome::Blocked(403);
        assert!(p.is_blocked());
    }
}
