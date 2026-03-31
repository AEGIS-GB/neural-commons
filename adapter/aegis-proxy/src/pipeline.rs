//! Request pipeline state — tracks every step of request processing.
//!
//! A single PipelineState is created at request arrival and carries
//! the results of each screening layer. At request completion, it
//! produces both evidence receipts and traffic entries from a single
//! source of truth.

use uuid::Uuid;

/// A receipt to be recorded from pipeline results.
#[derive(Debug, Clone)]
pub struct PipelineReceipt {
    pub receipt_type: String, // "api_call", "vault_detection", "write_barrier", "slm_analysis"
    pub action: String,
    pub outcome: String,
    pub detail: Option<serde_json::Value>,
}

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

    /// Produce all evidence receipts from the pipeline's collected results.
    ///
    /// Called once at request completion. Returns receipts in chronological order.
    pub fn to_receipts(
        &self,
        body_hash: &str,
        body_size: usize,
        resp_status: Option<u16>,
        resp_body_size: Option<usize>,
        resp_duration_ms: Option<u64>,
    ) -> Vec<PipelineReceipt> {
        let mut receipts = Vec::new();

        // 1. Vault detection (request)
        if let Some(ref vault) = self.vault_request
            && !vault.secrets_found.is_empty()
        {
            receipts.push(PipelineReceipt {
                receipt_type: "vault_detection".to_string(),
                action: format!("vault_request {}", self.path),
                outcome: format!(
                    "credentials detected (count={}, types={})",
                    vault.secrets_found.len(),
                    vault.secrets_found.join(", ")
                ),
                detail: None,
            });
        }

        // 2. API call (request direction) — always
        receipts.push(PipelineReceipt {
            receipt_type: "api_call".to_string(),
            action: format!("{} {}", self.method, self.path),
            outcome: format!(
                "intercepted (body={}B hash={})",
                body_size,
                &body_hash[..16.min(body_hash.len())]
            ),
            detail: None,
        });

        // 3. Barrier check
        if let Some(ref barrier) = self.barrier
            && barrier.decision != "allow"
        {
            receipts.push(PipelineReceipt {
                receipt_type: "write_barrier".to_string(),
                action: format!("{} {}", self.method, self.path),
                outcome: barrier
                    .reason
                    .clone()
                    .unwrap_or_else(|| barrier.decision.clone()),
                detail: None,
            });
        }

        // 4. SLM fast layer
        if let Some(ref slm) = self.slm_fast {
            receipts.push(PipelineReceipt {
                receipt_type: "slm_analysis".to_string(),
                action: format!(
                    "slm_screen {}",
                    slm.verdict
                        .as_ref()
                        .map(|v| v.engine.as_str())
                        .unwrap_or("unknown")
                ),
                outcome: format!(
                    "action={} threat_score={} intent={}",
                    slm.decision,
                    slm.verdict.as_ref().map(|v| v.threat_score).unwrap_or(0),
                    slm.verdict
                        .as_ref()
                        .map(|v| v.intent.as_str())
                        .unwrap_or("unknown")
                ),
                detail: slm
                    .verdict
                    .as_ref()
                    .and_then(|v| serde_json::to_value(v).ok()),
            });
        }

        // 5. SLM deep layer
        if let Some(ref slm) = self.slm_deep {
            receipts.push(PipelineReceipt {
                receipt_type: "slm_analysis".to_string(),
                action: format!(
                    "slm_screen {}",
                    slm.verdict
                        .as_ref()
                        .map(|v| v.engine.as_str())
                        .unwrap_or("unknown")
                ),
                outcome: format!(
                    "action={} threat_score={} intent={}",
                    slm.decision,
                    slm.verdict.as_ref().map(|v| v.threat_score).unwrap_or(0),
                    slm.verdict
                        .as_ref()
                        .map(|v| v.intent.as_str())
                        .unwrap_or("unknown")
                ),
                detail: slm
                    .verdict
                    .as_ref()
                    .and_then(|v| serde_json::to_value(v).ok()),
            });
        }

        // 6. API call (response direction)
        if let Some(status) = resp_status {
            receipts.push(PipelineReceipt {
                receipt_type: "api_call".to_string(),
                action: format!("response {} {}", self.method, self.path),
                outcome: format!(
                    "status={} body={}B duration={}ms",
                    status,
                    resp_body_size.unwrap_or(0),
                    resp_duration_ms.unwrap_or(0)
                ),
                detail: None,
            });
        }

        // 7. Vault detection (response)
        if let Some(ref vault) = self.vault_response
            && !vault.secrets_found.is_empty()
        {
            receipts.push(PipelineReceipt {
                receipt_type: "vault_detection".to_string(),
                action: format!("vault_response {}", self.path),
                outcome: format!(
                    "credentials detected (count={}, types={})",
                    vault.secrets_found.len(),
                    vault.secrets_found.join(", ")
                ),
                detail: None,
            });
        }

        receipts
    }
}

/// Fields extracted from the pipeline for traffic recording.
/// Maps directly to TrafficEntry fields without depending on aegis-dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficFields {
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub source_ip: String,
    pub slm_verdict: Option<String>,
    pub slm_threat_score: Option<u32>,
    pub slm_duration_ms: Option<u64>,
    pub slm_detail: Option<serde_json::Value>,
    pub channel: Option<String>,
    pub trust_level: Option<String>,
    pub response_screen: Option<serde_json::Value>,
}

impl PipelineState {
    /// Extract traffic recording fields from the pipeline.
    /// Called when recording to the dashboard traffic store.
    pub fn to_traffic_fields(&self, channel_trust: &aegis_schemas::ChannelTrust) -> TrafficFields {
        // Pick the most relevant SLM verdict (deep overrides fast)
        let slm = self.slm_deep.as_ref().or(self.slm_fast.as_ref());

        TrafficFields {
            request_id: self.request_id_str(),
            method: self.method.clone(),
            path: self.path.clone(),
            source_ip: self.source_ip.clone(),
            slm_verdict: slm.map(|s| s.decision.clone()),
            slm_threat_score: slm.and_then(|s| s.verdict.as_ref().map(|v| v.threat_score)),
            slm_duration_ms: slm.and_then(|s| s.verdict.as_ref().map(|v| v.screening_ms)),
            slm_detail: slm.and_then(|s| {
                s.verdict
                    .as_ref()
                    .and_then(|v| serde_json::to_value(v).ok())
            }),
            channel: channel_trust.channel.clone(),
            trust_level: Some(format!("{:?}", channel_trust.trust_level).to_lowercase()),
            response_screen: self.dlp.as_ref().and_then(|d| d.detail.clone()),
        }
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

    #[test]
    fn to_receipts_minimal_request() {
        let p = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        let receipts = p.to_receipts("abcd1234", 256, Some(200), Some(1024), Some(150));
        // Should have: 1 request ApiCall + 1 response ApiCall = 2
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].receipt_type, "api_call");
        assert!(receipts[0].action.contains("POST /v1/messages"));
        assert_eq!(receipts[1].receipt_type, "api_call");
        assert!(receipts[1].action.contains("response"));
    }

    #[test]
    fn to_receipts_with_vault_and_slm() {
        let mut p = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        p.vault_request = Some(VaultStepResult {
            direction: "request".to_string(),
            secrets_found: vec!["api_key:sk-****".to_string()],
        });
        p.slm_fast = Some(SlmStepResult {
            layer: "fast".to_string(),
            decision: "quarantine".to_string(),
            verdict: None,
        });
        let receipts = p.to_receipts("abcd1234", 256, Some(200), Some(1024), Some(150));
        // vault_detection + api_call(req) + slm_analysis + api_call(resp) = 4
        assert_eq!(receipts.len(), 4);
        assert_eq!(receipts[0].receipt_type, "vault_detection");
        assert_eq!(receipts[1].receipt_type, "api_call");
        assert_eq!(receipts[2].receipt_type, "slm_analysis");
        assert_eq!(receipts[3].receipt_type, "api_call");
    }

    #[test]
    fn to_traffic_fields_extracts_slm() {
        let mut p = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        p.slm_fast = Some(SlmStepResult {
            layer: "fast".to_string(),
            decision: "admit".to_string(),
            verdict: None,
        });

        let trust = aegis_schemas::ChannelTrust::default();
        let fields = p.to_traffic_fields(&trust);
        assert_eq!(fields.request_id, p.request_id_str());
        assert_eq!(fields.slm_verdict, Some("admit".to_string()));
        assert_eq!(fields.trust_level, Some("unknown".to_string()));
    }

    #[test]
    fn to_traffic_fields_deep_overrides_fast() {
        let mut p = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        p.slm_fast = Some(SlmStepResult {
            layer: "fast".to_string(),
            decision: "admit".to_string(),
            verdict: None,
        });
        p.slm_deep = Some(SlmStepResult {
            layer: "deep".to_string(),
            decision: "quarantine".to_string(),
            verdict: None,
        });

        let trust = aegis_schemas::ChannelTrust::default();
        let fields = p.to_traffic_fields(&trust);
        // Deep should override fast
        assert_eq!(fields.slm_verdict, Some("quarantine".to_string()));
    }

    #[test]
    fn to_receipts_blocked_no_response() {
        let mut p = PipelineState::new("POST", "/v1/messages", "127.0.0.1");
        p.outcome = PipelineOutcome::Blocked(403);
        // No response (blocked before forwarding)
        let receipts = p.to_receipts("abcd1234", 256, None, None, None);
        // Only request ApiCall, no response
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].receipt_type, "api_call");
    }
}
