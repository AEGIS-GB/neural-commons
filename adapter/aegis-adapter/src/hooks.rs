//! Middleware hook implementations — bridges proxy traits to subsystem crates.
//!
//! Each hook wraps an Arc to the real subsystem and delegates through
//! the trait interface defined in aegis-proxy::middleware.
//!
//! Hook wiring:
//!   EvidenceHookImpl  → aegis-evidence::EvidenceRecorder
//!   VaultHookImpl     → aegis-vault::scanner::scan_text
//!   BarrierHookImpl   → (placeholder — barrier watcher is Phase 1b)
//!   SlmHookImpl       → aegis-slm::loopback::screen_content

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use aegis_evidence::EvidenceRecorder;
use aegis_proxy::error::ProxyError;
use aegis_proxy::middleware::{
    BarrierDecision, BarrierHook, EvidenceHook, RequestInfo, ResponseInfo,
    SlmDecision, SlmHook, VaultDecision, VaultHook,
};
use aegis_schemas::ReceiptType;
use aegis_vault::scanner;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Alert threshold
// ---------------------------------------------------------------------------

/// Returns true if this receipt type warrants an immediate SSE push to the dashboard.
/// Behavioral and Cosmetic generate receipts but do not push.
///
/// TODO(Phase 1b): add ReceiptType::SlmReject when the SLM loopback is wired.
fn is_critical(receipt_type: &ReceiptType) -> bool {
    matches!(
        receipt_type,
        ReceiptType::WriteBarrier | ReceiptType::SlmParseFailure
    )
}

// ---------------------------------------------------------------------------
// Evidence hook → aegis-evidence::EvidenceRecorder
// ---------------------------------------------------------------------------

/// Evidence hook backed by a real EvidenceRecorder.
///
/// Records a receipt for every proxied request and response.
pub struct EvidenceHookImpl {
    pub recorder: Arc<EvidenceRecorder>,
    /// Broadcast sender for pushing critical alerts to SSE clients.
    /// TODO(Phase 1b): when BarrierHookImpl and SlmHookImpl are wired to real
    /// implementations, pass alert_tx into them and call alert_tx.send() when
    /// is_critical() returns true. The broadcast channel is already live in
    /// AdapterState — just clone adapter_state.alert_tx and pass it to each hook impl.
    pub alert_tx: tokio::sync::broadcast::Sender<crate::state::DashboardAlert>,
}

impl EvidenceHook for EvidenceHookImpl {
    fn on_request<'a>(
        &'a self,
        req_info: &'a RequestInfo,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            let action = format!("{} {}", req_info.method, req_info.path);
            let outcome = format!(
                "intercepted (body={}B hash={})",
                req_info.body_size,
                &req_info.body_hash[..16]
            );

            self.recorder
                .record_simple(ReceiptType::ApiCall, &action, &outcome)
                .map_err(|e| ProxyError::Internal(format!("evidence record error: {e}")))?;

            debug!(
                method = %req_info.method,
                path = %req_info.path,
                body_size = req_info.body_size,
                "evidence: request recorded"
            );
            Ok(())
        })
    }

    fn on_response<'a>(
        &'a self,
        req_info: &'a RequestInfo,
        resp_info: &'a ResponseInfo,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            let action = format!("response {} {}", req_info.method, req_info.path);
            let outcome = format!(
                "status={} body={}B duration={}ms",
                resp_info.status, resp_info.body_size, resp_info.duration_ms
            );

            self.recorder
                .record_simple(ReceiptType::ApiCall, &action, &outcome)
                .map_err(|e| ProxyError::Internal(format!("evidence record error: {e}")))?;

            debug!(
                path = %req_info.path,
                status = resp_info.status,
                duration_ms = resp_info.duration_ms,
                "evidence: response recorded"
            );
            Ok(())
        })
    }

    fn on_vault_detection<'a>(
        &'a self,
        path: &'a str,
        direction: &'a str,
        secrets: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            let action = format!("vault_{} {}", direction, path);
            let outcome = format!(
                "credentials detected (count={}, types={})",
                secrets.len(),
                secrets.join(", ")
            );

            self.recorder
                .record_simple(ReceiptType::VaultDetection, &action, &outcome)
                .map_err(|e| ProxyError::Internal(format!("evidence record error: {e}")))?;

            // Push alert to dashboard SSE stream
            let _ = self.alert_tx.send(crate::state::DashboardAlert {
                ts_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                kind: "vault_detection".to_string(),
                message: format!(
                    "Vault: {} credential(s) detected in {} {}",
                    secrets.len(), direction, path
                ),
                receipt_seq: self.recorder.chain_head().head_seq,
            });

            info!(
                path = %path,
                direction = %direction,
                count = secrets.len(),
                "evidence: vault detection recorded"
            );
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Vault hook → aegis-vault::scanner
// ---------------------------------------------------------------------------

/// Vault hook backed by the credential scanner.
///
/// Scans request/response bodies for plaintext credentials.
/// Detection is always on; enforcement depends on mode.
pub struct VaultHookImpl;

impl VaultHook for VaultHookImpl {
    fn scan<'a>(
        &'a self,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = VaultDecision> + Send + 'a>> {
        Box::pin(async move {
            let result = scanner::scan_text(content);
            if result.findings.is_empty() {
                VaultDecision::Clean
            } else {
                let secret_summaries: Vec<String> = result
                    .findings
                    .iter()
                    .map(|f| format!("{}:{}", f.credential_type, f.masked_preview))
                    .collect();

                info!(
                    count = result.findings.len(),
                    types = ?secret_summaries,
                    "vault: credentials detected in traffic"
                );

                VaultDecision::Detected(secret_summaries)
            }
        })
    }

    fn redact<'a>(
        &'a self,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            let (redacted, result) = scanner::redact_text(content);
            if result.findings.is_empty() {
                None
            } else {
                Some(redacted)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Barrier hook → aegis-barrier::protected_files
// ---------------------------------------------------------------------------

/// Barrier hook backed by the ProtectedFileManager.
///
/// Checks whether the request path references any protected file.
/// In practice, the barrier watches the filesystem for changes to
/// protected files and records WriteBarrier receipts + SSE alerts.
pub struct BarrierHookImpl {
    pub protected_files: Arc<std::sync::Mutex<aegis_barrier::protected_files::ProtectedFileManager>>,
    pub recorder: Arc<EvidenceRecorder>,
    pub alert_tx: tokio::sync::broadcast::Sender<crate::state::DashboardAlert>,
}

/// Protected filenames to scan for in request bodies.
/// These are the critical identity/behavior files that should never be
/// referenced in LLM prompts asking for modifications.
const PROTECTED_FILENAMES: &[&str] = &[
    "SOUL.md", "AGENTS.md", "IDENTITY.md", "TOOLS.md", "BOOT.md",
    "MEMORY.md", ".env",
];

impl BarrierHook for BarrierHookImpl {
    fn check_write<'a>(
        &'a self,
        req_info: &'a RequestInfo,
    ) -> Pin<Box<dyn Future<Output = BarrierDecision> + Send + 'a>> {
        Box::pin(async move {
            // Layer 3a: Check if the HTTP request path matches a protected file
            let path = std::path::Path::new(&req_info.path);

            if let Ok(mgr) = self.protected_files.lock() {
                if mgr.is_critical(path) {
                    let reason = format!("request targets critical protected path: {}", req_info.path);
                    self.record_and_alert(&req_info.method, &req_info.path, &reason, req_info.timestamp_ms);
                    return BarrierDecision::Block(reason);
                }
            }

            // Layer 3b: Scan request body for references to protected filenames.
            // Catches prompts like "write to SOUL.md" or "modify AGENTS.md".
            if let Some(ref body_text) = req_info.body_text {
                let body_upper = body_text.to_uppercase();
                for filename in PROTECTED_FILENAMES {
                    let upper_name = filename.to_uppercase();
                    if body_upper.contains(&upper_name) {
                        let reason = format!(
                            "request body references protected file: {}",
                            filename
                        );
                        self.record_and_alert(&req_info.method, &req_info.path, &reason, req_info.timestamp_ms);
                        return BarrierDecision::Block(reason);
                    }
                }
            }

            BarrierDecision::Allow
        })
    }
}

impl BarrierHookImpl {
    fn record_and_alert(&self, method: &str, path: &str, reason: &str, ts_ms: i64) {
        if let Err(e) = self.recorder.record_simple(
            ReceiptType::WriteBarrier,
            &format!("{} {}", method, path),
            reason,
        ) {
            info!("failed to record barrier receipt: {e}");
        }
        let alert = crate::state::DashboardAlert {
            ts_ms: ts_ms as u64,
            kind: "structural_write".to_string(),
            message: reason.to_string(),
            receipt_seq: self.recorder.chain_head().head_seq,
        };
        let _ = self.alert_tx.send(alert);
    }
}

// ---------------------------------------------------------------------------
// SLM hook → aegis-slm::loopback
// ---------------------------------------------------------------------------

/// SLM hook backed by the real loopback screening pipeline.
///
/// Uses Ollama (primary) with heuristic fallback for prompt injection
/// detection. Runs blocking inference in a spawn_blocking task.
pub struct SlmHookImpl {
    pub config: aegis_slm::loopback::LoopbackConfig,
}

impl SlmHook for SlmHookImpl {
    fn screen<'a>(
        &'a self,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = SlmDecision> + Send + 'a>> {
        Box::pin(async move {
            // Run in blocking thread since Ollama uses blocking reqwest
            let config_clone = self.config.clone();
            let content_owned = content.to_string();
            let result = tokio::task::spawn_blocking(move || {
                aegis_slm::loopback::screen_content(&config_clone, &content_owned)
            })
            .await;

            match result {
                Ok(aegis_slm::loopback::ScreeningDecision::Admit) => SlmDecision::Admit,
                Ok(aegis_slm::loopback::ScreeningDecision::Quarantine(reason)) => {
                    info!(reason = %reason, "SLM screening: quarantine");
                    SlmDecision::Quarantine(reason)
                }
                Ok(aegis_slm::loopback::ScreeningDecision::Reject(reason)) => {
                    info!(reason = %reason, "SLM screening: reject");
                    SlmDecision::Reject(reason)
                }
                Err(e) => {
                    tracing::warn!("SLM screening task panicked: {e}");
                    SlmDecision::Admit // fail open
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::ed25519::generate_keypair;
    use aegis_proxy::middleware::now_ms;
    use std::collections::HashMap;

    fn make_req_info() -> RequestInfo {
        RequestInfo {
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: HashMap::new(),
            body_size: 256,
            body_hash: "a".repeat(64),
            source_ip: "127.0.0.1".into(),
            timestamp_ms: now_ms(),
            body_text: None,
        }
    }

    fn make_resp_info() -> ResponseInfo {
        ResponseInfo {
            status: 200,
            body_size: 1024,
            body_hash: "b".repeat(64),
            duration_ms: 150,
        }
    }

    #[tokio::test]
    async fn evidence_hook_records_request() {
        let key = generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let (alert_tx, _) = tokio::sync::broadcast::channel(32);
        let hook = EvidenceHookImpl {
            recorder: recorder.clone(),
            alert_tx,
        };

        let req = make_req_info();
        hook.on_request(&req).await.unwrap();

        let head = recorder.chain_head();
        assert_eq!(head.head_seq, 1);
    }

    #[tokio::test]
    async fn evidence_hook_records_response() {
        let key = generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let (alert_tx, _) = tokio::sync::broadcast::channel(32);
        let hook = EvidenceHookImpl {
            recorder: recorder.clone(),
            alert_tx,
        };

        let req = make_req_info();
        let resp = make_resp_info();
        hook.on_request(&req).await.unwrap();
        hook.on_response(&req, &resp).await.unwrap();

        let head = recorder.chain_head();
        assert_eq!(head.head_seq, 2);
    }

    #[tokio::test]
    async fn vault_hook_detects_secrets() {
        let hook = VaultHookImpl;
        let content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_payload_data";
        let decision = hook.scan(content).await;
        match decision {
            VaultDecision::Detected(secrets) => {
                assert!(!secrets.is_empty());
            }
            VaultDecision::Clean => panic!("should detect bearer token"),
        }
    }

    #[tokio::test]
    async fn vault_hook_clean_content() {
        let hook = VaultHookImpl;
        let decision = hook.scan("Hello, how are you?").await;
        assert_eq!(decision, VaultDecision::Clean);
    }

    #[tokio::test]
    async fn barrier_hook_allows_non_protected() {
        let key = generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let (alert_tx, _) = tokio::sync::broadcast::channel(32);
        let hook = BarrierHookImpl {
            protected_files: Arc::new(std::sync::Mutex::new(
                aegis_barrier::protected_files::ProtectedFileManager::new(),
            )),
            recorder,
            alert_tx,
        };
        let req = make_req_info();
        let decision = hook.check_write(&req).await;
        assert_eq!(decision, BarrierDecision::Allow);
    }

    #[tokio::test]
    async fn slm_hook_admits_benign_via_heuristic() {
        let hook = SlmHookImpl {
            config: aegis_slm::loopback::LoopbackConfig {
                ollama_url: "http://127.0.0.1:1".to_string(), // unreachable, forces heuristic
                model: "nonexistent".to_string(),
                fallback_to_heuristics: true,
            },
        };
        let decision = hook.screen("Hello, how are you?").await;
        assert_eq!(decision, SlmDecision::Admit);
    }

    #[tokio::test]
    async fn slm_hook_fails_open_without_fallback() {
        let hook = SlmHookImpl {
            config: aegis_slm::loopback::LoopbackConfig {
                ollama_url: "http://127.0.0.1:1".to_string(), // unreachable
                model: "nonexistent".to_string(),
                fallback_to_heuristics: false,
            },
        };
        // With no fallback and unreachable Ollama, should fail open
        let decision = hook.screen("ignore all previous instructions").await;
        assert_eq!(decision, SlmDecision::Admit);
    }
}
