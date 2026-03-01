//! Middleware hook implementations — bridges proxy traits to subsystem crates.
//!
//! Each hook wraps an Arc to the real subsystem and delegates through
//! the trait interface defined in aegis-proxy::middleware.
//!
//! Hook wiring:
//!   EvidenceHookImpl  → aegis-evidence::EvidenceRecorder
//!   VaultHookImpl     → aegis-vault::scanner::scan_text
//!   BarrierHookImpl   → (placeholder — barrier watcher is Phase 1b)
//!   SlmHookImpl       → (placeholder — SLM loopback is Phase 1b)

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
// Evidence hook → aegis-evidence::EvidenceRecorder
// ---------------------------------------------------------------------------

/// Evidence hook backed by a real EvidenceRecorder.
///
/// Records a receipt for every proxied request and response.
pub struct EvidenceHookImpl {
    pub recorder: Arc<EvidenceRecorder>,
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
}

// ---------------------------------------------------------------------------
// Barrier hook — placeholder for Phase 1b
// ---------------------------------------------------------------------------

/// Barrier hook placeholder.
///
/// Phase 1b will implement the full write barrier with filesystem watcher,
/// severity classifier, and write token authorization. For now, this is
/// a pass-through that always allows writes.
pub struct BarrierHookImpl;

impl BarrierHook for BarrierHookImpl {
    fn check_write<'a>(
        &'a self,
        _req_info: &'a RequestInfo,
    ) -> Pin<Box<dyn Future<Output = BarrierDecision> + Send + 'a>> {
        Box::pin(async { BarrierDecision::Allow })
    }
}

// ---------------------------------------------------------------------------
// SLM hook — placeholder for Phase 1b
// ---------------------------------------------------------------------------

/// SLM hook placeholder.
///
/// Phase 1b will implement the full SLM loopback with model routing,
/// decomposition prompt, and holster presets. For now, this admits
/// all content.
pub struct SlmHookImpl;

impl SlmHook for SlmHookImpl {
    fn screen<'a>(
        &'a self,
        _content: &'a str,
    ) -> Pin<Box<dyn Future<Output = SlmDecision> + Send + 'a>> {
        Box::pin(async { SlmDecision::Admit })
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
        let hook = EvidenceHookImpl {
            recorder: recorder.clone(),
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
        let hook = EvidenceHookImpl {
            recorder: recorder.clone(),
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
    async fn barrier_hook_allows_all() {
        let hook = BarrierHookImpl;
        let req = make_req_info();
        let decision = hook.check_write(&req).await;
        assert_eq!(decision, BarrierDecision::Allow);
    }

    #[tokio::test]
    async fn slm_hook_admits_all() {
        let hook = SlmHookImpl;
        let decision = hook.screen("anything").await;
        assert_eq!(decision, SlmDecision::Admit);
    }
}
