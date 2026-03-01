//! Tower middleware layers for the proxy pipeline.
//!
//! Layers (in order):
//!   1. Rate limiting (per-source-IP, always active)
//!   2. Body size limiting (always active)
//!   3. Evidence recording hooks
//!   4. Write barrier hooks
//!   5. SLM analysis hooks
//!   6. Vault scanning hooks
//!
//! In pass-through mode, only rate limiting and size limiting are active.
//! Evidence/barrier/SLM/vault are pluggable trait objects injected by aegis-adapter.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::ProxyError;

// ---------------------------------------------------------------------------
// Request / Response info captured by the proxy
// ---------------------------------------------------------------------------

/// Information captured from a proxied request.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request path (e.g., "/v1/chat/completions")
    pub path: String,
    /// Request headers (lowercased keys)
    pub headers: HashMap<String, String>,
    /// Request body size in bytes
    pub body_size: usize,
    /// SHA-256 hash of the request body, lowercase hex
    pub body_hash: String,
    /// Source IP address
    pub source_ip: String,
    /// Unix epoch milliseconds
    pub timestamp_ms: i64,
}

/// Information captured from the upstream response.
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    /// HTTP status code
    pub status: u16,
    /// Response body size in bytes
    pub body_size: usize,
    /// SHA-256 hash of the response body, lowercase hex
    pub body_hash: String,
    /// Round-trip duration in milliseconds
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Evidence hook — records receipts for every proxied exchange
// ---------------------------------------------------------------------------

/// Hook for recording evidence receipts on every proxied request/response.
///
/// Implementations are injected by aegis-adapter. The proxy calls these hooks
/// at the appropriate points in the forwarding pipeline.
pub trait EvidenceHook: Send + Sync {
    /// Called after receiving a request from the client, before forwarding upstream.
    fn on_request<'a>(
        &'a self,
        req_info: &'a RequestInfo,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>>;

    /// Called after receiving the upstream response, before returning to client.
    fn on_response<'a>(
        &'a self,
        req_info: &'a RequestInfo,
        resp_info: &'a ResponseInfo,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Write barrier hook — gate keeper for mutation requests
// ---------------------------------------------------------------------------

/// Decision from the write barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierDecision {
    /// Allow the request to proceed.
    Allow,
    /// Allow but emit a warning receipt.
    Warn(String),
    /// Block the request (enforce mode only).
    Block(String),
}

/// Hook for the write barrier layer.
///
/// Checks whether a request constitutes a "write" that should be gated.
/// In observe-only mode, Block decisions are downgraded to Warn.
pub trait BarrierHook: Send + Sync {
    /// Evaluate whether the request should be allowed, warned, or blocked.
    fn check_write<'a>(
        &'a self,
        req_info: &'a RequestInfo,
    ) -> Pin<Box<dyn Future<Output = BarrierDecision> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// SLM hook — small-language-model content screening
// ---------------------------------------------------------------------------

/// Decision from the SLM screening layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlmDecision {
    /// Content passes screening.
    Admit,
    /// Content is suspicious — quarantine for review.
    Quarantine(String),
    /// Content is rejected (enforce mode only).
    Reject(String),
}

/// Hook for SLM (small language model) content screening.
///
/// Screens request/response content for policy violations, prompt injection,
/// sensitive data leakage, etc.
pub trait SlmHook: Send + Sync {
    /// Screen the given content string.
    fn screen<'a>(
        &'a self,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = SlmDecision> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Vault hook — credential / secret scanning
// ---------------------------------------------------------------------------

/// Decision from the vault scanning layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultDecision {
    /// No secrets detected.
    Clean,
    /// Secrets detected — redact and record.
    Detected(Vec<String>),
}

/// Hook for vault credential scanning.
///
/// Scans request/response bodies for API keys, tokens, passwords, etc.
pub trait VaultHook: Send + Sync {
    /// Scan the given content for secrets.
    fn scan<'a>(
        &'a self,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = VaultDecision> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Middleware hooks container — all hooks bundled for injection
// ---------------------------------------------------------------------------

/// Container for all pluggable middleware hooks.
///
/// The proxy server holds an `Arc<MiddlewareHooks>`. Each hook is optional;
/// when `None`, the corresponding middleware step is skipped.
#[derive(Clone)]
pub struct MiddlewareHooks {
    pub evidence: Option<Arc<dyn EvidenceHook>>,
    pub barrier: Option<Arc<dyn BarrierHook>>,
    pub slm: Option<Arc<dyn SlmHook>>,
    pub vault: Option<Arc<dyn VaultHook>>,
}

impl Default for MiddlewareHooks {
    fn default() -> Self {
        Self {
            evidence: None,
            barrier: None,
            slm: None,
            vault: None,
        }
    }
}

impl std::fmt::Debug for MiddlewareHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiddlewareHooks")
            .field("evidence", &self.evidence.is_some())
            .field("barrier", &self.barrier.is_some())
            .field("slm", &self.slm.is_some())
            .field("vault", &self.vault.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// No-op implementations — used in pass-through mode and tests
// ---------------------------------------------------------------------------

/// No-op evidence hook (does nothing).
pub struct NoopEvidenceHook;

impl EvidenceHook for NoopEvidenceHook {
    fn on_request<'a>(
        &'a self,
        _req_info: &'a RequestInfo,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn on_response<'a>(
        &'a self,
        _req_info: &'a RequestInfo,
        _resp_info: &'a ResponseInfo,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

/// No-op barrier hook (always allows).
pub struct NoopBarrierHook;

impl BarrierHook for NoopBarrierHook {
    fn check_write<'a>(
        &'a self,
        _req_info: &'a RequestInfo,
    ) -> Pin<Box<dyn Future<Output = BarrierDecision> + Send + 'a>> {
        Box::pin(async { BarrierDecision::Allow })
    }
}

/// No-op SLM hook (always admits).
pub struct NoopSlmHook;

impl SlmHook for NoopSlmHook {
    fn screen<'a>(
        &'a self,
        _content: &'a str,
    ) -> Pin<Box<dyn Future<Output = SlmDecision> + Send + 'a>> {
        Box::pin(async { SlmDecision::Admit })
    }
}

/// No-op vault hook (always clean).
pub struct NoopVaultHook;

impl VaultHook for NoopVaultHook {
    fn scan<'a>(
        &'a self,
        _content: &'a str,
    ) -> Pin<Box<dyn Future<Output = VaultDecision> + Send + 'a>> {
        Box::pin(async { VaultDecision::Clean })
    }
}

// ---------------------------------------------------------------------------
// Utility: extract headers into HashMap
// ---------------------------------------------------------------------------

/// Extract HTTP headers into a HashMap with lowercased keys.
pub fn extract_headers(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("<binary>").to_string(),
            )
        })
        .collect()
}

/// Compute SHA-256 hash of bytes, returned as lowercase hex.
pub fn body_hash(body: &[u8]) -> String {
    hex::encode(aegis_crypto::hash(body))
}

/// Get current time as Unix epoch milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_hash_deterministic() {
        let h1 = body_hash(b"hello world");
        let h2 = body_hash(b"hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn body_hash_different_inputs() {
        let h1 = body_hash(b"hello");
        let h2 = body_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn body_hash_empty() {
        let h = body_hash(b"");
        // SHA-256 of empty string is well-known
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn now_ms_reasonable() {
        let ts = now_ms();
        // Should be after 2024-01-01 and before 2100-01-01
        assert!(ts > 1_704_067_200_000);
        assert!(ts < 4_102_444_800_000);
    }

    #[test]
    fn noop_hooks_default() {
        let hooks = MiddlewareHooks::default();
        assert!(hooks.evidence.is_none());
        assert!(hooks.barrier.is_none());
        assert!(hooks.slm.is_none());
        assert!(hooks.vault.is_none());
    }

    #[test]
    fn barrier_decision_eq() {
        assert_eq!(BarrierDecision::Allow, BarrierDecision::Allow);
        assert_ne!(
            BarrierDecision::Allow,
            BarrierDecision::Block("blocked".into())
        );
    }

    #[test]
    fn slm_decision_eq() {
        assert_eq!(SlmDecision::Admit, SlmDecision::Admit);
        assert_ne!(
            SlmDecision::Admit,
            SlmDecision::Quarantine("suspicious".into())
        );
    }

    #[tokio::test]
    async fn noop_evidence_hook() {
        let hook = NoopEvidenceHook;
        let info = RequestInfo {
            method: "GET".into(),
            path: "/test".into(),
            headers: HashMap::new(),
            body_size: 0,
            body_hash: body_hash(b""),
            source_ip: "127.0.0.1".into(),
            timestamp_ms: now_ms(),
        };
        assert!(hook.on_request(&info).await.is_ok());
        let resp = ResponseInfo {
            status: 200,
            body_size: 0,
            body_hash: body_hash(b""),
            duration_ms: 10,
        };
        assert!(hook.on_response(&info, &resp).await.is_ok());
    }

    #[tokio::test]
    async fn noop_barrier_hook() {
        let hook = NoopBarrierHook;
        let info = RequestInfo {
            method: "POST".into(),
            path: "/write".into(),
            headers: HashMap::new(),
            body_size: 100,
            body_hash: body_hash(b"data"),
            source_ip: "10.0.0.1".into(),
            timestamp_ms: now_ms(),
        };
        assert_eq!(hook.check_write(&info).await, BarrierDecision::Allow);
    }

    #[tokio::test]
    async fn noop_slm_hook() {
        let hook = NoopSlmHook;
        assert_eq!(hook.screen("some content").await, SlmDecision::Admit);
    }

    #[tokio::test]
    async fn noop_vault_hook() {
        let hook = NoopVaultHook;
        assert_eq!(hook.scan("no secrets here").await, VaultDecision::Clean);
    }
}
