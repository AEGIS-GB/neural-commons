//! NC-Ed25519 stateless request signing (D3)
//!
//! HTTP: `Authorization: NC-Ed25519 <pubkey>:<sig>`
//!   sig = Ed25519(transport_key, JCS({method, path, ts_ms, body_hash}))
//!   Timestamp via `X-Aegis-Timestamp: <epoch_ms>` header.
//!   Gateway validates statelessly, rejects ts_ms outside +/-15s.
//!
//! WSS: Challenge-response on upgrade handshake only (one-time).
//!
//! Transport auth key: derived via m/44'/784'/3'/0' (D0).
//! Verifiers map transport pubkey -> bot identity via cluster-registered key hierarchy.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};

/// Maximum clock skew for request timestamps (+/-15 seconds)
pub const MAX_CLOCK_SKEW_MS: i64 = 15_000;

/// Replay protection window (30 seconds covers both sides of ±15s skew)
pub const REPLAY_WINDOW_MS: i64 = 30_000;

/// Replay protection — tracks recent request hashes to prevent replay attacks.
///
/// Hash = SHA-256(pubkey + ts_ms + body_hash). Entries older than 30 seconds
/// are purged inline on each check (no background task).
pub struct ReplayProtection {
    /// Recent request hashes: hash → ts_ms
    seen: RwLock<HashMap<String, i64>>,
}

impl ReplayProtection {
    pub fn new() -> Self {
        Self {
            seen: RwLock::new(HashMap::new()),
        }
    }

    /// Check if this request is a replay. Returns `true` if the request is NEW
    /// (not a replay), `false` if it has been seen before.
    pub fn check_and_record(&self, pubkey: &str, ts_ms: i64, body_hash: &str) -> bool {
        let input = format!("{}:{}:{}", pubkey, ts_ms, body_hash);
        let request_hash = hex::encode(aegis_crypto::hash(input.as_bytes()));

        let mut seen = self.seen.write().unwrap();

        // Cleanup old entries (>30s from now)
        let now_ms = current_ts_ms();
        seen.retain(|_, ts| now_ms - *ts < REPLAY_WINDOW_MS);

        // Check for replay
        if seen.contains_key(&request_hash) {
            return false; // Replay detected
        }

        seen.insert(request_hash, ts_ms);
        true
    }
}

/// Request signing input -- JCS-canonicalized before signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningInput {
    /// SHA-256 of request body, lowercase hex. Empty body = hash of empty bytes.
    pub body_hash: String,
    /// HTTP method (uppercase: GET, POST, etc.)
    pub method: String,
    /// Request path (e.g., "/evidence/batch")
    pub path: String,
    /// Unix epoch milliseconds
    pub ts_ms: i64,
}

/// Parsed NC-Ed25519 authorization header
#[derive(Debug, Clone)]
pub struct NcAuth {
    /// Transport public key, lowercase hex (32 bytes = 64 hex chars)
    pub pubkey: String,
    /// Ed25519 signature, lowercase hex (64 bytes = 128 hex chars)
    pub sig: String,
}

/// Verified identity extracted by auth middleware, available to handlers.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// Transport public key, lowercase hex
    pub pubkey: String,
}

/// WSS challenge for upgrade handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WssChallenge {
    /// Random nonce, lowercase hex
    pub nonce: String,
    /// Unix epoch milliseconds
    pub ts_ms: i64,
}

/// WSS challenge response from adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WssChallengeResponse {
    /// Transport public key, lowercase hex
    pub pubkey: String,
    /// Ed25519(transport_key, JCS({nonce, ts_ms}))
    pub sig: String,
}

/// Parse an NC-Ed25519 authorization header.
/// Format: `NC-Ed25519 <pubkey>:<sig>`
pub fn parse_auth_header(header: &str) -> Option<NcAuth> {
    let rest = header.strip_prefix("NC-Ed25519 ")?;
    let (pubkey, sig) = rest.split_once(':')?;

    // Validate hex lengths
    if pubkey.len() != 64 || sig.len() != 128 {
        return None;
    }

    // Validate hex chars
    if !pubkey.chars().all(|c| c.is_ascii_hexdigit()) || !sig.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }

    Some(NcAuth {
        pubkey: pubkey.to_string(),
        sig: sig.to_string(),
    })
}

/// Validate request timestamp is within +/-15s of current time
pub fn validate_timestamp(request_ts_ms: i64, current_ts_ms: i64) -> bool {
    let diff = (request_ts_ms - current_ts_ms).abs();
    diff <= MAX_CLOCK_SKEW_MS
}

/// Verify an NC-Ed25519 signed request.
///
/// 1. Parse pubkey from hex
/// 2. Parse signature from hex
/// 3. Compute body_hash = SHA-256(body)
/// 4. Build SigningInput = {method, path, ts_ms, body_hash}
/// 5. JCS-canonicalize the SigningInput
/// 6. Verify Ed25519 signature over canonical bytes
pub fn verify_request(
    auth: &NcAuth,
    method: &str,
    path: &str,
    ts_ms: i64,
    body: &[u8],
) -> Result<(), String> {
    // 1. Parse pubkey from hex
    let pubkey_bytes = hex::decode(&auth.pubkey).map_err(|e| format!("invalid pubkey hex: {e}"))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| format!("invalid Ed25519 key: {e}"))?;

    // 2. Parse signature from hex
    let sig_bytes = hex::decode(&auth.sig).map_err(|e| format!("invalid sig hex: {e}"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "sig must be 64 bytes".to_string())?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    // 3. Compute body hash
    let body_hash = hex::encode(aegis_crypto::hash(body));

    // 4. Build signing input
    let signing_input = SigningInput {
        body_hash,
        method: method.to_string(),
        path: path.to_string(),
        ts_ms,
    };

    // 5. JCS-canonicalize
    let canonical = aegis_crypto::canonicalize(&signing_input)
        .map_err(|e| format!("canonicalization failed: {e}"))?;

    // 6. Verify signature
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| "signature verification failed".to_string())
}

fn current_ts_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Axum middleware that enforces NC-Ed25519 authentication.
///
/// Extracts:
///   - `Authorization: NC-Ed25519 <pubkey>:<sig>` header
///   - `X-Aegis-Timestamp: <epoch_ms>` header
///
/// On success, inserts `VerifiedIdentity` into request extensions.
/// On failure, returns 401 Unauthorized.
pub async fn auth_middleware(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();

    // Extract Authorization header
    let auth_header = match parts.headers.get("authorization") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return auth_error("invalid authorization header encoding"),
        },
        None => return auth_error("missing Authorization header"),
    };

    let auth = match parse_auth_header(&auth_header) {
        Some(a) => a,
        None => return auth_error("malformed NC-Ed25519 authorization header"),
    };

    // Extract X-Aegis-Timestamp header
    let ts_ms: i64 = match parts.headers.get("x-aegis-timestamp") {
        Some(v) => match v.to_str() {
            Ok(s) => match s.parse() {
                Ok(t) => t,
                Err(_) => return auth_error("invalid X-Aegis-Timestamp value"),
            },
            Err(_) => return auth_error("invalid X-Aegis-Timestamp encoding"),
        },
        None => return auth_error("missing X-Aegis-Timestamp header"),
    };

    // Validate timestamp
    let now = current_ts_ms();
    if !validate_timestamp(ts_ms, now) {
        return auth_error("request timestamp outside allowed window (+/-15s)");
    }

    // Read body bytes
    let body_bytes = match axum::body::to_bytes(body, 2 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return auth_error("failed to read request body"),
    };

    // Verify signature
    let method = parts.method.as_str();
    let path = parts.uri.path();
    if let Err(e) = verify_request(&auth, method, path, ts_ms, &body_bytes) {
        return auth_error(&format!("signature verification failed: {e}"));
    }

    // Replay protection: check if this exact request has been seen before
    if let Some(replay_guard) = parts.extensions.get::<Arc<ReplayProtection>>() {
        let body_hash = hex::encode(aegis_crypto::hash(&body_bytes));
        if !replay_guard.check_and_record(&auth.pubkey, ts_ms, &body_hash) {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({ "error": "replay detected" })),
            )
                .into_response();
        }
    }

    // Tier-based rate limiting: look up TRUSTMARK score → tier → check bucket
    if let Some(rate_limiter) = parts
        .extensions
        .get::<Arc<crate::rate_limit::TierRateLimiter>>()
        .cloned()
    {
        // Determine tier from TRUSTMARK cache (if available)
        let tier = if let Some(cache) = parts
            .extensions
            .get::<Arc<crate::nats_bridge::TrustmarkCache>>()
        {
            let score_bp = cache
                .get(&auth.pubkey)
                .await
                .map(|s| s.score_bp)
                .unwrap_or(0);
            crate::rate_limit::tier_from_score_bp(score_bp)
        } else {
            1 // default to Tier 1 if no cache
        };

        if let Err(retry_after) = rate_limiter.check(&auth.pubkey, tier) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    axum::http::header::RETRY_AFTER,
                    format!("{}", retry_after.ceil() as u64),
                )],
                axum::Json(serde_json::json!({
                    "error": "rate limit exceeded",
                    "retry_after": retry_after
                })),
            )
                .into_response();
        }
    }

    // Inject verified identity and reconstruct request
    let mut request = Request::from_parts(parts, Body::from(body_bytes));
    request.extensions_mut().insert(VerifiedIdentity {
        pubkey: auth.pubkey,
    });

    next.run(request).await
}

fn auth_error(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::{Extension, Router, middleware};
    use ed25519_dalek::Signer;
    use tower::ServiceExt;

    /// Helper: sign a request and return (pubkey_hex, sig_hex, ts_ms)
    fn sign_request(
        signing_key: &ed25519_dalek::SigningKey,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (String, String, i64) {
        let ts_ms = current_ts_ms();
        let body_hash = hex::encode(aegis_crypto::hash(body));
        let input = SigningInput {
            body_hash,
            method: method.to_string(),
            path: path.to_string(),
            ts_ms,
        };
        let canonical = aegis_crypto::canonicalize(&input).unwrap();
        let sig = signing_key.sign(&canonical);
        let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        (pubkey_hex, sig_hex, ts_ms)
    }

    fn test_app() -> Router {
        let authed =
            Router::new()
                .route(
                    "/protected",
                    get(|ext: Extension<VerifiedIdentity>| async move {
                        format!("hello {}", ext.pubkey)
                    }),
                )
                .route(
                    "/echo",
                    post(
                        |ext: Extension<VerifiedIdentity>, body: String| async move {
                            format!("from {} body={}", ext.pubkey, body)
                        },
                    ),
                )
                .layer(middleware::from_fn(auth_middleware));

        Router::new()
            .route("/health", get(|| async { "ok" }))
            .merge(authed)
    }

    #[tokio::test]
    async fn valid_signed_get_request() {
        let app = test_app();
        let sk = aegis_crypto::ed25519::generate_keypair();
        let (pubkey, sig, ts_ms) = sign_request(&sk, "GET", "/protected", b"");

        let req = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains(&pubkey));
    }

    #[tokio::test]
    async fn valid_signed_post_request() {
        let app = test_app();
        let sk = aegis_crypto::ed25519::generate_keypair();
        let body_bytes = b"test body content";
        let (pubkey, sig, ts_ms) = sign_request(&sk, "POST", "/echo", body_bytes);

        let req = Request::builder()
            .method("POST")
            .uri("/echo")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::from(&body_bytes[..]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains(&pubkey));
        assert!(text.contains("test body content"));
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let app = test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_timestamp_returns_401() {
        let app = test_app();
        let sk = aegis_crypto::ed25519::generate_keypair();
        let old_ts = current_ts_ms() - 30_000; // 30s ago
        let body_hash = hex::encode(aegis_crypto::hash(b""));
        let input = SigningInput {
            body_hash,
            method: "GET".to_string(),
            path: "/protected".to_string(),
            ts_ms: old_ts,
        };
        let canonical = aegis_crypto::canonicalize(&input).unwrap();
        let sig = sk.sign(&canonical);
        let pubkey = hex::encode(sk.verifying_key().as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());

        let req = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig_hex}"))
            .header("x-aegis-timestamp", old_ts.to_string())
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tampered_body_returns_401() {
        let app = test_app();
        let sk = aegis_crypto::ed25519::generate_keypair();
        // Sign with original body
        let (pubkey, sig, ts_ms) = sign_request(&sk, "POST", "/echo", b"original");

        // But send different body
        let req = Request::builder()
            .method("POST")
            .uri("/echo")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::from("tampered"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_bypasses_auth() {
        let app = test_app();
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_parse_valid_auth_header() {
        let pubkey = "a".repeat(64);
        let sig = "b".repeat(128);
        let header = format!("NC-Ed25519 {}:{}", pubkey, sig);
        let auth = parse_auth_header(&header).unwrap();
        assert_eq!(auth.pubkey, pubkey);
        assert_eq!(auth.sig, sig);
    }

    #[test]
    fn test_parse_invalid_prefix() {
        assert!(parse_auth_header("Bearer token123").is_none());
    }

    #[test]
    fn test_parse_wrong_lengths() {
        let header = "NC-Ed25519 abc:def";
        assert!(parse_auth_header(header).is_none());
    }

    #[test]
    fn test_timestamp_validation() {
        let now = 1740000000000i64;
        assert!(validate_timestamp(now, now)); // exact match
        assert!(validate_timestamp(now + 14_000, now)); // within window
        assert!(validate_timestamp(now - 14_000, now)); // within window
        assert!(!validate_timestamp(now + 16_000, now)); // outside window
        assert!(!validate_timestamp(now - 16_000, now)); // outside window
    }

    #[test]
    fn test_verify_request_roundtrip() {
        let sk = aegis_crypto::ed25519::generate_keypair();
        let ts_ms = current_ts_ms();
        let body = b"hello world";
        let body_hash = hex::encode(aegis_crypto::hash(body));
        let input = SigningInput {
            body_hash,
            method: "POST".to_string(),
            path: "/evidence".to_string(),
            ts_ms,
        };
        let canonical = aegis_crypto::canonicalize(&input).unwrap();
        let sig = sk.sign(&canonical);
        let auth = NcAuth {
            pubkey: hex::encode(sk.verifying_key().as_bytes()),
            sig: hex::encode(sig.to_bytes()),
        };
        assert!(verify_request(&auth, "POST", "/evidence", ts_ms, body).is_ok());
    }

    #[test]
    fn test_verify_request_wrong_body() {
        let sk = aegis_crypto::ed25519::generate_keypair();
        let ts_ms = current_ts_ms();
        let body = b"hello world";
        let body_hash = hex::encode(aegis_crypto::hash(body));
        let input = SigningInput {
            body_hash,
            method: "POST".to_string(),
            path: "/evidence".to_string(),
            ts_ms,
        };
        let canonical = aegis_crypto::canonicalize(&input).unwrap();
        let sig = sk.sign(&canonical);
        let auth = NcAuth {
            pubkey: hex::encode(sk.verifying_key().as_bytes()),
            sig: hex::encode(sig.to_bytes()),
        };
        // Verify with different body
        assert!(verify_request(&auth, "POST", "/evidence", ts_ms, b"different").is_err());
    }

    // --- Replay protection tests ---

    #[test]
    fn replay_protection_first_request_accepted() {
        let rp = ReplayProtection::new();
        assert!(rp.check_and_record("pubkey1", current_ts_ms(), "hash1"));
    }

    #[test]
    fn replay_protection_identical_replay_rejected() {
        let rp = ReplayProtection::new();
        let ts = current_ts_ms();
        assert!(rp.check_and_record("pubkey1", ts, "hash1"));
        // Exact same request again → replay
        assert!(!rp.check_and_record("pubkey1", ts, "hash1"));
    }

    #[test]
    fn replay_protection_different_ts_accepted() {
        let rp = ReplayProtection::new();
        let ts = current_ts_ms();
        assert!(rp.check_and_record("pubkey1", ts, "hash1"));
        // Same body_hash but different ts_ms → new request
        assert!(rp.check_and_record("pubkey1", ts + 1, "hash1"));
    }

    #[test]
    fn replay_protection_old_nonce_purged() {
        let rp = ReplayProtection::new();
        // Insert with a very old timestamp (31 seconds ago)
        let old_ts = current_ts_ms() - 31_000;
        {
            let mut seen = rp.seen.write().unwrap();
            let input = format!("pubkey1:{}:hash1", old_ts);
            let hash = hex::encode(aegis_crypto::hash(input.as_bytes()));
            seen.insert(hash, old_ts);
        }
        // Now a new check should purge old entries and accept
        assert!(rp.check_and_record("pubkey1", old_ts, "hash1"));
    }

    fn sign_request_with_ts(
        signing_key: &ed25519_dalek::SigningKey,
        method: &str,
        path: &str,
        body: &[u8],
        ts_ms: i64,
    ) -> (String, String) {
        let body_hash = hex::encode(aegis_crypto::hash(body));
        let input = SigningInput {
            body_hash,
            method: method.to_string(),
            path: path.to_string(),
            ts_ms,
        };
        let canonical = aegis_crypto::canonicalize(&input).unwrap();
        let sig = signing_key.sign(&canonical);
        let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        (pubkey_hex, sig_hex)
    }

    fn test_app_with_replay() -> (Router, Arc<ReplayProtection>) {
        let rp = Arc::new(ReplayProtection::new());
        let rp_clone = rp.clone();
        let authed =
            Router::new()
                .route(
                    "/protected",
                    get(|ext: Extension<VerifiedIdentity>| async move {
                        format!("hello {}", ext.pubkey)
                    }),
                )
                .route(
                    "/echo",
                    post(
                        |ext: Extension<VerifiedIdentity>, body: String| async move {
                            format!("from {} body={}", ext.pubkey, body)
                        },
                    ),
                )
                .layer(middleware::from_fn(auth_middleware))
                .layer(Extension(rp_clone));

        let router = Router::new()
            .route("/health", get(|| async { "ok" }))
            .merge(authed);

        (router, rp)
    }

    #[tokio::test]
    async fn replay_middleware_first_request_accepted() {
        let (app, _rp) = test_app_with_replay();
        let sk = aegis_crypto::ed25519::generate_keypair();
        let (pubkey, sig, ts_ms) = sign_request(&sk, "GET", "/protected", b"");

        let req = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn replay_middleware_identical_replay_returns_409() {
        let rp = Arc::new(ReplayProtection::new());
        let sk = aegis_crypto::ed25519::generate_keypair();
        let ts_ms = current_ts_ms();
        let (pubkey, sig) = sign_request_with_ts(&sk, "GET", "/protected", b"", ts_ms);

        // First request
        {
            let app = {
                let rp_clone = rp.clone();
                let authed = Router::new()
                    .route(
                        "/protected",
                        get(|ext: Extension<VerifiedIdentity>| async move {
                            format!("hello {}", ext.pubkey)
                        }),
                    )
                    .layer(middleware::from_fn(auth_middleware))
                    .layer(Extension(rp_clone));
                Router::new().merge(authed)
            };
            let req = Request::builder()
                .method("GET")
                .uri("/protected")
                .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
                .header("x-aegis-timestamp", ts_ms.to_string())
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Replay: exact same request
        {
            let app = {
                let rp_clone = rp.clone();
                let authed = Router::new()
                    .route(
                        "/protected",
                        get(|ext: Extension<VerifiedIdentity>| async move {
                            format!("hello {}", ext.pubkey)
                        }),
                    )
                    .layer(middleware::from_fn(auth_middleware))
                    .layer(Extension(rp_clone));
                Router::new().merge(authed)
            };
            let req = Request::builder()
                .method("GET")
                .uri("/protected")
                .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
                .header("x-aegis-timestamp", ts_ms.to_string())
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CONFLICT);
        }
    }

    #[tokio::test]
    async fn replay_middleware_different_ts_accepted() {
        let rp = Arc::new(ReplayProtection::new());
        let sk = aegis_crypto::ed25519::generate_keypair();

        // First request at ts
        let ts1 = current_ts_ms();
        let (pubkey1, sig1) = sign_request_with_ts(&sk, "GET", "/protected", b"", ts1);
        {
            let app = {
                let rp_clone = rp.clone();
                let authed = Router::new()
                    .route(
                        "/protected",
                        get(|ext: Extension<VerifiedIdentity>| async move {
                            format!("hello {}", ext.pubkey)
                        }),
                    )
                    .layer(middleware::from_fn(auth_middleware))
                    .layer(Extension(rp_clone));
                Router::new().merge(authed)
            };
            let req = Request::builder()
                .method("GET")
                .uri("/protected")
                .header("authorization", format!("NC-Ed25519 {pubkey1}:{sig1}"))
                .header("x-aegis-timestamp", ts1.to_string())
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Second request at ts+1 (different ts_ms = new request)
        let ts2 = ts1 + 1;
        let (pubkey2, sig2) = sign_request_with_ts(&sk, "GET", "/protected", b"", ts2);
        {
            let app = {
                let rp_clone = rp.clone();
                let authed = Router::new()
                    .route(
                        "/protected",
                        get(|ext: Extension<VerifiedIdentity>| async move {
                            format!("hello {}", ext.pubkey)
                        }),
                    )
                    .layer(middleware::from_fn(auth_middleware))
                    .layer(Extension(rp_clone));
                Router::new().merge(authed)
            };
            let req = Request::builder()
                .method("GET")
                .uri("/protected")
                .header("authorization", format!("NC-Ed25519 {pubkey2}:{sig2}"))
                .header("x-aegis-timestamp", ts2.to_string())
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }
}
