//! Edge Gateway HTTP routes (D3)
//!
//! Endpoints:
//!   POST /evidence         -- single receipt submission
//!   POST /evidence/batch   -- batch receipt submission (max 100 or 1MB)
//!   GET  /trustmark/:bot_id -- query TRUSTMARK score
//!   GET  /botawiki/query    -- Botawiki structured query
//!   GET  /verify/:fingerprint -- certificate verification (D29)
//!   POST /rollup           -- Merkle rollup submission
//!   POST /embedding        -- direct embedding via load balancer (D3 v3)
//!
//! All routes require NC-Ed25519 authentication.
//! Rate limits per D24. Credit deductions per D19.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};

use crate::auth::VerifiedIdentity;
use crate::store::{EvidenceRecord, EvidenceStore};

/// Maximum receipts per batch
pub const MAX_BATCH_SIZE: usize = 100;

/// Maximum batch body size in bytes (1MB)
pub const MAX_BATCH_BYTES: usize = 1_048_576;

/// Submitted receipt core from an adapter.
/// This is the cluster-visible portion of a receipt (no context).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SubmittedReceipt {
    /// Receipt UUID (v7)
    pub id: String,
    /// Receipt type (snake_case)
    #[serde(rename = "type")]
    pub receipt_type: String,
    /// Unix epoch milliseconds
    pub ts_ms: i64,
    /// Monotonic sequence number
    pub seq: i64,
    /// SHA-256 of previous receipt core, lowercase hex
    pub prev_hash: String,
    /// SHA-256 of context payload, lowercase hex
    pub payload_hash: String,
    /// Ed25519 signature over JCS(core fields), lowercase hex
    pub sig: String,
    /// Receipt hash (SHA-256 of signed core), lowercase hex
    pub receipt_hash: String,
    /// Pipeline request ID (optional)
    #[serde(default)]
    pub request_id: Option<String>,
}

fn validate_receipt(receipt: &SubmittedReceipt) -> Result<(), String> {
    if receipt.id.is_empty() {
        return Err("receipt id is required".to_string());
    }
    if receipt.receipt_type.is_empty() {
        return Err("receipt type is required".to_string());
    }
    if receipt.ts_ms <= 0 {
        return Err("ts_ms must be positive".to_string());
    }
    if receipt.seq <= 0 {
        return Err("seq must be positive".to_string());
    }
    if receipt.prev_hash.is_empty() {
        return Err("prev_hash is required".to_string());
    }
    if receipt.receipt_hash.is_empty() {
        return Err("receipt_hash is required".to_string());
    }
    Ok(())
}

fn receipt_to_record(
    receipt: &SubmittedReceipt,
    bot_fingerprint: &str,
) -> Result<EvidenceRecord, String> {
    let core_json = serde_json::to_string(receipt).map_err(|e| format!("serialization: {e}"))?;
    Ok(EvidenceRecord {
        id: receipt.id.clone(),
        bot_fingerprint: bot_fingerprint.to_string(),
        seq: receipt.seq,
        receipt_type: receipt.receipt_type.clone(),
        ts_ms: receipt.ts_ms,
        core_json,
        receipt_hash: receipt.receipt_hash.clone(),
        request_id: receipt.request_id.clone(),
    })
}

/// POST /evidence -- accept a single receipt core from an authenticated adapter.
pub async fn post_evidence<S: EvidenceStore>(
    Extension(identity): Extension<VerifiedIdentity>,
    Extension(store): Extension<S>,
    Json(receipt): Json<SubmittedReceipt>,
) -> impl IntoResponse {
    if let Err(e) = validate_receipt(&receipt) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        );
    }

    let record = match receipt_to_record(&receipt, &identity.pubkey) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            );
        }
    };

    let id = record.id.clone();
    match store.insert(record).await {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

/// POST /evidence/batch -- accept a batch of receipt cores.
///
/// Limits: max 100 receipts, max 1MB body.
/// Returns 201 with count on success, 413 if limits exceeded.
pub async fn post_evidence_batch<S: EvidenceStore>(
    Extension(identity): Extension<VerifiedIdentity>,
    Extension(store): Extension<S>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Check body size
    if body.len() > MAX_BATCH_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": format!("body size {} exceeds limit of {} bytes", body.len(), MAX_BATCH_BYTES)
            })),
        );
    }

    // Parse JSON array
    let receipts: Vec<SubmittedReceipt> = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid JSON: {e}") })),
            );
        }
    };

    // Check batch size
    if receipts.len() > MAX_BATCH_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": format!("batch size {} exceeds limit of {}", receipts.len(), MAX_BATCH_SIZE)
            })),
        );
    }

    if receipts.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "batch must not be empty" })),
        );
    }

    // Validate all receipts first
    for (i, receipt) in receipts.iter().enumerate() {
        if let Err(e) = validate_receipt(receipt) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("receipt[{i}]: {e}") })),
            );
        }
    }

    // Convert to records
    let mut records = Vec::with_capacity(receipts.len());
    for receipt in &receipts {
        match receipt_to_record(receipt, &identity.pubkey) {
            Ok(r) => records.push(r),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e })),
                );
            }
        }
    }

    // Batch insert
    match store.insert_batch(records).await {
        Ok(count) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "count": count })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use crate::store::MemoryStore;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::{Router, middleware};
    use ed25519_dalek::Signer;
    use tower::ServiceExt;

    fn sign_request(
        sk: &ed25519_dalek::SigningKey,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (String, String, i64) {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let body_hash = hex::encode(aegis_crypto::hash(body));
        let input = auth::SigningInput {
            body_hash,
            method: method.to_string(),
            path: path.to_string(),
            ts_ms,
        };
        let canonical = aegis_crypto::canonicalize(&input).unwrap();
        let sig = sk.sign(&canonical);
        (
            hex::encode(sk.verifying_key().as_bytes()),
            hex::encode(sig.to_bytes()),
            ts_ms,
        )
    }

    fn test_app(store: MemoryStore) -> Router {
        let authed = Router::new()
            .route("/evidence", post(post_evidence::<MemoryStore>))
            .route("/evidence/batch", post(post_evidence_batch::<MemoryStore>))
            .layer(Extension(store))
            .layer(middleware::from_fn(auth::auth_middleware));

        Router::new().merge(authed)
    }

    fn sample_receipt_json() -> serde_json::Value {
        serde_json::json!({
            "id": "01234567-89ab-cdef-0123-456789abcdef",
            "type": "api_call",
            "ts_ms": 1700000000000i64,
            "seq": 1,
            "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "payload_hash": "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb",
            "sig": "a".repeat(128),
            "receipt_hash": "deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb",
        })
    }

    #[tokio::test]
    async fn post_evidence_returns_201() {
        let store = MemoryStore::new();
        let app = test_app(store.clone());
        let sk = aegis_crypto::ed25519::generate_keypair();
        let body = serde_json::to_vec(&sample_receipt_json()).unwrap();
        let (pubkey, sig, ts_ms) = sign_request(&sk, "POST", "/evidence", &body);

        let req = Request::builder()
            .method("POST")
            .uri("/evidence")
            .header("content-type", "application/json")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], "01234567-89ab-cdef-0123-456789abcdef");

        // Verify stored
        let count = store.count_for_bot(&pubkey).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn post_evidence_unauthenticated_returns_401() {
        let store = MemoryStore::new();
        let app = test_app(store);
        let body = serde_json::to_vec(&sample_receipt_json()).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/evidence")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_evidence_invalid_receipt_returns_400() {
        let store = MemoryStore::new();
        let app = test_app(store);
        let sk = aegis_crypto::ed25519::generate_keypair();
        let bad_receipt = serde_json::json!({
            "id": "",
            "type": "api_call",
            "ts_ms": 1700000000000i64,
            "seq": 1,
            "prev_hash": "0000",
            "payload_hash": "aabb",
            "sig": "a".repeat(128),
            "receipt_hash": "dead",
        });
        let body = serde_json::to_vec(&bad_receipt).unwrap();
        let (pubkey, sig, ts_ms) = sign_request(&sk, "POST", "/evidence", &body);

        let req = Request::builder()
            .method("POST")
            .uri("/evidence")
            .header("content-type", "application/json")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_evidence_duplicate_returns_error() {
        let store = MemoryStore::new();
        let app = test_app(store.clone());
        let sk = aegis_crypto::ed25519::generate_keypair();

        // Insert first
        let body = serde_json::to_vec(&sample_receipt_json()).unwrap();
        let (pubkey, sig, ts_ms) = sign_request(&sk, "POST", "/evidence", &body);
        let req = Request::builder()
            .method("POST")
            .uri("/evidence")
            .header("content-type", "application/json")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Try duplicate
        let app2 = test_app(store);
        let body2 = serde_json::to_vec(&sample_receipt_json()).unwrap();
        let (pubkey2, sig2, ts_ms2) = sign_request(&sk, "POST", "/evidence", &body2);
        let req2 = Request::builder()
            .method("POST")
            .uri("/evidence")
            .header("content-type", "application/json")
            .header("authorization", format!("NC-Ed25519 {pubkey2}:{sig2}"))
            .header("x-aegis-timestamp", ts_ms2.to_string())
            .body(Body::from(body2))
            .unwrap();
        let resp2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── Batch endpoint tests ──

    fn make_batch(count: usize) -> Vec<serde_json::Value> {
        (0..count)
            .map(|i| {
                serde_json::json!({
                    "id": format!("receipt-{i:04}"),
                    "type": "api_call",
                    "ts_ms": 1700000000000i64 + i as i64,
                    "seq": i as i64 + 1,
                    "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "payload_hash": "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb",
                    "sig": "a".repeat(128),
                    "receipt_hash": format!("{:064x}", i),
                })
            })
            .collect()
    }

    #[tokio::test]
    async fn batch_50_receipts_returns_201() {
        let store = MemoryStore::new();
        let app = test_app(store.clone());
        let sk = aegis_crypto::ed25519::generate_keypair();
        let batch = make_batch(50);
        let body = serde_json::to_vec(&batch).unwrap();
        let (pubkey, sig, ts_ms) = sign_request(&sk, "POST", "/evidence/batch", &body);

        let req = Request::builder()
            .method("POST")
            .uri("/evidence/batch")
            .header("content-type", "application/json")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["count"], 50);

        let count = store.count_for_bot(&pubkey).await.unwrap();
        assert_eq!(count, 50);
    }

    #[tokio::test]
    async fn batch_101_receipts_returns_413() {
        let store = MemoryStore::new();
        let app = test_app(store);
        let sk = aegis_crypto::ed25519::generate_keypair();
        let batch = make_batch(101);
        let body = serde_json::to_vec(&batch).unwrap();
        let (pubkey, sig, ts_ms) = sign_request(&sk, "POST", "/evidence/batch", &body);

        let req = Request::builder()
            .method("POST")
            .uri("/evidence/batch")
            .header("content-type", "application/json")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn batch_empty_returns_400() {
        let store = MemoryStore::new();
        let app = test_app(store);
        let sk = aegis_crypto::ed25519::generate_keypair();
        let batch: Vec<serde_json::Value> = vec![];
        let body = serde_json::to_vec(&batch).unwrap();
        let (pubkey, sig, ts_ms) = sign_request(&sk, "POST", "/evidence/batch", &body);

        let req = Request::builder()
            .method("POST")
            .uri("/evidence/batch")
            .header("content-type", "application/json")
            .header("authorization", format!("NC-Ed25519 {pubkey}:{sig}"))
            .header("x-aegis-timestamp", ts_ms.to_string())
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn batch_unauthenticated_returns_401() {
        let store = MemoryStore::new();
        let app = test_app(store);
        let batch = make_batch(5);
        let body = serde_json::to_vec(&batch).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/evidence/batch")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
