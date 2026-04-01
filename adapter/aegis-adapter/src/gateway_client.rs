//! Gateway client -- pushes evidence to the cluster Gateway.
//!
//! Periodically batches local receipts and POSTs them to the Gateway.
//! Uses NC-Ed25519 signing for authentication (D3).
//!
//! The gateway expects `SubmittedReceipt` objects (receipt core fields only,
//! no context). This module converts `Receipt` to the gateway wire format
//! before sending.

use std::sync::Arc;

use aegis_crypto::ed25519::SigningKey;

/// Receipt core in the format expected by the Gateway's POST /evidence/batch.
#[derive(Debug, serde::Serialize)]
struct SubmittedReceipt {
    id: String,
    #[serde(rename = "type")]
    receipt_type: String,
    ts_ms: i64,
    seq: i64,
    prev_hash: String,
    payload_hash: String,
    sig: String,
    receipt_hash: String,
}

/// Gateway HTTP client for pushing evidence batches.
pub struct GatewayClient {
    gateway_url: String,
    signing_key: Arc<SigningKey>,
    http_client: reqwest::Client,
    /// Last receipt sequence number that was successfully pushed.
    last_pushed_seq: std::sync::atomic::AtomicU64,
}

impl GatewayClient {
    /// Create a new GatewayClient.
    ///
    /// `gateway_url` is the base URL of the Gateway (e.g. "http://gateway:8080").
    /// Trailing slashes are stripped.
    pub fn new(gateway_url: &str, signing_key: Arc<SigningKey>) -> Self {
        Self {
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            signing_key,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
            last_pushed_seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Sign a request using NC-Ed25519 (D3).
    ///
    /// Returns `(Authorization header value, X-Aegis-Timestamp header value)`.
    fn sign_request(&self, method: &str, path: &str, body: &[u8]) -> (String, String) {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let body_hash = hex::encode(aegis_crypto::hash(body));

        // Build signing input per D3: {body_hash, method, path, ts_ms}
        let signing_input = serde_json::json!({
            "method": method,
            "path": path,
            "ts_ms": ts_ms,
            "body_hash": body_hash,
        });

        let canonical = aegis_crypto::rfc8785::canonicalize(&signing_input)
            .expect("failed to canonicalize signing input");

        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(&canonical);
        let pubkey_hex = aegis_crypto::ed25519::pubkey_hex(&self.signing_key.verifying_key());
        let sig_hex = hex::encode(signature.to_bytes());

        let auth = format!("NC-Ed25519 {}:{}", pubkey_hex, sig_hex);
        let ts = ts_ms.to_string();

        (auth, ts)
    }

    /// Push a batch of receipts to the Gateway.
    ///
    /// Converts each `Receipt` to the gateway wire format (core fields only,
    /// context is never sent to the cluster) and POSTs to `/evidence/batch`.
    pub async fn push_evidence_batch(
        &self,
        receipts: &[aegis_schemas::Receipt],
    ) -> Result<(), String> {
        if receipts.is_empty() {
            return Ok(());
        }

        // Convert to gateway wire format
        let submitted: Vec<SubmittedReceipt> = receipts
            .iter()
            .map(|r| {
                let receipt_hash = aegis_evidence::chain::compute_receipt_hash(&r.core);
                // Serialize receipt_type via serde to get snake_case string
                let receipt_type_str = serde_json::to_value(&r.core.receipt_type)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_else(|| "unknown".to_string());
                SubmittedReceipt {
                    id: r.core.id.to_string(),
                    receipt_type: receipt_type_str,
                    ts_ms: r.core.ts_ms,
                    seq: r.core.seq as i64,
                    prev_hash: r.core.prev_hash.clone(),
                    payload_hash: r.core.payload_hash.clone(),
                    sig: r.core.sig.clone(),
                    receipt_hash,
                }
            })
            .collect();

        let body =
            serde_json::to_vec(&submitted).map_err(|e| format!("failed to serialize: {e}"))?;

        let path = "/evidence/batch";
        let (auth, ts) = self.sign_request("POST", path, &body);

        let url = format!("{}{}", self.gateway_url, path);
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", auth)
            .header("X-Aegis-Timestamp", ts)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("gateway request failed: {e}"))?;

        if resp.status().is_success() {
            tracing::info!(count = receipts.len(), "evidence batch pushed to gateway");
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(format!("gateway returned {}: {}", status, text))
        }
    }

    /// Get the last pushed sequence number.
    pub fn last_pushed_seq(&self) -> u64 {
        self.last_pushed_seq
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Update the last pushed sequence number.
    pub fn set_last_pushed_seq(&self, seq: u64) {
        self.last_pushed_seq
            .store(seq, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Maximum receipts per batch push (matches gateway limit).
const BATCH_SIZE: usize = 100;

/// Evidence push interval in seconds.
const PUSH_INTERVAL_SECS: u64 = 30;

/// Spawn a background task that periodically pushes new evidence to the Gateway.
///
/// Runs every 30 seconds. Exports receipts since `last_pushed_seq` from the
/// evidence recorder and pushes them in batches of up to 100.
pub fn spawn_evidence_push_task(
    client: Arc<GatewayClient>,
    evidence: Arc<aegis_evidence::EvidenceRecorder>,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(PUSH_INTERVAL_SECS));
        interval.tick().await; // skip immediate first tick

        loop {
            interval.tick().await;

            let last_seq = client.last_pushed_seq();
            let head_seq = evidence.chain_head().head_seq;

            if head_seq <= last_seq {
                continue; // nothing new
            }

            // Export new receipts (start_seq is inclusive in the export API)
            let start = if last_seq == 0 { 1 } else { last_seq + 1 };
            let receipts = match evidence.export(Some(start), Some(head_seq)) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("gateway push: failed to export receipts: {e}");
                    continue;
                }
            };

            if receipts.is_empty() {
                continue;
            }

            // Push in batches of BATCH_SIZE
            let mut all_ok = true;
            for chunk in receipts.chunks(BATCH_SIZE) {
                match client.push_evidence_batch(chunk).await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!("gateway push failed: {e}");
                        all_ok = false;
                        break;
                    }
                }
            }

            if all_ok {
                // Update last_pushed_seq to the highest seq we actually exported
                if let Some(last) = receipts.last() {
                    client.set_last_pushed_seq(last.core.seq);
                }
            }
        }
    });
    tracing::info!(
        interval_secs = PUSH_INTERVAL_SECS,
        batch_size = BATCH_SIZE,
        "gateway evidence push task started"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::ed25519::generate_keypair;

    #[test]
    fn sign_request_produces_valid_auth_header() {
        let key = generate_keypair();
        let client = GatewayClient::new("http://localhost:8080", Arc::new(key));

        let body = b"test body";
        let (auth, ts) = client.sign_request("POST", "/evidence/batch", body);

        // Auth header format: "NC-Ed25519 <pubkey_hex>:<sig_hex>"
        assert!(
            auth.starts_with("NC-Ed25519 "),
            "auth should start with NC-Ed25519"
        );
        let parts: Vec<&str> = auth["NC-Ed25519 ".len()..].split(':').collect();
        assert_eq!(parts.len(), 2, "auth should have pubkey:sig format");
        assert_eq!(
            parts[0].len(),
            64,
            "pubkey should be 32 bytes hex (64 chars)"
        );
        assert_eq!(
            parts[1].len(),
            128,
            "signature should be 64 bytes hex (128 chars)"
        );

        // Timestamp should be a valid number
        let ts_val: i64 = ts.parse().expect("timestamp should be a number");
        assert!(ts_val > 0, "timestamp should be positive");
    }

    #[tokio::test]
    async fn push_empty_batch_is_ok() {
        let key = generate_keypair();
        let client = GatewayClient::new("http://localhost:8080", Arc::new(key));

        let result = client.push_evidence_batch(&[]).await;
        assert!(result.is_ok(), "empty batch should return Ok");
    }

    #[test]
    fn last_pushed_seq_default_is_zero() {
        let key = generate_keypair();
        let client = GatewayClient::new("http://localhost:8080", Arc::new(key));
        assert_eq!(client.last_pushed_seq(), 0);
    }

    #[test]
    fn last_pushed_seq_round_trip() {
        let key = generate_keypair();
        let client = GatewayClient::new("http://localhost:8080", Arc::new(key));
        client.set_last_pushed_seq(42);
        assert_eq!(client.last_pushed_seq(), 42);
    }

    #[test]
    fn gateway_url_strips_trailing_slash() {
        let key = generate_keypair();
        let client = GatewayClient::new("http://localhost:8080/", Arc::new(key));
        assert_eq!(client.gateway_url, "http://localhost:8080");
    }

    #[test]
    fn sign_request_different_bodies_produce_different_sigs() {
        let key = generate_keypair();
        let client = GatewayClient::new("http://localhost:8080", Arc::new(key));

        let (auth1, _) = client.sign_request("POST", "/evidence/batch", b"body1");
        let (auth2, _) = client.sign_request("POST", "/evidence/batch", b"body2");

        // Different body content should produce different signatures
        assert_ne!(
            auth1, auth2,
            "different bodies should produce different signatures"
        );
    }
}
