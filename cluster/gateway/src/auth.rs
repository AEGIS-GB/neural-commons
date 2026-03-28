//! NC-Ed25519 stateless request signing (D3)
//!
//! HTTP: `Authorization: NC-Ed25519 <pubkey>:<sig>`
//!   sig = Ed25519(transport_key, JCS({method, path, ts_ms, body_hash}))
//!   Gateway validates statelessly, rejects ts_ms outside ±15s.
//!
//! WSS: Challenge-response on upgrade handshake only (one-time).
//!
//! Transport auth key: derived via m/44'/784'/3'/0' (D0).
//! Verifiers map transport pubkey → bot identity via cluster-registered key hierarchy.

use serde::{Deserialize, Serialize};

/// Maximum clock skew for request timestamps (±15 seconds)
pub const MAX_CLOCK_SKEW_MS: i64 = 15_000;

/// Request signing input — JCS-canonicalized before signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningInput {
    /// HTTP method (uppercase: GET, POST, etc.)
    pub method: String,
    /// Request path (e.g., "/evidence/batch")
    pub path: String,
    /// Unix epoch milliseconds
    pub ts_ms: i64,
    /// SHA-256 of request body, lowercase hex. Empty body = hash of empty bytes.
    pub body_hash: String,
}

/// Parsed NC-Ed25519 authorization header
#[derive(Debug, Clone)]
pub struct NcAuth {
    /// Transport public key, lowercase hex (32 bytes = 64 hex chars)
    pub pubkey: String,
    /// Ed25519 signature, lowercase hex (64 bytes = 128 hex chars)
    pub sig: String,
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

/// Validate request timestamp is within ±15s of current time
pub fn validate_timestamp(request_ts_ms: i64, current_ts_ms: i64) -> bool {
    let diff = (request_ts_ms - current_ts_ms).abs();
    diff <= MAX_CLOCK_SKEW_MS
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
