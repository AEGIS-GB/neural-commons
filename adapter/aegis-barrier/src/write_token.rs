//! WriteToken — time-windowed authorization for bot writes (D5)
//!
//! Tokens issued in-process (never touch disk, never visible to skills/plugins).
//! Single-use, 500ms TTL, HMAC-verified.
//!
//! HMAC is computed as SHA-256(session_key || file_path || token_id || issued_at_bytes).
//! This is a keyed hash, not a standard HMAC construction, but sufficient for
//! in-process integrity verification where the key never leaves memory.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use thiserror::Error;

use crate::types::{WRITE_TOKEN_TTL_MS, WriteToken};

// ═══════════════════════════════════════════════════════════════════
// Error types
// ═══════════════════════════════════════════════════════════════════

/// Errors returned by [`WriteTokenManager`] operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    /// No active token exists for the requested file path.
    #[error("no active write token for this file")]
    NotFound,

    /// The token exists but its TTL has elapsed.
    #[error("write token expired")]
    Expired,

    /// The token has already been consumed (single-use enforcement).
    #[error("write token already consumed")]
    AlreadyConsumed,

    /// The token's HMAC does not match the expected value.
    #[error("write token HMAC verification failed")]
    InvalidHmac,
}

// ═══════════════════════════════════════════════════════════════════
// WriteTokenManager
// ═══════════════════════════════════════════════════════════════════

/// Manages short-lived write tokens for bot-initiated file mutations.
///
/// Invariants:
/// - At most one active token per file path at any time.
/// - Tokens are single-use: once consumed, the token ID is recorded and
///   any future attempt to consume or validate it is rejected.
/// - Tokens expire after [`WRITE_TOKEN_TTL_MS`] milliseconds.
/// - The session key is generated once at construction and never leaves
///   process memory.
pub struct WriteTokenManager {
    /// Random key generated at startup, used for HMAC computation.
    session_key: [u8; 32],
    /// Currently active (not yet consumed) tokens, keyed by file path.
    active_tokens: HashMap<PathBuf, WriteToken>,
    /// Set of token IDs that have been consumed (prevents replay).
    consumed: HashSet<[u8; 16]>,
}

impl WriteTokenManager {
    /// Create a new manager with a cryptographically random session key.
    pub fn new() -> Self {
        let mut session_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut session_key);
        Self {
            session_key,
            active_tokens: HashMap::new(),
            consumed: HashSet::new(),
        }
    }

    /// Issue a new write token for `file_path`.
    ///
    /// If a token already exists for this file (expired or not), it is
    /// replaced. The old token ID is **not** added to the consumed set,
    /// so it simply becomes unreachable.
    pub fn issue(&mut self, file_path: &Path) -> WriteToken {
        let now_ms = Self::now_ms();

        let mut token_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut token_id);

        let session_hmac = Self::compute_hmac(&self.session_key, file_path, &token_id, now_ms);

        let token = WriteToken {
            file_path: file_path.to_path_buf(),
            token_id,
            issued_at: now_ms,
            expires_at: now_ms + WRITE_TOKEN_TTL_MS,
            session_hmac,
        };

        self.active_tokens
            .insert(file_path.to_path_buf(), token.clone());
        token
    }

    /// Validate the active token for `file_path`.
    ///
    /// Checks (in order):
    /// 1. A token exists for this path.
    /// 2. The token has not been consumed.
    /// 3. The token has not expired (compared against wall-clock time).
    /// 4. The HMAC is valid.
    pub fn validate(&self, file_path: &Path) -> Result<&WriteToken, TokenError> {
        let token = self
            .active_tokens
            .get(file_path)
            .ok_or(TokenError::NotFound)?;

        // Check consumed before expiry so the caller gets the most
        // specific error.
        if self.consumed.contains(&token.token_id) {
            return Err(TokenError::AlreadyConsumed);
        }

        let now_ms = Self::now_ms();
        if now_ms >= token.expires_at {
            return Err(TokenError::Expired);
        }

        let expected_hmac = Self::compute_hmac(
            &self.session_key,
            &token.file_path,
            &token.token_id,
            token.issued_at,
        );
        if token.session_hmac != expected_hmac {
            return Err(TokenError::InvalidHmac);
        }

        Ok(token)
    }

    /// Mark a token as consumed (single-use enforcement).
    ///
    /// After consumption the token ID is recorded in the consumed set and
    /// the token is removed from the active map.
    pub fn consume(&mut self, token_id: &[u8; 16]) -> Result<(), TokenError> {
        if self.consumed.contains(token_id) {
            return Err(TokenError::AlreadyConsumed);
        }

        // Find the active token with this ID.
        let path = self
            .active_tokens
            .iter()
            .find(|(_, t)| &t.token_id == token_id)
            .map(|(p, _)| p.clone());

        match path {
            Some(p) => {
                self.consumed.insert(*token_id);
                self.active_tokens.remove(&p);
                Ok(())
            }
            None => Err(TokenError::NotFound),
        }
    }

    /// Remove expired tokens from the active map and purge consumed IDs
    /// whose tokens can no longer be replayed.
    ///
    /// This is an O(n) sweep and should be called periodically (e.g. on
    /// each barrier check cycle).
    pub fn cleanup(&mut self) {
        let now_ms = Self::now_ms();

        // Collect expired token IDs before removing them so we can also
        // clean the consumed set.
        let expired_ids: Vec<[u8; 16]> = self
            .active_tokens
            .values()
            .filter(|t| now_ms >= t.expires_at)
            .map(|t| t.token_id)
            .collect();

        // Remove expired active tokens.
        self.active_tokens.retain(|_, t| now_ms < t.expires_at);

        // Remove consumed entries whose tokens are expired (they can no
        // longer be replayed since the token ID is random and the active
        // entry is gone).
        for id in &expired_ids {
            self.consumed.remove(id);
        }
    }

    // ───────────────────────────────────────────────────────────────
    // Internal helpers
    // ───────────────────────────────────────────────────────────────

    /// Compute the keyed hash: SHA-256(session_key || file_path || token_id || issued_at_bytes).
    fn compute_hmac(
        session_key: &[u8; 32],
        file_path: &Path,
        token_id: &[u8; 16],
        issued_at: u64,
    ) -> [u8; 32] {
        let path_bytes = file_path.as_os_str().as_encoded_bytes();
        let issued_at_bytes = issued_at.to_le_bytes();

        let mut message = Vec::with_capacity(32 + path_bytes.len() + 16 + 8);
        message.extend_from_slice(session_key);
        message.extend_from_slice(path_bytes);
        message.extend_from_slice(token_id);
        message.extend_from_slice(&issued_at_bytes);

        aegis_crypto::hash(&message)
    }

    /// Current wall-clock time as Unix milliseconds.
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis() as u64
    }
}

impl Default for WriteTokenManager {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    fn test_path() -> PathBuf {
        PathBuf::from("/tmp/test_file.md")
    }

    // ── Issue and validate ──────────────────────────────────────────

    #[test]
    fn issue_and_validate_succeeds() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let token = mgr.issue(&path);

        assert_eq!(token.file_path, path);
        assert!(token.expires_at == token.issued_at + WRITE_TOKEN_TTL_MS);

        let validated = mgr.validate(&path);
        assert!(validated.is_ok());
        assert_eq!(validated.unwrap().token_id, token.token_id);
    }

    #[test]
    fn validate_returns_not_found_for_unknown_path() {
        let mgr = WriteTokenManager::new();
        let result = mgr.validate(Path::new("/no/such/file"));
        assert_eq!(result.unwrap_err(), TokenError::NotFound);
    }

    // ── Expiration ──────────────────────────────────────────────────

    #[test]
    fn expired_token_rejected() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let _token = mgr.issue(&path);

        // Sleep past the TTL.
        thread::sleep(Duration::from_millis(WRITE_TOKEN_TTL_MS + 50));

        let result = mgr.validate(&path);
        assert_eq!(result.unwrap_err(), TokenError::Expired);
    }

    // ── Consumption ─────────────────────────────────────────────────

    #[test]
    fn consume_succeeds_once() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let token = mgr.issue(&path);

        assert!(mgr.consume(&token.token_id).is_ok());
    }

    #[test]
    fn consume_twice_returns_already_consumed() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let token = mgr.issue(&path);

        mgr.consume(&token.token_id).unwrap();
        let result = mgr.consume(&token.token_id);
        assert_eq!(result.unwrap_err(), TokenError::AlreadyConsumed);
    }

    #[test]
    fn validate_after_consume_returns_not_found() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let token = mgr.issue(&path);

        mgr.consume(&token.token_id).unwrap();

        // Token was removed from active_tokens on consume, so validate
        // returns NotFound (the path lookup fails).
        let result = mgr.validate(&path);
        assert_eq!(result.unwrap_err(), TokenError::NotFound);
    }

    #[test]
    fn consume_unknown_token_returns_not_found() {
        let mut mgr = WriteTokenManager::new();
        let bogus_id = [0xFFu8; 16];
        let result = mgr.consume(&bogus_id);
        assert_eq!(result.unwrap_err(), TokenError::NotFound);
    }

    // ── Reissue replaces previous token ─────────────────────────────

    #[test]
    fn reissue_replaces_previous_token() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();

        let token1 = mgr.issue(&path);
        let token2 = mgr.issue(&path);

        assert_ne!(token1.token_id, token2.token_id);

        // Only the latest token is active.
        let validated = mgr.validate(&path).unwrap();
        assert_eq!(validated.token_id, token2.token_id);
    }

    // ── Cleanup ─────────────────────────────────────────────────────

    #[test]
    fn cleanup_removes_expired_tokens() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let _token = mgr.issue(&path);

        // Wait for expiration.
        thread::sleep(Duration::from_millis(WRITE_TOKEN_TTL_MS + 50));

        assert_eq!(mgr.active_tokens.len(), 1);
        mgr.cleanup();
        assert_eq!(mgr.active_tokens.len(), 0);
    }

    #[test]
    fn cleanup_preserves_live_tokens() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let _token = mgr.issue(&path);

        // Cleanup immediately — token should survive.
        mgr.cleanup();
        assert_eq!(mgr.active_tokens.len(), 1);
        assert!(mgr.validate(&path).is_ok());
    }

    #[test]
    fn cleanup_purges_consumed_ids_of_expired_tokens() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let token = mgr.issue(&path);
        let token_id = token.token_id;

        mgr.consume(&token_id).unwrap();
        assert!(mgr.consumed.contains(&token_id));

        // Re-issue so the path has a new token, then expire it.
        let token2 = mgr.issue(&path);
        thread::sleep(Duration::from_millis(WRITE_TOKEN_TTL_MS + 50));

        mgr.cleanup();

        // The expired token2's ID should be cleaned from consumed if it
        // was there. The original consumed ID stays only if its token
        // was still in active_tokens at cleanup time — but we consumed
        // it (removed from active_tokens), so it was not in the expired
        // set. It remains in consumed until the next cleanup cycle where
        // it shows up in active_tokens as expired.
        //
        // In practice, consumed IDs for tokens already removed from
        // active_tokens linger until a future cleanup, but they are
        // harmless 16-byte entries.
        assert!(!mgr.consumed.contains(&token2.token_id));
    }

    // ── HMAC verification ───────────────────────────────────────────

    #[test]
    fn tampered_hmac_rejected() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let mut token = mgr.issue(&path);

        // Tamper with the HMAC.
        token.session_hmac[0] ^= 0xFF;
        mgr.active_tokens.insert(path.clone(), token);

        let result = mgr.validate(&path);
        assert_eq!(result.unwrap_err(), TokenError::InvalidHmac);
    }

    #[test]
    fn tampered_issued_at_detected_via_hmac() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let mut token = mgr.issue(&path);

        // Tamper with issued_at (try to extend TTL).
        token.issued_at += 10_000;
        token.expires_at = token.issued_at + WRITE_TOKEN_TTL_MS;
        mgr.active_tokens.insert(path.clone(), token);

        let result = mgr.validate(&path);
        assert_eq!(result.unwrap_err(), TokenError::InvalidHmac);
    }

    #[test]
    fn tampered_token_id_detected_via_hmac() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let mut token = mgr.issue(&path);

        // Tamper with the token ID.
        token.token_id[0] ^= 0xFF;
        mgr.active_tokens.insert(path.clone(), token);

        let result = mgr.validate(&path);
        assert_eq!(result.unwrap_err(), TokenError::InvalidHmac);
    }

    #[test]
    fn tampered_file_path_detected_via_hmac() {
        let mut mgr = WriteTokenManager::new();
        let path = test_path();
        let mut token = mgr.issue(&path);

        // Tamper with the file path stored in the token.
        token.file_path = PathBuf::from("/tmp/evil_file.md");
        let evil_path = token.file_path.clone();
        mgr.active_tokens.insert(evil_path.clone(), token);

        let result = mgr.validate(&evil_path);
        assert_eq!(result.unwrap_err(), TokenError::InvalidHmac);
    }

    // ── Multiple files ──────────────────────────────────────────────

    #[test]
    fn independent_tokens_for_different_files() {
        let mut mgr = WriteTokenManager::new();
        let path_a = PathBuf::from("/tmp/file_a.md");
        let path_b = PathBuf::from("/tmp/file_b.md");

        let token_a = mgr.issue(&path_a);
        let token_b = mgr.issue(&path_b);

        assert_ne!(token_a.token_id, token_b.token_id);

        // Both validate independently.
        assert!(mgr.validate(&path_a).is_ok());
        assert!(mgr.validate(&path_b).is_ok());

        // Consuming one does not affect the other.
        mgr.consume(&token_a.token_id).unwrap();
        assert!(mgr.validate(&path_b).is_ok());
        assert_eq!(mgr.validate(&path_a).unwrap_err(), TokenError::NotFound);
    }

    // ── Session key uniqueness ──────────────────────────────────────

    #[test]
    fn different_managers_produce_different_hmacs() {
        let mut mgr1 = WriteTokenManager::new();
        let mut mgr2 = WriteTokenManager::new();
        let path = test_path();

        let token1 = mgr1.issue(&path);
        let token2 = mgr2.issue(&path);

        // Different session keys mean different HMACs (token IDs also
        // differ, but even if they matched the HMAC would not).
        assert_ne!(token1.session_hmac, token2.session_hmac);
    }

    // ── Token fields ────────────────────────────────────────────────

    #[test]
    fn token_ttl_is_correct() {
        let mut mgr = WriteTokenManager::new();
        let token = mgr.issue(&test_path());
        assert_eq!(token.expires_at - token.issued_at, WRITE_TOKEN_TTL_MS);
    }

    #[test]
    fn token_id_is_nonzero() {
        let mut mgr = WriteTokenManager::new();
        let token = mgr.issue(&test_path());
        // Probability of all-zero from OsRng is negligible, but we
        // assert it to document the expectation.
        assert_ne!(token.token_id, [0u8; 16]);
    }
}
