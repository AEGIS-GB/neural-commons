//! Cryptographic verification of submitted evidence receipts.
//!
//! Without this, a fresh Ed25519 identity can forge a valid-shaped evidence
//! chain with random `sig`/`receipt_hash`/`prev_hash` values, reach Tier 3
//! via the TRUSTMARK derivation, and call mesh/botawiki endpoints —
//! effectively a backdoor into the mesh.
//!
//! This module:
//! - Recomputes the Ed25519 signature over the same JCS(SigningInput) the
//!   adapter signs, using the *authenticated* sender pubkey as `bot_id` (so
//!   a caller can only push their own chain).
//! - Recomputes `receipt_hash = SHA-256(JCS(ReceiptCore))` and verifies it
//!   matches the submitted value.
//! - Verifies `prev_hash` chain linkage against the previous stored
//!   receipt (or GENESIS_PREV_HASH at seq == 1).

use aegis_crypto::rfc8785;
use aegis_schemas::{GENESIS_PREV_HASH, ReceiptCore, ReceiptType};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::routes::SubmittedReceipt;

/// Mirror of the adapter's signing input (see aegis-evidence/src/chain.rs).
/// The receipt_type is serialized as a snake_case string, which is what the
/// adapter's `ReceiptType` enum produces via `#[serde(rename_all = "snake_case")]`.
#[derive(Serialize)]
struct SigningInput<'a> {
    bot_id: &'a str,
    id: Uuid,
    payload_hash: &'a str,
    prev_hash: &'a str,
    seq: u64,
    ts_ms: i64,
    #[serde(rename = "type")]
    receipt_type: &'a str,
}

/// Verify a submitted receipt. Returns Ok(()) if every check passes.
///
/// `sender_pubkey` is the authenticated Ed25519 pubkey of the caller (from
/// NC-Ed25519 auth). It is used as `bot_id` — a caller can only push their
/// own chain.
///
/// `prev_receipt_hash` is the `receipt_hash` of the previous receipt in
/// this bot's chain (None when `receipt.seq == 1`, indicating genesis).
/// The stored `receipt_hash` on each record is the same value the adapter
/// computed as `SHA-256(JCS(ReceiptCore))`, so the gateway doesn't need to
/// reconstruct the previous core to check linkage.
pub fn verify_submitted_receipt(
    receipt: &SubmittedReceipt,
    sender_pubkey: &str,
    prev_receipt_hash: Option<&str>,
) -> Result<(), String> {
    let id = Uuid::parse_str(&receipt.id).map_err(|e| format!("invalid receipt id: {e}"))?;

    let seq: u64 = receipt
        .seq
        .try_into()
        .map_err(|_| "seq must be a positive integer".to_string())?;
    if seq == 0 {
        return Err("seq must start at 1".to_string());
    }

    let pubkey_bytes =
        hex::decode(sender_pubkey).map_err(|e| format!("invalid sender pubkey hex: {e}"))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "sender pubkey must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| format!("invalid Ed25519 pubkey: {e}"))?;

    let sig_bytes = hex::decode(&receipt.sig).map_err(|e| format!("invalid sig hex: {e}"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "sig must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_array);

    let signing_input = SigningInput {
        bot_id: sender_pubkey,
        id,
        payload_hash: &receipt.payload_hash,
        prev_hash: &receipt.prev_hash,
        seq,
        ts_ms: receipt.ts_ms,
        receipt_type: &receipt.receipt_type,
    };
    let canonical = rfc8785::canonicalize(&signing_input)
        .map_err(|e| format!("signing input canonicalization failed: {e}"))?;
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| "receipt signature verification failed".to_string())?;

    // receipt_hash = SHA-256(JCS(ReceiptCore)) — ReceiptCore includes the
    // sig, which is what makes the chain self-authenticating.
    let receipt_type_enum: ReceiptType =
        serde_json::from_value(serde_json::Value::String(receipt.receipt_type.clone()))
            .map_err(|e| format!("unknown receipt type {:?}: {e}", receipt.receipt_type))?;
    let core = ReceiptCore {
        id,
        bot_id: sender_pubkey.to_string(),
        receipt_type: receipt_type_enum,
        ts_ms: receipt.ts_ms,
        prev_hash: receipt.prev_hash.clone(),
        payload_hash: receipt.payload_hash.clone(),
        seq,
        sig: receipt.sig.clone(),
    };
    let canonical_core = rfc8785::canonicalize(&core)
        .map_err(|e| format!("receipt core canonicalization failed: {e}"))?;
    let recomputed_hash = {
        let mut h = Sha256::new();
        h.update(&canonical_core);
        hex::encode(h.finalize())
    };
    if recomputed_hash != receipt.receipt_hash {
        return Err(format!(
            "receipt_hash mismatch (expected {recomputed_hash}, got {})",
            receipt.receipt_hash
        ));
    }

    let expected_prev = prev_receipt_hash.unwrap_or(GENESIS_PREV_HASH);
    if receipt.prev_hash != expected_prev {
        return Err(format!(
            "prev_hash mismatch (expected {}, got {})",
            &expected_prev[..16],
            &receipt.prev_hash[..16.min(receipt.prev_hash.len())]
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::ed25519::{Signer, SigningKey};
    use rand::RngCore;

    fn make_signed_receipt(seq: u64, prev_hash: &str) -> (SubmittedReceipt, String) {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pubkey = hex::encode(sk.verifying_key().as_bytes());

        let id = Uuid::now_v7();
        let ts_ms = 1_700_000_000_000 + seq as i64;
        let payload_hash = "a".repeat(64);
        let receipt_type = "api_call";

        let signing_input = SigningInput {
            bot_id: &pubkey,
            id,
            payload_hash: &payload_hash,
            prev_hash,
            seq,
            ts_ms,
            receipt_type,
        };
        let canonical = rfc8785::canonicalize(&signing_input).unwrap();
        let sig = hex::encode(sk.sign(&canonical).to_bytes());

        let core = ReceiptCore {
            id,
            bot_id: pubkey.clone(),
            receipt_type: ReceiptType::ApiCall,
            ts_ms,
            prev_hash: prev_hash.to_string(),
            payload_hash: payload_hash.clone(),
            seq,
            sig: sig.clone(),
        };
        let canonical_core = rfc8785::canonicalize(&core).unwrap();
        let mut h = Sha256::new();
        h.update(&canonical_core);
        let receipt_hash = hex::encode(h.finalize());

        let submitted = SubmittedReceipt {
            id: id.to_string(),
            receipt_type: receipt_type.to_string(),
            ts_ms,
            seq: seq as i64,
            prev_hash: prev_hash.to_string(),
            payload_hash,
            sig,
            receipt_hash,
            request_id: None,
        };
        (submitted, pubkey)
    }

    #[test]
    fn valid_genesis_receipt_verifies() {
        let (r, pk) = make_signed_receipt(1, GENESIS_PREV_HASH);
        assert!(verify_submitted_receipt(&r, &pk, None).is_ok());
    }

    #[test]
    fn forged_sig_is_rejected() {
        let (mut r, pk) = make_signed_receipt(1, GENESIS_PREV_HASH);
        r.sig = "00".repeat(64);
        let err = verify_submitted_receipt(&r, &pk, None).unwrap_err();
        assert!(err.contains("signature"), "got: {err}");
    }

    #[test]
    fn forged_receipt_hash_is_rejected() {
        let (mut r, pk) = make_signed_receipt(1, GENESIS_PREV_HASH);
        r.receipt_hash = "0".repeat(64);
        let err = verify_submitted_receipt(&r, &pk, None).unwrap_err();
        assert!(err.contains("receipt_hash"), "got: {err}");
    }

    #[test]
    fn wrong_prev_hash_at_genesis_is_rejected() {
        let (r, pk) = make_signed_receipt(1, &"f".repeat(64));
        let err = verify_submitted_receipt(&r, &pk, None).unwrap_err();
        assert!(err.contains("prev_hash"), "got: {err}");
    }

    #[test]
    fn mismatched_sender_pubkey_rejects_sig() {
        let (r, _a) = make_signed_receipt(1, GENESIS_PREV_HASH);
        let wrong = "b".repeat(64);
        let err = verify_submitted_receipt(&r, &wrong, None).unwrap_err();
        assert!(
            err.contains("signature") || err.contains("pubkey"),
            "got: {err}"
        );
    }
}
