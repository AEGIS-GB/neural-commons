//! Hash chain manager — prev_hash linkage, sequence numbering, receipt creation.
//!
//! Key rules (D1):
//! - Genesis: seq=1, prev_hash = GENESIS_PREV_HASH (64 zeros)
//! - Each receipt's prev_hash = SHA-256 of JCS(previous receipt's core fields including sig)
//! - Sequence numbers are monotonic, no gaps
//! - Chain verification: walk from genesis, verify each prev_hash link

use aegis_crypto::ed25519::{self, Signer as _, SigningKey};
use aegis_crypto::rfc8785;
use aegis_crypto::sha256;
use aegis_schemas::{GENESIS_PREV_HASH, Receipt, ReceiptContext, ReceiptCore, ReceiptType};
use serde::Serialize;
use uuid::Uuid;

use crate::EvidenceError;

/// Current state of the evidence hash chain.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// SHA-256 of JCS(last receipt's core), lowercase hex.
    /// For genesis state this is GENESIS_PREV_HASH.
    pub head_hash: String,
    /// Sequence number of the last receipt. 0 means no receipts yet.
    pub head_seq: u64,
    /// Total number of receipts in the chain.
    pub receipt_count: u64,
}

/// Intermediate struct for the signing input — the fields that get signed.
/// Field order doesn't matter because JCS sorts keys lexicographically.
#[derive(Serialize)]
struct SigningInput {
    bot_id: String,
    id: Uuid,
    payload_hash: String,
    prev_hash: String,
    seq: u64,
    ts_ms: i64,
    #[serde(rename = "type")]
    receipt_type: ReceiptType,
}

/// Compute the receipt hash: SHA-256 of JCS-serialized core (including sig), lowercase hex.
/// This hash becomes the prev_hash for the next receipt in the chain.
pub fn compute_receipt_hash(core: &ReceiptCore) -> String {
    let canonical = rfc8785::canonicalize(core).expect("ReceiptCore must be serializable");
    let hash_bytes = sha256::hash(&canonical);
    hex::encode(hash_bytes)
}

/// Compute the payload hash: SHA-256 of JCS-serialized context, lowercase hex.
/// This commits to the context without revealing it.
pub fn compute_payload_hash(context: &ReceiptContext) -> String {
    let canonical = rfc8785::canonicalize(context).expect("ReceiptContext must be serializable");
    let hash_bytes = sha256::hash(&canonical);
    hex::encode(hash_bytes)
}

/// Create a new receipt with proper chain linkage and Ed25519 signature.
///
/// Steps:
/// 1. Generate UUID v7 (time-ordered)
/// 2. Set ts_ms = current epoch milliseconds
/// 3. Set prev_hash from chain_state.head_hash
/// 4. Set seq = chain_state.head_seq + 1
/// 5. Compute payload_hash = SHA-256(JCS(context))
/// 6. Construct signing input = JCS({id, bot_id, type, ts_ms, prev_hash, payload_hash, seq})
/// 7. Sign with Ed25519
/// 8. Return Receipt
pub fn create_receipt(
    signing_key: &SigningKey,
    bot_id: &str,
    receipt_type: ReceiptType,
    context: ReceiptContext,
    chain_state: &ChainState,
) -> Result<Receipt, EvidenceError> {
    let id = Uuid::now_v7();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| EvidenceError::ChainError(format!("system clock error: {e}")))?
        .as_millis() as i64;
    let prev_hash = chain_state.head_hash.clone();
    let seq = chain_state.head_seq + 1;
    let payload_hash = compute_payload_hash(&context);

    // Build the signing input
    let signing_input = SigningInput {
        id,
        bot_id: bot_id.to_string(),
        receipt_type: receipt_type.clone(),
        ts_ms,
        prev_hash: prev_hash.clone(),
        payload_hash: payload_hash.clone(),
        seq,
    };

    let canonical_bytes = rfc8785::canonicalize(&signing_input)?;
    let signature = signing_key.sign(&canonical_bytes);
    let sig_hex = ed25519::signature_hex(&signature);

    let core = ReceiptCore {
        id,
        bot_id: bot_id.to_string(),
        receipt_type,
        ts_ms,
        prev_hash,
        payload_hash,
        seq,
        sig: sig_hex,
    };

    Ok(Receipt { core, context })
}

/// Verify that `current` receipt's prev_hash matches the hash of `prev` receipt's core.
pub fn verify_chain_link(current: &ReceiptCore, prev: &ReceiptCore) -> bool {
    let expected = compute_receipt_hash(prev);
    current.prev_hash == expected
}

/// Create the genesis chain state — no receipts yet.
/// head_hash = GENESIS_PREV_HASH, head_seq = 0, receipt_count = 0.
pub fn init_genesis() -> ChainState {
    ChainState {
        head_hash: GENESIS_PREV_HASH.to_string(),
        head_seq: 0,
        receipt_count: 0,
    }
}

/// Advance chain state after appending a receipt.
pub fn advance_chain_state(chain_state: &ChainState, receipt: &Receipt) -> ChainState {
    ChainState {
        head_hash: compute_receipt_hash(&receipt.core),
        head_seq: receipt.core.seq,
        receipt_count: chain_state.receipt_count + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::ed25519::generate_keypair;
    use aegis_schemas::receipt::generate_blinding_nonce;

    fn make_context() -> ReceiptContext {
        ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: Some("test_action".to_string()),
            subject: Some("test_subject".to_string()),
            trigger: Some("unit_test".to_string()),
            outcome: Some("pass".to_string()),
            detail: None,
            enterprise: None,
        }
    }

    #[test]
    fn test_genesis_state() {
        let state = init_genesis();
        assert_eq!(state.head_hash, GENESIS_PREV_HASH);
        assert_eq!(state.head_seq, 0);
        assert_eq!(state.receipt_count, 0);
    }

    #[test]
    fn test_create_first_receipt() {
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let state = init_genesis();
        let ctx = make_context();

        let receipt = create_receipt(&key, &bot_id, ReceiptType::ApiCall, ctx, &state).unwrap();
        assert_eq!(receipt.core.seq, 1);
        assert_eq!(receipt.core.prev_hash, GENESIS_PREV_HASH);
        assert!(!receipt.core.sig.is_empty());
        assert!(!receipt.core.payload_hash.is_empty());
        // All hashes are lowercase hex
        assert_eq!(
            receipt.core.prev_hash,
            receipt.core.prev_hash.to_lowercase()
        );
        assert_eq!(
            receipt.core.payload_hash,
            receipt.core.payload_hash.to_lowercase()
        );
        assert_eq!(receipt.core.sig, receipt.core.sig.to_lowercase());
    }

    #[test]
    fn test_chain_linkage() {
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let state0 = init_genesis();

        let r1 =
            create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state0).unwrap();
        let state1 = advance_chain_state(&state0, &r1);

        let r2 = create_receipt(
            &key,
            &bot_id,
            ReceiptType::WriteBarrier,
            make_context(),
            &state1,
        )
        .unwrap();

        assert_eq!(r2.core.seq, 2);
        assert!(verify_chain_link(&r2.core, &r1.core));
    }

    #[test]
    fn test_chain_link_fails_on_tamper() {
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let state0 = init_genesis();

        let r1 =
            create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state0).unwrap();
        let state1 = advance_chain_state(&state0, &r1);

        let mut r2 = create_receipt(
            &key,
            &bot_id,
            ReceiptType::WriteBarrier,
            make_context(),
            &state1,
        )
        .unwrap();
        // Tamper with prev_hash
        r2.core.prev_hash = "deadbeef".repeat(8);
        assert!(!verify_chain_link(&r2.core, &r1.core));
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let state = init_genesis();
        let ctx = make_context();

        let receipt = create_receipt(&key, &bot_id, ReceiptType::ApiCall, ctx, &state).unwrap();
        let hash1 = compute_receipt_hash(&receipt.core);
        let hash2 = compute_receipt_hash(&receipt.core);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32 bytes hex = 64 chars
    }

    #[test]
    fn test_payload_hash_matches_context() {
        let ctx = make_context();
        let h1 = compute_payload_hash(&ctx);
        let h2 = compute_payload_hash(&ctx);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_sequence_monotonic() {
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();

        for expected_seq in 1..=5 {
            let r = create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state)
                .unwrap();
            assert_eq!(r.core.seq, expected_seq);
            state = advance_chain_state(&state, &r);
        }
    }
}
