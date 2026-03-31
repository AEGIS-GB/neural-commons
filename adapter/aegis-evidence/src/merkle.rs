//! Merkle rollup — periodic compression of receipt hashes into a Merkle root.
//!
//! Binary Merkle tree over receipt hashes. SHA-256 at every node.
//! Odd leaf gets promoted to the next level (no duplication).
//!
//! Used by MerkleRollup receipts to compress N receipts into one verifiable root.

use std::collections::HashMap;

use aegis_crypto::sha256;
use aegis_schemas::{Receipt, RollupDetail, RollupHistogram};

use crate::chain::{self, ChainState};

/// Compute the Merkle root of a list of hash strings (lowercase hex).
///
/// Algorithm:
/// - Leaf hashes are the input hashes (already hex-encoded SHA-256).
/// - Each pair of adjacent nodes is combined: SHA-256(left_bytes || right_bytes).
/// - If a level has an odd number of nodes, the last node is promoted as-is.
/// - Returns the final single root hash, lowercase hex.
/// - Empty input returns the hash of empty data.
pub fn compute_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return hex::encode(sha256::hash(&[]));
    }
    if hashes.len() == 1 {
        return hashes[0].clone();
    }

    let mut current_level: Vec<String> = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                // Combine pair: hash(left_bytes || right_bytes)
                let left_bytes =
                    hex::decode(&current_level[i]).expect("merkle hash must be valid hex");
                let right_bytes =
                    hex::decode(&current_level[i + 1]).expect("merkle hash must be valid hex");

                let mut combined = Vec::with_capacity(left_bytes.len() + right_bytes.len());
                combined.extend_from_slice(&left_bytes);
                combined.extend_from_slice(&right_bytes);

                let parent_hash = sha256::hash(&combined);
                next_level.push(hex::encode(parent_hash));
                i += 2;
            } else {
                // Odd node — promote as-is
                next_level.push(current_level[i].clone());
                i += 1;
            }
        }
        current_level = next_level;
    }

    current_level.into_iter().next().unwrap()
}

/// Build a rollup detail from a batch of receipts.
///
/// Collects receipt hashes, computes Merkle root, builds histogram,
/// and packages everything into a RollupDetail.
pub fn build_rollup(receipts: &[Receipt], chain_state: &ChainState) -> RollupDetail {
    assert!(
        !receipts.is_empty(),
        "cannot build rollup from empty receipts"
    );

    let seq_start = receipts.first().unwrap().core.seq;
    let seq_end = receipts.last().unwrap().core.seq;
    let receipt_count = receipts.len() as u64;

    // Compute receipt hashes for the Merkle tree
    let hashes: Vec<String> = receipts
        .iter()
        .map(|r| chain::compute_receipt_hash(&r.core))
        .collect();

    let merkle_root = compute_merkle_root(&hashes);
    let histogram = build_histogram(receipts);

    RollupDetail {
        seq_start,
        seq_end,
        receipt_count,
        merkle_root,
        head_hash: chain_state.head_hash.clone(),
        histogram,
    }
}

/// Build a histogram of receipt types from a batch of receipts.
pub fn build_histogram(receipts: &[Receipt]) -> RollupHistogram {
    let mut type_counts: HashMap<String, u64> = HashMap::new();

    for r in receipts {
        // Serialize the receipt type to get its snake_case string
        let type_str = serde_json::to_value(&r.core.receipt_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        *type_counts.entry(type_str).or_insert(0) += 1;
    }

    RollupHistogram {
        type_counts,
        severity_counts: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{advance_chain_state, create_receipt, init_genesis};
    use aegis_crypto::ed25519::{self, generate_keypair};
    use aegis_schemas::{ReceiptContext, ReceiptType, receipt::generate_blinding_nonce};

    fn make_context() -> ReceiptContext {
        ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: Some("test".to_string()),
            subject: None,
            trigger: None,
            outcome: None,
            detail: None,
            enterprise: None,
            request_id: None,
        }
    }

    #[test]
    fn test_merkle_single_hash() {
        let hash = hex::encode(aegis_crypto::sha256::hash(b"hello"));
        let root = compute_merkle_root(std::slice::from_ref(&hash));
        assert_eq!(root, hash);
    }

    #[test]
    fn test_merkle_two_hashes() {
        let h1 = hex::encode(aegis_crypto::sha256::hash(b"a"));
        let h2 = hex::encode(aegis_crypto::sha256::hash(b"b"));
        let root = compute_merkle_root(&[h1.clone(), h2.clone()]);

        // Manually compute expected
        let left = hex::decode(&h1).unwrap();
        let right = hex::decode(&h2).unwrap();
        let mut combined = Vec::new();
        combined.extend_from_slice(&left);
        combined.extend_from_slice(&right);
        let expected = hex::encode(aegis_crypto::sha256::hash(&combined));

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_three_hashes_odd_promotion() {
        let h1 = hex::encode(aegis_crypto::sha256::hash(b"a"));
        let h2 = hex::encode(aegis_crypto::sha256::hash(b"b"));
        let h3 = hex::encode(aegis_crypto::sha256::hash(b"c"));

        let root = compute_merkle_root(&[h1.clone(), h2.clone(), h3.clone()]);

        // Level 1: combine(h1, h2) and promote h3
        let left = hex::decode(&h1).unwrap();
        let right = hex::decode(&h2).unwrap();
        let mut combined = Vec::new();
        combined.extend_from_slice(&left);
        combined.extend_from_slice(&right);
        let h12 = hex::encode(aegis_crypto::sha256::hash(&combined));

        // Level 2: combine(h12, h3)
        let left2 = hex::decode(&h12).unwrap();
        let right2 = hex::decode(&h3).unwrap();
        let mut combined2 = Vec::new();
        combined2.extend_from_slice(&left2);
        combined2.extend_from_slice(&right2);
        let expected = hex::encode(aegis_crypto::sha256::hash(&combined2));

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_empty() {
        let root = compute_merkle_root(&[]);
        assert_eq!(root, hex::encode(aegis_crypto::sha256::hash(&[])));
    }

    #[test]
    fn test_merkle_deterministic() {
        let hashes: Vec<String> = (0..10)
            .map(|i| hex::encode(aegis_crypto::sha256::hash(&[i as u8])))
            .collect();
        let root1 = compute_merkle_root(&hashes);
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_build_rollup_basic() {
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();
        let mut receipts = Vec::new();

        for _ in 0..3 {
            let r = create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state)
                .unwrap();
            state = advance_chain_state(&state, &r);
            receipts.push(r);
        }

        let rollup = build_rollup(&receipts, &state);
        assert_eq!(rollup.seq_start, 1);
        assert_eq!(rollup.seq_end, 3);
        assert_eq!(rollup.receipt_count, 3);
        assert_eq!(rollup.merkle_root.len(), 64);
        assert_eq!(rollup.head_hash, state.head_hash);
    }

    #[test]
    fn test_histogram() {
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();
        let mut receipts = Vec::new();

        let types = [
            ReceiptType::ApiCall,
            ReceiptType::ApiCall,
            ReceiptType::WriteBarrier,
        ];
        for t in &types {
            let r = create_receipt(&key, &bot_id, t.clone(), make_context(), &state).unwrap();
            state = advance_chain_state(&state, &r);
            receipts.push(r);
        }

        let hist = build_histogram(&receipts);
        assert_eq!(*hist.type_counts.get("api_call").unwrap(), 2);
        assert_eq!(*hist.type_counts.get("write_barrier").unwrap(), 1);
    }
}
