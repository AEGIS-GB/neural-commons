//! Evidence recorder — high-level API that the rest of the adapter uses.
//!
//! Wraps chain + store + merkle into a single interface.
//! Thread-safe: the recorder holds a Mutex around the store.

use std::path::Path;
use std::sync::Mutex;

use aegis_crypto::ed25519::{self, SigningKey};
use aegis_schemas::{Receipt, ReceiptContext, ReceiptType, receipt::generate_blinding_nonce};

use crate::chain::{self, ChainState};
use crate::merkle;
use crate::store::EvidenceStore;
use crate::EvidenceError;

/// Default number of receipts before an automatic Merkle rollup.
pub const DEFAULT_ROLLUP_THRESHOLD: u64 = 100;

/// High-level evidence recorder.
///
/// The adapter creates one `EvidenceRecorder` at startup. All evidence
/// recording flows through this struct.
pub struct EvidenceRecorder {
    store: Mutex<EvidenceStore>,
    chain_state: Mutex<ChainState>,
    signing_key: SigningKey,
    bot_id: String,
    rollup_threshold: u64,
    /// Sequence number of the last rollup's end (for computing next rollup range).
    last_rollup_seq: Mutex<u64>,
}

impl EvidenceRecorder {
    /// Create a new recorder backed by a SQLite database.
    ///
    /// If the database already contains receipts, the chain state is loaded.
    /// Otherwise, genesis state is initialized.
    pub fn new(db_path: &Path, signing_key: SigningKey) -> Result<Self, EvidenceError> {
        let store = EvidenceStore::open(db_path)?;
        let chain_state = store.get_chain_state()?;
        let bot_id = ed25519::pubkey_hex(&signing_key.verifying_key());

        Ok(EvidenceRecorder {
            store: Mutex::new(store),
            chain_state: Mutex::new(chain_state),
            signing_key,
            bot_id,
            rollup_threshold: DEFAULT_ROLLUP_THRESHOLD,
            last_rollup_seq: Mutex::new(0),
        })
    }

    /// Create a recorder backed by an in-memory database (for testing).
    pub fn new_in_memory(signing_key: SigningKey) -> Result<Self, EvidenceError> {
        let store = EvidenceStore::open_in_memory()?;
        let chain_state = chain::init_genesis();
        let bot_id = ed25519::pubkey_hex(&signing_key.verifying_key());

        Ok(EvidenceRecorder {
            store: Mutex::new(store),
            chain_state: Mutex::new(chain_state),
            signing_key,
            bot_id,
            rollup_threshold: DEFAULT_ROLLUP_THRESHOLD,
            last_rollup_seq: Mutex::new(0),
        })
    }

    /// Set the rollup threshold (number of receipts between auto-rollups).
    pub fn set_rollup_threshold(&mut self, threshold: u64) {
        self.rollup_threshold = threshold;
    }

    /// Record a new evidence receipt.
    ///
    /// Creates the receipt with proper chain linkage and signature,
    /// appends it to storage, and updates the chain state.
    pub fn record(
        &self,
        receipt_type: ReceiptType,
        context: ReceiptContext,
    ) -> Result<Receipt, EvidenceError> {
        let mut chain_state = self.chain_state.lock()
            .map_err(|e| EvidenceError::ChainError(format!("lock poisoned: {e}")))?;

        let receipt = chain::create_receipt(
            &self.signing_key,
            &self.bot_id,
            receipt_type,
            context,
            &chain_state,
        )?;

        let new_state = chain::advance_chain_state(&chain_state, &receipt);

        let store = self.store.lock()
            .map_err(|e| EvidenceError::StoreError(format!("lock poisoned: {e}")))?;
        store.append_receipt(&receipt, &new_state)?;

        *chain_state = new_state;

        Ok(receipt)
    }

    /// Convenience: record a receipt with minimal context.
    pub fn record_simple(
        &self,
        receipt_type: ReceiptType,
        action: &str,
        outcome: &str,
    ) -> Result<Receipt, EvidenceError> {
        let context = ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: Some(action.to_string()),
            subject: None,
            trigger: None,
            outcome: Some(outcome.to_string()),
            detail: None,
            enterprise: None,
        };
        self.record(receipt_type, context)
    }

    /// Create a Merkle rollup covering receipts since the last rollup.
    pub fn rollup(&self) -> Result<Receipt, EvidenceError> {
        let store = self.store.lock()
            .map_err(|e| EvidenceError::StoreError(format!("lock poisoned: {e}")))?;
        let mut chain_state = self.chain_state.lock()
            .map_err(|e| EvidenceError::ChainError(format!("lock poisoned: {e}")))?;
        let mut last_rollup = self.last_rollup_seq.lock()
            .map_err(|e| EvidenceError::ChainError(format!("lock poisoned: {e}")))?;

        let start_seq = *last_rollup + 1;
        let end_seq = chain_state.head_seq;

        if start_seq > end_seq {
            return Err(EvidenceError::ChainError(
                "no receipts to rollup".to_string(),
            ));
        }

        let receipts = store.get_receipts_range(start_seq, end_seq)?;
        if receipts.is_empty() {
            return Err(EvidenceError::ChainError(
                "no receipts found in range".to_string(),
            ));
        }

        let rollup_detail = merkle::build_rollup(&receipts, &chain_state);

        // Create a rollup receipt
        let rollup_context = ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: Some("merkle_rollup".to_string()),
            subject: None,
            trigger: Some("periodic".to_string()),
            outcome: Some("completed".to_string()),
            detail: Some(serde_json::to_value(&rollup_detail)?),
            enterprise: None,
        };

        let rollup_receipt = chain::create_receipt(
            &self.signing_key,
            &self.bot_id,
            ReceiptType::MerkleRollup,
            rollup_context,
            &chain_state,
        )?;

        let new_state = chain::advance_chain_state(&chain_state, &rollup_receipt);
        store.append_rollup(&rollup_detail, &rollup_receipt, &new_state)?;

        *chain_state = new_state;
        *last_rollup = end_seq;

        Ok(rollup_receipt)
    }

    /// Verify the entire evidence chain from genesis.
    pub fn verify_chain(&self) -> Result<bool, EvidenceError> {
        let store = self.store.lock()
            .map_err(|e| EvidenceError::StoreError(format!("lock poisoned: {e}")))?;
        store.verify_full_chain()
    }

    /// Export receipts for audit. Returns all receipts or a filtered range.
    pub fn export(
        &self,
        start_seq: Option<u64>,
        end_seq: Option<u64>,
    ) -> Result<Vec<Receipt>, EvidenceError> {
        let store = self.store.lock()
            .map_err(|e| EvidenceError::StoreError(format!("lock poisoned: {e}")))?;
        let chain_state = self.chain_state.lock()
            .map_err(|e| EvidenceError::ChainError(format!("lock poisoned: {e}")))?;

        let start = start_seq.unwrap_or(1);
        let end = end_seq.unwrap_or(chain_state.head_seq);
        store.get_receipts_range(start, end)
    }

    /// Get the current chain head info.
    pub fn chain_head(&self) -> ChainState {
        self.chain_state.lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| chain::init_genesis())
    }

    /// Get the bot ID (public key hex).
    pub fn bot_id(&self) -> &str {
        &self.bot_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::ed25519::generate_keypair;
    use aegis_schemas::GENESIS_PREV_HASH;

    #[test]
    fn recorder_basic_flow() {
        let key = generate_keypair();
        let recorder = EvidenceRecorder::new_in_memory(key).unwrap();

        // Genesis state
        let head = recorder.chain_head();
        assert_eq!(head.head_seq, 0);
        assert_eq!(head.head_hash, GENESIS_PREV_HASH);

        // Record first receipt
        let r1 = recorder.record_simple(
            ReceiptType::ApiCall,
            "chat_completion",
            "forwarded",
        ).unwrap();
        assert_eq!(r1.core.seq, 1);
        assert_eq!(r1.core.prev_hash, GENESIS_PREV_HASH);

        // Record second
        let r2 = recorder.record_simple(
            ReceiptType::SlmAnalysis,
            "screen_prompt",
            "admitted",
        ).unwrap();
        assert_eq!(r2.core.seq, 2);

        // Chain head updated
        let head = recorder.chain_head();
        assert_eq!(head.head_seq, 2);
        assert_eq!(head.receipt_count, 2);
    }

    #[test]
    fn recorder_verify_chain() {
        let key = generate_keypair();
        let recorder = EvidenceRecorder::new_in_memory(key).unwrap();

        for i in 0..5 {
            recorder.record_simple(
                ReceiptType::ApiCall,
                &format!("action_{i}"),
                "ok",
            ).unwrap();
        }

        assert!(recorder.verify_chain().unwrap());
    }

    #[test]
    fn recorder_rollup() {
        let key = generate_keypair();
        let recorder = EvidenceRecorder::new_in_memory(key).unwrap();

        for _ in 0..10 {
            recorder.record_simple(ReceiptType::ApiCall, "test", "ok").unwrap();
        }

        let rollup_receipt = recorder.rollup().unwrap();
        assert_eq!(rollup_receipt.core.receipt_type, ReceiptType::MerkleRollup);
        assert_eq!(rollup_receipt.core.seq, 11); // 10 receipts + 1 rollup

        // Verify chain still valid after rollup
        assert!(recorder.verify_chain().unwrap());
    }

    #[test]
    fn recorder_export() {
        let key = generate_keypair();
        let recorder = EvidenceRecorder::new_in_memory(key).unwrap();

        for _ in 0..5 {
            recorder.record_simple(ReceiptType::ApiCall, "test", "ok").unwrap();
        }

        let all = recorder.export(None, None).unwrap();
        assert_eq!(all.len(), 5);

        let partial = recorder.export(Some(2), Some(4)).unwrap();
        assert_eq!(partial.len(), 3);
        assert_eq!(partial[0].core.seq, 2);
        assert_eq!(partial[2].core.seq, 4);
    }

    #[test]
    fn recorder_rollup_empty_fails() {
        let key = generate_keypair();
        let recorder = EvidenceRecorder::new_in_memory(key).unwrap();

        assert!(recorder.rollup().is_err());
    }
}
