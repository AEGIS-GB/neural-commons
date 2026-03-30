//! SQLite WAL-mode storage for receipts and chain state.
//!
//! Append-only for receipts. Updateable for chain_state.
//! Single-writer design — only one EvidenceStore per adapter instance.

use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

use aegis_schemas::{Receipt, ReceiptContext, ReceiptCore};

use crate::EvidenceError;
use crate::chain::{self, ChainState};

/// SQLite-backed evidence storage.
pub struct EvidenceStore {
    db: Connection,
}

impl EvidenceStore {
    /// Open or create an evidence database at `path`.
    /// Enables WAL mode and creates tables if they don't exist.
    pub fn open(path: &Path) -> Result<Self, EvidenceError> {
        let db = Connection::open(path)
            .map_err(|e| EvidenceError::StoreError(format!("failed to open db: {e}")))?;

        // Enable WAL mode for concurrent reads
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| EvidenceError::StoreError(format!("pragma failed: {e}")))?;

        init_tables(&db)?;

        Ok(EvidenceStore { db })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, EvidenceError> {
        let db = Connection::open_in_memory()
            .map_err(|e| EvidenceError::StoreError(format!("failed to open in-memory db: {e}")))?;
        init_tables(&db)?;
        Ok(EvidenceStore { db })
    }

    /// Append a receipt and update chain state in a single transaction.
    pub fn append_receipt(
        &self,
        receipt: &Receipt,
        new_chain_state: &ChainState,
    ) -> Result<(), EvidenceError> {
        let core_json = serde_json::to_string(&receipt.core)?;
        let context_json = serde_json::to_string(&receipt.context)?;
        let receipt_hash = chain::compute_receipt_hash(&receipt.core);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|e| EvidenceError::StoreError(format!("tx start failed: {e}")))?;

        tx.execute(
            "INSERT INTO receipts (id, seq, core_json, context_json, receipt_hash, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                receipt.core.id.to_string(),
                receipt.core.seq as i64,
                core_json,
                context_json,
                receipt_hash,
                now_ms,
            ],
        )?;

        tx.execute(
            "INSERT OR REPLACE INTO chain_state (id, head_hash, head_seq, receipt_count) VALUES (1, ?1, ?2, ?3)",
            params![
                new_chain_state.head_hash,
                new_chain_state.head_seq as i64,
                new_chain_state.receipt_count as i64,
            ],
        )?;

        tx.commit()
            .map_err(|e| EvidenceError::StoreError(format!("tx commit failed: {e}")))?;

        Ok(())
    }

    /// Get the current chain state. Returns genesis if no receipts exist.
    pub fn get_chain_state(&self) -> Result<ChainState, EvidenceError> {
        let result = self
            .db
            .query_row(
                "SELECT head_hash, head_seq, receipt_count FROM chain_state WHERE id = 1",
                [],
                |row| {
                    Ok(ChainState {
                        head_hash: row.get(0)?,
                        head_seq: row.get::<_, i64>(1)? as u64,
                        receipt_count: row.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()?;

        Ok(result.unwrap_or_else(chain::init_genesis))
    }

    /// Get a receipt by sequence number.
    pub fn get_receipt_by_seq(&self, seq: u64) -> Result<Option<Receipt>, EvidenceError> {
        let result = self
            .db
            .query_row(
                "SELECT core_json, context_json FROM receipts WHERE seq = ?1",
                params![seq as i64],
                |row| {
                    let core_json: String = row.get(0)?;
                    let context_json: String = row.get(1)?;
                    Ok((core_json, context_json))
                },
            )
            .optional()?;

        match result {
            Some((core_json, context_json)) => {
                let core: ReceiptCore = serde_json::from_str(&core_json)?;
                let context: ReceiptContext = serde_json::from_str(&context_json)?;
                Ok(Some(Receipt { core, context }))
            }
            None => Ok(None),
        }
    }

    /// Get receipts in a sequence range (inclusive, for Merkle rollup).
    pub fn get_receipts_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<Receipt>, EvidenceError> {
        let mut stmt = self.db.prepare(
            "SELECT core_json, context_json FROM receipts WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq ASC",
        )?;

        let rows = stmt.query_map(params![start_seq as i64, end_seq as i64], |row| {
            let core_json: String = row.get(0)?;
            let context_json: String = row.get(1)?;
            Ok((core_json, context_json))
        })?;

        let mut receipts = Vec::new();
        for row in rows {
            let (core_json, context_json) = row?;
            let core: ReceiptCore = serde_json::from_str(&core_json)
                .map_err(|e| EvidenceError::SerializationError(e.to_string()))?;
            let context: ReceiptContext = serde_json::from_str(&context_json)
                .map_err(|e| EvidenceError::SerializationError(e.to_string()))?;
            receipts.push(Receipt { core, context });
        }

        Ok(receipts)
    }

    /// Store a Merkle rollup alongside its receipt.
    pub fn append_rollup(
        &self,
        rollup: &aegis_schemas::RollupDetail,
        receipt: &Receipt,
        new_chain_state: &ChainState,
    ) -> Result<(), EvidenceError> {
        let detail_json = serde_json::to_string(rollup)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|e| EvidenceError::StoreError(format!("tx start failed: {e}")))?;

        // Store the rollup receipt as a regular receipt
        let core_json = serde_json::to_string(&receipt.core)?;
        let context_json = serde_json::to_string(&receipt.context)?;
        let receipt_hash = chain::compute_receipt_hash(&receipt.core);

        tx.execute(
            "INSERT INTO receipts (id, seq, core_json, context_json, receipt_hash, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                receipt.core.id.to_string(),
                receipt.core.seq as i64,
                core_json,
                context_json,
                receipt_hash,
                now_ms,
            ],
        )?;

        // Store rollup metadata
        tx.execute(
            "INSERT INTO rollups (id, seq_start, seq_end, merkle_root, detail_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                receipt.core.id.to_string(),
                rollup.seq_start as i64,
                rollup.seq_end as i64,
                rollup.merkle_root,
                detail_json,
                now_ms,
            ],
        )?;

        // Update chain state
        tx.execute(
            "INSERT OR REPLACE INTO chain_state (id, head_hash, head_seq, receipt_count) VALUES (1, ?1, ?2, ?3)",
            params![
                new_chain_state.head_hash,
                new_chain_state.head_seq as i64,
                new_chain_state.receipt_count as i64,
            ],
        )?;

        tx.commit()
            .map_err(|e| EvidenceError::StoreError(format!("tx commit failed: {e}")))?;

        Ok(())
    }

    /// Total receipt count.
    pub fn get_receipt_count(&self) -> Result<u64, EvidenceError> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Verify the entire hash chain from genesis.
    /// Returns true if every receipt's prev_hash matches the hash of the previous receipt.
    pub fn verify_full_chain(&self) -> Result<bool, EvidenceError> {
        let count = self.get_receipt_count()?;
        if count == 0 {
            return Ok(true);
        }

        let mut prev_hash = aegis_schemas::GENESIS_PREV_HASH.to_string();

        for seq in 1..=count {
            let receipt = self.get_receipt_by_seq(seq)?.ok_or_else(|| {
                EvidenceError::ChainError(format!("missing receipt at seq {seq}"))
            })?;

            if receipt.core.prev_hash != prev_hash {
                tracing::error!(
                    seq = seq,
                    expected = prev_hash,
                    actual = receipt.core.prev_hash,
                    "chain link broken"
                );
                return Ok(false);
            }

            prev_hash = chain::compute_receipt_hash(&receipt.core);
        }

        Ok(true)
    }

    /// Create a backup of the evidence database at the given path.
    ///
    /// Uses SQLite's `VACUUM INTO` to create a consistent, compacted copy.
    /// The destination file must not already exist.
    pub fn backup(&self, dest: &Path) -> Result<(), EvidenceError> {
        let dest_str = dest.to_str().ok_or_else(|| {
            EvidenceError::StoreError("backup path contains invalid UTF-8".to_string())
        })?;
        self.db
            .execute_batch(&format!("VACUUM INTO '{}'", dest_str.replace('\'', "''")))
            .map_err(|e| EvidenceError::StoreError(format!("backup failed: {e}")))?;
        Ok(())
    }

    /// Run SQLite integrity check on the evidence database.
    ///
    /// Returns `Ok(())` if the database passes integrity check,
    /// or an error describing the integrity failure.
    pub fn integrity_check(&self) -> Result<(), EvidenceError> {
        let result: String = self
            .db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|e| EvidenceError::StoreError(format!("integrity_check failed: {e}")))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(EvidenceError::StoreError(format!(
                "integrity check failed: {result}"
            )))
        }
    }
}

/// Create database tables if they don't exist.
fn init_tables(db: &Connection) -> Result<(), EvidenceError> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS receipts (
            id TEXT PRIMARY KEY,
            seq INTEGER NOT NULL UNIQUE,
            core_json TEXT NOT NULL,
            context_json TEXT NOT NULL,
            receipt_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chain_state (
            id INTEGER PRIMARY KEY DEFAULT 1,
            head_hash TEXT NOT NULL,
            head_seq INTEGER NOT NULL,
            receipt_count INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rollups (
            id TEXT PRIMARY KEY,
            seq_start INTEGER NOT NULL,
            seq_end INTEGER NOT NULL,
            merkle_root TEXT NOT NULL,
            detail_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_receipts_seq ON receipts(seq);
        CREATE INDEX IF NOT EXISTS idx_rollups_range ON rollups(seq_start, seq_end);",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{advance_chain_state, create_receipt, init_genesis};
    use aegis_crypto::ed25519::{self, generate_keypair};
    use aegis_schemas::{ReceiptType, receipt::generate_blinding_nonce};

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
        }
    }

    #[test]
    fn open_in_memory() {
        let store = EvidenceStore::open_in_memory().unwrap();
        let state = store.get_chain_state().unwrap();
        assert_eq!(state.head_seq, 0);
        assert_eq!(state.receipt_count, 0);
    }

    #[test]
    fn append_and_retrieve() {
        let store = EvidenceStore::open_in_memory().unwrap();
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let state = init_genesis();

        let receipt =
            create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state).unwrap();
        let new_state = advance_chain_state(&state, &receipt);

        store.append_receipt(&receipt, &new_state).unwrap();

        let loaded = store.get_receipt_by_seq(1).unwrap().unwrap();
        assert_eq!(loaded.core.id, receipt.core.id);
        assert_eq!(loaded.core.seq, 1);
        assert_eq!(loaded.core.sig, receipt.core.sig);
    }

    #[test]
    fn chain_state_persists() {
        let store = EvidenceStore::open_in_memory().unwrap();
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();

        for _ in 0..3 {
            let r = create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state)
                .unwrap();
            state = advance_chain_state(&state, &r);
            store.append_receipt(&r, &state).unwrap();
        }

        let loaded_state = store.get_chain_state().unwrap();
        assert_eq!(loaded_state.head_seq, 3);
        assert_eq!(loaded_state.receipt_count, 3);
        assert_eq!(loaded_state.head_hash, state.head_hash);
    }

    #[test]
    fn get_receipts_range() {
        let store = EvidenceStore::open_in_memory().unwrap();
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();

        for _ in 0..5 {
            let r = create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state)
                .unwrap();
            state = advance_chain_state(&state, &r);
            store.append_receipt(&r, &state).unwrap();
        }

        let range = store.get_receipts_range(2, 4).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].core.seq, 2);
        assert_eq!(range[2].core.seq, 4);
    }

    #[test]
    fn verify_chain_integrity() {
        let store = EvidenceStore::open_in_memory().unwrap();
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();

        for _ in 0..5 {
            let r = create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state)
                .unwrap();
            state = advance_chain_state(&state, &r);
            store.append_receipt(&r, &state).unwrap();
        }

        assert!(store.verify_full_chain().unwrap());
    }

    #[test]
    fn empty_chain_is_valid() {
        let store = EvidenceStore::open_in_memory().unwrap();
        assert!(store.verify_full_chain().unwrap());
    }

    #[test]
    fn integrity_check_passes_on_fresh_db() {
        let store = EvidenceStore::open_in_memory().unwrap();
        assert!(store.integrity_check().is_ok());
    }

    #[test]
    fn integrity_check_passes_after_receipts() {
        let store = EvidenceStore::open_in_memory().unwrap();
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();

        for _ in 0..3 {
            let r = create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state)
                .unwrap();
            state = advance_chain_state(&state, &r);
            store.append_receipt(&r, &state).unwrap();
        }

        assert!(store.integrity_check().is_ok());
    }

    #[test]
    fn backup_creates_copy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("evidence.db");
        let store = EvidenceStore::open(&db_path).unwrap();
        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();

        for _ in 0..3 {
            let r = create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state)
                .unwrap();
            state = advance_chain_state(&state, &r);
            store.append_receipt(&r, &state).unwrap();
        }

        let backup_path = tmp.path().join("backup.db");
        store.backup(&backup_path).unwrap();
        assert!(backup_path.exists());

        // Open the backup and verify it has the same data
        let backup_store = EvidenceStore::open(&backup_path).unwrap();
        assert_eq!(backup_store.get_receipt_count().unwrap(), 3);
        assert!(backup_store.integrity_check().is_ok());
    }

    #[test]
    fn receipt_count() {
        let store = EvidenceStore::open_in_memory().unwrap();
        assert_eq!(store.get_receipt_count().unwrap(), 0);

        let key = generate_keypair();
        let bot_id = ed25519::fingerprint_hex(&key.verifying_key());
        let mut state = init_genesis();

        for _ in 0..3 {
            let r = create_receipt(&key, &bot_id, ReceiptType::ApiCall, make_context(), &state)
                .unwrap();
            state = advance_chain_state(&state, &r);
            store.append_receipt(&r, &state).unwrap();
        }

        assert_eq!(store.get_receipt_count().unwrap(), 3);
    }
}
