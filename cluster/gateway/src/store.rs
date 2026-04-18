//! Evidence receipt storage for the cluster Gateway.
//!
//! Trait-based design: `MemoryStore` for tests, `PostgresStore` for production.
//! The Gateway stores receipt cores (not contexts) submitted by adapters.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};

/// A receipt record as stored in the cluster evidence table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Receipt UUID (from ReceiptCore.id)
    pub id: String,
    /// Bot's transport pubkey (from auth middleware)
    pub bot_fingerprint: String,
    /// Monotonic sequence number
    pub seq: i64,
    /// Receipt type (snake_case string)
    pub receipt_type: String,
    /// Unix epoch milliseconds
    pub ts_ms: i64,
    /// JCS-canonicalized receipt core JSON
    pub core_json: String,
    /// Receipt hash (SHA-256 of core, lowercase hex)
    pub receipt_hash: String,
    /// Pipeline request ID (optional)
    pub request_id: Option<String>,
}

/// Evidence store trait -- abstraction over storage backend.
pub trait EvidenceStore: Send + Sync + 'static {
    /// Insert a single evidence record. Returns the record ID.
    fn insert(
        &self,
        record: EvidenceRecord,
    ) -> impl std::future::Future<Output = Result<String, String>> + Send;

    /// Insert a batch of evidence records. Returns count inserted.
    fn insert_batch(
        &self,
        records: Vec<EvidenceRecord>,
    ) -> impl std::future::Future<Output = Result<usize, String>> + Send;

    /// Count receipts for a given bot fingerprint.
    fn count_for_bot(
        &self,
        bot_fingerprint: &str,
    ) -> impl std::future::Future<Output = Result<u64, String>> + Send;

    /// Get all records for a bot (for trustmark computation).
    fn get_for_bot(
        &self,
        bot_fingerprint: &str,
    ) -> impl std::future::Future<Output = Result<Vec<EvidenceRecord>, String>> + Send;
}

/// In-memory evidence store for testing.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    records: Arc<RwLock<HashMap<String, EvidenceRecord>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EvidenceStore for MemoryStore {
    async fn insert(&self, record: EvidenceRecord) -> Result<String, String> {
        let id = record.id.clone();
        let mut store = self.records.write().await;
        if store.contains_key(&id) {
            return Err(format!("duplicate receipt id: {id}"));
        }
        store.insert(id.clone(), record);
        Ok(id)
    }

    async fn insert_batch(&self, records: Vec<EvidenceRecord>) -> Result<usize, String> {
        // Evidence is an append-only log with deterministic receipt IDs.
        // A repeat of the same ID is a no-op, not an error — the adapter re-
        // pushes from seq 1 after a restart, so aborting the batch on the
        // first duplicate stalls the push loop forever. Skip duplicates and
        // return the count of newly inserted records instead.
        let mut store = self.records.write().await;
        let mut inserted = 0usize;
        for record in records {
            let id = record.id.clone();
            if store.contains_key(&id) {
                continue;
            }
            store.insert(id, record);
            inserted += 1;
        }
        Ok(inserted)
    }

    async fn count_for_bot(&self, bot_fingerprint: &str) -> Result<u64, String> {
        let store = self.records.read().await;
        let count = store
            .values()
            .filter(|r| r.bot_fingerprint == bot_fingerprint)
            .count();
        Ok(count as u64)
    }

    async fn get_for_bot(&self, bot_fingerprint: &str) -> Result<Vec<EvidenceRecord>, String> {
        let store = self.records.read().await;
        let mut records: Vec<EvidenceRecord> = store
            .values()
            .filter(|r| r.bot_fingerprint == bot_fingerprint)
            .cloned()
            .collect();
        records.sort_by_key(|r| r.seq);
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, seq: i64) -> EvidenceRecord {
        EvidenceRecord {
            id: id.to_string(),
            bot_fingerprint: "test-bot".to_string(),
            seq,
            receipt_type: "ApiCall".to_string(),
            ts_ms: 1_000_000 + seq,
            core_json: "{}".to_string(),
            receipt_hash: "h".to_string(),
            request_id: None,
        }
    }

    #[tokio::test]
    async fn insert_batch_skips_duplicates_and_reports_new_inserts() {
        let store = MemoryStore::new();

        let first = store
            .insert_batch(vec![rec("a", 1), rec("b", 2)])
            .await
            .unwrap();
        assert_eq!(first, 2);

        // Re-push an overlapping batch (a is duplicate, c is new)
        let second = store
            .insert_batch(vec![rec("a", 1), rec("c", 3)])
            .await
            .unwrap();
        assert_eq!(second, 1, "only the new record should count");

        assert_eq!(store.count_for_bot("test-bot").await.unwrap(), 3);
    }

    #[tokio::test]
    async fn insert_batch_full_duplicate_batch_is_zero_not_error() {
        let store = MemoryStore::new();
        store.insert_batch(vec![rec("a", 1)]).await.unwrap();
        let repeat = store.insert_batch(vec![rec("a", 1)]).await.unwrap();
        assert_eq!(repeat, 0);
    }
}
