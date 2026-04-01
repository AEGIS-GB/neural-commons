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
        let mut store = self.records.write().await;
        let count = records.len();
        for record in records {
            let id = record.id.clone();
            if store.contains_key(&id) {
                return Err(format!("duplicate receipt id: {id}"));
            }
            store.insert(id, record);
        }
        Ok(count)
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
