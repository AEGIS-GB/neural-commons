//! aegis-evidence: Evidence recorder with hash-chained receipts
//!
//! Every adapter action produces a receipt. Receipts form a hash chain (SHA-256).
//! Periodic Merkle rollups compress the chain. Storage: SQLite WAL mode.

pub mod chain;
pub mod merkle;
pub mod recorder;
pub mod store;

pub use chain::ChainState;
pub use recorder::EvidenceRecorder;
pub use store::EvidenceStore;

use thiserror::Error;

/// Errors produced by the evidence subsystem.
#[derive(Debug, Error)]
pub enum EvidenceError {
    /// Hash chain integrity violation (gap, wrong prev_hash, etc.)
    #[error("chain error: {0}")]
    ChainError(String),

    /// SQLite storage error
    #[error("store error: {0}")]
    StoreError(String),

    /// Cryptographic operation failed (signing, hashing)
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// JCS / JSON serialization failure
    #[error("serialization error: {0}")]
    SerializationError(String),
}

impl From<rusqlite::Error> for EvidenceError {
    fn from(e: rusqlite::Error) -> Self {
        EvidenceError::StoreError(e.to_string())
    }
}

impl From<aegis_crypto::rfc8785::CanonicalizationError> for EvidenceError {
    fn from(e: aegis_crypto::rfc8785::CanonicalizationError) -> Self {
        EvidenceError::SerializationError(e.to_string())
    }
}

impl From<serde_json::Error> for EvidenceError {
    fn from(e: serde_json::Error) -> Self {
        EvidenceError::SerializationError(e.to_string())
    }
}
