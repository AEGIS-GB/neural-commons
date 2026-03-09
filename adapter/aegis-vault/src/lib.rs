//! aegis-vault: Credential vault
//!
//! Scans for plaintext credentials in bot configuration and API traffic.
//! Encrypts detected secrets with AES-256-GCM (key derived via HKDF-SHA256, D9).
//! Per-tool access policy controls which tools can access which secrets.
//!
//! Enforcement mode (D30):
//!   vault_block is ALWAYS enforced — not configurable. Cannot be set to observe.
//!   Rationale: plaintext credentials must never leave the adapter. An observe-mode
//!   vault would be a completed credential leak, not a warning.
//!   Receipt omits enforcement_mode field (always-enforce, not switchable).
//!   TODO(D9): vault key derivation via HKDF-SHA256 must be locked before
//!   actual encryption can be wired.

pub mod scanner;
pub mod storage;
pub mod policy;
pub mod kdf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("decryption error: {0}")]
    Decryption(String),
    #[error("key derivation error: {0}")]
    KeyDerivation(String),
    #[error("access denied: tool {tool} not authorized for secret {secret_id}")]
    AccessDenied { tool: String, secret_id: String },
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("scanner error: {0}")]
    ScannerError(String),
}
