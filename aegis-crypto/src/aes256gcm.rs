// AES-256-GCM authenticated encryption — vault secrets, backup encryption, RAG chunks

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AesError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
}

/// Encrypt plaintext with AES-256-GCM
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, AesError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AesError::EncryptionFailed)?;
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, plaintext).map_err(|_| AesError::EncryptionFailed)
}

/// Decrypt ciphertext with AES-256-GCM
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, AesError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AesError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|_| AesError::DecryptionFailed)
}
