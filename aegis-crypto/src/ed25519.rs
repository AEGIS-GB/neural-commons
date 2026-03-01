// Ed25519 signing and verification — wraps ed25519-dalek
// SLIP-0010 deterministic derivation from BIP-39 seed (D0)
// Derivation path: m/44'/784'/0'/0' (signing purpose)
// See bip39.rs for full HD path hierarchy

pub use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Ed25519Error {
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid key bytes")]
    InvalidKey,
    #[error("SLIP-0010 derivation failed: {0}")]
    DerivationFailed(String),
}

/// Generate a new random Ed25519 keypair (NOT for production identity — use bip39::create_identity)
pub fn generate_keypair() -> SigningKey {
    let mut csprng = rand::rngs::OsRng;
    SigningKey::generate(&mut csprng)
}

/// Compute the bot fingerprint (thumbprint) from a verifying key — raw bytes
pub fn fingerprint(key: &VerifyingKey) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}

/// Compute the bot fingerprint as lowercase hex string (D2: all binary fields lowercase hex)
pub fn fingerprint_hex(key: &VerifyingKey) -> String {
    let fp = fingerprint(key);
    hex::encode(fp)
}

/// Encode a verifying key as lowercase hex (D2 compliance: bot_id format)
pub fn pubkey_hex(key: &VerifyingKey) -> String {
    hex::encode(key.as_bytes())
}

/// Encode a signature as lowercase hex (D2 compliance)
pub fn signature_hex(sig: &Signature) -> String {
    hex::encode(sig.to_bytes())
}
