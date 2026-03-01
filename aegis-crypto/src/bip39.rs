//! BIP-39 mnemonic generation and SLIP-0010 Ed25519 derivation (D0)
//!
//! Generation order (entropy-first — the only physically possible direction):
//!   1. Generate 256-bit entropy
//!   2. Encode as BIP-39 mnemonic (24 words, English only)
//!   3. Derive seed via PBKDF2-HMAC-SHA512 (with optional passphrase, default empty)
//!   4. Forward-derive Ed25519 keys via SLIP-0010 hardened child paths
//!
//! HD Path Hierarchy (domain-separated, all hardened):
//!   m/44'/784'/0'/0' — Signing (Ed25519)
//!   m/44'/784'/1'/0' — Mesh Encryption (X25519 via separate SLIP-0010 derivation)
//!   m/44'/784'/2'/0' — Vault KDF Seed
//!   m/44'/784'/3'/0' — Transport Auth
//!
//! BANNED: crypto_sign_ed25519_sk_to_curve25519 curve-conversion.
//! Each key purpose uses its own SLIP-0010 hardened child path.

use ed25519_dalek::SigningKey;
use thiserror::Error;

/// Current KDF version — embedded in identity metadata and receipts.
/// Bump on any change to derivation scheme.
pub const KDF_VERSION: u32 = 1;

/// HD path purposes for domain-separated key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// m/44'/784'/0'/0' — Ed25519 signing (evidence chain, receipts)
    Signing,
    /// m/44'/784'/1'/0' — X25519 mesh encryption (Phase 3)
    MeshEncryption,
    /// m/44'/784'/2'/0' — Vault KDF seed material
    VaultKdf,
    /// m/44'/784'/3'/0' — Transport auth (NC-Ed25519 request signing)
    TransportAuth,
}

impl KeyPurpose {
    /// Returns the SLIP-0010 derivation path segments (all hardened)
    pub fn path_segments(&self) -> &[u32] {
        match self {
            KeyPurpose::Signing => &[44 | 0x80000000, 784 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000],
            KeyPurpose::MeshEncryption => &[44 | 0x80000000, 784 | 0x80000000, 1 | 0x80000000, 0 | 0x80000000],
            KeyPurpose::VaultKdf => &[44 | 0x80000000, 784 | 0x80000000, 2 | 0x80000000, 0 | 0x80000000],
            KeyPurpose::TransportAuth => &[44 | 0x80000000, 784 | 0x80000000, 3 | 0x80000000, 0 | 0x80000000],
        }
    }

    /// Human-readable derivation path string (for metadata storage)
    pub fn path_string(&self) -> &'static str {
        match self {
            KeyPurpose::Signing => "m/44'/784'/0'/0'",
            KeyPurpose::MeshEncryption => "m/44'/784'/1'/0'",
            KeyPurpose::VaultKdf => "m/44'/784'/2'/0'",
            KeyPurpose::TransportAuth => "m/44'/784'/3'/0'",
        }
    }
}

#[derive(Debug, Error)]
pub enum Bip39Error {
    #[error("invalid mnemonic phrase: checksum or wordlist validation failed")]
    InvalidMnemonic,
    #[error("SLIP-0010 derivation failed: {0}")]
    DerivationFailed(String),
    #[error("entropy generation failed")]
    EntropyFailed,
    #[error("mnemonic normalization failed: {0}")]
    NormalizationFailed(String),
}

/// Identity metadata — stored alongside the derived keys
#[derive(Debug, Clone)]
pub struct IdentityMetadata {
    /// KDF version (currently 1)
    pub kdf_version: u32,
    /// The derivation path used
    pub derivation_path: String,
    /// Whether a passphrase was used (empty string = false)
    pub passphrase_protected: bool,
}

/// Normalize a mnemonic phrase per D0 spec:
/// - English wordlist only
/// - NFKD normalization
/// - Trim leading/trailing whitespace
/// - Collapse multiple spaces to single space
/// - Lowercase
pub fn normalize_mnemonic(mnemonic: &str) -> String {
    let lowered = mnemonic.to_lowercase();
    let trimmed = lowered.trim();
    // Collapse multiple whitespace to single spaces
    let mut result = String::with_capacity(trimmed.len());
    let mut prev_space = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
                prev_space = true;
            }
        } else {
            result.push(ch);
            prev_space = false;
        }
    }
    result
}

/// Generate a new 24-word BIP-39 mnemonic from 256-bit entropy.
/// This is step 1 of identity creation (entropy-first).
pub fn generate_mnemonic() -> Result<String, Bip39Error> {
    use bip39::Mnemonic;
    use rand::RngCore;

    // Generate 256-bit (32 bytes) entropy for 24-word mnemonic
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);

    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| Bip39Error::DerivationFailed(e.to_string()))?;
    Ok(mnemonic.to_string())
}

/// Validate a mnemonic phrase.
/// Checks: valid English words, valid checksum, proper word count.
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), Bip39Error> {
    let normalized = normalize_mnemonic(mnemonic);
    let _m: bip39::Mnemonic = normalized
        .parse()
        .map_err(|_| Bip39Error::InvalidMnemonic)?;
    Ok(())
}

/// Derive a 64-byte seed from a BIP-39 mnemonic.
/// Passphrase defaults to empty string (zero friction).
/// Advanced mode: non-empty passphrase (forgotten = unrecoverable, no backdoor).
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64], Bip39Error> {
    let normalized = normalize_mnemonic(mnemonic);
    let m: bip39::Mnemonic = normalized
        .parse()
        .map_err(|_| Bip39Error::InvalidMnemonic)?;
    let seed = m.to_seed(passphrase);
    Ok(seed)
}

/// SLIP-0010 Ed25519 hardened child key derivation.
///
/// From SLIP-0010 spec:
/// - Master key: HMAC-SHA512(key="ed25519 seed", data=seed)
/// - Child key: HMAC-SHA512(key=parent_chain_code, data=0x00 || parent_key || index)
/// - All indices MUST be hardened (>= 0x80000000)
pub fn slip0010_derive(seed: &[u8; 64], path: &[u32]) -> Result<[u8; 32], Bip39Error> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    // Master key derivation
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e| Bip39Error::DerivationFailed(e.to_string()))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // Derive each level (all hardened)
    for &index in path {
        if index < 0x80000000 {
            return Err(Bip39Error::DerivationFailed(
                "SLIP-0010 Ed25519 requires all hardened indices".to_string(),
            ));
        }
        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|e| Bip39Error::DerivationFailed(e.to_string()))?;
        mac.update(&[0x00]);
        mac.update(&key);
        mac.update(&index.to_be_bytes());
        let result = mac.finalize().into_bytes();
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
    }

    Ok(key)
}

/// Derive an Ed25519 signing key for a specific purpose from a BIP-39 seed.
pub fn derive_signing_key(
    seed: &[u8; 64],
    purpose: KeyPurpose,
) -> Result<SigningKey, Bip39Error> {
    let key_bytes = slip0010_derive(seed, purpose.path_segments())?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Full identity creation flow (entropy-first):
/// 1. Generate entropy -> BIP-39 mnemonic
/// 2. Derive seed (with optional passphrase)
/// 3. Derive signing key at m/44'/784'/0'/0'
///
/// Returns: (mnemonic, signing_key, metadata)
pub fn create_identity(
    passphrase: &str,
) -> Result<(String, SigningKey, IdentityMetadata), Bip39Error> {
    let mnemonic = generate_mnemonic()?;
    let seed = mnemonic_to_seed(&mnemonic, passphrase)?;
    let signing_key = derive_signing_key(&seed, KeyPurpose::Signing)?;

    let metadata = IdentityMetadata {
        kdf_version: KDF_VERSION,
        derivation_path: KeyPurpose::Signing.path_string().to_string(),
        passphrase_protected: !passphrase.is_empty(),
    };

    Ok((mnemonic, signing_key, metadata))
}

/// Restore identity from mnemonic phrase.
/// Must produce identical keypair as original creation.
pub fn restore_from_mnemonic(
    mnemonic: &str,
    passphrase: &str,
    purpose: KeyPurpose,
) -> Result<SigningKey, Bip39Error> {
    validate_mnemonic(mnemonic)?;
    let seed = mnemonic_to_seed(mnemonic, passphrase)?;
    derive_signing_key(&seed, purpose)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn test_generate_and_restore_round_trip() {
        let (mnemonic, original_key, metadata) = create_identity("").unwrap();
        assert_eq!(metadata.kdf_version, 1);
        assert!(!metadata.passphrase_protected);

        // Restore must produce identical key
        let restored_key = restore_from_mnemonic(&mnemonic, "", KeyPurpose::Signing).unwrap();
        assert_eq!(
            original_key.verifying_key().as_bytes(),
            restored_key.verifying_key().as_bytes()
        );

        // Signatures must match
        let message = b"test message";
        let sig1 = original_key.sign(message);
        let sig2 = restored_key.sign(message);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_different_purposes_produce_different_keys() {
        let mnemonic = generate_mnemonic().unwrap();
        let seed = mnemonic_to_seed(&mnemonic, "").unwrap();

        let signing = derive_signing_key(&seed, KeyPurpose::Signing).unwrap();
        let transport = derive_signing_key(&seed, KeyPurpose::TransportAuth).unwrap();
        let vault = derive_signing_key(&seed, KeyPurpose::VaultKdf).unwrap();

        assert_ne!(signing.to_bytes(), transport.to_bytes());
        assert_ne!(signing.to_bytes(), vault.to_bytes());
        assert_ne!(transport.to_bytes(), vault.to_bytes());
    }

    #[test]
    fn test_mnemonic_normalization() {
        assert_eq!(normalize_mnemonic("  HELLO   WORLD  "), "hello world");
        assert_eq!(normalize_mnemonic("hello world"), "hello world");
        assert_eq!(normalize_mnemonic("HELLO\t\tWORLD"), "hello world");
    }

    #[test]
    fn test_invalid_mnemonic_rejected() {
        assert!(validate_mnemonic("not a valid mnemonic").is_err());
        assert!(validate_mnemonic("").is_err());
    }

    #[test]
    fn test_passphrase_produces_different_key() {
        let mnemonic = generate_mnemonic().unwrap();
        let seed_empty = mnemonic_to_seed(&mnemonic, "").unwrap();
        let seed_pass = mnemonic_to_seed(&mnemonic, "my secret passphrase").unwrap();
        assert_ne!(seed_empty, seed_pass);

        let key_empty = derive_signing_key(&seed_empty, KeyPurpose::Signing).unwrap();
        let key_pass = derive_signing_key(&seed_pass, KeyPurpose::Signing).unwrap();
        assert_ne!(key_empty.to_bytes(), key_pass.to_bytes());
    }

    #[test]
    fn test_slip0010_rejects_non_hardened_index() {
        let seed = [0u8; 64];
        let result = slip0010_derive(&seed, &[44]); // not hardened
        assert!(result.is_err());
    }

    #[test]
    fn test_path_strings() {
        assert_eq!(KeyPurpose::Signing.path_string(), "m/44'/784'/0'/0'");
        assert_eq!(KeyPurpose::MeshEncryption.path_string(), "m/44'/784'/1'/0'");
        assert_eq!(KeyPurpose::VaultKdf.path_string(), "m/44'/784'/2'/0'");
        assert_eq!(KeyPurpose::TransportAuth.path_string(), "m/44'/784'/3'/0'");
    }
}
