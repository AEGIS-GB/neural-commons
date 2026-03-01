//! Vault key derivation (D9)
//!
//! HKDF-SHA256, domain "aegis-vault-v1", info = bot fingerprint.
//! 256-bit output key for AES-256-GCM.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::VaultError;

/// Domain separation string for vault key derivation.
pub const VAULT_DOMAIN: &str = "aegis-vault-v1";

/// Derive a 256-bit vault key using HKDF-SHA256.
///
/// - `master_key_material`: the input keying material (e.g. bot master secret)
/// - `bot_fingerprint`: the Ed25519 public key thumbprint (hex), used as HKDF info
///
/// HKDF parameters:
///   salt  = VAULT_DOMAIN bytes ("aegis-vault-v1")
///   ikm   = master_key_material
///   info  = bot_fingerprint bytes
///   len   = 32 (256 bits)
pub fn derive_vault_key(
    master_key_material: &[u8],
    bot_fingerprint: &str,
) -> Result<[u8; 32], VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(VAULT_DOMAIN.as_bytes()), master_key_material);
    let mut okm = [0u8; 32];
    hk.expand(bot_fingerprint.as_bytes(), &mut okm)
        .map_err(|e| VaultError::KeyDerivation(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}

/// Generate a random 12-byte nonce for AES-256-GCM.
pub fn generate_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_vault_key_deterministic() {
        let master = b"test-master-key-material-for-vault";
        let fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let key1 = derive_vault_key(master, fp).unwrap();
        let key2 = derive_vault_key(master, fp).unwrap();
        assert_eq!(key1, key2, "same inputs must produce same key");
        assert_ne!(key1, [0u8; 32], "derived key must not be all zeros");
    }

    #[test]
    fn different_fingerprints_produce_different_keys() {
        let master = b"test-master-key-material-for-vault";
        let fp_a = "aaaa0000000000000000000000000000aaaa0000000000000000000000000000";
        let fp_b = "bbbb0000000000000000000000000000bbbb0000000000000000000000000000";

        let key_a = derive_vault_key(master, fp_a).unwrap();
        let key_b = derive_vault_key(master, fp_b).unwrap();
        assert_ne!(key_a, key_b, "different fingerprints must produce different keys");
    }

    #[test]
    fn different_master_keys_produce_different_keys() {
        let fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let key_a = derive_vault_key(b"master-a", fp).unwrap();
        let key_b = derive_vault_key(b"master-b", fp).unwrap();
        assert_ne!(key_a, key_b, "different master keys must produce different keys");
    }

    #[test]
    fn generate_nonce_unique() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2, "two random nonces should differ");
        assert_eq!(n1.len(), 12);
    }
}
