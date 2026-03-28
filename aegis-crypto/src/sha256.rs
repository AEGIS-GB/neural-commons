// SHA-256 hashing — evidence chain, Merkle rollups, fingerprints

use sha2::{Digest, Sha256};

/// Hash arbitrary bytes with SHA-256
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash chain: compute hash of (prev_hash || current_data)
pub fn chain_hash(prev_hash: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(data);
    hasher.finalize().into()
}
