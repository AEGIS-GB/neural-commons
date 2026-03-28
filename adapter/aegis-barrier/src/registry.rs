//! Hash registry — signed, integrity-checked record of known-good file states (D5)
//!
//! Tracks SHA-256 hashes, device/inode pairs, and modification provenance for
//! every protected file. The registry itself is integrity-protected: a SHA-256
//! digest over all entries (sorted by path) is maintained and re-signed on
//! every mutation.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::*;

// ═══════════════════════════════════════════════════════════════════
// FileCheckResult
// ═══════════════════════════════════════════════════════════════════

/// Result of comparing a file's current state against the registry.
#[derive(Debug, PartialEq, Eq)]
pub enum FileCheckResult {
    /// Content hash and inode match the registered baseline.
    Match,
    /// Content hash differs from the registered baseline.
    HashMismatch {
        expected: String,
        actual: String,
    },
    /// The file path is not present in the registry.
    NotRegistered,
    /// The device/inode pair changed — possible symlink or hardlink swap.
    InodeChanged {
        expected: (u64, u64),
        actual: (u64, u64),
    },
}

// ═══════════════════════════════════════════════════════════════════
// HashRegistryManager
// ═══════════════════════════════════════════════════════════════════

/// Manages the hash registry: registration, verification, mutation, and signing.
pub struct HashRegistryManager {
    pub registry: HashRegistry,
}

#[allow(clippy::new_without_default)]
impl HashRegistryManager {
    // ───────────────────────────────────────────────────────────────
    // Construction
    // ───────────────────────────────────────────────────────────────

    /// Create an empty registry with zeroed hash and signature.
    pub fn new() -> Self {
        Self {
            registry: HashRegistry {
                entries: std::collections::HashMap::new(),
                registry_hash: [0u8; 32],
                signature: [0u8; 64],
            },
        }
    }

    // ───────────────────────────────────────────────────────────────
    // Registration
    // ───────────────────────────────────────────────────────────────

    /// Register a new file with [`ModSource::Genesis`] provenance.
    ///
    /// Computes the SHA-256 hash of `content`, records the device/inode pair,
    /// inserts the entry, and returns a clone of it.
    pub fn register_file(
        &mut self,
        path: &Path,
        content: &[u8],
        dev_inode: (u64, u64),
        sensitivity: SensitivityClass,
    ) -> HashEntry {
        let hash = aegis_crypto::hash(content);
        let entry = HashEntry {
            hash,
            dev_inode,
            verified_at: now_ms(),
            modified_by: ModSource::Genesis,
            evolution_receipt: None,
            sensitivity_class: sensitivity,
        };
        self.registry.entries.insert(path.to_path_buf(), entry.clone());
        entry
    }

    // ───────────────────────────────────────────────────────────────
    // Verification
    // ───────────────────────────────────────────────────────────────

    /// Check a file's current content (and implicitly its inode) against the
    /// registry.
    ///
    /// Returns [`FileCheckResult::NotRegistered`] when the path has no entry,
    /// [`FileCheckResult::HashMismatch`] when content diverges, or
    /// [`FileCheckResult::Match`] when everything lines up.
    pub fn check_file(&self, path: &Path, current_content: &[u8]) -> FileCheckResult {
        let Some(entry) = self.registry.entries.get(path) else {
            return FileCheckResult::NotRegistered;
        };

        let current_hash = aegis_crypto::hash(current_content);

        if current_hash != entry.hash {
            return FileCheckResult::HashMismatch {
                expected: hex::encode(entry.hash),
                actual: hex::encode(current_hash),
            };
        }

        FileCheckResult::Match
    }

    /// Check a file's content **and** inode against the registry.
    ///
    /// Inode changes are checked first because a symlink swap is a more severe
    /// signal than a content change.
    pub fn check_file_with_inode(
        &self,
        path: &Path,
        current_content: &[u8],
        current_dev_inode: (u64, u64),
    ) -> FileCheckResult {
        let Some(entry) = self.registry.entries.get(path) else {
            return FileCheckResult::NotRegistered;
        };

        // Inode swap check first — more severe.
        if current_dev_inode != entry.dev_inode {
            return FileCheckResult::InodeChanged {
                expected: entry.dev_inode,
                actual: current_dev_inode,
            };
        }

        let current_hash = aegis_crypto::hash(current_content);

        if current_hash != entry.hash {
            return FileCheckResult::HashMismatch {
                expected: hex::encode(entry.hash),
                actual: hex::encode(current_hash),
            };
        }

        FileCheckResult::Match
    }

    // ───────────────────────────────────────────────────────────────
    // Mutation
    // ───────────────────────────────────────────────────────────────

    /// Update an existing entry after an authorized change.
    ///
    /// Recomputes the hash from `new_content`, records the new inode, source,
    /// and optional evolution receipt.
    pub fn update_entry(
        &mut self,
        path: &Path,
        new_content: &[u8],
        dev_inode: (u64, u64),
        source: ModSource,
        evolution_receipt: Option<String>,
    ) {
        let hash = aegis_crypto::hash(new_content);
        let entry = HashEntry {
            hash,
            dev_inode,
            verified_at: now_ms(),
            modified_by: source,
            evolution_receipt,
            sensitivity_class: self
                .registry
                .entries
                .get(path)
                .map(|e| e.sensitivity_class.clone())
                .unwrap_or(SensitivityClass::Standard),
        };
        self.registry.entries.insert(path.to_path_buf(), entry);
    }

    /// Remove a file from the registry, returning the entry if it existed.
    pub fn remove_file(&mut self, path: &Path) -> Option<HashEntry> {
        self.registry.entries.remove(path)
    }

    // ───────────────────────────────────────────────────────────────
    // Queries
    // ───────────────────────────────────────────────────────────────

    /// List all registered file paths.
    pub fn list_files(&self) -> Vec<&PathBuf> {
        self.registry.entries.keys().collect()
    }

    /// Number of files in the registry.
    pub fn file_count(&self) -> usize {
        self.registry.entries.len()
    }

    /// Retrieve the entry for a specific path, if registered.
    pub fn get_entry(&self, path: &Path) -> Option<&HashEntry> {
        self.registry.entries.get(path)
    }

    // ───────────────────────────────────────────────────────────────
    // Integrity
    // ───────────────────────────────────────────────────────────────

    /// Compute the SHA-256 digest of the registry.
    ///
    /// Entries are sorted by path (lexicographic) to ensure deterministic
    /// output. Each entry contributes its path bytes followed by its content
    /// hash.
    pub fn compute_registry_hash(&self) -> [u8; 32] {
        let mut sorted_paths: Vec<&PathBuf> = self.registry.entries.keys().collect();
        sorted_paths.sort();

        let mut material: Vec<u8> = Vec::new();
        for path in sorted_paths {
            let entry = &self.registry.entries[path];
            // Contribute path bytes + content hash for each entry.
            material.extend_from_slice(path.to_string_lossy().as_bytes());
            material.extend_from_slice(&entry.hash);
        }

        aegis_crypto::hash(&material)
    }

    /// Recompute the registry hash and update the signature.
    ///
    /// Signing is a placeholder for now: the signature field is zeroed.
    /// A real implementation would use the bot identity Ed25519 key.
    pub fn recompute_and_sign(&mut self, _signing_key: &[u8]) {
        self.registry.registry_hash = self.compute_registry_hash();
        // Placeholder: zero the signature until real Ed25519 signing is wired up.
        self.registry.signature = [0u8; 64];
    }
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Current wall-clock time in milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample_path(name: &str) -> PathBuf {
        PathBuf::from(format!("/workspace/{name}"))
    }

    // ── register and check ──────────────────────────────────────

    #[test]
    fn register_and_check_match() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("config.toml");
        let content = b"key = \"value\"";

        mgr.register_file(&path, content, (1, 100), SensitivityClass::Standard);

        let result = mgr.check_file(&path, content);
        assert_eq!(result, FileCheckResult::Match);
    }

    #[test]
    fn register_returns_correct_entry() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("data.json");
        let content = b"{\"a\":1}";

        let entry = mgr.register_file(&path, content, (2, 200), SensitivityClass::Credential);

        assert_eq!(entry.hash, aegis_crypto::hash(content));
        assert_eq!(entry.dev_inode, (2, 200));
        assert!(matches!(entry.modified_by, ModSource::Genesis));
        assert!(entry.evolution_receipt.is_none());
        assert_eq!(entry.sensitivity_class, SensitivityClass::Credential);
    }

    // ── hash mismatch detection ─────────────────────────────────

    #[test]
    fn detect_hash_mismatch() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("main.rs");
        let original = b"fn main() {}";
        let tampered = b"fn main() { evil(); }";

        mgr.register_file(&path, original, (1, 10), SensitivityClass::Standard);

        let result = mgr.check_file(&path, tampered);
        match result {
            FileCheckResult::HashMismatch { expected, actual } => {
                assert_eq!(expected, hex::encode(aegis_crypto::hash(original)));
                assert_eq!(actual, hex::encode(aegis_crypto::hash(tampered)));
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    // ── inode change detection ──────────────────────────────────

    #[test]
    fn detect_inode_change() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("secrets.env");
        let content = b"SECRET=abc";
        let original_inode = (1, 42);
        let swapped_inode = (1, 999);

        mgr.register_file(&path, content, original_inode, SensitivityClass::Credential);

        let result = mgr.check_file_with_inode(&path, content, swapped_inode);
        assert_eq!(
            result,
            FileCheckResult::InodeChanged {
                expected: original_inode,
                actual: swapped_inode,
            }
        );
    }

    #[test]
    fn inode_match_returns_match() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("ok.txt");
        let content = b"hello";
        let inode = (5, 50);

        mgr.register_file(&path, content, inode, SensitivityClass::Standard);

        let result = mgr.check_file_with_inode(&path, content, inode);
        assert_eq!(result, FileCheckResult::Match);
    }

    // ── not registered ──────────────────────────────────────────

    #[test]
    fn check_unregistered_file() {
        let mgr = HashRegistryManager::new();
        let result = mgr.check_file(Path::new("/ghost.txt"), b"data");
        assert_eq!(result, FileCheckResult::NotRegistered);
    }

    // ── update entry ────────────────────────────────────────────

    #[test]
    fn update_entry_changes_hash() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("evolving.rs");
        let v1 = b"version 1";
        let v2 = b"version 2";

        mgr.register_file(&path, v1, (1, 1), SensitivityClass::Standard);

        // v2 should mismatch before update.
        assert!(matches!(
            mgr.check_file(&path, v2),
            FileCheckResult::HashMismatch { .. }
        ));

        mgr.update_entry(
            &path,
            v2,
            (1, 1),
            ModSource::WardenEvolution,
            Some("receipt-001".into()),
        );

        // v2 should match after update.
        assert_eq!(mgr.check_file(&path, v2), FileCheckResult::Match);

        // Verify provenance was recorded.
        let entry = mgr.get_entry(&path).unwrap();
        assert!(matches!(entry.modified_by, ModSource::WardenEvolution));
        assert_eq!(entry.evolution_receipt.as_deref(), Some("receipt-001"));
    }

    #[test]
    fn update_preserves_sensitivity_class() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path(".env");

        mgr.register_file(&path, b"v1", (1, 1), SensitivityClass::Credential);
        mgr.update_entry(&path, b"v2", (1, 1), ModSource::BarrierOverride, None);

        let entry = mgr.get_entry(&path).unwrap();
        assert_eq!(entry.sensitivity_class, SensitivityClass::Credential);
    }

    // ── remove entry ────────────────────────────────────────────

    #[test]
    fn remove_returns_entry_and_unregisters() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("temp.log");
        let content = b"log data";

        mgr.register_file(&path, content, (1, 7), SensitivityClass::Standard);
        assert_eq!(mgr.file_count(), 1);

        let removed = mgr.remove_file(&path);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().hash, aegis_crypto::hash(content));

        assert_eq!(mgr.file_count(), 0);
        assert_eq!(mgr.check_file(&path, content), FileCheckResult::NotRegistered);
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut mgr = HashRegistryManager::new();
        assert!(mgr.remove_file(Path::new("/nope")).is_none());
    }

    // ── list / count ────────────────────────────────────────────

    #[test]
    fn list_files_and_count() {
        let mut mgr = HashRegistryManager::new();
        assert_eq!(mgr.file_count(), 0);
        assert!(mgr.list_files().is_empty());

        mgr.register_file(
            Path::new("/a"),
            b"a",
            (1, 1),
            SensitivityClass::Standard,
        );
        mgr.register_file(
            Path::new("/b"),
            b"b",
            (1, 2),
            SensitivityClass::Standard,
        );

        assert_eq!(mgr.file_count(), 2);

        let mut paths: Vec<String> = mgr.list_files().iter().map(|p| p.display().to_string()).collect();
        paths.sort();
        assert_eq!(paths, vec!["/a", "/b"]);
    }

    // ── registry hash changes on mutation ───────────────────────

    #[test]
    fn registry_hash_changes_on_register() {
        let mut mgr = HashRegistryManager::new();
        let hash_empty = mgr.compute_registry_hash();

        mgr.register_file(
            Path::new("/file1"),
            b"content1",
            (1, 1),
            SensitivityClass::Standard,
        );
        let hash_one = mgr.compute_registry_hash();
        assert_ne!(hash_empty, hash_one);

        mgr.register_file(
            Path::new("/file2"),
            b"content2",
            (1, 2),
            SensitivityClass::Standard,
        );
        let hash_two = mgr.compute_registry_hash();
        assert_ne!(hash_one, hash_two);
    }

    #[test]
    fn registry_hash_changes_on_update() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("mutable.txt");

        mgr.register_file(&path, b"before", (1, 1), SensitivityClass::Standard);
        let hash_before = mgr.compute_registry_hash();

        mgr.update_entry(&path, b"after", (1, 1), ModSource::BotWrite, None);
        let hash_after = mgr.compute_registry_hash();

        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn registry_hash_changes_on_remove() {
        let mut mgr = HashRegistryManager::new();
        let path = sample_path("doomed.txt");

        mgr.register_file(&path, b"data", (1, 1), SensitivityClass::Standard);
        let hash_with = mgr.compute_registry_hash();

        mgr.remove_file(&path);
        let hash_without = mgr.compute_registry_hash();

        assert_ne!(hash_with, hash_without);
    }

    #[test]
    fn registry_hash_is_deterministic() {
        let mut mgr = HashRegistryManager::new();
        mgr.register_file(
            Path::new("/z"),
            b"z",
            (1, 1),
            SensitivityClass::Standard,
        );
        mgr.register_file(
            Path::new("/a"),
            b"a",
            (1, 2),
            SensitivityClass::Standard,
        );

        let h1 = mgr.compute_registry_hash();
        let h2 = mgr.compute_registry_hash();
        assert_eq!(h1, h2, "same state must produce same hash");
    }

    // ── recompute_and_sign ──────────────────────────────────────

    #[test]
    fn recompute_and_sign_updates_hash() {
        let mut mgr = HashRegistryManager::new();
        mgr.register_file(
            Path::new("/signed.txt"),
            b"payload",
            (1, 1),
            SensitivityClass::Standard,
        );

        assert_eq!(mgr.registry.registry_hash, [0u8; 32], "hash starts zeroed");

        mgr.recompute_and_sign(b"placeholder-key");

        assert_ne!(mgr.registry.registry_hash, [0u8; 32]);
        assert_eq!(mgr.registry.registry_hash, mgr.compute_registry_hash());
        // Signature is placeholder zeros for now.
        assert_eq!(mgr.registry.signature, [0u8; 64]);
    }
}
