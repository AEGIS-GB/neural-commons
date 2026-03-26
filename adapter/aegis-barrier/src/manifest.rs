//! Between-session hash manifest — carries known-good file hashes across restarts.
//!
//! On startup, Aegis writes a signed manifest of all critical file hashes.
//! On the next startup, it loads the old manifest, verifies the Ed25519
//! signature, and compares hashes against disk to detect between-session
//! tampering.
//!
//! The manifest is updated at runtime when a protected file is legitimately
//! changed through a trusted channel.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::snapshot::SnapshotStore;

/// The on-disk manifest format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// Workspace-relative path → SHA-256 hex hash.
    pub files: BTreeMap<String, String>,
    /// Unix epoch milliseconds when the manifest was written.
    pub written_at_ms: u64,
    /// Ed25519 signature (hex) over the canonical JSON of `files` + `written_at_ms`.
    pub signature: String,
}

/// Result of comparing the manifest against current disk state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestCheckResult {
    /// File hash matches the manifest.
    Match,
    /// File hash differs from the manifest (between-session tampering).
    HashChanged {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    /// File existed in manifest but is missing from disk.
    Missing { path: PathBuf },
    /// File exists on disk but was not in the manifest (new file).
    NewFile { path: PathBuf },
}

/// Default manifest filename.
pub const MANIFEST_FILENAME: &str = "file_manifest.json";

/// Compute the signing payload: deterministic JSON of files + timestamp.
fn signing_payload(files: &BTreeMap<String, String>, written_at_ms: u64) -> Vec<u8> {
    // BTreeMap is already sorted, so serialization is deterministic.
    let payload = serde_json::json!({
        "files": files,
        "written_at_ms": written_at_ms,
    });
    serde_json::to_vec(&payload).expect("JSON serialization cannot fail for simple types")
}

impl FileManifest {
    /// Create a new manifest from a snapshot store and sign it.
    pub fn from_snapshot(
        store: &SnapshotStore,
        signing_key: &aegis_crypto::ed25519::SigningKey,
    ) -> Self {
        use aegis_crypto::ed25519::Signer;

        let files: BTreeMap<String, String> = store
            .all_entries()
            .into_iter()
            .map(|(path, hash)| (path.to_string_lossy().to_string(), hash.to_string()))
            .collect();

        let written_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_millis() as u64;

        let payload = signing_payload(&files, written_at_ms);
        let signature = signing_key.sign(&payload);

        Self {
            files,
            written_at_ms,
            signature: aegis_crypto::ed25519::signature_hex(&signature),
        }
    }

    /// Write the manifest to the data directory.
    pub fn write_to(&self, data_dir: &Path) -> Result<(), std::io::Error> {
        let manifest_path = data_dir.join(MANIFEST_FILENAME);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Atomic write: tmp then rename
        let tmp_path = manifest_path.with_extension("tmp");
        std::fs::write(&tmp_path, json.as_bytes())?;
        std::fs::rename(&tmp_path, &manifest_path)?;

        info!(
            path = %manifest_path.display(),
            files = self.files.len(),
            "manifest: written"
        );
        Ok(())
    }

    /// Load the manifest from the data directory. Returns None if not found.
    pub fn load_from(data_dir: &Path) -> Option<Self> {
        let manifest_path = data_dir.join(MANIFEST_FILENAME);
        let data = match std::fs::read_to_string(&manifest_path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("manifest: no previous manifest found (first run?)");
                return None;
            }
            Err(e) => {
                warn!(error = %e, "manifest: failed to read manifest file");
                return None;
            }
        };

        match serde_json::from_str::<Self>(&data) {
            Ok(m) => {
                info!(
                    files = m.files.len(),
                    written_at = m.written_at_ms,
                    "manifest: loaded previous session manifest"
                );
                Some(m)
            }
            Err(e) => {
                warn!(error = %e, "manifest: failed to parse manifest JSON");
                None
            }
        }
    }

    /// Verify the Ed25519 signature on this manifest.
    pub fn verify_signature(
        &self,
        verifying_key: &aegis_crypto::ed25519::VerifyingKey,
    ) -> bool {
        use aegis_crypto::ed25519::Signature;

        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => {
                warn!("manifest: invalid hex signature");
                return false;
            }
        };

        let sig = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => {
                warn!("manifest: invalid signature bytes");
                return false;
            }
        };

        let payload = signing_payload(&self.files, self.written_at_ms);

        use ed25519_dalek::Verifier;
        verifying_key.verify(&payload, &sig).is_ok()
    }

    /// Compare the manifest against current disk state.
    ///
    /// `workspace` is the workspace root where files live.
    /// Returns a list of discrepancies.
    pub fn compare_against_disk(&self, workspace: &Path) -> Vec<ManifestCheckResult> {
        let mut results = Vec::new();

        for (rel_path_str, expected_hash) in &self.files {
            let rel_path = PathBuf::from(rel_path_str);
            let abs_path = workspace.join(&rel_path);

            match std::fs::read(&abs_path) {
                Ok(content) => {
                    let actual_hash = hex::encode(aegis_crypto::hash(&content));
                    if &actual_hash != expected_hash {
                        results.push(ManifestCheckResult::HashChanged {
                            path: rel_path,
                            expected: expected_hash.clone(),
                            actual: actual_hash,
                        });
                    } else {
                        results.push(ManifestCheckResult::Match);
                    }
                }
                Err(_) => {
                    results.push(ManifestCheckResult::Missing {
                        path: rel_path,
                    });
                }
            }
        }

        results
    }

    /// Update the hash for a single file (after a trusted channel change).
    /// Re-signs the manifest.
    pub fn update_file(
        &mut self,
        rel_path: &str,
        new_hash: &str,
        signing_key: &aegis_crypto::ed25519::SigningKey,
    ) {
        use aegis_crypto::ed25519::Signer;

        self.files.insert(rel_path.to_string(), new_hash.to_string());
        self.written_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_millis() as u64;

        let payload = signing_payload(&self.files, self.written_at_ms);
        let signature = signing_key.sign(&payload);
        self.signature = aegis_crypto::ed25519::signature_hex(&signature);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_signing_key() -> aegis_crypto::ed25519::SigningKey {
        aegis_crypto::ed25519::generate_keypair()
    }

    #[test]
    fn create_and_verify_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"soul content").unwrap();
        fs::write(ws.join("AGENTS.md"), b"agents content").unwrap();

        let store = SnapshotStore::load(
            ws,
            &[PathBuf::from("SOUL.md"), PathBuf::from("AGENTS.md")],
        );

        let key = test_signing_key();
        let manifest = FileManifest::from_snapshot(&store, &key);

        assert_eq!(manifest.files.len(), 2);
        assert!(manifest.verify_signature(&key.verifying_key()));
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"soul").unwrap();
        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        let key = test_signing_key();
        let mut manifest = FileManifest::from_snapshot(&store, &key);

        // Tamper with the manifest
        manifest.files.insert("SOUL.md".to_string(), "deadbeef".to_string());

        assert!(!manifest.verify_signature(&key.verifying_key()));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"soul").unwrap();
        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        let key1 = test_signing_key();
        let key2 = test_signing_key();
        let manifest = FileManifest::from_snapshot(&store, &key1);

        // Different key should fail
        assert!(!manifest.verify_signature(&key2.verifying_key()));
    }

    #[test]
    fn write_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let data_dir = tempfile::tempdir().unwrap();

        fs::write(ws.join("SOUL.md"), b"soul").unwrap();
        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        let key = test_signing_key();
        let manifest = FileManifest::from_snapshot(&store, &key);
        manifest.write_to(data_dir.path()).unwrap();

        let loaded = FileManifest::load_from(data_dir.path()).unwrap();
        assert_eq!(loaded.files, manifest.files);
        assert_eq!(loaded.written_at_ms, manifest.written_at_ms);
        assert_eq!(loaded.signature, manifest.signature);
        assert!(loaded.verify_signature(&key.verifying_key()));
    }

    #[test]
    fn compare_clean_disk() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"soul").unwrap();
        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        let key = test_signing_key();
        let manifest = FileManifest::from_snapshot(&store, &key);

        let results = manifest.compare_against_disk(ws);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], ManifestCheckResult::Match);
    }

    #[test]
    fn compare_detects_between_session_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"original soul").unwrap();
        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        let key = test_signing_key();
        let manifest = FileManifest::from_snapshot(&store, &key);

        // Simulate between-session tampering
        fs::write(ws.join("SOUL.md"), b"tampered soul").unwrap();

        let results = manifest.compare_against_disk(ws);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], ManifestCheckResult::HashChanged { .. }));
    }

    #[test]
    fn compare_detects_deleted_file() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"soul").unwrap();
        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        let key = test_signing_key();
        let manifest = FileManifest::from_snapshot(&store, &key);

        fs::remove_file(ws.join("SOUL.md")).unwrap();

        let results = manifest.compare_against_disk(ws);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], ManifestCheckResult::Missing { .. }));
    }

    #[test]
    fn update_file_resigns_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"soul v1").unwrap();
        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        let key = test_signing_key();
        let mut manifest = FileManifest::from_snapshot(&store, &key);
        let old_sig = manifest.signature.clone();

        // Update after trusted channel change
        let new_hash = hex::encode(aegis_crypto::hash(b"soul v2"));
        manifest.update_file("SOUL.md", &new_hash, &key);

        assert_ne!(manifest.signature, old_sig);
        assert_eq!(manifest.files["SOUL.md"], new_hash);
        assert!(manifest.verify_signature(&key.verifying_key()));
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(FileManifest::load_from(dir.path()).is_none());
    }
}
