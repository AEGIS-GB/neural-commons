//! Snapshot store for critical protected files.
//!
//! At startup, Aegis reads every critical protected file into memory.
//! When the barrier watcher detects tampering in enforce mode, it
//! restores the file from the in-memory snapshot — no git, no external
//! dependencies.
//!
//! Design constraints:
//!   - Only critical files are snapshotted (SOUL.md, AGENTS.md, etc.)
//!   - Snapshots are immutable after initial load (no runtime updates)
//!   - Files that don't exist at startup get no snapshot (can't restore what never was)
//!   - Restore writes atomically: write to .tmp, then rename

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// A single file's snapshotted state.
#[derive(Debug, Clone)]
pub struct FileSnapshot {
    /// Original file content at startup.
    pub content: Vec<u8>,
    /// SHA-256 of content, lowercase hex.
    pub hash: String,
}

/// Holds in-memory snapshots of critical protected files.
///
/// Thread-safe: all reads are immutable after `load()`.
#[derive(Debug)]
pub struct SnapshotStore {
    /// workspace_root-relative path → snapshot
    snapshots: HashMap<PathBuf, FileSnapshot>,
}

impl SnapshotStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
        }
    }

    /// Load snapshots for all critical files that exist on disk.
    ///
    /// `workspace` is the absolute path to the bot's workspace root.
    /// `critical_paths` are workspace-relative paths (e.g. "SOUL.md").
    ///
    /// Files that don't exist or can't be read are skipped with a warning.
    pub fn load(workspace: &Path, critical_paths: &[PathBuf]) -> Self {
        let mut snapshots = HashMap::new();

        for rel_path in critical_paths {
            let abs_path = workspace.join(rel_path);
            match std::fs::read(&abs_path) {
                Ok(content) => {
                    let hash = hex::encode(aegis_crypto::hash(&content));
                    info!(
                        path = %rel_path.display(),
                        hash = &hash[..16],
                        size = content.len(),
                        "snapshot: captured critical file"
                    );
                    snapshots.insert(
                        rel_path.clone(),
                        FileSnapshot { content, hash },
                    );
                }
                Err(e) => {
                    debug!(
                        path = %rel_path.display(),
                        error = %e,
                        "snapshot: critical file not found at startup — will be protected once created"
                    );
                }
            }
        }

        info!(count = snapshots.len(), "snapshot store loaded");
        Self { snapshots }
    }

    /// Check whether we have a snapshot for this path.
    pub fn has_snapshot(&self, rel_path: &Path) -> bool {
        self.snapshots.contains_key(rel_path)
    }

    /// Get the snapshot hash for a path (if snapshotted).
    pub fn get_hash(&self, rel_path: &Path) -> Option<&str> {
        self.snapshots.get(rel_path).map(|s| s.hash.as_str())
    }

    /// Restore a file from its snapshot.
    ///
    /// Writes to a `.tmp` file first, then renames for atomicity.
    /// Returns `Ok(true)` if restored, `Ok(false)` if no snapshot exists,
    /// `Err` on I/O failure.
    pub fn restore(&self, workspace: &Path, rel_path: &Path) -> Result<bool, std::io::Error> {
        let snapshot = match self.snapshots.get(rel_path) {
            Some(s) => s,
            None => {
                debug!(path = %rel_path.display(), "snapshot: no snapshot available for restore");
                return Ok(false);
            }
        };

        let abs_path = workspace.join(rel_path);
        let tmp_path = abs_path.with_extension("aegis-restore.tmp");

        // Write to temp file first
        std::fs::write(&tmp_path, &snapshot.content)?;

        // Atomic rename
        std::fs::rename(&tmp_path, &abs_path)?;

        info!(
            path = %rel_path.display(),
            hash = &snapshot.hash[..16],
            "snapshot: file restored from startup snapshot"
        );

        Ok(true)
    }

    /// Number of snapshotted files.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

impl Default for SnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn load_captures_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"I am the soul").unwrap();
        fs::write(ws.join("AGENTS.md"), b"Agent list").unwrap();

        let paths = vec![
            PathBuf::from("SOUL.md"),
            PathBuf::from("AGENTS.md"),
            PathBuf::from("MISSING.md"),
        ];

        let store = SnapshotStore::load(ws, &paths);
        assert_eq!(store.len(), 2);
        assert!(store.has_snapshot(Path::new("SOUL.md")));
        assert!(store.has_snapshot(Path::new("AGENTS.md")));
        assert!(!store.has_snapshot(Path::new("MISSING.md")));
    }

    #[test]
    fn restore_overwrites_tampered_file() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        let original = b"I am the original soul";
        fs::write(ws.join("SOUL.md"), original).unwrap();

        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        // Tamper with the file
        fs::write(ws.join("SOUL.md"), b"I have been corrupted").unwrap();

        // Restore
        let restored = store.restore(ws, Path::new("SOUL.md")).unwrap();
        assert!(restored);

        // Verify content matches original
        let content = fs::read(ws.join("SOUL.md")).unwrap();
        assert_eq!(content, original);
    }

    #[test]
    fn restore_returns_false_for_unknown_path() {
        let store = SnapshotStore::new();
        let dir = tempfile::tempdir().unwrap();
        let result = store.restore(dir.path(), Path::new("unknown.md")).unwrap();
        assert!(!result);
    }

    #[test]
    fn get_hash_returns_correct_hash() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let content = b"test content";
        fs::write(ws.join("test.md"), content).unwrap();

        let expected_hash = hex::encode(aegis_crypto::hash(content));
        let store = SnapshotStore::load(ws, &[PathBuf::from("test.md")]);

        assert_eq!(store.get_hash(Path::new("test.md")), Some(expected_hash.as_str()));
    }

    #[test]
    fn empty_store() {
        let store = SnapshotStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn restore_recreates_deleted_file() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        fs::write(ws.join("SOUL.md"), b"original").unwrap();
        let store = SnapshotStore::load(ws, &[PathBuf::from("SOUL.md")]);

        // Delete the file
        fs::remove_file(ws.join("SOUL.md")).unwrap();
        assert!(!ws.join("SOUL.md").exists());

        // Restore brings it back
        let restored = store.restore(ws, Path::new("SOUL.md")).unwrap();
        assert!(restored);
        assert_eq!(fs::read(ws.join("SOUL.md")).unwrap(), b"original");
    }
}
