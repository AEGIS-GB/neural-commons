//! Memory write interception (D11, D5)
//!
//! Two modes of interception:
//!   1. Tool-mediated: writes through MCP tool calls are intercepted inline
//!      before execution via the proxy middleware
//!   2. External: filesystem watcher detects changes after the fact
//!
//! Both produce MemoryIntegrity receipts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Tracks the known state of each monitored memory file.
#[derive(Debug, Clone)]
pub struct MemoryFileState {
    /// File path
    pub path: PathBuf,
    /// SHA-256 hash of current content, lowercase hex
    pub content_hash: String,
    /// Last modification timestamp (epoch ms)
    pub last_modified_ms: i64,
    /// Who last modified this file
    pub last_modifier: MemoryModifier,
    /// Whether this file has been acknowledged by the warden
    pub warden_acknowledged: bool,
}

/// Who modified a memory file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryModifier {
    /// Modified through an authorized tool call (proxy-intercepted)
    ToolCall { tool_name: String },
    /// Modified externally (detected by filesystem watcher)
    External,
    /// Modified by the warden through aegis CLI (evolution flow)
    WardenEvolution,
    /// Initial state (first scan)
    Genesis,
    /// Unknown modifier (pre-existing file)
    Unknown,
}

/// Result of checking a memory file for changes
#[derive(Debug, Clone)]
pub enum ChangeDetection {
    /// No change detected
    Unchanged,
    /// Content changed — includes old and new hashes
    Changed {
        old_hash: String,
        new_hash: String,
        modifier: MemoryModifier,
    },
    /// File was deleted
    Deleted { old_hash: String },
    /// New file appeared
    NewFile { hash: String },
}

/// Manages tracked memory file states.
pub struct MemoryTracker {
    /// Known states of monitored files
    states: HashMap<PathBuf, MemoryFileState>,
}

impl MemoryTracker {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    /// Initialize tracking for a file (first scan).
    pub fn track_file(&mut self, path: &Path) -> Result<MemoryFileState, crate::MemoryError> {
        let content = std::fs::read(path).map_err(crate::MemoryError::IoError)?;
        let hash = compute_content_hash(&content);
        let now_ms = current_epoch_ms();

        let state = MemoryFileState {
            path: path.to_path_buf(),
            content_hash: hash,
            last_modified_ms: now_ms,
            last_modifier: MemoryModifier::Genesis,
            warden_acknowledged: true,
        };

        self.states.insert(path.to_path_buf(), state.clone());
        Ok(state)
    }

    /// Check a tracked file for changes.
    pub fn check_file(&self, path: &Path) -> Result<ChangeDetection, crate::MemoryError> {
        let known_state = self.states.get(path);

        if !path.exists() {
            return match known_state {
                Some(state) => Ok(ChangeDetection::Deleted {
                    old_hash: state.content_hash.clone(),
                }),
                None => Err(crate::MemoryError::FileNotFound(
                    path.to_string_lossy().to_string(),
                )),
            };
        }

        let content = std::fs::read(path).map_err(crate::MemoryError::IoError)?;
        let new_hash = compute_content_hash(&content);

        match known_state {
            Some(state) => {
                if state.content_hash == new_hash {
                    Ok(ChangeDetection::Unchanged)
                } else {
                    Ok(ChangeDetection::Changed {
                        old_hash: state.content_hash.clone(),
                        new_hash,
                        modifier: MemoryModifier::External,
                    })
                }
            }
            None => Ok(ChangeDetection::NewFile { hash: new_hash }),
        }
    }

    /// Update tracked state after a change has been processed.
    pub fn update_state(
        &mut self,
        path: &Path,
        new_hash: String,
        modifier: MemoryModifier,
        acknowledged: bool,
    ) {
        let now_ms = current_epoch_ms();
        let state = MemoryFileState {
            path: path.to_path_buf(),
            content_hash: new_hash,
            last_modified_ms: now_ms,
            last_modifier: modifier,
            warden_acknowledged: acknowledged,
        };
        self.states.insert(path.to_path_buf(), state);
    }

    /// Get the current state of a tracked file.
    pub fn get_state(&self, path: &Path) -> Option<&MemoryFileState> {
        self.states.get(path)
    }

    /// Get all tracked file paths.
    pub fn tracked_files(&self) -> Vec<&PathBuf> {
        self.states.keys().collect()
    }

    /// Check all tracked files for changes.
    pub fn check_all(&self) -> Vec<(PathBuf, ChangeDetection)> {
        let mut results = Vec::new();
        for path in self.states.keys() {
            match self.check_file(path) {
                Ok(detection) => results.push((path.clone(), detection)),
                Err(_) => results.push((
                    path.clone(),
                    ChangeDetection::Deleted {
                        old_hash: self.states[path].content_hash.clone(),
                    },
                )),
            }
        }
        results
    }
}

impl Default for MemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-256 hash of content, returned as lowercase hex.
fn compute_content_hash(content: &[u8]) -> String {
    let hash = aegis_crypto::hash(content);
    hex::encode(hash)
}

/// Get current time as epoch milliseconds.
fn current_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash_deterministic() {
        let hash1 = compute_content_hash(b"hello world");
        let hash2 = compute_content_hash(b"hello world");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_content_hash_different_for_different_content() {
        let hash1 = compute_content_hash(b"hello world");
        let hash2 = compute_content_hash(b"goodbye world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_tracker_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("MEMORY.md");
        std::fs::write(&file_path, "initial content").unwrap();

        let mut tracker = MemoryTracker::new();
        let state = tracker.track_file(&file_path).unwrap();
        assert_eq!(state.last_modifier, MemoryModifier::Genesis);
        assert!(state.warden_acknowledged);
    }

    #[test]
    fn test_tracker_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("MEMORY.md");
        std::fs::write(&file_path, "initial content").unwrap();

        let mut tracker = MemoryTracker::new();
        tracker.track_file(&file_path).unwrap();

        // Modify the file
        std::fs::write(&file_path, "modified content").unwrap();

        match tracker.check_file(&file_path).unwrap() {
            ChangeDetection::Changed {
                old_hash, new_hash, ..
            } => {
                assert_ne!(old_hash, new_hash);
            }
            other => panic!("expected Changed, got {:?}", other),
        }
    }

    #[test]
    fn test_tracker_detects_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("MEMORY.md");
        std::fs::write(&file_path, "initial content").unwrap();

        let mut tracker = MemoryTracker::new();
        tracker.track_file(&file_path).unwrap();

        match tracker.check_file(&file_path).unwrap() {
            ChangeDetection::Unchanged => {} // expected
            other => panic!("expected Unchanged, got {:?}", other),
        }
    }

    #[test]
    fn test_tracker_detects_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("MEMORY.md");
        std::fs::write(&file_path, "initial content").unwrap();

        let mut tracker = MemoryTracker::new();
        tracker.track_file(&file_path).unwrap();

        std::fs::remove_file(&file_path).unwrap();

        match tracker.check_file(&file_path).unwrap() {
            ChangeDetection::Deleted { .. } => {} // expected
            other => panic!("expected Deleted, got {:?}", other),
        }
    }
}
