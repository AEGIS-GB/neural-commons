//! Warden evolution flow (D5)
//!
//! No grace window. Evolution is explicit and pre-authorized:
//! 1. Warden initiates (`nockchain evolve SOUL.md`)
//! 2. Per-file flock, registry marks "evolution_in_progress" (5min timeout)
//! 3. Editor opens
//! 4. Warden edits and saves
//! 5. Adapter computes diff, runs severity classification (informational)
//! 6. Warden confirms → evolution receipt signed
//! 7. HashRegistry updated → flock released
//!
//! Concurrency: per-file flock. Only one evolution per file at a time.
//! Bot writes during evolution: WriteToken queued, processed after.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{
    ClassificationMethod, EvolutionDetail, EvolutionState, Severity, EVOLUTION_TIMEOUT_MS,
};

// ═══════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur during the evolution flow.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EvolutionError {
    /// Attempted to start an evolution for a file that already has one in progress.
    #[error("evolution already in progress for `{0}`")]
    AlreadyEvolving(PathBuf),

    /// Attempted to confirm or cancel an evolution that does not exist.
    #[error("no active evolution for `{0}`")]
    NotEvolving(PathBuf),

    /// The evolution exceeded the 5-minute timeout window.
    #[error("evolution timed out for `{0}`")]
    TimedOut(PathBuf),
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Returns the current time as Unix milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

// ═══════════════════════════════════════════════════════════════════
// EvolutionManager
// ═══════════════════════════════════════════════════════════════════

/// Manages in-progress warden evolution sessions.
///
/// Each protected file may have at most one active evolution at a time.
/// Evolutions that exceed [`EVOLUTION_TIMEOUT_MS`] are considered expired
/// and will be cleaned up on the next relevant check.
#[derive(Debug)]
pub struct EvolutionManager {
    /// Currently in-progress evolutions, keyed by canonical file path.
    active_evolutions: HashMap<PathBuf, EvolutionState>,
}

impl EvolutionManager {
    /// Create a new, empty evolution manager.
    pub fn new() -> Self {
        Self {
            active_evolutions: HashMap::new(),
        }
    }

    /// Start an evolution session for `file_path`.
    ///
    /// Fails with [`EvolutionError::AlreadyEvolving`] if an evolution is
    /// already active for this file (even if it has timed out — call
    /// [`cleanup_expired`] or [`check_timeout`] first).
    pub fn start(&mut self, file_path: &Path, from_quarantine: bool) -> Result<(), EvolutionError> {
        if self.active_evolutions.contains_key(file_path) {
            return Err(EvolutionError::AlreadyEvolving(file_path.to_path_buf()));
        }

        let now = now_ms();
        let state = EvolutionState {
            file_path: file_path.to_path_buf(),
            started_at: now,
            timeout_at: now + EVOLUTION_TIMEOUT_MS,
            from_quarantine,
        };

        self.active_evolutions.insert(file_path.to_path_buf(), state);
        Ok(())
    }

    /// Check whether `file_path` currently has an active evolution.
    pub fn is_evolving(&self, file_path: &Path) -> bool {
        self.active_evolutions.contains_key(file_path)
    }

    /// If the evolution for `file_path` has exceeded its timeout, remove and
    /// return the state. Returns `None` if no evolution exists or it has not
    /// yet timed out.
    pub fn check_timeout(&mut self, file_path: &Path) -> Option<EvolutionState> {
        let timed_out = self
            .active_evolutions
            .get(file_path)
            .is_some_and(|s| now_ms() > s.timeout_at);

        if timed_out {
            self.active_evolutions.remove(file_path)
        } else {
            None
        }
    }

    /// Confirm (finalize) the evolution for `file_path`.
    ///
    /// The caller provides the hashes and severity classification that were
    /// computed from the diff. On success the evolution state is removed and
    /// an [`EvolutionDetail`] suitable for receipt signing is returned.
    ///
    /// Fails with:
    /// - [`EvolutionError::NotEvolving`] if no evolution is active.
    /// - [`EvolutionError::TimedOut`] if the evolution has expired (the state
    ///   is removed in this case as well).
    pub fn confirm(
        &mut self,
        file_path: &Path,
        previous_hash: &str,
        new_hash: &str,
        diff_hash: &str,
        severity: Severity,
        method: ClassificationMethod,
    ) -> Result<EvolutionDetail, EvolutionError> {
        let state = self
            .active_evolutions
            .remove(file_path)
            .ok_or_else(|| EvolutionError::NotEvolving(file_path.to_path_buf()))?;

        // Even though we removed it, check the timeout so we don't silently
        // accept a stale evolution.
        if now_ms() > state.timeout_at {
            return Err(EvolutionError::TimedOut(file_path.to_path_buf()));
        }

        let source = if state.from_quarantine {
            "from_quarantine".to_owned()
        } else {
            "editor".to_owned()
        };

        Ok(EvolutionDetail {
            previous_hash: previous_hash.to_owned(),
            new_hash: new_hash.to_owned(),
            diff_hash: diff_hash.to_owned(),
            change_severity: severity,
            classification_method: method,
            source,
        })
    }

    /// Cancel the evolution for `file_path`, releasing the slot.
    ///
    /// Returns the removed [`EvolutionState`] so the caller can produce a
    /// cancellation receipt. Fails with [`EvolutionError::NotEvolving`] if no
    /// evolution is active.
    pub fn cancel(&mut self, file_path: &Path) -> Result<EvolutionState, EvolutionError> {
        self.active_evolutions
            .remove(file_path)
            .ok_or_else(|| EvolutionError::NotEvolving(file_path.to_path_buf()))
    }

    /// Remove all evolutions that have exceeded their timeout window.
    ///
    /// Returns a vector of the expired [`EvolutionState`]s so the caller can
    /// generate timeout receipts for each.
    pub fn cleanup_expired(&mut self) -> Vec<EvolutionState> {
        let now = now_ms();
        let expired_keys: Vec<PathBuf> = self
            .active_evolutions
            .iter()
            .filter(|(_, state)| now > state.timeout_at)
            .map(|(path, _)| path.clone())
            .collect();

        expired_keys
            .into_iter()
            .filter_map(|key| self.active_evolutions.remove(&key))
            .collect()
    }

    /// Number of currently active (including possibly expired) evolutions.
    pub fn active_count(&self) -> usize {
        self.active_evolutions.len()
    }
}

impl Default for EvolutionManager {
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
    use std::path::Path;

    /// Helper: build a manager and start an evolution, returning both.
    fn start_fresh(file: &str, from_quarantine: bool) -> EvolutionManager {
        let mut mgr = EvolutionManager::new();
        mgr.start(Path::new(file), from_quarantine).unwrap();
        mgr
    }

    // ---------------------------------------------------------------
    // Start / Confirm happy path
    // ---------------------------------------------------------------

    #[test]
    fn start_and_confirm_flow() {
        let mut mgr = start_fresh("SOUL.md", false);

        assert!(mgr.is_evolving(Path::new("SOUL.md")));
        assert_eq!(mgr.active_count(), 1);

        let detail = mgr
            .confirm(
                Path::new("SOUL.md"),
                "aaa111",
                "bbb222",
                "ccc333",
                Severity::Behavioral,
                ClassificationMethod::Heuristic,
            )
            .unwrap();

        assert_eq!(detail.previous_hash, "aaa111");
        assert_eq!(detail.new_hash, "bbb222");
        assert_eq!(detail.diff_hash, "ccc333");
        assert_eq!(detail.change_severity, Severity::Behavioral);
        assert_eq!(detail.classification_method, ClassificationMethod::Heuristic);
        assert_eq!(detail.source, "editor");

        // State should be gone after confirm.
        assert!(!mgr.is_evolving(Path::new("SOUL.md")));
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn confirm_from_quarantine_sets_source() {
        let mut mgr = start_fresh("SOUL.md", true);

        let detail = mgr
            .confirm(
                Path::new("SOUL.md"),
                "a",
                "b",
                "c",
                Severity::Cosmetic,
                ClassificationMethod::Slm,
            )
            .unwrap();

        assert_eq!(detail.source, "from_quarantine");
    }

    // ---------------------------------------------------------------
    // Double-start rejected
    // ---------------------------------------------------------------

    #[test]
    fn double_start_rejected() {
        let mut mgr = start_fresh("SOUL.md", false);

        let err = mgr.start(Path::new("SOUL.md"), false).unwrap_err();
        assert!(
            matches!(err, EvolutionError::AlreadyEvolving(ref p) if p == Path::new("SOUL.md"))
        );
    }

    // ---------------------------------------------------------------
    // Confirm / Cancel on non-existent evolution
    // ---------------------------------------------------------------

    #[test]
    fn confirm_not_evolving() {
        let mut mgr = EvolutionManager::new();

        let err = mgr
            .confirm(
                Path::new("nope.md"),
                "a",
                "b",
                "c",
                Severity::Cosmetic,
                ClassificationMethod::Heuristic,
            )
            .unwrap_err();

        assert!(matches!(err, EvolutionError::NotEvolving(_)));
    }

    #[test]
    fn cancel_not_evolving() {
        let mut mgr = EvolutionManager::new();

        let err = mgr.cancel(Path::new("nope.md")).unwrap_err();
        assert!(matches!(err, EvolutionError::NotEvolving(_)));
    }

    // ---------------------------------------------------------------
    // Cancel happy path
    // ---------------------------------------------------------------

    #[test]
    fn cancel_returns_state_and_clears() {
        let mut mgr = start_fresh("SOUL.md", false);

        let state = mgr.cancel(Path::new("SOUL.md")).unwrap();
        assert_eq!(state.file_path, Path::new("SOUL.md"));
        assert!(!state.from_quarantine);
        assert!(!mgr.is_evolving(Path::new("SOUL.md")));
        assert_eq!(mgr.active_count(), 0);
    }

    // ---------------------------------------------------------------
    // Timeout detection
    // ---------------------------------------------------------------

    #[test]
    fn check_timeout_returns_none_when_not_expired() {
        let mut mgr = start_fresh("SOUL.md", false);
        // Just started, should not be timed out.
        assert!(mgr.check_timeout(Path::new("SOUL.md")).is_none());
        // Still active.
        assert!(mgr.is_evolving(Path::new("SOUL.md")));
    }

    #[test]
    fn check_timeout_detects_expired() {
        let mut mgr = EvolutionManager::new();

        // Manually insert a state that is already expired.
        let now = now_ms();
        mgr.active_evolutions.insert(
            PathBuf::from("SOUL.md"),
            EvolutionState {
                file_path: PathBuf::from("SOUL.md"),
                started_at: now.saturating_sub(EVOLUTION_TIMEOUT_MS + 1000),
                timeout_at: now.saturating_sub(1000),
                from_quarantine: false,
            },
        );

        let state = mgr.check_timeout(Path::new("SOUL.md"));
        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.file_path, Path::new("SOUL.md"));
        // Should be removed.
        assert!(!mgr.is_evolving(Path::new("SOUL.md")));
    }

    #[test]
    fn confirm_rejects_timed_out_evolution() {
        let mut mgr = EvolutionManager::new();

        let now = now_ms();
        mgr.active_evolutions.insert(
            PathBuf::from("SOUL.md"),
            EvolutionState {
                file_path: PathBuf::from("SOUL.md"),
                started_at: now.saturating_sub(EVOLUTION_TIMEOUT_MS + 1000),
                timeout_at: now.saturating_sub(1000),
                from_quarantine: false,
            },
        );

        let err = mgr
            .confirm(
                Path::new("SOUL.md"),
                "a",
                "b",
                "c",
                Severity::Structural,
                ClassificationMethod::Slm,
            )
            .unwrap_err();

        assert!(matches!(err, EvolutionError::TimedOut(_)));
        // State should still be removed even on timeout error.
        assert!(!mgr.is_evolving(Path::new("SOUL.md")));
    }

    // ---------------------------------------------------------------
    // Cleanup expired
    // ---------------------------------------------------------------

    #[test]
    fn cleanup_expired_removes_only_expired() {
        let mut mgr = EvolutionManager::new();
        let now = now_ms();

        // One expired evolution.
        mgr.active_evolutions.insert(
            PathBuf::from("old.md"),
            EvolutionState {
                file_path: PathBuf::from("old.md"),
                started_at: now.saturating_sub(EVOLUTION_TIMEOUT_MS + 5000),
                timeout_at: now.saturating_sub(5000),
                from_quarantine: false,
            },
        );

        // One fresh evolution.
        mgr.start(Path::new("fresh.md"), true).unwrap();

        let expired = mgr.cleanup_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].file_path, Path::new("old.md"));

        // Fresh one should still be there.
        assert!(mgr.is_evolving(Path::new("fresh.md")));
        assert!(!mgr.is_evolving(Path::new("old.md")));
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn cleanup_expired_returns_empty_when_none_expired() {
        let mut mgr = start_fresh("active.md", false);

        let expired = mgr.cleanup_expired();
        assert!(expired.is_empty());
        assert_eq!(mgr.active_count(), 1);
    }

    // ---------------------------------------------------------------
    // Multiple files
    // ---------------------------------------------------------------

    #[test]
    fn multiple_concurrent_evolutions_on_different_files() {
        let mut mgr = EvolutionManager::new();
        mgr.start(Path::new("a.md"), false).unwrap();
        mgr.start(Path::new("b.md"), true).unwrap();
        mgr.start(Path::new("c.md"), false).unwrap();

        assert_eq!(mgr.active_count(), 3);
        assert!(mgr.is_evolving(Path::new("a.md")));
        assert!(mgr.is_evolving(Path::new("b.md")));
        assert!(mgr.is_evolving(Path::new("c.md")));
        assert!(!mgr.is_evolving(Path::new("d.md")));

        mgr.cancel(Path::new("b.md")).unwrap();
        assert_eq!(mgr.active_count(), 2);
        assert!(!mgr.is_evolving(Path::new("b.md")));
    }

    // ---------------------------------------------------------------
    // Default trait
    // ---------------------------------------------------------------

    #[test]
    fn default_creates_empty_manager() {
        let mgr = EvolutionManager::default();
        assert_eq!(mgr.active_count(), 0);
    }

    // ---------------------------------------------------------------
    // now_ms sanity
    // ---------------------------------------------------------------

    #[test]
    fn now_ms_returns_reasonable_value() {
        let ms = now_ms();
        // Should be after 2024-01-01 00:00:00 UTC (1704067200000 ms).
        assert!(ms > 1_704_067_200_000);
    }
}
