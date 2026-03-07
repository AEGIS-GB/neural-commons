//! Protected file list management (D5)
//!
//! Network-broadcasted defaults (Foundation-signed, monotonic version).
//! Warden-selectable custom files (count toward 50-path cap).
//! Directory exclusions: .git, node_modules, .venv, __pycache__, target, .cache

use std::path::Path;

use crate::types::{
    FileScope, ProtectedFileEntry, SensitivityClass, EXCLUDED_DIRS, MAX_WATCHED_PATHS,
};

// ═══════════════════════════════════════════════════════════════════
// Error type
// ═══════════════════════════════════════════════════════════════════

/// Errors arising from protected-file list operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BarrierError {
    /// Adding this entry would exceed the MAX_WATCHED_PATHS cap.
    #[error(
        "watched-path cap exceeded: {current} + 1 > {cap} (MAX_WATCHED_PATHS)",
        cap = MAX_WATCHED_PATHS,
    )]
    CapExceeded { current: usize },

    /// Attempted to remove a system-protected file (only warden files can be removed).
    #[error("cannot remove system-protected pattern: {pattern}")]
    SystemFileProtected { pattern: String },

    /// The supplied pattern is empty or otherwise invalid.
    #[error("invalid pattern: {reason}")]
    InvalidPattern { reason: String },

    /// The pattern was not found in the warden list.
    #[error("pattern not found in warden list: {pattern}")]
    PatternNotFound { pattern: String },
}

// ═══════════════════════════════════════════════════════════════════
// Manager
// ═══════════════════════════════════════════════════════════════════

/// Manages the combined set of system-default and warden-selected protected files.
///
/// System files originate from Foundation-signed broadcasts and cannot be removed
/// by the warden.  Warden files are user-added and may be freely added or removed
/// provided the total count stays within [`MAX_WATCHED_PATHS`].
#[derive(Debug, Clone)]
pub struct ProtectedFileManager {
    /// Files from the Foundation broadcast (immutable once loaded).
    pub system_files: Vec<ProtectedFileEntry>,
    /// User-added files selected by the warden.
    pub warden_files: Vec<ProtectedFileEntry>,
    /// Monotonic version of the currently loaded system list.
    pub current_version: u32,
}

impl ProtectedFileManager {
    // ───────────────────────────────────────────────────────────────
    // Construction
    // ───────────────────────────────────────────────────────────────

    /// Create a new manager pre-loaded with hardcoded system defaults.
    ///
    /// Default system files:
    ///   SOUL.md         — WorkspaceRoot, critical, Standard
    ///   AGENTS.md       — WorkspaceRoot, critical, Standard
    ///   IDENTITY.md     — WorkspaceRoot, critical, Standard
    ///   TOOLS.md        — WorkspaceRoot, critical, Standard
    ///   BOOT.md         — WorkspaceRoot, critical, Standard
    ///   MEMORY.md       — WorkspaceRoot, critical, Standard
    ///   *.memory.md     — DepthLimited(3), critical, Standard
    ///   .env*           — DepthLimited(2), critical, Credential
    ///   config.toml     — WorkspaceRoot, not critical, Standard
    pub fn new() -> Self {
        let system_files = vec![
            ProtectedFileEntry {
                pattern: "SOUL.md".into(),
                scope: FileScope::WorkspaceRoot,
                max_depth: None,
                critical: true,
                sensitivity: SensitivityClass::Standard,
            },
            ProtectedFileEntry {
                pattern: "AGENTS.md".into(),
                scope: FileScope::WorkspaceRoot,
                max_depth: None,
                critical: true,
                sensitivity: SensitivityClass::Standard,
            },
            ProtectedFileEntry {
                pattern: "IDENTITY.md".into(),
                scope: FileScope::WorkspaceRoot,
                max_depth: None,
                critical: true,
                sensitivity: SensitivityClass::Standard,
            },
            ProtectedFileEntry {
                pattern: "TOOLS.md".into(),
                scope: FileScope::WorkspaceRoot,
                max_depth: None,
                critical: true,
                sensitivity: SensitivityClass::Standard,
            },
            ProtectedFileEntry {
                pattern: "BOOT.md".into(),
                scope: FileScope::WorkspaceRoot,
                max_depth: None,
                critical: true,
                sensitivity: SensitivityClass::Standard,
            },
            ProtectedFileEntry {
                pattern: "MEMORY.md".into(),
                scope: FileScope::WorkspaceRoot,
                max_depth: None,
                critical: true,
                sensitivity: SensitivityClass::Standard,
            },
            ProtectedFileEntry {
                pattern: "*.memory.md".into(),
                scope: FileScope::DepthLimited,
                max_depth: Some(3),
                critical: true,
                sensitivity: SensitivityClass::Standard,
            },
            ProtectedFileEntry {
                pattern: ".env*".into(),
                scope: FileScope::DepthLimited,
                max_depth: Some(2),
                critical: true,
                sensitivity: SensitivityClass::Credential,
            },
            ProtectedFileEntry {
                pattern: "config.toml".into(),
                scope: FileScope::WorkspaceRoot,
                max_depth: None,
                critical: false,
                sensitivity: SensitivityClass::Standard,
            },
        ];

        Self {
            system_files,
            warden_files: Vec::new(),
            current_version: 1,
        }
    }

    // ───────────────────────────────────────────────────────────────
    // Warden file management
    // ───────────────────────────────────────────────────────────────

    /// Add a warden-selected file to the protected list.
    ///
    /// Returns [`BarrierError::CapExceeded`] if the total (system + warden)
    /// would exceed [`MAX_WATCHED_PATHS`].
    /// Returns [`BarrierError::InvalidPattern`] if the pattern is empty.
    pub fn add_warden_file(
        &mut self,
        pattern: String,
        scope: FileScope,
        max_depth: Option<u32>,
        critical: bool,
        sensitivity: SensitivityClass,
    ) -> Result<(), BarrierError> {
        // Validate pattern.
        if pattern.is_empty() {
            return Err(BarrierError::InvalidPattern {
                reason: "pattern must not be empty".into(),
            });
        }

        // DepthLimited scope requires a max_depth value.
        if scope == FileScope::DepthLimited && max_depth.is_none() {
            return Err(BarrierError::InvalidPattern {
                reason: "DepthLimited scope requires max_depth".into(),
            });
        }

        // Enforce the cap.
        let total = self.system_files.len() + self.warden_files.len();
        if total >= MAX_WATCHED_PATHS {
            return Err(BarrierError::CapExceeded { current: total });
        }

        self.warden_files.push(ProtectedFileEntry {
            pattern,
            scope,
            max_depth,
            critical,
            sensitivity,
        });

        Ok(())
    }

    /// Remove a warden-selected file from the protected list.
    ///
    /// Returns [`BarrierError::SystemFileProtected`] if the pattern belongs to
    /// the system list.
    /// Returns [`BarrierError::PatternNotFound`] if the pattern is not present
    /// in the warden list.
    pub fn remove_warden_file(&mut self, pattern: &str) -> Result<(), BarrierError> {
        // Guard: cannot remove system files.
        if self.system_files.iter().any(|e| e.pattern == pattern) {
            return Err(BarrierError::SystemFileProtected {
                pattern: pattern.into(),
            });
        }

        let before = self.warden_files.len();
        self.warden_files.retain(|e| e.pattern != pattern);

        if self.warden_files.len() == before {
            return Err(BarrierError::PatternNotFound {
                pattern: pattern.into(),
            });
        }

        Ok(())
    }

    // ───────────────────────────────────────────────────────────────
    // Queries
    // ───────────────────────────────────────────────────────────────

    /// Return references to all protected file entries (system first, then warden).
    pub fn list_all(&self) -> Vec<&ProtectedFileEntry> {
        self.system_files
            .iter()
            .chain(self.warden_files.iter())
            .collect()
    }

    /// Check whether `path` matches any protected-file pattern (system or warden).
    ///
    /// Paths that traverse an excluded directory never match.
    pub fn is_protected(&self, path: &Path) -> bool {
        if Self::is_excluded_dir(path) {
            return false;
        }
        self.list_all()
            .iter()
            .any(|entry| Self::matches_pattern(&entry.pattern, &entry.scope, entry.max_depth, path))
    }

    /// Check whether `path` matches a *critical* protected-file entry.
    ///
    /// Critical files participate in the Layer 3 outbound-proxy interlock.
    pub fn is_critical(&self, path: &Path) -> bool {
        if Self::is_excluded_dir(path) {
            return false;
        }
        self.list_all().iter().any(|entry| {
            entry.critical
                && Self::matches_pattern(&entry.pattern, &entry.scope, entry.max_depth, path)
        })
    }

    /// Return the [`SensitivityClass`] for a given path.
    ///
    /// If the path matches multiple entries, the *most sensitive* class wins
    /// (`Credential` > `Standard`).  If the path is not protected at all,
    /// returns [`SensitivityClass::Standard`] as a safe default.
    pub fn get_sensitivity(&self, path: &Path) -> SensitivityClass {
        let mut result = SensitivityClass::Standard;

        for entry in self.list_all() {
            if Self::matches_pattern(&entry.pattern, &entry.scope, entry.max_depth, path) {
                if entry.sensitivity == SensitivityClass::Credential {
                    // Credential is the highest class; short-circuit.
                    return SensitivityClass::Credential;
                }
                result = entry.sensitivity.clone();
            }
        }

        result
    }

    // ───────────────────────────────────────────────────────────────
    // Pattern matching
    // ───────────────────────────────────────────────────────────────

    /// Determine whether `path` matches a single protected-file pattern under
    /// the given scope and optional depth limit.
    ///
    /// Supported pattern forms:
    ///   - Exact name: `"config.toml"` matches only that file name.
    ///   - Leading glob: `"*.memory.md"` matches any file ending in `.memory.md`.
    ///   - Trailing glob: `".env*"` matches any file starting with `.env`.
    ///
    /// Scope semantics:
    ///   - [`FileScope::WorkspaceRoot`]: only the file name (final component) is
    ///     checked; the path must have at most one component (i.e. live at the
    ///     workspace root).
    ///   - [`FileScope::DepthLimited`]: the file name is checked, and the path
    ///     depth must not exceed `max_depth`.
    pub fn matches_pattern(
        pattern: &str,
        scope: &FileScope,
        max_depth: Option<u32>,
        path: &Path,
    ) -> bool {
        // Extract the file-name component.
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => return false,
        };

        // Check scope / depth constraints.
        let depth = path.components().count();
        match scope {
            FileScope::WorkspaceRoot => {
                // Must be a single-component path (lives at workspace root).
                if depth != 1 {
                    return false;
                }
            }
            FileScope::DepthLimited => {
                if let Some(max) = max_depth {
                    if depth as u32 > max {
                        return false;
                    }
                }
            }
        }

        // Pattern matching against the file name.
        Self::name_matches_pattern(pattern, file_name)
    }

    /// Pure file-name vs pattern check (no scope/depth logic).
    fn name_matches_pattern(pattern: &str, file_name: &str) -> bool {
        if pattern.starts_with('*') {
            // Leading glob: "*.memory.md"  ->  suffix = ".memory.md"
            let suffix = &pattern[1..];
            file_name.ends_with(suffix)
        } else if pattern.ends_with('*') {
            // Trailing glob: ".env*"  ->  prefix = ".env"
            let prefix = &pattern[..pattern.len() - 1];
            file_name.starts_with(prefix)
        } else {
            // Exact match.
            file_name == pattern
        }
    }

    // ───────────────────────────────────────────────────────────────
    // Directory exclusions
    // ───────────────────────────────────────────────────────────────

    /// Returns `true` if *any* component of `path` is one of the
    /// [`EXCLUDED_DIRS`] (e.g. `.git`, `node_modules`, `target`).
    pub fn is_excluded_dir(path: &Path) -> bool {
        for component in path.components() {
            if let Some(s) = component.as_os_str().to_str() {
                if EXCLUDED_DIRS.contains(&s) {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for ProtectedFileManager {
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

    // ─── Default system patterns ─────────────────────────────────

    #[test]
    fn default_system_files_count() {
        let mgr = ProtectedFileManager::new();
        assert_eq!(mgr.system_files.len(), 9);
        assert!(mgr.warden_files.is_empty());
        assert_eq!(mgr.current_version, 1);
    }

    #[test]
    fn default_soul_md_is_critical() {
        let mgr = ProtectedFileManager::new();
        assert!(mgr.is_protected(Path::new("SOUL.md")));
        assert!(mgr.is_critical(Path::new("SOUL.md")));
    }

    #[test]
    fn default_agents_md_is_critical() {
        let mgr = ProtectedFileManager::new();
        assert!(mgr.is_protected(Path::new("AGENTS.md")));
        assert!(mgr.is_critical(Path::new("AGENTS.md")));
    }

    #[test]
    fn default_identity_md_is_critical() {
        let mgr = ProtectedFileManager::new();
        assert!(mgr.is_protected(Path::new("IDENTITY.md")));
        assert!(mgr.is_critical(Path::new("IDENTITY.md")));
    }

    #[test]
    fn default_tools_md_is_critical() {
        let mgr = ProtectedFileManager::new();
        assert!(mgr.is_protected(Path::new("TOOLS.md")));
        assert!(mgr.is_critical(Path::new("TOOLS.md")));
    }

    #[test]
    fn default_boot_md_is_critical() {
        let mgr = ProtectedFileManager::new();
        assert!(mgr.is_protected(Path::new("BOOT.md")));
        assert!(mgr.is_critical(Path::new("BOOT.md")));
    }

    #[test]
    fn default_memory_md_is_critical() {
        let mgr = ProtectedFileManager::new();
        assert!(mgr.is_protected(Path::new("MEMORY.md")));
        assert!(mgr.is_critical(Path::new("MEMORY.md")));
    }

    #[test]
    fn default_config_toml_not_critical() {
        let mgr = ProtectedFileManager::new();
        assert!(mgr.is_protected(Path::new("config.toml")));
        assert!(!mgr.is_critical(Path::new("config.toml")));
    }

    #[test]
    fn default_env_files_are_credential() {
        let mgr = ProtectedFileManager::new();
        assert!(mgr.is_protected(Path::new(".env")));
        assert!(mgr.is_protected(Path::new(".env.local")));
        assert!(mgr.is_protected(Path::new(".env.production")));
        assert_eq!(
            mgr.get_sensitivity(Path::new(".env")),
            SensitivityClass::Credential
        );
    }

    #[test]
    fn default_memory_glob_matches_nested() {
        let mgr = ProtectedFileManager::new();
        // Depth 2 — within max_depth=3
        assert!(mgr.is_protected(Path::new("sub/notes.memory.md")));
        // Depth 3 — still within
        assert!(mgr.is_protected(Path::new("a/b/notes.memory.md")));
        // Depth 4 — exceeds max_depth=3
        assert!(!mgr.is_protected(Path::new("a/b/c/notes.memory.md")));
    }

    // ─── Warden add / remove ─────────────────────────────────────

    #[test]
    fn add_warden_file_success() {
        let mut mgr = ProtectedFileManager::new();
        let result = mgr.add_warden_file(
            "secrets.yaml".into(),
            FileScope::WorkspaceRoot,
            None,
            false,
            SensitivityClass::Credential,
        );
        assert!(result.is_ok());
        assert_eq!(mgr.warden_files.len(), 1);
        assert!(mgr.is_protected(Path::new("secrets.yaml")));
        assert_eq!(
            mgr.get_sensitivity(Path::new("secrets.yaml")),
            SensitivityClass::Credential
        );
    }

    #[test]
    fn add_warden_file_empty_pattern_rejected() {
        let mut mgr = ProtectedFileManager::new();
        let result = mgr.add_warden_file(
            "".into(),
            FileScope::WorkspaceRoot,
            None,
            false,
            SensitivityClass::Standard,
        );
        assert_eq!(
            result,
            Err(BarrierError::InvalidPattern {
                reason: "pattern must not be empty".into(),
            })
        );
    }

    #[test]
    fn add_warden_file_depth_limited_requires_max_depth() {
        let mut mgr = ProtectedFileManager::new();
        let result = mgr.add_warden_file(
            "*.log".into(),
            FileScope::DepthLimited,
            None, // missing max_depth
            false,
            SensitivityClass::Standard,
        );
        assert!(matches!(result, Err(BarrierError::InvalidPattern { .. })));
    }

    #[test]
    fn remove_warden_file_success() {
        let mut mgr = ProtectedFileManager::new();
        mgr.add_warden_file(
            "custom.yaml".into(),
            FileScope::WorkspaceRoot,
            None,
            false,
            SensitivityClass::Standard,
        )
        .unwrap();

        assert!(mgr.remove_warden_file("custom.yaml").is_ok());
        assert!(mgr.warden_files.is_empty());
    }

    #[test]
    fn remove_system_file_rejected() {
        let mut mgr = ProtectedFileManager::new();
        let result = mgr.remove_warden_file("SOUL.md");
        assert_eq!(
            result,
            Err(BarrierError::SystemFileProtected {
                pattern: "SOUL.md".into(),
            })
        );
    }

    #[test]
    fn remove_nonexistent_pattern_rejected() {
        let mut mgr = ProtectedFileManager::new();
        let result = mgr.remove_warden_file("nope.txt");
        assert_eq!(
            result,
            Err(BarrierError::PatternNotFound {
                pattern: "nope.txt".into(),
            })
        );
    }

    // ─── Cap enforcement ─────────────────────────────────────────

    #[test]
    fn cap_enforcement() {
        let mut mgr = ProtectedFileManager::new();
        let system_count = mgr.system_files.len();
        let slots = MAX_WATCHED_PATHS - system_count;

        // Fill remaining slots.
        for i in 0..slots {
            mgr.add_warden_file(
                format!("file_{i}.txt"),
                FileScope::WorkspaceRoot,
                None,
                false,
                SensitivityClass::Standard,
            )
            .unwrap();
        }

        assert_eq!(
            mgr.system_files.len() + mgr.warden_files.len(),
            MAX_WATCHED_PATHS
        );

        // One more should fail.
        let result = mgr.add_warden_file(
            "overflow.txt".into(),
            FileScope::WorkspaceRoot,
            None,
            false,
            SensitivityClass::Standard,
        );
        assert!(matches!(result, Err(BarrierError::CapExceeded { .. })));
    }

    // ─── list_all ────────────────────────────────────────────────

    #[test]
    fn list_all_combines_system_and_warden() {
        let mut mgr = ProtectedFileManager::new();
        mgr.add_warden_file(
            "extra.md".into(),
            FileScope::WorkspaceRoot,
            None,
            false,
            SensitivityClass::Standard,
        )
        .unwrap();

        let all = mgr.list_all();
        assert_eq!(all.len(), mgr.system_files.len() + 1);
        // System files come first.
        assert_eq!(all[0].pattern, "SOUL.md");
        // Warden file at the end.
        assert_eq!(all.last().unwrap().pattern, "extra.md");
    }

    // ─── Pattern matching ────────────────────────────────────────

    #[test]
    fn exact_match() {
        assert!(ProtectedFileManager::matches_pattern(
            "config.toml",
            &FileScope::WorkspaceRoot,
            None,
            Path::new("config.toml"),
        ));
    }

    #[test]
    fn exact_match_wrong_name() {
        assert!(!ProtectedFileManager::matches_pattern(
            "config.toml",
            &FileScope::WorkspaceRoot,
            None,
            Path::new("other.toml"),
        ));
    }

    #[test]
    fn leading_glob_match() {
        assert!(ProtectedFileManager::matches_pattern(
            "*.memory.md",
            &FileScope::DepthLimited,
            Some(3),
            Path::new("sub/notes.memory.md"),
        ));
    }

    #[test]
    fn trailing_glob_match() {
        assert!(ProtectedFileManager::matches_pattern(
            ".env*",
            &FileScope::DepthLimited,
            Some(2),
            Path::new(".env.local"),
        ));
    }

    #[test]
    fn workspace_root_rejects_nested_path() {
        assert!(!ProtectedFileManager::matches_pattern(
            "SOUL.md",
            &FileScope::WorkspaceRoot,
            None,
            Path::new("sub/SOUL.md"),
        ));
    }

    #[test]
    fn depth_limited_rejects_too_deep() {
        assert!(!ProtectedFileManager::matches_pattern(
            "*.memory.md",
            &FileScope::DepthLimited,
            Some(2),
            Path::new("a/b/notes.memory.md"),
        ));
    }

    #[test]
    fn depth_limited_accepts_within_limit() {
        assert!(ProtectedFileManager::matches_pattern(
            "*.memory.md",
            &FileScope::DepthLimited,
            Some(2),
            Path::new("a/notes.memory.md"),
        ));
    }

    // ─── Excluded directories ────────────────────────────────────

    #[test]
    fn excluded_dirs_detected() {
        assert!(ProtectedFileManager::is_excluded_dir(Path::new(
            ".git/config"
        )));
        assert!(ProtectedFileManager::is_excluded_dir(Path::new(
            "node_modules/pkg/index.js"
        )));
        assert!(ProtectedFileManager::is_excluded_dir(Path::new(
            "src/.venv/lib"
        )));
        assert!(ProtectedFileManager::is_excluded_dir(Path::new(
            "__pycache__/mod.pyc"
        )));
        assert!(ProtectedFileManager::is_excluded_dir(Path::new(
            "target/debug/bin"
        )));
        assert!(ProtectedFileManager::is_excluded_dir(Path::new(
            ".cache/data"
        )));
    }

    #[test]
    fn non_excluded_dir_not_detected() {
        assert!(!ProtectedFileManager::is_excluded_dir(Path::new(
            "src/main.rs"
        )));
        assert!(!ProtectedFileManager::is_excluded_dir(Path::new(
            "config.toml"
        )));
    }

    #[test]
    fn excluded_dir_prevents_protection_match() {
        let mgr = ProtectedFileManager::new();
        // .env inside node_modules should NOT be considered protected.
        assert!(!mgr.is_protected(Path::new("node_modules/.env")));
        assert!(!mgr.is_critical(Path::new(".git/SOUL.md")));
    }

    // ─── Critical check ──────────────────────────────────────────

    #[test]
    fn is_critical_returns_false_for_non_critical_entry() {
        let mgr = ProtectedFileManager::new();
        assert!(!mgr.is_critical(Path::new("config.toml")));
    }

    #[test]
    fn is_critical_returns_false_for_unprotected_path() {
        let mgr = ProtectedFileManager::new();
        assert!(!mgr.is_critical(Path::new("random.txt")));
    }

    // ─── Sensitivity ─────────────────────────────────────────────

    #[test]
    fn sensitivity_standard_for_unprotected() {
        let mgr = ProtectedFileManager::new();
        assert_eq!(
            mgr.get_sensitivity(Path::new("unknown.txt")),
            SensitivityClass::Standard
        );
    }

    #[test]
    fn sensitivity_credential_wins_over_standard() {
        let mut mgr = ProtectedFileManager::new();
        // Add a warden file that matches `.env.local` as Standard to verify
        // that the system Credential entry wins.
        mgr.add_warden_file(
            ".env.local".into(),
            FileScope::WorkspaceRoot,
            None,
            false,
            SensitivityClass::Standard,
        )
        .unwrap();
        assert_eq!(
            mgr.get_sensitivity(Path::new(".env.local")),
            SensitivityClass::Credential
        );
    }

    // ─── Default trait ───────────────────────────────────────────

    #[test]
    fn default_trait_works() {
        let mgr = ProtectedFileManager::default();
        assert_eq!(mgr.system_files.len(), 9);
    }

    // ─── Edge cases ──────────────────────────────────────────────

    #[test]
    fn empty_path_does_not_match() {
        let mgr = ProtectedFileManager::new();
        assert!(!mgr.is_protected(Path::new("")));
    }

    #[test]
    fn path_with_no_file_name_does_not_match() {
        // A bare "." has no file_name component on most platforms.
        assert!(!ProtectedFileManager::matches_pattern(
            "SOUL.md",
            &FileScope::WorkspaceRoot,
            None,
            Path::new("."),
        ));
    }

    #[test]
    fn warden_critical_file_detected() {
        let mut mgr = ProtectedFileManager::new();
        mgr.add_warden_file(
            "important.lock".into(),
            FileScope::WorkspaceRoot,
            None,
            true,
            SensitivityClass::Standard,
        )
        .unwrap();
        assert!(mgr.is_critical(Path::new("important.lock")));
    }
}
