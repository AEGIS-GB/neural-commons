//! Memory file configuration (D11)
//!
//! Defines which files are considered "memory files" and should be monitored.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Hard-coded default memory file patterns (D11).
/// These are always monitored regardless of config.
pub const DEFAULT_MEMORY_PATTERNS: &[&str] = &[
    "MEMORY.md",
    "*.memory.md",
    "memory/*.md",
    "SOUL.md",
];

/// Memory monitoring configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Additional paths to monitor (from config.json -> memory_paths[]).
    /// Supports glob patterns.
    #[serde(default)]
    pub memory_paths: Vec<String>,

    /// Whether to include default patterns (default: true).
    #[serde(default = "default_true")]
    pub include_defaults: bool,

    /// Hash check interval in seconds (default: 60, per D5 periodic hash).
    #[serde(default = "default_hash_interval")]
    pub hash_interval_secs: u64,
}

fn default_true() -> bool { true }
fn default_hash_interval() -> u64 { 60 }

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            memory_paths: Vec::new(),
            include_defaults: true,
            hash_interval_secs: 60,
        }
    }
}

impl MemoryConfig {
    /// Get all memory file patterns (defaults + configured).
    pub fn all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        if self.include_defaults {
            for p in DEFAULT_MEMORY_PATTERNS {
                patterns.push(p.to_string());
            }
        }
        patterns.extend(self.memory_paths.clone());
        patterns
    }

    /// Check if a file path matches any memory file pattern.
    pub fn is_memory_file(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        let file_name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        for pattern in self.all_patterns() {
            if matches_pattern(&pattern, &path_str, &file_name) {
                return true;
            }
        }
        false
    }

    /// Resolve all matching files in a directory.
    pub fn find_memory_files(&self, base_dir: &Path) -> Vec<PathBuf> {
        let mut results = Vec::new();
        let _patterns = self.all_patterns();

        if let Ok(entries) = std::fs::read_dir(base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && self.is_memory_file(&path) {
                    results.push(path);
                }
            }
        }

        // Also check memory/ subdirectory
        let memory_dir = base_dir.join("memory");
        if memory_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&memory_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && self.is_memory_file(&path) {
                        results.push(path);
                    }
                }
            }

        results.sort();
        results
    }
}

/// Simple glob pattern matching.
/// Supports: * (any sequence), exact match, prefix/suffix matching.
fn matches_pattern(pattern: &str, full_path: &str, file_name: &str) -> bool {
    // Exact filename match
    if file_name == pattern {
        return true;
    }

    // Simple wildcard patterns
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // e.g., ".memory.md"
        return file_name.ends_with(suffix);
    }

    if pattern.contains('/') {
        // Path pattern like "memory/*.md"
        let parts: Vec<&str> = pattern.splitn(2, '/').collect();
        if parts.len() == 2 {
            let dir_part = parts[0];
            let file_part = parts[1];

            // Check if the full path contains the directory
            if full_path.contains(&format!("/{}/", dir_part))
                || full_path.contains(&format!("\\{}\\", dir_part))
            {
                if file_part == "*.md" {
                    return file_name.ends_with(".md");
                }
                return file_name == file_part;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_patterns() {
        let config = MemoryConfig::default();
        assert_eq!(config.all_patterns().len(), 4);
    }

    #[test]
    fn test_is_memory_file_exact_match() {
        let config = MemoryConfig::default();
        assert!(config.is_memory_file(Path::new("MEMORY.md")));
        assert!(config.is_memory_file(Path::new("SOUL.md")));
        assert!(config.is_memory_file(Path::new("/some/path/MEMORY.md")));
    }

    #[test]
    fn test_is_memory_file_wildcard() {
        let config = MemoryConfig::default();
        assert!(config.is_memory_file(Path::new("project.memory.md")));
        assert!(config.is_memory_file(Path::new("notes.memory.md")));
        assert!(!config.is_memory_file(Path::new("notes.md")));
    }

    #[test]
    fn test_is_memory_file_custom_paths() {
        let config = MemoryConfig {
            memory_paths: vec!["CUSTOM.md".to_string()],
            include_defaults: true,
            hash_interval_secs: 60,
        };
        assert!(config.is_memory_file(Path::new("CUSTOM.md")));
        assert!(config.is_memory_file(Path::new("MEMORY.md"))); // default still active
    }

    #[test]
    fn test_no_defaults() {
        let config = MemoryConfig {
            memory_paths: vec!["CUSTOM.md".to_string()],
            include_defaults: false,
            hash_interval_secs: 60,
        };
        assert!(config.is_memory_file(Path::new("CUSTOM.md")));
        assert!(!config.is_memory_file(Path::new("MEMORY.md"))); // default disabled
    }
}
