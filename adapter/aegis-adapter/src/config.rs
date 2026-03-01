//! Adapter configuration
//!
//! Loads configuration from TOML file or environment.
//! Composes configs for all sub-crates.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::Mode;

/// Top-level adapter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    /// Operating mode
    #[serde(default)]
    pub mode: AdapterMode,

    /// Proxy configuration
    #[serde(default)]
    pub proxy: ProxySection,

    /// Vault configuration
    #[serde(default)]
    pub vault: VaultSection,

    /// Memory monitoring configuration
    #[serde(default)]
    pub memory: MemorySection,

    /// Data directory for SQLite databases and state
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterMode {
    ObserveOnly,
    Enforce,
    PassThrough,
}

impl Default for AdapterMode {
    fn default() -> Self {
        AdapterMode::ObserveOnly
    }
}

impl From<AdapterMode> for Mode {
    fn from(m: AdapterMode) -> Self {
        match m {
            AdapterMode::ObserveOnly => Mode::ObserveOnly,
            AdapterMode::Enforce => Mode::Enforce,
            AdapterMode::PassThrough => Mode::PassThrough,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySection {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_upstream_url")]
    pub upstream_url: String,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            upstream_url: default_upstream_url(),
            max_body_size: default_max_body_size(),
            rate_limit_per_minute: default_rate_limit(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSection {
    /// Additional file extensions to scan for credentials
    #[serde(default)]
    pub scan_extensions: Vec<String>,
    /// Whether to auto-scan on startup
    #[serde(default = "default_true")]
    pub auto_scan: bool,
}

impl Default for VaultSection {
    fn default() -> Self {
        Self {
            scan_extensions: Vec::new(),
            auto_scan: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySection {
    /// Additional memory file patterns
    #[serde(default)]
    pub memory_paths: Vec<String>,
    /// Hash check interval in seconds
    #[serde(default = "default_hash_interval")]
    pub hash_interval_secs: u64,
}

impl Default for MemorySection {
    fn default() -> Self {
        Self {
            memory_paths: Vec::new(),
            hash_interval_secs: default_hash_interval(),
        }
    }
}

fn default_data_dir() -> PathBuf { PathBuf::from(".aegis") }
fn default_listen_addr() -> String { "127.0.0.1:8080".to_string() }
fn default_upstream_url() -> String { "http://localhost:11434".to_string() }
fn default_max_body_size() -> usize { 10 * 1024 * 1024 } // 10MB
fn default_rate_limit() -> u32 { 1000 }
fn default_true() -> bool { true }
fn default_hash_interval() -> u64 { 60 }

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            mode: AdapterMode::default(),
            proxy: ProxySection::default(),
            vault: VaultSection::default(),
            memory: MemorySection::default(),
            data_dir: default_data_dir(),
        }
    }
}

impl AdapterConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file {}: {e}", path.display()))?;
        toml::from_str(&content)
            .map_err(|e| format!("failed to parse config file: {e}"))
    }

    /// Load from default location (.aegis/config.toml) or return defaults.
    pub fn load_or_default() -> Self {
        let default_path = PathBuf::from(".aegis").join("config.toml");
        if default_path.exists() {
            Self::from_file(&default_path).unwrap_or_default()
        } else {
            Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_observe_only() {
        let config = AdapterConfig::default();
        assert!(matches!(config.mode, AdapterMode::ObserveOnly));
    }

    #[test]
    fn default_listen_addr_is_localhost() {
        let config = AdapterConfig::default();
        assert_eq!(config.proxy.listen_addr, "127.0.0.1:8080");
    }

    #[test]
    fn toml_round_trip() {
        let config = AdapterConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AdapterConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.proxy.listen_addr, config.proxy.listen_addr);
    }
}
