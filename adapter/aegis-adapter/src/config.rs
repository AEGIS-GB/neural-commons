//! Adapter configuration
//!
//! Loads configuration from TOML file or environment.
//! Composes configs for all sub-crates.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::Mode;
use aegis_schemas::config::RateLimitConfig;

/// Top-level adapter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    /// Operating mode
    #[serde(default)]
    pub mode: AdapterMode,

    /// Proxy configuration
    #[serde(default)]
    pub proxy: ProxySection,

    /// Dashboard configuration
    #[serde(default)]
    pub dashboard: DashboardSection,

    /// SLM (Small Language Model) configuration
    #[serde(default)]
    pub slm: SlmSection,

    /// Vault configuration
    #[serde(default)]
    pub vault: VaultSection,

    /// Memory monitoring configuration
    #[serde(default)]
    pub memory: MemorySection,

    /// Rate limiting config. Keyed by bot identity fingerprint. See D30.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Data directory for SQLite databases and state
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Channel trust configuration
    #[serde(default)]
    pub trust: TrustSection,

    /// Optional webhook URL for critical alerts.
    /// When set, critical alerts are POSTed here in addition to the SSE dashboard stream.
    #[serde(default)]
    pub webhook_url: Option<String>,
}

/// Trust configuration — channel-based access control + context observability.
///
/// An Aegis **channel** is the source connecting to the proxy (identified by IP).
/// Trust is resolved from the channel (source IP), not from agent-internal context.
///
/// An agent framework like OpenClaw may report **context** metadata (e.g. which
/// Telegram group or CLI session originated a request). This is observability
/// metadata — useful for the dashboard and trace, but does not affect trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSection {
    /// Default trust level for unknown channels (default: "unknown")
    #[serde(default = "default_trust_level")]
    pub default_level: String,

    /// Ed25519 public key (hex) for verifying context certs from OpenClaw.
    /// Context certs are observability metadata (which context sent this request).
    /// The signature ensures the context claim is authentic.
    #[serde(default)]
    pub signing_pubkey: Option<String>,

    /// Channel → trust level mappings (access control).
    /// A channel is identified by source IP or hostname pattern.
    #[serde(default)]
    pub channels: Vec<ChannelPattern>,

    /// OpenClaw context patterns (observability metadata, not access control).
    /// Maps context identifiers like "telegram:dm:*" for dashboard display.
    #[serde(default)]
    pub contexts: Vec<ContextPattern>,
}

/// Channel identity pattern for trust resolution.
/// A channel = a source connecting to Aegis (IP, hostname).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPattern {
    /// IP address, CIDR, or hostname pattern (e.g. "127.0.0.1", "192.168.*", "localhost")
    pub identity: String,
    /// Trust level: "full", "trusted", "public", "restricted"
    pub level: String,
}

/// OpenClaw context pattern (observability metadata).
/// Maps agent-framework-internal identifiers to labels for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPattern {
    /// Glob pattern (e.g. "telegram:dm:owner", "telegram:group:*", "openclaw:web:*")
    pub pattern: String,
    /// Label for this context (e.g. "owner-dm", "public-group")
    #[serde(default)]
    pub label: Option<String>,
}

impl Default for TrustSection {
    fn default() -> Self {
        Self {
            default_level: default_trust_level(),
            signing_pubkey: None,
            channels: Vec::new(),
            contexts: Vec::new(),
        }
    }
}

fn default_trust_level() -> String {
    "unknown".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum AdapterMode {
    #[default]
    ObserveOnly,
    Enforce,
    PassThrough,
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
    /// Allow any provider through without detection (default: false)
    #[serde(default)]
    pub allow_any_provider: bool,
    /// Upstream provider type — determines metaprompt injection format.
    /// Auto-detected from upstream_url if not set.
    #[serde(default)]
    pub provider: Option<String>,
    /// Burst size for rate limiting (default: 50)
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSection {
    /// Path prefix where the dashboard is served (default: "/dashboard")
    #[serde(default = "default_dashboard_path")]
    pub path: String,
    /// Auth token for dashboard access. Auto-generated on first run if not set.
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Default for DashboardSection {
    fn default() -> Self {
        Self {
            path: default_dashboard_path(),
            auth_token: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmSection {
    /// Enable SLM screening (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// SLM engine: "ollama" (default), "openai", or "anthropic"
    #[serde(default = "default_slm_engine")]
    pub engine: String,
    /// SLM server URL (accepts legacy "ollama_url" for backward compatibility)
    #[serde(default = "default_server_url", alias = "ollama_url")]
    pub server_url: String,
    /// Model name (default: "llama3.2:1b")
    #[serde(default = "default_slm_model")]
    pub model: String,
    /// Fall back to heuristic patterns if model unavailable
    #[serde(default = "default_true")]
    pub fallback_to_heuristics: bool,
    /// Inject metaprompt hardening rules into upstream system messages (default: true)
    #[serde(default = "default_true")]
    pub metaprompt_hardening: bool,
    /// ProtectAI classifier model directory (contains model.onnx + tokenizer.json).
    /// If not set, auto-detects from standard paths.
    #[serde(default = "default_prompt_guard_dir")]
    pub prompt_guard_model_dir: Option<String>,
    /// SLM deep screening timeout in seconds (default: 15)
    #[serde(default = "default_slm_timeout")]
    pub slm_timeout_secs: u64,
    /// Max characters of content to send to SLM for screening.
    /// Should match the SLM model's context window minus prompt overhead.
    #[serde(default = "default_slm_max_chars")]
    pub slm_max_content_chars: usize,
}

fn default_slm_timeout() -> u64 {
    15
}
fn default_slm_max_chars() -> usize {
    24_000
}

impl Default for SlmSection {
    fn default() -> Self {
        Self {
            enabled: true,
            engine: default_slm_engine(),
            server_url: default_server_url(),
            model: default_slm_model(),
            fallback_to_heuristics: true,
            metaprompt_hardening: true,
            prompt_guard_model_dir: default_prompt_guard_dir(),
            slm_timeout_secs: default_slm_timeout(),
            slm_max_content_chars: default_slm_max_chars(),
        }
    }
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            upstream_url: default_upstream_url(),
            max_body_size: default_max_body_size(),
            rate_limit_per_minute: default_rate_limit(),
            allow_any_provider: false,
            provider: None,
            burst_size: default_burst_size(),
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

fn default_data_dir() -> PathBuf {
    PathBuf::from(".aegis")
}
fn default_listen_addr() -> String {
    "127.0.0.1:3141".to_string()
}
fn default_upstream_url() -> String {
    "https://api.anthropic.com".to_string()
}
fn default_max_body_size() -> usize {
    10 * 1024 * 1024
} // 10MB
fn default_rate_limit() -> u32 {
    1000
}
fn default_burst_size() -> u32 {
    50
}
fn default_true() -> bool {
    true
}
fn default_hash_interval() -> u64 {
    60
}
fn default_dashboard_path() -> String {
    "/dashboard".to_string()
}
fn default_slm_engine() -> String {
    "ollama".to_string()
}
fn default_server_url() -> String {
    "http://localhost:11434".to_string()
}
fn default_slm_model() -> String {
    "llama3.2:1b".to_string()
}
fn default_prompt_guard_dir() -> Option<String> {
    // Auto-detect classifier model from standard paths
    let candidates = [
        "models/protectai-v2",
        "models/prompt-guard-2",
        "../models/protectai-v2",
    ];
    for path in &candidates {
        let model_path = std::path::Path::new(path).join("model.onnx");
        if model_path.exists() {
            return Some(path.to_string());
        }
    }
    None
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            mode: AdapterMode::default(),
            proxy: ProxySection::default(),
            dashboard: DashboardSection::default(),
            slm: SlmSection::default(),
            vault: VaultSection::default(),
            memory: MemorySection::default(),
            rate_limit: RateLimitConfig::default(),
            data_dir: default_data_dir(),
            trust: TrustSection::default(),
            webhook_url: None,
        }
    }
}

impl AdapterConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file {}: {e}", path.display()))?;
        let mut config: Self =
            toml::from_str(&content).map_err(|e| format!("failed to parse config file: {e}"))?;

        // Resolve relative data_dir against the config file's parent directory.
        if config.data_dir.is_relative()
            && let Some(config_dir) = path.parent()
        {
            let resolved = config_dir.join(&config.data_dir);
            if let Ok(abs) = resolved.canonicalize() {
                config.data_dir = abs;
            } else if let Ok(abs) = std::env::current_dir().map(|cwd| cwd.join(&config.data_dir)) {
                config.data_dir = abs;
            }
        }

        Ok(config)
    }

    /// Validate configuration values at startup.
    /// Returns an error string describing the first invalid field found.
    pub fn validate(&self) -> Result<(), String> {
        if self.proxy.rate_limit_per_minute == 0 {
            return Err("proxy.rate_limit_per_minute must be > 0".to_string());
        }
        if self.proxy.burst_size == 0 {
            return Err("proxy.burst_size must be > 0".to_string());
        }
        if self.proxy.max_body_size == 0 {
            return Err("proxy.max_body_size must be > 0".to_string());
        }
        if self.slm.slm_timeout_secs == 0 {
            return Err("slm.slm_timeout_secs must be > 0".to_string());
        }
        Ok(())
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
        assert_eq!(config.proxy.listen_addr, "127.0.0.1:3141");
    }

    #[test]
    fn toml_round_trip() {
        let config = AdapterConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AdapterConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.proxy.listen_addr, config.proxy.listen_addr);
    }

    #[test]
    fn default_config_validates() {
        let config = AdapterConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_rate_limit_fails_validation() {
        let mut config = AdapterConfig::default();
        config.proxy.rate_limit_per_minute = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_burst_size_fails_validation() {
        let mut config = AdapterConfig::default();
        config.proxy.burst_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_max_body_size_fails_validation() {
        let mut config = AdapterConfig::default();
        config.proxy.max_body_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_slm_timeout_fails_validation() {
        let mut config = AdapterConfig::default();
        config.slm.slm_timeout_secs = 0;
        assert!(config.validate().is_err());
    }
}
