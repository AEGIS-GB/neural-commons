//! Proxy configuration types.

use serde::{Deserialize, Serialize};

/// Proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Upstream LLM provider URL (e.g., "http://localhost:8080")
    pub upstream_url: String,

    /// Listen address (e.g., "127.0.0.1:3000")
    pub listen_addr: String,

    /// Maximum request body size in bytes (default: 10MB per D30)
    pub max_body_size: usize,

    /// Per-source-IP rate limit (requests/minute, default: 1000 per D30)
    pub rate_limit_per_minute: u32,

    /// Operating mode
    pub mode: ProxyMode,
}

/// Proxy operating mode.
///
/// - `PassThrough`: zero inspection, transparent forwarding
/// - `ObserveOnly`: full inspection + receipts, no blocking (default)
/// - `Enforce`: full inspection + receipts + blocking on policy violations
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    PassThrough,
    ObserveOnly,
    Enforce,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream_url: "http://localhost:8080".to_string(),
            listen_addr: "127.0.0.1:3000".to_string(),
            max_body_size: 10 * 1024 * 1024, // 10MB
            rate_limit_per_minute: 1000,
            mode: ProxyMode::ObserveOnly,
        }
    }
}

impl ProxyConfig {
    /// Create a pass-through config (no inspection).
    pub fn pass_through(upstream_url: &str, listen_addr: &str) -> Self {
        Self {
            upstream_url: upstream_url.to_string(),
            listen_addr: listen_addr.to_string(),
            mode: ProxyMode::PassThrough,
            ..Self::default()
        }
    }

    /// Create an enforcement config (blocks on violations).
    pub fn enforce(upstream_url: &str, listen_addr: &str) -> Self {
        Self {
            upstream_url: upstream_url.to_string(),
            listen_addr: listen_addr.to_string(),
            mode: ProxyMode::Enforce,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = ProxyConfig::default();
        assert_eq!(cfg.upstream_url, "http://localhost:8080");
        assert_eq!(cfg.listen_addr, "127.0.0.1:3000");
        assert_eq!(cfg.max_body_size, 10 * 1024 * 1024);
        assert_eq!(cfg.rate_limit_per_minute, 1000);
        assert_eq!(cfg.mode, ProxyMode::ObserveOnly);
    }

    #[test]
    fn pass_through_config() {
        let cfg = ProxyConfig::pass_through("http://upstream:9090", "0.0.0.0:4000");
        assert_eq!(cfg.upstream_url, "http://upstream:9090");
        assert_eq!(cfg.listen_addr, "0.0.0.0:4000");
        assert_eq!(cfg.mode, ProxyMode::PassThrough);
    }

    #[test]
    fn enforce_config() {
        let cfg = ProxyConfig::enforce("http://upstream:9090", "0.0.0.0:4000");
        assert_eq!(cfg.mode, ProxyMode::Enforce);
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = ProxyConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.upstream_url, cfg.upstream_url);
        assert_eq!(decoded.mode, cfg.mode);
    }

    #[test]
    fn mode_serde_snake_case() {
        let json = serde_json::to_string(&ProxyMode::PassThrough).unwrap();
        assert_eq!(json, "\"pass_through\"");

        let json = serde_json::to_string(&ProxyMode::ObserveOnly).unwrap();
        assert_eq!(json, "\"observe_only\"");

        let json = serde_json::to_string(&ProxyMode::Enforce).unwrap();
        assert_eq!(json, "\"enforce\"");
    }
}
