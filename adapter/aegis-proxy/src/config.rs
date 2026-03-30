//! Proxy configuration types.

use serde::{Deserialize, Serialize};

/// Supported upstream LLM providers.
///
/// Phase 1: Anthropic only. When OpenAI support is added in Phase 2,
/// a new variant is added here — no string comparisons needed.
fn default_slm_max_content_chars() -> usize {
    24_000
}
fn default_burst_size() -> u32 {
    50
}
fn default_metaprompt_hardening() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Anthropic Messages API (/v1/messages) — system field is top-level, not in messages array
    Anthropic,
    /// OpenAI Chat Completions (/v1/chat/completions) — system role in messages array
    OpenAi,
    /// OpenAI Responses API (/v1/responses) — developer role in input array
    OpenAiResponses,
    /// Ollama native (/api/chat, /api/generate) — system role in messages array
    Ollama,
    /// Generic OpenAI-compatible (LM Studio, vLLM, llama.cpp) — system role in messages array
    OpenAiCompat,
}

/// Proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Upstream LLM provider URL.
    ///
    /// For Anthropic (Phase 1): `https://api.anthropic.com`
    /// OpenClaw's `baseUrl` points at the proxy; the proxy forwards here.
    pub upstream_url: String,

    /// Listen address (e.g., "127.0.0.1:3000")
    pub listen_addr: String,

    /// Maximum request body size in bytes (default: 10MB per D30)
    pub max_body_size: usize,

    /// Per-identity rate limit (requests/minute, default: 1000 per D30).
    /// Keyed by bot Ed25519 fingerprint, not source IP (D30).
    pub rate_limit_per_minute: u32,

    /// Rate limit burst size (default: 50)
    #[serde(default = "default_burst_size")]
    pub rate_limit_burst: u32,

    /// Operating mode
    pub mode: ProxyMode,

    /// Upstream provider (D31-A: Anthropic-only in Phase 1)
    pub provider: Provider,

    /// Allow any provider through without detection (default: false).
    /// Set to true in config.toml to bypass the provider check.
    #[serde(default)]
    pub allow_any_provider: bool,

    /// Inject metaprompt hardening rules into upstream system messages (default: true).
    /// When enabled, Aegis prepends security rules to the system prompt of every
    /// forwarded request, instructing the upstream LLM to treat ingested content
    /// as untrusted and refuse social engineering / exfiltration attempts.
    #[serde(default = "default_metaprompt_hardening")]
    pub metaprompt_hardening: bool,

    /// Max characters of content to send to SLM for screening (default: 24000).
    #[serde(default = "default_slm_max_content_chars")]
    pub slm_max_content_chars: usize,
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

impl Provider {
    /// Resolve provider from a well-known upstream URL.
    ///
    /// Parses the URL to extract the host and matches against known provider
    /// domains exactly (or by suffix for subdomains). Falls back to
    /// `OpenAiCompat` for unrecognised URLs with a warning.
    pub fn from_url(url: &str) -> Self {
        let host = Self::extract_host(url);

        if let Some(h) = &host {
            if h == "anthropic.com" || h.ends_with(".anthropic.com") {
                return Provider::Anthropic;
            }
            if h == "api.openai.com" {
                return Provider::OpenAi;
            }
            if h == "openrouter.ai" || h.ends_with(".openrouter.ai") {
                return Provider::OpenAiCompat;
            }
            // Ollama default port
            if h == "localhost" || h == "127.0.0.1" || h == "::1" {
                if let Some(port) = Self::extract_port(url) {
                    if port == 11434 {
                        return Provider::Ollama;
                    }
                }
            }
        }

        tracing::warn!(url = %url, "unrecognised provider URL, defaulting to OpenAI-compatible");
        Provider::OpenAiCompat
    }

    /// Extract the host portion from a URL string without pulling in the
    /// `url` crate. Handles `scheme://host:port/path` and `scheme://host/path`.
    fn extract_host(url: &str) -> Option<String> {
        // Strip scheme
        let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
        // Strip path
        let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
        // Strip userinfo (user:pass@host)
        let host_port = host_port.rsplit('@').next().unwrap_or(host_port);
        // Strip port — but be careful with IPv6 [::1]:port
        let host = if host_port.starts_with('[') {
            // IPv6: [::1]:port or [::1]
            host_port
                .find(']')
                .map(|i| &host_port[1..i])
                .unwrap_or(host_port)
        } else {
            host_port.rsplit(':').last().unwrap_or(host_port)
        };
        if host.is_empty() {
            None
        } else {
            Some(host.to_lowercase())
        }
    }

    /// Extract the port number from a URL string, if present.
    fn extract_port(url: &str) -> Option<u16> {
        let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
        let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
        // For IPv6 [::1]:port
        if host_port.starts_with('[') {
            let after_bracket = host_port.find(']').map(|i| &host_port[i + 1..])?;
            after_bracket.strip_prefix(':')?.parse().ok()
        } else {
            let parts: Vec<&str> = host_port.rsplitn(2, ':').collect();
            if parts.len() == 2 {
                parts[0].parse().ok()
            } else {
                None
            }
        }
    }

    /// Get the default upstream URL for this provider.
    pub fn default_url(&self) -> &'static str {
        match self {
            Provider::Anthropic => "https://api.anthropic.com",
            Provider::OpenAi => "https://api.openai.com",
            Provider::OpenAiResponses => "https://api.openai.com",
            Provider::Ollama => "http://localhost:11434",
            Provider::OpenAiCompat => "http://localhost:1234",
        }
    }

    /// Display name for the CLI.
    pub fn display_name(&self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAi => "openai",
            Provider::OpenAiResponses => "openai-responses",
            Provider::Ollama => "ollama",
            Provider::OpenAiCompat => "openai-compat",
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream_url: "https://api.anthropic.com".to_string(),
            listen_addr: "127.0.0.1:3141".to_string(),
            max_body_size: 10 * 1024 * 1024, // 10MB
            rate_limit_per_minute: 1000,
            mode: ProxyMode::ObserveOnly,
            provider: Provider::Anthropic,
            allow_any_provider: false,
            metaprompt_hardening: true,
            slm_max_content_chars: default_slm_max_content_chars(),
            rate_limit_burst: default_burst_size(),
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

    /// Validate configuration values at startup.
    /// Returns an error string describing the first invalid field found.
    pub fn validate(&self) -> Result<(), String> {
        if self.rate_limit_per_minute == 0 {
            return Err("rate_limit_per_minute must be > 0".to_string());
        }
        if self.rate_limit_burst == 0 {
            return Err("rate_limit_burst must be > 0".to_string());
        }
        if self.max_body_size == 0 {
            return Err("max_body_size must be > 0".to_string());
        }
        Ok(())
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
        assert_eq!(cfg.upstream_url, "https://api.anthropic.com");
        assert_eq!(cfg.listen_addr, "127.0.0.1:3141");
        assert_eq!(cfg.max_body_size, 10 * 1024 * 1024);
        assert_eq!(cfg.rate_limit_per_minute, 1000);
        assert_eq!(cfg.mode, ProxyMode::ObserveOnly);
        assert_eq!(cfg.provider, Provider::Anthropic);
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
        assert_eq!(decoded.provider, Provider::Anthropic);
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

    #[test]
    fn provider_serde_snake_case() {
        let json = serde_json::to_string(&Provider::Anthropic).unwrap();
        assert_eq!(json, "\"anthropic\"");

        let decoded: Provider = serde_json::from_str("\"anthropic\"").unwrap();
        assert_eq!(decoded, Provider::Anthropic);
    }

    #[test]
    fn from_url_detects_anthropic() {
        assert_eq!(
            Provider::from_url("https://api.anthropic.com"),
            Provider::Anthropic
        );
        assert_eq!(
            Provider::from_url("https://api.anthropic.com/v1/messages"),
            Provider::Anthropic
        );
    }

    #[test]
    fn from_url_detects_openai() {
        assert_eq!(
            Provider::from_url("https://api.openai.com"),
            Provider::OpenAi
        );
        assert_eq!(
            Provider::from_url("https://api.openai.com/v1/chat/completions"),
            Provider::OpenAi
        );
    }

    #[test]
    fn from_url_detects_ollama() {
        assert_eq!(
            Provider::from_url("http://localhost:11434"),
            Provider::Ollama
        );
        assert_eq!(
            Provider::from_url("http://127.0.0.1:11434/api/chat"),
            Provider::Ollama
        );
    }

    #[test]
    fn from_url_detects_openrouter() {
        assert_eq!(
            Provider::from_url("https://openrouter.ai/api/v1"),
            Provider::OpenAiCompat
        );
    }

    #[test]
    fn from_url_rejects_spoofed_domains() {
        // These should NOT match Anthropic — they are attacker-controlled domains
        assert_eq!(
            Provider::from_url("https://evil-anthropic.com"),
            Provider::OpenAiCompat
        );
        assert_eq!(
            Provider::from_url("https://notanthropic.com"),
            Provider::OpenAiCompat
        );
        assert_eq!(
            Provider::from_url("https://anthropic.com.evil.com"),
            Provider::OpenAiCompat
        );
    }

    #[test]
    fn from_url_unknown_defaults_to_compat() {
        assert_eq!(
            Provider::from_url("https://my-llm-server.example.com"),
            Provider::OpenAiCompat
        );
    }

    #[test]
    fn default_proxy_config_validates() {
        let cfg = ProxyConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zero_rate_limit_fails_validation() {
        let mut cfg = ProxyConfig::default();
        cfg.rate_limit_per_minute = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_burst_fails_validation() {
        let mut cfg = ProxyConfig::default();
        cfg.rate_limit_burst = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_max_body_size_fails_validation() {
        let mut cfg = ProxyConfig::default();
        cfg.max_body_size = 0;
        assert!(cfg.validate().is_err());
    }
}
