//! Channel trust — parse and verify X-Aegis-Channel-Cert headers.
//!
//! Resolves the trust level for each request based on:
//! 1. The signed channel certificate from the agent framework (OpenClaw)
//! 2. The trust config (channel patterns → trust levels)
//!
//! If no cert or invalid signature → TrustLevel::Unknown (backward compatible).

use aegis_schemas::{ChannelCert, ChannelTrust, TrustLevel};
use tracing::{debug, warn};

/// Configuration for channel trust resolution.
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// Default trust level when no cert or no pattern match
    pub default_level: TrustLevel,
    /// Ed25519 verifying key for cert signatures (None = no verification)
    pub signing_pubkey: Option<Vec<u8>>,
    /// Channel pattern → trust level mappings
    pub channels: Vec<(String, TrustLevel)>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            default_level: TrustLevel::Unknown,
            signing_pubkey: None,
            channels: Vec::new(),
        }
    }
}

/// Parse a trust level string into the enum.
pub fn parse_trust_level(s: &str) -> TrustLevel {
    match s.to_lowercase().as_str() {
        "full" => TrustLevel::Full,
        "trusted" => TrustLevel::Trusted,
        "public" => TrustLevel::Public,
        "restricted" => TrustLevel::Restricted,
        _ => TrustLevel::Unknown,
    }
}

/// Parse the X-Aegis-Channel-Cert header value into a ChannelCert.
pub fn parse_channel_cert(header_value: &str) -> Option<ChannelCert> {
    // Try base64 decode first, then raw JSON
    let json_str = if let Ok(decoded) = base64_decode(header_value.trim()) {
        decoded
    } else {
        header_value.trim().to_string()
    };

    match serde_json::from_str::<ChannelCert>(&json_str) {
        Ok(cert) => Some(cert),
        Err(e) => {
            warn!("failed to parse channel cert: {e}");
            None
        }
    }
}

/// Verify the Ed25519 signature on a channel cert.
/// Uses ed25519-dalek directly for signature verification.
pub fn verify_cert(cert: &ChannelCert, pubkey_bytes: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Reconstruct the signing payload: canonical JSON of {channel, user, trust, ts}
    let payload = serde_json::json!({
        "channel": cert.channel,
        "ts": cert.ts,
        "trust": cert.trust,
        "user": cert.user,
    });
    let payload_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Decode pubkey
    let pubkey_array: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            warn!("verify_cert: pubkey wrong length {}", pubkey_bytes.len());
            return false;
        }
    };
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_array) {
        Ok(k) => k,
        Err(e) => {
            warn!("verify_cert: invalid pubkey: {e}");
            return false;
        }
    };

    // Decode signature from hex
    let sig_bytes = match hex::decode(&cert.sig) {
        Ok(b) => b,
        Err(e) => {
            warn!("verify_cert: sig hex decode failed: {e}");
            return false;
        }
    };
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(v) => {
            warn!("verify_cert: sig wrong length {}", v.len());
            return false;
        }
    };
    let signature = Signature::from_bytes(&sig_array);

    // Verify
    debug!(
        payload_len = payload_bytes.len(),
        "verifying channel cert signature"
    );
    match verifying_key.verify(&payload_bytes, &signature) {
        Ok(()) => {
            debug!(channel = %cert.channel, user = %cert.user, "channel cert verified");
            true
        }
        Err(e) => {
            warn!(channel = %cert.channel, error = %e, "channel cert signature invalid");
            false
        }
    }
}

/// Resolve the trust level for a request based on the cert and config.
pub fn resolve_trust(
    cert: Option<&ChannelCert>,
    cert_verified: bool,
    config: &TrustConfig,
) -> ChannelTrust {
    let Some(cert) = cert else {
        // No cert → default trust level
        return ChannelTrust::default();
    };

    if !cert_verified && config.signing_pubkey.is_some() {
        // Cert provided but signature didn't verify → untrusted
        warn!(channel = %cert.channel, "unverified cert — treating as unknown");
        return ChannelTrust::from_level(
            TrustLevel::Unknown,
            Some(cert.channel.clone()),
            Some(cert.user.clone()),
            false,
        );
    }

    // Match channel against configured patterns
    let matched_level = config
        .channels
        .iter()
        .find(|(pattern, _)| channel_matches(&cert.channel, pattern))
        .map(|(_, level)| *level);

    let trust_level = matched_level.unwrap_or_else(|| {
        // No pattern match → use claimed trust level if verified, else default
        if cert_verified || config.signing_pubkey.is_none() {
            parse_trust_level(&cert.trust)
        } else {
            config.default_level
        }
    });

    ChannelTrust::from_level(
        trust_level,
        Some(cert.channel.clone()),
        Some(cert.user.clone()),
        cert_verified,
    )
}

/// Check if a channel string matches a glob pattern.
/// Supports `*` as a wildcard for a single segment.
fn channel_matches(channel: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let chan_parts: Vec<&str> = channel.split(':').collect();
    let pat_parts: Vec<&str> = pattern.split(':').collect();

    if chan_parts.len() != pat_parts.len() {
        return false;
    }

    chan_parts
        .iter()
        .zip(pat_parts.iter())
        .all(|(c, p)| *p == "*" || *c == *p)
}

fn base64_decode(input: &str) -> Result<String, ()> {
    // Simple base64 decode (standard alphabet)
    let decoded = base64_decode_bytes(input)?;
    String::from_utf8(decoded).map_err(|_| ())
}

fn base64_decode_bytes(input: &str) -> Result<Vec<u8>, ()> {
    // Minimal base64 decoder
    let input = input.trim();
    if input.is_empty() {
        return Err(());
    }

    let table: Vec<u8> =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_vec();
    let mut buf = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input.as_bytes() {
        if byte == b'=' {
            break;
        }
        let val = table.iter().position(|&b| b == byte).ok_or(())? as u32;
        acc = (acc << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_cert() {
        let json = r#"{"channel":"telegram:group:123","user":"telegram:user:456","trust":"public","ts":1774000000,"sig":"aabbccdd"}"#;
        let cert = parse_channel_cert(json).unwrap();
        assert_eq!(cert.channel, "telegram:group:123");
        assert_eq!(cert.user, "telegram:user:456");
        assert_eq!(cert.trust, "public");
    }

    #[test]
    fn parse_invalid_json() {
        assert!(parse_channel_cert("not json").is_none());
    }

    #[test]
    fn parse_missing_fields() {
        assert!(parse_channel_cert(r#"{"channel":"x"}"#).is_none());
    }

    #[test]
    fn channel_match_exact() {
        assert!(channel_matches("telegram:group:123", "telegram:group:123"));
        assert!(!channel_matches("telegram:group:123", "telegram:group:456"));
    }

    #[test]
    fn channel_match_wildcard() {
        assert!(channel_matches("telegram:group:123", "telegram:group:*"));
        assert!(channel_matches("telegram:dm:owner", "telegram:*:*"));
        assert!(!channel_matches("discord:group:123", "telegram:group:*"));
    }

    #[test]
    fn channel_match_all() {
        assert!(channel_matches("anything:here:123", "*"));
    }

    #[test]
    fn resolve_no_cert_gives_unknown() {
        let config = TrustConfig::default();
        let trust = resolve_trust(None, false, &config);
        assert_eq!(trust.trust_level, TrustLevel::Unknown);
        assert!(!trust.ssrf_allowed);
    }

    #[test]
    fn resolve_cert_no_pubkey_uses_claimed_trust() {
        let config = TrustConfig {
            signing_pubkey: None, // no verification
            ..Default::default()
        };
        let cert = ChannelCert {
            channel: "telegram:dm:owner".into(),
            user: "telegram:user:1".into(),
            trust: "full".into(),
            ts: 1774000000,
            sig: String::new(),
        };
        let trust = resolve_trust(Some(&cert), false, &config);
        assert_eq!(trust.trust_level, TrustLevel::Full);
        assert!(trust.ssrf_allowed);
    }

    #[test]
    fn resolve_pattern_overrides_claimed_trust() {
        let config = TrustConfig {
            signing_pubkey: None,
            channels: vec![("telegram:group:*".into(), TrustLevel::Restricted)],
            ..Default::default()
        };
        let cert = ChannelCert {
            channel: "telegram:group:123".into(),
            user: "telegram:user:1".into(),
            trust: "full".into(), // claims full
            ts: 1774000000,
            sig: String::new(),
        };
        let trust = resolve_trust(Some(&cert), false, &config);
        // Pattern overrides: group → restricted, not full
        assert_eq!(trust.trust_level, TrustLevel::Restricted);
        assert!(!trust.ssrf_allowed);
    }

    #[test]
    fn resolve_unverified_cert_with_pubkey_gives_unknown() {
        let config = TrustConfig {
            signing_pubkey: Some(vec![0u8; 32]), // has a pubkey configured
            ..Default::default()
        };
        let cert = ChannelCert {
            channel: "telegram:dm:owner".into(),
            user: "telegram:user:1".into(),
            trust: "full".into(),
            ts: 1774000000,
            sig: "invalid".into(),
        };
        // cert_verified = false, pubkey is set → unknown
        let trust = resolve_trust(Some(&cert), false, &config);
        assert_eq!(trust.trust_level, TrustLevel::Unknown);
    }

    #[test]
    fn trust_level_parsing() {
        assert_eq!(parse_trust_level("full"), TrustLevel::Full);
        assert_eq!(parse_trust_level("trusted"), TrustLevel::Trusted);
        assert_eq!(parse_trust_level("public"), TrustLevel::Public);
        assert_eq!(parse_trust_level("restricted"), TrustLevel::Restricted);
        assert_eq!(parse_trust_level("unknown"), TrustLevel::Unknown);
        assert_eq!(parse_trust_level("garbage"), TrustLevel::Unknown);
    }

    #[test]
    fn full_trust_allows_ssrf() {
        let trust = ChannelTrust::from_level(TrustLevel::Full, None, None, true);
        assert!(trust.ssrf_allowed);
    }

    #[test]
    fn non_full_trust_blocks_ssrf() {
        for level in [
            TrustLevel::Trusted,
            TrustLevel::Public,
            TrustLevel::Restricted,
            TrustLevel::Unknown,
        ] {
            let trust = ChannelTrust::from_level(level, None, None, false);
            assert!(!trust.ssrf_allowed, "level {:?} should block SSRF", level);
        }
    }
}
