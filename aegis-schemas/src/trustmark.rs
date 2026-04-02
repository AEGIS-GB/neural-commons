//! TRUSTMARK scoring types (D13, D2)
//!
//! All scores are integer basis points (0-10000). No floats in signed data.
//! 8500 = 85.00%.

use crate::BasisPoints;
use serde::{Deserialize, Serialize};

/// TRUSTMARK score — 7-dimensional weighted sum.
/// All values in basis points (0-10000).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustmarkScore {
    /// Overall score in basis points [0, 10000]
    pub score_bp: BasisPoints,

    /// Per-dimension breakdown (all in basis points)
    pub dimensions: TrustmarkDimensions,

    /// Current trust tier
    pub tier: Tier,

    /// Unix epoch milliseconds of last computation
    pub computed_at_ms: i64,
}

/// Individual TRUSTMARK dimensions (D13)
/// All values in basis points (0-10000).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustmarkDimensions {
    /// Does this bot reliably relay mesh messages? Weight: 0.10
    pub relay_reliability: BasisPoints,
    /// Is SOUL.md intact, no unauthorized changes? Weight: 0.25
    pub persona_integrity: BasisPoints,
    /// Is the evidence chain unbroken? Weight: 0.20
    pub chain_integrity: BasisPoints,
    /// How active is this bot? Weight: 0.10
    pub contribution_volume: BasisPoints,
    /// Is activity consistent over time? Weight: 0.10
    pub temporal_consistency: BasisPoints,
    /// Are credentials properly secured? Weight: 0.15
    pub vault_hygiene: BasisPoints,
    /// Is PII/PHI properly screened in responses? Weight: 0.10
    #[serde(default)]
    pub response_hygiene: BasisPoints,
}

/// Trust tier (D14)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Any installed adapter. Score >= 0.
    Tier1,
    /// Identity activated + 72h evidence + vault active.
    /// Botawiki Read available on identity activation (50 reads/h).
    Tier2,
    /// Score >= 4000bp (0.40) + Evaluator admission.
    Tier3,
}

// ---------------------------------------------------------------------------
// Channel Trust (Tier 1 local, extends to TRUSTMARK in v0.4)
// ---------------------------------------------------------------------------

/// Trust level for a channel/user sending requests through the proxy.
/// Determines holster profile and SSRF policy.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Bot owner / admin — full access, SSRF allowed, permissive holster
    Full,
    /// Explicitly trusted user or group
    Trusted,
    /// Public channel, anyone can message
    Public,
    /// Explicitly restricted
    Restricted,
    /// No channel cert or unverified — backward compatible default
    #[default]
    Unknown,
}

/// Channel certificate — signed claim from the agent framework (e.g. OpenClaw)
/// identifying the channel and user for this request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCert {
    /// Channel identifier (e.g. "telegram:group:12345", "telegram:dm:67890")
    pub channel: String,
    /// User identifier (e.g. "telegram:user:67890")
    pub user: String,
    /// Claimed trust level
    pub trust: String,
    /// Unix epoch milliseconds when cert was created
    pub ts: i64,
    /// Ed25519 signature over {channel, user, trust, ts} canonical JSON
    pub sig: String,
}

/// Resolved channel trust context for a request.
/// Attached to RequestInfo and flows through the entire pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelTrust {
    /// Source channel (None if no cert provided)
    pub channel: Option<String>,
    /// Source user (None if no cert provided)
    pub user: Option<String>,
    /// Resolved trust level
    pub trust_level: TrustLevel,
    /// Whether the channel cert signature was verified
    pub cert_verified: bool,
    /// Whether internal/SSRF URLs are allowed for this trust level
    pub ssrf_allowed: bool,
}

impl Default for ChannelTrust {
    fn default() -> Self {
        Self {
            channel: None,
            user: None,
            trust_level: TrustLevel::Unknown,
            cert_verified: false,
            ssrf_allowed: false,
        }
    }
}

impl ChannelTrust {
    /// Create a resolved trust context from a trust level.
    pub fn from_level(
        level: TrustLevel,
        channel: Option<String>,
        user: Option<String>,
        verified: bool,
    ) -> Self {
        let ssrf_allowed = matches!(level, TrustLevel::Full);
        Self {
            channel,
            user,
            trust_level: level,
            cert_verified: verified,
            ssrf_allowed,
        }
    }
}
