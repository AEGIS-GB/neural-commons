//! TRUSTMARK scoring types (D13, D2)
//!
//! All scores are integer basis points (0-10000). No floats in signed data.
//! 8500 = 85.00%.

use serde::{Deserialize, Serialize};

/// TRUSTMARK score — 6-dimensional weighted sum.
/// All values in basis points (0-10000).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustmarkScore {
    /// Overall score in basis points [0, 10000]
    pub score_bp: u32,

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
    /// Does this bot reliably relay mesh messages? Weight: 0.15
    pub relay_reliability: u32,
    /// Is SOUL.md intact, no unauthorized changes? Weight: 0.25
    pub persona_integrity: u32,
    /// Is the evidence chain unbroken? Weight: 0.20
    pub chain_integrity: u32,
    /// How active is this bot? Weight: 0.10
    pub contribution_volume: u32,
    /// Is activity consistent over time? Weight: 0.15
    pub temporal_consistency: u32,
    /// Are credentials properly secured? Weight: 0.15
    pub vault_hygiene: u32,
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
