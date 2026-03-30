//! Botawiki claim schema (D2)
//!
//! All scores in integer basis points. No floats in signed data.

use crate::BasisPoints;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Botawiki claim — a piece of shared bot knowledge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub id: Uuid,

    #[serde(rename = "type")]
    pub claim_type: ClaimType,

    /// Namespace (e.g., "b/lore", "b/skills/malicious")
    pub namespace: String,

    /// Bot fingerprint of the attester (lowercase hex)
    pub attester_id: String,

    /// Confidence in basis points (0-10000), validated at deserialization
    pub confidence_bp: BasisPoints,

    /// Temporal scope of this claim
    pub temporal_scope: TemporalScope,

    /// Receipt IDs that support this claim
    pub provenance: Vec<Uuid>,

    /// Schema version (integer, not semver — for JCS determinism)
    pub schema_version: u32,

    /// Computed by quarantine validator, basis points (0-10000)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confabulation_score_bp: Option<BasisPoints>,

    /// Computed by quarantine temporal coherence check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal_coherence_flag: Option<bool>,

    /// How many unique wardens attested
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distinct_warden_count: Option<u32>,

    /// Per-type payload (JSONB)
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    Lore,
    Skills,
    Cognition,
    Peers,
    Reputation,
    Provenance,
}

/// Temporal scope — uses unix epoch milliseconds (D2: no DateTime, pure i64)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemporalScope {
    /// Start time, unix epoch milliseconds
    pub start_ms: i64,
    /// End time, unix epoch milliseconds. Omitted = ongoing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_ms: Option<i64>,
}
