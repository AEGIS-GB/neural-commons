//! aegis-trustmark: TRUSTMARK scoring engine
//!
//! 6-dimension weighted sum normalized to [0, 1]:
//!   relay_reliability(0.15) + persona_integrity(0.25) + chain_integrity(0.20)
//!   + contribution_volume(0.10) + temporal_consistency(0.15) + vault_hygiene(0.15)
//!
//! Temporal decay: 90-day half-life (D15)
//! Tier gates: T1(>=0), T2(identity+72h+vault), T3(>=0.4+evaluator) (D14)

pub mod scoring;
pub mod decay;
pub mod tiers;

// TODO(D13): Confirm dimension weights
// TODO(D14): Confirm tier thresholds
// TODO(D15): Confirm temporal decay half-life
