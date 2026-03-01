//! aegis-evaluator: Evaluator gateway
//!
//! Attestation package builder + evaluator selection (3 per request)
//! Vote aggregation: 2/3 must approve for Tier 3 admission
//! Accountability linkage: evaluator TRUSTMARK penalized if admittee misbehaves (D20)

pub mod attestation;
pub mod selection;
pub mod voting;
pub mod accountability;

// TODO(D20): Confirm evaluator accountability penalties
