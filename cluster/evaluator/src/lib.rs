//! aegis-evaluator: Evaluator gateway
//!
//! Attestation package builder + evaluator selection (3 per request)
//! Vote aggregation: 2/3 must approve for Tier 3 admission
//! Accountability linkage: evaluator TRUSTMARK penalized if admittee misbehaves (D20)
//!
//! # Security limitation
//!
//! The 2/3 quorum (2 of 3 validators) is crash-fault tolerant but NOT
//! Byzantine-fault tolerant. BFT requires strictly > 2/3 honest nodes
//! (i.e., 3f+1 total to tolerate f faults). With 3 evaluators, a single
//! compromised evaluator + one colluding = full quorum control.
//!
//! For Byzantine safety, increase the evaluator set to 4+ nodes
//! (requiring 3/4 approval) or 7+ nodes (requiring 5/7 approval).
//! Until then, this module provides Tier 3 admission ceremony with
//! crash-fault tolerance only.

pub mod accountability;
pub mod attestation;
pub mod selection;
pub mod voting;

// TODO(D20): Confirm evaluator accountability penalties
