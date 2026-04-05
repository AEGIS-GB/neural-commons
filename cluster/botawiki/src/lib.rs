//! aegis-botawiki: Botawiki knowledge service
//!
//! Claim storage, quarantine, voting, and canonical promotion.
//! 6 claim types: lore, skills, cognition, peers, reputation, provenance
//!
//! The `BotawikiStore` manages in-memory claim state with adaptive quorum
//! voting (2/3 of selected validators). The standalone `aegis-botawiki-service`
//! binary runs as a NATS service, processing claims and votes from the Gateway.

pub mod dispute;
pub mod quarantine;
pub mod read;
pub mod storage;
pub mod write;

// Re-export core types for ergonomic imports
pub use storage::{
    BotawikiStore, ClaimStatus, ClaimSummary, PendingVote, StoredClaim, StoredClaimView, Vote,
};
