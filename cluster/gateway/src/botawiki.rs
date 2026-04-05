//! Botawiki claim storage — re-exported from aegis-botawiki crate (Phase 3).
//!
//! The BotawikiStore implementation has been extracted to the aegis-botawiki
//! crate. This module re-exports the types so that existing Gateway code
//! (routes.rs, mesh_routes.rs, nats_bridge.rs, main.rs) continues to compile
//! without changes to their `use crate::botawiki::*` imports.

pub use aegis_botawiki::{
    BotawikiStore, ClaimStatus, ClaimSummary, PendingVote, StoredClaim, StoredClaimView, Vote,
};
