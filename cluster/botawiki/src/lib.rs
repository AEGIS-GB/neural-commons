//! aegis-botawiki: Botawiki knowledge service
//!
//! Phase 2: Read API (structured query, identity activation required, NOT TRUSTMARK)
//! Phase 3b: Write path + quarantine + disputes + semantic search
//!
//! Storage: PostgreSQL + pgvector
//! 6 claim types: lore, skills, cognition, peers, reputation, provenance

pub mod dispute;
pub mod quarantine;
pub mod read;
pub mod storage;
pub mod write;

// TODO(D2): Confirm per-type claim payload schemas
// TODO(D22): Confirm quarantine quorum (3 validators, 2/3 approve)
// WARNING: 2/3 quorum is crash-fault tolerant only, NOT Byzantine-safe.
// See cluster/evaluator/src/lib.rs for details. Consider 4+ validators.
// TODO(D28): Confirm confabulation score threshold (0.5 default)
// TODO(D29): Confirm source diversity minimums per namespace
