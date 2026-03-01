//! Edge Gateway HTTP routes (D3)
//!
//! Endpoints:
//!   POST /evidence         — single receipt submission
//!   POST /evidence/batch   — batch receipt submission (max 100 or 1MB)
//!   GET  /trustmark/:bot_id — query TRUSTMARK score
//!   GET  /botawiki/query    — Botawiki structured query
//!   GET  /verify/:fingerprint — certificate verification (D29)
//!   POST /rollup           — Merkle rollup submission
//!
//! All routes require NC-Ed25519 authentication.
//! Rate limits per D24.

// TODO: Implement axum routes
// - POST /evidence: single receipt, validate signature, publish to NATS evidence.new
// - POST /evidence/batch: max 100 receipts or 1MB, validate all, publish batch
// - GET /trustmark/:bot_id: query current TRUSTMARK score
// - GET /botawiki/query: structured query (Phase 2), semantic search (Phase 3b)
// - GET /verify/:fingerprint: certificate verification API route
// - POST /rollup: Merkle rollup submission with histogram

/// Maximum receipts per batch
pub const MAX_BATCH_SIZE: usize = 100;

/// Maximum batch body size in bytes (1MB)
pub const MAX_BATCH_BYTES: usize = 1_048_576;
