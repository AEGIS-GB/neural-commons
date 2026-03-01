//! aegis-common: Shared cluster utilities
//!
//! - NATS client helpers (connect, publish, subscribe with typed messages)
//! - Database pool management (sqlx PostgreSQL)
//! - Schema client (query aegis-schemas types)
//! - signed_bundle_verify: Ed25519 bundle verification (used by auto-updater, broadcast, policy)

pub mod nats;
pub mod db;
pub mod bundle;
