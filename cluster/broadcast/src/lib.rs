//! aegis-broadcast: Emergency broadcast + policy distribution
//!
//! Receive: subscribe broadcast.*, verify Foundation Ed25519 signature
//! Send (Phase 3): Foundation-signed emergency messages
//! Policy: signed bundles, pull model (Foundation-only)
//! Uses signed_bundle_verify from aegis-common

pub mod policy;
pub mod receive;
pub mod send;
