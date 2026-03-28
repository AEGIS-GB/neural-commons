//! aegis-mesh: Encrypted mesh relay
//!
//! rust-libp2p: Noise/X25519 encryption, DHT key directory, multi-hop relay
//! Content sanitization: SLM screen on ALL received messages (no fast-path override, §7.4)
//! Trust-weighted routing: exclude TRUSTMARK < 0.3, weight = TRUSTMARK^2 (D21)
//! Dead-drop: 72h TTL (D25)

pub mod dead_drop;
pub mod relay;
pub mod routing;
pub mod sanitization;

// TODO(D21): Confirm mesh trust-weight routing function
// TODO(D25): Confirm dead drop TTL
