//! aegis-mesh: Mesh Relay service
//!
//! 3-layer content screening (heuristic → classifier → deep SLM)
//! Trust-weighted routing: exclude TRUSTMARK < 0.3, weight = TRUSTMARK^2 (D21)
//! NATS-based relay: subscribe to incoming, publish screened/quarantined

pub mod dead_drop;
pub mod relay;
pub mod routing;
pub mod sanitization;
pub mod screening;
