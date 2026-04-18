//! Edge Gateway — adapter-facing HTTP/WSS service (D3)
//!
//! Adapter → Gateway: HTTPS (receipts, rollups, TRUSTMARK queries, Botawiki queries)
//! Gateway → Adapter: WSS (mesh messages, tier notifications, contamination alerts)
//!
//! Auth: NC-Ed25519 stateless request signing (HTTP), challenge-response (WSS upgrade)
//! Internal: Translates HTTP↔NATS, WSS↔NATS. NATS never exposed to adapters.
//!
//! Transport auth key: m/44'/784'/3'/0' (D0, D3). NOT the root signing key.

pub mod auth;
pub mod botawiki;
pub mod embedding_pool;
pub mod evaluator;
pub mod evidence_verify;
pub mod mesh_routes;
pub mod nats_bridge;
pub mod rate_limit;
pub mod routes;
pub mod session_gate;
pub mod store;
pub mod ws;

// Relay screening has been extracted to the aegis-mesh-relay service.
// The Gateway now publishes to NATS `mesh.relay.incoming` and the Mesh Relay
// service handles 3-layer screening (heuristic + classifier + SLM).
// For local/test deployments without NATS, the Gateway falls back to
// inline heuristic-only screening.
