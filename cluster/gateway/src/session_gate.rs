//! Mesh session gate — enforces "one bot, one unified session".
//!
//! Mesh membership = a WSS-authenticated session exists for the caller's
//! Ed25519 identity. Signed HTTP writes (mesh/send, botawiki/claim,
//! botawiki/vote, evaluator/*) are then gated on that session being live.
//!
//! This closes the "HTTP-only backdoor" where a fresh keypair could talk
//! to mesh endpoints without completing the WSS challenge-response
//! handshake the adapter performs at startup. One identity, two connection
//! modes (HTTP writes + WSS inbox) — not two parallel tracks.
//!
//! Evidence submission intentionally does NOT require a session: adapters
//! must be able to push backlogged receipts while their WSS reconnect
//! loop is still settling. Evidence is protected by the cryptographic
//! chain check in `evidence_verify.rs`.

use std::sync::Arc;

use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::ws::WssConnectionRegistry;

/// Check that `pubkey` has an active WSS session with the gateway.
///
/// Returns `Ok(())` if the session exists, otherwise a 403 response with a
/// clear error telling the caller to complete the WSS handshake.
pub async fn require_mesh_session(
    pubkey: &str,
    registry: &WssConnectionRegistry,
) -> Result<(), axum::response::Response> {
    if registry.is_online(pubkey).await {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "no mesh session — complete the WSS handshake (see aegis adapter)",
                "hint": "GET /ws with NC-Ed25519 challenge-response. \
                        One identity holds both HTTP writes and WSS session concurrently."
            })),
        )
            .into_response())
    }
}

/// Re-export `Arc<WssConnectionRegistry>` for use in handler extensions.
pub type SharedRegistry = Arc<WssConnectionRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn offline_bot_is_rejected() {
        let reg = WssConnectionRegistry::new();
        let res = require_mesh_session("deadbeef", &reg).await;
        assert!(res.is_err());
    }

    // `is_online` requires WssConnection entries; full integration is covered
    // in routes::tests where the test app registers bots via the public API.
}
