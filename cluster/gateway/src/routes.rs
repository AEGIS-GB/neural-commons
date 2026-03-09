//! Edge Gateway HTTP routes (D3)
//!
//! Endpoints:
//!   POST /evidence         — single receipt submission
//!   POST /evidence/batch   — batch receipt submission (max 100 or 1MB)
//!   GET  /trustmark/:bot_id — query TRUSTMARK score
//!   GET  /botawiki/query    — Botawiki structured query
//!   GET  /verify/:fingerprint — certificate verification (D29)
//!   POST /rollup           — Merkle rollup submission
//!   POST /embedding        — direct embedding via load balancer (D3 v3)
//!
//! All routes require NC-Ed25519 authentication.
//! Rate limits per D24. Credit deductions per D19.

// Embedding pool imports — uncomment when AppState is defined:
// use std::sync::atomic::Ordering;
// use axum::extract::State;
// use bytes::Bytes;
// use crate::embedding_pool::EmbeddingPool;
use axum::response::IntoResponse;
use axum::http::StatusCode;

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

// TODO: Define AppState, ExtractedAuth, RateLimiter, Ledger types
// TODO: Implement rate_limit_response() and credit_exhausted_response() helpers

/// POST /embedding — direct embedding via Gateway load balancer (D3 v3)
///
/// This handler replaces the old NATS→Scheduler path for direct embedding.
/// In Option B, Nodes 1+3 are dedicated embedding nodes — no GPU-state
/// awareness needed. Simple least-connections load balancing is sufficient.
///
/// Flow:
///   1. Rate limit check — D24: embedding counter +1
///   2. Credit check — D19: 1 credit per direct embedding call
///   3. Pick embedding node — least connections
///   4. Forward to embedding node
///   5. Return result
///
/// Option C: when Centaur is added to Nodes 1+3, this handler is replaced
/// by Scheduler-aware routing. Config change, not code change.
#[allow(dead_code)]
async fn handle_embedding(
    // State(state): State<AppState>,
    // auth: ExtractedAuth,
    // body: Bytes,
) -> impl IntoResponse {
    // TODO: Uncomment when AppState is defined
    //
    // // 1. Rate limit check — D24: embedding counter +1
    // if !state.rate_limiter.check(&auth.pubkey, "embedding").await {
    //     return rate_limit_response("embedding", auth.tier);
    // }
    //
    // // 2. Credit check — D19: 1 credit per direct embedding call
    // if !state.ledger.check_and_deduct(&auth.pubkey, 1).await {
    //     return credit_exhausted_response("embedding", 1);
    // }
    //
    // // 3. Pick embedding node — least connections
    // let node = match state.embedding_pool.pick() {
    //     Some(n) => n,
    //     None    => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    // };
    //
    // // 4. Forward to embedding node
    // node.active_reqs.fetch_add(1, Ordering::Relaxed);
    // let result = state.http_client
    //     .post(format!("{}/embed", node.address))
    //     .body(body)
    //     .send()
    //     .await;
    // node.active_reqs.fetch_sub(1, Ordering::Relaxed);
    //
    // // 5. Return result
    // match result {
    //     Ok(r)  => (r.status(), r.bytes().await.unwrap_or_default())
    //               .into_response(),
    //     Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    // }

    StatusCode::NOT_IMPLEMENTED.into_response()
}
