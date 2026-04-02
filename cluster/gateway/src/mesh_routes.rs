//! Mesh status API — visibility into cluster state (Issue #221)
//!
//! Public endpoints (no auth required) that expose aggregate mesh metrics.
//! These power the Dashboard "Mesh" tab and CLI `aegis mesh` commands.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Serialize;

use crate::botawiki::BotawikiStore;
use crate::nats_bridge::TrustmarkCache;
use crate::ws::{DeadDropStore, WssConnectionRegistry};

/// Atomic counters for relay message activity.
///
/// Incremented in `routes::mesh_send` on each relay outcome.
/// Read by `GET /mesh/relay/stats` for dashboard visualization.
#[derive(Debug, Default)]
pub struct RelayStats {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub quarantined: AtomicU64,
    pub dead_dropped: AtomicU64,
}

impl RelayStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> RelayStatsSnapshot {
        RelayStatsSnapshot {
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            quarantined: self.quarantined.load(Ordering::Relaxed),
            dead_dropped: self.dead_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of relay counters.
#[derive(Debug, Clone, Serialize)]
pub struct RelayStatsSnapshot {
    pub sent: u64,
    pub received: u64,
    pub quarantined: u64,
    pub dead_dropped: u64,
}

/// GET /mesh/status — gateway health overview.
pub async fn mesh_status(
    Extension(wss_registry): Extension<Arc<WssConnectionRegistry>>,
    Extension(trustmark_cache): Extension<Arc<TrustmarkCache>>,
    Extension(relay_stats): Extension<Arc<RelayStats>>,
) -> impl IntoResponse {
    let peer_count = wss_registry.connection_count().await;
    let cached_scores = trustmark_cache.len().await;
    let stats = relay_stats.snapshot();

    Json(serde_json::json!({
        "gateway": "ok",
        "peers_online": peer_count,
        "cached_scores": cached_scores,
        "relay": {
            "sent": stats.sent,
            "received": stats.received,
            "quarantined": stats.quarantined,
            "dead_dropped": stats.dead_dropped,
        },
    }))
}

/// GET /mesh/peers — list of connected bots with TRUSTMARK scores.
pub async fn mesh_peers(
    Extension(wss_registry): Extension<Arc<WssConnectionRegistry>>,
    Extension(trustmark_cache): Extension<Arc<TrustmarkCache>>,
) -> impl IntoResponse {
    let peer_ids = wss_registry.list_peers().await;
    let mut peers = Vec::with_capacity(peer_ids.len());

    for id in &peer_ids {
        let score = trustmark_cache.get(id).await;
        peers.push(serde_json::json!({
            "bot_id": id,
            "online": true,
            "score_bp": score.as_ref().map(|s| s.score_bp),
            "tier": score.as_ref().map(|s| &s.tier),
            "computed_at_ms": score.as_ref().map(|s| s.computed_at_ms),
        }));
    }

    Json(serde_json::json!({
        "peers": peers,
        "count": peers.len(),
    }))
}

/// GET /mesh/relay/stats — relay message counters.
pub async fn mesh_relay_stats(
    Extension(relay_stats): Extension<Arc<RelayStats>>,
) -> impl IntoResponse {
    Json(relay_stats.snapshot())
}

/// GET /mesh/claims — Botawiki claim summary.
pub async fn mesh_claims(
    Extension(botawiki_store): Extension<Arc<BotawikiStore>>,
) -> impl IntoResponse {
    let summary = botawiki_store.summary().await;
    Json(summary)
}

/// GET /mesh/dead-drops — dead-drop queue status.
pub async fn mesh_dead_drops(
    Extension(dead_drop_store): Extension<Arc<DeadDropStore>>,
) -> impl IntoResponse {
    let summary = dead_drop_store.summary().await;
    Json(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_stats_default_zero() {
        let stats = RelayStats::new();
        let snap = stats.snapshot();
        assert_eq!(snap.sent, 0);
        assert_eq!(snap.received, 0);
        assert_eq!(snap.quarantined, 0);
        assert_eq!(snap.dead_dropped, 0);
    }

    #[test]
    fn relay_stats_increment_and_snapshot() {
        let stats = RelayStats::new();
        stats.sent.fetch_add(5, Ordering::Relaxed);
        stats.quarantined.fetch_add(2, Ordering::Relaxed);
        stats.dead_dropped.fetch_add(1, Ordering::Relaxed);

        let snap = stats.snapshot();
        assert_eq!(snap.sent, 5);
        assert_eq!(snap.received, 0);
        assert_eq!(snap.quarantined, 2);
        assert_eq!(snap.dead_dropped, 1);
    }

    #[test]
    fn relay_stats_snapshot_serializes() {
        let snap = RelayStatsSnapshot {
            sent: 10,
            received: 8,
            quarantined: 1,
            dead_dropped: 3,
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"sent\":10"));
        assert!(json.contains("\"dead_dropped\":3"));
    }
}
