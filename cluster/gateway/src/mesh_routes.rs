//! Mesh status API — visibility into cluster state (Issue #221)
//!
//! Public endpoints (no auth required) that expose aggregate mesh metrics.
//! These power the Dashboard "Mesh" tab and CLI `aegis mesh` commands.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Path, Query};
use axum::http::StatusCode;
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

// ── Drill-down endpoints ──────────────────────────────────────────

/// A single relay event for the log.
#[derive(Debug, Clone, Serialize)]
pub struct RelayEvent {
    pub from: String,
    pub to: String,
    pub status: String, // "delivered", "dead_dropped", "quarantined"
    pub msg_type: String,
    pub ts_ms: i64,
}

/// Append-only relay log (last 100 events).
#[derive(Debug, Default)]
pub struct RelayLog {
    events: std::sync::RwLock<VecDeque<RelayEvent>>,
}

impl RelayLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, event: RelayEvent) {
        let mut events = self.events.write().unwrap();
        events.push_back(event);
        if events.len() > 100 {
            events.pop_front();
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<RelayEvent> {
        let events = self.events.read().unwrap();
        events.iter().rev().take(limit).cloned().collect()
    }
}

/// GET /mesh/peers/:bot_id — peer detail with TRUSTMARK dimensions and online status.
pub async fn mesh_peer_detail(
    Extension(trustmark_cache): Extension<Arc<TrustmarkCache>>,
    Extension(wss_registry): Extension<Arc<WssConnectionRegistry>>,
    Path(bot_id): Path<String>,
) -> impl IntoResponse {
    let online = wss_registry.is_online(&bot_id).await;
    let score = trustmark_cache.get(&bot_id).await;
    match score {
        Some(cached) => Json(serde_json::json!({
            "bot_id": bot_id,
            "online": online,
            "score_bp": cached.score_bp,
            "dimensions": cached.dimensions,
            "tier": cached.tier,
            "computed_at_ms": cached.computed_at_ms,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "bot not found"})),
        )
            .into_response(),
    }
}

/// GET /mesh/relay/log — recent relay events.
pub async fn mesh_relay_log(
    Extension(relay_log): Extension<Arc<RelayLog>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let limit = params
        .get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(20);
    let events = relay_log.recent(limit);
    Json(serde_json::json!({ "events": events, "count": events.len() }))
}

/// GET /mesh/dead-drops/:bot_id — per-bot dead-drop detail.
pub async fn mesh_dead_drop_detail(
    Extension(dead_drop_store): Extension<Arc<DeadDropStore>>,
    Path(bot_id): Path<String>,
) -> impl IntoResponse {
    let drops = dead_drop_store.get_for_bot(&bot_id).await;
    Json(serde_json::json!({ "bot_id": bot_id, "drops": drops, "count": drops.len() }))
}

/// GET /botawiki/claims/all — full claim list with content.
pub async fn botawiki_list_all(
    Extension(botawiki_store): Extension<Arc<BotawikiStore>>,
) -> impl IntoResponse {
    let claims = botawiki_store.list_all().await;
    Json(serde_json::json!({ "claims": claims, "count": claims.len() }))
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

    #[test]
    fn relay_log_push_and_recent() {
        let log = RelayLog::new();
        for i in 0..5 {
            log.push(RelayEvent {
                from: format!("bot_{i}"),
                to: "target".into(),
                status: "delivered".into(),
                msg_type: "relay".into(),
                ts_ms: 1700000000000 + i,
            });
        }
        let recent = log.recent(3);
        assert_eq!(recent.len(), 3);
        // Most recent first
        assert_eq!(recent[0].from, "bot_4");
        assert_eq!(recent[2].from, "bot_2");
    }

    #[test]
    fn relay_log_caps_at_100() {
        let log = RelayLog::new();
        for i in 0..120 {
            log.push(RelayEvent {
                from: format!("bot_{i}"),
                to: "target".into(),
                status: "delivered".into(),
                msg_type: "relay".into(),
                ts_ms: 1700000000000 + i,
            });
        }
        let all = log.recent(200);
        assert_eq!(all.len(), 100);
        // Oldest remaining should be bot_20 (0..19 were evicted)
        assert_eq!(all.last().unwrap().from, "bot_20");
    }

    #[test]
    fn relay_event_serializes() {
        let event = RelayEvent {
            from: "sender".into(),
            to: "receiver".into(),
            status: "delivered".into(),
            msg_type: "relay".into(),
            ts_ms: 1700000000000,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"from\":\"sender\""));
        assert!(json.contains("\"status\":\"delivered\""));
    }
}
