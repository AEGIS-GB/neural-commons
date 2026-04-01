//! Concrete WSS message handler -- wires Gateway WebSocket messages to adapter state.
//!
//! - `TrustmarkUpdate` -> updates the local TRUSTMARK cache in AdapterState
//! - `Broadcast` -> logs + pushes to dashboard SSE alert channel
//! - `MeshRelay` -> logs + pushes to dashboard (actual handling deferred to Phase 4)

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::gateway_wss::WssHandler;
use crate::state::TrustmarkCache;
use aegis_dashboard::DashboardAlert;

/// Adapter-side handler for Gateway WSS messages.
///
/// Holds references to shared adapter state needed to process each message type.
pub struct AdapterWssHandler {
    /// Broadcast sender for pushing alerts to SSE dashboard clients.
    alert_tx: broadcast::Sender<DashboardAlert>,
    /// TRUSTMARK score cache (shared with AdapterState).
    trustmark_cache: Arc<std::sync::RwLock<Option<TrustmarkCache>>>,
}

impl AdapterWssHandler {
    /// Create a new handler wired to adapter state.
    pub fn new(
        alert_tx: broadcast::Sender<DashboardAlert>,
        trustmark_cache: Arc<std::sync::RwLock<Option<TrustmarkCache>>>,
    ) -> Self {
        Self {
            alert_tx,
            trustmark_cache,
        }
    }
}

/// Convert a basis-point score (0-10000) to a 0.0-1.0 float.
fn bp_to_float(score_bp: u32) -> f64 {
    (score_bp as f64) / 10000.0
}

/// Get the current epoch time in milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl WssHandler for AdapterWssHandler {
    fn on_trustmark_update(&self, bot_id: &str, score_bp: u32) {
        let score_f64 = bp_to_float(score_bp);

        // Build a minimal TrustmarkScore for the cache.
        // The cluster-provided score replaces the locally-computed one.
        let score = aegis_trustmark::scoring::TrustmarkScore {
            total: score_f64,
            dimensions: vec![], // Cluster provides aggregate only
            computed_at_ms: now_ms(),
        };
        let cache_entry = TrustmarkCache {
            score,
            computed_at_ms: now_ms() as i64,
        };

        if let Ok(mut cache) = self.trustmark_cache.write() {
            *cache = Some(cache_entry);
        }

        tracing::info!(
            bot_id = %bot_id,
            score_bp,
            score = format!("{:.4}", score_f64),
            "TRUSTMARK cache updated from gateway WSS"
        );
    }

    fn on_broadcast(&self, kind: &str, message: &str) {
        let alert = DashboardAlert {
            ts_ms: now_ms(),
            kind: format!("gateway_broadcast_{}", kind),
            message: message.to_string(),
            receipt_seq: 0,
        };
        let _ = self.alert_tx.send(alert);

        tracing::info!(
            kind = %kind,
            "gateway broadcast pushed to dashboard"
        );
    }

    fn on_mesh_relay(&self, from: &str, body: &str) {
        // Phase 4 will add actual mesh message handling.
        // For now, log and push to dashboard as an informational alert.
        let alert = DashboardAlert {
            ts_ms: now_ms(),
            kind: "mesh_relay".to_string(),
            message: format!("mesh relay from {}: {}", from, truncate(body, 200)),
            receipt_seq: 0,
        };
        let _ = self.alert_tx.send(alert);

        tracing::debug!(
            from = %from,
            body_len = body.len(),
            "mesh relay forwarded to dashboard"
        );
    }
}

/// Truncate a string to `max_len` chars, appending "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handler() -> (AdapterWssHandler, broadcast::Receiver<DashboardAlert>) {
        let (tx, rx) = broadcast::channel(32);
        let cache = Arc::new(std::sync::RwLock::new(None));
        let handler = AdapterWssHandler::new(tx, cache);
        (handler, rx)
    }

    #[test]
    fn trustmark_update_updates_cache() {
        let (tx, _rx) = broadcast::channel(32);
        let cache = Arc::new(std::sync::RwLock::new(None));
        let handler = AdapterWssHandler::new(tx, cache.clone());

        // Before update, cache should be empty
        assert!(cache.read().unwrap().is_none());

        handler.on_trustmark_update("bot123", 8500);

        // After update, cache should have the score
        let cached = cache.read().unwrap();
        let entry = cached.as_ref().expect("cache should have entry");
        assert!((entry.score.total - 0.85).abs() < 0.001);
    }

    #[test]
    fn broadcast_creates_dashboard_alert() {
        let (handler, mut rx) = make_handler();

        handler.on_broadcast("announcement", "test message");

        let alert = rx.try_recv().expect("should receive alert");
        assert_eq!(alert.kind, "gateway_broadcast_announcement");
        assert_eq!(alert.message, "test message");
        assert!(alert.ts_ms > 0);
    }

    #[test]
    fn mesh_relay_creates_dashboard_alert() {
        let (handler, mut rx) = make_handler();

        handler.on_mesh_relay("peer-abc", "relay payload");

        let alert = rx.try_recv().expect("should receive alert");
        assert_eq!(alert.kind, "mesh_relay");
        assert!(alert.message.contains("peer-abc"));
        assert!(alert.message.contains("relay payload"));
    }

    #[test]
    fn trustmark_update_overwrites_previous_cache() {
        let (tx, _rx) = broadcast::channel(32);
        let cache = Arc::new(std::sync::RwLock::new(None));
        let handler = AdapterWssHandler::new(tx, cache.clone());

        handler.on_trustmark_update("bot1", 5000);
        handler.on_trustmark_update("bot1", 9000);

        let cached = cache.read().unwrap();
        let entry = cached.as_ref().unwrap();
        assert!((entry.score.total - 0.90).abs() < 0.001);
    }

    #[test]
    fn bp_to_float_conversion() {
        assert!((bp_to_float(0) - 0.0).abs() < f64::EPSILON);
        assert!((bp_to_float(5000) - 0.5).abs() < f64::EPSILON);
        assert!((bp_to_float(10000) - 1.0).abs() < f64::EPSILON);
        assert!((bp_to_float(8500) - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string() {
        let long = "a".repeat(300);
        let result = truncate(&long, 200);
        assert_eq!(result.len(), 203); // 200 + "..."
        assert!(result.ends_with("..."));
    }
}
