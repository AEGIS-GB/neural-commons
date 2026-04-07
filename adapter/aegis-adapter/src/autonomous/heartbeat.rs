//! Task 2: Peer status broadcast (heartbeat).
//!
//! Every 5 minutes, broadcasts our current TRUSTMARK score, chain sequence,
//! uptime, and screening stats to the mesh. Persists each snapshot to
//! `peer_status.jsonl` for mesh behavior analysis.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use crate::gateway_client::GatewayClient;
use crate::state::{AdapterState, DashboardAlert};

use super::AutonomousConfig;
use super::state::{AutonomousState, PeerStatusSnapshot};

/// Spawn the heartbeat task.
pub fn spawn(
    adapter_state: Arc<AdapterState>,
    auto_state: Arc<AutonomousState>,
    _gateway_client: Arc<GatewayClient>,
    _alert_tx: broadcast::Sender<DashboardAlert>,
    config: AutonomousConfig,
) {
    let interval_secs = config.heartbeat_interval_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // skip immediate tick

        loop {
            interval.tick().await;

            // Gather current state
            let uptime_ms = adapter_state.start_time.elapsed().as_millis() as u64;
            let chain_seq = adapter_state.chain_head_seq();

            // Read TRUSTMARK score (basis points = score * 10000)
            let trustmark_bp = {
                let cache = adapter_state.trustmark_cache.read().ok();
                cache
                    .and_then(|c| c.as_ref().map(|tc| (tc.score.total * 10_000.0) as u32))
                    .unwrap_or(0)
            };

            // Get screening stats from the log
            let screening = {
                let log = auto_state.screening_log.read().await;
                log.stats(300) // 5-minute window matches heartbeat interval
            };

            let snapshot = PeerStatusSnapshot {
                ts_ms: now_ms(),
                trustmark_bp,
                chain_seq,
                uptime_ms,
                screening: screening.clone(),
            };

            // Persist snapshot locally
            snapshot.persist(&adapter_state.data_dir);

            // NOTE: Gateway broadcast endpoint not yet implemented.
            // For now we log locally. Gateway fanout will be added in a
            // separate PR when POST /mesh/send supports to="broadcast".
            tracing::debug!(
                trustmark_bp,
                chain_seq,
                uptime_ms,
                screened = screening.screened,
                "heartbeat: peer status snapshot persisted"
            );
        }
    });
    tracing::info!(interval_secs, "autonomous: heartbeat task started");
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
