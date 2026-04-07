//! Autonomous mesh adapter — 6 background tasks that make the mesh alive
//! without human prompting.
//!
//! Tasks:
//! 1. (WSS handler — already exists in gateway_wss.rs)
//! 2. Heartbeat — peer status broadcast every 5 minutes
//! 3. Inbox poll — process relay messages every 30 seconds
//! 4. Botawiki sync — fetch canonical claims every 10 minutes
//! 5. Harvest — submit novel patterns every 1 hour
//! 6. Vote — validate claims on demand (event-driven from inbox)
//!
//! All data is persisted as append-only JSONL files in `{data_dir}/autonomous/`
//! for KB building and model fine-tuning.

pub mod harvest;
pub mod heartbeat;
pub mod inbox;
pub mod state;
pub mod sync;
pub mod types;
pub mod vote;

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::gateway_client::GatewayClient;
use crate::state::{AdapterState, DashboardAlert};

pub use state::AutonomousState;

/// Configuration for autonomous task intervals and thresholds.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AutonomousConfig {
    /// Enable autonomous tasks (default: true when gateway_url is set).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Heartbeat broadcast interval in seconds (default: 300 = 5 min).
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_secs: u64,

    /// Inbox poll interval in seconds (default: 30).
    #[serde(default = "default_inbox_poll")]
    pub inbox_poll_interval_secs: u64,

    /// Botawiki sync interval in seconds (default: 600 = 10 min).
    #[serde(default = "default_sync")]
    pub sync_interval_secs: u64,

    /// Harvest interval in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_harvest")]
    pub harvest_interval_secs: u64,

    /// Minimum TRUSTMARK (basis points) to accept threat intel (default: 4000).
    #[serde(default = "default_min_trust")]
    pub min_trust_for_intel_bp: u32,
}

fn default_true() -> bool {
    true
}
fn default_heartbeat() -> u64 {
    300
}
fn default_inbox_poll() -> u64 {
    30
}
fn default_sync() -> u64 {
    600
}
fn default_harvest() -> u64 {
    3600
}
fn default_min_trust() -> u32 {
    4000
}

impl Default for AutonomousConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            heartbeat_interval_secs: default_heartbeat(),
            inbox_poll_interval_secs: default_inbox_poll(),
            sync_interval_secs: default_sync(),
            harvest_interval_secs: default_harvest(),
            min_trust_for_intel_bp: default_min_trust(),
        }
    }
}

/// Orchestrates the 6 autonomous background tasks.
pub struct AutonomousRunner {
    pub adapter_state: Arc<AdapterState>,
    pub relay_inbox: Arc<aegis_proxy::cognitive_bridge::RelayInbox>,
    pub gateway_client: Arc<GatewayClient>,
    pub auto_state: Arc<AutonomousState>,
    pub alert_tx: broadcast::Sender<DashboardAlert>,
    pub config: AutonomousConfig,
}

impl AutonomousRunner {
    /// Spawn all 6 autonomous tasks as tokio background tasks.
    ///
    /// Task 1 (WSS handler) is already spawned separately.
    /// This method spawns tasks 2-6.
    pub fn spawn(self) {
        if !self.config.enabled {
            tracing::info!("autonomous: disabled by config");
            return;
        }

        // Task 2: Heartbeat
        heartbeat::spawn(
            self.adapter_state.clone(),
            self.auto_state.clone(),
            self.gateway_client.clone(),
            self.alert_tx.clone(),
            self.config.clone(),
        );

        // Task 3: Inbox poll
        inbox::spawn(
            self.adapter_state.clone(),
            self.relay_inbox.clone(),
            self.gateway_client.clone(),
            self.auto_state.clone(),
            self.alert_tx.clone(),
            self.config.clone(),
        );

        // Task 4: Botawiki sync
        sync::spawn(
            self.adapter_state.clone(),
            self.gateway_client.clone(),
            self.auto_state.clone(),
            self.config.clone(),
        );

        // Task 5: Harvest
        harvest::spawn(
            self.adapter_state.clone(),
            self.gateway_client.clone(),
            self.auto_state.clone(),
            self.config.clone(),
        );

        // Task 6: Vote — event-driven, called from inbox processor
        // (no separate spawn needed)

        tracing::info!(
            "autonomous: all mesh tasks spawned (heartbeat, inbox, sync, harvest, vote)"
        );
    }
}
