//! Shared adapter state — accessible to all subsystems, dashboard, and CLI.
//!
//! AdapterState is created once at startup and shared via Arc across
//! the proxy, dashboard, cognitive bridge, memory monitor, and CLI.

use std::sync::Arc;
use std::time::Instant;

use aegis_evidence::EvidenceRecorder;
use tokio::sync::broadcast;

pub use aegis_dashboard::DashboardAlert;

use crate::mode::ModeController;
use crate::replay::{MonotonicCounter, NonceRegistry};

/// Shared state for the entire adapter.
///
/// Created once at startup, wrapped in `Arc`, and passed to all subsystems.
pub struct AdapterState {
    /// Evidence recorder (hash-chained receipts).
    pub evidence: Arc<EvidenceRecorder>,

    /// Runtime mode controller (observe-only / enforce / pass-through).
    pub mode: Arc<ModeController>,

    /// Request monotonic counter for ordering.
    pub request_counter: MonotonicCounter,

    /// Nonce registry for replay prevention.
    pub nonce_registry: std::sync::Mutex<NonceRegistry>,

    /// Timestamp when the adapter started.
    pub start_time: Instant,

    /// Data directory path.
    pub data_dir: std::path::PathBuf,

    /// Listen address (for dashboard URL construction).
    pub listen_addr: String,

    /// Upstream URL.
    pub upstream_url: String,

    /// Broadcast channel for pushing critical alerts to SSE clients.
    /// Sender is cloned into each subsystem that can generate alerts.
    /// SSE handler calls `.subscribe()` to get a per-connection receiver.
    pub alert_tx: broadcast::Sender<DashboardAlert>,
}

impl AdapterState {
    /// Uptime in seconds since adapter start.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Current mode as a human-readable string.
    pub fn mode_str(&self) -> &'static str {
        match self.mode.current() {
            crate::Mode::ObserveOnly => "observe_only",
            crate::Mode::Enforce => "enforce",
            crate::Mode::PassThrough => "pass_through",
        }
    }

    /// Get the current evidence chain head sequence number.
    pub fn chain_head_seq(&self) -> u64 {
        self.evidence.chain_head().head_seq
    }

    /// Get the current evidence chain head hash (hex).
    pub fn chain_head_hash(&self) -> String {
        self.evidence.chain_head().head_hash.clone()
    }

    /// Get the total receipt count.
    pub fn receipt_count(&self) -> u64 {
        self.evidence.chain_head().receipt_count
    }

    /// Register a nonce for replay prevention. Returns true if new.
    pub fn register_nonce(&self, nonce: &str) -> bool {
        if let Ok(mut registry) = self.nonce_registry.lock() {
            registry.register(nonce)
        } else {
            // Lock poisoned — allow through (fail open)
            true
        }
    }

    /// Get the next request sequence number.
    pub fn next_request_seq(&self) -> u64 {
        self.request_counter.next()
    }

    /// Dashboard URL.
    pub fn dashboard_url(&self) -> String {
        format!("http://{}/dashboard", self.listen_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::ed25519::generate_keypair;
    use std::path::PathBuf;

    fn make_state() -> AdapterState {
        let key = generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let (alert_tx, _) = broadcast::channel(32);
        AdapterState {
            evidence: recorder,
            mode: Arc::new(ModeController::default()),
            request_counter: MonotonicCounter::new(),
            nonce_registry: std::sync::Mutex::new(NonceRegistry::new()),
            start_time: Instant::now(),
            data_dir: PathBuf::from(".aegis"),
            listen_addr: "127.0.0.1:8080".into(),
            upstream_url: "http://localhost:11434".into(),
            alert_tx,
        }
    }

    #[test]
    fn state_uptime() {
        let state = make_state();
        assert!(state.uptime_secs() < 2);
    }

    #[test]
    fn state_mode_default() {
        let state = make_state();
        assert_eq!(state.mode_str(), "observe_only");
    }

    #[test]
    fn state_chain_head() {
        let state = make_state();
        assert_eq!(state.chain_head_seq(), 0);
        assert_eq!(state.receipt_count(), 0);
    }

    #[test]
    fn state_nonce_replay() {
        let state = make_state();
        assert!(state.register_nonce("test-nonce-1"));
        assert!(!state.register_nonce("test-nonce-1")); // replay
        assert!(state.register_nonce("test-nonce-2"));
    }

    #[test]
    fn state_request_seq() {
        let state = make_state();
        assert_eq!(state.next_request_seq(), 1);
        assert_eq!(state.next_request_seq(), 2);
        assert_eq!(state.next_request_seq(), 3);
    }

    #[test]
    fn state_dashboard_url() {
        let state = make_state();
        assert_eq!(state.dashboard_url(), "http://127.0.0.1:8080/dashboard");
    }
}
