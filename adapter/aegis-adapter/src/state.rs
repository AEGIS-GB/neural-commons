//! Shared adapter state — accessible to all subsystems, dashboard, and CLI.
//!
//! AdapterState is created once at startup and shared via Arc across
//! the proxy, dashboard, cognitive bridge, memory monitor, and CLI.
//!
//! Sub-structs group related fields:
//! - `SecurityState` — nonce registry for replay prevention
//! - `EvidenceState` — evidence recorder and chain helper methods

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use aegis_evidence::EvidenceRecorder;
use tokio::sync::broadcast;

pub use aegis_dashboard::DashboardAlert;

use crate::mode::ModeController;
use crate::replay::{MonotonicCounter, NonceRegistry};

// ---------------------------------------------------------------------------
// Sub-structs
// ---------------------------------------------------------------------------

/// Security-related state: nonce registry for replay prevention.
pub struct SecurityState {
    /// Nonce registry for replay prevention.
    pub nonce_registry: std::sync::Mutex<NonceRegistry>,
}

impl SecurityState {
    /// Create a new SecurityState with a fresh nonce registry.
    pub fn new() -> Self {
        Self {
            nonce_registry: std::sync::Mutex::new(NonceRegistry::new()),
        }
    }

    /// Register a nonce for replay prevention. Returns true if new (allowed).
    /// Fails closed: if the mutex is poisoned, returns false (rejected)
    /// to prevent replay attacks via panic-induced lock poisoning.
    pub fn register_nonce(&self, nonce: &str) -> bool {
        match self.nonce_registry.lock() {
            Ok(mut registry) => registry.register(nonce),
            Err(_poisoned) => {
                tracing::error!(
                    "nonce registry mutex poisoned — failing closed, rejecting request"
                );
                false
            }
        }
    }
}

/// Evidence-related state: recorder and chain helper methods.
pub struct EvidenceState {
    /// Evidence recorder (hash-chained receipts).
    pub evidence: Arc<EvidenceRecorder>,
}

impl EvidenceState {
    /// Create a new EvidenceState wrapping the given recorder.
    pub fn new(evidence: Arc<EvidenceRecorder>) -> Self {
        Self { evidence }
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
}

// ---------------------------------------------------------------------------
// TRUSTMARK cache
// ---------------------------------------------------------------------------

/// Per-dimension health check result.
pub struct DimensionHealth {
    pub name: String,
    pub value: f64,
    pub threshold: f64,
    pub healthy: bool,
}

/// Cached TRUSTMARK score with freshness tracking.
#[derive(Clone)]
pub struct TrustmarkCache {
    pub score: aegis_trustmark::scoring::TrustmarkScore,
    pub computed_at_ms: i64,
}

/// Return the current epoch time in milliseconds.
fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ---------------------------------------------------------------------------
// AdapterState
// ---------------------------------------------------------------------------

/// Shared state for the entire adapter.
///
/// Created once at startup, wrapped in `Arc`, and passed to all subsystems.
pub struct AdapterState {
    /// Evidence-related state (recorder + chain helpers).
    pub evidence_state: EvidenceState,

    /// Security-related state (nonce registry).
    pub security_state: SecurityState,

    /// Evidence recorder (hash-chained receipts).
    /// Kept for backward compatibility — delegates to `evidence_state.evidence`.
    pub evidence: Arc<EvidenceRecorder>,

    /// Runtime mode controller (observe-only / enforce / pass-through).
    pub mode: Arc<ModeController>,

    /// Request monotonic counter for ordering.
    pub request_counter: MonotonicCounter,

    /// Nonce registry for replay prevention.
    /// Kept for backward compatibility — delegates to `security_state.nonce_registry`.
    pub nonce_registry: std::sync::Mutex<NonceRegistry>,

    /// Timestamp when the adapter started.
    pub start_time: Instant,

    /// Data directory path.
    pub data_dir: std::path::PathBuf,

    /// Listen address (for dashboard URL construction).
    pub listen_addr: String,

    /// Upstream URL.
    pub upstream_url: String,

    /// Dashboard path prefix (e.g., "/dashboard").
    pub dashboard_path: String,

    /// Broadcast channel for pushing critical alerts to SSE clients.
    /// Sender is cloned into each subsystem that can generate alerts.
    /// SSE handler calls `.subscribe()` to get a per-connection receiver.
    pub alert_tx: broadcast::Sender<DashboardAlert>,

    /// Cached TRUSTMARK score with freshness tracking.
    /// Auto-recomputed when stale (>5 minutes).
    pub trustmark_cache: std::sync::RwLock<Option<TrustmarkCache>>,
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
    /// Delegates to `evidence_state`.
    pub fn chain_head_seq(&self) -> u64 {
        self.evidence_state.chain_head_seq()
    }

    /// Get the current evidence chain head hash (hex).
    /// Delegates to `evidence_state`.
    pub fn chain_head_hash(&self) -> String {
        self.evidence_state.chain_head_hash()
    }

    /// Get the total receipt count.
    /// Delegates to `evidence_state`.
    pub fn receipt_count(&self) -> u64 {
        self.evidence_state.receipt_count()
    }

    /// Register a nonce for replay prevention. Returns true if new (allowed).
    /// Fails closed: if the mutex is poisoned, returns false (rejected)
    /// to prevent replay attacks via panic-induced lock poisoning.
    /// Delegates to `security_state`.
    pub fn register_nonce(&self, nonce: &str) -> bool {
        self.security_state.register_nonce(nonce)
    }

    /// Get the next request sequence number.
    pub fn next_request_seq(&self) -> u64 {
        self.request_counter.next()
    }

    /// Dashboard URL.
    pub fn dashboard_url(&self) -> String {
        format!("http://{}{}", self.listen_addr, self.dashboard_path)
    }

    /// Check per-dimension TRUSTMARK health against thresholds.
    /// Returns a health report for each dimension.
    pub fn check_trustmark_health(&self, data_dir: &Path) -> Vec<DimensionHealth> {
        let tm = self.trustmark_score(data_dir);
        let thresholds = [
            ("persona_integrity", 0.95),
            ("chain_integrity", 0.95),
            ("vault_hygiene", 0.90),
            ("temporal_consistency", 0.80),
            ("contribution_volume", 0.50),
        ];

        let mut results = Vec::new();
        for dim in &tm.score.dimensions {
            let threshold = thresholds
                .iter()
                .find(|(n, _)| *n == dim.name)
                .map(|(_, t)| *t)
                .unwrap_or(0.50);
            results.push(DimensionHealth {
                name: dim.name.clone(),
                value: dim.value,
                threshold,
                healthy: dim.value >= threshold,
            });
        }
        results
    }

    /// Get the current TRUSTMARK score, recomputing if stale (>5 minutes).
    pub fn trustmark_score(&self, data_dir: &Path) -> TrustmarkCache {
        let stale_threshold_ms: i64 = 5 * 60 * 1000; // 5 minutes
        let now_ms = now_epoch_ms();

        // Check cache
        if let Ok(cache) = self.trustmark_cache.read() {
            if let Some(ref cached) = *cache {
                if now_ms - cached.computed_at_ms < stale_threshold_ms {
                    return cached.clone(); // Fresh enough
                }
            }
        }

        // Recompute
        let signals = aegis_trustmark::gather::gather_local_signals(data_dir);
        let score = aegis_trustmark::scoring::TrustmarkScore::compute(&signals);
        let cache_entry = TrustmarkCache {
            score,
            computed_at_ms: now_ms,
        };

        if let Ok(mut cache) = self.trustmark_cache.write() {
            *cache = Some(cache_entry.clone());
        }

        cache_entry
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
            evidence_state: EvidenceState::new(recorder.clone()),
            security_state: SecurityState::new(),
            evidence: recorder,
            mode: Arc::new(ModeController::default()),
            request_counter: MonotonicCounter::new(),
            nonce_registry: std::sync::Mutex::new(NonceRegistry::new()),
            start_time: Instant::now(),
            data_dir: PathBuf::from(".aegis"),
            listen_addr: "127.0.0.1:3141".into(),
            upstream_url: "https://api.anthropic.com".into(),
            dashboard_path: "/dashboard".into(),
            alert_tx,
            trustmark_cache: std::sync::RwLock::new(None),
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
        assert_eq!(state.dashboard_url(), "http://127.0.0.1:3141/dashboard");
    }

    #[test]
    fn security_state_standalone() {
        let sec = SecurityState::new();
        assert!(sec.register_nonce("nonce-a"));
        assert!(!sec.register_nonce("nonce-a")); // replay rejected
        assert!(sec.register_nonce("nonce-b"));
    }

    #[test]
    fn evidence_state_standalone() {
        let key = generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let ev = EvidenceState::new(recorder);
        assert_eq!(ev.chain_head_seq(), 0);
        assert_eq!(ev.receipt_count(), 0);
        assert_eq!(ev.chain_head_hash().len(), 64);
    }

    #[test]
    fn trustmark_health_check() {
        let state = make_state();
        let data_dir = PathBuf::from(".aegis");
        let health = state.check_trustmark_health(&data_dir);
        // Should return a health entry for each dimension
        assert!(!health.is_empty(), "health check should have dimensions");
        for dim in &health {
            assert!(!dim.name.is_empty());
            assert!(dim.threshold > 0.0);
        }
    }

    #[test]
    fn trustmark_cache_freshness() {
        let state = make_state();
        let data_dir = PathBuf::from(".aegis");
        let s1 = state.trustmark_score(&data_dir);
        let s2 = state.trustmark_score(&data_dir);
        assert_eq!(
            s1.computed_at_ms, s2.computed_at_ms,
            "second call should return cached value"
        );
    }
}
