//! Replay & Ordering — monotonic counter + nonce registry (§19)
//!
//! Prevents replay attacks by:
//! 1. Monotonic sequence counter: every receipt gets a strictly increasing seq.
//!    (Already handled by evidence chain — this module exposes request-level nonces.)
//! 2. Nonce registry: each proxied request gets a unique nonce. The nonce is
//!    included in the evidence receipt. Duplicate nonces are rejected.
//!
//! The nonce registry uses a time-windowed sliding window (default: 5 minutes).
//! Nonces older than the window are automatically purged.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default nonce expiry window: 5 minutes.
const DEFAULT_WINDOW_SECS: u64 = 300;

/// Maximum nonce registry size before forced compaction.
const MAX_REGISTRY_SIZE: usize = 100_000;

/// Monotonic counter for request sequencing.
///
/// Thread-safe via AtomicU64. Each call to `next()` returns a
/// strictly increasing value, starting from 1.
pub struct MonotonicCounter {
    current: std::sync::atomic::AtomicU64,
}

impl MonotonicCounter {
    pub fn new() -> Self {
        Self {
            current: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Start from a given value (e.g., restored from evidence chain).
    pub fn from_seq(seq: u64) -> Self {
        Self {
            current: std::sync::atomic::AtomicU64::new(seq),
        }
    }

    /// Get the next sequence number (strictly increasing).
    pub fn next(&self) -> u64 {
        self.current
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1
    }

    /// Get the current value without incrementing.
    pub fn current(&self) -> u64 {
        self.current
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for MonotonicCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Nonce registry for replay prevention.
///
/// Stores nonces with timestamps. Nonces older than the sliding window
/// are purged automatically during insertion.
pub struct NonceRegistry {
    /// Map from nonce → insertion time.
    nonces: HashMap<String, Instant>,
    /// Sliding window duration.
    window: Duration,
}

impl NonceRegistry {
    /// Create a new nonce registry with the default window (5 minutes).
    pub fn new() -> Self {
        Self {
            nonces: HashMap::new(),
            window: Duration::from_secs(DEFAULT_WINDOW_SECS),
        }
    }

    /// Create a registry with a custom window.
    pub fn with_window(window: Duration) -> Self {
        Self {
            nonces: HashMap::new(),
            window,
        }
    }

    /// Generate a unique nonce (64-bit random hex).
    pub fn generate_nonce() -> String {
        use rand::RngCore;
        let mut buf = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        hex::encode(buf)
    }

    /// Register a nonce. Returns `true` if the nonce was new (not a replay).
    /// Returns `false` if the nonce was already seen (replay detected).
    pub fn register(&mut self, nonce: &str) -> bool {
        let now = Instant::now();

        // Purge expired nonces periodically
        if self.nonces.len() > MAX_REGISTRY_SIZE / 2 {
            self.purge_expired(now);
        }

        // Check for duplicate
        if let Some(prev_time) = self.nonces.get(nonce) {
            if now.duration_since(*prev_time) < self.window {
                // Nonce still within window — replay detected
                return false;
            }
            // Nonce expired — allow reuse (unlikely but valid)
        }

        self.nonces.insert(nonce.to_string(), now);
        true
    }

    /// Check if a nonce has been seen (without registering it).
    pub fn is_seen(&self, nonce: &str) -> bool {
        if let Some(prev_time) = self.nonces.get(nonce) {
            Instant::now().duration_since(*prev_time) < self.window
        } else {
            false
        }
    }

    /// Number of active (non-expired) nonces.
    pub fn active_count(&self) -> usize {
        let now = Instant::now();
        self.nonces
            .values()
            .filter(|t| now.duration_since(**t) < self.window)
            .count()
    }

    /// Purge all expired nonces.
    fn purge_expired(&mut self, now: Instant) {
        self.nonces
            .retain(|_, t| now.duration_since(*t) < self.window);
    }

    /// Force purge all nonces older than the window.
    pub fn compact(&mut self) {
        self.purge_expired(Instant::now());
    }
}

impl Default for NonceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_counter_starts_at_one() {
        let counter = MonotonicCounter::new();
        assert_eq!(counter.next(), 1);
        assert_eq!(counter.next(), 2);
        assert_eq!(counter.next(), 3);
    }

    #[test]
    fn monotonic_counter_from_seq() {
        let counter = MonotonicCounter::from_seq(100);
        assert_eq!(counter.current(), 100);
        assert_eq!(counter.next(), 101);
        assert_eq!(counter.next(), 102);
    }

    #[test]
    fn monotonic_counter_is_thread_safe() {
        use std::sync::Arc;
        use std::thread;

        let counter = Arc::new(MonotonicCounter::new());
        let mut handles = Vec::new();

        for _ in 0..10 {
            let c = counter.clone();
            handles.push(thread::spawn(move || {
                let mut values = Vec::new();
                for _ in 0..100 {
                    values.push(c.next());
                }
                values
            }));
        }

        let mut all_values: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all_values.sort();
        all_values.dedup();

        // All 1000 values should be unique
        assert_eq!(all_values.len(), 1000);
        // Should be 1..=1000
        assert_eq!(*all_values.first().unwrap(), 1);
        assert_eq!(*all_values.last().unwrap(), 1000);
    }

    #[test]
    fn nonce_registry_new_nonce() {
        let mut reg = NonceRegistry::new();
        assert!(reg.register("nonce-1"));
        assert!(reg.register("nonce-2"));
    }

    #[test]
    fn nonce_registry_detects_replay() {
        let mut reg = NonceRegistry::new();
        assert!(reg.register("nonce-1"));
        assert!(!reg.register("nonce-1")); // replay!
    }

    #[test]
    fn nonce_registry_different_nonces_ok() {
        let mut reg = NonceRegistry::new();
        assert!(reg.register("aaa"));
        assert!(reg.register("bbb"));
        assert!(reg.register("ccc"));
        assert_eq!(reg.active_count(), 3);
    }

    #[test]
    fn nonce_registry_expired_nonces_allow_reuse() {
        let mut reg = NonceRegistry::with_window(Duration::from_millis(10));
        assert!(reg.register("nonce-1"));
        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));
        // Should now be allowed (expired)
        assert!(reg.register("nonce-1"));
    }

    #[test]
    fn nonce_registry_compact() {
        let mut reg = NonceRegistry::with_window(Duration::from_millis(10));
        for i in 0..100 {
            reg.register(&format!("nonce-{i}"));
        }
        assert_eq!(reg.nonces.len(), 100);
        std::thread::sleep(Duration::from_millis(20));
        reg.compact();
        assert_eq!(reg.nonces.len(), 0);
    }

    #[test]
    fn nonce_registry_is_seen() {
        let mut reg = NonceRegistry::new();
        assert!(!reg.is_seen("nonce-1"));
        reg.register("nonce-1");
        assert!(reg.is_seen("nonce-1"));
    }

    #[test]
    fn generate_nonce_unique() {
        let n1 = NonceRegistry::generate_nonce();
        let n2 = NonceRegistry::generate_nonce();
        assert_ne!(n1, n2);
        assert_eq!(n1.len(), 32); // 16 bytes → 32 hex chars
    }
}
