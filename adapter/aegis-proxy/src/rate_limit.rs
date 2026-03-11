//! Token bucket rate limiter per bot identity.
//!
//! Keyed by Ed25519 fingerprint (not source IP — proxy is localhost-only).
//! Refills at `rate` tokens/second with burst capacity.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// A token bucket for a single identity.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    rate: f64,
}

impl TokenBucket {
    fn new(capacity: f64, rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            rate,
        }
    }

    /// Try to consume one token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns seconds until a token is available.
    fn retry_after(&self) -> f64 {
        if self.tokens >= 1.0 {
            0.0
        } else {
            (1.0 - self.tokens) / self.rate
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }
}

/// Per-identity rate limiter.
///
/// Thread-safe via Mutex. The proxy runs on a single machine,
/// so contention is minimal.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    /// Tokens per second (rate_limit_per_minute / 60)
    rate: f64,
    /// Maximum burst size
    burst: f64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `per_minute`: maximum requests per minute per identity
    /// - `burst`: maximum burst size (instantaneous capacity)
    pub fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate: per_minute as f64 / 60.0,
            burst: burst as f64,
        }
    }

    /// Check if a request from the given identity is allowed.
    ///
    /// Returns `Ok(())` if allowed, `Err(retry_after_secs)` if rate limited.
    pub fn check(&self, identity: &str) -> Result<(), f64> {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        let bucket = buckets
            .entry(identity.to_string())
            .or_insert_with(|| TokenBucket::new(self.burst, self.rate));

        if bucket.try_consume() {
            Ok(())
        } else {
            Err(bucket.retry_after())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_burst() {
        let limiter = RateLimiter::new(60, 10);
        for _ in 0..10 {
            assert!(limiter.check("bot1").is_ok());
        }
    }

    #[test]
    fn blocks_after_burst() {
        let limiter = RateLimiter::new(60, 5);
        for _ in 0..5 {
            assert!(limiter.check("bot1").is_ok());
        }
        // 6th request should be blocked
        let result = limiter.check("bot1");
        assert!(result.is_err());
    }

    #[test]
    fn separate_identities() {
        let limiter = RateLimiter::new(60, 2);
        assert!(limiter.check("bot1").is_ok());
        assert!(limiter.check("bot1").is_ok());
        assert!(limiter.check("bot1").is_err());
        // bot2 should still be allowed
        assert!(limiter.check("bot2").is_ok());
    }

    #[test]
    fn retry_after_is_positive() {
        let limiter = RateLimiter::new(60, 1);
        assert!(limiter.check("bot1").is_ok());
        match limiter.check("bot1") {
            Err(retry_after) => assert!(retry_after > 0.0),
            Ok(()) => panic!("should be rate limited"),
        }
    }
}
