//! Per-tier token bucket rate limiter for the Gateway.
//!
//! Each bot gets a separate bucket keyed by pubkey. Bucket capacity and refill
//! rate are determined by the bot's TRUSTMARK tier:
//!   - Tier 1 (TRUSTMARK < 0.3): 10 req/min
//!   - Tier 2 (0.3 <= TRUSTMARK < 0.4): 100 req/min
//!   - Tier 3 (TRUSTMARK >= 0.4): 1000 req/min
//!
//! Uses the same token bucket pattern as adapter/aegis-proxy/src/rate_limit.rs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// A token bucket for a single bot identity.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    rate: f64, // tokens per second
    tier: u8,
}

impl TokenBucket {
    fn new(capacity: f64, rate: f64, tier: u8) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            rate,
            tier,
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

/// Return (capacity, rate_per_second) for a given tier.
fn tier_limits(tier: u8) -> (f64, f64) {
    match tier {
        1 => (10.0, 10.0 / 60.0),     // 10 req/min
        2 => (100.0, 100.0 / 60.0),   // 100 req/min
        3 => (1000.0, 1000.0 / 60.0), // 1000 req/min
        _ => (10.0, 10.0 / 60.0),     // default to Tier 1
    }
}

/// Determine tier from TRUSTMARK score in basis points.
pub fn tier_from_score_bp(score_bp: u32) -> u8 {
    if score_bp >= 4000 {
        3
    } else if score_bp >= 3000 {
        2
    } else {
        1
    }
}

/// Per-bot rate limiter with tier-aware token buckets.
///
/// Thread-safe via Mutex. The Gateway runs on a single machine,
/// so contention is minimal.
pub struct TierRateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

impl TierRateLimiter {
    /// Create a new rate limiter.
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request from the given bot is allowed at the specified tier.
    ///
    /// Returns `Ok(())` if allowed, `Err(retry_after_secs)` if rate limited.
    /// If the bot's tier has changed, the bucket is replaced with a fresh one.
    pub fn check(&self, bot_id: &str, tier: u8) -> Result<(), f64> {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => {
                tracing::error!("tier rate limiter mutex poisoned — failing closed");
                return Err(60.0);
            }
        };

        let (capacity, rate) = tier_limits(tier);

        let bucket = buckets
            .entry(bot_id.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, rate, tier));

        // If tier changed, replace bucket with fresh one at new tier
        if bucket.tier != tier {
            *bucket = TokenBucket::new(capacity, rate, tier);
        }

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
    fn tier1_allows_10_requests() {
        let limiter = TierRateLimiter::new();
        for _ in 0..10 {
            assert!(limiter.check("bot1", 1).is_ok());
        }
    }

    #[test]
    fn tier1_blocks_11th_request() {
        let limiter = TierRateLimiter::new();
        for _ in 0..10 {
            assert!(limiter.check("bot1", 1).is_ok());
        }
        let result = limiter.check("bot1", 1);
        assert!(result.is_err());
    }

    #[test]
    fn tier2_allows_100_requests() {
        let limiter = TierRateLimiter::new();
        for _ in 0..100 {
            assert!(limiter.check("bot1", 2).is_ok());
        }
    }

    #[test]
    fn tier2_blocks_101st_request() {
        let limiter = TierRateLimiter::new();
        for _ in 0..100 {
            assert!(limiter.check("bot1", 2).is_ok());
        }
        let result = limiter.check("bot1", 2);
        assert!(result.is_err());
    }

    #[test]
    fn tier3_allows_1000_requests() {
        let limiter = TierRateLimiter::new();
        for _ in 0..1000 {
            assert!(limiter.check("bot1", 3).is_ok());
        }
    }

    #[test]
    fn separate_bots_get_separate_buckets() {
        let limiter = TierRateLimiter::new();
        // Exhaust bot1
        for _ in 0..10 {
            assert!(limiter.check("bot1", 1).is_ok());
        }
        assert!(limiter.check("bot1", 1).is_err());
        // bot2 should still be allowed
        assert!(limiter.check("bot2", 1).is_ok());
    }

    #[test]
    fn retry_after_is_positive_when_rate_limited() {
        let limiter = TierRateLimiter::new();
        // Exhaust tier 1 bucket
        for _ in 0..10 {
            assert!(limiter.check("bot1", 1).is_ok());
        }
        match limiter.check("bot1", 1) {
            Err(retry_after) => assert!(retry_after > 0.0),
            Ok(()) => panic!("should be rate limited"),
        }
    }

    #[test]
    fn tier_upgrade_resets_bucket() {
        let limiter = TierRateLimiter::new();
        // Exhaust tier 1
        for _ in 0..10 {
            assert!(limiter.check("bot1", 1).is_ok());
        }
        assert!(limiter.check("bot1", 1).is_err());

        // Upgrade to tier 2 — should get a fresh bucket
        assert!(limiter.check("bot1", 2).is_ok());
    }

    #[test]
    fn tier_from_score_boundaries() {
        assert_eq!(tier_from_score_bp(0), 1);
        assert_eq!(tier_from_score_bp(2999), 1);
        assert_eq!(tier_from_score_bp(3000), 2);
        assert_eq!(tier_from_score_bp(3999), 2);
        assert_eq!(tier_from_score_bp(4000), 3);
        assert_eq!(tier_from_score_bp(10000), 3);
    }
}
