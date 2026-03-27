//! Temporal decay (D15) — old evidence loses influence over time.
//!
//! 90-day half-life: a receipt from 90 days ago contributes half as much
//! as an identical receipt from today.

/// Half-life in milliseconds (90 days).
pub const HALF_LIFE_MS: f64 = 90.0 * 24.0 * 3600.0 * 1000.0;

/// Compute the decay factor for a receipt at `age_ms` milliseconds old.
///
/// Returns a value in (0.0, 1.0] where 1.0 = now, 0.5 = 90 days ago.
pub fn decay_factor(age_ms: u64) -> f64 {
    let exponent = -(age_ms as f64) * (2.0_f64.ln()) / HALF_LIFE_MS;
    exponent.exp()
}

/// Apply decay to a score based on when it was computed.
pub fn apply_decay(score: f64, age_ms: u64) -> f64 {
    score * decay_factor(age_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_full_weight() {
        let f = decay_factor(0);
        assert!((f - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn half_life_is_half() {
        let f = decay_factor(HALF_LIFE_MS as u64);
        assert!((f - 0.5).abs() < 0.001, "90 days should be 0.5: {f}");
    }

    #[test]
    fn double_half_life_is_quarter() {
        let f = decay_factor(2 * HALF_LIFE_MS as u64);
        assert!((f - 0.25).abs() < 0.001, "180 days should be 0.25: {f}");
    }

    #[test]
    fn one_day_barely_decays() {
        let one_day = 24 * 3600 * 1000;
        let f = decay_factor(one_day);
        assert!(f > 0.99, "1 day should barely decay: {f}");
    }

    #[test]
    fn apply_decay_works() {
        let score = apply_decay(0.8, HALF_LIFE_MS as u64);
        assert!((score - 0.4).abs() < 0.001);
    }
}
