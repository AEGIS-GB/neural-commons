//! Enforcement configuration (D30)
//!
//! Defines which adapter checks are in observe mode (warn, don't act)
//! vs enforce mode (act on violations).
//!
//! Only write_barrier and slm_reject are switchable.
//! vault_block, memory_write, identity_check, failure_rollback are always enforced.

use serde::{Deserialize, Serialize};

/// The two valid values for a switchable enforcement check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckMode {
    /// Log the event and issue a receipt. Take no blocking action.
    Observe,
    /// Log the event, issue a receipt, and act (revert / drop / encrypt / block).
    Enforce,
}

impl CheckMode {
    pub fn is_observe(&self) -> bool {
        matches!(self, CheckMode::Observe)
    }
    pub fn is_enforce(&self) -> bool {
        matches!(self, CheckMode::Enforce)
    }
}

/// Per-check enforcement posture for the adapter.
///
/// Embedded in AdapterConfig. Serializes as:
/// ```json
/// {
///   "enforcement": {
///     "write_barrier": "observe",
///     "slm_reject": "observe"
///   }
/// }
/// ```
///
/// vault_block, memory_write, identity_check, failure_rollback are
/// intentionally absent — they are always "enforce" and not configurable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    /// Write barrier: detect unauthorized file writes.
    /// observe = receipt only, no revert.
    /// enforce = receipt + revert.
    pub write_barrier: CheckMode,

    /// SLM threat reject: screen prompts for injection patterns.
    /// observe = summary receipt only, request still forwarded.
    /// enforce = receipt + request dropped if score exceeds holster threshold.
    pub slm_reject: CheckMode,
}

impl EnforcementConfig {
    /// External warden default — safe install, nothing breaks.
    pub fn observe_default() -> Self {
        Self {
            write_barrier: CheckMode::Observe,
            slm_reject: CheckMode::Observe,
        }
    }

    /// Test cluster default — full enforcement from day 1.
    pub fn enforce_default() -> Self {
        Self {
            write_barrier: CheckMode::Enforce,
            slm_reject: CheckMode::Enforce,
        }
    }

    /// Apply --observe-only flag: sets both switchable checks to observe.
    /// Does NOT affect vault, memory, identity, or failure.
    pub fn apply_observe_only_flag(&mut self) {
        self.write_barrier = CheckMode::Observe;
        self.slm_reject = CheckMode::Observe;
    }
}

/// Rate limit configuration (D30).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Key by bot Ed25519 fingerprint (NOT source IP).
    /// Source IP is meaningless on a local proxy — all requests are 127.0.0.1.
    pub req_per_min: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { req_per_min: 1000 }
    }
}

/// Body size cap (D30).
pub const BODY_SIZE_CAP_MB: usize = 10;

/// SLM warn-mode receipt detail level (D30).
/// Phase 1: summary only. Phase 2: full per-pattern breakdown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlmReceiptDetail {
    /// Aggregate score + action only. No per-pattern breakdown.
    #[default]
    Summary,
    /// Full per-pattern basis-point scores + action. Phase 2 only.
    Full,
}
