//! aegis-failure: Failure detection (§2.10)
//!
//! §2.10.1 Heartbeat Monitor
//! §2.10.2 Action Verification receipts
//! §2.10.3 Anomaly Threshold Engine (7-day auto-calibration)
//! §2.10.4 Rollback Suggestion Engine (guided investigation)

pub mod heartbeat;
pub mod anomaly;
pub mod rollback;
