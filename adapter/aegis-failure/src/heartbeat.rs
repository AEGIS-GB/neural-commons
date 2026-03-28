//! Heartbeat Monitor (§2.10.1)
//!
//! Monitors upstream LLM provider connectivity and adapter health.
//! Produces heartbeat receipts at configurable intervals.
//!
//! Phase 1: optional velocity stretch
//! Phase 2: full implementation

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Heartbeat configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    /// Interval between heartbeat checks (seconds).
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Number of consecutive failures before declaring unhealthy.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Timeout for upstream health check (seconds).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_interval() -> u64 {
    30
}
fn default_failure_threshold() -> u32 {
    3
}
fn default_timeout() -> u64 {
    5
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval(),
            failure_threshold: default_failure_threshold(),
            timeout_secs: default_timeout(),
        }
    }
}

/// Current health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// All systems operational.
    Healthy,
    /// Degraded — some failures detected but below threshold.
    Degraded,
    /// Unhealthy — consecutive failures exceeded threshold.
    Unhealthy,
    /// Unknown — no checks performed yet.
    Unknown,
}

/// Heartbeat monitor state.
pub struct HeartbeatMonitor {
    config: HeartbeatConfig,
    consecutive_failures: u32,
    last_check: Option<Instant>,
    status: HealthStatus,
    total_checks: u64,
    total_failures: u64,
}

impl HeartbeatMonitor {
    pub fn new(config: HeartbeatConfig) -> Self {
        Self {
            config,
            consecutive_failures: 0,
            last_check: None,
            status: HealthStatus::Unknown,
            total_checks: 0,
            total_failures: 0,
        }
    }

    /// Record a successful health check.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_check = Some(Instant::now());
        self.total_checks += 1;
        self.status = HealthStatus::Healthy;
    }

    /// Record a failed health check.
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_check = Some(Instant::now());
        self.total_checks += 1;
        self.total_failures += 1;

        if self.consecutive_failures >= self.config.failure_threshold {
            self.status = HealthStatus::Unhealthy;
        } else {
            self.status = HealthStatus::Degraded;
        }
    }

    /// Get current health status.
    pub fn status(&self) -> HealthStatus {
        self.status
    }

    /// Get consecutive failure count.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Check if a heartbeat is due.
    pub fn is_check_due(&self) -> bool {
        match self.last_check {
            None => true,
            Some(last) => last.elapsed() >= Duration::from_secs(self.config.interval_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_status_is_unknown() {
        let monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        assert_eq!(monitor.status(), HealthStatus::Unknown);
    }

    #[test]
    fn success_makes_healthy() {
        let mut monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        monitor.record_success();
        assert_eq!(monitor.status(), HealthStatus::Healthy);
    }

    #[test]
    fn failures_degrade_then_unhealthy() {
        let mut monitor = HeartbeatMonitor::new(HeartbeatConfig {
            failure_threshold: 3,
            ..Default::default()
        });

        monitor.record_failure();
        assert_eq!(monitor.status(), HealthStatus::Degraded);

        monitor.record_failure();
        assert_eq!(monitor.status(), HealthStatus::Degraded);

        monitor.record_failure();
        assert_eq!(monitor.status(), HealthStatus::Unhealthy);
    }

    #[test]
    fn success_resets_failures() {
        let mut monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        monitor.record_failure();
        monitor.record_failure();
        monitor.record_success();
        assert_eq!(monitor.consecutive_failures(), 0);
        assert_eq!(monitor.status(), HealthStatus::Healthy);
    }
}
