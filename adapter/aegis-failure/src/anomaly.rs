//! Anomaly Threshold Engine (§2.10.3)
//!
//! 7-day auto-calibrating anomaly detection.
//! Tracks baseline metrics and flags deviations.
//!
//! Phase 2: full implementation with auto-calibration.
//! Phase 1: stub with basic threshold checking.

use serde::{Deserialize, Serialize};

/// A metric data point for anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    /// Metric name (e.g. "request_latency_ms", "error_rate", "body_size_bytes")
    pub name: String,
    /// Metric value
    pub value: f64,
    /// Timestamp (epoch ms)
    pub timestamp_ms: i64,
}

/// Anomaly detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    /// Whether an anomaly was detected
    pub is_anomaly: bool,
    /// The metric that triggered the anomaly
    pub metric_name: String,
    /// The observed value
    pub observed: f64,
    /// The expected baseline value
    pub baseline: f64,
    /// Deviation as a percentage
    pub deviation_pct: f64,
    /// Explanation
    pub explanation: String,
}

/// Simple threshold-based anomaly detector (Phase 1 stub).
/// Full auto-calibrating engine in Phase 2.
pub struct AnomalyDetector {
    /// Static thresholds per metric name.
    thresholds: Vec<MetricThreshold>,
}

/// A threshold for a specific metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricThreshold {
    /// Metric name
    pub name: String,
    /// Maximum acceptable value (absolute)
    pub max_value: f64,
    /// Minimum acceptable value (absolute)
    pub min_value: f64,
}

impl AnomalyDetector {
    /// Create with default thresholds.
    pub fn new() -> Self {
        Self {
            thresholds: vec![
                MetricThreshold {
                    name: "request_latency_ms".to_string(),
                    max_value: 30_000.0,
                    min_value: 0.0,
                },
                MetricThreshold {
                    name: "error_rate".to_string(),
                    max_value: 0.5,
                    min_value: 0.0,
                },
                MetricThreshold {
                    name: "body_size_bytes".to_string(),
                    max_value: 10_000_000.0,
                    min_value: 0.0,
                },
            ],
        }
    }

    /// Check a metric point against thresholds.
    pub fn check(&self, point: &MetricPoint) -> Option<AnomalyResult> {
        for threshold in &self.thresholds {
            if threshold.name == point.name {
                if point.value > threshold.max_value {
                    let deviation = ((point.value - threshold.max_value) / threshold.max_value) * 100.0;
                    return Some(AnomalyResult {
                        is_anomaly: true,
                        metric_name: point.name.clone(),
                        observed: point.value,
                        baseline: threshold.max_value,
                        deviation_pct: deviation,
                        explanation: format!(
                            "{} ({:.1}) exceeds max threshold ({:.1})",
                            point.name, point.value, threshold.max_value
                        ),
                    });
                }
                if point.value < threshold.min_value {
                    return Some(AnomalyResult {
                        is_anomaly: true,
                        metric_name: point.name.clone(),
                        observed: point.value,
                        baseline: threshold.min_value,
                        deviation_pct: 100.0,
                        explanation: format!(
                            "{} ({:.1}) below min threshold ({:.1})",
                            point.name, point.value, threshold.min_value
                        ),
                    });
                }
                // Within thresholds
                return None;
            }
        }
        None // No threshold defined for this metric
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_value_no_anomaly() {
        let detector = AnomalyDetector::new();
        let point = MetricPoint {
            name: "request_latency_ms".to_string(),
            value: 500.0,
            timestamp_ms: 0,
        };
        assert!(detector.check(&point).is_none());
    }

    #[test]
    fn high_latency_is_anomaly() {
        let detector = AnomalyDetector::new();
        let point = MetricPoint {
            name: "request_latency_ms".to_string(),
            value: 60_000.0,
            timestamp_ms: 0,
        };
        let result = detector.check(&point).unwrap();
        assert!(result.is_anomaly);
    }

    #[test]
    fn unknown_metric_no_anomaly() {
        let detector = AnomalyDetector::new();
        let point = MetricPoint {
            name: "unknown_metric".to_string(),
            value: 999_999.0,
            timestamp_ms: 0,
        };
        assert!(detector.check(&point).is_none());
    }
}
