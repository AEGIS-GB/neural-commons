//! TRUSTMARK score computation (D13) — weighted sum of 6 dimensions.
//!
//! # WARNING: unsafe float arithmetic
//!
//! This module uses `f64` internally for dimension scoring and weighted sums.
//! The design doc (D13/D2) mandates integer basis points for all signed data.
//! The internal `TrustmarkScore` here is a computation convenience type and
//! MUST NOT be used directly in signed receipts or wire formats.
//!
//! Use [`TrustmarkScore::to_schema_score`] to convert to the
//! `aegis_schemas::TrustmarkScore` (which uses validated `BasisPoints`)
//! before persisting or transmitting.

use serde::{Deserialize, Serialize};

/// Default dimension weights (D13).
pub const WEIGHT_PERSONA_INTEGRITY: f64 = 0.25;
pub const WEIGHT_CHAIN_INTEGRITY: f64 = 0.20;
pub const WEIGHT_VAULT_HYGIENE: f64 = 0.15;
pub const WEIGHT_TEMPORAL_CONSISTENCY: f64 = 0.15;
pub const WEIGHT_RELAY_RELIABILITY: f64 = 0.15;
pub const WEIGHT_CONTRIBUTION_VOLUME: f64 = 0.10;

/// A single dimension score with its weight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionScore {
    pub name: String,
    /// Raw score [0.0, 1.0].
    pub value: f64,
    pub weight: f64,
    /// Weighted contribution (value * weight).
    pub contribution: f64,
    /// Human-readable reason for the score.
    pub reason: String,
    /// Formula used to compute this score.
    pub formula: String,
    /// Raw input values (for display).
    pub inputs: String,
    /// How to improve this score.
    pub improve: String,
    /// Target value for "healthy" (green threshold).
    pub target: f64,
    /// Status label: "healthy", "attention", "critical".
    pub status: String,
    /// Whether this dimension has a real signal source.
    /// Dimensions backed by unimplemented modules (mesh relay, volume baseline)
    /// are flagged as estimated so consumers don't treat them as authoritative.
    #[serde(default)]
    pub estimated: bool,
}

/// Complete TRUSTMARK score with all dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustmarkScore {
    /// Final weighted score [0.0, 1.0].
    pub total: f64,
    pub dimensions: Vec<DimensionScore>,
    /// Epoch ms when computed.
    pub computed_at_ms: u64,
}

/// Input signals from local subsystems.
/// Each field is `Option`-like — missing data uses a conservative default.
#[derive(Debug, Clone, Default)]
pub struct LocalSignals {
    // ── Persona Integrity ──
    pub protected_files_total: usize,
    pub protected_files_intact: usize,
    pub manifest_signature_valid: Option<bool>,
    pub between_session_tampers: usize,

    // ── Chain Integrity ──
    pub chain_verified: Option<bool>,
    pub chain_receipt_count: u64,

    // ── Vault Hygiene ──
    pub vault_scans_total: u64,
    pub vault_leaks_detected: u64,
    pub vault_leaks_redacted: u64,

    // ── Temporal Consistency ──
    /// Receipt timestamps for the scoring window (epoch ms, sorted).
    pub receipt_timestamps: Vec<u64>,

    // ── Contribution Volume ──
    pub receipts_last_24h: u64,
    /// Baseline for "full activity" (default: 100 receipts/day).
    pub volume_baseline: Option<u64>,

    // ── Relay Reliability (placeholder until mesh) ──
    pub relay_forwarded: u64,
    pub relay_failed: u64,
}

impl TrustmarkScore {
    /// Compute the TRUSTMARK score from local signals.
    pub fn compute(signals: &LocalSignals) -> Self {
        let dims = vec![
            Self::score_persona_integrity(signals),
            Self::score_chain_integrity(signals),
            Self::score_vault_hygiene(signals),
            Self::score_temporal_consistency(signals),
            Self::score_relay_reliability(signals),
            Self::score_contribution_volume(signals),
        ];

        let total: f64 = dims.iter().map(|d| d.contribution).sum();
        let total = total.clamp(0.0, 1.0);

        let computed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            total,
            dimensions: dims,
            computed_at_ms,
        }
    }

    fn score_persona_integrity(s: &LocalSignals) -> DimensionScore {
        let (value, reason) = if s.protected_files_total == 0 {
            (0.5, "no protected files configured".into())
        } else if s.between_session_tampers > 0 {
            let penalty = (s.between_session_tampers as f64 * 0.3).min(1.0);
            (
                (1.0 - penalty).max(0.0),
                format!(
                    "{} between-session tamper(s) detected",
                    s.between_session_tampers
                ),
            )
        } else {
            let intact_ratio = s.protected_files_intact as f64 / s.protected_files_total as f64;
            let manifest_adj = match s.manifest_signature_valid {
                Some(true) => 0.0,
                Some(false) => -0.3,
                None => -0.1,
            };
            let value = (intact_ratio + manifest_adj).clamp(0.0, 1.0);
            (
                value,
                format!(
                    "{}/{} files intact, manifest {}",
                    s.protected_files_intact,
                    s.protected_files_total,
                    match s.manifest_signature_valid {
                        Some(true) => "valid",
                        Some(false) => "INVALID",
                        None => "absent",
                    }
                ),
            )
        };

        let formula = if s.between_session_tampers > 0 {
            "1.0 - (tampers × 0.3)".into()
        } else {
            "intact_ratio + manifest_adjustment".into()
        };
        let inputs = format!(
            "{}/{} files intact · manifest {} · {} between-session tampers",
            s.protected_files_intact,
            s.protected_files_total,
            match s.manifest_signature_valid {
                Some(true) => "valid",
                Some(false) => "INVALID",
                None => "absent",
            },
            s.between_session_tampers,
        );
        let improve = if value >= 0.95 {
            String::new()
        } else if s.between_session_tampers > 0 {
            "Investigate between-session tampering. Check barrier alerts. Verify no unauthorized access while Aegis was offline.".into()
        } else if s.manifest_signature_valid.is_none() {
            "Run Aegis once to generate the signed manifest (automatic on first startup).".into()
        } else {
            "Ensure all protected files match their startup hashes. Run: aegis scan".into()
        };
        dim(
            "persona_integrity",
            value,
            WEIGHT_PERSONA_INTEGRITY,
            reason,
            formula,
            inputs,
            improve,
        )
    }

    fn score_chain_integrity(s: &LocalSignals) -> DimensionScore {
        let (value, reason) = match s.chain_verified {
            Some(true) => (
                1.0,
                format!("chain intact ({} receipts)", s.chain_receipt_count),
            ),
            Some(false) => (0.0, "chain verification FAILED".into()),
            None => {
                if s.chain_receipt_count > 0 {
                    (
                        0.7,
                        format!("{} receipts, not yet verified", s.chain_receipt_count),
                    )
                } else {
                    (0.3, "no evidence receipts yet".into())
                }
            }
        };
        let formula = "1.0 if verified, 0.7 if unverified with receipts, 0.0 if broken".into();
        let inputs = format!(
            "{} receipts · verified: {}",
            s.chain_receipt_count,
            match s.chain_verified {
                Some(true) => "yes",
                Some(false) => "FAILED",
                None => "not checked",
            }
        );
        let improve = if value >= 0.95 {
            String::new()
        } else if s.chain_verified == Some(false) {
            "Evidence chain is broken. Run: aegis export --verify to diagnose. May need to restart the chain.".into()
        } else {
            "Start Aegis to begin recording evidence receipts. Chain verifies automatically on startup.".into()
        };
        dim(
            "chain_integrity",
            value,
            WEIGHT_CHAIN_INTEGRITY,
            reason,
            formula,
            inputs,
            improve,
        )
    }

    fn score_vault_hygiene(s: &LocalSignals) -> DimensionScore {
        let (value, reason) = if s.vault_scans_total == 0 {
            (0.5, "no vault scans performed yet".into())
        } else if s.vault_leaks_detected == 0 {
            (1.0, format!("{} scans, 0 leaks", s.vault_scans_total))
        } else {
            let leak_rate = s.vault_leaks_detected as f64 / s.vault_scans_total as f64;
            let redaction_rate = if s.vault_leaks_detected > 0 {
                s.vault_leaks_redacted as f64 / s.vault_leaks_detected as f64
            } else {
                1.0
            };
            let value = ((1.0 - leak_rate) * 0.7 + redaction_rate * 0.3).clamp(0.0, 1.0);
            (
                value,
                format!(
                    "{} leaks in {} scans ({:.1}%), {} redacted",
                    s.vault_leaks_detected,
                    s.vault_scans_total,
                    leak_rate * 100.0,
                    s.vault_leaks_redacted,
                ),
            )
        };
        let formula = "(1 - leak_rate) × 0.7 + redaction_rate × 0.3".into();
        let inputs = format!(
            "{} detections / {} scans · {} redacted",
            s.vault_leaks_detected, s.vault_scans_total, s.vault_leaks_redacted
        );
        let improve = if value >= 0.95 {
            String::new()
        } else if s.vault_leaks_redacted == 0 && s.vault_leaks_detected > 0 {
            "Enable enforce mode (aegis --enforce) to auto-redact credentials. Or add known-safe tokens to [vault] allowlist in config.toml.".into()
        } else {
            "Reduce credential exposure. Check which requests contain API keys or tokens in the Trace tab.".into()
        };
        dim(
            "vault_hygiene",
            value,
            WEIGHT_VAULT_HYGIENE,
            reason,
            formula,
            inputs,
            improve,
        )
    }

    fn score_temporal_consistency(s: &LocalSignals) -> DimensionScore {
        let (value, reason) = if s.receipt_timestamps.len() < 3 {
            (
                0.5,
                format!("only {} timestamps, need 3+", s.receipt_timestamps.len()),
            )
        } else {
            let intervals: Vec<f64> = s
                .receipt_timestamps
                .windows(2)
                .map(|w| (w[1] as f64) - (w[0] as f64))
                .collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean == 0.0 {
                (0.5, "all timestamps identical".into())
            } else {
                let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
                    / intervals.len() as f64;
                let cv = variance.sqrt() / mean;
                let value = (1.0 - (cv - 0.5).max(0.0) / 1.5).clamp(0.2, 1.0);
                (
                    value,
                    format!(
                        "{} intervals, CV={:.2} ({})",
                        intervals.len(),
                        cv,
                        if cv < 0.5 {
                            "very consistent"
                        } else if cv < 1.0 {
                            "consistent"
                        } else if cv < 2.0 {
                            "somewhat bursty"
                        } else {
                            "very bursty"
                        }
                    ),
                )
            }
        };
        let formula =
            "1.0 - clamp((CV - 0.5) / 1.5, 0, 0.8) where CV = stddev/mean of intervals".into();
        let inputs = format!(
            "{} receipt timestamps in scoring window",
            s.receipt_timestamps.len()
        );
        let improve = if value >= 0.95 {
            String::new()
        } else if s.receipt_timestamps.len() < 3 {
            "Send more traffic through Aegis. Need at least 3 requests for temporal scoring.".into()
        } else {
            "Traffic is bursty. Consistent request patterns (e.g. regular cron, steady usage) improve this score.".into()
        };
        dim(
            "temporal_consistency",
            value,
            WEIGHT_TEMPORAL_CONSISTENCY,
            reason,
            formula,
            inputs,
            improve,
        )
    }

    fn score_relay_reliability(s: &LocalSignals) -> DimensionScore {
        let total = s.relay_forwarded + s.relay_failed;
        let is_estimated = total == 0; // No real signal source until mesh is implemented
        let (value, reason) = if total == 0 {
            (0.5, "mesh relay not active — estimated".into())
        } else {
            let rate = s.relay_forwarded as f64 / total as f64;
            (
                rate,
                format!(
                    "{}/{} relayed ({:.0}%)",
                    s.relay_forwarded,
                    total,
                    rate * 100.0
                ),
            )
        };
        let formula = "forwarded / (forwarded + failed), default 0.5 if inactive".into();
        let inputs = format!("{} forwarded, {} failed", s.relay_forwarded, s.relay_failed);
        let improve = if total > 0 && value < 0.95 {
            "Investigate relay failures. Check mesh connectivity.".into()
        } else {
            "Mesh relay activates in Tier 3. Default score 0.5 until then.".into()
        };
        let mut d = dim(
            "relay_reliability",
            value,
            WEIGHT_RELAY_RELIABILITY,
            reason,
            formula,
            inputs,
            improve,
        );
        d.estimated = is_estimated;
        d
    }

    fn score_contribution_volume(s: &LocalSignals) -> DimensionScore {
        let baseline = s.volume_baseline.unwrap_or(100);
        let is_estimated = s.volume_baseline.is_none();
        let (value, reason) = if baseline == 0 {
            (0.5, "no baseline configured — estimated".into())
        } else {
            let ratio = (s.receipts_last_24h as f64 / baseline as f64).min(1.0);
            (
                ratio,
                format!(
                    "{} receipts in 24h (baseline: {})",
                    s.receipts_last_24h, baseline
                ),
            )
        };
        let formula = "min(receipts_24h / baseline, 1.0)".into();
        let inputs = format!(
            "{} receipts in 24h, baseline: {}",
            s.receipts_last_24h, baseline
        );
        let improve = if value >= 0.95 {
            String::new()
        } else {
            format!(
                "Route more traffic through Aegis. Any channel counts. Need {} receipts/day for full score.",
                baseline
            )
        };
        let mut d = dim(
            "contribution_volume",
            value,
            WEIGHT_CONTRIBUTION_VOLUME,
            reason,
            formula,
            inputs,
            improve,
        );
        d.estimated = is_estimated;
        d
    }
}

impl TrustmarkScore {
    /// Convert the internal f64-based score to the schema type
    /// (`aegis_schemas::TrustmarkScore`) which uses validated `BasisPoints`.
    ///
    /// All float values are converted by multiplying by 10000 and clamping
    /// to [0, 10000]. This is the ONLY safe path from internal scoring to
    /// wire/signed data.
    pub fn to_schema_score(&self) -> aegis_schemas::TrustmarkScore {
        let to_bp = |v: f64| aegis_schemas::BasisPoints::clamped((v * 10_000.0).round() as u32);

        // Extract dimension values by name
        let dim_val = |name: &str| -> f64 {
            self.dimensions
                .iter()
                .find(|d| d.name == name)
                .map(|d| d.value)
                .unwrap_or(0.0)
        };

        let dimensions = aegis_schemas::trustmark::TrustmarkDimensions {
            relay_reliability: to_bp(dim_val("relay_reliability")),
            persona_integrity: to_bp(dim_val("persona_integrity")),
            chain_integrity: to_bp(dim_val("chain_integrity")),
            contribution_volume: to_bp(dim_val("contribution_volume")),
            temporal_consistency: to_bp(dim_val("temporal_consistency")),
            vault_hygiene: to_bp(dim_val("vault_hygiene")),
        };

        let tier = if self.total >= 0.40 {
            aegis_schemas::trustmark::Tier::Tier3
        } else if self.total >= 0.20 {
            aegis_schemas::trustmark::Tier::Tier2
        } else {
            aegis_schemas::trustmark::Tier::Tier1
        };

        aegis_schemas::TrustmarkScore {
            score_bp: to_bp(self.total),
            dimensions,
            tier,
            computed_at_ms: self.computed_at_ms as i64,
        }
    }
}

/// Target thresholds per dimension.
fn target_for(name: &str) -> f64 {
    match name {
        "persona_integrity" => 0.95,    // all files intact + valid manifest
        "chain_integrity" => 0.95,      // chain verified
        "vault_hygiene" => 0.90,        // < 3% leak rate or credentials redacted
        "temporal_consistency" => 0.80, // regular traffic pattern (CV < 1.0)
        "relay_reliability" => 0.50,    // placeholder until mesh
        "contribution_volume" => 0.50,  // at least half the baseline
        _ => 0.80,
    }
}

fn status_label(value: f64, target: f64) -> String {
    if value >= target {
        "healthy".into()
    } else if value >= target * 0.6 {
        "attention".into()
    } else {
        "critical".into()
    }
}

fn dim(
    name: &str,
    value: f64,
    weight: f64,
    reason: String,
    formula: String,
    inputs: String,
    improve: String,
) -> DimensionScore {
    let target = target_for(name);
    let status = status_label(value, target);
    DimensionScore {
        name: name.to_string(),
        value,
        weight,
        contribution: value * weight,
        reason,
        formula,
        inputs,
        improve,
        target,
        status,
        estimated: false,
    }
}

// ═══════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_install_moderate_score() {
        let score = TrustmarkScore::compute(&LocalSignals::default());
        assert!(
            score.total > 0.3 && score.total < 0.7,
            "fresh install should be moderate: {}",
            score.total
        );
        assert_eq!(score.dimensions.len(), 6);
    }

    #[test]
    fn perfect_signals_high_score() {
        let signals = LocalSignals {
            protected_files_total: 9,
            protected_files_intact: 9,
            manifest_signature_valid: Some(true),
            between_session_tampers: 0,
            chain_verified: Some(true),
            chain_receipt_count: 10000,
            vault_scans_total: 500,
            vault_leaks_detected: 0,
            vault_leaks_redacted: 0,
            receipt_timestamps: (0..288).map(|i| i * 300_000).collect(),
            receipts_last_24h: 288,
            volume_baseline: Some(100),
            relay_forwarded: 100,
            relay_failed: 0,
        };
        let score = TrustmarkScore::compute(&signals);
        assert!(
            score.total > 0.90,
            "perfect should be > 0.90: {}",
            score.total
        );
    }

    #[test]
    fn terrible_signals_low_score() {
        let signals = LocalSignals {
            protected_files_total: 9,
            protected_files_intact: 3,
            manifest_signature_valid: Some(false),
            between_session_tampers: 5,
            chain_verified: Some(false),
            chain_receipt_count: 10,
            vault_scans_total: 100,
            vault_leaks_detected: 50,
            vault_leaks_redacted: 10,
            receipt_timestamps: vec![1000, 2000, 100_000_000],
            receipts_last_24h: 3,
            volume_baseline: Some(100),
            relay_forwarded: 10,
            relay_failed: 90,
        };
        let score = TrustmarkScore::compute(&signals);
        assert!(
            score.total < 0.25,
            "terrible should be < 0.25: {}",
            score.total
        );
    }

    #[test]
    fn persona_all_intact_is_1() {
        let s = LocalSignals {
            protected_files_total: 9,
            protected_files_intact: 9,
            manifest_signature_valid: Some(true),
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!((score.dimensions[0].value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn persona_between_session_tamper_drops() {
        let s = LocalSignals {
            protected_files_total: 9,
            protected_files_intact: 9,
            manifest_signature_valid: Some(true),
            between_session_tampers: 2,
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!(score.dimensions[0].value < 0.5);
    }

    #[test]
    fn chain_verified_is_1() {
        let s = LocalSignals {
            chain_verified: Some(true),
            chain_receipt_count: 5000,
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!((score.dimensions[1].value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn chain_broken_is_0() {
        let s = LocalSignals {
            chain_verified: Some(false),
            chain_receipt_count: 5000,
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!((score.dimensions[1].value - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn vault_no_leaks_is_1() {
        let s = LocalSignals {
            vault_scans_total: 1000,
            vault_leaks_detected: 0,
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!((score.dimensions[2].value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn vault_leaks_with_redaction() {
        let s = LocalSignals {
            vault_scans_total: 100,
            vault_leaks_detected: 10,
            vault_leaks_redacted: 8,
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!(score.dimensions[2].value > 0.5 && score.dimensions[2].value < 1.0);
    }

    #[test]
    fn temporal_regular_is_high() {
        let s = LocalSignals {
            receipt_timestamps: (0..100).map(|i| i * 60_000).collect(),
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!(
            score.dimensions[3].value > 0.9,
            "{}",
            score.dimensions[3].value
        );
    }

    #[test]
    fn temporal_bursty_is_low() {
        let s = LocalSignals {
            receipt_timestamps: vec![1000, 1001, 1002, 1003, 100_000_000, 100_000_001],
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!(score.dimensions[3].value < 0.5);
    }

    #[test]
    fn temporal_too_few_is_default() {
        let s = LocalSignals {
            receipt_timestamps: vec![1000, 2000],
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!((score.dimensions[3].value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_not_active_is_default() {
        let score = TrustmarkScore::compute(&LocalSignals::default());
        assert!((score.dimensions[4].value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn volume_above_baseline_caps_at_1() {
        let s = LocalSignals {
            receipts_last_24h: 200,
            volume_baseline: Some(100),
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!((score.dimensions[5].value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn volume_half_baseline() {
        let s = LocalSignals {
            receipts_last_24h: 50,
            volume_baseline: Some(100),
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&s);
        assert!((score.dimensions[5].value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn weights_sum_to_one() {
        let sum = WEIGHT_PERSONA_INTEGRITY
            + WEIGHT_CHAIN_INTEGRITY
            + WEIGHT_VAULT_HYGIENE
            + WEIGHT_TEMPORAL_CONSISTENCY
            + WEIGHT_RELAY_RELIABILITY
            + WEIGHT_CONTRIBUTION_VOLUME;
        assert!((sum - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn to_schema_score_clamps_and_converts() {
        let signals = LocalSignals {
            protected_files_total: 9,
            protected_files_intact: 9,
            manifest_signature_valid: Some(true),
            between_session_tampers: 0,
            chain_verified: Some(true),
            chain_receipt_count: 10000,
            vault_scans_total: 500,
            vault_leaks_detected: 0,
            vault_leaks_redacted: 0,
            receipt_timestamps: (0..288).map(|i| i * 300_000).collect(),
            receipts_last_24h: 288,
            volume_baseline: Some(100),
            relay_forwarded: 100,
            relay_failed: 0,
        };
        let internal = TrustmarkScore::compute(&signals);
        let schema = internal.to_schema_score();

        // All BasisPoints values must be in [0, 10000]
        assert!(schema.score_bp.value() <= 10000);
        assert!(schema.dimensions.persona_integrity.value() <= 10000);
        assert!(schema.dimensions.chain_integrity.value() <= 10000);
        assert!(schema.dimensions.vault_hygiene.value() <= 10000);
        assert!(schema.dimensions.temporal_consistency.value() <= 10000);
        assert!(schema.dimensions.relay_reliability.value() <= 10000);
        assert!(schema.dimensions.contribution_volume.value() <= 10000);

        // Perfect signals should produce a high score
        assert!(schema.score_bp.value() > 9000, "perfect signals should yield >9000bp, got {}", schema.score_bp.value());
    }

    #[test]
    fn to_schema_score_fresh_install() {
        let internal = TrustmarkScore::compute(&LocalSignals::default());
        let schema = internal.to_schema_score();
        // Fresh install should have moderate score
        assert!(schema.score_bp.value() > 3000 && schema.score_bp.value() < 7000);
    }

    #[test]
    fn score_is_serializable() {
        let score = TrustmarkScore::compute(&LocalSignals::default());
        let json = serde_json::to_string_pretty(&score).unwrap();
        assert!(json.contains("persona_integrity"));
        let rt: TrustmarkScore = serde_json::from_str(&json).unwrap();
        assert!((rt.total - score.total).abs() < f64::EPSILON);
    }
}
