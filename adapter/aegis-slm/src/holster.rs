//! SLM Holster — applies warden-local policy to enriched analysis.
//!
//! Three presets (D8):
//!   Aggressive: reject > 6000bp
//!   Balanced: reject > 8000bp (default)
//!   Permissive: reject > 9000bp
//!
//! Per-namespace overrides allowed.
//! effective_threshold is FORBIDDEN in any outbound structure (leaks coefficients).

use crate::types::*;

/// Map a trust level to the appropriate holster profile.
/// Higher trust → more permissive thresholds.
/// Unknown maps to Balanced for backward compatibility (no cert = same as before).
///
/// When `trustmark_degraded` is true, Permissive is downgraded to Balanced
/// (TRUSTMARK health check — tightens holster when the node's trust score is low).
pub fn trust_to_profile(
    trust: &aegis_schemas::TrustLevel,
    trustmark_degraded: bool,
) -> HolsterProfile {
    let base = match trust {
        aegis_schemas::TrustLevel::Full => HolsterProfile::Permissive,
        aegis_schemas::TrustLevel::Trusted => HolsterProfile::Balanced,
        aegis_schemas::TrustLevel::Public => HolsterProfile::Aggressive,
        aegis_schemas::TrustLevel::Restricted => HolsterProfile::Aggressive,
        aegis_schemas::TrustLevel::Unknown => HolsterProfile::Balanced, // backward compat
    };

    if trustmark_degraded && base == HolsterProfile::Permissive {
        HolsterProfile::Balanced
    } else {
        base
    }
}

/// Apply holster policy to an enriched analysis.
/// Returns a HolsterDecision.
///
/// `custom_threshold` is used when `profile` is `Custom`. If `None`,
/// defaults to 8000 for backward compatibility.
pub fn apply_holster(
    analysis: &EnrichedAnalysis,
    profile: &HolsterProfile,
    namespace: &Namespace,
    engine: &EngineProfile,
    escalated: bool,
) -> HolsterDecision {
    apply_holster_with_custom(analysis, profile, namespace, engine, escalated, None)
}

/// Apply holster policy with an optional custom threshold.
///
/// When `profile` is `HolsterProfile::Custom`, uses `custom_threshold`
/// if provided, otherwise defaults to 8000 for backward compatibility.
pub fn apply_holster_with_custom(
    analysis: &EnrichedAnalysis,
    profile: &HolsterProfile,
    namespace: &Namespace,
    engine: &EngineProfile,
    escalated: bool,
    custom_threshold: Option<u32>,
) -> HolsterDecision {
    let threshold = match profile {
        HolsterProfile::Aggressive => 6000,
        HolsterProfile::Balanced => 8000,
        HolsterProfile::Permissive => 9000,
        HolsterProfile::Custom => custom_threshold.unwrap_or(8000),
    };

    let threshold_exceeded = analysis.threat_score > threshold;

    let action = if analysis.threat_score == 0 {
        HolsterAction::Admit
    } else if threshold_exceeded {
        HolsterAction::Reject
    } else {
        HolsterAction::Quarantine
    };

    // Compute cost
    let mut cost = engine.base_compute_cost_bp();
    if escalated {
        cost += 200;
    }

    HolsterDecision {
        holster_profile: profile.clone(),
        namespace: namespace.clone(),
        engine_profile: engine.clone(),
        action,
        threshold_exceeded,
        escalated,
        hil_required: false, // TODO: determine based on severity + namespace
        hil_outcome: None,
        peer_leverage: None,
        compute_cost_bp: cost,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balanced_admits_below_threshold() {
        let analysis = EnrichedAnalysis {
            schema_version: 2,
            scoring_version: 1,
            confidence: 9000,
            intent: Intent::Probe,
            threat_score: 5000,
            dimensions: ThreatDimensions::default(),
            annotations: vec![],
            explanation: "test".to_string(),
        };

        let decision = apply_holster(
            &analysis,
            &HolsterProfile::Balanced,
            &Namespace::Inbound,
            &EngineProfile::LocalSlm,
            false,
        );

        assert_eq!(decision.action, HolsterAction::Quarantine);
        assert!(!decision.threshold_exceeded);
        assert_eq!(decision.compute_cost_bp, 100);
    }

    #[test]
    fn test_balanced_rejects_above_threshold() {
        let analysis = EnrichedAnalysis {
            schema_version: 2,
            scoring_version: 1,
            confidence: 9100,
            intent: Intent::Inject,
            threat_score: 8500,
            dimensions: ThreatDimensions {
                injection: 8500,
                ..Default::default()
            },
            annotations: vec![],
            explanation: "test".to_string(),
        };

        let decision = apply_holster(
            &analysis,
            &HolsterProfile::Balanced,
            &Namespace::Inbound,
            &EngineProfile::Loopback,
            false,
        );

        assert_eq!(decision.action, HolsterAction::Reject);
        assert!(decision.threshold_exceeded);
    }

    #[test]
    fn test_benign_admitted() {
        let analysis = EnrichedAnalysis {
            schema_version: 2,
            scoring_version: 1,
            confidence: 9500,
            intent: Intent::Benign,
            threat_score: 0,
            dimensions: ThreatDimensions::default(),
            annotations: vec![],
            explanation: "Benign".to_string(),
        };

        let decision = apply_holster(
            &analysis,
            &HolsterProfile::Balanced,
            &Namespace::Inbound,
            &EngineProfile::LocalSlm,
            false,
        );

        assert_eq!(decision.action, HolsterAction::Admit);
    }

    #[test]
    fn test_escalated_adds_cost() {
        let analysis = EnrichedAnalysis {
            schema_version: 2,
            scoring_version: 1,
            confidence: 9000,
            intent: Intent::Probe,
            threat_score: 5000,
            dimensions: ThreatDimensions::default(),
            annotations: vec![],
            explanation: "test".to_string(),
        };

        let decision = apply_holster(
            &analysis,
            &HolsterProfile::Balanced,
            &Namespace::Inbound,
            &EngineProfile::LocalSlm,
            true, // escalated
        );

        assert_eq!(decision.compute_cost_bp, 300); // 100 + 200
    }

    #[test]
    fn test_custom_profile_uses_configured_threshold() {
        let analysis = EnrichedAnalysis {
            schema_version: 2,
            scoring_version: 1,
            confidence: 9000,
            intent: Intent::Inject,
            threat_score: 7500,
            dimensions: ThreatDimensions::default(),
            annotations: vec![],
            explanation: "test".to_string(),
        };

        // With custom threshold of 7000, 7500 should exceed → Reject
        let decision = apply_holster_with_custom(
            &analysis,
            &HolsterProfile::Custom,
            &Namespace::Inbound,
            &EngineProfile::LocalSlm,
            false,
            Some(7000),
        );
        assert_eq!(decision.action, HolsterAction::Reject);
        assert!(decision.threshold_exceeded);

        // With custom threshold of 8000 (default), 7500 should not exceed → Quarantine
        let decision = apply_holster_with_custom(
            &analysis,
            &HolsterProfile::Custom,
            &Namespace::Inbound,
            &EngineProfile::LocalSlm,
            false,
            Some(8000),
        );
        assert_eq!(decision.action, HolsterAction::Quarantine);
        assert!(!decision.threshold_exceeded);

        // With no custom threshold, defaults to 8000 → Quarantine
        let decision = apply_holster_with_custom(
            &analysis,
            &HolsterProfile::Custom,
            &Namespace::Inbound,
            &EngineProfile::LocalSlm,
            false,
            None,
        );
        assert_eq!(decision.action, HolsterAction::Quarantine);
        assert!(!decision.threshold_exceeded);
    }

    #[test]
    fn trust_full_maps_to_permissive() {
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Full, false),
            HolsterProfile::Permissive
        );
    }

    #[test]
    fn trust_trusted_maps_to_balanced() {
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Trusted, false),
            HolsterProfile::Balanced
        );
    }

    #[test]
    fn trust_public_maps_to_aggressive() {
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Public, false),
            HolsterProfile::Aggressive
        );
    }

    #[test]
    fn trust_restricted_maps_to_aggressive() {
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Restricted, false),
            HolsterProfile::Aggressive
        );
    }

    #[test]
    fn trust_unknown_maps_to_balanced() {
        // Backward compat: no cert = same as before
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Unknown, false),
            HolsterProfile::Balanced
        );
    }

    #[test]
    fn holster_tightens_on_low_trustmark() {
        // Without degradation: Full → Permissive
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Full, false),
            HolsterProfile::Permissive
        );
        // With degradation: Full → Balanced (tightened)
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Full, true),
            HolsterProfile::Balanced
        );
        // Balanced stays Balanced even when degraded
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Trusted, true),
            HolsterProfile::Balanced
        );
        // Aggressive stays Aggressive even when degraded
        assert_eq!(
            trust_to_profile(&aegis_schemas::TrustLevel::Public, true),
            HolsterProfile::Aggressive
        );
    }
}
