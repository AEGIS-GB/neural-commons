//! Tier classification (D14) — gates access based on TRUSTMARK score + requirements.

use serde::{Deserialize, Serialize};

/// Trust tiers (D14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// Any installed adapter. Full local protection.
    Tier1,
    /// Identity activated + 72h evidence + vault active.
    Tier2,
    /// TRUSTMARK >= 0.4 + evaluator admission.
    Tier3,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Tier1 => write!(f, "Tier 1"),
            Tier::Tier2 => write!(f, "Tier 2"),
            Tier::Tier3 => write!(f, "Tier 3"),
        }
    }
}

/// Requirements status for tier advancement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierStatus {
    pub current: Tier,
    pub trustmark_score: f64,
    /// Age of identity key in hours.
    pub identity_age_hours: f64,
    /// Whether vault scanning is active.
    pub vault_active: bool,
    /// Whether the evidence chain is intact.
    pub chain_intact: bool,
    /// Number of evaluator vouches received (for Tier 3).
    pub evaluator_vouches: usize,
    /// What's needed for the next tier.
    pub next_tier_requirements: Vec<String>,
}

/// Resolve the current tier from local state.
pub fn resolve_tier(
    trustmark_score: f64,
    identity_age_hours: f64,
    vault_active: bool,
    chain_intact: bool,
    evaluator_vouches: usize,
) -> TierStatus {
    let mut missing = Vec::new();

    // Tier 3 check
    let is_tier3 = trustmark_score >= 0.4
        && identity_age_hours >= 72.0
        && vault_active
        && chain_intact
        && evaluator_vouches >= 2;

    // Tier 2 check
    let is_tier2 = identity_age_hours >= 72.0 && vault_active && chain_intact;

    let current = if is_tier3 {
        Tier::Tier3
    } else if is_tier2 {
        // Show what's needed for Tier 3
        if trustmark_score < 0.4 {
            missing.push(format!("TRUSTMARK score {:.2} < 0.40 required", trustmark_score));
        }
        if evaluator_vouches < 2 {
            missing.push(format!("{}/2 evaluator vouches", evaluator_vouches));
        }
        Tier::Tier2
    } else {
        // Show what's needed for Tier 2
        if identity_age_hours < 72.0 {
            missing.push(format!("identity age {:.0}h < 72h required", identity_age_hours));
        }
        if !vault_active {
            missing.push("vault scanning not active".into());
        }
        if !chain_intact {
            missing.push("evidence chain not intact".into());
        }
        Tier::Tier1
    };

    TierStatus {
        current,
        trustmark_score,
        identity_age_hours,
        vault_active,
        chain_intact,
        evaluator_vouches,
        next_tier_requirements: missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_install_is_tier1() {
        let s = resolve_tier(0.45, 1.0, false, false, 0);
        assert_eq!(s.current, Tier::Tier1);
        assert!(!s.next_tier_requirements.is_empty());
    }

    #[test]
    fn after_72h_with_vault_is_tier2() {
        let s = resolve_tier(0.35, 100.0, true, true, 0);
        assert_eq!(s.current, Tier::Tier2);
    }

    #[test]
    fn tier2_shows_tier3_requirements() {
        let s = resolve_tier(0.35, 100.0, true, true, 1);
        assert_eq!(s.current, Tier::Tier2);
        assert!(s.next_tier_requirements.iter().any(|r| r.contains("TRUSTMARK")));
        assert!(s.next_tier_requirements.iter().any(|r| r.contains("vouches")));
    }

    #[test]
    fn high_score_with_vouches_is_tier3() {
        let s = resolve_tier(0.5, 200.0, true, true, 3);
        assert_eq!(s.current, Tier::Tier3);
        assert!(s.next_tier_requirements.is_empty());
    }

    #[test]
    fn broken_chain_stays_tier1() {
        let s = resolve_tier(0.8, 200.0, true, false, 5);
        assert_eq!(s.current, Tier::Tier1);
    }

    #[test]
    fn no_vault_stays_tier1() {
        let s = resolve_tier(0.8, 200.0, false, true, 5);
        assert_eq!(s.current, Tier::Tier1);
    }

    #[test]
    fn tier_display() {
        assert_eq!(format!("{}", Tier::Tier1), "Tier 1");
        assert_eq!(format!("{}", Tier::Tier3), "Tier 3");
    }
}
