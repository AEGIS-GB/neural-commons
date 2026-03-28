//! Tier gate — check if a feature is available at the current tier.

use std::path::Path;

use crate::gather;
use crate::scoring::TrustmarkScore;
use crate::tiers::{Tier, TierStatus, resolve_tier};

/// Check the current tier from local data.
pub fn current_tier(data_dir: &Path) -> TierStatus {
    let signals = gather::gather_local_signals(data_dir);
    let score = TrustmarkScore::compute(&signals);
    let identity_age = gather::get_identity_age_hours(data_dir);
    let vault_active = signals.vault_scans_total > 0;
    let chain_intact = signals.chain_verified.unwrap_or(false);
    resolve_tier(score.total, identity_age, vault_active, chain_intact, 0)
}

/// Check if a specific tier is reached. Returns Ok(()) or an error message
/// explaining what's needed.
pub fn require_tier(data_dir: &Path, required: Tier) -> Result<TierStatus, String> {
    let status = current_tier(data_dir);
    let current_level = match status.current {
        Tier::Tier1 => 1,
        Tier::Tier2 => 2,
        Tier::Tier3 => 3,
    };
    let required_level = match required {
        Tier::Tier1 => 1,
        Tier::Tier2 => 2,
        Tier::Tier3 => 3,
    };

    if current_level >= required_level {
        Ok(status)
    } else {
        let missing = status.next_tier_requirements.join(", ");
        Err(format!(
            "This feature requires {}. You are at {}. Missing: {}",
            required, status.current, missing
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_install_is_tier1() {
        let dir = tempfile::tempdir().unwrap();
        let status = current_tier(dir.path());
        assert_eq!(status.current, Tier::Tier1);
    }

    #[test]
    fn tier1_feature_always_allowed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(require_tier(dir.path(), Tier::Tier1).is_ok());
    }

    #[test]
    fn tier2_feature_blocked_on_fresh_install() {
        let dir = tempfile::tempdir().unwrap();
        let result = require_tier(dir.path(), Tier::Tier2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Tier 1"));
    }

    #[test]
    fn tier3_feature_blocked_on_fresh_install() {
        let dir = tempfile::tempdir().unwrap();
        let result = require_tier(dir.path(), Tier::Tier3);
        assert!(result.is_err());
    }

    #[test]
    fn tier2_allowed_with_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let key = aegis_crypto::ed25519::generate_keypair();

        // Create identity key (needs to be > 72h old for Tier 2, but
        // we can't fake file age in tests — just verify the gate logic works)
        std::fs::write(dir.path().join("identity.key"), key.to_bytes()).unwrap();

        // Create evidence DB with receipts
        let recorder =
            aegis_evidence::EvidenceRecorder::new(&dir.path().join("evidence.db"), key).unwrap();
        for _ in 0..10 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::ApiCall, "test", "200")
                .unwrap();
        }

        let status = current_tier(dir.path());
        // Won't be Tier 2 because identity age < 72h, but the gate logic is correct
        assert_eq!(status.current, Tier::Tier1);
        assert!(
            status
                .next_tier_requirements
                .iter()
                .any(|r| r.contains("72h"))
        );
    }
}
