//! Score persistence — store and retrieve TRUSTMARK score snapshots.
//!
//! Scores are stored as TrustmarkUpdate receipts in the evidence chain.
//! The receipt context.action contains "trustmark_snapshot" and
//! context.outcome contains the JSON-serialized score.

use std::path::Path;

use crate::scoring::TrustmarkScore;

/// Record a TRUSTMARK score snapshot as an evidence receipt.
pub fn record_snapshot(
    recorder: &aegis_evidence::EvidenceRecorder,
    score: &TrustmarkScore,
) -> Result<(), String> {
    let score_json =
        serde_json::to_string(score).map_err(|e| format!("failed to serialize score: {e}"))?;

    recorder
        .record_simple(
            aegis_schemas::ReceiptType::TrustmarkUpdate,
            "trustmark_snapshot",
            &score_json,
        )
        .map_err(|e| format!("failed to record trustmark snapshot: {e}"))?;

    Ok(())
}

/// Load the most recent TRUSTMARK score snapshot from the evidence chain.
/// Returns None if no snapshots exist.
pub fn load_latest_snapshot(data_dir: &Path) -> Option<TrustmarkScore> {
    let db_path = data_dir.join("evidence.db");
    let store = aegis_evidence::EvidenceStore::open(&db_path).ok()?;
    let chain = store.get_chain_state().ok()?;

    if chain.receipt_count == 0 {
        return None;
    }

    // Scan backwards from the end to find the latest TrustmarkUpdate
    let batch_size: u64 = 100;
    let mut end = chain.receipt_count;

    while end > 0 {
        let start = end.saturating_sub(batch_size).max(1);
        let receipts = store.get_receipts_range(start, end).ok()?;

        // Search backwards
        for receipt in receipts.iter().rev() {
            if receipt.core.receipt_type == aegis_schemas::ReceiptType::TrustmarkUpdate {
                let outcome = receipt.context.outcome.as_deref()?;
                let score: TrustmarkScore = serde_json::from_str(outcome).ok()?;
                return Some(score);
            }
        }

        if start <= 1 {
            break;
        }
        end = start - 1;
    }

    None
}

/// Load all TRUSTMARK score snapshots from the evidence chain.
/// Returns them in chronological order (oldest first).
pub fn load_history(data_dir: &Path, limit: usize) -> Vec<TrustmarkScore> {
    let db_path = data_dir.join("evidence.db");
    let store = match aegis_evidence::EvidenceStore::open(&db_path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let chain = match store.get_chain_state() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    if chain.receipt_count == 0 {
        return Vec::new();
    }

    let mut scores = Vec::new();
    let batch_size: u64 = 500;
    let mut seq: u64 = 1;

    while seq <= chain.receipt_count {
        let end = (seq + batch_size - 1).min(chain.receipt_count);
        let receipts = match store.get_receipts_range(seq, end) {
            Ok(r) => r,
            Err(_) => break,
        };

        for receipt in &receipts {
            if receipt.core.receipt_type == aegis_schemas::ReceiptType::TrustmarkUpdate
                && let Some(outcome) = receipt.context.outcome.as_deref()
                && let Ok(score) = serde_json::from_str::<TrustmarkScore>(outcome)
            {
                scores.push(score);
            }
        }

        seq = end + 1;
    }

    // Keep only the last `limit` entries
    if scores.len() > limit {
        scores = scores.split_off(scores.len() - limit);
    }

    scores
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_recorder(dir: &Path) -> aegis_evidence::EvidenceRecorder {
        let key = aegis_crypto::ed25519::generate_keypair();
        aegis_evidence::EvidenceRecorder::new(&dir.join("evidence.db"), key).unwrap()
    }

    #[test]
    fn record_and_load_latest() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = test_recorder(dir.path());

        // No snapshots yet
        assert!(load_latest_snapshot(dir.path()).is_none());

        // Record a score
        let signals = crate::scoring::LocalSignals {
            protected_files_total: 9,
            protected_files_intact: 9,
            manifest_signature_valid: Some(true),
            chain_verified: Some(true),
            chain_receipt_count: 100,
            ..Default::default()
        };
        let score = TrustmarkScore::compute(&signals);
        record_snapshot(&recorder, &score).unwrap();

        // Load it back
        let loaded = load_latest_snapshot(dir.path()).unwrap();
        assert!((loaded.total - score.total).abs() < f64::EPSILON);
        assert_eq!(loaded.dimensions.len(), 6);
    }

    #[test]
    fn latest_returns_most_recent() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = test_recorder(dir.path());

        // Record two snapshots with different scores
        let s1 = TrustmarkScore::compute(&crate::scoring::LocalSignals::default());
        record_snapshot(&recorder, &s1).unwrap();

        let s2 = TrustmarkScore::compute(&crate::scoring::LocalSignals {
            protected_files_total: 9,
            protected_files_intact: 9,
            manifest_signature_valid: Some(true),
            chain_verified: Some(true),
            chain_receipt_count: 5000,
            vault_scans_total: 500,
            ..Default::default()
        });
        record_snapshot(&recorder, &s2).unwrap();

        let latest = load_latest_snapshot(dir.path()).unwrap();
        assert!(
            (latest.total - s2.total).abs() < f64::EPSILON,
            "should return most recent: {} vs {}",
            latest.total,
            s2.total
        );
    }

    #[test]
    fn load_history_chronological() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = test_recorder(dir.path());

        for i in 0..5 {
            let signals = crate::scoring::LocalSignals {
                receipts_last_24h: i * 20,
                volume_baseline: Some(100),
                ..Default::default()
            };
            let score = TrustmarkScore::compute(&signals);
            record_snapshot(&recorder, &score).unwrap();
        }

        let history = load_history(dir.path(), 100);
        assert_eq!(history.len(), 5);
        // Chronological — contribution_volume should increase
        for w in history.windows(2) {
            let vol0 = w[0]
                .dimensions
                .iter()
                .find(|d| d.name == "contribution_volume")
                .unwrap()
                .value;
            let vol1 = w[1]
                .dimensions
                .iter()
                .find(|d| d.name == "contribution_volume")
                .unwrap()
                .value;
            assert!(vol1 >= vol0, "history should be chronological");
        }
    }

    #[test]
    fn load_history_respects_limit() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = test_recorder(dir.path());

        for _ in 0..10 {
            let score = TrustmarkScore::compute(&crate::scoring::LocalSignals::default());
            record_snapshot(&recorder, &score).unwrap();
        }

        let history = load_history(dir.path(), 3);
        assert_eq!(history.len(), 3, "should respect limit");
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_latest_snapshot(dir.path()).is_none());
        assert!(load_history(dir.path(), 100).is_empty());
    }

    #[test]
    fn non_trustmark_receipts_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = test_recorder(dir.path());

        // Add non-trustmark receipts
        for _ in 0..5 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::ApiCall, "forward", "200")
                .unwrap();
        }

        assert!(load_latest_snapshot(dir.path()).is_none());
        assert!(load_history(dir.path(), 100).is_empty());
    }
}
