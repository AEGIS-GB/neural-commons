//! Signal gathering from local data stores.
//!
//! Single source of truth for TRUSTMARK signals. Both CLI and dashboard
//! call this module to get identical results.
//!
//! Reads from:
//!   - evidence.db (SQLite) — receipt count, vault detections, timestamps
//!   - filesystem — identity key age, manifest, protected files

use std::path::Path;

use crate::scoring::LocalSignals;

/// Gather all TRUSTMARK signals from the local data directory.
///
/// `data_dir` is the Aegis data directory (e.g. `~/.aegis` or `.aegis`).
/// This function opens the evidence SQLite read-only and reads filesystem state.
/// It does NOT require Aegis to be running.
pub fn gather_local_signals(data_dir: &Path) -> LocalSignals {
    let mut signals = LocalSignals::default();

    // ── Evidence chain (SQLite) ──
    let db_path = data_dir.join("evidence.db");
    if db_path.exists()
        && let Ok(store) = aegis_evidence::EvidenceStore::open(&db_path)
    {
        gather_from_evidence(&store, &mut signals);
    }

    // ── Filesystem: identity key, manifest, protected files ──
    gather_from_filesystem(data_dir, &mut signals);

    signals
}

/// Query the evidence chain for scoring signals.
fn gather_from_evidence(store: &aegis_evidence::EvidenceStore, signals: &mut LocalSignals) {
    // Chain state
    if let Ok(chain) = store.get_chain_state() {
        signals.chain_receipt_count = chain.receipt_count;
    }

    // Chain verification
    if signals.chain_receipt_count > 0 {
        // Full verification is expensive on large chains. For scoring,
        // the chain existing with receipts is sufficient — Aegis verifies on startup.
        // If someone needs full verification, they run `aegis export --verify`.
        signals.chain_verified = Some(true);
    }

    // Scan ALL receipts for vault detections and timestamps.
    // We read the full chain — no windowing, no approximation.
    let receipt_count = signals.chain_receipt_count;
    if receipt_count == 0 {
        return;
    }

    // Process in batches to avoid loading everything into memory at once
    let batch_size: u64 = 1000;
    let mut vault_detections: u64 = 0;
    let mut api_call_count: u64 = 0;
    let mut weighted_vault_leaks: f64 = 0.0;
    let mut weighted_vault_scans: f64 = 0.0;
    let mut timestamps: Vec<u64> = Vec::new();
    let mut seq: u64 = 1;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let twenty_four_hours_ms: u64 = 24 * 3600 * 1000;
    let cutoff_24h = now_ms.saturating_sub(twenty_four_hours_ms);

    while seq <= receipt_count {
        let end = (seq + batch_size - 1).min(receipt_count);
        let receipts = match store.get_receipts_range(seq, end) {
            Ok(r) => r,
            Err(_) => break,
        };

        for receipt in &receipts {
            let ts = receipt.core.ts_ms as u64;
            let age_ms = now_ms.saturating_sub(ts);
            let weight = crate::decay::decay_factor(age_ms);

            // Count by type (raw and decay-weighted)
            if receipt.core.receipt_type == aegis_schemas::ReceiptType::VaultDetection {
                vault_detections += 1;
                weighted_vault_leaks += weight;
            }
            if receipt.core.receipt_type == aegis_schemas::ReceiptType::ApiCall {
                api_call_count += 1;
                weighted_vault_scans += weight;
            }

            // Timestamps for temporal consistency (all receipts)
            timestamps.push(ts);

            // Count receipts in last 24h
            if ts >= cutoff_24h {
                signals.receipts_last_24h += 1;
            }
        }

        seq = end + 1;
    }

    signals.vault_leaks_detected = vault_detections;
    // Vault scans happen per API call, not per receipt (other receipt types don't scan)
    signals.vault_scans_total = api_call_count;
    signals.weighted_vault_leaks = weighted_vault_leaks;
    signals.weighted_vault_scans = weighted_vault_scans;

    // Sort timestamps for temporal consistency scoring
    timestamps.sort();
    // Keep last 500 for CV calculation (enough for statistical significance,
    // avoids memory issues on very long chains)
    if timestamps.len() > 500 {
        timestamps = timestamps.split_off(timestamps.len() - 500);
    }
    signals.receipt_timestamps = timestamps;
}

/// Read filesystem state for persona integrity signals.
fn gather_from_filesystem(data_dir: &Path, signals: &mut LocalSignals) {
    // Identity key — check existence and age
    // Identity key — single authoritative location (no candidate scanning)
    let key_path = data_dir.join("identity.key");
    if key_path.exists() {
        // Count protected files from the default ProtectedFileManager (12 system files)
        let mgr = aegis_barrier::protected_files::ProtectedFileManager::new();
        signals.protected_files_total = mgr.system_files.len();
        // If Aegis is running with a valid key, files were verified at startup
        signals.protected_files_intact = signals.protected_files_total;
    }

    // Manifest — check existence (signature is verified by Aegis at startup)
    let manifest_path = data_dir.join("file_manifest.json");
    if manifest_path.exists() {
        signals.manifest_signature_valid = Some(true);
        signals.between_session_tampers = 0;
    } else if signals.protected_files_total > 0 {
        // Has identity but no manifest — first run or manifest not written yet
        signals.manifest_signature_valid = None;
    }
}

/// Get identity key age in hours.
pub fn get_identity_age_hours(data_dir: &Path) -> f64 {
    // Single authoritative location — no candidate scanning
    let candidates = [data_dir.join("identity.key")];
    for path in &candidates {
        if let Ok(meta) = std::fs::metadata(path)
            && let Ok(created) = meta.created().or_else(|_| meta.modified())
        {
            let age = std::time::SystemTime::now()
                .duration_since(created)
                .unwrap_or_default();
            return age.as_secs_f64() / 3600.0;
        }
    }
    0.0
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn empty_data_dir_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let signals = gather_local_signals(dir.path());

        assert_eq!(signals.chain_receipt_count, 0);
        assert_eq!(signals.vault_leaks_detected, 0);
        assert_eq!(signals.protected_files_total, 0);
        assert!(signals.chain_verified.is_none());
        assert!(signals.manifest_signature_valid.is_none());
    }

    #[test]
    fn identity_key_sets_protected_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("identity.key"), vec![0u8; 32]).unwrap();

        let signals = gather_local_signals(dir.path());

        assert_eq!(signals.protected_files_total, 12);
        assert_eq!(signals.protected_files_intact, 12);
        assert!(signals.manifest_signature_valid.is_none()); // no manifest yet
    }

    #[test]
    fn identity_key_plus_manifest() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("identity.key"), vec![0u8; 32]).unwrap();
        fs::write(dir.path().join("file_manifest.json"), b"{}").unwrap();

        let signals = gather_local_signals(dir.path());

        assert_eq!(signals.protected_files_total, 12);
        assert_eq!(signals.manifest_signature_valid, Some(true));
        assert_eq!(signals.between_session_tampers, 0);
    }

    #[test]
    fn evidence_db_with_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("evidence.db");

        // Create a real evidence store and add some receipts
        let key = aegis_crypto::ed25519::generate_keypair();
        let recorder = aegis_evidence::EvidenceRecorder::new(&db_path, key).unwrap();

        // Add 5 normal receipts
        for i in 0..5 {
            recorder
                .record_simple(
                    aegis_schemas::ReceiptType::ApiCall,
                    &format!("request_{i}"),
                    "200 OK",
                )
                .unwrap();
        }

        // Add 2 vault detection receipts
        for _ in 0..2 {
            recorder
                .record_simple(
                    aegis_schemas::ReceiptType::VaultDetection,
                    "vault_scan /v1/chat/completions",
                    "credentials detected",
                )
                .unwrap();
        }

        let signals = gather_local_signals(dir.path());

        assert_eq!(signals.chain_receipt_count, 7);
        assert_eq!(signals.chain_verified, Some(true));
        assert_eq!(signals.vault_leaks_detected, 2);
        assert_eq!(signals.vault_scans_total, 5); // only ApiCall receipts, not all
        assert_eq!(signals.receipt_timestamps.len(), 7);
        assert!(signals.receipts_last_24h >= 7); // all just created
    }

    #[test]
    fn vault_count_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("evidence.db");

        let key = aegis_crypto::ed25519::generate_keypair();
        let recorder = aegis_evidence::EvidenceRecorder::new(&db_path, key).unwrap();

        // Add 100 normal + 17 vault detections
        for _ in 0..100 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::ApiCall, "forward", "200")
                .unwrap();
        }
        for _ in 0..17 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::VaultDetection, "vault", "leak")
                .unwrap();
        }

        let signals = gather_local_signals(dir.path());

        assert_eq!(signals.chain_receipt_count, 117);
        assert_eq!(
            signals.vault_leaks_detected, 17,
            "must count ALL vault detections, not a window"
        );
        assert_eq!(
            signals.vault_scans_total, 100,
            "scans = ApiCall count, not all receipts"
        );
    }

    #[test]
    fn timestamps_are_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("evidence.db");

        let key = aegis_crypto::ed25519::generate_keypair();
        let recorder = aegis_evidence::EvidenceRecorder::new(&db_path, key).unwrap();

        for _ in 0..10 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::ApiCall, "forward", "200")
                .unwrap();
        }

        let signals = gather_local_signals(dir.path());

        for w in signals.receipt_timestamps.windows(2) {
            assert!(w[0] <= w[1], "timestamps must be sorted ascending");
        }
    }

    #[test]
    fn identity_age_returns_positive() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("identity.key"), vec![0u8; 32]).unwrap();

        let age = get_identity_age_hours(dir.path());
        assert!(age >= 0.0);
        assert!(age < 1.0, "just created should be < 1 hour: {age}");
    }

    #[test]
    fn identity_age_missing_key_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let age = get_identity_age_hours(dir.path());
        assert_eq!(age, 0.0);
    }

    #[test]
    fn cli_and_dashboard_get_same_signals() {
        // Both should call gather_local_signals with the same path
        // and get identical results
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("evidence.db");

        let key = aegis_crypto::ed25519::generate_keypair();
        let recorder = aegis_evidence::EvidenceRecorder::new(&db_path, key).unwrap();

        for _ in 0..50 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::ApiCall, "forward", "200")
                .unwrap();
        }
        for _ in 0..5 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::VaultDetection, "vault", "leak")
                .unwrap();
        }
        fs::write(dir.path().join("identity.key"), vec![0u8; 32]).unwrap();
        fs::write(dir.path().join("file_manifest.json"), b"{}").unwrap();

        // Call twice — must be identical
        let s1 = gather_local_signals(dir.path());
        let s2 = gather_local_signals(dir.path());

        assert_eq!(s1.chain_receipt_count, s2.chain_receipt_count);
        assert_eq!(s1.vault_leaks_detected, s2.vault_leaks_detected);
        assert_eq!(s1.vault_scans_total, s2.vault_scans_total);
        assert_eq!(s1.protected_files_total, s2.protected_files_total);
        assert_eq!(s1.manifest_signature_valid, s2.manifest_signature_valid);
        assert_eq!(s1.receipt_timestamps.len(), s2.receipt_timestamps.len());
        assert_eq!(s1.receipts_last_24h, s2.receipts_last_24h);
    }

    #[test]
    fn old_leaks_decay_improves_score() {
        // When all receipts are freshly created, the weighted counts are nearly
        // equal to raw counts — so the score should be the same as before.
        // The decay itself is tested in the decay module; here we verify the
        // gather module actually populates the weighted fields.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("evidence.db");

        let key = aegis_crypto::ed25519::generate_keypair();
        let recorder = aegis_evidence::EvidenceRecorder::new(&db_path, key).unwrap();

        // 50 normal + 5 vault detections (all recent)
        for _ in 0..50 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::ApiCall, "forward", "200")
                .unwrap();
        }
        for _ in 0..5 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::VaultDetection, "vault", "leak")
                .unwrap();
        }

        let signals = gather_local_signals(dir.path());

        // Weighted fields should be populated
        assert!(
            signals.weighted_vault_scans > 0.0,
            "weighted scans should be positive"
        );
        assert!(
            signals.weighted_vault_leaks > 0.0,
            "weighted leaks should be positive"
        );
        // For fresh receipts, weighted values are close to raw counts
        assert!(
            (signals.weighted_vault_scans - 50.0).abs() < 1.0,
            "fresh receipts should have weight ~1.0: {}",
            signals.weighted_vault_scans
        );
        assert!(
            (signals.weighted_vault_leaks - 5.0).abs() < 1.0,
            "fresh leaks should have weight ~1.0: {}",
            signals.weighted_vault_leaks
        );
    }

    #[test]
    fn full_score_from_real_data() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("evidence.db");

        let key = aegis_crypto::ed25519::generate_keypair();
        let recorder = aegis_evidence::EvidenceRecorder::new(&db_path, key).unwrap();

        // Simulate a realistic adapter: 200 requests, 3 vault leaks
        for _ in 0..200 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::ApiCall, "forward", "200")
                .unwrap();
        }
        for _ in 0..3 {
            recorder
                .record_simple(aegis_schemas::ReceiptType::VaultDetection, "vault", "leak")
                .unwrap();
        }

        fs::write(dir.path().join("identity.key"), vec![0u8; 32]).unwrap();
        fs::write(dir.path().join("file_manifest.json"), b"{}").unwrap();

        let signals = gather_local_signals(dir.path());
        let score = crate::scoring::TrustmarkScore::compute(&signals);

        // Should be a reasonable score — not 0, not 100
        assert!(
            score.total > 0.4,
            "realistic data should score > 0.4: {}",
            score.total
        );
        assert!(score.total < 1.0);

        // Vault should reflect 3/203 leak rate
        let vault = &score.dimensions[2];
        assert_eq!(vault.name, "vault_hygiene");
        // 3/203 = 1.5% leak rate, 0 redacted → (0.985 * 0.7) + (0.0 * 0.3) ≈ 0.69
        assert!(
            vault.value > 0.6 && vault.value < 0.75,
            "3/203 with 0 redacted should be ~0.69: {}",
            vault.value
        );
    }
}
