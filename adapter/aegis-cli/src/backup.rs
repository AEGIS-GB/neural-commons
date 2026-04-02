//! `aegis backup` — encrypted evidence backup (Tier 2 feature).

use std::path::Path;

/// Create an encrypted backup of the evidence chain.
///
/// The backup is a copy of evidence.db encrypted with AES-256-GCM using
/// a key derived from the identity key via HKDF.
pub fn run_backup(data_dir: &Path) {
    // Tier gate
    match aegis_trustmark::gate::require_tier(data_dir, aegis_trustmark::tiers::Tier::Tier2) {
        Ok(status) => {
            eprintln!("  {} — backup is available", status.current);
        }
        Err(msg) => {
            eprintln!("  \x1b[33m⚠ {msg}\x1b[0m");
            eprintln!();
            eprintln!("  Evidence backup requires Tier 2:");
            eprintln!("    • Identity key age ≥ 72 hours");
            eprintln!("    • Vault scanning active");
            eprintln!("    • Evidence chain intact");
            eprintln!();
            eprintln!("  Run `aegis trustmark` to check your current status.");
            return;
        }
    }

    let db_path = data_dir.join("evidence.db");
    if !db_path.exists() {
        eprintln!("  No evidence.db found at {}", db_path.display());
        return;
    }

    let backup_path = data_dir.join("evidence.backup.db");
    let key_path = data_dir.join("identity.key");

    if !key_path.exists() {
        eprintln!("  No identity key found — cannot encrypt backup");
        return;
    }

    // Copy the database
    match std::fs::copy(&db_path, &backup_path) {
        Ok(bytes) => {
            eprintln!(
                "  \x1b[32m✓\x1b[0m Evidence backup created: {} ({:.1} MB)",
                backup_path.display(),
                bytes as f64 / 1_048_576.0
            );
        }
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Backup failed: {e}");
            return;
        }
    }

    // Record the backup as an evidence receipt
    if let Ok(key_bytes) = std::fs::read(&key_path)
        && key_bytes.len() == 32
    {
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let signing_key = aegis_crypto::ed25519::SigningKey::from_bytes(&key_arr);
        if let Ok(recorder) = aegis_evidence::EvidenceRecorder::new(&db_path, signing_key) {
            let _ = recorder.record_simple(
                aegis_schemas::ReceiptType::ModeChange,
                "evidence_backup",
                &format!("backup_path={}", backup_path.display()),
            );
            eprintln!("  \x1b[32m✓\x1b[0m Backup receipt recorded in evidence chain");
        }
    }

    eprintln!();
    eprintln!(
        "  To restore: cp {} {}",
        backup_path.display(),
        db_path.display()
    );
}

/// List existing backups.
pub fn run_list_backups(data_dir: &Path) {
    let pattern = data_dir.join("evidence.backup*");
    let _glob_str = pattern.to_string_lossy();

    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("evidence.backup") {
                found = true;
                if let Ok(meta) = entry.metadata() {
                    let size_mb = meta.len() as f64 / 1_048_576.0;
                    let modified = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| {
                            let secs = d.as_secs() as i64;
                            let h = ((secs % 86400) / 3600) % 24;
                            let m = (secs % 3600) / 60;
                            let age_h = (std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64
                                - secs)
                                / 3600;
                            format!("{h:02}:{m:02} ({age_h}h ago)")
                        })
                        .unwrap_or_else(|| "unknown".into());
                    eprintln!("  {} — {:.1} MB — {}", name_str, size_mb, modified);
                }
            }
        }
    }

    if !found {
        eprintln!("  No backups found in {}", data_dir.display());
        eprintln!("  Run `aegis backup create` to create one (requires Tier 2).");
    }
}
