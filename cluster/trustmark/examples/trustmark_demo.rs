use aegis_trustmark::decay::decay_factor;
use aegis_trustmark::scoring::{LocalSignals, TrustmarkScore};
use aegis_trustmark::tiers::resolve_tier;

fn print_score(label: &str, score: &TrustmarkScore) {
    println!("━━━ {} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", label);
    println!("  TOTAL: {:.4} ({:.1}%)", score.total, score.total * 100.0);
    println!();
    for d in &score.dimensions {
        let bar_len = (d.value * 20.0) as usize;
        let bar: String = "█".repeat(bar_len) + &"░".repeat(20 - bar_len);
        println!(
            "  {:<25} {:.3} × {:.2} = {:.4}  [{}]",
            d.name, d.value, d.weight, d.contribution, bar
        );
        println!("  {:<25} {}", "", d.reason);
    }
    println!();
}

fn main() {
    // Scenario 1: Fresh install
    println!();
    let fresh = TrustmarkScore::compute(&LocalSignals::default());
    print_score("SCENARIO 1: Fresh Install (no data)", &fresh);

    // Scenario 2: Perfect
    let perfect = TrustmarkScore::compute(&LocalSignals {
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
        ..Default::default()
    });
    print_score("SCENARIO 2: Perfect (everything healthy)", &perfect);

    // Scenario 3: Compromised
    let bad = TrustmarkScore::compute(&LocalSignals {
        protected_files_total: 9,
        protected_files_intact: 5,
        manifest_signature_valid: Some(false),
        between_session_tampers: 3,
        chain_verified: Some(false),
        chain_receipt_count: 50,
        vault_scans_total: 200,
        vault_leaks_detected: 30,
        vault_leaks_redacted: 5,
        receipt_timestamps: vec![1000, 1001, 1002, 50_000_000, 50_000_001],
        receipts_last_24h: 10,
        volume_baseline: Some(100),
        relay_forwarded: 5,
        relay_failed: 45,
        ..Default::default()
    });
    print_score("SCENARIO 3: Compromised (tampered, leaking, bursty)", &bad);

    // Scenario 4: Typical running agent (2 days old)
    let typical = TrustmarkScore::compute(&LocalSignals {
        protected_files_total: 9,
        protected_files_intact: 9,
        manifest_signature_valid: Some(true),
        between_session_tampers: 0,
        chain_verified: Some(true),
        chain_receipt_count: 800,
        vault_scans_total: 150,
        vault_leaks_detected: 2,
        vault_leaks_redacted: 2,
        receipt_timestamps: (0..50).map(|i| i * 600_000).collect(), // every 10 min
        receipts_last_24h: 80,
        volume_baseline: Some(100),
        relay_forwarded: 0,
        relay_failed: 0,
        ..Default::default()
    });
    print_score("SCENARIO 4: Typical (2 days, few leaks redacted)", &typical);

    // Tier classification
    println!("━━━ TIER CLASSIFICATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    for (label, score, hours, vault, chain, vouches) in [
        ("Fresh install", fresh.total, 1.0, false, false, 0),
        ("Perfect", perfect.total, 200.0, true, true, 3),
        ("Compromised", bad.total, 200.0, true, false, 0),
        ("Typical (2 days)", typical.total, 48.0, true, true, 0),
        ("Typical (4 days)", typical.total, 96.0, true, true, 0),
        ("Typical + vouches", typical.total, 96.0, true, true, 2),
    ] {
        let tier = resolve_tier(score, hours, vault, chain, vouches);
        let next = if tier.next_tier_requirements.is_empty() {
            "—".to_string()
        } else {
            tier.next_tier_requirements.join(", ")
        };
        println!(
            "  {:<22} score={:.3}  → {}  needs: {}",
            label, score, tier.current, next
        );
    }
    println!();

    // Decay
    println!("━━━ TEMPORAL DECAY (90-day half-life) ━━━━━━━━━━━━━━━");
    for days in [0, 1, 7, 30, 60, 90, 180, 365] {
        let age_ms = days as u64 * 24 * 3600 * 1000;
        let factor = decay_factor(age_ms);
        let bar_len = (factor * 20.0) as usize;
        let bar: String = "█".repeat(bar_len) + &"░".repeat(20 - bar_len);
        println!("  {:>4} days  factor={:.4}  [{}]", days, factor, bar);
    }
    println!();
}
