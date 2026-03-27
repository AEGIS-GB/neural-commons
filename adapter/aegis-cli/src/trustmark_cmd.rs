//! `aegis trustmark` — compute and display TRUSTMARK score from local data.
//!
//! Reads directly from evidence.db and filesystem. Does NOT require Aegis to be running.

use aegis_trustmark::gather;
use aegis_trustmark::scoring::TrustmarkScore;
use aegis_trustmark::tiers::resolve_tier;

/// Resolve the Aegis data directory.
fn resolve_data_dir() -> std::path::PathBuf {
    // Check common locations
    let candidates = [
        std::path::PathBuf::from(".aegis"),
        dirs::home_dir().map(|h| h.join(".aegis")).unwrap_or_default(),
        dirs::home_dir().map(|h| h.join(".aegis/data")).unwrap_or_default(),
    ];
    for c in &candidates {
        if c.join("evidence.db").exists() {
            return c.clone();
        }
    }
    // Default
    candidates[0].clone()
}

/// Run the trustmark command.
pub fn run(aegis_url: &str, json_output: bool) {
    let _ = aegis_url; // Not used — we read from local data directly
    let data_dir = resolve_data_dir();

    let signals = gather::gather_local_signals(&data_dir);
    let score = TrustmarkScore::compute(&signals);
    let identity_age = gather::get_identity_age_hours(&data_dir);
    let vault_active = signals.vault_scans_total > 0;
    let chain_intact = signals.chain_verified.unwrap_or(false);
    let tier = resolve_tier(score.total, identity_age, vault_active, chain_intact, 0);

    if json_output {
        let output = serde_json::json!({
            "score": score,
            "tier": tier,
            "identity_age_hours": identity_age,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    // Visual output — dimensions first, total at bottom
    println!();
    println!("━━━ TRUSTMARK ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    for d in &score.dimensions {
        let status_icon = match d.status.as_str() {
            "healthy" => "\x1b[32m✓ healthy\x1b[0m",
            "attention" => "\x1b[33m! attention\x1b[0m",
            "critical" => "\x1b[31m✗ critical\x1b[0m",
            _ => "?",
        };
        let dcolor = match d.status.as_str() {
            "healthy" => "\x1b[32m",
            "attention" => "\x1b[33m",
            _ => "\x1b[31m",
        };

        // Header: name + status + score vs target
        println!("  {:<25} {}  {dcolor}{:.3}\x1b[0m / {:.3} target  (weight: {:.0}%)",
            d.name, status_icon, d.value, d.target, d.weight * 100.0);

        // Progress bar showing score vs target
        let bar_len = (d.value * 20.0) as usize;
        let target_pos = (d.target * 20.0) as usize;
        let mut bar_chars: Vec<char> = vec!['░'; 20];
        for i in 0..bar_len.min(20) { bar_chars[i] = '█'; }
        if target_pos < 20 { bar_chars[target_pos] = '|'; }
        let bar: String = bar_chars.into_iter().collect();
        println!("  {:<25} [{bar}]", "");

        // Details
        println!("  {:<25} \x1b[90m{}\x1b[0m", "", d.inputs);
        println!("  {:<25} \x1b[90m{}\x1b[0m", "", d.formula);
        if !d.improve.is_empty() {
            println!("  {:<25} \x1b[36m→ {}\x1b[0m", "", d.improve);
        }
        println!();
    }

    // Summary at bottom
    let total_status = if score.total >= 0.8 { "\x1b[32mhealthy\x1b[0m" }
        else if score.total >= 0.5 { "\x1b[33mneeds attention\x1b[0m" }
        else { "\x1b[31mcritical\x1b[0m" };
    println!("  ── Summary ────────────────────────────────────────────");
    println!("  TRUSTMARK: {:.3}  {}  |  {}  |  Identity: {:.0}h", score.total, total_status, tier.current, identity_age);
    if !tier.next_tier_requirements.is_empty() {
        println!("  Next tier: {}", tier.next_tier_requirements.join(" | "));
    }
    println!("  Source: {} (read-only, no server required)", data_dir.display());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
}
