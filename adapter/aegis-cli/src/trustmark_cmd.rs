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

    // Visual output
    println!();
    println!("━━━ TRUSTMARK Score ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let pct = (score.total * 100.0) as u32;
    let bar_len = (score.total * 30.0) as usize;
    let bar: String = "█".repeat(bar_len) + &"░".repeat(30 - bar_len);
    let color = if score.total >= 0.7 { "\x1b[32m" }
        else if score.total >= 0.4 { "\x1b[33m" }
        else { "\x1b[31m" };
    println!("  Total:  {color}{:.4}\x1b[0m  ({pct}%)  [{bar}]", score.total);
    println!("  Tier:   {}  |  Identity: {:.0}h", tier.current, identity_age);
    if !tier.next_tier_requirements.is_empty() {
        println!("  Next:   {}", tier.next_tier_requirements.join(" | "));
    }
    println!();

    println!("  ── Dimensions ─────────────────────────────────────────");
    for d in &score.dimensions {
        let dbar_len = (d.value * 20.0) as usize;
        let dbar: String = "█".repeat(dbar_len) + &"░".repeat(20 - dbar_len);
        let dcolor = if d.value >= 0.8 { "\x1b[32m" }
            else if d.value >= 0.5 { "\x1b[33m" }
            else { "\x1b[31m" };
        println!("  {:<25} {dcolor}{:.3}\x1b[0m × {:.2} = {:.4}  [{dbar}]",
            d.name, d.value, d.weight, d.contribution);
        println!("  {:<25} \x1b[90mFormula: {}\x1b[0m", "", d.formula);
        println!("  {:<25} \x1b[90mInputs:  {}\x1b[0m", "", d.inputs);
        if !d.improve.is_empty() {
            println!("  {:<25} \x1b[36m→ {}\x1b[0m", "", d.improve);
        }
        println!();
    }
    println!();
    println!("  Source: {} (read-only, no server required)", data_dir.display());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
}
