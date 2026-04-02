//! `aegis trustmark` — compute and display TRUSTMARK score from local data.
//!
//! Uses config.data_dir as the single source of truth for the data directory.
//! Does NOT require Aegis to be running.

use std::path::Path;

use aegis_trustmark::gather;
use aegis_trustmark::scoring::TrustmarkScore;
use aegis_trustmark::tiers::resolve_tier;

/// Run the trustmark command (current score).
/// `data_dir` comes from config.toml — the same path the server uses.
pub fn run(data_dir: &Path, json_output: bool) {
    let signals = gather::gather_local_signals(data_dir);
    let score = TrustmarkScore::compute(&signals);
    let identity_age = gather::get_identity_age_hours(data_dir);
    let vault_active = signals.vault_scans_total > 0;
    let chain_intact = signals.chain_verified.unwrap_or(false);
    let tier = resolve_tier(score.total, identity_age, vault_active, chain_intact, 0);

    if json_output {
        let output = serde_json::json!({
            "score": score,
            "tier": tier,
            "identity_age_hours": identity_age,
            "data_dir": data_dir.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!();
    println!("━━━ TRUSTMARK ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    for d in &score.dimensions {
        let status_icon = match d.status.as_str() {
            "healthy" => "\x1b[32m✓ healthy\x1b[0m",
            "attention" => "\x1b[33m! attention\x1b[0m",
            _ => "\x1b[31m✗ critical\x1b[0m",
        };
        let dcolor = match d.status.as_str() {
            "healthy" => "\x1b[32m",
            "attention" => "\x1b[33m",
            _ => "\x1b[31m",
        };

        println!(
            "  {:<25} {}  {dcolor}{:.3}\x1b[0m / {:.3} target  (weight: {:.0}%)",
            d.name,
            status_icon,
            d.value,
            d.target,
            d.weight * 100.0
        );

        let bar_len = (d.value * 20.0) as usize;
        let target_pos = (d.target * 20.0) as usize;
        let mut bar_chars: Vec<char> = vec!['░'; 20];
        for ch in bar_chars.iter_mut().take(bar_len.min(20)) {
            *ch = '█';
        }
        if target_pos < 20 {
            bar_chars[target_pos] = '|';
        }
        let bar: String = bar_chars.into_iter().collect();
        println!("  {:<25} [{bar}]", "");

        println!("  {:<25} \x1b[90m{}\x1b[0m", "", d.inputs);
        println!("  {:<25} \x1b[90m{}\x1b[0m", "", d.formula);
        if !d.improve.is_empty() {
            println!("  {:<25} \x1b[36m→ {}\x1b[0m", "", d.improve);
        }
        println!();
    }

    let total_status = if score.total >= 0.8 {
        "\x1b[32mhealthy\x1b[0m"
    } else if score.total >= 0.5 {
        "\x1b[33mneeds attention\x1b[0m"
    } else {
        "\x1b[31mcritical\x1b[0m"
    };
    println!("  ── Summary ────────────────────────────────────────────");
    println!(
        "  TRUSTMARK: {:.3}  {}  |  {}  |  Identity: {:.0}h",
        score.total, total_status, tier.current, identity_age
    );
    if !tier.next_tier_requirements.is_empty() {
        println!("  Next tier: {}", tier.next_tier_requirements.join(" | "));
    }
    println!("  Data dir: {}", data_dir.display());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
}

/// Run the trustmark history command.
pub fn run_history(data_dir: &Path, limit: usize, json_output: bool) {
    let history = aegis_trustmark::persist::load_history(data_dir, limit);

    if history.is_empty() {
        eprintln!("No TRUSTMARK snapshots recorded yet.");
        eprintln!("Start Aegis to begin recording (snapshots every hour).");
        eprintln!("Data dir: {}", data_dir.display());
        return;
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&history).unwrap());
        return;
    }

    println!();
    println!(
        "━━━ TRUSTMARK History ({} snapshots) ━━━━━━━━━━━━━━━━━━━━━━",
        history.len()
    );
    println!();
    println!(
        "  {:<22} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8}",
        "Time", "Total", "Person", "Chain", "Vault", "Temprl", "Relay", "Volume"
    );
    println!("  {}", "─".repeat(76));

    for score in &history {
        let time = {
            let secs = (score.computed_at_ms / 1000) as i64;
            let total = secs % 86400;
            let h = (total / 3600) % 24;
            let m = (total % 3600) / 60;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let age_h = (now_ms - score.computed_at_ms as i64) / 3_600_000;
            if age_h < 24 {
                format!("{:02}:{:02} ({}h ago)", h, m, age_h)
            } else {
                format!("{:02}:{:02} ({}d ago)", h, m, age_h / 24)
            }
        };

        let dims: Vec<f64> = score.dimensions.iter().map(|d| d.value).collect();
        let (p, c, v, t, r, vol) = (
            dims.first().unwrap_or(&0.0),
            dims.get(1).unwrap_or(&0.0),
            dims.get(2).unwrap_or(&0.0),
            dims.get(3).unwrap_or(&0.0),
            dims.get(4).unwrap_or(&0.0),
            dims.get(5).unwrap_or(&0.0),
        );

        let col = if score.total >= 0.8 {
            "\x1b[32m"
        } else if score.total >= 0.5 {
            "\x1b[33m"
        } else {
            "\x1b[31m"
        };

        println!(
            "  {:<22} {col}{:<8.3}\x1b[0m {:<8.3} {:<8.3} {:<8.3} {:<8.3} {:<8.3} {:<8.3}",
            time, score.total, p, c, v, t, r, vol
        );
    }

    println!();
    println!("  Data dir: {}", data_dir.display());
    println!();
}
