//! `aegis setup cluster` — connect to an Aegis cluster Gateway.
//!
//! Tests connectivity, checks mesh API, reads bot identity,
//! and writes `gateway_url` into the adapter config file.

use std::path::Path;
use std::time::Duration;

pub fn setup_cluster(gateway_url: &str, dry_run: bool, config_path: &str) {
    println!();
    println!("--- Aegis Cluster Setup ---------------------------------");
    println!();

    // 1. Test Gateway connection
    println!("  Testing Gateway connection...");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let health = match client.get(&format!("{gateway_url}/health")).send() {
        Ok(r) if r.status().is_success() => {
            println!("  [ok] Gateway reachable at {gateway_url}");
            true
        }
        Ok(r) => {
            eprintln!("  [FAIL] Gateway returned {}", r.status());
            false
        }
        Err(e) => {
            eprintln!("  [FAIL] Cannot connect to {gateway_url}: {e}");
            eprintln!("    Is the Gateway running?");
            false
        }
    };

    if !health {
        std::process::exit(1);
    }

    // 2. Check mesh endpoints
    println!("  Testing mesh API...");
    match client.get(&format!("{gateway_url}/mesh/status")).send() {
        Ok(r) if r.status().is_success() => {
            let status: serde_json::Value = r.json().unwrap_or_default();
            let peers = status
                .get("peers_online")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("  [ok] Mesh API available ({peers} peers online)");
        }
        _ => {
            println!("  [warn] Mesh API not available (Gateway may be an older version)");
        }
    }

    // 3. Show bot identity
    let identity_path = Path::new(config_path)
        .parent()
        .unwrap_or(Path::new("."))
        .parent()
        .unwrap_or(Path::new("."))
        .join("identity.key");

    if identity_path.exists() {
        if let Ok(key_bytes) = std::fs::read(&identity_path) {
            if key_bytes.len() == 32 {
                use ed25519_dalek::SigningKey;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_bytes);
                let sk = SigningKey::from_bytes(&arr);
                let pk = hex::encode(sk.verifying_key().as_bytes());
                println!(
                    "  [ok] Bot identity: {}...{}",
                    &pk[..16],
                    &pk[pk.len() - 8..]
                );
            }
        }
    } else {
        println!("  [warn] No identity key found (will be generated on first start)");
    }

    if dry_run {
        println!();
        println!("  Dry run -- no changes made.");
        println!("  To connect: aegis setup cluster {gateway_url}");
        return;
    }

    // 4. Update config.toml
    println!();
    println!("  Writing gateway_url to config...");

    let config_file = Path::new(config_path);
    if !config_file.exists() {
        eprintln!("  [FAIL] Config file not found: {}", config_file.display());
        eprintln!("    Run 'aegis' first to generate default config, then re-run setup.");
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(config_file).unwrap_or_default();

    let new_content = if content.contains("gateway_url") {
        // Replace existing gateway_url line
        let re = regex::Regex::new(r#"gateway_url\s*=\s*"[^"]*""#).unwrap();
        let replaced = re
            .replace(&content, &format!("gateway_url = \"{gateway_url}\""))
            .to_string();
        println!("  [ok] Updated gateway_url in {}", config_file.display());
        replaced
    } else {
        // Insert before [proxy] section if it exists, otherwise after first two lines
        let inserted = content.replacen(
            "\n[proxy]",
            &format!("\ngateway_url = \"{gateway_url}\"\n\n[proxy]"),
            1,
        );
        if inserted == content {
            // Fallback: insert after second line (after mode and data_dir)
            let mut new = String::new();
            for (i, line) in content.lines().enumerate() {
                new.push_str(line);
                new.push('\n');
                if i == 1 {
                    new.push_str(&format!("gateway_url = \"{gateway_url}\"\n"));
                }
            }
            println!("  [ok] Added gateway_url to {}", config_file.display());
            new
        } else {
            println!("  [ok] Added gateway_url to {}", config_file.display());
            inserted
        }
    };

    std::fs::write(config_file, new_content).unwrap();

    println!();
    println!("  [ok] Cluster connection configured!");
    println!();
    println!("  Restart aegis to connect:");
    println!("    aegis");
    println!();
    println!("  Then check mesh status:");
    println!("    aegis mesh --gateway-url {gateway_url} status");
    println!();
}
