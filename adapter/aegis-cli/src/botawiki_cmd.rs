//! `aegis botawiki` — Botawiki knowledge base CLI commands.
//!
//! Fetches data from the Gateway's Botawiki API endpoints and renders
//! rich terminal output with aligned tables.

use serde::Deserialize;

use crate::mesh_cmd::{format_age_ms, format_bot_id_short};

// ── API response types ──────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct AllClaimsResponse {
    pub claims: Vec<ClaimView>,
    #[allow(dead_code)]
    pub count: usize,
}

#[derive(Deserialize, Debug)]
pub struct ClaimView {
    pub id: String,
    pub claim_type: serde_json::Value,
    pub namespace: String,
    pub attester_id: String,
    pub confidence_bp: u32,
    pub status: String,
    pub votes: Vec<VoteView>,
    #[allow(dead_code)]
    pub validators: Vec<String>,
    pub submitted_at_ms: i64,
    pub payload: serde_json::Value,
}

#[derive(Deserialize, Debug)]
pub struct VoteView {
    #[allow(dead_code)]
    pub validator_id: String,
    pub approve: bool,
    pub ts_ms: i64,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to build HTTP client")
}

fn print_connection_error(gateway_url: &str) {
    eprintln!("Error: cannot connect to Gateway at {gateway_url}");
    eprintln!("  Is the Gateway running? Start with: aegis-gateway -c gateway_config.toml");
}

fn format_claim_type(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}

fn format_timestamp(ms: i64) -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let age = now_ms - ms;
    if age < 0 {
        "just now".to_string()
    } else {
        format_age_ms(age)
    }
}

// ── Subcommand runners ──────────────────────────────────────────────

pub fn run_list(gateway_url: &str) {
    let url = format!("{gateway_url}/botawiki/claims/all");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let data: AllClaimsResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse claims response: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!(
        "\u{2501}\u{2501}\u{2501} Botawiki Claims \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}"
    );
    println!();

    if data.claims.is_empty() {
        println!("  No claims found.");
        println!();
        return;
    }

    println!(
        "  {:<18} {:<28} {:<8} {:<12} {:<12} Votes",
        "ID", "Namespace", "Type", "Status", "Confidence"
    );
    println!(
        "  {:<18} {:<28} {:<8} {:<12} {:<12} \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
    );

    let mut canonical_count = 0u32;
    let mut quarantine_count = 0u32;
    let mut tombstoned_count = 0u32;

    for claim in &data.claims {
        match claim.status.as_str() {
            "canonical" => canonical_count += 1,
            "quarantine" => quarantine_count += 1,
            "tombstoned" => tombstoned_count += 1,
            _ => {}
        }

        let id_short = format_bot_id_short(&claim.id);
        let claim_type = format_claim_type(&claim.claim_type);
        let approvals = claim.votes.iter().filter(|v| v.approve).count();
        let total_votes = claim.votes.len();

        println!(
            "  {:<18} {:<28} {:<8} {:<12} {:<12} {}/{}",
            id_short,
            &claim.namespace,
            claim_type,
            claim.status,
            format!("{} bp", claim.confidence_bp),
            approvals,
            total_votes,
        );
    }

    println!();
    println!(
        "  {} claims total ({} canonical, {} quarantine, {} tombstoned)",
        data.claims.len(),
        canonical_count,
        quarantine_count,
        tombstoned_count,
    );
    println!();
}

pub fn run_show(gateway_url: &str, claim_id: &str) {
    let url = format!("{gateway_url}/botawiki/claims/all");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let data: AllClaimsResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse claims response: {e}");
            std::process::exit(1);
        }
    };

    let claim = data
        .claims
        .iter()
        .find(|c| c.id == claim_id || c.id.starts_with(claim_id));

    let claim = match claim {
        Some(c) => c,
        None => {
            eprintln!("Error: claim not found: {claim_id}");
            std::process::exit(1);
        }
    };

    println!();
    println!(
        "\u{2501}\u{2501}\u{2501} Claim {}... \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}",
        format_bot_id_short(&claim.id)
    );
    println!();
    println!("  ID:           {}", claim.id);
    println!("  Type:         {}", format_claim_type(&claim.claim_type));
    println!("  Namespace:    {}", claim.namespace);
    println!(
        "  Attester:     {}",
        format_bot_id_short(&claim.attester_id)
    );
    println!("  Confidence:   {} bp", claim.confidence_bp);
    println!("  Status:       {}", claim.status);
    println!(
        "  Submitted:    {}",
        format_timestamp(claim.submitted_at_ms)
    );
    println!();

    println!("  \u{2500}\u{2500} Payload \u{2500}\u{2500}");
    let payload_str = serde_json::to_string_pretty(&claim.payload).unwrap_or_default();
    for line in payload_str.lines() {
        println!("  {line}");
    }
    println!();

    if !claim.votes.is_empty() {
        println!("  \u{2500}\u{2500} Votes \u{2500}\u{2500}");
        for (i, vote) in claim.votes.iter().enumerate() {
            let action = if vote.approve { "approve" } else { "reject " };
            println!(
                "  v{}: {} ({})",
                i + 1,
                action,
                format_timestamp(vote.ts_ms)
            );
        }
        println!();
    }
}

pub fn run_search(gateway_url: &str, namespace: &str) {
    let url = format!("{gateway_url}/botawiki/claims/all");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let data: AllClaimsResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse claims response: {e}");
            std::process::exit(1);
        }
    };

    let matched: Vec<&ClaimView> = data
        .claims
        .iter()
        .filter(|c| c.namespace.contains(namespace))
        .collect();

    println!();
    println!(
        "\u{2501}\u{2501}\u{2501} Search: \"{}\" \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}",
        namespace
    );
    println!();

    if matched.is_empty() {
        println!("  No claims matching namespace \"{namespace}\"");
        println!();
        return;
    }

    println!(
        "  {:<18} {:<28} {:<8} {:<12} Confidence",
        "ID", "Namespace", "Type", "Status"
    );
    println!(
        "  {:<18} {:<28} {:<8} {:<12} \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
    );

    for claim in &matched {
        let id_short = format_bot_id_short(&claim.id);
        let claim_type = format_claim_type(&claim.claim_type);
        println!(
            "  {:<18} {:<28} {:<8} {:<12} {} bp",
            id_short, &claim.namespace, claim_type, claim.status, claim.confidence_bp,
        );
    }

    println!();
    println!("  {} claims found", matched.len());
    println!();
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_claims_response() {
        let json = r#"{
            "claims": [
                {
                    "id": "abc12345-6789-abcd-ef01-234567890abc",
                    "claim_type": "skills",
                    "namespace": "b/skills/malicious-urls",
                    "attester_id": "a7f3b2c1d9e4f5a2",
                    "confidence_bp": 8500,
                    "status": "canonical",
                    "votes": [
                        {"validator_id": "v1", "approve": true, "ts_ms": 1700000000000},
                        {"validator_id": "v2", "approve": true, "ts_ms": 1700000001000}
                    ],
                    "validators": ["v1", "v2", "v3"],
                    "submitted_at_ms": 1700000000000,
                    "payload": {"description": "test"}
                }
            ],
            "count": 1
        }"#;
        let resp: AllClaimsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.count, 1);
        assert_eq!(resp.claims.len(), 1);
        assert_eq!(resp.claims[0].namespace, "b/skills/malicious-urls");
        assert_eq!(resp.claims[0].confidence_bp, 8500);
        assert_eq!(resp.claims[0].votes.len(), 2);
        assert!(resp.claims[0].votes[0].approve);
    }

    #[test]
    fn format_claim_type_string_and_other() {
        let s = serde_json::Value::String("skills".into());
        assert_eq!(format_claim_type(&s), "skills");

        let o = serde_json::json!({"type": "lore"});
        assert_eq!(format_claim_type(&o), r#"{"type":"lore"}"#);
    }
}
