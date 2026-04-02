//! `aegis mesh` — mesh network status and monitoring commands.
//!
//! Fetches data from the Gateway's mesh status API endpoints and renders
//! rich terminal output with aligned tables and status bars.

use serde::Deserialize;

// ── API response types ──────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct MeshStatus {
    #[allow(dead_code)]
    pub gateway: String,
    pub peers_online: usize,
    pub cached_scores: usize,
    pub relay: RelayStats,
}

#[derive(Deserialize, Debug)]
pub struct RelayStats {
    pub sent: u64,
    pub received: u64,
    pub quarantined: u64,
    pub dead_dropped: u64,
}

#[derive(Deserialize, Debug)]
pub struct PeersResponse {
    pub peers: Vec<Peer>,
    #[allow(dead_code)]
    pub count: usize,
}

#[derive(Deserialize, Debug)]
pub struct Peer {
    pub bot_id: String,
    pub online: bool,
    pub score_bp: Option<u32>,
    pub tier: Option<String>,
    #[allow(dead_code)]
    pub computed_at_ms: Option<i64>,
}

#[derive(Deserialize, Debug)]
pub struct ClaimsResponse {
    pub quarantine: usize,
    pub canonical: usize,
    pub tombstoned: usize,
    pub disputed: usize,
    pub total: usize,
    pub pending_votes: Vec<PendingVote>,
}

#[derive(Deserialize, Debug)]
pub struct PendingVote {
    pub claim_id: String,
    pub votes: usize,
    pub required: usize,
    pub namespace: String,
}

#[derive(Deserialize, Debug)]
pub struct DeadDropsResponse {
    pub total_queued: usize,
    pub recipients: usize,
    pub queues: Vec<DeadDropQueue>,
}

#[derive(Deserialize, Debug)]
pub struct DeadDropQueue {
    pub bot_id: String,
    pub queued: usize,
    pub oldest_ms: i64,
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format a millisecond age into a human-readable string like "2h 15m ago".
pub fn format_age_ms(age_ms: i64) -> String {
    if age_ms < 0 {
        return "just now".to_string();
    }
    let total_mins = age_ms / 60_000;
    let hours = total_mins / 60;
    let mins = total_mins % 60;
    if hours > 0 {
        format!("{}h {}m ago", hours, mins)
    } else {
        format!("{}m ago", mins)
    }
}

/// Truncate a hex bot ID to first 8 chars + "..." for display.
pub fn format_bot_id_short(bot_id: &str) -> String {
    if bot_id.len() > 11 {
        format!("{}...", &bot_id[..8])
    } else {
        bot_id.to_string()
    }
}

/// Render a simple bar chart segment (filled + empty) of the given width.
fn render_bar(value: u64, max: u64, width: usize) -> String {
    if max == 0 {
        return "░".repeat(width);
    }
    let filled = ((value as f64 / max as f64) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

/// Print gateway connection error and hint.
fn print_connection_error(gateway_url: &str) {
    eprintln!("Error: cannot connect to Gateway at {gateway_url}");
    eprintln!("  Is the Gateway running? Start with: aegis-gateway -c gateway_config.toml");
}

/// Build a blocking reqwest client with a short timeout.
fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to build HTTP client")
}

// ── Subcommand runners ──────────────────────────────────────────────

pub fn run_status(gateway_url: &str) {
    let url = format!("{gateway_url}/mesh/status");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let status: MeshStatus = match resp.json() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: failed to parse mesh status: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!("━━━ Mesh Status ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  Gateway:         connected ({gateway_url})");
    println!("  Peers online:    {}", status.peers_online);
    println!("  Cached scores:   {}", status.cached_scores);
    println!();
    println!("  ── Relay Activity ──");
    println!("  Sent:            {}", status.relay.sent);
    println!("  Received:        {}", status.relay.received);
    println!("  Quarantined:     {}", status.relay.quarantined);
    println!("  Dead-dropped:    {}", status.relay.dead_dropped);
    println!();
}

pub fn run_peers(gateway_url: &str) {
    let url = format!("{gateway_url}/mesh/peers");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let data: PeersResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse peers response: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!("━━━ Mesh Peers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!(
        "  {:<20} {:<12} {:<8} {}",
        "Bot ID", "TRUSTMARK", "Tier", "Status"
    );
    println!(
        "  {:<20} {:<12} {:<8} {}",
        "──────────────────", "─────────", "────", "──────"
    );

    for peer in &data.peers {
        let id_short = format_bot_id_short(&peer.bot_id);
        let score_str = match peer.score_bp {
            Some(bp) => format!("{} bp", bp),
            None => "—".to_string(),
        };
        let tier_str = peer.tier.as_deref().unwrap_or("—");
        let status_str = if peer.online { "online" } else { "offline" };

        println!(
            "  {:<20} {:<12} {:<8} {}",
            id_short, score_str, tier_str, status_str
        );
    }

    println!();
    let online_count = data.peers.iter().filter(|p| p.online).count();
    println!("  {} peers connected", online_count);
    println!();
}

pub fn run_relay(gateway_url: &str) {
    let url = format!("{gateway_url}/mesh/status");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let status: MeshStatus = match resp.json() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: failed to parse mesh status: {e}");
            std::process::exit(1);
        }
    };

    let relay = &status.relay;
    let max_val = relay
        .sent
        .max(relay.received)
        .max(relay.quarantined)
        .max(relay.dead_dropped);
    let bar_width = 30;

    println!();
    println!("━━━ Relay Stats ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!(
        "  Sent:         {:>5}      {}",
        relay.sent,
        render_bar(relay.sent, max_val, bar_width)
    );
    println!(
        "  Received:     {:>5}      {}",
        relay.received,
        render_bar(relay.received, max_val, bar_width)
    );
    println!(
        "  Quarantined:  {:>5}      {}",
        relay.quarantined,
        render_bar(relay.quarantined, max_val, bar_width)
    );
    println!(
        "  Dead-dropped: {:>5}      {}",
        relay.dead_dropped,
        render_bar(relay.dead_dropped, max_val, bar_width)
    );
    println!();

    let total = relay.sent + relay.received;
    let failed = relay.quarantined + relay.dead_dropped;
    if total > 0 {
        let success_rate = ((total - failed) as f64 / total as f64 * 100.0).round() as u64;
        println!("  Success rate: {}%", success_rate);
    } else {
        println!("  Success rate: —");
    }
    println!();
}

pub fn run_claims(gateway_url: &str) {
    let url = format!("{gateway_url}/mesh/claims");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let data: ClaimsResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse claims response: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!("━━━ Botawiki Claims ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  Quarantine:   {:>3}", data.quarantine);
    println!("  Canonical:    {:>3}", data.canonical);
    println!("  Tombstoned:   {:>3}", data.tombstoned);
    println!("  Disputed:     {:>3}", data.disputed);
    println!("  Total:        {:>3}", data.total);

    if !data.pending_votes.is_empty() {
        println!();
        println!("  ── Pending Votes ──");
        for vote in &data.pending_votes {
            println!(
                "  claim {}  votes: {}/{}  namespace: {}",
                format_bot_id_short(&vote.claim_id),
                vote.votes,
                vote.required,
                vote.namespace
            );
        }
    }
    println!();
}

pub fn run_dead_drops(gateway_url: &str) {
    let url = format!("{gateway_url}/mesh/dead-drops");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let data: DeadDropsResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse dead-drops response: {e}");
            std::process::exit(1);
        }
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    println!();
    println!("━━━ Dead-Drops ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  Total queued:    {}", data.total_queued);
    println!("  Recipients:      {}", data.recipients);

    if !data.queues.is_empty() {
        println!();
        println!("  {:<20} {:<10} {}", "Bot ID", "Queued", "Oldest");
        println!(
            "  {:<20} {:<10} {}",
            "──────────────────", "──────", "──────"
        );
        for q in &data.queues {
            let id_short = format_bot_id_short(&q.bot_id);
            let age = format_age_ms(now_ms - q.oldest_ms);
            println!("  {:<20} {:>6}    {}", id_short, q.queued, age);
        }
    }
    println!();
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mesh_status_response() {
        let json = r#"{
            "gateway": "aegis-gw-01",
            "peers_online": 3,
            "cached_scores": 5,
            "relay": {
                "sent": 47,
                "received": 31,
                "quarantined": 2,
                "dead_dropped": 8
            }
        }"#;
        let status: MeshStatus = serde_json::from_str(json).expect("deserialize MeshStatus");
        assert_eq!(status.gateway, "aegis-gw-01");
        assert_eq!(status.peers_online, 3);
        assert_eq!(status.cached_scores, 5);
        assert_eq!(status.relay.sent, 47);
        assert_eq!(status.relay.received, 31);
        assert_eq!(status.relay.quarantined, 2);
        assert_eq!(status.relay.dead_dropped, 8);
    }

    #[test]
    fn parse_peers_response() {
        let json = r#"{
            "peers": [
                {
                    "bot_id": "a7f3b2c1d9e4f5a2",
                    "online": true,
                    "score_bp": 8420,
                    "tier": "T2",
                    "computed_at_ms": 1700000000000
                },
                {
                    "bot_id": "c3b8d1e7",
                    "online": true,
                    "score_bp": null,
                    "tier": null,
                    "computed_at_ms": null
                }
            ],
            "count": 2
        }"#;
        let resp: PeersResponse = serde_json::from_str(json).expect("deserialize PeersResponse");
        assert_eq!(resp.count, 2);
        assert_eq!(resp.peers.len(), 2);
        assert_eq!(resp.peers[0].bot_id, "a7f3b2c1d9e4f5a2");
        assert!(resp.peers[0].online);
        assert_eq!(resp.peers[0].score_bp, Some(8420));
        assert_eq!(resp.peers[0].tier.as_deref(), Some("T2"));
        assert!(resp.peers[1].score_bp.is_none());
        assert!(resp.peers[1].tier.is_none());
    }

    #[test]
    fn parse_relay_stats() {
        let json = r#"{
            "sent": 100,
            "received": 80,
            "quarantined": 5,
            "dead_dropped": 15
        }"#;
        let stats: RelayStats = serde_json::from_str(json).expect("deserialize RelayStats");
        assert_eq!(stats.sent, 100);
        assert_eq!(stats.received, 80);
        assert_eq!(stats.quarantined, 5);
        assert_eq!(stats.dead_dropped, 15);
    }

    #[test]
    fn format_age_ms_hours_and_minutes() {
        // 2h 0m
        assert_eq!(format_age_ms(7_200_000), "2h 0m ago");
        // 1h 30m
        assert_eq!(format_age_ms(5_400_000), "1h 30m ago");
        // 45m
        assert_eq!(format_age_ms(2_700_000), "45m ago");
        // 0m
        assert_eq!(format_age_ms(30_000), "0m ago");
        // negative
        assert_eq!(format_age_ms(-1000), "just now");
    }

    #[test]
    fn format_bot_id_short_truncation() {
        // Long ID gets truncated
        assert_eq!(format_bot_id_short("a7f3b2c1d9e4f5a2"), "a7f3b2c1...");
        // Short ID stays as-is
        assert_eq!(format_bot_id_short("abcdef"), "abcdef");
        // Exactly 11 chars stays as-is
        assert_eq!(format_bot_id_short("12345678901"), "12345678901");
        // 12 chars gets truncated
        assert_eq!(format_bot_id_short("123456789012"), "12345678...");
    }
}
