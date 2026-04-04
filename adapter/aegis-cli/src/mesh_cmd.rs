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
    #[serde(default)]
    pub dead_drops_delivered: u64,
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
    pub votes_cast: usize,
    pub validators_total: usize,
    pub namespace: String,
}

#[derive(Deserialize, Debug)]
pub struct DeadDropsResponse {
    pub total: usize,
    pub recipients_count: usize,
    pub recipients: Vec<DeadDropQueue>,
}

#[derive(Deserialize, Debug)]
pub struct DeadDropQueue {
    pub bot_id: String,
    pub count: usize,
    pub oldest_age_ms: Option<i64>,
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

/// Raw JSON output — fetches an endpoint and prints the response as-is.
/// Used with `--json` flag for piping to jq or machine consumption.
pub fn run_json(gateway_url: &str, path: &str) {
    let url = format!("{gateway_url}{path}");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };
    let json: serde_json::Value = match resp.json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
}

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
    println!("  DD delivered:    {}", status.relay.dead_drops_delivered);
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
        "  {:<20} {:<12} {:<8} Status",
        "Bot ID", "TRUSTMARK", "Tier"
    );
    println!(
        "  {:<20} {:<12} {:<8} ──────",
        "──────────────────", "─────────", "────"
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
                vote.votes_cast,
                vote.validators_total,
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

    println!();
    println!("━━━ Dead-Drops ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  Total queued:    {}", data.total);
    println!("  Recipients:      {}", data.recipients_count);

    if !data.recipients.is_empty() {
        println!();
        println!("  {:<20} {:<10} Oldest", "Bot ID", "Queued");
        println!("  {:<20} {:<10} ──────", "──────────────────", "──────");
        for q in &data.recipients {
            let id_short = format_bot_id_short(&q.bot_id);
            let age = match q.oldest_age_ms {
                Some(ms) => format_age_ms(ms),
                None => "—".to_string(),
            };
            println!("  {:<20} {:>6}    {}", id_short, q.count, age);
        }
    }
    println!();
}

// ── Relay Inbox types ──────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct InboxResponse {
    pub messages: Vec<InboxMessage>,
    pub count: usize,
}

#[derive(Deserialize, Debug)]
pub struct InboxMessage {
    pub from: String,
    pub body: String,
    pub ts_ms: u64,
    pub read: bool,
}

// ── Drill-down response types ──────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct PeerDetailResponse {
    pub bot_id: String,
    pub online: bool,
    pub score_bp: u32,
    pub dimensions: serde_json::Value,
    pub tier: String,
    pub computed_at_ms: i64,
}

#[derive(Deserialize, Debug)]
pub struct RelayLogResponse {
    pub events: Vec<RelayLogEvent>,
    #[allow(dead_code)]
    pub count: usize,
}

#[derive(Deserialize, Debug)]
pub struct RelayLogEvent {
    pub from: String,
    pub to: String,
    pub status: String,
    pub msg_type: String,
    pub ts_ms: i64,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub body_preview: String,
}

#[derive(Deserialize, Debug)]
pub struct DeadDropDetailResponse {
    #[allow(dead_code)]
    pub bot_id: String,
    pub drops: Vec<DeadDropMessage>,
    #[allow(dead_code)]
    pub count: usize,
}

#[derive(Deserialize, Debug)]
pub struct DeadDropMessage {
    pub from: String,
    pub body: String,
    pub msg_type: String,
    pub ts_ms: i64,
    pub expires_ms: i64,
}

// ── Drill-down subcommand runners ──────────────────────────────────

pub fn run_peer_detail(gateway_url: &str, bot_id: &str) {
    let url = format!("{gateway_url}/mesh/peers/{bot_id}");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    if resp.status().as_u16() == 404 {
        eprintln!("Error: bot not found: {bot_id}");
        std::process::exit(1);
    }

    let data: PeerDetailResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse peer detail: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!(
        "\u{2501}\u{2501}\u{2501} Peer Detail \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}"
    );
    println!();
    println!("  Bot ID:       {}", data.bot_id);
    println!(
        "  Status:       {}",
        if data.online { "online" } else { "offline" }
    );
    println!("  TRUSTMARK:    {} bp", data.score_bp);
    println!("  Tier:         {}", data.tier);
    println!(
        "  Computed at:  {}",
        format_age_ms(now_ms() - data.computed_at_ms)
    );
    println!();

    // Render dimensions if available
    if let Some(dims) = data.dimensions.as_array() {
        println!("  \u{2500}\u{2500} Dimensions \u{2500}\u{2500}");
        for dim in dims {
            let name = dim["name"].as_str().unwrap_or("?");
            let score = dim["score"].as_f64().unwrap_or(0.0);
            let target = dim["target"].as_f64().unwrap_or(1.0);
            let bar_width = 20;
            let filled = ((score / target.max(0.001)) * bar_width as f64)
                .round()
                .min(bar_width as f64) as usize;
            let empty = bar_width - filled;
            println!(
                "  {:<22} {:.3} / {:.3}  {}{}",
                name,
                score,
                target,
                "\u{2588}".repeat(filled),
                "\u{2591}".repeat(empty)
            );
        }
    } else if data.dimensions.is_object() {
        println!("  \u{2500}\u{2500} Dimensions \u{2500}\u{2500}");
        let pretty = serde_json::to_string_pretty(&data.dimensions).unwrap_or_default();
        for line in pretty.lines() {
            println!("  {line}");
        }
    }
    println!();
}

pub fn run_relay_log(gateway_url: &str, limit: usize) {
    let url = format!("{gateway_url}/mesh/relay/log?limit={limit}");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let data: RelayLogResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse relay log: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!(
        "\u{2501}\u{2501}\u{2501} Relay Log \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}"
    );
    println!();

    if data.events.is_empty() {
        println!("  No relay events recorded yet.");
        println!();
        return;
    }

    println!(
        "  {:<14} {:<14} {:<14} {:<14} {:<8} {:<24} Preview",
        "Time", "From", "To", "Status", "Type", "Reason"
    );
    println!(
        "  {:<14} {:<14} {:<14} {:<14} {:<8} {:<24} \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
    );

    for event in &data.events {
        let age = format_age_ms(now_ms() - event.ts_ms);
        let reason = if event.reason.is_empty() {
            "\u{2014}".to_string()
        } else {
            event.reason.clone()
        };
        let preview: String = event.body_preview.chars().take(40).collect();
        let preview = if event.body_preview.len() > 40 {
            format!("{preview}...")
        } else {
            preview
        };
        println!(
            "  {:<14} {:<14} {:<14} {:<14} {:<8} {:<24} {}",
            age,
            format_bot_id_short(&event.from),
            format_bot_id_short(&event.to),
            &event.status,
            &event.msg_type,
            reason,
            preview,
        );
    }

    println!();
    println!("  {} events shown", data.events.len());
    println!();
}

pub fn run_dead_drop_detail(gateway_url: &str, bot_id: &str) {
    let url = format!("{gateway_url}/mesh/dead-drops/{bot_id}");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            print_connection_error(gateway_url);
            std::process::exit(1);
        }
    };

    let data: DeadDropDetailResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse dead-drop detail: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!(
        "\u{2501}\u{2501}\u{2501} Dead-Drops for {} \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}",
        format_bot_id_short(bot_id)
    );
    println!();

    if data.drops.is_empty() {
        println!("  No pending dead-drops for this bot.");
        println!();
        return;
    }

    for (i, drop) in data.drops.iter().enumerate() {
        let age = format_age_ms(now_ms() - drop.ts_ms);
        let ttl = format_age_ms(drop.expires_ms - now_ms());
        let body_preview = if drop.body.len() > 80 {
            format!("{}...", &drop.body[..80])
        } else {
            drop.body.clone()
        };

        println!("  [{}/{}]", i + 1, data.drops.len());
        println!("    From:    {}", format_bot_id_short(&drop.from));
        println!("    Type:    {}", drop.msg_type);
        println!("    Age:     {}", age);
        println!("    Expires: {}", ttl);
        println!("    Body:    {}", body_preview);
        println!();
    }

    println!("  {} pending messages", data.drops.len());
    println!();
}

pub fn run_inbox(adapter_url: &str) {
    let url = format!("{adapter_url}/aegis/relay/inbox");
    let resp = match client().get(&url).send() {
        Ok(r) => r,
        Err(_) => {
            eprintln!("Error: cannot connect to Adapter at {adapter_url}");
            eprintln!("  Is the Adapter running? Start with: aegis (default listens on port 3141)");
            std::process::exit(1);
        }
    };

    let data: InboxResponse = match resp.json() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to parse inbox response: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!("━━━ Relay Inbox ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  Messages: {}", data.count);

    if data.messages.is_empty() {
        println!();
        println!("  No relay messages received.");
        println!();
        return;
    }

    println!();
    println!("  {:<14} {:<20} {:<6} Message", "Time", "From", "Read");
    println!(
        "  {:<14} {:<20} {:<6} ──────────────────────────────",
        "────────────", "──────────────────", "────"
    );

    for msg in &data.messages {
        let age = format_age_ms(now_ms() - msg.ts_ms as i64);
        let from_short = format_bot_id_short(&msg.from);
        let read_str = if msg.read { "yes" } else { "NEW" };
        let preview: String = msg.body.chars().take(50).collect();
        let preview = if msg.body.len() > 50 {
            format!("{preview}...")
        } else {
            preview
        };
        println!(
            "  {:<14} {:<20} {:<6} {}",
            age, from_short, read_str, preview,
        );
    }

    println!();
    let unread = data.messages.iter().filter(|m| !m.read).count();
    println!("  {} total, {} unread", data.messages.len(), unread);
    println!();
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
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
    fn parse_peer_detail_response() {
        let json = r#"{
            "bot_id": "a7f3b2c1d9e4f5a2",
            "online": true,
            "score_bp": 8420,
            "dimensions": [{"name": "chain_integrity", "score": 0.95, "target": 1.0}],
            "tier": "T2",
            "computed_at_ms": 1700000000000
        }"#;
        let resp: PeerDetailResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.bot_id, "a7f3b2c1d9e4f5a2");
        assert!(resp.online);
        assert_eq!(resp.score_bp, 8420);
        assert_eq!(resp.tier, "T2");
    }

    #[test]
    fn parse_relay_log_response() {
        let json = r#"{
            "events": [
                {"from": "bot_a", "to": "bot_b", "status": "delivered", "msg_type": "relay", "ts_ms": 1700000000000}
            ],
            "count": 1
        }"#;
        let resp: RelayLogResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.count, 1);
        assert_eq!(resp.events[0].status, "delivered");
    }

    #[test]
    fn parse_dead_drop_detail_response() {
        let json = r#"{
            "bot_id": "bot_b",
            "drops": [
                {"from": "bot_a", "body": "hello", "msg_type": "relay", "ts_ms": 1700000000000, "expires_ms": 1700259200000}
            ],
            "count": 1
        }"#;
        let resp: DeadDropDetailResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.bot_id, "bot_b");
        assert_eq!(resp.drops.len(), 1);
        assert_eq!(resp.drops[0].body, "hello");
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
