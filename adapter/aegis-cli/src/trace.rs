//! `aegis trace` — end-to-end request flow inspector.
//!
//! Reads from the dashboard API and presents a unified view of each request's
//! journey through Aegis: channel → trust → SLM screening → upstream → response.

use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Debug)]
struct TrafficList {
    entries: Vec<TrafficSummary>,
}

#[derive(Deserialize, Debug)]
struct TrafficSummary {
    id: u64,
    ts_ms: i64,
    #[allow(dead_code)]
    method: String,
    #[allow(dead_code)]
    path: String,
    status: u16,
    request_size: usize,
    response_size: usize,
    duration_ms: u64,
    #[allow(dead_code)]
    is_streaming: bool,
    slm_duration_ms: Option<u64>,
    slm_verdict: Option<String>,
    slm_threat_score: Option<u32>,
    channel: Option<String>,
    trust_level: Option<String>,
    model: Option<String>,
    context: Option<String>,
    response_screen: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct TrafficDetail {
    entry: TrafficDetailEntry,
    chat: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct TrafficDetailEntry {
    id: u64,
    ts_ms: i64,
    method: String,
    path: String,
    status: u16,
    request_body: Option<String>,
    response_body: Option<String>,
    request_size: usize,
    response_size: usize,
    duration_ms: u64,
    is_streaming: bool,
    slm_duration_ms: Option<u64>,
    slm_verdict: Option<String>,
    slm_threat_score: Option<u32>,
    channel: Option<String>,
    trust_level: Option<String>,
    model: Option<String>,
    context: Option<String>,
    response_screen: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct SlmList {
    entries: Option<Vec<SlmEntry>>,
}

#[derive(Deserialize, Debug)]
struct SlmEntry {
    ts_ms: Option<i64>,
    action: Option<String>,
    threat_score: Option<u32>,
    screening_ms: Option<u64>,
    channel: Option<String>,
    trust_level: Option<String>,
}

/// Extract model name from request body JSON.
fn extract_model(req_body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(req_body)
        .ok()?
        .get("model")?
        .as_str()
        .map(|s| s.to_string())
}

/// Estimate token counts from request/response sizes.
/// Rough heuristic: ~4 chars per token for English text.
fn estimate_tokens(size: usize) -> usize {
    size / 4
}

/// Extract the last user message from the request body.
fn extract_last_user_message(req_body: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(req_body).ok()?;
    let messages = json.get("messages")?.as_array()?;
    for msg in messages.iter().rev() {
        if msg.get("role")?.as_str()? == "user" {
            let content = msg.get("content")?.as_str()?;
            // Take first 200 chars
            let truncated: String = content.chars().take(200).collect();
            if truncated.len() < content.len() {
                return Some(format!("{}...", truncated));
            }
            return Some(truncated);
        }
    }
    None
}

/// Format a timestamp as local time.
fn format_ts(ts_ms: i64) -> String {
    let secs = ts_ms / 1000;
    let dt = UNIX_EPOCH + std::time::Duration::from_secs(secs as u64);
    let elapsed = SystemTime::now().duration_since(dt).unwrap_or_default();

    // Format as HH:MM:SS
    let total_secs = secs % 86400;
    // Use local timezone offset (approximate)

    let h = (total_secs / 3600) % 24;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;

    let ago = if elapsed.as_secs() < 60 {
        format!("{}s ago", elapsed.as_secs())
    } else if elapsed.as_secs() < 3600 {
        format!("{}m ago", elapsed.as_secs() / 60)
    } else {
        format!("{}h ago", elapsed.as_secs() / 3600)
    };

    format!("{:02}:{:02}:{:02} UTC ({})", h, m, s, ago)
}

/// Run the trace command.
pub fn run(
    aegis_url: &str,
    id: Option<u64>,
    channel_filter: Option<&str>,
    verdict_filter: Option<&str>,
    last_minutes: Option<&str>,
    show_body: bool,
    show_health: bool,
    num: usize,
) {
    let dashboard_base = format!("{}/dashboard/api", aegis_url.trim_end_matches('/'));

    if let Some(entry_id) = id {
        show_detail(&dashboard_base, entry_id, show_body);
    } else {
        show_table(
            &dashboard_base,
            channel_filter,
            verdict_filter,
            last_minutes,
            num,
        );
    }

    if show_health {
        show_slm_health(aegis_url);
    }
}

/// Read dashboard auth token from config files.
fn get_dashboard_token() -> Option<String> {
    let candidates = [
        std::path::PathBuf::from(".aegis/config/config.toml"),
        dirs::home_dir()?.join(".aegis/config/config.toml"),
    ];
    for path in &candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                if let Some(val) = line.trim().strip_prefix("auth_token") {
                    let val = val.trim().trim_start_matches('=').trim().trim_matches('"');
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

fn fetch_json<T: for<'de> Deserialize<'de>>(url: &str) -> Option<T> {
    let client = reqwest::blocking::Client::new();
    let mut req = client.get(url);
    // Read dashboard auth token from config
    if let Some(token) = get_dashboard_token() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().ok()?;
    if !resp.status().is_success() {
        eprintln!("  error: {} returned {}", url, resp.status());
        return None;
    }
    resp.json().ok()
}

fn show_table(
    base: &str,
    channel_filter: Option<&str>,
    verdict_filter: Option<&str>,
    last_minutes: Option<&str>,
    num: usize,
) {
    let traffic: TrafficList = match fetch_json(&format!("{}/traffic", base)) {
        Some(t) => t,
        None => {
            eprintln!("Failed to connect to Aegis at {base}");
            eprintln!("Is Aegis running? Try: aegis --config ~/.aegis/config/config.toml");
            return;
        }
    };

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let cutoff_ms = last_minutes
        .and_then(|s| {
            let s = s.trim_end_matches('m').trim_end_matches("min");
            s.parse::<i64>().ok()
        })
        .map(|mins| now_ms - mins * 60_000);

    let mut entries: Vec<&TrafficSummary> = traffic.entries.iter().rev().collect();

    // Apply time filter
    if let Some(cutoff) = cutoff_ms {
        entries.retain(|e| e.ts_ms >= cutoff);
    }

    // Apply channel filter
    if let Some(cf) = channel_filter {
        entries.retain(|e| {
            e.channel
                .as_deref()
                .map(|c| c.contains(cf))
                .unwrap_or(false)
        });
    }

    // Apply verdict filter
    if let Some(vf) = verdict_filter {
        entries.retain(|e| e.slm_verdict.as_deref() == Some(vf));
    }

    // Take only num entries
    entries.truncate(num);

    if entries.is_empty() {
        eprintln!("No matching traffic entries found.");
        return;
    }

    // Header
    println!();
    println!(
        " {:<5} {:<10} {:<16} {:<9} {:<18} {:<14} {:<8} {:>8}",
        "#", "Time", "Channel", "Trust", "Context", "Model", "SLM", "Duration"
    );
    println!("{}", "━".repeat(106));

    for entry in &entries {
        let time = {
            let secs = entry.ts_ms / 1000;
            let total = secs % 86400;
            let h = (total / 3600) % 24;
            let m = (total % 3600) / 60;
            let s = total % 60;
            format!("{:02}:{:02}:{:02}", h, m, s)
        };

        let channel = entry
            .channel
            .as_deref()
            .unwrap_or("—")
            .chars()
            .take(16)
            .collect::<String>();

        let context = entry
            .context
            .as_deref()
            .map(|c| {
                if c.starts_with("telegram:direct:") {
                    format!("tg:{}", &c[16..])
                } else if c.starts_with("telegram:dm:") {
                    format!("tg:dm:{}", &c[12..])
                } else if c.starts_with("openclaw:web:") {
                    format!("web:{}", &c[13..])
                } else if c.starts_with("cli:local:") {
                    format!("cli:{}", &c[10..])
                } else {
                    c.chars().take(18).collect()
                }
            })
            .unwrap_or_else(|| "—".to_string());

        let trust = entry.trust_level.as_deref().unwrap_or("—");
        let model = entry.model.as_deref().unwrap_or("—");
        let req_tok = estimate_tokens(entry.request_size);
        let resp_tok = estimate_tokens(entry.response_size);

        let slm = match entry.slm_verdict.as_deref() {
            Some("admit") => "admit".to_string(),
            Some("reject") => "REJECT".to_string(),
            Some("quarantine") => "QRNTNE".to_string(),
            Some(v) => v.to_string(),
            None => "—".to_string(),
        };

        let dur = if entry.duration_ms > 1000 {
            format!("{:.1}s", entry.duration_ms as f64 / 1000.0)
        } else {
            format!("{}ms", entry.duration_ms)
        };

        println!(
            " {:<5} {:<10} {:<16} {:<9} {:<18} {:<14} {:<8} {:>8}",
            entry.id, time, channel, trust, context, model, slm, dur
        );
    }

    println!();
    println!(
        "  {} entries shown. Use `aegis trace <ID>` for full detail.",
        entries.len()
    );
    println!();
}

fn show_detail(base: &str, id: u64, show_body: bool) {
    let detail: TrafficDetail = match fetch_json(&format!("{}/traffic/{}", base, id)) {
        Some(d) => d,
        None => {
            eprintln!("Failed to fetch traffic entry #{id}. Is the ID correct?");
            return;
        }
    };

    let e = &detail.entry;
    let model = e
        .model
        .as_deref()
        .or_else(|| {
            e.request_body
                .as_deref()
                .and_then(extract_model)
                .as_deref()
                .map(|_| "")
        })
        .unwrap_or("—");
    let model_display = if model.is_empty() {
        e.request_body
            .as_deref()
            .and_then(extract_model)
            .unwrap_or_else(|| "—".to_string())
    } else {
        model.to_string()
    };
    let req_tok = estimate_tokens(e.request_size);
    let resp_tok = estimate_tokens(e.response_size);
    let total_tok = req_tok + resp_tok;
    let streaming = if e.is_streaming { "yes" } else { "no" };
    let channel = e.channel.as_deref().unwrap_or("—");
    let trust = e.trust_level.as_deref().unwrap_or("—");
    let context = e.context.as_deref().unwrap_or("—");

    let upstream = if e.status == 403 {
        "BLOCKED (never forwarded)".to_string()
    } else {
        format!("→ {}", e.status)
    };

    println!();
    println!("━━━ Request #{} {}", e.id, "━".repeat(58));
    println!(
        "  Time       {}                Duration   {}ms",
        format_ts(e.ts_ms),
        e.duration_ms
    );
    println!("  Channel    {:<28} Trust      {}", channel, trust);
    println!("  Context    {}", context);
    println!("  Route      {} {} {}", e.method, e.path, upstream);
    println!(
        "  Model      {:<28} Streaming  {}",
        model_display, streaming
    );

    // Tokens
    println!();
    println!("  ── Tokens ─────────────────────────────────────────────────────────");
    println!(
        "  Prompt     {:<10} Completion   {:<10} Total   {}",
        req_tok, resp_tok, total_tok
    );

    // SLM Screening
    let verdict_label = match e.slm_verdict.as_deref() {
        Some("admit") => "ADMIT",
        Some("reject") => "REJECT",
        Some("quarantine") => "QUARANTINE",
        Some(v) => v,
        None => "NOT RUN",
    };
    println!();
    println!(
        "  ── SLM Screening ── verdict: {} ───────────────────────────────",
        verdict_label
    );

    if let Some(dur) = e.slm_duration_ms {
        println!(
            "  Deep SLM     {}  {}ms   threat={}/10000",
            verdict_label.to_lowercase(),
            dur,
            e.slm_threat_score.unwrap_or(0)
        );
    } else {
        println!("  (SLM screening not recorded for this entry)");
    }

    // Response Screening (DLP)
    if let Some(ref rs) = e.response_screen {
        let screened = rs
            .get("screened")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let blocked = rs.get("blocked").and_then(|v| v.as_bool()).unwrap_or(false);
        let redactions = rs
            .get("redaction_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        if blocked {
            let reason = rs
                .get("block_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("dangerous operation");
            println!();
            println!("  ── Response Screening ── \x1b[31mBLOCKED\x1b[0m ─────────────────────────");
            println!("  Reason     {}", reason);
        } else if screened {
            println!();
            println!(
                "  ── Response Screening ── \x1b[33m{} redaction{}\x1b[0m ─────────────────────",
                redactions,
                if redactions > 1 { "s" } else { "" }
            );
        } else {
            println!();
            println!("  ── Response Screening ── \x1b[32mclean\x1b[0m ───────────────────────────");
        }

        if let Some(findings) = rs.get("findings").and_then(|v| v.as_array()) {
            for f in findings {
                let cat = f.get("category").and_then(|v| v.as_str()).unwrap_or("?");
                let desc = f.get("description").and_then(|v| v.as_str()).unwrap_or("");
                println!("  \x1b[33m{:<20}\x1b[0m {}", cat, desc);
            }
        }
    }

    // Last user message
    if let Some(ref body) = e.request_body
        && let Some(msg) = extract_last_user_message(body)
    {
        println!();
        println!("  ── Last User Message ──────────────────────────────────────────────");
        // Word-wrap at ~70 chars with indent
        for line in textwrap(&msg, 68) {
            println!("  {}", line);
        }
    }

    // Evidence
    println!();
    println!("  ── Evidence ───────────────────────────────────────────────────────");
    println!("  Chain: recorded");

    // Body
    if show_body {
        if let Some(ref body) = e.request_body {
            println!();
            println!(
                "  ── Request Body ({} bytes) ────────────────────────────────────",
                e.request_size
            );
            let truncated: String = body.chars().take(2000).collect();
            println!("{}", truncated);
        }
        if let Some(ref body) = e.response_body {
            println!();
            println!(
                "  ── Response Body ({} bytes) ───────────────────────────────────",
                e.response_size
            );
            let truncated: String = body.chars().take(2000).collect();
            println!("{}", truncated);
        }
    }

    println!("{}", "━".repeat(70));
    println!();
}

fn show_slm_health(aegis_url: &str) {
    let status_url = format!("{}/aegis/status", aegis_url.trim_end_matches('/'));
    let slm_url = format!("{}/dashboard/api/slm", aegis_url.trim_end_matches('/'));

    println!("  ── SLM Health ─────────────────────────────────────────────────────");

    if let Some(status) = fetch_json::<serde_json::Value>(&status_url) {
        let mode = status.get("mode").and_then(|v| v.as_str()).unwrap_or("?");
        let slm_model = status
            .get("slm_model")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let slm_engine = status
            .get("slm_engine")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let slm_server = status
            .get("slm_server")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        println!("  Engine     {} → {}", slm_engine, slm_server);
        println!("  Model      {}", slm_model);
        println!("  Mode       {}", mode);
    }

    if let Some(slm_data) = fetch_json::<SlmList>(&slm_url)
        && let Some(entries) = slm_data.entries
    {
        if let Some(last) = entries.last() {
            println!(
                "  Last       verdict={} threat={} in {}ms",
                last.action.as_deref().unwrap_or("?"),
                last.threat_score.unwrap_or(0),
                last.screening_ms.unwrap_or(0)
            );
        }
        // Average screening time
        let times: Vec<u64> = entries.iter().filter_map(|e| e.screening_ms).collect();
        if !times.is_empty() {
            let avg = times.iter().sum::<u64>() / times.len() as u64;
            println!("  Avg time   {}ms ({} screenings)", avg, times.len());
        }
    }
    println!();
}

/// Simple text wrapping.
fn textwrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.len() + word.len() + 1 > width && !current.is_empty() {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}
