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
    #[allow(dead_code)]
    status: u16,
    #[allow(dead_code)]
    request_size: usize,
    #[allow(dead_code)]
    response_size: usize,
    duration_ms: u64,
    #[allow(dead_code)]
    is_streaming: bool,
    #[allow(dead_code)]
    slm_duration_ms: Option<u64>,
    slm_verdict: Option<String>,
    slm_threat_score: Option<u32>,
    channel: Option<String>,
    trust_level: Option<String>,
    model: Option<String>,
    #[allow(dead_code)]
    context: Option<String>,
    #[allow(dead_code)]
    response_screen: Option<serde_json::Value>,
    request_id: Option<String>,
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
    #[allow(dead_code)]
    context: Option<String>,
    response_screen: Option<serde_json::Value>,
    #[allow(dead_code)]
    request_id: Option<String>,
    slm_detail: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct ReceiptsResponse {
    #[allow(dead_code)]
    request_id: Option<String>,
    receipts: Option<Vec<ReceiptInfo>>,
}

#[derive(Deserialize, Debug)]
struct ReceiptInfo {
    receipt_type: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    #[allow(dead_code)]
    id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct SlmList {
    entries: Option<Vec<SlmEntry>>,
}

#[derive(Deserialize, Debug)]
struct SlmEntry {
    #[allow(dead_code)]
    ts_ms: Option<i64>,
    action: Option<String>,
    threat_score: Option<u32>,
    screening_ms: Option<u64>,
    #[allow(dead_code)]
    channel: Option<String>,
    #[allow(dead_code)]
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
#[allow(dead_code)]
fn estimate_tokens(size: usize) -> usize {
    size / 4
}

/// Extract the last user message from the request body.
#[allow(dead_code)]
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
#[allow(clippy::too_many_arguments)]
pub fn run(
    aegis_url: &str,
    id: Option<u64>,
    channel_filter: Option<&str>,
    verdict_filter: Option<&str>,
    last_minutes: Option<&str>,
    show_body: bool,
    show_health: bool,
    num: usize,
    watch: bool,
    section: Option<&str>,
    json: bool,
) {
    if watch {
        run_watch(aegis_url, channel_filter, verdict_filter, num);
        return;
    }

    let dashboard_base = format!("{}/dashboard/api", aegis_url.trim_end_matches('/'));

    if let Some(entry_id) = id {
        show_detail(&dashboard_base, entry_id, show_body, section, json);
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

/// Fetch a URL and return the raw JSON string.
fn fetch_raw_json(url: &str) -> Option<String> {
    let client = reqwest::blocking::Client::new();
    let mut req = client.get(url);
    if let Some(token) = get_dashboard_token() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().ok()
}

/// Color an SLM verdict string with ANSI escapes.
fn color_verdict(verdict: &str) -> String {
    match verdict {
        "admit" => format!("\x1b[32m{:<8}\x1b[0m", "admit"),
        "REJECT" | "reject" => format!("\x1b[31m{:<8}\x1b[0m", "REJECT"),
        "QRNTNE" | "quarantine" => format!("\x1b[33m{:<8}\x1b[0m", "QRNTNE"),
        other => format!("{:<8}", other),
    }
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
        " {:<5} {:<10} {:<9} {:<16} {:<9} {:<14} {:<8} {:<6} {:>8}",
        "#", "Time", "ReqID", "Channel", "Trust", "Model", "SLM", "Score", "Duration"
    );
    println!("{}", "\u{2501}".repeat(106));

    for entry in &entries {
        let time = {
            let secs = entry.ts_ms / 1000;
            let total = secs % 86400;
            let h = (total / 3600) % 24;
            let m = (total % 3600) / 60;
            let s = total % 60;
            format!("{:02}:{:02}:{:02}", h, m, s)
        };

        let req_id = entry
            .request_id
            .as_deref()
            .map(|r| r.chars().take(8).collect::<String>())
            .unwrap_or_else(|| "\u{2014}".to_string());

        let channel = entry
            .channel
            .as_deref()
            .unwrap_or("\u{2014}")
            .chars()
            .take(16)
            .collect::<String>();

        let trust = entry.trust_level.as_deref().unwrap_or("\u{2014}");
        let model = entry
            .model
            .as_deref()
            .unwrap_or("\u{2014}")
            .chars()
            .take(14)
            .collect::<String>();

        let slm_raw = match entry.slm_verdict.as_deref() {
            Some("admit") => "admit",
            Some("reject") => "REJECT",
            Some("quarantine") => "QRNTNE",
            Some(v) => v,
            None => "\u{2014}",
        };
        let slm = color_verdict(slm_raw);

        let score = entry
            .slm_threat_score
            .map(|s| s.to_string())
            .unwrap_or_else(|| "\u{2014}".to_string());

        let dur = if entry.duration_ms > 1000 {
            format!("{:.1}s", entry.duration_ms as f64 / 1000.0)
        } else {
            format!("{}ms", entry.duration_ms)
        };

        println!(
            " {:<5} {:<10} {:<9} {:<16} {:<9} {:<14} {} {:<6} {:>8}",
            entry.id, time, req_id, channel, trust, model, slm, score, dur
        );
    }

    println!();
    println!(
        "  {} entries shown. Use `aegis trace <ID>` for full detail.",
        entries.len()
    );
    println!();
}

/// Format a byte size as a human-readable string (e.g. 75454 -> "74KB").
fn format_size(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{}MB", bytes / 1_048_576)
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}

/// Render a dimension bar: filled blocks + empty blocks scaled to 10 chars.
fn dimension_bar(value: u64, max: u64) -> String {
    let filled = if max == 0 {
        0
    } else {
        ((value as f64 / max as f64) * 10.0).round() as usize
    };
    let filled = filled.min(10);
    let empty = 10 - filled;
    format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty))
}

/// Section header with consistent width.
fn section_header(title: &str) {
    let prefix = format!("  \u{2500}\u{2500} {} ", title);
    let padding = if prefix.len() < 75 {
        75 - prefix.len()
    } else {
        3
    };
    println!("{}{}", prefix, "\u{2500}".repeat(padding));
}

fn show_detail(base: &str, id: u64, show_body: bool, section: Option<&str>, json: bool) {
    // --- JSON mode: dump raw API responses and return ---
    if json {
        let traffic_url = format!("{}/traffic/{}", base, id);
        let receipts_url = format!("{}/traffic/{}/receipts", base, id);
        if let Some(raw) = fetch_raw_json(&traffic_url) {
            println!("{}", raw);
        } else {
            eprintln!("Failed to fetch traffic entry #{id}.");
        }
        if let Some(raw) = fetch_raw_json(&receipts_url) {
            println!("{}", raw);
        }
        return;
    }

    let detail: TrafficDetail = match fetch_json(&format!("{}/traffic/{}", base, id)) {
        Some(d) => d,
        None => {
            eprintln!("Failed to fetch traffic entry #{id}. Is the ID correct?");
            return;
        }
    };

    let e = &detail.entry;

    // Fetch receipts once for all sections that need them
    let receipts_url = format!("{}/traffic/{}/receipts", base, id);
    let receipts_resp: Option<ReceiptsResponse> = fetch_json(&receipts_url);
    let receipts: Vec<&ReceiptInfo> = receipts_resp
        .as_ref()
        .and_then(|r| r.receipts.as_ref())
        .map(|v| v.iter().collect())
        .unwrap_or_default();

    let show_all = section.is_none();
    let sec = section.unwrap_or("");

    // === Top banner ===
    if show_all {
        println!();
        println!(
            "\u{2501}\u{2501}\u{2501} Request #{} {}",
            e.id,
            "\u{2501}".repeat(58)
        );
    }

    // === Overview ===
    if show_all || sec == "overview" {
        let model_display = e
            .model
            .as_deref()
            .map(|s| s.to_string())
            .or_else(|| e.request_body.as_deref().and_then(extract_model))
            .unwrap_or_else(|| "\u{2014}".to_string());
        let streaming = if e.is_streaming { "yes" } else { "no" };
        let channel = e.channel.as_deref().unwrap_or("\u{2014}");
        let trust = e.trust_level.as_deref().unwrap_or("\u{2014}");
        let req_id_display = e.request_id.as_deref().unwrap_or("\u{2014}");
        let route = if e.status == 403 {
            format!("{} {} \u{2192} BLOCKED", e.method, e.path)
        } else {
            format!("{} {} \u{2192} {}", e.method, e.path, e.status)
        };

        println!();
        section_header("Overview");
        println!("  {:<13}{}", "Request ID", req_id_display);
        println!("  {:<13}{}", "Time", format_ts(e.ts_ms));
        println!("  {:<13}{}", "Route", route);
        println!(
            "  {:<13}{:<26}{:<13}{}",
            "Model", model_display, "Streaming", streaming
        );
        println!("  {:<13}{:<26}{:<13}{}", "Channel", channel, "Trust", trust);
        println!(
            "  {:<13}{:<26}{:<13}{} \u{2192} {}",
            "Duration",
            format!("{}ms", e.duration_ms),
            "Body",
            format_size(e.request_size),
            format_size(e.response_size)
        );
    }

    // === Screening Layers (SLM section) ===
    if show_all || sec == "slm" {
        let slm = e.slm_detail.as_ref();
        let engine = slm
            .and_then(|s| s.get("engine"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let action_str = slm
            .and_then(|s| s.get("action"))
            .and_then(|v| v.as_str())
            .unwrap_or(e.slm_verdict.as_deref().unwrap_or(""));
        let threat_score = slm
            .and_then(|s| s.get("threat_score"))
            .and_then(|v| v.as_u64())
            .unwrap_or(e.slm_threat_score.map(|s| s as u64).unwrap_or(0));
        let annotation_count = slm
            .and_then(|s| s.get("annotation_count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let screening_ms = slm
            .and_then(|s| s.get("screening_ms"))
            .and_then(|v| v.as_u64())
            .or(e.slm_duration_ms)
            .unwrap_or(0);
        let pass_a_ms = slm
            .and_then(|s| s.get("pass_a_ms"))
            .and_then(|v| v.as_u64());
        let classifier_ms = slm
            .and_then(|s| s.get("classifier_ms"))
            .and_then(|v| v.as_u64());
        let classifier_advisory = slm
            .and_then(|s| s.get("classifier_advisory"))
            .and_then(|v| v.as_bool());

        let has_slm = e.slm_verdict.is_some() || slm.is_some();

        if has_slm {
            println!();
            section_header("Screening Layers");

            // Layer 1: Heuristic
            let heuristic_ran = engine == "heuristic" || pass_a_ms.is_some();
            if heuristic_ran {
                let verdict_display = match action_str {
                    "reject" => "\x1b[31m\u{2588}\u{2588} REJECT\x1b[0m",
                    "admit" => "\x1b[32m\u{2588}\u{2588} ADMIT\x1b[0m",
                    "quarantine" => "\x1b[33m\u{2588}\u{2588} QUARANTINE\x1b[0m",
                    _ => action_str,
                };
                let time_display = if screening_ms < 1 {
                    "<1ms".to_string()
                } else {
                    format!("{}ms", screening_ms)
                };
                let pattern_display = if annotation_count > 0 {
                    format!("  {} patterns", annotation_count)
                } else {
                    String::new()
                };
                println!(
                    "  Layer 1  {:<16}{}   score={}{}   {}",
                    "Heuristic", verdict_display, threat_score, pattern_display, time_display
                );

                // Show annotations
                if let Some(annotations) = slm
                    .and_then(|s| s.get("annotations"))
                    .and_then(|v| v.as_array())
                {
                    for (i, ann) in annotations.iter().enumerate() {
                        let pattern = ann.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
                        let severity = ann.get("severity").and_then(|v| v.as_u64()).unwrap_or(0);
                        let excerpt = ann.get("excerpt").and_then(|v| v.as_str()).unwrap_or("");
                        let excerpt_trunc: String = excerpt.chars().take(50).collect();
                        let connector = if i == annotations.len() - 1 {
                            "\u{2514}\u{2500}"
                        } else {
                            "\u{251c}\u{2500}"
                        };
                        println!(
                            "    {} {:<20}({})  \"{}\"",
                            connector, pattern, severity, excerpt_trunc
                        );
                    }
                }
            }

            // Layer 2: Classifier
            if let Some(cms) = classifier_ms {
                let advisory = classifier_advisory.unwrap_or(false);
                let mode = if advisory { " (advisory)" } else { "" };
                println!(
                    "  Layer 2  {:<16}\u{2713} ran   {}ms{}",
                    "Classifier", cms, mode
                );
            } else if engine == "heuristic"
                && (action_str == "reject" || action_str == "quarantine")
            {
                println!(
                    "  Layer 2  {:<16}\u{2500}\u{2500} not run (heuristic caught first) \u{2500}\u{2500}",
                    "Classifier"
                );
            }

            // Layer 3: Deep SLM
            if engine != "heuristic" && pass_a_ms.is_some() {
                println!(
                    "  Layer 3  {:<16}\u{2713} ran   {}ms",
                    "Deep SLM",
                    pass_a_ms.unwrap_or(0)
                );
            } else if engine == "heuristic"
                && (action_str == "reject" || action_str == "quarantine")
            {
                println!(
                    "  Layer 3  {:<16}\u{2500}\u{2500} not run (heuristic caught first) \u{2500}\u{2500}",
                    "Deep SLM"
                );
            }

            // Layer 4: Metaprompt (check receipts for hints)
            let has_metaprompt = receipts.iter().any(|r| {
                r.receipt_type.as_deref() == Some("MetapromptInjection")
                    || r.outcome
                        .as_deref()
                        .map(|o| o.contains("metaprompt"))
                        .unwrap_or(false)
            });
            if has_metaprompt {
                println!("  Layer 4  {:<16}\u{2713} injected", "Metaprompt");
            }

            // === Threat Dimensions ===
            if let Some(dims) = slm.and_then(|s| s.get("dimensions")) {
                println!();
                section_header("Threat Dimensions");
                let dim_names = [
                    ("injection", "manipulation"),
                    ("exfiltration", "persistence"),
                    ("evasion", ""),
                ];
                for (left, right) in &dim_names {
                    let lv = dims.get(*left).and_then(|v| v.as_u64()).unwrap_or(0);
                    let left_bar = dimension_bar(lv, 10000);
                    let left_str = format!("  {:<14}{} {:>5}", left, left_bar, lv);
                    if !right.is_empty() {
                        let rv = dims.get(*right).and_then(|v| v.as_u64()).unwrap_or(0);
                        let right_bar = dimension_bar(rv, 10000);
                        println!("{}    {:<14}{} {:>5}", left_str, right, right_bar, rv);
                    } else {
                        println!("{}", left_str);
                    }
                }
            }

            // === Holster Decision ===
            let holster_profile = slm
                .and_then(|s| s.get("holster_profile"))
                .and_then(|v| v.as_str());
            let holster_action = slm
                .and_then(|s| s.get("holster_action"))
                .and_then(|v| v.as_str());
            if holster_profile.is_some() || holster_action.is_some() {
                let threshold = slm
                    .and_then(|s| s.get("threshold_exceeded"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let confidence = slm
                    .and_then(|s| s.get("confidence"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let explanation = slm
                    .and_then(|s| s.get("explanation"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                println!();
                section_header("Holster Decision");
                println!(
                    "  {:<13}{}",
                    "Profile",
                    holster_profile.unwrap_or("\u{2014}")
                );
                let action_suffix = if threshold {
                    " (threshold exceeded)"
                } else {
                    ""
                };
                println!(
                    "  {:<13}{}{}",
                    "Action",
                    holster_action.unwrap_or("\u{2014}"),
                    action_suffix
                );
                println!("  {:<13}{}/10000", "Confidence", confidence);
                if !explanation.is_empty() {
                    println!("  {:<13}{}", "Explanation", explanation);
                }
            }
        } else {
            println!();
            section_header("Screening Layers");
            println!("  (SLM screening not recorded for this entry)");
        }
    }

    // === Vault Scanning ===
    if show_all || sec == "vault" {
        let vault_receipts: Vec<&&ReceiptInfo> = receipts
            .iter()
            .filter(|r| {
                r.receipt_type
                    .as_deref()
                    .map(|t| t.eq_ignore_ascii_case("VaultDetection"))
                    .unwrap_or(false)
            })
            .collect();

        if !vault_receipts.is_empty() || show_all {
            println!();
            section_header("Vault Scanning");
            if vault_receipts.is_empty() {
                println!("  Request      \u{2713} clean");
                println!("  Response     \u{2713} clean");
            } else {
                for vr in &vault_receipts {
                    let outcome = vr.outcome.as_deref().unwrap_or("detected");
                    let action = vr.action.as_deref().unwrap_or("");
                    let label = if action.contains("response") {
                        "Response"
                    } else {
                        "Request"
                    };
                    println!("  {:<13}\u{26a0} {}", label, outcome);
                }
            }
        }
    }

    // === Write Barrier ===
    if show_all || sec == "barrier" {
        let barrier_receipts: Vec<&&ReceiptInfo> = receipts
            .iter()
            .filter(|r| {
                r.receipt_type
                    .as_deref()
                    .map(|t| t.eq_ignore_ascii_case("WriteBarrier"))
                    .unwrap_or(false)
            })
            .collect();

        if !barrier_receipts.is_empty() {
            println!();
            section_header("Write Barrier");
            for br in &barrier_receipts {
                let outcome = br.outcome.as_deref().unwrap_or("barrier triggered");
                println!("  \u{26a0} {}", outcome);
            }
        }
    }

    // === Response Screening (DLP) ===
    if (show_all || sec == "dlp")
        && let Some(ref rs) = e.response_screen
    {
        let blocked = rs.get("blocked").and_then(|v| v.as_bool()).unwrap_or(false);
        let redactions = rs
            .get("redaction_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        println!();
        section_header("Response Screening (DLP)");

        if blocked {
            let reason = rs
                .get("block_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("dangerous operation");
            println!(
                "  {:<13}\x1b[31mBLOCKED\x1b[0m \u{2014} {}",
                "Status", reason
            );
        } else if redactions > 0 {
            println!(
                "  {:<13}{} redaction{}",
                "Status",
                redactions,
                if redactions > 1 { "s" } else { "" }
            );
        } else {
            println!("  {:<13}\x1b[32mclean\x1b[0m", "Status");
        }

        if let Some(findings) = rs.get("findings").and_then(|v| v.as_array()) {
            for f in findings {
                let cat = f.get("category").and_then(|v| v.as_str()).unwrap_or("?");
                let desc = f.get("description").and_then(|v| v.as_str()).unwrap_or("");
                let loc_suffix = match f.get("location").and_then(|v| v.as_str()) {
                    Some("message_content") => "  [message]",
                    Some("tool_call") => "  [tool call]",
                    Some("api_protocol") => "  [API metadata]",
                    _ => "",
                };
                println!("    {:<10} {}{}", cat, desc, loc_suffix);
            }
        }
    }

    // === Conversation ===
    if (show_all || sec == "conversation")
        && let Some(ref chat) = detail.chat
        && let Some(messages) = chat.as_array()
        && !messages.is_empty()
    {
        println!();
        section_header("Conversation");
        for msg in messages {
            let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("?");
            let content = msg.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let display = if role == "system" {
                // Truncate system message to first line
                let first_line = content.lines().next().unwrap_or(content);
                let trunc: String = first_line.chars().take(80).collect();
                if content.len() > trunc.len() {
                    format!("{}...", trunc)
                } else {
                    trunc
                }
            } else {
                let trunc: String = content.chars().take(200).collect();
                if content.len() > trunc.len() {
                    format!("{}...", trunc)
                } else {
                    trunc
                }
            };
            println!("  \x1b[2m[{}]\x1b[0m     {}", role, display);
        }
    }

    // === Evidence Chain ===
    if show_all || sec == "evidence" {
        println!();
        section_header("Evidence Chain");
        if receipts.is_empty() {
            println!("  (no receipts found)");
        } else {
            let short_req_id = e
                .request_id
                .as_deref()
                .map(|r| r.chars().take(12).collect::<String>())
                .unwrap_or_else(|| "\u{2014}".to_string());
            println!(
                "  {} receipts linked by request_id {}",
                receipts.len(),
                short_req_id
            );
            for (i, r) in receipts.iter().enumerate() {
                let rtype = r.receipt_type.as_deref().unwrap_or("unknown");
                let outcome = r.outcome.as_deref().unwrap_or("");
                let short_outcome: String = outcome.chars().take(60).collect();
                println!("  #{:<2} {:<18} {}", i + 1, rtype, short_outcome);
            }
        }
    }

    // === TRUSTMARK ===
    if sec == "trustmark" {
        let tm_url = format!("{}/trustmark", base);
        let tm_data: Option<serde_json::Value> = fetch_json(&tm_url);
        println!();
        section_header("TRUSTMARK");
        if let Some(tm) = tm_data {
            let total = tm.get("total").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let total_bp = (total * 10000.0).round() as u32;
            let mode = tm.get("mode").and_then(|v| v.as_str()).unwrap_or("warden");
            let tier = tm
                .get("tier")
                .and_then(|v| v.get("current"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            println!("  {:<20}{}/10000 ({} mode)", "Score", total_bp, mode);
            println!("  {:<20}{}", "Tier", tier);
            println!();
            println!("  Dimensions:");

            let thresholds = [
                ("persona_integrity", 0.95),
                ("chain_integrity", 0.95),
                ("vault_hygiene", 0.90),
                ("temporal_consistency", 0.80),
                ("contribution_volume", 0.50),
                ("relay_reliability", 0.50),
            ];

            if let Some(dims) = tm.get("dimensions").and_then(|v| v.as_array()) {
                for d in dims {
                    let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let value = d.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let value_bp = (value * 10000.0).round() as u32;
                    let threshold = thresholds
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, t)| *t)
                        .unwrap_or(0.50);

                    // Skip relay in warden mode
                    if name == "relay_reliability" && mode == "warden" {
                        let bar = "\u{2591}".repeat(10);
                        println!(
                            "  {:<20} {}  {:>5}  excluded (warden mode)",
                            name, bar, "\u{2014}"
                        );
                        continue;
                    }

                    let filled = ((value * 10.0).round() as usize).min(10);
                    let empty = 10 - filled;
                    let bar = format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty));
                    let healthy = value >= threshold;
                    let icon = if healthy { "\u{2713}" } else { "\u{26a0}" };
                    let health_label = if healthy { "healthy" } else { "degraded" };
                    let threshold_bp = (threshold * 10000.0).round() as u32;
                    println!(
                        "  {:<20} {}  {:>5}  {} {} (>= {})",
                        name, bar, value_bp, icon, health_label, threshold_bp
                    );
                }
            }
        } else {
            println!("  (unable to fetch TRUSTMARK data)");
        }
    }

    // === Raw bodies (existing --body flag) ===
    if show_body {
        if let Some(ref body) = e.request_body {
            println!();
            section_header(&format!("Request Body ({} bytes)", e.request_size));
            let truncated: String = body.chars().take(2000).collect();
            println!("{}", truncated);
        }
        if let Some(ref body) = e.response_body {
            println!();
            section_header(&format!("Response Body ({} bytes)", e.response_size));
            let truncated: String = body.chars().take(2000).collect();
            println!("{}", truncated);
        }
    }

    // === Footer ===
    if show_all {
        println!();
        println!("{}", "\u{2501}".repeat(75));
        println!();
    }
}

fn run_watch(
    aegis_url: &str,
    channel_filter: Option<&str>,
    verdict_filter: Option<&str>,
    num: usize,
) {
    let dashboard_base = format!("{}/dashboard/api", aegis_url.trim_end_matches('/'));
    let status_url = format!("{}/aegis/status", aegis_url.trim_end_matches('/'));

    loop {
        // Clear screen
        print!("\x1b[2J\x1b[H");

        // Fetch status
        let status: Option<serde_json::Value> = fetch_json(&status_url);

        // Header
        println!("  \x1b[1maegis trace\x1b[0m \u{2014} live monitoring (Ctrl+C to exit)");
        if let Some(ref s) = status {
            let mode = s.get("mode").and_then(|v| v.as_str()).unwrap_or("?");
            let uptime = s.get("uptime_secs").and_then(|v| v.as_u64()).unwrap_or(0);
            let receipts = s.get("receipt_count").and_then(|v| v.as_u64()).unwrap_or(0);
            let trustmark_bp = s
                .get("trustmark_score_bp")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let uptime_str = if uptime > 3600 {
                format!("{}h {}m", uptime / 3600, (uptime % 3600) / 60)
            } else {
                format!("{}m", uptime / 60)
            };
            let tm_indicator = if trustmark_bp > 0 {
                let tm_icon = if trustmark_bp >= 8000 {
                    "\u{2713}"
                } else if trustmark_bp >= 6000 {
                    "\u{26a0}"
                } else {
                    "\u{2717}"
                };
                format!(" | TRUSTMARK: {} {}", trustmark_bp, tm_icon)
            } else {
                String::new()
            };
            println!(
                "  Mode: {}{} | Uptime: {} | Evidence: {} receipts",
                mode, tm_indicator, uptime_str, receipts
            );
        }
        println!("  {}", "\u{2500}".repeat(90));

        // Table
        show_table(&dashboard_base, channel_filter, verdict_filter, None, num);

        // Refresh
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn show_slm_health(aegis_url: &str) {
    let status_url = format!("{}/aegis/status", aegis_url.trim_end_matches('/'));
    let slm_url = format!("{}/dashboard/api/slm", aegis_url.trim_end_matches('/'));

    println!(
        "  \u{2500}\u{2500} SLM Health \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}"
    );

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
        println!("  Engine     {} \u{2192} {}", slm_engine, slm_server);
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
#[allow(dead_code)]
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
