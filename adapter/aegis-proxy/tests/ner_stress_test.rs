//! Stress test: run diverse real-world text through the full screen_response
//! pipeline with NER loaded. Any unexpected finding is a potential false positive.
//!
//! These inputs should produce ZERO findings — they contain no PII.

use std::path::PathBuf;

fn model_dir() -> PathBuf {
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/pii-ner"),
        PathBuf::from("/home/aegis/aegis/neural-commons/models/pii-ner"),
    ];
    for p in &candidates {
        if p.join("model.onnx").exists() {
            return p.clone();
        }
    }
    panic!("NER model not found");
}

fn init_ner() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        aegis_proxy::ner_pii::init(&model_dir());
        assert!(aegis_proxy::ner_pii::is_available());
    });
}

fn screen(input: &str) -> (String, aegis_proxy::response_screen::ResponseScreenResult) {
    init_ner();
    aegis_proxy::response_screen::screen_response(input)
}

/// Assert NO findings at all — text must pass completely clean.
fn assert_clean(label: &str, input: &str) {
    let (text, result) = screen(input);
    assert!(
        result.findings.is_empty(),
        "[{label}] False positive!\n  Input: {input:?}\n  Findings: {:?}\n  Output: {text}",
        result.findings
    );
    assert_eq!(text, input, "[{label}] Text was modified");
}

// ═══════════════════════════════════════════════════════════════
//  Business / corporate language
// ═══════════════════════════════════════════════════════════════

#[test]
fn business_language() {
    let cases = [
        (
            "quarterly_report",
            "Q3 revenue grew 12% year-over-year, driven by enterprise adoption in EMEA.",
        ),
        (
            "meeting_notes",
            "The board meeting on Thursday covered budget allocation for the Austin expansion.",
        ),
        (
            "roadmap",
            "We plan to launch the beta in Helsinki during August and GA in November.",
        ),
        (
            "hiring",
            "The engineering team in Dublin is hiring 5 senior developers this quarter.",
        ),
        ("okr", "OKR: Reduce p99 latency to 200ms by end of March."),
        (
            "strategy",
            "Our Singapore office will lead the APAC go-to-market strategy.",
        ),
        (
            "contract",
            "The contract was signed on January 15 and expires December 31, 2027.",
        ),
        (
            "budget",
            "Total budget: $2.4 million for fiscal year 2026-2027.",
        ),
        (
            "standup",
            "Yesterday I fixed the memory leak in the Chicago data pipeline. Today I'll work on monitoring.",
        ),
        (
            "retro",
            "The sprint retrospective highlighted issues with the Denver deployment last Tuesday.",
        ),
    ];
    for (label, input) in cases {
        assert_clean(label, input);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Technical / engineering content
// ═══════════════════════════════════════════════════════════════

#[test]
fn engineering_content() {
    let cases = [
        (
            "git_log",
            "commit abc123: Fix null pointer in Portland module (merged March 3)",
        ),
        (
            "error_log",
            "ERROR 2026-03-29 14:23:01 [worker-7] Connection timeout after 30000ms",
        ),
        (
            "config",
            "Set max_connections=500, timeout=30s, region=us-east-1",
        ),
        (
            "metrics",
            "CPU: 78%, Memory: 62/128 GB, Disk: 450 GB used, Uptime: 42 days",
        ),
        (
            "deploy",
            "Deployed v2.8.1 to production-east at 09:15 UTC on March 28.",
        ),
        (
            "incident",
            "Incident #4521: Database failover in Frankfurt at 03:47 caused 12 minutes of downtime.",
        ),
        (
            "arch",
            "The service mesh routes traffic through the Amsterdam proxy before reaching the Milan backend.",
        ),
        (
            "perf",
            "Benchmark: 33 tokens/sec on Strix Halo, 256 GB/s memory bandwidth, 128 GB LPDDR5X.",
        ),
        (
            "ci",
            "Pipeline #8847 passed: 136 tests in 1.66 seconds, 0 failures, coverage 87%.",
        ),
        (
            "docker",
            "Container image size: 892 MB, base: Ubuntu 24.04, exposed port: 8080.",
        ),
    ];
    for (label, input) in cases {
        assert_clean(label, input);
    }
}

// ═══════════════════════════════════════════════════════════════
//  News / general knowledge
// ═══════════════════════════════════════════════════════════════

#[test]
fn news_style_content() {
    let cases = [
        (
            "weather",
            "Temperatures in Moscow dropped to -15°C on Wednesday, with more snow expected Friday.",
        ),
        (
            "sports",
            "The match in Barcelona ended 3-1, with goals scored in the 12th, 45th, and 78th minutes.",
        ),
        (
            "travel",
            "Flights from Boston to Rome start at $450 round trip in April.",
        ),
        (
            "food",
            "The restaurant in Kyoto serves 200 customers daily and has been open since March 2019.",
        ),
        (
            "history",
            "The treaty was signed in Vienna on June 12, 1815.",
        ),
        (
            "science",
            "The telescope in Hawaii captured images of a galaxy 13.2 billion light-years away.",
        ),
        (
            "economy",
            "GDP growth in Tokyo's metropolitan area reached 2.3% in Q4.",
        ),
        (
            "education",
            "The university in Cambridge enrolled 12,000 students for the September 2025 term.",
        ),
        (
            "tech_news",
            "The chip manufactured in Seoul uses a 3nm process and contains 50 billion transistors.",
        ),
        (
            "culture",
            "The museum in Cairo received 1.2 million visitors between January and June.",
        ),
    ];
    for (label, input) in cases {
        assert_clean(label, input);
    }
}

// ═══════════════════════════════════════════════════════════════
//  LLM / AI responses (common in proxy traffic)
// ═══════════════════════════════════════════════════════════════

#[test]
fn llm_response_patterns() {
    let cases = [
        (
            "code_review",
            "The function on line 42 has a potential buffer overflow. Consider using bounds checking.",
        ),
        (
            "explanation",
            "React components re-render when state or props change. Use useMemo to optimize expensive calculations.",
        ),
        (
            "list",
            "Here are the top 5 programming languages in 2026:\n1. Python\n2. Rust\n3. TypeScript\n4. Go\n5. Swift",
        ),
        (
            "comparison",
            "PostgreSQL handles complex queries better than MySQL, but MySQL has faster simple reads.",
        ),
        (
            "debugging",
            "The error on line 128 occurs because the variable is undefined. Initialize it before the loop.",
        ),
        (
            "summary",
            "In summary, the application processes 10,000 requests per minute with an average latency of 45ms.",
        ),
        (
            "recommendation",
            "I recommend upgrading from version 2.1 to version 3.0 before the end of April.",
        ),
        (
            "tutorial",
            "Step 1: Install Node.js 18 or later. Step 2: Run npm install. Step 3: Start the dev server on port 3000.",
        ),
        (
            "math",
            "The probability is 0.73, which means roughly 73 out of 100 trials will succeed.",
        ),
        (
            "planning",
            "Phase 1 runs from May through July. Phase 2 starts in August and completes by October 31.",
        ),
    ];
    for (label, input) in cases {
        assert_clean(label, input);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Edge cases — tricky patterns that might trip the model
// ═══════════════════════════════════════════════════════════════

#[test]
fn edge_cases() {
    let cases = [
        (
            "product_name",
            "The new Galaxy S26 Ultra ships in February at $1,199.",
        ),
        (
            "version_dots",
            "Upgrade from 10.15.7 to 14.2.1 for the latest security patches.",
        ),
        (
            "coordinates",
            "The data center is located at coordinates 47.6, -122.3.",
        ),
        ("ip_like", "Bind the server to 0.0.0.0 on port 443."),
        (
            "percentage",
            "Success rate improved from 85% to 97% after the fix.",
        ),
        (
            "model_name",
            "Qwen3-30B-A3B achieves 81.5 tokens per second on Vulkan.",
        ),
        (
            "file_sizes",
            "The model weights are 17.28 GiB, quantized to Q4_K_M.",
        ),
        (
            "currency",
            "The project cost EUR 250,000, under the EUR 300,000 budget.",
        ),
        (
            "time_zones",
            "The meeting is at 9:00 AM PST / 12:00 PM EST / 5:00 PM GMT.",
        ),
        (
            "ranges",
            "Acceptable values are between 18 and 65, inclusive.",
        ),
        (
            "acronyms",
            "The HIPAA audit of the PHI handling in the EHR system is due by EOD Friday.",
        ),
        (
            "mixed_numbers",
            "Batch size 2048, context 4096, 16 heads, 32 layers, hidden dim 4096.",
        ),
    ];
    for (label, input) in cases {
        assert_clean(label, input);
    }
}
