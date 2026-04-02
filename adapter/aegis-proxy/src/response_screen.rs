//! Response-side screening: DLP, tool call analysis, PII/PHI detection.
//!
//! Screens upstream LLM responses before returning to the client.
//! All detection is heuristic (regex) — no SLM needed for responses
//! because the patterns are deterministic.
//!
//! Pipeline:
//!   1. Tool call analyzer — detect dangerous function calls (exec, shell)
//!   2. DLP scanner — credentials, system prompt, env vars, PII, PHI, machine recon
//!   3. Redact or block based on findings

use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

/// Result of screening a response.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseScreenResult {
    /// Whether the response was modified.
    pub screened: bool,
    /// Number of redactions applied.
    pub redaction_count: u32,
    /// Whether the response should be blocked entirely (dangerous tool call).
    pub blocked: bool,
    /// Block reason (if blocked).
    pub block_reason: Option<String>,
    /// Categories of findings.
    pub findings: Vec<ResponseFinding>,
}

/// A single finding from response screening.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseFinding {
    /// Category: "credential", "pii", "phi", "system_prompt", "env_var",
    /// "machine_recon", "file_content", "agent_identity", "dangerous_tool"
    pub category: String,
    /// Short description.
    pub description: String,
    /// Original matched text (what was redacted). For warden eyes only —
    /// never sent to the client.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matched_values: Vec<String>,
    /// Where in the response this finding was located.
    /// "message_content" = in the assistant's actual reply
    /// "api_protocol" = in JSON metadata (id, model, system_fingerprint, etc.)
    /// "tool_call" = in a tool call argument
    /// "unknown" = could not determine location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl ResponseScreenResult {
    pub fn clean() -> Self {
        Self {
            screened: false,
            redaction_count: 0,
            blocked: false,
            block_reason: None,
            findings: Vec::new(),
        }
    }
}

/// Screen a response body WITHOUT trust policy (backward compat).
pub fn screen_response(body: &str) -> (String, ResponseScreenResult) {
    // Default: use Unknown policy (strictest)
    screen_response_with_policy(
        body,
        &crate::trust_policy::policy_for(aegis_schemas::TrustLevel::Unknown),
    )
}

/// Screen a response body with trust-aware policy.
/// This is the single entry point for all response screening.
pub fn screen_response_with_policy(
    body: &str,
    policy: &crate::trust_policy::TrustPolicy,
) -> (String, ResponseScreenResult) {
    let mut result = ResponseScreenResult::clean();
    let mut text = body.to_string();

    // Layer 1: Tool call analysis — trust-aware
    if let Some(tool_finding) = check_tools_with_policy(&text, policy) {
        result.blocked = true;
        result.block_reason = Some(tool_finding.description.clone());
        result.findings.push(tool_finding);
        return (text, result);
    }

    // Layer 2: DLP scanning + redaction
    let patterns = get_dlp_patterns();
    for p in patterns {
        let matches: Vec<String> = p
            .regex
            .find_iter(&text)
            .map(|m| {
                // Truncate long matches for storage (max 100 chars each)
                let s = m.as_str();
                if s.len() > 100 {
                    format!("{}...", &s[..97])
                } else {
                    s.to_string()
                }
            })
            .collect();
        if !matches.is_empty() {
            let count = matches.len() as u32;
            let new_text = p.regex.replace_all(&text, p.replacement).to_string();
            result.redaction_count += count;
            result.findings.push(ResponseFinding {
                category: p.category.to_string(),
                description: p.description.to_string(),
                matched_values: matches,
                location: None,
            });
            text = new_text;
        }
    }

    // Layer 3: NER-based PII detection (person names).
    //
    // Uses GDPR/NIST-compliant filtering: a single first name ("Mark") is NOT
    // PII. Only identifiable information is flagged:
    //   - Full names (first + last): "Sarah Johnson"
    //   - Title + surname: "Mr. Tanaka", "Dr. Kim"
    //   - Structured: "ZHANG, WEI"
    //
    // Supports both DistilBERT-NER (PER/LOC/ORG/MISC) and legacy XLM-RoBERTa
    // (GIVENNAME/SURNAME/...) label formats.
    #[cfg(feature = "ner")]
    {
        let ner_entities = crate::ner_pii::detect_entities(&text);

        for entity in &ner_entities {
            // Map entity type to DLP category.
            // Only person-name types are actionable — LOC/ORG/MISC/DATE/etc are skipped.
            let is_name_type = match entity.entity_type.as_str() {
                // DistilBERT-NER labels
                "PER" => true,
                // XLM-RoBERTa legacy labels (backward compat if old model loaded)
                "GIVENNAME" | "SURNAME" | "TITLE" => true,
                // Everything else: not actionable PII from NER
                // (emails, phones, SSNs, credentials are caught by regex Layer 2)
                _ => false,
            };

            if !is_name_type {
                continue;
            }

            // GDPR/NIST filter: a single first name is NOT identifiable PII.
            // Only flag full names, title+surname, or structured formats.
            if !crate::ner_pii::is_pii_name(&entity.text) {
                continue;
            }

            // Skip if already caught by regex
            let already_caught = result.findings.iter().any(|f| {
                f.matched_values
                    .iter()
                    .any(|v| v.contains(&entity.text) || entity.text.contains(v.as_str()))
            });

            let description = format!(
                "NER: person name detected ({})",
                entity.entity_type.to_lowercase()
            );

            if !already_caught {
                result.redaction_count += 1;
                result.findings.push(ResponseFinding {
                    category: "pii".to_string(),
                    description,
                    matched_values: vec![entity.text.clone()],
                    location: None,
                });
                // Redact the entity text
                text = text.replace(
                    &entity.text,
                    &format!("[REDACTED:{}]", entity.entity_type.to_lowercase()),
                );
            }
        }
    }

    result.screened = result.redaction_count > 0;

    // Classify the location of each finding post-hoc
    for finding in &mut result.findings {
        if finding.location.is_none() {
            finding.location = Some(classify_finding_location(finding, body));
        }
    }

    // Apply DLP mode based on trust policy
    match policy.dlp_mode {
        crate::trust_policy::DlpMode::LogOnly => {
            // Don't redact — return original text but keep findings for logging
            (body.to_string(), result)
        }
        crate::trust_policy::DlpMode::RedactCredentials => {
            // Only keep redactions for credential categories
            if result.screened {
                let cred_cats = ["credential", "env_var", "system_prompt", "agent_identity"];
                let has_creds = result
                    .findings
                    .iter()
                    .any(|f| cred_cats.contains(&f.category.as_str()));
                if has_creds {
                    (text, result)
                } else {
                    // Non-credential findings: log but don't redact
                    (body.to_string(), result)
                }
            } else {
                (text, result)
            }
        }
        crate::trust_policy::DlpMode::RedactAll => {
            // Redact everything found
            (text, result)
        }
        crate::trust_policy::DlpMode::BlockOnFinding => {
            // Block the entire response if anything was found
            if result.screened {
                result.blocked = true;
                result.block_reason =
                    Some("response contained sensitive data (unknown trust)".to_string());
            }
            (text, result)
        }
    }
}

/// Classify where in the response a finding was located.
/// Checks matched values against message content, tool call arguments,
/// and falls back to "api_protocol" for metadata fields.
fn classify_finding_location(finding: &ResponseFinding, body: &str) -> String {
    // Try to parse as OpenAI chat completion JSON
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return "unknown".to_string();
    };

    // Extract message content from all choices
    let content: String = json
        .get("choices")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("message"))
                .filter_map(|m| m.get("content"))
                .filter_map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    // Extract tool call arguments
    let tool_args: Vec<&str> = json
        .get("choices")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("message"))
                .filter_map(|m| m.get("tool_calls"))
                .filter_map(|tc| tc.as_array())
                .flat_map(|calls| calls.iter())
                .filter_map(|call| call.get("function"))
                .filter_map(|f| f.get("arguments"))
                .filter_map(|a| a.as_str())
                .collect()
        })
        .unwrap_or_default();

    // Check each matched value against content and tool args
    for val in &finding.matched_values {
        if content.contains(val.as_str()) {
            return "message_content".to_string();
        }
        for arg in &tool_args {
            if arg.contains(val.as_str()) {
                return "tool_call".to_string();
            }
        }
    }

    "api_protocol".to_string()
}

/// Check tool calls against trust policy.
fn check_tools_with_policy(
    body: &str,
    policy: &crate::trust_policy::TrustPolicy,
) -> Option<ResponseFinding> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;

    // Collect all tool names from the response
    let mut tool_names = Vec::new();

    // OpenAI format
    if let Some(calls) = json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array())
    {
        for call in calls {
            if let Some(name) = call
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
            {
                tool_names.push(name.to_string());
            }
        }
    }

    // Anthropic format
    if let Some(blocks) = json.get("content").and_then(|c| c.as_array()) {
        for block in blocks {
            if block.get("type").and_then(|t| t.as_str()) == Some("tool_use")
                && let Some(name) = block.get("name").and_then(|n| n.as_str())
            {
                tool_names.push(name.to_string());
            }
        }
    }

    // Check each tool against policy
    for name in &tool_names {
        if let Some(reason) = crate::trust_policy::check_tool_allowed(name, policy) {
            return Some(ResponseFinding {
                category: "blocked_tool".to_string(),
                description: reason,
                matched_values: vec![name.clone()],
                location: Some("tool_call".to_string()),
            });
        }
    }

    None
}

/// Legacy: Check for dangerous tool calls (hardcoded list). Kept for tests.
#[allow(dead_code)]
fn check_dangerous_tools(body: &str) -> Option<ResponseFinding> {
    // Parse as JSON to check for tool_calls / function_call
    let json: serde_json::Value = serde_json::from_str(body).ok()?;

    // Check OpenAI format: choices[].message.tool_calls[].function.name
    let tool_calls = json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|choices| choices.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array());

    // Also check Anthropic format: content[].type == "tool_use"
    let anthropic_tools = json
        .get("content")
        .and_then(|c| c.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                .collect::<Vec<_>>()
        });

    let dangerous_names = [
        "exec",
        "execute",
        "shell",
        "bash",
        "cmd",
        "run_command",
        "system",
        "subprocess",
        "eval",
        "os_command",
    ];

    // Check OpenAI tool calls
    if let Some(calls) = tool_calls {
        for call in calls {
            let name = call
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let name_lower = name.to_lowercase();
            if dangerous_names.iter().any(|d| name_lower.contains(d)) {
                return Some(ResponseFinding {
                    category: "dangerous_tool".to_string(),
                    description: format!("dangerous tool call: {name}"),
                    matched_values: vec![name.to_string()],
                    location: Some("tool_call".to_string()),
                });
            }
        }
    }

    // Check Anthropic tool calls
    if let Some(tools) = anthropic_tools {
        for tool in tools {
            let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let name_lower = name.to_lowercase();
            if dangerous_names.iter().any(|d| name_lower.contains(d)) {
                return Some(ResponseFinding {
                    category: "dangerous_tool".to_string(),
                    description: format!("dangerous tool call: {name}"),
                    matched_values: vec![name.to_string()],
                    location: Some("tool_call".to_string()),
                });
            }
        }
    }

    None
}

/// A single DLP detection pattern.
struct DlpPattern {
    regex: Regex,
    category: &'static str,
    description: &'static str,
    replacement: &'static str,
}

/// DLP patterns for response screening.
fn get_dlp_patterns() -> &'static Vec<DlpPattern> {
    static PATTERNS: OnceLock<Vec<DlpPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // ── Credentials ──
            DlpPattern { regex: Regex::new(r"(?i)(sk-[a-zA-Z0-9_-]{20,}|sk-ant-[a-zA-Z0-9_-]{20,})").unwrap(), category: "credential", description: "API key detected", replacement: "[REDACTED:key]" },
            DlpPattern { regex: Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|bearer)\s*[=:]\s*["']?[A-Za-z0-9_\-/.]{16,}["']?"#).unwrap(), category: "credential", description: "credential pattern", replacement: "[REDACTED:credential]" },
            DlpPattern { regex: Regex::new(r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----").unwrap(), category: "credential", description: "private key", replacement: "[REDACTED:private_key]" },
            // ── System prompt ──
            DlpPattern { regex: Regex::new(r"\[AEGIS SECURITY RULES[^\]]*\]").unwrap(), category: "system_prompt", description: "Aegis metaprompt leaked", replacement: "[REDACTED:system_config]" },
            DlpPattern { regex: Regex::new(r"(?i)you\s+are\s+a\s+personal\s+assistant\s+running\s+inside\s+OpenClaw").unwrap(), category: "system_prompt", description: "agent system prompt leaked", replacement: "[REDACTED:system_config]" },
            // ── Environment variables ──
            DlpPattern { regex: Regex::new(r"(?i)(ANTHROPIC_API_KEY|OPENAI_API_KEY|DATABASE_URL|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|SLACK_TOKEN|TELEGRAM_BOT_TOKEN)\s*=\s*\S+").unwrap(), category: "env_var", description: "environment variable leaked", replacement: "[REDACTED:env_var]" },
            // ── Machine recon ──
            DlpPattern { regex: Regex::new(r"/home/[a-zA-Z0-9_-]+/").unwrap(), category: "machine_recon", description: "home directory path leaked", replacement: "[REDACTED:path]/" },
            DlpPattern { regex: Regex::new(r"(?i)hostname:\s*\S+|uname\s*-a\s*.*Linux\s+\S+").unwrap(), category: "machine_recon", description: "hostname/OS info leaked", replacement: "[REDACTED:machine_info]" },
            DlpPattern { regex: Regex::new(r"(?:^|\n)\s*(?:tcp|udp)\s+\d+\s+\d+\s+[\d.:]+\s+[\d.:]+\s+\w+").unwrap(), category: "machine_recon", description: "network connection info leaked", replacement: "[REDACTED:network_info]" },
            // ── File content ──
            DlpPattern { regex: Regex::new(r"root:[x*]:\d+:\d+:").unwrap(), category: "file_content", description: "/etc/passwd content leaked", replacement: "[REDACTED:file_content]" },
            DlpPattern { regex: Regex::new(r"(?i)ssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{40,}").unwrap(), category: "file_content", description: "SSH key leaked", replacement: "[REDACTED:ssh_key]" },
            // ── Agent identity ──
            DlpPattern { regex: Regex::new(r"(?i)(bot[_\s]?id|identity[_\s]?key|fingerprint)\s*[:=]\s*[0-9a-f]{16,}").unwrap(), category: "agent_identity", description: "agent identity leaked", replacement: "[REDACTED:agent_id]" },
            // ── PII ──
            DlpPattern { regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(), category: "pii", description: "SSN pattern", replacement: "[REDACTED:ssn]" },
            DlpPattern { regex: Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap(), category: "pii", description: "credit card number", replacement: "[REDACTED:cc]" },
            DlpPattern { regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(), category: "pii", description: "email address", replacement: "[REDACTED:email]" },
            // ── PHI ──
            DlpPattern { regex: Regex::new(r"(?i)(MRN|medical\s+record|patient\s+id)\s*[:=]\s*\S+").unwrap(), category: "phi", description: "medical record identifier", replacement: "[REDACTED:phi]" },
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ═══════════════════════════════════════════════════════════════
    //  FALSE POSITIVES — these must NOT be flagged as PII
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn month_names_not_pii() {
        // Standalone month names must never be flagged
        let months = [
            "The meeting is in March.",
            "January was cold this year.",
            "We launched the product in September 2025.",
            "The deadline is February 14.",
            "Report for Q1: January, February, March.",
        ];
        for input in months {
            let (text, result) = screen_response(input);
            assert!(
                !result.screened,
                "False positive on month name: {input} — findings: {:?}",
                result.findings
            );
            assert_eq!(text, input, "Text was modified for: {input}");
        }
    }

    #[test]
    fn dates_not_pii() {
        // Ordinary dates should not be flagged
        let dates = [
            "The event is on March 15, 2026.",
            "Updated: 2025-12-01",
            "Next review: June 30.",
            "Created on Monday, April 7th.",
            "Timestamp: 2026-03-29T09:12:53Z",
        ];
        for input in dates {
            let (text, result) = screen_response(input);
            let date_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.category == "pii" && f.description.to_lowercase().contains("date"))
                .collect();
            assert!(
                date_findings.is_empty(),
                "Date falsely flagged as PII: {input} — findings: {:?}",
                date_findings
            );
        }
    }

    #[test]
    fn times_not_pii() {
        // Ordinary times should not be flagged
        let times = [
            "The meeting is at 3:00 PM.",
            "Server rebooted at 14:30 UTC.",
            "Logs from 09:15:32.001 show the error.",
        ];
        for input in times {
            let (text, result) = screen_response(input);
            let time_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.category == "pii" && f.description.to_lowercase().contains("time"))
                .collect();
            assert!(
                time_findings.is_empty(),
                "Time falsely flagged as PII: {input} — findings: {:?}",
                time_findings
            );
        }
    }

    #[test]
    fn city_names_in_general_context_not_pii() {
        // City names in non-address contexts should not be flagged
        let inputs = [
            "The capital of France is Paris.",
            "New York has many skyscrapers.",
            "The server is hosted in London.",
        ];
        for input in inputs {
            let (text, result) = screen_response(input);
            assert!(
                !result.screened,
                "City name falsely flagged: {input} — findings: {:?}",
                result.findings
            );
            assert_eq!(text, input);
        }
    }

    #[test]
    fn common_words_not_pii() {
        // Words that look like names but are common English words
        let inputs = [
            "The application will process the request.",
            "We need to grant access to the system.",
            "The bill was paid in full.",
            "Mark the task as complete.",
        ];
        for input in inputs {
            let (text, result) = screen_response(input);
            assert!(
                !result.screened,
                "Common word falsely flagged: {input} — findings: {:?}",
                result.findings
            );
            assert_eq!(text, input);
        }
    }

    #[test]
    fn clean_response_passes() {
        let (text, result) = screen_response("The capital of France is Paris.");
        assert!(!result.screened);
        assert_eq!(result.redaction_count, 0);
        assert!(!result.blocked);
        assert_eq!(text, "The capital of France is Paris.");
    }

    // ═══════════════════════════════════════════════════════════════
    //  TRUE POSITIVES — these MUST be detected and redacted
    // ═══════════════════════════════════════════════════════════════

    // ── Credentials ──

    #[test]
    fn api_key_redacted() {
        let (text, result) =
            screen_response("Your key is sk-ant-api03-abc123def456ghi789jkl012mno345");
        assert!(result.screened);
        assert!(result.redaction_count > 0);
        assert!(text.contains("[REDACTED:key]"));
        assert!(!text.contains("sk-ant-api03"));
    }

    #[test]
    fn openai_key_redacted() {
        let (text, result) = screen_response("Key: sk-proj-abc123def456ghi789jkl012mno345pqr678");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:key]"));
    }

    #[test]
    fn credential_pattern_redacted() {
        let (text, result) = screen_response("secret_key = 'abcdef1234567890abcdef'");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:credential]"));
    }

    #[test]
    fn bearer_token_redacted() {
        // The credential regex matches "access_token = <value>" style patterns
        let (text, result) =
            screen_response("access_token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc123defg");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:credential]"));
    }

    #[test]
    fn private_key_redacted() {
        let (text, result) =
            screen_response("Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:private_key]"));
    }

    #[test]
    fn ec_private_key_redacted() {
        let (text, result) = screen_response("-----BEGIN PRIVATE KEY-----\nMIGH...");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:private_key]"));
    }

    // ── Environment Variables ──

    #[test]
    fn env_var_redacted() {
        let (text, result) = screen_response(
            "Config: ANTHROPIC_API_KEY=sk-secret-value-here DATABASE_URL=postgres://user:pass@host/db",
        );
        assert!(result.screened);
        assert!(text.contains("[REDACTED:env_var]"));
    }

    #[test]
    fn aws_key_env_var_redacted() {
        let (text, result) =
            screen_response("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:env_var]"));
    }

    // ── PII: SSN ──

    #[test]
    fn ssn_redacted() {
        let (text, result) = screen_response("SSN: 123-45-6789");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:ssn]"));
        assert!(!text.contains("123-45-6789"));
    }

    #[test]
    fn ssn_in_sentence_redacted() {
        let (text, result) =
            screen_response("The patient's social security number is 987-65-4321 on file.");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:ssn]"));
        assert!(!text.contains("987-65-4321"));
    }

    // ── PII: Credit Cards ──

    #[test]
    fn credit_card_redacted() {
        let (text, result) = screen_response("Card: 4111 1111 1111 1111");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:cc]"));
    }

    #[test]
    fn credit_card_dashes_redacted() {
        let (text, result) = screen_response("Card: 4111-1111-1111-1111");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:cc]"));
    }

    #[test]
    fn credit_card_no_separator_redacted() {
        let (text, result) = screen_response("Card: 4111111111111111");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:cc]"));
    }

    // ── PII: Email ──

    #[test]
    fn email_redacted() {
        let (text, result) = screen_response("Contact john.doe@company.com for details");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:email]"));
        assert!(!text.contains("john.doe@company.com"));
    }

    #[test]
    fn multiple_emails_redacted() {
        let (text, result) = screen_response("CC: alice@example.org and bob@example.net");
        assert!(result.screened);
        assert!(result.redaction_count >= 2);
        assert!(!text.contains("alice@"));
        assert!(!text.contains("bob@"));
    }

    // ── PHI: Medical Records ──

    #[test]
    fn phi_mrn_redacted() {
        let (text, result) = screen_response("Patient info: MRN: 12345678");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:phi]"));
    }

    #[test]
    fn phi_patient_id_redacted() {
        // PHI regex matches "patient id:" or "patient_id:" style
        let (text, result) = screen_response("patient id: PAT-9928371");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:phi]"));
    }

    #[test]
    fn phi_medical_record_redacted() {
        let (text, result) = screen_response("medical record: MR-2026-4455");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:phi]"));
    }

    // ── System Prompt Leakage ──

    #[test]
    fn system_prompt_redacted() {
        let (text, result) =
            screen_response("My instructions are: [AEGIS SECURITY RULES — Always enforce]...");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:system_config]"));
    }

    #[test]
    fn agent_system_prompt_redacted() {
        let (text, result) = screen_response(
            "Sure! you are a personal assistant running inside OpenClaw with these rules...",
        );
        assert!(result.screened);
        assert!(text.contains("[REDACTED:system_config]"));
    }

    // ── Machine Recon ──

    #[test]
    fn home_path_redacted() {
        let (text, result) =
            screen_response("The config is at /home/aegis/.aegis/config/config.toml");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:path]"));
        assert!(!text.contains("/home/aegis/"));
    }

    #[test]
    fn home_path_other_users_redacted() {
        let (text, result) = screen_response("Found at /home/deploy/app/secrets.json");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:path]"));
    }

    #[test]
    fn hostname_redacted() {
        let (text, result) = screen_response("hostname: aegis-production-web-01");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:machine_info]"));
    }

    // ── File Content ──

    #[test]
    fn etc_passwd_redacted() {
        let (text, result) = screen_response(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        );
        assert!(result.screened);
        assert!(text.contains("[REDACTED:file_content]"));
    }

    #[test]
    fn ssh_key_redacted() {
        let (text, result) = screen_response(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKxvDm9mGQj3r1A4BxGHk7jFS0bNe6g21RMtXxfPq9wN user@host",
        );
        assert!(result.screened);
        assert!(text.contains("[REDACTED:ssh_key]"));
    }

    // ── Agent Identity ──

    #[test]
    fn agent_identity_redacted() {
        let (text, result) = screen_response("bot_id: 97510100abcdef1234567890abcdef51f01589");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:agent_id]"));
    }

    // ═══════════════════════════════════════════════════════════════
    //  TOOL CALL BLOCKING — trust-aware
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn exec_blocked_all_tiers() {
        use crate::trust_policy::policy_for;
        let response = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"exec","arguments":"{\"command\":\"rm -rf /\"}"}}]}}]}"#;
        for level in [
            aegis_schemas::TrustLevel::Full,
            aegis_schemas::TrustLevel::Trusted,
            aegis_schemas::TrustLevel::Unknown,
        ] {
            let (_, result) = screen_response_with_policy(response, &policy_for(level));
            assert!(result.blocked, "exec should be blocked for {:?}", level);
        }
    }

    #[test]
    fn shell_full_allowed() {
        use crate::trust_policy::policy_for;
        let response = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"shell","arguments":"{}"}}]}}]}"#;
        let (_, result) =
            screen_response_with_policy(response, &policy_for(aegis_schemas::TrustLevel::Full));
        assert!(!result.blocked);
    }

    #[test]
    fn shell_trusted_blocked() {
        use crate::trust_policy::policy_for;
        let response = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"shell","arguments":"{}"}}]}}]}"#;
        let (_, result) =
            screen_response_with_policy(response, &policy_for(aegis_schemas::TrustLevel::Trusted));
        assert!(result.blocked);
    }

    #[test]
    fn read_tool_trusted_allowed() {
        use crate::trust_policy::policy_for;
        let response = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"read_file","arguments":"{\"path\":\"README.md\"}"}}]}}]}"#;
        let (_, result) =
            screen_response_with_policy(response, &policy_for(aegis_schemas::TrustLevel::Trusted));
        assert!(!result.blocked);
    }

    #[test]
    fn read_tool_unknown_blocked() {
        use crate::trust_policy::policy_for;
        let response = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"read_file","arguments":"{\"path\":\"README.md\"}"}}]}}]}"#;
        let (_, result) =
            screen_response_with_policy(response, &policy_for(aegis_schemas::TrustLevel::Unknown));
        assert!(result.blocked);
    }

    #[test]
    fn write_tool_public_blocked() {
        use crate::trust_policy::policy_for;
        let response = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"write","arguments":"{}"}}]}}]}"#;
        let (_, result) =
            screen_response_with_policy(response, &policy_for(aegis_schemas::TrustLevel::Public));
        assert!(result.blocked);
    }

    #[test]
    fn anthropic_tool_call_blocked() {
        let response = r#"{"content":[{"type":"tool_use","name":"shell","input":{"command":"cat /etc/shadow"}}]}"#;
        let (_, result) = screen_response(response);
        assert!(result.blocked);
    }

    // ═══════════════════════════════════════════════════════════════
    //  MIXED CONTENT — partial redaction, preserve clean text
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn mixed_content_partial_redaction() {
        let (text, result) = screen_response(
            "The answer is 42. Your key is sk-ant-api03-abc123def456ghi789jkl012. Have a nice day!",
        );
        assert!(result.screened);
        assert!(text.contains("The answer is 42"));
        assert!(text.contains("[REDACTED:key]"));
        assert!(text.contains("Have a nice day!"));
    }

    #[test]
    fn date_next_to_real_pii_only_pii_redacted() {
        // Date should survive, SSN should be redacted
        let (text, result) =
            screen_response("On March 15, the patient's SSN 123-45-6789 was recorded.");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:ssn]"));
        assert!(text.contains("March 15"), "March should not be redacted");
    }

    #[test]
    fn multiple_categories_all_redacted() {
        let input =
            "Contact john@evil.com, SSN 111-22-3333, key: sk-ant-api03-aaabbbcccdddeeefffggghh";
        let (text, result) = screen_response(input);
        assert!(result.screened);
        assert!(text.contains("[REDACTED:email]"));
        assert!(text.contains("[REDACTED:ssn]"));
        assert!(text.contains("[REDACTED:key]"));
        assert!(!text.contains("john@evil.com"));
        assert!(!text.contains("111-22-3333"));
    }

    // ═══════════════════════════════════════════════════════════════
    //  DLP MODE — trust-level controls redaction behavior
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn log_only_mode_finds_but_does_not_redact() {
        use crate::trust_policy::policy_for;
        let input = "SSN: 123-45-6789";
        let (text, result) =
            screen_response_with_policy(input, &policy_for(aegis_schemas::TrustLevel::Full));
        // Full trust = LogOnly mode: findings recorded but text untouched
        assert!(!result.findings.is_empty(), "Should still find SSN");
        assert_eq!(text, input, "Text should not be modified in LogOnly mode");
    }

    #[test]
    fn block_on_finding_mode_blocks_any_pii() {
        use crate::trust_policy::policy_for;
        let input = "SSN: 123-45-6789";
        let (_, result) =
            screen_response_with_policy(input, &policy_for(aegis_schemas::TrustLevel::Unknown));
        assert!(result.blocked, "Unknown trust should block on any finding");
    }
}
