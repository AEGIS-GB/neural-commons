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
            });
            text = new_text;
        }
    }

    result.screened = result.redaction_count > 0;

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
            if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                if let Some(name) = block.get("name").and_then(|n| n.as_str()) {
                    tool_names.push(name.to_string());
                }
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

    #[test]
    fn clean_response_passes() {
        let (text, result) = screen_response("The capital of France is Paris.");
        assert!(!result.screened);
        assert_eq!(result.redaction_count, 0);
        assert!(!result.blocked);
        assert_eq!(text, "The capital of France is Paris.");
    }

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
    fn env_var_redacted() {
        let (text, result) = screen_response(
            "Config: ANTHROPIC_API_KEY=sk-secret-value-here DATABASE_URL=postgres://user:pass@host/db",
        );
        assert!(result.screened);
        assert!(text.contains("[REDACTED:env_var]"));
    }

    #[test]
    fn etc_passwd_redacted() {
        let (text, result) = screen_response(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        );
        assert!(result.screened);
        assert!(text.contains("[REDACTED:file_content]"));
    }

    #[test]
    fn home_path_redacted() {
        let (text, result) =
            screen_response("The config is at /home/aegis/.aegis/config/config.toml");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:path]"));
        assert!(!text.contains("/home/aegis/"));
    }

    #[test]
    fn ssn_redacted() {
        let (text, result) = screen_response("SSN: 123-45-6789");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:ssn]"));
    }

    #[test]
    fn credit_card_redacted() {
        let (text, result) = screen_response("Card: 4111 1111 1111 1111");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:cc]"));
    }

    #[test]
    fn email_redacted() {
        let (text, result) = screen_response("Contact john.doe@company.com for details");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:email]"));
    }

    #[test]
    fn system_prompt_redacted() {
        let (text, result) =
            screen_response("My instructions are: [AEGIS SECURITY RULES — Always enforce]...");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:system_config]"));
    }

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
    fn shell_trusted_blocked() {
        use crate::trust_policy::policy_for;
        let response = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"shell","arguments":"{}"}}]}}]}"#;
        let (_, result) =
            screen_response_with_policy(response, &policy_for(aegis_schemas::TrustLevel::Trusted));
        assert!(result.blocked);
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
    fn private_key_redacted() {
        let (text, result) =
            screen_response("Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:private_key]"));
    }

    #[test]
    fn phi_redacted() {
        let (text, result) = screen_response("Patient info: MRN: 12345678");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:phi]"));
    }

    #[test]
    fn anthropic_tool_call_blocked() {
        let response = r#"{"content":[{"type":"tool_use","name":"shell","input":{"command":"cat /etc/shadow"}}]}"#;
        let (_, result) = screen_response(response);
        assert!(result.blocked);
    }

    #[test]
    fn agent_identity_redacted() {
        let (text, result) = screen_response("bot_id: 97510100abcdef1234567890abcdef51f01589");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:agent_id]"));
    }

    #[test]
    fn credential_pattern_redacted() {
        let (text, result) = screen_response("secret_key = 'abcdef1234567890abcdef'");
        assert!(result.screened);
        assert!(text.contains("[REDACTED:credential]"));
    }
}
