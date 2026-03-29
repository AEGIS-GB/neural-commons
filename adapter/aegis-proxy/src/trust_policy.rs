//! Trust policy — unified rules for what each trust tier can do.
//!
//! Both request screening and response screening read from this module.
//! One source of truth for all trust-aware decisions.

use aegis_schemas::TrustLevel;

/// Policy for a specific trust tier — what's allowed, what's blocked.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    // ── Request side ──
    /// SLM runs deferred (after response) instead of sequential (before forwarding).
    pub slm_deferred: bool,
    /// Classifier is advisory only (log, don't block).
    pub classifier_advisory: bool,
    /// System/developer messages allowed in request body.
    pub system_messages_allowed: bool,
    /// Fail-closed when SLM semaphore is full (reject request).
    pub fail_closed_on_busy: bool,

    // ── Response side: tools ──
    /// Tool calls allowed in response (function names).
    pub tools_read: bool,
    pub tools_write: bool,
    pub tools_shell: bool,
    pub tools_web_fetch: bool,
    /// Block ALL tool calls (overrides individual flags).
    pub tools_block_all: bool,

    // ── Response side: DLP ──
    /// How to handle DLP findings.
    pub dlp_mode: DlpMode,
}

/// DLP behavior per trust tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlpMode {
    /// Log findings but don't redact (warden sees raw data).
    LogOnly,
    /// Redact credentials and secrets only.
    RedactCredentials,
    /// Redact all PII + credentials.
    RedactAll,
    /// Block the response entirely if any DLP finding.
    BlockOnFinding,
}

/// Get the trust policy for a given trust level.
pub fn policy_for(level: TrustLevel) -> TrustPolicy {
    match level {
        TrustLevel::Full => TrustPolicy {
            // Request: deferred SLM, advisory classifier, system msgs allowed
            slm_deferred: true,
            classifier_advisory: true,
            system_messages_allowed: true,
            fail_closed_on_busy: false,
            // Response: all tools except exec (exec blocked for everyone)
            tools_read: true,
            tools_write: true,
            tools_shell: true,
            tools_web_fetch: true,
            tools_block_all: false,
            // DLP: log only — owner sees their own data
            dlp_mode: DlpMode::LogOnly,
        },
        TrustLevel::Trusted => TrustPolicy {
            slm_deferred: true,
            classifier_advisory: true,
            system_messages_allowed: true,
            fail_closed_on_busy: false,
            // No shell — trusted users don't get code execution
            tools_read: true,
            tools_write: true,
            tools_shell: false,
            tools_web_fetch: true,
            tools_block_all: false,
            // Redact credentials from responses
            dlp_mode: DlpMode::RedactCredentials,
        },
        TrustLevel::Public => TrustPolicy {
            slm_deferred: false,
            classifier_advisory: false,
            system_messages_allowed: false,
            fail_closed_on_busy: true,
            // Read only — no writes, no shell, no external fetch
            tools_read: true,
            tools_write: false,
            tools_shell: false,
            tools_web_fetch: false,
            tools_block_all: false,
            // Redact everything sensitive
            dlp_mode: DlpMode::RedactAll,
        },
        TrustLevel::Restricted => TrustPolicy {
            slm_deferred: false,
            classifier_advisory: false,
            system_messages_allowed: false,
            fail_closed_on_busy: true,
            // Read workspace only — no writes, no shell, no fetch
            tools_read: true,
            tools_write: false,
            tools_shell: false,
            tools_web_fetch: false,
            tools_block_all: false,
            dlp_mode: DlpMode::RedactAll,
        },
        TrustLevel::Unknown => TrustPolicy {
            slm_deferred: false,
            classifier_advisory: false,
            system_messages_allowed: false,
            fail_closed_on_busy: true,
            // No tools at all
            tools_read: false,
            tools_write: false,
            tools_shell: false,
            tools_web_fetch: false,
            tools_block_all: true,
            // Block response if anything found
            dlp_mode: DlpMode::BlockOnFinding,
        },
    }
}

/// Check if a tool call is allowed for a given policy.
/// Returns None if allowed, Some(reason) if blocked.
pub fn check_tool_allowed(tool_name: &str, policy: &TrustPolicy) -> Option<String> {
    let name = tool_name.to_lowercase();

    // exec is ALWAYS blocked — no tier gets remote code execution through LLM
    let always_blocked = [
        "exec",
        "execute",
        "system",
        "subprocess",
        "eval",
        "os_command",
    ];
    if always_blocked.iter().any(|b| name.contains(b)) {
        return Some(format!("tool '{tool_name}' is blocked for all trust tiers"));
    }

    // Block all tools for this tier
    if policy.tools_block_all {
        return Some(format!(
            "tool '{tool_name}' blocked — no tool calls allowed for this trust tier"
        ));
    }

    // Shell tools
    let shell_tools = ["shell", "bash", "cmd", "run_command", "terminal"];
    if shell_tools.iter().any(|b| name.contains(b)) && !policy.tools_shell {
        return Some(format!(
            "tool '{tool_name}' blocked — shell not allowed for this trust tier"
        ));
    }

    // Write tools
    let write_tools = [
        "write",
        "create_file",
        "save",
        "edit",
        "append",
        "delete",
        "remove",
        "mkdir",
        "rename",
        "move",
    ];
    if write_tools.iter().any(|b| name.contains(b)) && !policy.tools_write {
        return Some(format!(
            "tool '{tool_name}' blocked — write not allowed for this trust tier"
        ));
    }

    // Web fetch tools
    let fetch_tools = [
        "web_fetch",
        "http_request",
        "fetch",
        "curl",
        "wget",
        "request",
        "browse",
    ];
    if fetch_tools.iter().any(|b| name.contains(b)) && !policy.tools_web_fetch {
        return Some(format!(
            "tool '{tool_name}' blocked — web fetch not allowed for this trust tier"
        ));
    }

    // Read tools — most permissive
    let read_tools = [
        "read", "cat", "head", "tail", "search", "find", "glob", "grep",
    ];
    if read_tools.iter().any(|b| name.contains(b)) && !policy.tools_read {
        return Some(format!(
            "tool '{tool_name}' blocked — read not allowed for this trust tier"
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_allows_most_tools() {
        let p = policy_for(TrustLevel::Full);
        assert!(check_tool_allowed("read", &p).is_none());
        assert!(check_tool_allowed("write", &p).is_none());
        assert!(check_tool_allowed("shell", &p).is_none());
        assert!(check_tool_allowed("web_fetch", &p).is_none());
        // exec always blocked
        assert!(check_tool_allowed("exec", &p).is_some());
    }

    #[test]
    fn trusted_no_shell() {
        let p = policy_for(TrustLevel::Trusted);
        assert!(check_tool_allowed("read", &p).is_none());
        assert!(check_tool_allowed("write", &p).is_none());
        assert!(check_tool_allowed("shell", &p).is_some());
        assert!(check_tool_allowed("web_fetch", &p).is_none());
        assert!(check_tool_allowed("exec", &p).is_some());
    }

    #[test]
    fn public_read_only() {
        let p = policy_for(TrustLevel::Public);
        assert!(check_tool_allowed("read", &p).is_none());
        assert!(check_tool_allowed("write", &p).is_some());
        assert!(check_tool_allowed("shell", &p).is_some());
        assert!(check_tool_allowed("web_fetch", &p).is_some());
    }

    #[test]
    fn unknown_blocks_all() {
        let p = policy_for(TrustLevel::Unknown);
        assert!(check_tool_allowed("read", &p).is_some());
        assert!(check_tool_allowed("write", &p).is_some());
        assert!(check_tool_allowed("shell", &p).is_some());
        assert!(check_tool_allowed("web_fetch", &p).is_some());
        assert!(check_tool_allowed("exec", &p).is_some());
    }

    #[test]
    fn exec_always_blocked() {
        for level in [
            TrustLevel::Full,
            TrustLevel::Trusted,
            TrustLevel::Public,
            TrustLevel::Restricted,
            TrustLevel::Unknown,
        ] {
            let p = policy_for(level);
            assert!(
                check_tool_allowed("exec", &p).is_some(),
                "exec should be blocked for {:?}",
                level
            );
            assert!(
                check_tool_allowed("execute", &p).is_some(),
                "execute should be blocked for {:?}",
                level
            );
        }
    }

    #[test]
    fn policy_slm_behavior() {
        assert!(policy_for(TrustLevel::Full).slm_deferred);
        assert!(policy_for(TrustLevel::Trusted).slm_deferred);
        assert!(!policy_for(TrustLevel::Public).slm_deferred);
        assert!(!policy_for(TrustLevel::Unknown).slm_deferred);
    }

    #[test]
    fn policy_system_messages() {
        assert!(policy_for(TrustLevel::Full).system_messages_allowed);
        assert!(policy_for(TrustLevel::Trusted).system_messages_allowed);
        assert!(!policy_for(TrustLevel::Public).system_messages_allowed);
        assert!(!policy_for(TrustLevel::Unknown).system_messages_allowed);
    }

    #[test]
    fn policy_classifier_mode() {
        assert!(policy_for(TrustLevel::Full).classifier_advisory);
        assert!(policy_for(TrustLevel::Trusted).classifier_advisory);
        assert!(!policy_for(TrustLevel::Public).classifier_advisory);
        assert!(!policy_for(TrustLevel::Unknown).classifier_advisory);
    }

    #[test]
    fn dlp_modes_per_tier() {
        assert_eq!(policy_for(TrustLevel::Full).dlp_mode, DlpMode::LogOnly);
        assert_eq!(
            policy_for(TrustLevel::Trusted).dlp_mode,
            DlpMode::RedactCredentials
        );
        assert_eq!(policy_for(TrustLevel::Public).dlp_mode, DlpMode::RedactAll);
        assert_eq!(
            policy_for(TrustLevel::Unknown).dlp_mode,
            DlpMode::BlockOnFinding
        );
    }
}
