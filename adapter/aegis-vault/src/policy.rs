//! Per-tool access policy for the credential vault (D9)
//!
//! Controls which tools can access which secrets.
//! Policy rules support glob patterns for both tool names and secret IDs.
//!
//! Default policy: deny all. Access must be explicitly granted.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::VaultError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Access policy for the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Policy rules, keyed by rule name.
    pub rules: Vec<AccessRule>,
    /// Default action when no rule matches.
    #[serde(default)]
    pub default_action: PolicyAction,
}

/// A single access rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    /// Human-readable name for this rule.
    pub name: String,
    /// Tool name pattern (supports * glob). E.g. "mcp_*", "file_write", "*".
    pub tool_pattern: String,
    /// Secret ID pattern (supports * glob). E.g. "openai-*", "*", "aws-prod-key".
    pub secret_pattern: String,
    /// What action to take.
    pub action: PolicyAction,
}

/// Policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow access to the secret.
    Allow,
    /// Deny access to the secret.
    Deny,
    /// Allow but log the access (audit trail).
    AllowWithAudit,
}

impl Default for PolicyAction {
    fn default() -> Self {
        PolicyAction::Deny
    }
}

/// Result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The action to take.
    pub action: PolicyAction,
    /// Which rule matched (None if default was used).
    pub matched_rule: Option<String>,
}

// ---------------------------------------------------------------------------
// Policy Engine
// ---------------------------------------------------------------------------

/// Evaluates access policy for tool→secret requests.
pub struct PolicyEngine {
    policy: AccessPolicy,
    /// Cache of tool→secret→decision for performance.
    /// (Not persisted — rebuilt each session.)
    cache: HashMap<(String, String), PolicyDecision>,
}

impl PolicyEngine {
    /// Create a new policy engine with the given policy.
    pub fn new(policy: AccessPolicy) -> Self {
        Self {
            policy,
            cache: HashMap::new(),
        }
    }

    /// Create a policy engine that denies everything.
    pub fn deny_all() -> Self {
        Self::new(AccessPolicy {
            rules: Vec::new(),
            default_action: PolicyAction::Deny,
        })
    }

    /// Create a policy engine that allows everything (for testing/development).
    pub fn allow_all() -> Self {
        Self::new(AccessPolicy {
            rules: vec![AccessRule {
                name: "allow-all".to_string(),
                tool_pattern: "*".to_string(),
                secret_pattern: "*".to_string(),
                action: PolicyAction::Allow,
            }],
            default_action: PolicyAction::Allow,
        })
    }

    /// Check whether a tool is allowed to access a secret.
    pub fn check(
        &mut self,
        tool_name: &str,
        secret_id: &str,
    ) -> PolicyDecision {
        let cache_key = (tool_name.to_string(), secret_id.to_string());
        if let Some(cached) = self.cache.get(&cache_key) {
            return cached.clone();
        }

        let decision = self.evaluate(tool_name, secret_id);
        self.cache.insert(cache_key, decision.clone());
        decision
    }

    /// Evaluate without caching.
    fn evaluate(&self, tool_name: &str, secret_id: &str) -> PolicyDecision {
        // Rules are evaluated in order; first match wins.
        for rule in &self.policy.rules {
            if matches_glob(&rule.tool_pattern, tool_name)
                && matches_glob(&rule.secret_pattern, secret_id)
            {
                return PolicyDecision {
                    action: rule.action,
                    matched_rule: Some(rule.name.clone()),
                };
            }
        }

        // No rule matched — use default.
        PolicyDecision {
            action: self.policy.default_action,
            matched_rule: None,
        }
    }

    /// Enforce the policy: returns Ok(decision) if allowed, Err if denied.
    pub fn enforce(
        &mut self,
        tool_name: &str,
        secret_id: &str,
    ) -> Result<PolicyDecision, VaultError> {
        let decision = self.check(tool_name, secret_id);
        match decision.action {
            PolicyAction::Deny => Err(VaultError::AccessDenied {
                tool: tool_name.to_string(),
                secret_id: secret_id.to_string(),
            }),
            PolicyAction::Allow | PolicyAction::AllowWithAudit => Ok(decision),
        }
    }

    /// Get the underlying policy (for serialization/display).
    pub fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    /// Add a rule to the policy.
    pub fn add_rule(&mut self, rule: AccessRule) {
        self.policy.rules.push(rule);
        self.cache.clear(); // invalidate cache
    }

    /// Remove a rule by name.
    pub fn remove_rule(&mut self, name: &str) -> bool {
        let before = self.policy.rules.len();
        self.policy.rules.retain(|r| r.name != name);
        let removed = self.policy.rules.len() < before;
        if removed {
            self.cache.clear();
        }
        removed
    }

    /// Clear the decision cache (call after policy changes).
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

// ---------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------

/// Simple glob pattern matching.
///
/// Supports:
///   - `*` matches any sequence of characters
///   - Exact match otherwise
///   - Case-sensitive
fn matches_glob(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }

    // Split pattern by '*' and match segments in order.
    let segments: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;

    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        match value[pos..].find(seg) {
            Some(found) => {
                // First segment must match at the start.
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + seg.len();
            }
            None => return false,
        }
    }

    // If pattern doesn't end with *, the value must end at pos.
    if !pattern.ends_with('*') {
        return pos == value.len();
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_match() {
        assert!(matches_glob("file_write", "file_write"));
        assert!(!matches_glob("file_write", "file_read"));
    }

    #[test]
    fn glob_wildcard_all() {
        assert!(matches_glob("*", "anything"));
        assert!(matches_glob("*", ""));
    }

    #[test]
    fn glob_prefix() {
        assert!(matches_glob("mcp_*", "mcp_tool"));
        assert!(matches_glob("mcp_*", "mcp_"));
        assert!(!matches_glob("mcp_*", "other_tool"));
    }

    #[test]
    fn glob_suffix() {
        assert!(matches_glob("*_key", "api_key"));
        assert!(matches_glob("*_key", "aws_key"));
        assert!(!matches_glob("*_key", "api_token"));
    }

    #[test]
    fn glob_middle() {
        assert!(matches_glob("aws-*-key", "aws-prod-key"));
        assert!(matches_glob("aws-*-key", "aws-staging-key"));
        assert!(!matches_glob("aws-*-key", "gcp-prod-key"));
    }

    #[test]
    fn deny_all_policy() {
        let mut engine = PolicyEngine::deny_all();
        let decision = engine.check("any_tool", "any_secret");
        assert_eq!(decision.action, PolicyAction::Deny);
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn allow_all_policy() {
        let mut engine = PolicyEngine::allow_all();
        let decision = engine.check("any_tool", "any_secret");
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn specific_rule_matches() {
        let policy = AccessPolicy {
            rules: vec![
                AccessRule {
                    name: "allow-mcp-openai".to_string(),
                    tool_pattern: "mcp_*".to_string(),
                    secret_pattern: "openai-*".to_string(),
                    action: PolicyAction::Allow,
                },
                AccessRule {
                    name: "audit-file-ops".to_string(),
                    tool_pattern: "file_*".to_string(),
                    secret_pattern: "*".to_string(),
                    action: PolicyAction::AllowWithAudit,
                },
            ],
            default_action: PolicyAction::Deny,
        };

        let mut engine = PolicyEngine::new(policy);

        // MCP tool accessing OpenAI key — allowed
        let d1 = engine.check("mcp_chat", "openai-api-key");
        assert_eq!(d1.action, PolicyAction::Allow);
        assert_eq!(d1.matched_rule.as_deref(), Some("allow-mcp-openai"));

        // File tool accessing anything — audit
        let d2 = engine.check("file_read", "aws-key");
        assert_eq!(d2.action, PolicyAction::AllowWithAudit);

        // Unknown tool — denied
        let d3 = engine.check("unknown_tool", "some-secret");
        assert_eq!(d3.action, PolicyAction::Deny);
    }

    #[test]
    fn first_match_wins() {
        let policy = AccessPolicy {
            rules: vec![
                AccessRule {
                    name: "deny-specific".to_string(),
                    tool_pattern: "bad_tool".to_string(),
                    secret_pattern: "*".to_string(),
                    action: PolicyAction::Deny,
                },
                AccessRule {
                    name: "allow-all".to_string(),
                    tool_pattern: "*".to_string(),
                    secret_pattern: "*".to_string(),
                    action: PolicyAction::Allow,
                },
            ],
            default_action: PolicyAction::Deny,
        };

        let mut engine = PolicyEngine::new(policy);

        let d1 = engine.check("bad_tool", "secret");
        assert_eq!(d1.action, PolicyAction::Deny);

        let d2 = engine.check("good_tool", "secret");
        assert_eq!(d2.action, PolicyAction::Allow);
    }

    #[test]
    fn enforce_returns_error_on_deny() {
        let mut engine = PolicyEngine::deny_all();
        match engine.enforce("tool", "secret") {
            Err(VaultError::AccessDenied { tool, secret_id }) => {
                assert_eq!(tool, "tool");
                assert_eq!(secret_id, "secret");
            }
            other => panic!("expected AccessDenied, got: {:?}", other),
        }
    }

    #[test]
    fn enforce_returns_ok_on_allow() {
        let mut engine = PolicyEngine::allow_all();
        let decision = engine.enforce("tool", "secret").unwrap();
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn add_and_remove_rules() {
        let mut engine = PolicyEngine::deny_all();

        // Initially denied
        assert_eq!(engine.check("tool", "key").action, PolicyAction::Deny);

        // Add a rule
        engine.add_rule(AccessRule {
            name: "new-rule".to_string(),
            tool_pattern: "tool".to_string(),
            secret_pattern: "key".to_string(),
            action: PolicyAction::Allow,
        });
        assert_eq!(engine.check("tool", "key").action, PolicyAction::Allow);

        // Remove it
        assert!(engine.remove_rule("new-rule"));
        assert_eq!(engine.check("tool", "key").action, PolicyAction::Deny);

        // Remove non-existent
        assert!(!engine.remove_rule("nonexistent"));
    }

    #[test]
    fn cache_is_used() {
        let mut engine = PolicyEngine::allow_all();

        // First call populates cache
        let d1 = engine.check("t", "s");
        assert_eq!(d1.action, PolicyAction::Allow);

        // Second call should hit cache (same result)
        let d2 = engine.check("t", "s");
        assert_eq!(d2.action, PolicyAction::Allow);
        assert_eq!(d2.matched_rule, d1.matched_rule);
    }
}
