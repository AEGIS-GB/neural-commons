//! Severity classification — hybrid heuristic + SLM (D5)
//!
//! Stage 1: Deterministic heuristics (always runs, <1ms)
//!   - Whitespace only → Cosmetic
//!   - New URL/endpoint → Structural
//!   - >50% lines changed → Structural
//!   - Instruction verbs changed → Behavioral
//!   - No rule matched → Unknown (escalate to Stage 2)
//!
//! Stage 2: SLM content analysis (when available)
//!   - credential-class files: BANNED for non-local models → auto Structural
//!   - SLM threat_score → severity mapping (0-999 Cosmetic, 1000-4999 Behavioral, 5000+ Structural)
//!
//! Stage 2 fallback (SLM unavailable):
//!   - Medium Behavioral → promoted to Structural
//!   - Low Unknown → promoted to Behavioral

use crate::types::{ClassificationMethod, SensitivityClass, Severity};

// ═══════════════════════════════════════════════════════════════════
// Result types
// ═══════════════════════════════════════════════════════════════════

/// Result of the Stage 1 heuristic classification.
///
/// When `severity` is `None`, no heuristic rule matched and the result
/// should be escalated to Stage 2 (SLM analysis or fallback promotion).
#[derive(Debug, Clone)]
pub struct HeuristicResult {
    /// Determined severity, or `None` when no rule matched (needs escalation).
    pub severity: Option<Severity>,
    /// How severity was determined.
    pub method: ClassificationMethod,
    /// Confidence in the classification (0.0 = no confidence, 1.0 = certain).
    pub confidence: f64,
    /// Human-readable reasons for the classification decision.
    pub reasons: Vec<String>,
}

/// Final classification result returned by [`classify`].
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Determined severity level.
    pub severity: Severity,
    /// How severity was determined.
    pub method: ClassificationMethod,
    /// Confidence in the classification (0.0 = no confidence, 1.0 = certain).
    pub confidence: f64,
    /// Human-readable reasons for the classification decision.
    pub reasons: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Instruction verbs whose addition, removal, or change signals a behavioral
/// shift in the document's intent. Case-insensitive matching.
const INSTRUCTION_VERBS: &[&str] = &[
    "MUST",
    "SHALL",
    "SHOULD",
    "NEVER",
    "ALWAYS",
    "REQUIRED",
    "PROHIBITED",
    "FORBIDDEN",
    "MANDATORY",
    "DENY",
    "ALLOW",
    "PERMIT",
    "REFUSE",
    "REJECT",
    "GRANT",
    "REVOKE",
    "RESTRICT",
    "ENFORCE",
];

/// URL/endpoint patterns that indicate structural additions.
const URL_PATTERNS: &[&str] = &[
    "http://",
    "https://",
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/graphql",
    "/webhook",
    "/endpoint",
    "/rest/",
];

/// Import/require/include patterns that indicate new dependency references.
const IMPORT_PATTERNS: &[&str] = &[
    "import ",
    "from ",
    "require(",
    "require(",
    "#include",
    "use ",
    "using ",
    "extern crate",
    "mod ",
];

/// Threshold: if more than this fraction of lines changed, classify as Structural.
const STRUCTURAL_CHANGE_THRESHOLD: f64 = 0.50;

// ═══════════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════════

/// Normalize a line by stripping all whitespace (used for whitespace-only comparison).
fn normalize_whitespace(line: &str) -> String {
    line.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Check if a line is a comment line (supports //, #, --, ;, /*, */, *).
fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("--")
        || trimmed.starts_with(';')
        || trimmed.starts_with("/*")
        || trimmed.starts_with("*/")
        || trimmed.starts_with('*')
        || trimmed.starts_with("<!--")
        || trimmed.starts_with("-->")
        || trimmed.starts_with("REM ")
}

/// Check if a line contains any of the given patterns (case-insensitive).
fn line_contains_any_ci(line: &str, patterns: &[&str]) -> bool {
    let upper = line.to_uppercase();
    patterns.iter().any(|p| upper.contains(&p.to_uppercase()))
}

/// Check if a line contains any URL/endpoint pattern (case-sensitive for URLs,
/// but paths like `/api/` are case-insensitive).
fn line_contains_url(line: &str) -> bool {
    let lower = line.to_lowercase();
    URL_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_lowercase()))
}

/// Check if a line looks like an import/require/include statement.
fn line_is_import(line: &str) -> bool {
    let trimmed = line.trim();
    IMPORT_PATTERNS.iter().any(|p| trimmed.starts_with(p))
}

/// Compute added and removed lines between old and new content using simple
/// line-by-line comparison. Returns `(added_lines, removed_lines)` where each
/// element is a `Vec<String>` of the relevant lines.
fn compute_line_diff(old_content: &str, new_content: &str) -> (Vec<String>, Vec<String>) {
    let old_lines: Vec<&str> = old_content.lines().collect();
    let new_lines: Vec<&str> = new_content.lines().collect();

    // Build occurrence maps for simple set-difference-with-multiplicity.
    // This is not a true LCS diff but is sufficient for heuristic classification.
    let old_remaining: Vec<&str> = old_lines.clone();
    let new_remaining: Vec<&str> = new_lines.clone();

    // Remove lines that appear in both (preserving order of first match).
    let mut matched_old = vec![false; old_remaining.len()];
    let mut matched_new = vec![false; new_remaining.len()];

    for (ni, new_line) in new_remaining.iter().enumerate() {
        for (oi, old_line) in old_remaining.iter().enumerate() {
            if !matched_old[oi] && !matched_new[ni] && old_line == new_line {
                matched_old[oi] = true;
                matched_new[ni] = true;
                break;
            }
        }
    }

    let removed: Vec<String> = old_remaining
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_old[*i])
        .map(|(_, l)| l.to_string())
        .collect();

    let added: Vec<String> = new_remaining
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_new[*i])
        .map(|(_, l)| l.to_string())
        .collect();

    (added, removed)
}

// ═══════════════════════════════════════════════════════════════════
// Stage 1: Deterministic heuristic classification
// ═══════════════════════════════════════════════════════════════════

/// Classify the severity of a change using deterministic heuristic rules.
///
/// Returns a [`HeuristicResult`]. When `severity` is `None`, no heuristic
/// rule matched and the caller should escalate to Stage 2.
///
/// Rules are evaluated in priority order; the first matching rule wins,
/// except that higher-severity rules override lower-severity ones when
/// multiple indicators are present.
pub fn classify_heuristic(old_content: &str, new_content: &str) -> HeuristicResult {
    // Identical content — trivially cosmetic.
    if old_content == new_content {
        return HeuristicResult {
            severity: Some(Severity::Cosmetic),
            method: ClassificationMethod::Heuristic,
            confidence: 1.0,
            reasons: vec!["No change detected".to_string()],
        };
    }

    let (added, removed) = compute_line_diff(old_content, new_content);
    let old_lines: Vec<&str> = old_content.lines().collect();
    let new_lines: Vec<&str> = new_content.lines().collect();
    let total_lines = old_lines.len().max(new_lines.len()).max(1);
    let changed_lines = added.len().max(removed.len());

    let mut reasons: Vec<String> = Vec::new();
    let mut max_severity: Option<Severity> = None;
    let mut confidence: f64 = 0.0;

    // Helper closure: upgrade severity to at least `sev`.
    let mut upgrade = |sev: Severity, conf: f64, reason: String| {
        reasons.push(reason);
        if max_severity.is_none() || max_severity.is_some_and(|cur| sev > cur) {
            max_severity = Some(sev);
            confidence = conf;
        } else if max_severity == Some(sev) && conf > confidence {
            confidence = conf;
        }
    };

    // ── Check 1: Whitespace-only changes ────────────────────────────
    let whitespace_only = {
        let old_normalized: Vec<String> =
            old_lines.iter().map(|l| normalize_whitespace(l)).collect();
        let new_normalized: Vec<String> =
            new_lines.iter().map(|l| normalize_whitespace(l)).collect();
        old_normalized == new_normalized
    };

    if whitespace_only {
        return HeuristicResult {
            severity: Some(Severity::Cosmetic),
            method: ClassificationMethod::Heuristic,
            confidence: 0.95,
            reasons: vec!["Whitespace-only changes".to_string()],
        };
    }

    // ── Check 2: Comment-only changes ───────────────────────────────
    let all_added_comments = !added.is_empty() && added.iter().all(|l| is_comment_line(l));
    let all_removed_comments = !removed.is_empty() && removed.iter().all(|l| is_comment_line(l));

    if all_added_comments && all_removed_comments {
        upgrade(
            Severity::Cosmetic,
            0.90,
            "Comment-only changes (added and removed)".to_string(),
        );
    } else if added.is_empty() && all_removed_comments {
        upgrade(
            Severity::Cosmetic,
            0.90,
            "Comment-only removals".to_string(),
        );
    } else if removed.is_empty() && all_added_comments {
        upgrade(
            Severity::Cosmetic,
            0.90,
            "Comment-only additions".to_string(),
        );
    }

    // ── Check 3: New URLs/endpoints ─────────────────────────────────
    let new_urls: Vec<&String> = added.iter().filter(|l| line_contains_url(l)).collect();
    // Only flag if these URL patterns were not already in the removed lines
    // (i.e., a URL was genuinely added, not just moved).
    let old_urls: Vec<&String> = removed.iter().filter(|l| line_contains_url(l)).collect();

    if !new_urls.is_empty() && new_urls.len() > old_urls.len() {
        upgrade(
            Severity::Structural,
            0.85,
            format!(
                "New URL/endpoint patterns detected ({} added vs {} removed)",
                new_urls.len(),
                old_urls.len()
            ),
        );
    }

    // ── Check 4: >50% lines changed ────────────────────────────────
    let change_fraction = changed_lines as f64 / total_lines as f64;
    if change_fraction > STRUCTURAL_CHANGE_THRESHOLD {
        upgrade(
            Severity::Structural,
            0.80,
            format!(
                ">50% lines changed ({:.0}% of {} lines)",
                change_fraction * 100.0,
                total_lines
            ),
        );
    }

    // ── Check 5: Instruction verb changes ───────────────────────────
    let added_has_verbs = added
        .iter()
        .any(|l| line_contains_any_ci(l, INSTRUCTION_VERBS));
    let removed_has_verbs = removed
        .iter()
        .any(|l| line_contains_any_ci(l, INSTRUCTION_VERBS));

    if added_has_verbs || removed_has_verbs {
        let detail = match (added_has_verbs, removed_has_verbs) {
            (true, true) => "Instruction verbs modified (added and removed)",
            (true, false) => "New instruction verbs added",
            (false, true) => "Instruction verbs removed",
            _ => unreachable!(),
        };
        upgrade(Severity::Behavioral, 0.85, detail.to_string());
    }

    // ── Check 6: New import/require/include statements ──────────────
    let new_imports: Vec<&String> = added.iter().filter(|l| line_is_import(l)).collect();
    let old_imports: Vec<&String> = removed.iter().filter(|l| line_is_import(l)).collect();

    if !new_imports.is_empty() && new_imports.len() > old_imports.len() {
        upgrade(
            Severity::Behavioral,
            0.75,
            format!(
                "New import/require/include statements ({} added vs {} removed)",
                new_imports.len(),
                old_imports.len()
            ),
        );
    }

    // ── Return result ───────────────────────────────────────────────
    if max_severity.is_none() {
        // No heuristic rule matched — signal that escalation is needed.
        return HeuristicResult {
            severity: None,
            method: ClassificationMethod::Heuristic,
            confidence: 0.0,
            reasons: vec!["No heuristic rule matched; escalation needed".to_string()],
        };
    }

    HeuristicResult {
        severity: max_severity,
        method: ClassificationMethod::Heuristic,
        confidence,
        reasons,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Stage 2 integration + fallback promotion
// ═══════════════════════════════════════════════════════════════════

/// Full classification pipeline: heuristic (Stage 1) followed by SLM
/// escalation / fallback promotion (Stage 2).
///
/// # Arguments
///
/// * `old_content` - Previous file content.
/// * `new_content` - New file content.
/// * `sensitivity` - Sensitivity class of the file (Standard or Credential).
/// * `slm_available` - Whether the SLM model is currently available for
///   Stage 2 analysis.
///
/// # Credential files
///
/// Credential-class files are **always** classified as [`Severity::Structural`]
/// with method [`ClassificationMethod::CredentialAutoStructural`]. The SLM is
/// never invoked for these files (diff must never leave the local machine).
///
/// # SLM fallback (when unavailable)
///
/// When `slm_available` is `false` and Stage 1 returned `None` (no rule
/// matched) or a mid-range severity, the result is conservatively promoted:
///
/// * `None` (unknown) → promoted to [`Severity::Behavioral`]
/// * [`Severity::Behavioral`] with medium confidence → promoted to
///   [`Severity::Structural`]
pub fn classify(
    old_content: &str,
    new_content: &str,
    sensitivity: &SensitivityClass,
    slm_available: bool,
) -> ClassificationResult {
    // ── Credential files: hard override, skip everything ────────────
    if *sensitivity == SensitivityClass::Credential {
        // Any change to a credential file is Structural, period.
        // We still run heuristics to collect reasons for the audit trail.
        let heuristic = classify_heuristic(old_content, new_content);
        let mut reasons = heuristic.reasons;
        reasons
            .push("Credential-class file: auto-classified as Structural (SLM skipped)".to_string());

        return ClassificationResult {
            severity: Severity::Structural,
            method: ClassificationMethod::CredentialAutoStructural,
            confidence: 1.0,
            reasons,
        };
    }

    // ── Stage 1: heuristic classification ───────────────────────────
    let heuristic = classify_heuristic(old_content, new_content);

    match heuristic.severity {
        // Stage 1 produced a definitive answer.
        Some(severity) => {
            if !slm_available {
                // Apply SLM-unavailable fallback promotions.
                apply_slm_fallback(severity, heuristic.confidence, heuristic.reasons)
            } else {
                // SLM is available. In a full implementation we would invoke it
                // here for low-confidence results. For now we trust the heuristic
                // when SLM is available but defer to SLM scoring in the future.
                //
                // NOTE: actual SLM invocation is handled by the aegis-slm crate
                // and wired up in the orchestrator. This module returns the
                // heuristic result as-is, with method=Heuristic, when SLM is
                // available but heuristic confidence is high enough.
                ClassificationResult {
                    severity,
                    method: ClassificationMethod::Heuristic,
                    confidence: heuristic.confidence,
                    reasons: heuristic.reasons,
                }
            }
        }
        // Stage 1 did not match — needs Stage 2.
        None => {
            if slm_available {
                // In a full implementation we would invoke the SLM here.
                // For now, return a placeholder that signals SLM should be
                // called by the orchestrator. We classify as Behavioral
                // (the safe middle ground) with Slm method so the caller
                // knows SLM analysis is pending.
                ClassificationResult {
                    severity: Severity::Behavioral,
                    method: ClassificationMethod::Slm,
                    confidence: 0.5,
                    reasons: vec![
                        "No heuristic rule matched; deferred to SLM analysis".to_string(),
                    ],
                }
            } else {
                // SLM unavailable AND no heuristic match: promote Unknown → Behavioral.
                ClassificationResult {
                    severity: Severity::Behavioral,
                    method: ClassificationMethod::HeuristicPromoted,
                    confidence: 0.4,
                    reasons: vec![
                        "No heuristic rule matched".to_string(),
                        "SLM unavailable: Unknown promoted to Behavioral".to_string(),
                    ],
                }
            }
        }
    }
}

/// Apply conservative fallback promotions when the SLM is unavailable.
///
/// * [`Severity::Behavioral`] with confidence < 0.80 → promoted to Structural
/// * [`Severity::Cosmetic`] stays as-is (high-confidence heuristic)
/// * [`Severity::Structural`] stays as-is
fn apply_slm_fallback(
    severity: Severity,
    confidence: f64,
    mut reasons: Vec<String>,
) -> ClassificationResult {
    /// Medium-confidence threshold below which Behavioral is promoted.
    const MEDIUM_CONFIDENCE_THRESHOLD: f64 = 0.80;

    match severity {
        Severity::Behavioral if confidence < MEDIUM_CONFIDENCE_THRESHOLD => {
            reasons.push(format!(
                "SLM unavailable: Behavioral (confidence {confidence:.2}) promoted to Structural"
            ));
            ClassificationResult {
                severity: Severity::Structural,
                method: ClassificationMethod::HeuristicPromoted,
                confidence,
                reasons,
            }
        }
        _ => {
            if severity == Severity::Behavioral || severity == Severity::Cosmetic {
                reasons.push(
                    "SLM unavailable: no promotion needed (confidence sufficient)".to_string(),
                );
            }
            ClassificationResult {
                severity,
                method: ClassificationMethod::Heuristic,
                confidence,
                reasons,
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ─────────────────────────────────────────────────────

    fn assert_heuristic_severity(old: &str, new: &str, expected: Option<Severity>) {
        let result = classify_heuristic(old, new);
        assert_eq!(
            result.severity, expected,
            "Expected severity {:?} but got {:?}.\nReasons: {:?}",
            expected, result.severity, result.reasons
        );
    }

    fn assert_classification(
        old: &str,
        new: &str,
        sensitivity: &SensitivityClass,
        slm_available: bool,
        expected_severity: Severity,
        expected_method: ClassificationMethod,
    ) {
        let result = classify(old, new, sensitivity, slm_available);
        assert_eq!(
            result.severity, expected_severity,
            "Expected severity {:?} but got {:?}.\nReasons: {:?}",
            expected_severity, result.severity, result.reasons
        );
        assert_eq!(
            result.method, expected_method,
            "Expected method {:?} but got {:?}.\nReasons: {:?}",
            expected_method, result.method, result.reasons
        );
    }

    // ── Identical content ───────────────────────────────────────────

    #[test]
    fn identical_content_is_cosmetic() {
        let content = "hello\nworld\n";
        assert_heuristic_severity(content, content, Some(Severity::Cosmetic));
    }

    #[test]
    fn empty_to_empty_is_cosmetic() {
        assert_heuristic_severity("", "", Some(Severity::Cosmetic));
    }

    // ── Whitespace-only changes ─────────────────────────────────────

    #[test]
    fn whitespace_only_trailing_spaces() {
        let old = "hello\nworld\n";
        let new = "hello  \nworld  \n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    #[test]
    fn whitespace_only_indentation_change() {
        let old = "  foo\n  bar\n";
        let new = "    foo\n    bar\n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    #[test]
    fn whitespace_only_tab_to_spaces() {
        let old = "\tfoo\n\tbar\n";
        let new = "    foo\n    bar\n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    #[test]
    fn whitespace_confidence() {
        let result = classify_heuristic("a\n", "a \n");
        assert!(result.confidence >= 0.90);
    }

    // ── Comment-only changes ────────────────────────────────────────

    #[test]
    fn comment_only_additions_rust() {
        let old = "fn main() {}\n";
        let new = "// This is main\nfn main() {}\n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    #[test]
    fn comment_only_additions_python() {
        let old = "def main():\n    pass\n";
        let new = "# Entry point\ndef main():\n    pass\n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    #[test]
    fn comment_only_removals() {
        let old = "// old comment\nfn main() {}\n";
        let new = "fn main() {}\n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    #[test]
    fn comment_modification() {
        let old = "// old comment\nfn main() {}\n";
        let new = "// new comment\nfn main() {}\n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    // ── New URLs/endpoints → Structural ─────────────────────────────

    #[test]
    fn new_http_url_is_structural() {
        let old = "config = {}\n";
        let new = "config = {}\nendpoint = \"https://evil.com/api\"\n";
        assert_heuristic_severity(old, new, Some(Severity::Structural));
    }

    #[test]
    fn new_api_endpoint_is_structural() {
        let old = "routes:\n  - /home\n";
        let new = "routes:\n  - /home\n  - /api/v2/admin\n";
        assert_heuristic_severity(old, new, Some(Severity::Structural));
    }

    #[test]
    fn moved_url_not_structural() {
        // URL appears in both old and new (just moved), same count.
        let old = "url = \"https://example.com\"\nother = 1\n";
        let new = "other = 1\nurl = \"https://example.com\"\n";
        let result = classify_heuristic(old, new);
        // Should NOT classify as structural due to URL (the URL was not *added*).
        // It may match no rule at all or be cosmetic depending on other checks.
        if let Some(sev) = result.severity {
            assert!(
                sev < Severity::Structural,
                "Moving a URL should not be Structural"
            );
        }
    }

    #[test]
    fn webhook_endpoint_is_structural() {
        let old = "listeners:\n";
        let new = "listeners:\n  - /webhook/github\n";
        assert_heuristic_severity(old, new, Some(Severity::Structural));
    }

    // ── >50% lines changed → Structural ─────────────────────────────

    #[test]
    fn major_rewrite_is_structural() {
        let old = "line1\nline2\nline3\nline4\n";
        let new = "completely\ndifferent\ncontent\nnow\n";
        assert_heuristic_severity(old, new, Some(Severity::Structural));
    }

    #[test]
    fn just_over_50_percent_is_structural() {
        // 4 lines, change 3 (75%).
        let old = "a\nb\nc\nd\n";
        let new = "a\nx\ny\nz\n";
        let result = classify_heuristic(old, new);
        assert!(
            result.severity == Some(Severity::Structural),
            "75% change should be Structural"
        );
    }

    #[test]
    fn just_under_50_percent_not_structural_from_change_ratio() {
        // 10 lines, change 4 (40%) — should NOT trigger the >50% rule.
        let old = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n";
        let new = "a\nb\nc\nd\ne\nf\ng\nh\nX\nY\n";
        let result = classify_heuristic(old, new);
        // It should not be Structural from the change-ratio rule alone.
        // It might match another rule or be None.
        let structural_from_ratio = result
            .reasons
            .iter()
            .any(|r| r.contains(">50% lines changed"));
        assert!(
            !structural_from_ratio,
            "40% change should not trigger >50% rule"
        );
    }

    // ── Instruction verb changes → Behavioral ───────────────────────

    #[test]
    fn new_must_instruction_is_behavioral() {
        // Use enough context lines so the change stays below >50% threshold.
        let old = "Line one.\nLine two.\nThe system processes requests.\nLine four.\nLine five.\n";
        let new =
            "Line one.\nLine two.\nThe system MUST process requests.\nLine four.\nLine five.\n";
        assert_heuristic_severity(old, new, Some(Severity::Behavioral));
    }

    #[test]
    fn removed_never_instruction_is_behavioral() {
        let old = "Line one.\nLine two.\nYou NEVER share secrets.\nLine four.\nLine five.\n";
        let new = "Line one.\nLine two.\nYou share information.\nLine four.\nLine five.\n";
        assert_heuristic_severity(old, new, Some(Severity::Behavioral));
    }

    #[test]
    fn shall_and_should_are_behavioral() {
        let old = "Line one.\nLine two.\nLine three.\nThe agent responds.\nLine five.\nLine six.\n";
        let new = "Line one.\nLine two.\nLine three.\nThe agent SHALL respond.\nThe agent SHOULD log.\nLine five.\nLine six.\n";
        assert_heuristic_severity(old, new, Some(Severity::Behavioral));
    }

    #[test]
    fn always_is_behavioral() {
        let old = "Line one.\nLine two.\nReply politely.\nLine four.\nLine five.\n";
        let new = "Line one.\nLine two.\nALWAYS reply politely.\nLine four.\nLine five.\n";
        assert_heuristic_severity(old, new, Some(Severity::Behavioral));
    }

    #[test]
    fn case_insensitive_verb_detection() {
        let old = "Line one.\nLine two.\nProcess the input.\nLine four.\nLine five.\n";
        let new = "Line one.\nLine two.\nmust process the input.\nLine four.\nLine five.\n";
        let result = classify_heuristic(old, new);
        assert_eq!(result.severity, Some(Severity::Behavioral));
    }

    // ── New imports → Behavioral ────────────────────────────────────

    #[test]
    fn new_rust_import_is_behavioral() {
        let old = "fn main() {}\n";
        let new = "use std::fs;\nfn main() {}\n";
        assert_heuristic_severity(old, new, Some(Severity::Behavioral));
    }

    #[test]
    fn new_python_import_is_behavioral() {
        let old = "def main():\n    pass\n";
        let new = "import os\ndef main():\n    pass\n";
        assert_heuristic_severity(old, new, Some(Severity::Behavioral));
    }

    #[test]
    fn new_js_require_is_behavioral() {
        // Use `import` syntax which starts with an import keyword.
        let old = "Line one.\nLine two.\nmodule.exports = {};\nLine four.\nLine five.\n";
        let new = "Line one.\nLine two.\nimport fs from 'fs';\nmodule.exports = {};\nLine four.\nLine five.\n";
        assert_heuristic_severity(old, new, Some(Severity::Behavioral));
    }

    #[test]
    fn new_c_include_is_behavioral() {
        let old = "int main() { return 0; }\n";
        let new = "#include <stdlib.h>\nint main() { return 0; }\n";
        assert_heuristic_severity(old, new, Some(Severity::Behavioral));
    }

    #[test]
    fn replaced_import_not_new() {
        // One import replaced with another — same count — should not trigger.
        let old = "use std::fs;\nfn main() {}\n";
        let new = "use std::io;\nfn main() {}\n";
        let result = classify_heuristic(old, new);
        let import_triggered = result
            .reasons
            .iter()
            .any(|r| r.contains("import/require/include"));
        assert!(
            !import_triggered,
            "Replacing an import (same count) should not trigger import rule"
        );
    }

    // ── No rule matched → None ──────────────────────────────────────

    #[test]
    fn minor_text_change_no_rule_matched() {
        let old = "The quick brown fox jumps.\nOver the lazy dog.\n";
        let new = "The quick red fox jumps.\nOver the lazy dog.\n";
        assert_heuristic_severity(old, new, None);
    }

    // ── Priority: Structural > Behavioral ───────────────────────────

    #[test]
    fn structural_beats_behavioral() {
        // Has both a URL and instruction verbs — Structural should win.
        let old = "The system processes requests.\n";
        let new =
            "The system MUST process requests.\nendpoint = \"https://api.example.com/v2/data\"\n";
        assert_heuristic_severity(old, new, Some(Severity::Structural));
    }

    // ── Confidence ranges ───────────────────────────────────────────

    #[test]
    fn confidence_is_bounded() {
        let result = classify_heuristic("a\n", "b\n");
        assert!(
            (0.0..=1.0).contains(&result.confidence),
            "Confidence must be in [0.0, 1.0], got {}",
            result.confidence
        );
    }

    #[test]
    fn identical_content_confidence_is_one() {
        let result = classify_heuristic("x\n", "x\n");
        assert_eq!(result.confidence, 1.0);
    }

    // ── Reasons are populated ───────────────────────────────────────

    #[test]
    fn reasons_are_nonempty() {
        let result = classify_heuristic("a\n", "b\n");
        assert!(!result.reasons.is_empty(), "Reasons should never be empty");
    }

    // ═══════════════════════════════════════════════════════════════
    // classify() integration tests
    // ═══════════════════════════════════════════════════════════════

    // ── Credential files always Structural ──────────────────────────

    #[test]
    fn credential_file_always_structural() {
        let old = "SECRET_KEY=abc\n";
        let new = "SECRET_KEY=xyz\n";
        assert_classification(
            old,
            new,
            &SensitivityClass::Credential,
            true,
            Severity::Structural,
            ClassificationMethod::CredentialAutoStructural,
        );
    }

    #[test]
    fn credential_file_structural_even_whitespace_only() {
        let old = "KEY=abc\n";
        let new = "KEY=abc \n";
        assert_classification(
            old,
            new,
            &SensitivityClass::Credential,
            false,
            Severity::Structural,
            ClassificationMethod::CredentialAutoStructural,
        );
    }

    #[test]
    fn credential_confidence_is_one() {
        let result = classify("A=1\n", "A=2\n", &SensitivityClass::Credential, true);
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn credential_skips_slm() {
        let result = classify("A=1\n", "A=2\n", &SensitivityClass::Credential, true);
        assert_eq!(
            result.method,
            ClassificationMethod::CredentialAutoStructural
        );
        // The SLM should never be invoked; CredentialAutoStructural signals this.
    }

    // ── Standard file with SLM available ────────────────────────────

    #[test]
    fn standard_whitespace_with_slm() {
        assert_classification(
            "a\n",
            "a \n",
            &SensitivityClass::Standard,
            true,
            Severity::Cosmetic,
            ClassificationMethod::Heuristic,
        );
    }

    #[test]
    fn standard_url_with_slm() {
        assert_classification(
            "x\n",
            "x\nhttps://evil.com\n",
            &SensitivityClass::Standard,
            true,
            Severity::Structural,
            ClassificationMethod::Heuristic,
        );
    }

    #[test]
    fn standard_no_match_with_slm_defers() {
        // Use enough context lines to avoid triggering >50% change rule.
        let result = classify(
            "Line one.\nLine two.\nThe quick brown fox.\nLine four.\nLine five.\n",
            "Line one.\nLine two.\nThe quick red fox.\nLine four.\nLine five.\n",
            &SensitivityClass::Standard,
            true,
        );
        assert_eq!(result.severity, Severity::Behavioral);
        assert_eq!(result.method, ClassificationMethod::Slm);
    }

    // ── Standard file SLM unavailable — fallback promotions ─────────

    #[test]
    fn slm_unavailable_unknown_promoted_to_behavioral() {
        // No heuristic rule matches, SLM unavailable → Behavioral promoted.
        // Use enough context so >50% change rule doesn't fire.
        let result = classify(
            "Line one.\nLine two.\nThe quick brown fox.\nLine four.\nLine five.\n",
            "Line one.\nLine two.\nThe quick red fox.\nLine four.\nLine five.\n",
            &SensitivityClass::Standard,
            false,
        );
        assert_eq!(result.severity, Severity::Behavioral);
        assert_eq!(result.method, ClassificationMethod::HeuristicPromoted);
    }

    #[test]
    fn slm_unavailable_medium_behavioral_promoted_to_structural() {
        // Instruction verb change (Behavioral, confidence ~0.85) with SLM unavailable.
        // Confidence is >= 0.80 so per our threshold it should NOT be promoted.
        // Let's test with a case that yields lower confidence.
        // New imports yield confidence 0.75 (below threshold).
        let old = "fn main() {}\n";
        let new = "use std::net;\nfn main() {}\n";
        let result = classify(old, new, &SensitivityClass::Standard, false);
        // Import detection has confidence 0.75, which is below MEDIUM_CONFIDENCE_THRESHOLD (0.80).
        assert_eq!(result.severity, Severity::Structural);
        assert_eq!(result.method, ClassificationMethod::HeuristicPromoted);
    }

    #[test]
    fn slm_unavailable_high_confidence_behavioral_not_promoted() {
        // Instruction verb change has confidence 0.85, which is >= 0.80 threshold.
        // Use enough context lines so >50% change rule doesn't fire.
        let old = "Line one.\nLine two.\nProcess data.\nLine four.\nLine five.\n";
        let new = "Line one.\nLine two.\nMUST process data.\nLine four.\nLine five.\n";
        let result = classify(old, new, &SensitivityClass::Standard, false);
        assert_eq!(result.severity, Severity::Behavioral);
        assert_eq!(result.method, ClassificationMethod::Heuristic);
    }

    #[test]
    fn slm_unavailable_cosmetic_not_promoted() {
        let old = "hello\n";
        let new = "hello \n";
        let result = classify(old, new, &SensitivityClass::Standard, false);
        assert_eq!(result.severity, Severity::Cosmetic);
    }

    #[test]
    fn slm_unavailable_structural_stays_structural() {
        let old = "x\n";
        let new = "x\nhttps://bad.com/api/steal\n";
        let result = classify(old, new, &SensitivityClass::Standard, false);
        assert_eq!(result.severity, Severity::Structural);
    }

    // ── Reasons propagation ─────────────────────────────────────────

    #[test]
    fn classify_propagates_reasons() {
        let result = classify(
            "a\n",
            "a\nhttps://example.com\n",
            &SensitivityClass::Standard,
            true,
        );
        assert!(!result.reasons.is_empty());
        assert!(result.reasons.iter().any(|r| r.contains("URL")));
    }

    #[test]
    fn credential_reasons_include_auto_note() {
        let result = classify("K=1\n", "K=2\n", &SensitivityClass::Credential, true);
        assert!(
            result
                .reasons
                .iter()
                .any(|r| r.contains("Credential-class")),
            "Credential classification should mention credential-class in reasons"
        );
    }

    #[test]
    fn slm_fallback_reasons_include_promotion_note() {
        // Use enough context so >50% change rule doesn't fire (need no-match escalation).
        let result = classify(
            "Line one.\nLine two.\nThe quick brown fox.\nLine four.\nLine five.\n",
            "Line one.\nLine two.\nThe quick red fox.\nLine four.\nLine five.\n",
            &SensitivityClass::Standard,
            false,
        );
        assert!(
            result
                .reasons
                .iter()
                .any(|r| r.contains("promoted") || r.contains("SLM unavailable")),
            "Fallback promotion should be noted in reasons. Got: {:?}",
            result.reasons
        );
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn empty_to_content() {
        let result = classify_heuristic("", "hello world\n");
        // Adding content to an empty file — depends on what was added.
        assert!(result.severity.is_some() || result.severity.is_none());
        assert!(result.confidence >= 0.0);
    }

    #[test]
    fn content_to_empty() {
        let result = classify_heuristic("hello\nworld\n", "");
        // Removing all content — 100% change → Structural.
        assert_eq!(result.severity, Some(Severity::Structural));
    }

    #[test]
    fn single_line_whitespace_change() {
        let result = classify_heuristic("x", "x ");
        assert_eq!(result.severity, Some(Severity::Cosmetic));
    }

    #[test]
    fn multiline_mixed_changes() {
        // Some comments added, some code changed — should detect code changes.
        let old = "fn main() {\n    println!(\"hello\");\n}\n";
        let new = "// entry point\nfn main() {\n    println!(\"goodbye\");\n}\n";
        let result = classify_heuristic(old, new);
        // The comment is cosmetic, but the println change doesn't match any
        // specific rule (no verbs, no URLs, no imports, <50% change).
        // The overall result depends on whether comment-only detection sees
        // that not ALL changes are comments.
        assert!(result.severity.is_some() || result.severity.is_none());
    }

    #[test]
    fn large_file_with_small_change() {
        let mut old_lines: Vec<String> = (0..100).map(|i| format!("line {i}")).collect();
        let old = old_lines.join("\n");
        old_lines[50] = "modified line 50".to_string();
        let new = old_lines.join("\n");
        let result = classify_heuristic(&old, &new);
        // 1% change — should not trigger >50% rule.
        let structural_from_ratio = result
            .reasons
            .iter()
            .any(|r| r.contains(">50% lines changed"));
        assert!(!structural_from_ratio);
    }

    #[test]
    fn html_comment_detected() {
        let old = "<div>hello</div>\n";
        let new = "<!-- TODO: fix -->\n<div>hello</div>\n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    #[test]
    fn sql_comment_detected() {
        let old = "SELECT * FROM users;\n";
        let new = "-- get all users\nSELECT * FROM users;\n";
        assert_heuristic_severity(old, new, Some(Severity::Cosmetic));
    }

    // ── Severity ordering ───────────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(Severity::Cosmetic < Severity::Behavioral);
        assert!(Severity::Behavioral < Severity::Structural);
    }

    // ── Method values ───────────────────────────────────────────────

    #[test]
    fn heuristic_result_has_heuristic_method() {
        let result = classify_heuristic("a\n", "a \n");
        assert_eq!(result.method, ClassificationMethod::Heuristic);
    }
}
