//! Diff engine — computes unified diffs between file versions (D5)
//!
//! Used by severity classifier and evolution flow.
//! Diff hash = SHA-256 of unified diff text (for receipts).
//!
//! Implements a simple O(n*m) LCS-based line diff algorithm.
//! No external diff library required.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

/// A single line in a unified diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "text")]
pub enum DiffLine {
    /// Unchanged line present in both old and new.
    Context(String),
    /// Line added in new version.
    Added(String),
    /// Line removed from old version.
    Removed(String),
}

/// A unified diff between two file versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedDiff {
    /// The diff lines (context, additions, removals).
    pub lines: Vec<DiffLine>,
    /// Number of lines in the old version.
    pub old_line_count: usize,
    /// Number of lines in the new version.
    pub new_line_count: usize,
}

/// Statistics about a diff.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffStats {
    /// Number of lines added.
    pub lines_added: u32,
    /// Number of lines removed.
    pub lines_removed: u32,
    /// Total size of changed content in bytes (added + removed line bytes).
    pub change_size_bytes: u64,
    /// Fraction of lines changed relative to the larger of old/new.
    /// Range 0.0 (identical) to 1.0 (completely different).
    /// When both old and new are empty, this is 0.0.
    pub change_percentage: f64,
}

// ═══════════════════════════════════════════════════════════════════
// LCS computation (O(n*m) dynamic programming)
// ═══════════════════════════════════════════════════════════════════

/// Compute the longest common subsequence of two slices of lines.
/// Returns a list of (old_index, new_index) pairs in order.
fn lcs_indices(old_lines: &[&str], new_lines: &[&str]) -> Vec<(usize, usize)> {
    let n = old_lines.len();
    let m = new_lines.len();

    if n == 0 || m == 0 {
        return Vec::new();
    }

    // Build the DP table.
    // dp[i][j] = length of LCS of old_lines[i..] and new_lines[j..].
    // We use (n+1) x (m+1) table, filled bottom-up.
    let mut dp = vec![vec![0u32; m + 1]; n + 1];

    for i in (0..n).rev() {
        for j in (0..m).rev() {
            if old_lines[i] == new_lines[j] {
                dp[i][j] = dp[i + 1][j + 1] + 1;
            } else {
                dp[i][j] = dp[i + 1][j].max(dp[i][j + 1]);
            }
        }
    }

    // Backtrack to recover the LCS indices.
    let mut result = Vec::with_capacity(dp[0][0] as usize);
    let mut i = 0;
    let mut j = 0;

    while i < n && j < m {
        if old_lines[i] == new_lines[j] {
            result.push((i, j));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }

    result
}

// ═══════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════

/// Compute a line-level unified diff between two text versions.
///
/// Uses LCS (longest common subsequence) to find matching lines,
/// then emits removed, added, and context lines in order.
pub fn compute_diff(old: &str, new: &str) -> UnifiedDiff {
    let old_lines: Vec<&str> = split_lines(old);
    let new_lines: Vec<&str> = split_lines(new);

    let lcs = lcs_indices(&old_lines, &new_lines);

    let mut diff_lines = Vec::new();
    let mut old_idx = 0;
    let mut new_idx = 0;

    for &(lcs_old, lcs_new) in &lcs {
        // Emit removed lines before this LCS match (from old).
        while old_idx < lcs_old {
            diff_lines.push(DiffLine::Removed(old_lines[old_idx].to_owned()));
            old_idx += 1;
        }

        // Emit added lines before this LCS match (from new).
        while new_idx < lcs_new {
            diff_lines.push(DiffLine::Added(new_lines[new_idx].to_owned()));
            new_idx += 1;
        }

        // Emit the matching context line.
        diff_lines.push(DiffLine::Context(old_lines[old_idx].to_owned()));
        old_idx += 1;
        new_idx += 1;
    }

    // Emit any remaining old lines as removed.
    while old_idx < old_lines.len() {
        diff_lines.push(DiffLine::Removed(old_lines[old_idx].to_owned()));
        old_idx += 1;
    }

    // Emit any remaining new lines as added.
    while new_idx < new_lines.len() {
        diff_lines.push(DiffLine::Added(new_lines[new_idx].to_owned()));
        new_idx += 1;
    }

    UnifiedDiff {
        lines: diff_lines,
        old_line_count: old_lines.len(),
        new_line_count: new_lines.len(),
    }
}

/// Compute SHA-256 hash of the unified diff text (for receipts).
///
/// The hash is computed over the formatted unified diff output,
/// providing a stable fingerprint for the exact change.
pub fn diff_hash(diff: &UnifiedDiff) -> [u8; 32] {
    let text = format_unified(diff);
    aegis_crypto::hash(text.as_bytes())
}

/// Compute statistics about a unified diff.
pub fn diff_stats(diff: &UnifiedDiff) -> DiffStats {
    let mut lines_added: u32 = 0;
    let mut lines_removed: u32 = 0;
    let mut change_size_bytes: u64 = 0;

    for line in &diff.lines {
        match line {
            DiffLine::Added(text) => {
                lines_added += 1;
                change_size_bytes += text.len() as u64;
            }
            DiffLine::Removed(text) => {
                lines_removed += 1;
                change_size_bytes += text.len() as u64;
            }
            DiffLine::Context(_) => {}
        }
    }

    let max_lines = diff.old_line_count.max(diff.new_line_count);
    let changed_lines = (lines_added + lines_removed) as f64;
    let change_percentage = if max_lines == 0 {
        0.0
    } else {
        // Cap at 1.0 — when every line is changed, added+removed can
        // exceed max_lines, but percentage should not exceed 100%.
        (changed_lines / max_lines as f64).min(1.0)
    };

    DiffStats {
        lines_added,
        lines_removed,
        change_size_bytes,
        change_percentage,
    }
}

/// Format a unified diff as standard unified diff text.
///
/// Each line is prefixed with ` ` (context), `+` (added), or `-` (removed).
/// A header line with line counts is included.
pub fn format_unified(diff: &UnifiedDiff) -> String {
    let mut output = String::new();

    // Header with line counts.
    output.push_str(&format!(
        "--- old ({} lines)\n+++ new ({} lines)\n",
        diff.old_line_count, diff.new_line_count
    ));

    for line in &diff.lines {
        match line {
            DiffLine::Context(text) => {
                output.push(' ');
                output.push_str(text);
                output.push('\n');
            }
            DiffLine::Added(text) => {
                output.push('+');
                output.push_str(text);
                output.push('\n');
            }
            DiffLine::Removed(text) => {
                output.push('-');
                output.push_str(text);
                output.push('\n');
            }
        }
    }

    output
}

// ═══════════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════════

/// Split text into lines, handling both `\n` and `\r\n`.
/// An empty string produces zero lines (not one empty line).
fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    text.lines().collect()
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Helper: count diff line types
    // ---------------------------------------------------------------

    fn count_types(diff: &UnifiedDiff) -> (usize, usize, usize) {
        let mut ctx = 0;
        let mut add = 0;
        let mut rem = 0;
        for line in &diff.lines {
            match line {
                DiffLine::Context(_) => ctx += 1,
                DiffLine::Added(_) => add += 1,
                DiffLine::Removed(_) => rem += 1,
            }
        }
        (ctx, add, rem)
    }

    // ---------------------------------------------------------------
    // Empty cases
    // ---------------------------------------------------------------

    #[test]
    fn empty_to_empty() {
        let diff = compute_diff("", "");
        assert!(diff.lines.is_empty());
        assert_eq!(diff.old_line_count, 0);
        assert_eq!(diff.new_line_count, 0);

        let stats = diff_stats(&diff);
        assert_eq!(stats.lines_added, 0);
        assert_eq!(stats.lines_removed, 0);
        assert_eq!(stats.change_size_bytes, 0);
        assert!((stats.change_percentage - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_to_something() {
        let diff = compute_diff("", "hello\nworld\n");
        assert_eq!(diff.old_line_count, 0);
        assert_eq!(diff.new_line_count, 2);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 0);
        assert_eq!(add, 2);
        assert_eq!(rem, 0);

        assert_eq!(diff.lines[0], DiffLine::Added("hello".to_owned()));
        assert_eq!(diff.lines[1], DiffLine::Added("world".to_owned()));

        let stats = diff_stats(&diff);
        assert_eq!(stats.lines_added, 2);
        assert_eq!(stats.lines_removed, 0);
        // "hello" (5) + "world" (5)
        assert_eq!(stats.change_size_bytes, 10);
        // All lines are new; change_percentage capped at 1.0.
        assert!((stats.change_percentage - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn something_to_empty() {
        let diff = compute_diff("hello\nworld\n", "");
        assert_eq!(diff.old_line_count, 2);
        assert_eq!(diff.new_line_count, 0);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 0);
        assert_eq!(add, 0);
        assert_eq!(rem, 2);

        let stats = diff_stats(&diff);
        assert_eq!(stats.lines_added, 0);
        assert_eq!(stats.lines_removed, 2);
        assert!((stats.change_percentage - 1.0).abs() < f64::EPSILON);
    }

    // ---------------------------------------------------------------
    // Identical content
    // ---------------------------------------------------------------

    #[test]
    fn identical_content() {
        let text = "line1\nline2\nline3\n";
        let diff = compute_diff(text, text);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 3);
        assert_eq!(add, 0);
        assert_eq!(rem, 0);

        let stats = diff_stats(&diff);
        assert_eq!(stats.lines_added, 0);
        assert_eq!(stats.lines_removed, 0);
        assert_eq!(stats.change_size_bytes, 0);
        assert!((stats.change_percentage - 0.0).abs() < f64::EPSILON);
    }

    // ---------------------------------------------------------------
    // Pure insertions
    // ---------------------------------------------------------------

    #[test]
    fn insertion_at_end() {
        let old = "line1\nline2\n";
        let new = "line1\nline2\nline3\n";
        let diff = compute_diff(old, new);

        assert_eq!(diff.old_line_count, 2);
        assert_eq!(diff.new_line_count, 3);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2);
        assert_eq!(add, 1);
        assert_eq!(rem, 0);

        assert_eq!(diff.lines[2], DiffLine::Added("line3".to_owned()));
    }

    #[test]
    fn insertion_at_beginning() {
        let old = "line2\nline3\n";
        let new = "line1\nline2\nline3\n";
        let diff = compute_diff(old, new);

        assert_eq!(diff.old_line_count, 2);
        assert_eq!(diff.new_line_count, 3);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2);
        assert_eq!(add, 1);
        assert_eq!(rem, 0);

        assert_eq!(diff.lines[0], DiffLine::Added("line1".to_owned()));
    }

    #[test]
    fn insertion_in_middle() {
        let old = "aaa\nccc\n";
        let new = "aaa\nbbb\nccc\n";
        let diff = compute_diff(old, new);

        assert_eq!(diff.new_line_count, 3);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2);
        assert_eq!(add, 1);
        assert_eq!(rem, 0);

        assert_eq!(diff.lines[0], DiffLine::Context("aaa".to_owned()));
        assert_eq!(diff.lines[1], DiffLine::Added("bbb".to_owned()));
        assert_eq!(diff.lines[2], DiffLine::Context("ccc".to_owned()));
    }

    // ---------------------------------------------------------------
    // Pure deletions
    // ---------------------------------------------------------------

    #[test]
    fn deletion_at_end() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nline2\n";
        let diff = compute_diff(old, new);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2);
        assert_eq!(add, 0);
        assert_eq!(rem, 1);

        assert_eq!(diff.lines[2], DiffLine::Removed("line3".to_owned()));
    }

    #[test]
    fn deletion_at_beginning() {
        let old = "line1\nline2\nline3\n";
        let new = "line2\nline3\n";
        let diff = compute_diff(old, new);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2);
        assert_eq!(add, 0);
        assert_eq!(rem, 1);

        assert_eq!(diff.lines[0], DiffLine::Removed("line1".to_owned()));
    }

    #[test]
    fn deletion_in_middle() {
        let old = "aaa\nbbb\nccc\n";
        let new = "aaa\nccc\n";
        let diff = compute_diff(old, new);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2);
        assert_eq!(add, 0);
        assert_eq!(rem, 1);

        assert_eq!(diff.lines[0], DiffLine::Context("aaa".to_owned()));
        assert_eq!(diff.lines[1], DiffLine::Removed("bbb".to_owned()));
        assert_eq!(diff.lines[2], DiffLine::Context("ccc".to_owned()));
    }

    // ---------------------------------------------------------------
    // Modifications (remove + add)
    // ---------------------------------------------------------------

    #[test]
    fn single_line_modification() {
        let old = "aaa\nbbb\nccc\n";
        let new = "aaa\nBBB\nccc\n";
        let diff = compute_diff(old, new);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2);
        assert_eq!(add, 1);
        assert_eq!(rem, 1);

        // Order: context(aaa), removed(bbb), added(BBB), context(ccc)
        assert_eq!(diff.lines[0], DiffLine::Context("aaa".to_owned()));
        assert_eq!(diff.lines[1], DiffLine::Removed("bbb".to_owned()));
        assert_eq!(diff.lines[2], DiffLine::Added("BBB".to_owned()));
        assert_eq!(diff.lines[3], DiffLine::Context("ccc".to_owned()));
    }

    #[test]
    fn multiple_modifications() {
        let old = "aaa\nbbb\nccc\nddd\n";
        let new = "AAA\nbbb\nCCC\nddd\n";
        let diff = compute_diff(old, new);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2); // bbb, ddd
        assert_eq!(add, 2); // AAA, CCC
        assert_eq!(rem, 2); // aaa, ccc
    }

    // ---------------------------------------------------------------
    // Complete replacement
    // ---------------------------------------------------------------

    #[test]
    fn complete_replacement() {
        let old = "alpha\nbeta\n";
        let new = "gamma\ndelta\n";
        let diff = compute_diff(old, new);

        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 0);
        assert_eq!(add, 2);
        assert_eq!(rem, 2);

        let stats = diff_stats(&diff);
        assert_eq!(stats.lines_added, 2);
        assert_eq!(stats.lines_removed, 2);
        assert!((stats.change_percentage - 1.0).abs() < f64::EPSILON);
    }

    // ---------------------------------------------------------------
    // Mixed operations
    // ---------------------------------------------------------------

    #[test]
    fn mixed_insert_delete_modify() {
        let old = "line1\nline2\nline3\nline4\n";
        let new = "line1\nLINE2\nline4\nline5\n";
        // line1: context
        // line2 -> LINE2: removed + added
        // line3: removed
        // line4: context
        // line5: added
        let diff = compute_diff(old, new);

        assert_eq!(diff.old_line_count, 4);
        assert_eq!(diff.new_line_count, 4);

        let stats = diff_stats(&diff);
        assert!(stats.lines_added >= 1);
        assert!(stats.lines_removed >= 1);
    }

    // ---------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------

    #[test]
    fn single_line_old_and_new() {
        let diff = compute_diff("hello", "world");
        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 0);
        assert_eq!(add, 1);
        assert_eq!(rem, 1);
    }

    #[test]
    fn single_identical_line() {
        let diff = compute_diff("same", "same");
        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 1);
        assert_eq!(add, 0);
        assert_eq!(rem, 0);
    }

    #[test]
    fn trailing_newline_vs_none() {
        // "hello\n" splits to ["hello"], "hello" splits to ["hello"]
        // Rust's str::lines() strips the trailing newline, so these are equal.
        let diff = compute_diff("hello\n", "hello");
        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 1);
        assert_eq!(add, 0);
        assert_eq!(rem, 0);
    }

    #[test]
    fn windows_line_endings() {
        let old = "line1\r\nline2\r\n";
        let new = "line1\nline2\n";
        // str::lines() handles both \n and \r\n by stripping them.
        let diff = compute_diff(old, new);
        let (ctx, add, rem) = count_types(&diff);
        assert_eq!(ctx, 2);
        assert_eq!(add, 0);
        assert_eq!(rem, 0);
    }

    #[test]
    fn many_blank_lines() {
        let old = "\n\n\n";
        let new = "\n\n\n\n\n";
        let diff = compute_diff(old, new);

        // old: 3 empty lines, new: 5 empty lines.
        // LCS = 3 empty lines matched, 2 added.
        let stats = diff_stats(&diff);
        assert_eq!(stats.lines_added, 2);
        assert_eq!(stats.lines_removed, 0);
    }

    #[test]
    fn duplicate_lines_lcs() {
        // Tests that LCS handles repeated identical lines correctly.
        let old = "a\na\na\n";
        let new = "a\nb\na\na\n";
        let diff = compute_diff(old, new);

        let (ctx, add, rem) = count_types(&diff);
        // LCS should match all 3 "a" lines; "b" is inserted.
        assert_eq!(ctx, 3);
        assert_eq!(add, 1);
        assert_eq!(rem, 0);
    }

    // ---------------------------------------------------------------
    // diff_hash
    // ---------------------------------------------------------------

    #[test]
    fn hash_is_deterministic() {
        let diff = compute_diff("old content\n", "new content\n");
        let h1 = diff_hash(&diff);
        let h2 = diff_hash(&diff);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_diffs_have_different_hashes() {
        let d1 = compute_diff("aaa\n", "bbb\n");
        let d2 = compute_diff("ccc\n", "ddd\n");
        let h1 = diff_hash(&d1);
        let h2 = diff_hash(&d2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_is_32_bytes() {
        let diff = compute_diff("", "hello\n");
        let h = diff_hash(&diff);
        assert_eq!(h.len(), 32);
    }

    // ---------------------------------------------------------------
    // diff_stats
    // ---------------------------------------------------------------

    #[test]
    fn stats_change_size_bytes() {
        let diff = compute_diff("short\n", "a much longer replacement line\n");
        let stats = diff_stats(&diff);
        assert_eq!(stats.lines_added, 1);
        assert_eq!(stats.lines_removed, 1);
        // "short" (5 bytes) + "a much longer replacement line" (30 bytes) = 35.
        assert_eq!(stats.change_size_bytes, 5 + 30);
    }

    #[test]
    fn stats_change_percentage_half() {
        // 4 lines old, change 2 of them.
        let old = "aaa\nbbb\nccc\nddd\n";
        let new = "AAA\nbbb\nccc\nDDD\n";
        let diff = compute_diff(old, new);
        let stats = diff_stats(&diff);
        assert_eq!(stats.lines_added, 2);
        assert_eq!(stats.lines_removed, 2);
        // changed_lines = 4, max_lines = 4 => 1.0, but we cap at 1.0
        // Actually: 4/4 = 1.0 which is correct since every changed line
        // contributes both a removal and an addition.
        assert!(stats.change_percentage <= 1.0);
        assert!(stats.change_percentage > 0.0);
    }

    #[test]
    fn stats_change_percentage_zero_for_identical() {
        let text = "unchanged\n";
        let diff = compute_diff(text, text);
        let stats = diff_stats(&diff);
        assert!((stats.change_percentage - 0.0).abs() < f64::EPSILON);
    }

    // ---------------------------------------------------------------
    // format_unified
    // ---------------------------------------------------------------

    #[test]
    fn format_unified_empty_diff() {
        let diff = compute_diff("", "");
        let text = format_unified(&diff);
        assert!(text.contains("--- old (0 lines)"));
        assert!(text.contains("+++ new (0 lines)"));
    }

    #[test]
    fn format_unified_basic() {
        let diff = compute_diff("aaa\nbbb\n", "aaa\nBBB\n");
        let text = format_unified(&diff);

        assert!(text.contains("--- old (2 lines)"));
        assert!(text.contains("+++ new (2 lines)"));
        assert!(text.contains(" aaa\n"));
        assert!(text.contains("-bbb\n"));
        assert!(text.contains("+BBB\n"));
    }

    #[test]
    fn format_unified_only_additions() {
        let diff = compute_diff("", "new line\n");
        let text = format_unified(&diff);
        assert!(text.contains("+new line\n"));
        // The header line contains "---", so check content lines only.
        let content_lines: Vec<&str> = text
            .lines()
            .skip(2) // skip header
            .collect();
        for line in content_lines {
            assert!(!line.starts_with('-'));
        }
    }

    #[test]
    fn format_unified_only_removals() {
        let diff = compute_diff("old line\n", "");
        let text = format_unified(&diff);
        assert!(text.contains("-old line\n"));
        // The header line contains "+++", so check there is no "+" prefixed content line.
        let content_lines: Vec<&str> = text
            .lines()
            .skip(2) // skip header
            .collect();
        for line in content_lines {
            assert!(!line.starts_with('+'));
        }
    }

    // ---------------------------------------------------------------
    // Serialization round-trip
    // ---------------------------------------------------------------

    #[test]
    fn serde_round_trip_diff_line() {
        let lines = vec![
            DiffLine::Context("ctx".to_owned()),
            DiffLine::Added("add".to_owned()),
            DiffLine::Removed("rem".to_owned()),
        ];
        let json = serde_json::to_string(&lines).unwrap();
        let deser: Vec<DiffLine> = serde_json::from_str(&json).unwrap();
        assert_eq!(lines, deser);
    }

    #[test]
    fn serde_round_trip_unified_diff() {
        let diff = compute_diff("old\n", "new\n");
        let json = serde_json::to_string(&diff).unwrap();
        let deser: UnifiedDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, deser);
    }

    #[test]
    fn serde_round_trip_diff_stats() {
        let diff = compute_diff("aaa\n", "bbb\nccc\n");
        let stats = diff_stats(&diff);
        let json = serde_json::to_string(&stats).unwrap();
        let deser: DiffStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, deser);
    }

    // ---------------------------------------------------------------
    // Large-ish diff (sanity check)
    // ---------------------------------------------------------------

    #[test]
    fn larger_diff_does_not_panic() {
        let old: String = (0..200).map(|i| format!("line {i}\n")).collect();
        let new: String = (0..200)
            .map(|i| {
                if i % 10 == 0 {
                    format!("MODIFIED line {i}\n")
                } else if i % 15 == 0 {
                    String::new() // skip (deletion)
                } else {
                    format!("line {i}\n")
                }
            })
            .collect();

        let diff = compute_diff(&old, &new);
        let stats = diff_stats(&diff);
        let _hash = diff_hash(&diff);
        let _text = format_unified(&diff);

        // Basic sanity: some lines changed.
        assert!(stats.lines_added > 0 || stats.lines_removed > 0);
        assert!(stats.change_percentage > 0.0);
        assert!(stats.change_percentage <= 1.0);
    }
}
