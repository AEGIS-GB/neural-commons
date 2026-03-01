//! Rollback Suggestion Engine (§2.10.4)
//!
//! Guided investigation when anomalies or failures are detected.
//! Suggests rollback actions based on evidence chain analysis.
//!
//! Phase 2: full implementation with evidence chain integration.
//! Phase 1: stub types and basic suggestion generation.

use serde::{Deserialize, Serialize};

/// A rollback suggestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackSuggestion {
    /// Unique ID for this suggestion
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Severity of the issue
    pub severity: Severity,
    /// Suggested action
    pub action: SuggestedAction,
    /// Evidence chain sequence range to investigate
    pub evidence_range: Option<(u64, u64)>,
    /// Timestamp (epoch ms)
    pub timestamp_ms: i64,
}

/// Severity levels for rollback suggestions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Suggested actions for rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestedAction {
    /// Investigate the evidence chain around the specified range
    Investigate,
    /// Revert a specific memory file to its last acknowledged state
    RevertMemory { file_path: String },
    /// Rotate a potentially compromised credential
    RotateCredential { secret_id: String },
    /// Switch to observe-only mode
    SwitchToObserveOnly,
    /// Contact warden for manual review
    ManualReview,
}

/// Rollback engine (Phase 1 stub).
pub struct RollbackEngine;

impl RollbackEngine {
    pub fn new() -> Self {
        Self
    }

    /// Generate suggestions based on detected issues.
    /// Phase 1: returns empty. Phase 2: analyzes evidence chain.
    pub fn suggest(&self) -> Vec<RollbackSuggestion> {
        // Phase 1 stub — no suggestions yet.
        // Phase 2 will analyze the evidence chain and produce
        // contextual rollback suggestions.
        Vec::new()
    }
}

impl Default for RollbackEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_empty() {
        let engine = RollbackEngine::new();
        assert!(engine.suggest().is_empty());
    }
}
