//! SLM analysis types (D4)
//!
//! Pipeline: Input -> SLM Generation -> Adapter Enrichment -> Holster Decision -> Receipt
//!
//! All scores in integer basis points (0-10000). No floats.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
// SLM Generation Output (what the model produces)
// ═══════════════════════════════════════════════════════════════════

/// SLM generation output — the ONLY structure the model is asked to produce.
/// Qualitative only. No byte offsets, no arithmetic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmOutput {
    /// Must equal 2
    pub schema_version: u32,

    /// Model self-assessed confidence in basis points (0-10000)
    pub confidence: u32,

    /// Detected patterns. May be empty (benign input).
    pub annotations: Vec<SlmAnnotation>,

    /// Human-readable summary (max 500 chars)
    pub explanation: String,
}

/// A single SLM-detected pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlmAnnotation {
    /// Must be from the Pattern taxonomy
    pub pattern: Pattern,

    /// Literal substring from screened_input_bytes (max 100 Unicode scalars)
    pub excerpt: String,
}

// ═══════════════════════════════════════════════════════════════════
// Adapter-Enriched Analysis (deterministic scoring)
// ═══════════════════════════════════════════════════════════════════

/// Adapter-enriched analysis — stored in ReceiptContext under detail.slm_analysis.
/// Adds: spans (byte offsets), severity (from lookup table), threat_score, dimensions, intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedAnalysis {
    /// Must equal 2
    pub schema_version: u32,

    /// Scoring algorithm version (currently 1)
    pub scoring_version: u32,

    /// From SLM output, basis points
    pub confidence: u32,

    /// Derived from highest dimension score
    pub intent: Intent,

    /// Composite threat score, basis points (0-10000)
    /// base = max(per_pattern_max_severity)
    /// + compounding bonus for multiple distinct patterns
    pub threat_score: u32,

    /// Per-dimension max severity, basis points
    pub dimensions: ThreatDimensions,

    /// Enriched annotations with spans and severity
    pub annotations: Vec<EnrichedAnnotation>,

    /// From SLM output
    pub explanation: String,
}

/// Enriched annotation — SLM annotation + adapter-computed fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedAnnotation {
    /// Pattern from taxonomy
    pub pattern: Pattern,

    /// Byte offset span [start, end) into screened_input_bytes.
    /// Omitted if excerpt not found in input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<[usize; 2]>,

    /// Severity in basis points, from pattern lookup table
    pub severity: u32,

    /// Literal substring from input
    pub excerpt: String,

    /// True if multiple matches found (last occurrence used)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_ambiguous: Option<bool>,

    /// True if excerpt was truncated to 100 Unicode scalars
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt_truncated: Option<bool>,

    /// True if excerpt not found in input (span omitted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_approximate: Option<bool>,
}

/// 5 threat dimensions (D4)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ThreatDimensions {
    pub injection: u32,
    pub manipulation: u32,
    pub exfiltration: u32,
    pub persistence: u32,
    pub evasion: u32,
}

// ═══════════════════════════════════════════════════════════════════
// Holster Decision (private, never leaves device)
// ═══════════════════════════════════════════════════════════════════

/// Holster decision — stored in ReceiptContext under detail.holster_decision.
/// Private warden tuning. effective_threshold FORBIDDEN (leaks coefficients).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolsterDecision {
    /// Active holster profile name
    pub holster_profile: HolsterProfile,

    /// Request namespace
    pub namespace: Namespace,

    /// Which engine was used
    pub engine_profile: EngineProfile,

    /// Action taken
    pub action: HolsterAction,

    /// Was the threshold exceeded?
    pub threshold_exceeded: bool,

    /// Was this escalated from a lower engine?
    pub escalated: bool,

    /// Does this require human-in-the-loop?
    pub hil_required: bool,

    /// HIL outcome (if resolved)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hil_outcome: Option<String>,

    /// Peer leverage evidence (cryptographic pointers only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_leverage: Option<PeerLeverage>,

    /// Normalized compute cost in basis points
    /// local_slm=100, loopback=300, frontier=1000, +200 if escalated, +100 if HIL
    pub compute_cost_bp: u32,
}

/// Peer leverage evidence — cryptographic pointers, not self-reported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerLeverage {
    pub used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_receipt_refs: Option<Vec<PeerReceiptRef>>,
}

/// Minimum peer pointer: (peer_id, receipt_hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReceiptRef {
    /// Peer bot_id, lowercase hex
    pub peer_id: String,
    /// Receipt hash, lowercase hex
    pub receipt_hash: String,
}

// ═══════════════════════════════════════════════════════════════════
// Enums
// ═══════════════════════════════════════════════════════════════════

/// Pattern taxonomy (D4) — 15 patterns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Pattern {
    ExfiltrationAttempt,
    DirectInjection,
    MemoryPoison,
    CredentialProbe,
    IndirectInjection,
    PersonaHijack,
    ToolAbuse,
    MultiTurnChain,
    AuthorityEscalation,
    EncodingEvasion,
    LinkInjection,
    Other,
    BoundaryErosion,
    SsrfAttempt,
    Benign,
}

/// Intent — derived from highest dimension score
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    Benign,
    Inject,
    Manipulate,
    Exfiltrate,
    Probe,
}

/// Holster preset profiles (D8)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum HolsterProfile {
    /// Reject > 6000bp
    Aggressive,
    /// Reject > 8000bp (default)
    #[default]
    Balanced,
    /// Reject > 9000bp
    Permissive,
    /// Warden-defined thresholds
    Custom,
}

/// Holster action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HolsterAction {
    /// Allow through
    Admit,
    /// Flag but allow (observe-only)
    Quarantine,
    /// Block
    Reject,
}

/// Screening engine profile — determines annotation cap and compute cost
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineProfile {
    /// Edge token budget, cap 3 annotations
    LocalSlm,
    /// Higher-quality local/remote LLM, cap 8
    Loopback,
    /// Expensive, highest quality, cap 15
    Frontier,
}

impl EngineProfile {
    /// Maximum annotations allowed for this engine
    pub fn annotation_cap(&self) -> usize {
        match self {
            EngineProfile::LocalSlm => 3,
            EngineProfile::Loopback => 8,
            EngineProfile::Frontier => 15,
        }
    }

    /// Base compute cost in basis points
    pub fn base_compute_cost_bp(&self) -> u32 {
        match self {
            EngineProfile::LocalSlm => 100,
            EngineProfile::Loopback => 300,
            EngineProfile::Frontier => 1000,
        }
    }
}

/// Screening namespace — determines holster context
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Namespace {
    /// Inbound user/API messages
    Inbound,
    /// Memory write screening (S2.9)
    Memory,
    /// Mesh message screening (S7.4, always screened, no fast-path)
    Mesh,
    /// Swarm coordination messages
    Swarm,
    /// Write barrier diff screening (D5)
    Barrier,
}

// ═══════════════════════════════════════════════════════════════════
// Input tracking
// ═══════════════════════════════════════════════════════════════════

/// Input metadata — stored in receipt for span verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreeningInput {
    /// SHA-256 of screened_input_bytes, lowercase hex
    pub input_hash: String,
    /// Length of screened_input_bytes
    pub input_length_bytes: usize,
    /// Input format version (currently 1: single-buffer UTF-8 with LF newlines)
    pub input_format_version: u32,
}
