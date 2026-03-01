//! Write barrier types (D5)
//!
//! All types needed for the three-layer detection, hash registry,
//! write tokens, severity classification, and enforcement.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ═══════════════════════════════════════════════════════════════════
// Hash Registry
// ═══════════════════════════════════════════════════════════════════

/// Hash registry — tracks known-good state of all protected files.
/// Signed by bot identity key (D0). Persisted in encrypted SQLite WAL.
#[derive(Debug, Clone)]
pub struct HashRegistry {
    /// file_path → entry
    pub entries: HashMap<PathBuf, HashEntry>,
    /// SHA-256 of all entries (recomputed on every mutation)
    pub registry_hash: [u8; 32],
    /// Ed25519 signature over registry_hash, by bot identity key (D0)
    pub signature: [u8; 64],
}

/// A single protected file entry in the hash registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEntry {
    /// SHA-256 of file content
    pub hash: [u8; 32],
    /// (device_id, inode) at baseline — detects symlink/hardlink swap
    pub dev_inode: (u64, u64),
    /// Unix ms — last time hash was confirmed matching
    pub verified_at: u64,
    /// How was the last legitimate change made?
    pub modified_by: ModSource,
    /// Reference to the evolution receipt that authorized this state (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evolution_receipt: Option<String>,
    /// Standard or credential (affects SLM behavior)
    pub sensitivity_class: SensitivityClass,
}

/// How the file reached its current known-good state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModSource {
    /// Initial state at barrier activation
    Genesis,
    /// Warden explicitly approved via `nockchain evolve`
    WardenEvolution,
    /// Network-broadcasted system file update (Foundation-signed)
    PlatformUpdate,
    /// Warden CLI force-accept
    BarrierOverride,
    /// WriteToken-authorized bot write
    BotWrite,
}

/// File sensitivity class — determines SLM behavior
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityClass {
    /// Normal severity classification (heuristic + SLM)
    Standard,
    /// .env*, vault configs — NEVER send diff to non-local models.
    /// Any change → Structural severity. Hard rule, not configurable.
    Credential,
}

// ═══════════════════════════════════════════════════════════════════
// WriteToken
// ═══════════════════════════════════════════════════════════════════

/// Write token — time-windowed authorization for bot-initiated writes.
/// In-process channel only (never touches disk, never visible to skills/plugins).
#[derive(Debug, Clone)]
pub struct WriteToken {
    /// Target file
    pub file_path: PathBuf,
    /// Random nonce — single-use
    pub token_id: [u8; 16],
    /// Unix ms — when issued
    pub issued_at: u64,
    /// Unix ms — when expires (max 500ms TTL)
    pub expires_at: u64,
    /// HMAC(session_key, file_path || token_id || issued_at)
    pub session_hmac: [u8; 32],
}

/// Maximum WriteToken TTL in milliseconds
pub const WRITE_TOKEN_TTL_MS: u64 = 500;

// ═══════════════════════════════════════════════════════════════════
// Severity Classification
// ═══════════════════════════════════════════════════════════════════

/// Severity level for file modifications
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Whitespace, formatting, comments only
    Cosmetic,
    /// Instruction changes, boundary modifications
    Behavioral,
    /// New endpoints, >50% content change, new external refs
    Structural,
}

/// Classification method — how was severity determined?
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationMethod {
    /// Deterministic heuristic rules (Stage 1)
    Heuristic,
    /// SLM content analysis (Stage 2)
    Slm,
    /// Heuristic promoted because SLM was unavailable
    HeuristicPromoted,
    /// Credential file: SLM skipped, auto-classified as Structural
    CredentialAutoStructural,
}

/// Enforcement mode per file
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Receipts + dashboard alerts + warning in bot context. Bot continues.
    Warn,
    /// Quarantine unauthorized file, restore known-good. Dashboard alert.
    Block,
    /// Receipt only, no intervention, no context injection.
    Monitor,
}

/// What triggered the detection?
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionTrigger {
    /// Layer 1: OS filesystem watcher
    FilesystemWatcher,
    /// Layer 2: Periodic hash verification (60s)
    PeriodicHash,
    /// Layer 3: Outbound proxy interlock (before LLM request)
    OutboundProxyInterlock,
}

/// Enforcement outcome
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOutcome {
    /// File quarantined and known-good restored
    Quarantined,
    /// Warning issued, bot continues
    Warned,
    /// Silent receipt, no intervention
    Monitored,
    /// Revert blocked because symlink was detected
    RevertBlockedSymlink,
}

/// Tampering type detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TamperingType {
    /// Inode changed without authorization
    InodeSwap,
    /// Symlink detected during file operation
    SymlinkDetected,
    /// File deleted
    FileDeleted,
}

// ═══════════════════════════════════════════════════════════════════
// Protected File List
// ═══════════════════════════════════════════════════════════════════

/// Network-broadcasted protected file list (Foundation-signed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedFileList {
    /// Monotonic version number (reject <= current)
    pub barrier_file_list_version: u32,
    /// System-protected files
    pub system_protected: Vec<ProtectedFileEntry>,
    /// Ed25519 signature by Foundation root key, lowercase hex
    pub signature: String,
    /// When signed (ISO 8601)
    pub signed_at: String,
}

/// A single entry in the protected file list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedFileEntry {
    /// Glob pattern for file matching
    pub pattern: String,
    /// workspace_root (exact location) or depth_limited (recursive with max_depth)
    pub scope: FileScope,
    /// Maximum directory depth for depth_limited scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    /// If true, included in Layer 3 outbound proxy interlock
    pub critical: bool,
    /// Standard or credential
    pub sensitivity: SensitivityClass,
}

/// Protected file scope
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileScope {
    /// File at exact workspace root location
    WorkspaceRoot,
    /// Recursive search with max_depth limit. No unbounded recursion.
    DepthLimited,
}

/// Maximum total watched paths (system + warden)
pub const MAX_WATCHED_PATHS: usize = 50;

/// Directories always excluded from watching
pub const EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".venv",
    "__pycache__",
    "target",
    ".cache",
];

// ═══════════════════════════════════════════════════════════════════
// Evolution
// ═══════════════════════════════════════════════════════════════════

/// Evolution state for a file (warden is editing it)
#[derive(Debug, Clone)]
pub struct EvolutionState {
    /// File being evolved
    pub file_path: PathBuf,
    /// When evolution started (unix ms)
    pub started_at: u64,
    /// Evolution timeout (default 5 minutes, unix ms)
    pub timeout_at: u64,
    /// Whether warden is editing from quarantine
    pub from_quarantine: bool,
}

/// Evolution timeout in milliseconds (5 minutes)
pub const EVOLUTION_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Quarantine directory name
pub const QUARANTINE_DIR: &str = ".igentity/quarantine";

/// Quarantine file retention in days
pub const QUARANTINE_RETENTION_DAYS: u32 = 30;

// ═══════════════════════════════════════════════════════════════════
// Receipt Detail types
// ═══════════════════════════════════════════════════════════════════

/// Write barrier trigger receipt detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BarrierTriggerDetail {
    pub file_path: String,
    pub change_severity: Severity,
    pub classification_method: ClassificationMethod,
    pub enforcement_mode: EnforcementMode,
    pub sensitivity_class: SensitivityClass,
    /// SHA-256 of unified diff, lowercase hex
    pub diff_hash: String,
    /// SHA-256 of file before change, lowercase hex
    pub previous_hash: String,
    /// SHA-256 of file after change, lowercase hex
    pub current_hash: String,
    pub change_size_bytes: u64,
    pub lines_added: u32,
    pub lines_removed: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slm_analysis: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slm_unavailable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slm_skipped_credential: Option<bool>,
    pub write_token_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evolution_receipt_ref: Option<String>,
    pub inode_changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tampering_type: Option<TamperingType>,
}

/// Authorized write receipt detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedWriteDetail {
    pub file_path: String,
    /// WriteToken ID, lowercase hex
    pub token_id: String,
    /// SHA-256 before, lowercase hex
    pub previous_hash: String,
    /// SHA-256 after, lowercase hex
    pub new_hash: String,
    pub change_size_bytes: u64,
}

/// Evolution receipt detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionDetail {
    /// SHA-256 before, lowercase hex
    pub previous_hash: String,
    /// SHA-256 after, lowercase hex
    pub new_hash: String,
    /// SHA-256 of diff, lowercase hex
    pub diff_hash: String,
    pub change_severity: Severity,
    pub classification_method: ClassificationMethod,
    /// "editor" or "from_quarantine"
    pub source: String,
}

/// Barrier file list update receipt detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BarrierUpdateDetail {
    pub version: u32,
    pub previous_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths_added: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════
// Debounce config
// ═══════════════════════════════════════════════════════════════════

/// Watcher debounce configuration
#[derive(Debug)]
pub struct DebounceConfig {
    /// Per-file cooldown in milliseconds (default 2000)
    pub cooldown_ms: u64,
    /// Max events per file per minute before suppression (default 10)
    pub max_events_per_minute: u32,
    /// Suppression lift after quiet period in ms (default 60000)
    pub suppression_quiet_ms: u64,
}

impl Default for DebounceConfig {
    fn default() -> Self {
        Self {
            cooldown_ms: 2000,
            max_events_per_minute: 10,
            suppression_quiet_ms: 60_000,
        }
    }
}

/// Periodic hash verification interval in seconds
pub const PERIODIC_HASH_INTERVAL_SECS: u64 = 60;
