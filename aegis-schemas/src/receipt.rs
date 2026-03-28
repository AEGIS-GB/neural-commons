//! Evidence receipt schema (D1, D2)
//!
//! Two-part receipt design:
//!   ReceiptCore — signed, chain-linked, always shareable. Cluster sees only this.
//!   ReceiptContext — owner-only JSONB blob. Committed via payload_hash in core.
//!
//! Wire format: RFC 8785 (JCS) canonical JSON.
//! All binary fields: lowercase hex. No floats. No nulls in canonical form.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The signed, chain-linked core of an evidence receipt.
/// This is what gets shared with the cluster (context stripped).
///
/// Signing formula (D2):
///   sig_input = JCS({ id, bot_id, type, ts_ms, prev_hash, payload_hash, seq })
///   sig = Ed25519(SK, sig_input)
///
/// Chain formula (D1):
///   receipt_hash = SHA-256(JCS(core_fields_with_signature))
///   prev_hash = receipt_hash(previous_receipt)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptCore {
    /// UUID v7 (time-ordered), lowercase canonical string
    pub id: Uuid,

    /// Bot's Ed25519 public key, lowercase hex
    pub bot_id: String,

    /// Receipt type (lowercase string enum)
    #[serde(rename = "type")]
    pub receipt_type: ReceiptType,

    /// Unix epoch milliseconds (i64, never float)
    pub ts_ms: i64,

    /// SHA-256 of previous receipt's core+sig, lowercase hex.
    /// Genesis receipt: 64 zero chars ("00000000...0000")
    pub prev_hash: String,

    /// SHA-256 of JCS(ReceiptContext including blinding_nonce), lowercase hex.
    /// Commits to context without revealing it.
    pub payload_hash: String,

    /// Monotonic sequence number. Starts at 1. No gaps allowed.
    pub seq: u64,

    /// Ed25519 signature over JCS of {id, bot_id, type, ts_ms, prev_hash, payload_hash, seq}.
    /// Lowercase hex. Stored separately from the signing input.
    pub sig: String,
}

/// The owner-only context of an evidence receipt.
/// Never leaves the adapter by default. Committed via payload_hash in ReceiptCore.
///
/// MUST include blinding_nonce to prevent rainbow table attacks on payload_hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptContext {
    /// 32 bytes random, lowercase hex. MANDATORY. Regenerated per receipt.
    /// Prevents low-entropy context from being brute-forced via payload_hash.
    pub blinding_nonce: String,

    /// Which enforcement mode was active when this event fired.
    /// "observe" or "enforce". Omitted for always-enforced checks (vault, memory, identity, failure).
    /// D30: needed so TRUSTMARK can weight enforce-mode receipts differently from observe-mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<String>,

    /// What happened (e.g., "write_barrier_trigger", "authorized_write", "slm_screen")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// What was affected (e.g., "SOUL.md", "MEMORY.md")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// What caused it (e.g., "filesystem_watcher", "write_token", "warden_cli")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,

    /// Result (e.g., "quarantined", "warned", "accepted", "rejected")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,

    /// Structured per-type detail (JSONB). Contents vary by receipt_type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,

    /// Enterprise fields — nested object inside context, NOT top-level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise: Option<EnterpriseContext>,
}

/// Enterprise fields inside ReceiptContext (D1: nested, not flattened).
/// All fields optional — omitted when not used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnterpriseContext {
    /// Fleet identifier for managed deployments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fleet_id: Option<String>,

    /// Warden's Ed25519 public key (lowercase hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warden_key: Option<String>,

    /// URL to warden's policy document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_url: Option<String>,

    /// Issuer key identifier for certificate chains
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_key_id: Option<String>,

    /// Compliance-specific extensions (JSONB)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_extensions: Option<serde_json::Value>,

    /// Fleet-level aggregate data (JSONB)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fleet_aggregate: Option<serde_json::Value>,
}

/// Full evidence receipt (core + context together, local storage only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// The signed, chain-linked core
    pub core: ReceiptCore,
    /// Owner-only context (stripped before cluster sync)
    pub context: ReceiptContext,
}

/// Receipt types — categorize what action produced this receipt.
/// Lowercase string enum (D2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptType {
    /// API call evidence
    ApiCall,
    /// Write barrier detection
    WriteBarrier,
    /// SLM analysis result
    SlmAnalysis,
    /// SLM parse failure (D4 failure behavior)
    SlmParseFailure,
    /// Memory integrity event
    MemoryIntegrity,
    /// Vault credential detection
    VaultDetection,
    /// Identity key event (generation, rotation)
    IdentityKey,
    /// Merkle rollup
    MerkleRollup,
    /// Mesh relay
    MeshRelay,
    /// Evaluator decision
    EvaluatorDecision,
    /// Botawiki claim
    BotawikiClaim,
    /// TRUSTMARK update
    TrustmarkUpdate,
    /// Failure detection
    FailureDetection,
    /// Mode change (observe-only, pass-through, enforce)
    ModeChange,
    /// Evolution (warden SOUL.md etc. change)
    Evolution,
    /// Authorized bot write
    AuthorizedWrite,
    /// Barrier file list update
    BarrierUpdate,
}

/// Merkle rollup receipt detail (D1).
/// Included in ReceiptContext.detail for MerkleRollup receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupDetail {
    /// First sequence number in this rollup batch
    pub seq_start: u64,
    /// Last sequence number in this rollup batch
    pub seq_end: u64,
    /// Count of receipts in batch. Must equal seq_end - seq_start + 1.
    pub receipt_count: u64,
    /// Merkle root over receipt_hash values, lowercase hex
    pub merkle_root: String,
    /// Hash of last receipt in batch, lowercase hex
    pub head_hash: String,
    /// Histogram: counts by receipt type. Signed by Edge Gateway (not bot).
    pub histogram: RollupHistogram,
}

/// Receipt type counts for rollup anti-gaming (D1).
/// Bot-signed histograms are ignored — must be cluster-signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupHistogram {
    /// Counts per receipt type
    pub type_counts: std::collections::HashMap<String, u64>,
    /// Counts per severity bucket (for barrier/slm receipts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_counts: Option<std::collections::HashMap<String, u64>>,
}

/// The genesis prev_hash — 32 zero bytes as lowercase hex (64 chars)
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Generate a random blinding nonce (32 bytes, lowercase hex)
pub fn generate_blinding_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
