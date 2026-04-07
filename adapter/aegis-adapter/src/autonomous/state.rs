//! Autonomous shared state — peer cache, screening log, pattern store,
//! and submitted claims tracking.
//!
//! All mutable collections are append-only JSONL-persisted for KB building
//! and model fine-tuning.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::types::ScreeningStats;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum screening log entries in memory before oldest are dropped.
const SCREENING_LOG_MEM_CAP: usize = 10_000;

/// Rotate screening_log.jsonl at this size (10 MB).
const SCREENING_LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// AutonomousState
// ---------------------------------------------------------------------------

/// Shared state for the 6 autonomous mesh tasks.
///
/// All fields are `Arc<RwLock<..>>` so they can be shared across tasks.
pub struct AutonomousState {
    pub peer_cache: Arc<RwLock<HashMap<String, PeerInfo>>>,
    pub screening_log: Arc<RwLock<ScreeningLog>>,
    pub pattern_store: Arc<RwLock<PatternStore>>,
    pub submitted_claims: Arc<RwLock<HashSet<String>>>,
}

impl AutonomousState {
    /// Initialize autonomous state, creating the `autonomous/` data directory
    /// and loading any existing JSONL files.
    pub fn new(data_dir: &Path) -> Self {
        let auto_dir = data_dir.join("autonomous");
        if let Err(e) = std::fs::create_dir_all(&auto_dir) {
            tracing::warn!("failed to create autonomous data dir: {e}");
        }

        let pattern_store = PatternStore::load_or_create(auto_dir.join("patterns.jsonl"));
        let screening_log = ScreeningLog::new(auto_dir.join("screening_log.jsonl"));

        // Load submitted claims from JSONL
        let claims_path = auto_dir.join("claims_submitted.jsonl");
        let submitted = load_hashes_from_jsonl(&claims_path);

        Self {
            peer_cache: Arc::new(RwLock::new(HashMap::new())),
            screening_log: Arc::new(RwLock::new(screening_log)),
            pattern_store: Arc::new(RwLock::new(pattern_store)),
            submitted_claims: Arc::new(RwLock::new(submitted)),
        }
    }

    /// Path to the autonomous data directory.
    pub fn auto_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("autonomous")
    }
}

// ---------------------------------------------------------------------------
// PeerInfo
// ---------------------------------------------------------------------------

/// Cached information about a mesh peer, updated from PeerStatus broadcasts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub bot_id: String,
    pub trustmark_bp: u32,
    pub chain_seq: u64,
    pub last_seen_ms: i64,
    pub screening_stats: Option<ScreeningStats>,
}

// ---------------------------------------------------------------------------
// ScreeningLog
// ---------------------------------------------------------------------------

/// A single screening decision, persisted for training data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreeningLogEntry {
    pub ts_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// 1=heuristic, 2=classifier, 3=slm
    pub layer: u8,
    /// "admit" or "quarantine"
    pub verdict: String,
    pub patterns: Vec<String>,
    /// First 200 chars of the request body.
    pub body_preview: String,
    pub evidence_hash: String,
}

/// In-memory screening log backed by an append-only JSONL file.
///
/// The JSONL file at `{data_dir}/autonomous/screening_log.jsonl` is the
/// raw training data for fine-tuning the next aegis-screen model.
pub struct ScreeningLog {
    entries: VecDeque<ScreeningLogEntry>,
    store_path: PathBuf,
}

impl ScreeningLog {
    pub fn new(store_path: PathBuf) -> Self {
        Self {
            entries: VecDeque::new(),
            store_path,
        }
    }

    /// Append an entry to memory and persist to JSONL.
    pub fn append(&mut self, entry: ScreeningLogEntry) {
        // Persist to disk first
        self.append_to_disk(&entry);

        // Keep in memory (bounded)
        if self.entries.len() >= SCREENING_LOG_MEM_CAP {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Get entries from the last `secs` seconds.
    pub fn entries_since(&self, since_ms: i64) -> Vec<ScreeningLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.ts_ms >= since_ms)
            .cloned()
            .collect()
    }

    /// Get screening stats for the given time window.
    pub fn stats(&self, window_secs: u64) -> ScreeningStats {
        let now_ms = now_ms();
        let cutoff = now_ms - (window_secs as i64 * 1000);
        let recent: Vec<_> = self.entries.iter().filter(|e| e.ts_ms >= cutoff).collect();
        let quarantined = recent.iter().filter(|e| e.verdict == "quarantine").count() as u64;
        let admitted = recent.iter().filter(|e| e.verdict == "admit").count() as u64;
        ScreeningStats {
            screened: quarantined + admitted,
            quarantined,
            admitted,
            window_secs,
        }
    }

    fn append_to_disk(&self, entry: &ScreeningLogEntry) {
        // Rotate if needed
        if let Ok(meta) = std::fs::metadata(&self.store_path)
            && meta.len() > SCREENING_LOG_ROTATE_BYTES
        {
            let rotated = self.store_path.with_extension("jsonl.1");
            let _ = std::fs::rename(&self.store_path, rotated);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.store_path)
            && let Ok(line) = serde_json::to_string(entry)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

// ---------------------------------------------------------------------------
// PatternStore
// ---------------------------------------------------------------------------

/// A pattern learned from mesh intel, botawiki sync, or claim harvest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPattern {
    pub pattern_type: String,
    pub excerpt: String,
    /// "claim_harvest" | "threat_intel" | "botawiki_sync"
    pub source: String,
    pub source_bot_id: String,
    pub evidence_hash: String,
    pub learned_at_ms: i64,
    pub severity_bp: u32,
}

/// Persistent pattern store backed by a JSONL file.
///
/// Loaded on startup, new patterns appended in real time.
/// This file is the raw data for KB building and model fine-tuning.
pub struct PatternStore {
    pub patterns: Vec<LearnedPattern>,
    pub store_path: PathBuf,
}

impl PatternStore {
    /// Load existing patterns from JSONL or create empty store.
    pub fn load_or_create(store_path: PathBuf) -> Self {
        let patterns = if store_path.exists() {
            load_jsonl::<LearnedPattern>(&store_path)
        } else {
            Vec::new()
        };
        Self {
            patterns,
            store_path,
        }
    }

    /// Append a pattern and persist to disk.
    pub fn append(&mut self, pattern: LearnedPattern) {
        self.append_to_disk(&pattern);
        self.patterns.push(pattern);
    }

    /// Check if a pattern with this evidence_hash already exists.
    pub fn contains_hash(&self, evidence_hash: &str) -> bool {
        self.patterns
            .iter()
            .any(|p| p.evidence_hash == evidence_hash)
    }

    fn append_to_disk(&self, pattern: &LearnedPattern) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.store_path)
            && let Ok(line) = serde_json::to_string(pattern)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

// ---------------------------------------------------------------------------
// Vote record (persisted to votes_cast.jsonl)
// ---------------------------------------------------------------------------

/// A vote we cast on a Botawiki claim, persisted for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteCastRecord {
    pub ts_ms: i64,
    pub claim_id: String,
    pub attester_id: String,
    pub namespace: String,
    pub decision: String,
    pub reason: String,
}

impl VoteCastRecord {
    /// Append to votes_cast.jsonl.
    pub fn persist(&self, data_dir: &Path) {
        let path = data_dir.join("autonomous/votes_cast.jsonl");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            && let Ok(line) = serde_json::to_string(self)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

// ---------------------------------------------------------------------------
// Peer status snapshot (persisted to peer_status.jsonl)
// ---------------------------------------------------------------------------

/// A peer status snapshot we broadcast, persisted for mesh analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatusSnapshot {
    pub ts_ms: i64,
    pub trustmark_bp: u32,
    pub chain_seq: u64,
    pub uptime_ms: u64,
    pub screening: ScreeningStats,
}

impl PeerStatusSnapshot {
    /// Append to peer_status.jsonl.
    pub fn persist(&self, data_dir: &Path) {
        let path = data_dir.join("autonomous/peer_status.jsonl");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            && let Ok(line) = serde_json::to_string(self)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

// ---------------------------------------------------------------------------
// Claim submission record (persisted to claims_submitted.jsonl)
// ---------------------------------------------------------------------------

/// A claim we submitted to Botawiki, persisted for provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSubmittedRecord {
    pub ts_ms: i64,
    pub evidence_hash: String,
    pub pattern_type: String,
    pub excerpt_preview: String,
    pub layer: u8,
}

impl ClaimSubmittedRecord {
    /// Append to claims_submitted.jsonl.
    pub fn persist(&self, data_dir: &Path) {
        let path = data_dir.join("autonomous/claims_submitted.jsonl");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            && let Ok(line) = serde_json::to_string(self)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a JSONL file into a Vec, skipping malformed lines.
fn load_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Vec<T> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Load evidence_hash values from a claims_submitted.jsonl file.
fn load_hashes_from_jsonl(path: &Path) -> HashSet<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            v.get("evidence_hash")?.as_str().map(String::from)
        })
        .collect()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn autonomous_state_creates_directory() {
        let tmp = TempDir::new().unwrap();
        let _state = AutonomousState::new(tmp.path());
        assert!(tmp.path().join("autonomous").exists());
    }

    #[test]
    fn pattern_store_load_save_append() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("patterns.jsonl");

        let mut store = PatternStore::load_or_create(path.clone());
        assert!(store.patterns.is_empty());

        store.append(LearnedPattern {
            pattern_type: "prompt_injection".to_string(),
            excerpt: "ignore all previous".to_string(),
            source: "threat_intel".to_string(),
            source_bot_id: "bot-1".to_string(),
            evidence_hash: "hash1".to_string(),
            learned_at_ms: 1000,
            severity_bp: 9000,
        });
        assert_eq!(store.patterns.len(), 1);
        assert!(store.contains_hash("hash1"));
        assert!(!store.contains_hash("hash2"));

        // Reload from disk
        let store2 = PatternStore::load_or_create(path);
        assert_eq!(store2.patterns.len(), 1);
        assert_eq!(store2.patterns[0].evidence_hash, "hash1");
    }

    #[test]
    fn screening_log_append_and_stats() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("screening_log.jsonl");

        let mut log = ScreeningLog::new(path);
        let now = now_ms();

        log.append(ScreeningLogEntry {
            ts_ms: now,
            request_id: None,
            layer: 2,
            verdict: "quarantine".to_string(),
            patterns: vec!["injection".to_string()],
            body_preview: "test body".to_string(),
            evidence_hash: "h1".to_string(),
        });
        log.append(ScreeningLogEntry {
            ts_ms: now,
            request_id: None,
            layer: 1,
            verdict: "admit".to_string(),
            patterns: vec![],
            body_preview: "safe body".to_string(),
            evidence_hash: "h2".to_string(),
        });

        let stats = log.stats(3600);
        assert_eq!(stats.screened, 2);
        assert_eq!(stats.quarantined, 1);
        assert_eq!(stats.admitted, 1);
    }

    #[test]
    fn screening_log_entries_since() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("screening_log.jsonl");
        let mut log = ScreeningLog::new(path);
        let now = now_ms();

        log.append(ScreeningLogEntry {
            ts_ms: now - 5000,
            request_id: None,
            layer: 1,
            verdict: "admit".to_string(),
            patterns: vec![],
            body_preview: "old".to_string(),
            evidence_hash: "h-old".to_string(),
        });
        log.append(ScreeningLogEntry {
            ts_ms: now,
            request_id: None,
            layer: 2,
            verdict: "quarantine".to_string(),
            patterns: vec!["x".to_string()],
            body_preview: "new".to_string(),
            evidence_hash: "h-new".to_string(),
        });

        let recent = log.entries_since(now - 1000);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].evidence_hash, "h-new");
    }

    #[test]
    fn peer_info_serde() {
        let info = PeerInfo {
            bot_id: "bot-x".to_string(),
            trustmark_bp: 7500,
            chain_seq: 99,
            last_seen_ms: 1234567890000,
            screening_stats: Some(ScreeningStats {
                screened: 50,
                quarantined: 2,
                admitted: 48,
                window_secs: 300,
            }),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: PeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.bot_id, "bot-x");
        assert_eq!(parsed.trustmark_bp, 7500);
    }

    #[test]
    fn learned_pattern_serde() {
        let p = LearnedPattern {
            pattern_type: "jailbreak".to_string(),
            excerpt: "do anything now".to_string(),
            source: "claim_harvest".to_string(),
            source_bot_id: "self".to_string(),
            evidence_hash: "abc".to_string(),
            learned_at_ms: 1000,
            severity_bp: 8500,
        };
        let json = serde_json::to_string(&p).unwrap();
        let parsed: LearnedPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pattern_type, "jailbreak");
    }
}
