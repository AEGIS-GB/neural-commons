//! Integration tests for the autonomous mesh adapter module.
//!
//! Tests cover:
//! - ScreeningLogEntry serialization roundtrip
//! - PatternStore load/save/append JSONL
//! - TypedRelayMessage enum serialization for all variants
//! - PeerInfo update logic
//! - Claim harvest: novel pattern detection
//! - Vote validation: all checks pass/fail scenarios
//! - AutonomousState initialization creates directory

use aegis_adapter::autonomous::AutonomousConfig;
use aegis_adapter::autonomous::state::*;
use aegis_adapter::autonomous::types::*;
use aegis_adapter::autonomous::vote;

use std::sync::Arc;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// AutonomousState initialization
// ---------------------------------------------------------------------------

#[test]
fn autonomous_state_creates_data_directory() {
    let tmp = TempDir::new().unwrap();
    let _state = AutonomousState::new(tmp.path());
    let auto_dir = tmp.path().join("autonomous");
    assert!(auto_dir.exists(), "autonomous/ directory should be created");
    assert!(auto_dir.is_dir());
}

#[test]
fn autonomous_state_survives_existing_directory() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("autonomous")).unwrap();
    let _state = AutonomousState::new(tmp.path());
    // Should not panic
}

// ---------------------------------------------------------------------------
// ScreeningLogEntry serialization
// ---------------------------------------------------------------------------

#[test]
fn screening_log_entry_roundtrip() {
    let entry = ScreeningLogEntry {
        ts_ms: 1712345678000,
        request_id: Some("req-abc".to_string()),
        layer: 3,
        verdict: "quarantine".to_string(),
        patterns: vec!["injection".to_string(), "jailbreak".to_string()],
        body_preview: "ignore all previous instructions".to_string(),
        evidence_hash: "deadbeef".to_string(),
    };

    let json = serde_json::to_string(&entry).unwrap();
    let parsed: ScreeningLogEntry = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.ts_ms, 1712345678000);
    assert_eq!(parsed.request_id.as_deref(), Some("req-abc"));
    assert_eq!(parsed.layer, 3);
    assert_eq!(parsed.verdict, "quarantine");
    assert_eq!(parsed.patterns.len(), 2);
    assert_eq!(parsed.evidence_hash, "deadbeef");
}

#[test]
fn screening_log_entry_optional_request_id() {
    let entry = ScreeningLogEntry {
        ts_ms: 1000,
        request_id: None,
        layer: 1,
        verdict: "admit".to_string(),
        patterns: vec![],
        body_preview: "safe".to_string(),
        evidence_hash: "h".to_string(),
    };

    let json = serde_json::to_string(&entry).unwrap();
    // request_id should be omitted (skip_serializing_if)
    assert!(!json.contains("request_id"));
    let parsed: ScreeningLogEntry = serde_json::from_str(&json).unwrap();
    assert!(parsed.request_id.is_none());
}

// ---------------------------------------------------------------------------
// PatternStore JSONL persistence
// ---------------------------------------------------------------------------

#[test]
fn pattern_store_empty_on_fresh_path() {
    let tmp = TempDir::new().unwrap();
    let store = PatternStore::load_or_create(tmp.path().join("p.jsonl"));
    assert!(store.patterns.is_empty());
}

#[test]
fn pattern_store_append_and_reload() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("patterns.jsonl");

    {
        let mut store = PatternStore::load_or_create(path.clone());
        store.append(LearnedPattern {
            pattern_type: "injection".to_string(),
            excerpt: "ignore previous".to_string(),
            source: "threat_intel".to_string(),
            source_bot_id: "bot-1".to_string(),
            evidence_hash: "hash-1".to_string(),
            learned_at_ms: 1000,
            severity_bp: 9000,
        });
        store.append(LearnedPattern {
            pattern_type: "jailbreak".to_string(),
            excerpt: "DAN mode".to_string(),
            source: "botawiki_sync".to_string(),
            source_bot_id: "bot-2".to_string(),
            evidence_hash: "hash-2".to_string(),
            learned_at_ms: 2000,
            severity_bp: 8500,
        });
        assert_eq!(store.patterns.len(), 2);
    }

    // Reload from disk
    let store = PatternStore::load_or_create(path);
    assert_eq!(store.patterns.len(), 2);
    assert_eq!(store.patterns[0].evidence_hash, "hash-1");
    assert_eq!(store.patterns[1].evidence_hash, "hash-2");
}

#[test]
fn pattern_store_contains_hash() {
    let tmp = TempDir::new().unwrap();
    let mut store = PatternStore::load_or_create(tmp.path().join("p.jsonl"));
    assert!(!store.contains_hash("x"));
    store.append(LearnedPattern {
        pattern_type: "t".to_string(),
        excerpt: "e".to_string(),
        source: "s".to_string(),
        source_bot_id: "b".to_string(),
        evidence_hash: "x".to_string(),
        learned_at_ms: 0,
        severity_bp: 0,
    });
    assert!(store.contains_hash("x"));
    assert!(!store.contains_hash("y"));
}

// ---------------------------------------------------------------------------
// TypedRelayMessage serialization
// ---------------------------------------------------------------------------

#[test]
fn typed_relay_message_peer_status() {
    let msg = TypedRelayMessage::PeerStatus {
        trustmark_bp: 8500,
        chain_seq: 42,
        uptime_ms: 3_600_000,
        screening: ScreeningStats {
            screened: 100,
            quarantined: 3,
            admitted: 97,
            window_secs: 3600,
        },
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"PeerStatus\""));
    let parsed: TypedRelayMessage = serde_json::from_str(&json).unwrap();
    match parsed {
        TypedRelayMessage::PeerStatus { trustmark_bp, .. } => assert_eq!(trustmark_bp, 8500),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn typed_relay_message_threat_intel() {
    let msg = TypedRelayMessage::ThreatIntel {
        pattern_type: "prompt_injection".to_string(),
        excerpt: "test".to_string(),
        evidence_hash: "abc".to_string(),
        severity_bp: 9000,
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"ThreatIntel\""));
    let _: TypedRelayMessage = serde_json::from_str(&json).unwrap();
}

#[test]
fn typed_relay_message_knowledge_share() {
    let msg = TypedRelayMessage::KnowledgeShare {
        namespace: "b/lore".to_string(),
        claim_id: "c1".to_string(),
        content: "Aegis was born in the coral reef".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let parsed: TypedRelayMessage = serde_json::from_str(&json).unwrap();
    match parsed {
        TypedRelayMessage::KnowledgeShare { namespace, .. } => assert_eq!(namespace, "b/lore"),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn typed_relay_message_chain_verify_request() {
    let msg = TypedRelayMessage::ChainVerifyRequest {
        start_seq: 1,
        end_seq: 100,
    };
    let json = serde_json::to_string(&msg).unwrap();
    let _: TypedRelayMessage = serde_json::from_str(&json).unwrap();
}

#[test]
fn typed_relay_message_chain_verify_response() {
    let msg = TypedRelayMessage::ChainVerifyResponse {
        receipts: vec![serde_json::json!({"seq": 1, "hash": "abc"})],
    };
    let json = serde_json::to_string(&msg).unwrap();
    let _: TypedRelayMessage = serde_json::from_str(&json).unwrap();
}

#[test]
fn typed_relay_message_vote_request() {
    let msg = TypedRelayMessage::VoteRequest {
        claim_id: "c1".to_string(),
        attester_id: "bot-1".to_string(),
        namespace: "b/skills".to_string(),
        payload: serde_json::json!({"content": "pattern", "evidence_hash": "h1"}),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let _: TypedRelayMessage = serde_json::from_str(&json).unwrap();
}

#[test]
fn typed_relay_message_free_text() {
    let msg = TypedRelayMessage::FreeText {
        body: "hello mesh".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let parsed: TypedRelayMessage = serde_json::from_str(&json).unwrap();
    match parsed {
        TypedRelayMessage::FreeText { body } => assert_eq!(body, "hello mesh"),
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// PeerInfo update logic
// ---------------------------------------------------------------------------

#[tokio::test]
async fn peer_cache_update() {
    let tmp = TempDir::new().unwrap();
    let state = Arc::new(AutonomousState::new(tmp.path()));

    // Initially empty
    assert!(state.peer_cache.read().await.is_empty());

    // Insert peer
    state.peer_cache.write().await.insert(
        "bot-1".to_string(),
        PeerInfo {
            bot_id: "bot-1".to_string(),
            trustmark_bp: 5000,
            chain_seq: 10,
            last_seen_ms: 1000,
            screening_stats: None,
        },
    );

    {
        let cache = state.peer_cache.read().await;
        assert_eq!(cache.len(), 1);
        let peer = cache.get("bot-1").unwrap();
        assert_eq!(peer.trustmark_bp, 5000);
    }

    // Update peer
    state.peer_cache.write().await.insert(
        "bot-1".to_string(),
        PeerInfo {
            bot_id: "bot-1".to_string(),
            trustmark_bp: 7500,
            chain_seq: 20,
            last_seen_ms: 2000,
            screening_stats: Some(ScreeningStats {
                screened: 50,
                quarantined: 2,
                admitted: 48,
                window_secs: 300,
            }),
        },
    );

    {
        let cache = state.peer_cache.read().await;
        let peer = cache.get("bot-1").unwrap();
        assert_eq!(peer.trustmark_bp, 7500);
        assert_eq!(peer.chain_seq, 20);
        assert!(peer.screening_stats.is_some());
    }
}

// ---------------------------------------------------------------------------
// Vote validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vote_approve_all_checks_pass() {
    let tmp = TempDir::new().unwrap();
    let state = Arc::new(AutonomousState::new(tmp.path()));

    state.peer_cache.write().await.insert(
        "bot-good".to_string(),
        PeerInfo {
            bot_id: "bot-good".to_string(),
            trustmark_bp: 7000,
            chain_seq: 50,
            last_seen_ms: 0,
            screening_stats: None,
        },
    );

    let payload = serde_json::json!({"evidence_hash": "unique-hash"});
    let (decision, reason) = vote::validate("c1", "bot-good", &payload, &state).await;
    assert_eq!(decision, "approve");
    assert!(reason.contains("all checks passed"));
}

#[tokio::test]
async fn vote_reject_unknown_attester() {
    let tmp = TempDir::new().unwrap();
    let state = Arc::new(AutonomousState::new(tmp.path()));

    let payload = serde_json::json!({"evidence_hash": "h1"});
    let (decision, reason) = vote::validate("c1", "unknown", &payload, &state).await;
    assert_eq!(decision, "reject");
    assert!(reason.contains("not in mesh"));
}

#[tokio::test]
async fn vote_reject_low_trust_attester() {
    let tmp = TempDir::new().unwrap();
    let state = Arc::new(AutonomousState::new(tmp.path()));

    state.peer_cache.write().await.insert(
        "bot-low".to_string(),
        PeerInfo {
            bot_id: "bot-low".to_string(),
            trustmark_bp: 2000,
            chain_seq: 1,
            last_seen_ms: 0,
            screening_stats: None,
        },
    );

    let payload = serde_json::json!({"evidence_hash": "h1"});
    let (decision, _) = vote::validate("c1", "bot-low", &payload, &state).await;
    assert_eq!(decision, "reject");
}

#[tokio::test]
async fn vote_reject_missing_evidence_hash() {
    let tmp = TempDir::new().unwrap();
    let state = Arc::new(AutonomousState::new(tmp.path()));

    state.peer_cache.write().await.insert(
        "bot-ok".to_string(),
        PeerInfo {
            bot_id: "bot-ok".to_string(),
            trustmark_bp: 5000,
            chain_seq: 1,
            last_seen_ms: 0,
            screening_stats: None,
        },
    );

    let payload = serde_json::json!({"content": "no hash here"});
    let (decision, reason) = vote::validate("c1", "bot-ok", &payload, &state).await;
    assert_eq!(decision, "reject");
    assert!(reason.contains("missing evidence_hash"));
}

#[tokio::test]
async fn vote_reject_duplicate_evidence() {
    let tmp = TempDir::new().unwrap();
    let state = Arc::new(AutonomousState::new(tmp.path()));

    state.peer_cache.write().await.insert(
        "bot-ok".to_string(),
        PeerInfo {
            bot_id: "bot-ok".to_string(),
            trustmark_bp: 6000,
            chain_seq: 1,
            last_seen_ms: 0,
            screening_stats: None,
        },
    );

    // Pre-populate pattern store with existing hash
    {
        let mut store = state.pattern_store.write().await;
        store.append(LearnedPattern {
            pattern_type: "t".to_string(),
            excerpt: "e".to_string(),
            source: "s".to_string(),
            source_bot_id: "x".to_string(),
            evidence_hash: "dup-hash".to_string(),
            learned_at_ms: 0,
            severity_bp: 0,
        });
    }

    let payload = serde_json::json!({"evidence_hash": "dup-hash"});
    let (decision, reason) = vote::validate("c1", "bot-ok", &payload, &state).await;
    assert_eq!(decision, "reject");
    assert!(reason.contains("duplicate"));
}

// ---------------------------------------------------------------------------
// AutonomousConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn autonomous_config_defaults() {
    let config = AutonomousConfig::default();
    assert!(config.enabled);
    assert_eq!(config.heartbeat_interval_secs, 300);
    assert_eq!(config.inbox_poll_interval_secs, 30);
    assert_eq!(config.sync_interval_secs, 600);
    assert_eq!(config.harvest_interval_secs, 3600);
    assert_eq!(config.min_trust_for_intel_bp, 4000);
}

#[test]
fn autonomous_config_serde_roundtrip() {
    let config = AutonomousConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let parsed: AutonomousConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.heartbeat_interval_secs, 300);
}

// ---------------------------------------------------------------------------
// ScreeningLog stats
// ---------------------------------------------------------------------------

#[test]
fn screening_log_stats_empty() {
    let tmp = TempDir::new().unwrap();
    let log = ScreeningLog::new(tmp.path().join("s.jsonl"));
    let stats = log.stats(3600);
    assert_eq!(stats.screened, 0);
    assert_eq!(stats.quarantined, 0);
    assert_eq!(stats.admitted, 0);
}

// ---------------------------------------------------------------------------
// Persistence records serde
// ---------------------------------------------------------------------------

#[test]
fn vote_cast_record_serde() {
    let record = VoteCastRecord {
        ts_ms: 1000,
        claim_id: "c1".to_string(),
        attester_id: "a1".to_string(),
        namespace: "b/skills".to_string(),
        decision: "approve".to_string(),
        reason: "all checks passed".to_string(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let parsed: VoteCastRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.decision, "approve");
}

#[test]
fn peer_status_snapshot_serde() {
    let snapshot = PeerStatusSnapshot {
        ts_ms: 1000,
        trustmark_bp: 8000,
        chain_seq: 42,
        uptime_ms: 3_600_000,
        screening: ScreeningStats {
            screened: 100,
            quarantined: 3,
            admitted: 97,
            window_secs: 300,
        },
    };
    let json = serde_json::to_string(&snapshot).unwrap();
    let parsed: PeerStatusSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.trustmark_bp, 8000);
}

#[test]
fn claim_submitted_record_serde() {
    let record = ClaimSubmittedRecord {
        ts_ms: 1000,
        evidence_hash: "abc".to_string(),
        pattern_type: "injection".to_string(),
        excerpt_preview: "test".to_string(),
        layer: 3,
    };
    let json = serde_json::to_string(&record).unwrap();
    let parsed: ClaimSubmittedRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.layer, 3);
}

// ---------------------------------------------------------------------------
// Persistence to disk
// ---------------------------------------------------------------------------

#[test]
fn vote_cast_persists_to_jsonl() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("autonomous")).unwrap();

    let record = VoteCastRecord {
        ts_ms: 1000,
        claim_id: "c1".to_string(),
        attester_id: "a1".to_string(),
        namespace: "b/skills".to_string(),
        decision: "approve".to_string(),
        reason: "ok".to_string(),
    };
    record.persist(tmp.path());

    let content = std::fs::read_to_string(tmp.path().join("autonomous/votes_cast.jsonl")).unwrap();
    assert!(!content.is_empty());
    let parsed: VoteCastRecord = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed.claim_id, "c1");
}

#[test]
fn peer_status_persists_to_jsonl() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("autonomous")).unwrap();

    let snapshot = PeerStatusSnapshot {
        ts_ms: 2000,
        trustmark_bp: 9000,
        chain_seq: 100,
        uptime_ms: 7_200_000,
        screening: ScreeningStats {
            screened: 200,
            quarantined: 5,
            admitted: 195,
            window_secs: 600,
        },
    };
    snapshot.persist(tmp.path());

    let content = std::fs::read_to_string(tmp.path().join("autonomous/peer_status.jsonl")).unwrap();
    let parsed: PeerStatusSnapshot = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed.chain_seq, 100);
}
