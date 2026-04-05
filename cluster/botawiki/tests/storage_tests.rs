//! Integration tests for BotawikiStore — claim submission, quarantine,
//! voting, adaptive quorum, and query/list operations.

use aegis_botawiki::{BotawikiStore, ClaimStatus, StoredClaim, Vote};
use aegis_schemas::claim::{ClaimType, TemporalScope};
use aegis_schemas::{BasisPoints, Claim};
use uuid::Uuid;

fn sample_claim() -> Claim {
    Claim {
        id: Uuid::now_v7(),
        claim_type: ClaimType::Lore,
        namespace: "b/lore".to_string(),
        attester_id: "bot_a".to_string(),
        confidence_bp: BasisPoints::clamped(8000),
        temporal_scope: TemporalScope {
            start_ms: 1700000000000,
            end_ms: None,
        },
        provenance: vec![],
        schema_version: 1,
        confabulation_score_bp: None,
        temporal_coherence_flag: None,
        distinct_warden_count: None,
        payload: serde_json::json!({"key": "value"}),
    }
}

fn three_validators() -> Vec<String> {
    vec!["v1".into(), "v2".into(), "v3".into()]
}

// ── Submission ──────────────────────────────────────────────────────

#[tokio::test]
async fn submit_creates_quarantined_claim() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, three_validators()).await;

    let stored = store.get(&id).await.unwrap();
    assert_eq!(stored.status, ClaimStatus::Quarantine);
    assert_eq!(stored.validators.len(), 3);
    assert!(stored.votes.is_empty());
    assert!(stored.submitted_at_ms > 0);
}

#[tokio::test]
async fn submit_returns_claim_id() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let expected_id = claim.id;
    let returned_id = store.submit(claim, three_validators()).await;
    assert_eq!(returned_id, expected_id);
}

#[tokio::test]
async fn get_nonexistent_returns_none() {
    let store = BotawikiStore::new();
    assert!(store.get(&Uuid::now_v7()).await.is_none());
}

// ── Voting & Quorum ────────────────────────────────────────────────

#[tokio::test]
async fn two_approvals_makes_canonical() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, three_validators()).await;

    let status = store.vote(&id, "v1", true).await.unwrap();
    assert_eq!(status, ClaimStatus::Quarantine);

    let status = store.vote(&id, "v2", true).await.unwrap();
    assert_eq!(status, ClaimStatus::Canonical);
}

#[tokio::test]
async fn two_rejections_tombstones() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, three_validators()).await;

    store.vote(&id, "v1", false).await.unwrap();
    let status = store.vote(&id, "v2", false).await.unwrap();
    assert_eq!(status, ClaimStatus::Tombstoned);
}

#[tokio::test]
async fn non_validator_vote_rejected() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, three_validators()).await;

    let result = store.vote(&id, "intruder", true).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not a selected validator"));
}

#[tokio::test]
async fn double_vote_rejected() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, three_validators()).await;

    store.vote(&id, "v1", true).await.unwrap();
    let result = store.vote(&id, "v1", true).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("already voted"));
}

#[tokio::test]
async fn vote_on_nonexistent_claim_fails() {
    let store = BotawikiStore::new();
    let result = store.vote(&Uuid::now_v7(), "v1", true).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

#[tokio::test]
async fn vote_on_canonical_claim_fails() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, three_validators()).await;

    // Approve to canonical
    store.vote(&id, "v1", true).await.unwrap();
    store.vote(&id, "v2", true).await.unwrap();

    // Third vote on already-canonical claim
    let result = store.vote(&id, "v3", true).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not quarantined"));
}

// ── Adaptive quorum ────────────────────────────────────────────────

#[tokio::test]
async fn single_validator_quorum_one_approval_suffices() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, vec!["v1".into()]).await;

    let status = store.vote(&id, "v1", true).await.unwrap();
    assert_eq!(status, ClaimStatus::Canonical);
}

#[tokio::test]
async fn single_validator_quorum_one_rejection_tombstones() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, vec!["v1".into()]).await;

    let status = store.vote(&id, "v1", false).await.unwrap();
    assert_eq!(status, ClaimStatus::Tombstoned);
}

#[tokio::test]
async fn two_validator_quorum_needs_both() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, vec!["v1".into(), "v2".into()]).await;

    let status = store.vote(&id, "v1", true).await.unwrap();
    assert_eq!(status, ClaimStatus::Quarantine); // 1/2 not enough

    let status = store.vote(&id, "v2", true).await.unwrap();
    assert_eq!(status, ClaimStatus::Canonical); // 2/2 = quorum
}

#[tokio::test]
async fn five_validator_quorum_needs_four() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    let validators: Vec<String> = (1..=5).map(|i| format!("v{i}")).collect();
    store.submit(claim, validators).await;

    store.vote(&id, "v1", true).await.unwrap();
    store.vote(&id, "v2", true).await.unwrap();
    let status = store.vote(&id, "v3", true).await.unwrap();
    assert_eq!(status, ClaimStatus::Quarantine); // 3/5 < ceil(10/3) = 4

    let status = store.vote(&id, "v4", true).await.unwrap();
    assert_eq!(status, ClaimStatus::Canonical); // 4/5 >= 4
}

// ── Summary ────────────────────────────────────────────────────────

#[tokio::test]
async fn summary_counts_all_statuses() {
    let store = BotawikiStore::new();
    let validators = three_validators();

    let c1 = sample_claim();
    let id1 = c1.id;
    store.submit(c1, validators.clone()).await;

    let c2 = sample_claim();
    let id2 = c2.id;
    store.submit(c2, validators.clone()).await;

    let c3 = sample_claim();
    store.submit(c3, validators.clone()).await;

    // Approve c1
    store.vote(&id1, "v1", true).await.unwrap();
    store.vote(&id1, "v2", true).await.unwrap();

    // Reject c2
    store.vote(&id2, "v1", false).await.unwrap();
    store.vote(&id2, "v2", false).await.unwrap();

    let summary = store.summary().await;
    assert_eq!(summary.canonical, 1);
    assert_eq!(summary.tombstoned, 1);
    assert_eq!(summary.quarantine, 1);
    assert_eq!(summary.disputed, 0);
    assert_eq!(summary.total, 3);
    assert_eq!(summary.pending_votes.len(), 1);
}

// ── List all ───────────────────────────────────────────────────────

#[tokio::test]
async fn list_all_returns_all_claims_with_metadata() {
    let store = BotawikiStore::new();
    let validators = three_validators();

    let c1 = sample_claim();
    let id1 = c1.id;
    store.submit(c1, validators.clone()).await;

    let c2 = sample_claim();
    let id2 = c2.id;
    store.submit(c2, validators.clone()).await;
    store.vote(&id2, "v1", true).await.unwrap();
    store.vote(&id2, "v2", true).await.unwrap();

    let all = store.list_all().await;
    assert_eq!(all.len(), 2);

    let q = all.iter().find(|c| c.id == id1).unwrap();
    assert_eq!(q.status, ClaimStatus::Quarantine);
    assert_eq!(q.namespace, "b/lore");
    assert_eq!(q.confidence_bp, 8000);

    let can = all.iter().find(|c| c.id == id2).unwrap();
    assert_eq!(can.status, ClaimStatus::Canonical);
    assert_eq!(can.votes.len(), 2);
}

// ── Query ──────────────────────────────────────────────────────────

#[tokio::test]
async fn query_returns_only_canonical() {
    let store = BotawikiStore::new();
    let validators = three_validators();

    let claim1 = sample_claim();
    let id1 = claim1.id;
    store.submit(claim1, validators.clone()).await;
    store.vote(&id1, "v1", true).await.unwrap();
    store.vote(&id1, "v2", true).await.unwrap();

    // Quarantined — should not appear in query
    let claim2 = sample_claim();
    store.submit(claim2, validators).await;

    let results = store.query(Some("b/lore"), None, 50).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, id1);
}

#[tokio::test]
async fn query_with_namespace_filter() {
    let store = BotawikiStore::new();
    let validators = three_validators();

    let mut c1 = sample_claim();
    c1.namespace = "b/lore".to_string();
    let id1 = c1.id;
    store.submit(c1, validators.clone()).await;
    store.vote(&id1, "v1", true).await.unwrap();
    store.vote(&id1, "v2", true).await.unwrap();

    let mut c2 = sample_claim();
    c2.namespace = "b/skills".to_string();
    let id2 = c2.id;
    store.submit(c2, validators.clone()).await;
    store.vote(&id2, "v1", true).await.unwrap();
    store.vote(&id2, "v2", true).await.unwrap();

    let lore = store.query(Some("b/lore"), None, 50).await;
    assert_eq!(lore.len(), 1);
    assert_eq!(lore[0].namespace, "b/lore");

    let skills = store.query(Some("b/skills"), None, 50).await;
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].namespace, "b/skills");

    let all = store.query(None, None, 50).await;
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn query_respects_limit() {
    let store = BotawikiStore::new();
    let validators = three_validators();

    for _ in 0..5 {
        let c = sample_claim();
        let id = c.id;
        store.submit(c, validators.clone()).await;
        store.vote(&id, "v1", true).await.unwrap();
        store.vote(&id, "v2", true).await.unwrap();
    }

    let results = store.query(None, None, 3).await;
    assert_eq!(results.len(), 3);
}

// ── Restore (replay) ──────────────────────────────────────────────

#[tokio::test]
async fn restore_replays_stored_claim() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;

    let stored = StoredClaim {
        claim,
        status: ClaimStatus::Canonical,
        votes: vec![
            Vote {
                validator_id: "v1".into(),
                approve: true,
                ts_ms: 1700000000000,
            },
            Vote {
                validator_id: "v2".into(),
                approve: true,
                ts_ms: 1700000000001,
            },
        ],
        validators: vec!["v1".into(), "v2".into(), "v3".into()],
        submitted_at_ms: 1700000000000,
    };

    store.restore(stored).await;

    let retrieved = store.get(&id).await.unwrap();
    assert_eq!(retrieved.status, ClaimStatus::Canonical);
    assert_eq!(retrieved.votes.len(), 2);
    assert_eq!(retrieved.validators.len(), 3);
    assert_eq!(retrieved.claim.namespace, "b/lore");
}

// ── Serialization roundtrip ────────────────────────────────────────

#[tokio::test]
async fn stored_claim_serialization_roundtrip() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    let id = claim.id;
    store.submit(claim, three_validators()).await;
    store.vote(&id, "v1", true).await.unwrap();

    let stored = store.get(&id).await.unwrap();
    let json = serde_json::to_vec(&stored).unwrap();
    let deserialized: StoredClaim = serde_json::from_slice(&json).unwrap();

    assert_eq!(deserialized.claim.id, id);
    assert_eq!(deserialized.status, ClaimStatus::Quarantine);
    assert_eq!(deserialized.votes.len(), 1);
    assert_eq!(deserialized.votes[0].validator_id, "v1");
    assert!(deserialized.votes[0].approve);
}

#[tokio::test]
async fn claim_summary_serialization_roundtrip() {
    let store = BotawikiStore::new();
    let claim = sample_claim();
    store.submit(claim, three_validators()).await;

    let summary = store.summary().await;
    let json = serde_json::to_vec(&summary).unwrap();
    let deserialized: aegis_botawiki::ClaimSummary = serde_json::from_slice(&json).unwrap();

    assert_eq!(deserialized.quarantine, 1);
    assert_eq!(deserialized.total, 1);
    assert_eq!(deserialized.pending_votes.len(), 1);
}

#[test]
fn claim_status_serialization() {
    let canonical = ClaimStatus::Canonical;
    let json = serde_json::to_string(&canonical).unwrap();
    assert_eq!(json, "\"canonical\"");

    let quarantine: ClaimStatus = serde_json::from_str("\"quarantine\"").unwrap();
    assert_eq!(quarantine, ClaimStatus::Quarantine);

    let tombstoned: ClaimStatus = serde_json::from_str("\"tombstoned\"").unwrap();
    assert_eq!(tombstoned, ClaimStatus::Tombstoned);
}
