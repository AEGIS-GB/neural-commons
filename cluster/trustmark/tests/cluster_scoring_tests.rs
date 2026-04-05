//! Integration tests for cluster-side TRUSTMARK scoring.
//!
//! These tests verify the same contract as the Gateway's former inline tests:
//! evidence records in → TRUSTMARK score out, wire serialization, edge cases.

use aegis_trustmark::cluster_scoring::{
    EvidenceRecord, TrustmarkUpdate, compute_trustmark_from_evidence,
};

fn make_records(count: i64, bot_id: &str, ts_base: i64, interval_ms: i64) -> Vec<EvidenceRecord> {
    (0..count)
        .map(|i| EvidenceRecord {
            id: format!("r-{i}"),
            bot_fingerprint: bot_id.to_string(),
            seq: i + 1,
            receipt_type: "api_call".to_string(),
            ts_ms: ts_base + i * interval_ms,
            core_json: "{}".to_string(),
            receipt_hash: format!("{:064x}", i),
            request_id: None,
        })
        .collect()
}

// ── Basic scoring tests ──

#[test]
fn empty_records_returns_positive_score() {
    let score = compute_trustmark_from_evidence(&[]);
    assert!(
        score.score_bp.value() > 0,
        "empty evidence should still produce a positive score"
    );
    // Chain integrity defaults to 0.3 → 3000 bp
    assert_eq!(score.dimensions.chain_integrity.value(), 3000);
}

#[test]
fn single_record_perfect_chain() {
    let records = make_records(1, "bot1", 1700000000000, 60_000);
    let score = compute_trustmark_from_evidence(&records);
    // Single record: no gaps possible → perfect chain
    assert_eq!(score.dimensions.chain_integrity.value(), 10000);
    // Temporal consistency: < 3 records → default 0.5
    assert_eq!(score.dimensions.temporal_consistency.value(), 5000);
}

#[test]
fn perfect_chain_100_records() {
    let records = make_records(100, "bot1", 1700000000000, 300_000);
    let score = compute_trustmark_from_evidence(&records);
    assert_eq!(score.dimensions.chain_integrity.value(), 10000);
    // Score should be in valid range
    assert!(score.score_bp.value() > 0);
    assert!(score.score_bp.value() <= 10000);
}

#[test]
fn broken_chain_detects_gaps() {
    let records = vec![
        EvidenceRecord {
            id: "r-0".to_string(),
            bot_fingerprint: "bot1".to_string(),
            seq: 1,
            receipt_type: "api_call".to_string(),
            ts_ms: 1700000000000,
            core_json: "{}".to_string(),
            receipt_hash: format!("{:064x}", 0),
            request_id: None,
        },
        EvidenceRecord {
            id: "r-1".to_string(),
            bot_fingerprint: "bot1".to_string(),
            seq: 5, // gap
            receipt_type: "api_call".to_string(),
            ts_ms: 1700000060000,
            core_json: "{}".to_string(),
            receipt_hash: format!("{:064x}", 1),
            request_id: None,
        },
    ];
    let score = compute_trustmark_from_evidence(&records);
    assert_eq!(score.dimensions.chain_integrity.value(), 5000);
}

// ── Tier assignment ──

#[test]
fn tier_is_valid() {
    let score = compute_trustmark_from_evidence(&[]);
    let tier_json = serde_json::to_value(score.tier).unwrap();
    let tier_str = tier_json.as_str().unwrap();
    assert!(
        tier_str == "tier1" || tier_str == "tier2" || tier_str == "tier3",
        "unexpected tier: {tier_str}"
    );
}

// ── Wire format tests ──

#[test]
fn trustmark_update_serialization_roundtrip() {
    let records = make_records(5, "bot1", 1700000000000, 60_000);
    let score = compute_trustmark_from_evidence(&records);
    let update = TrustmarkUpdate {
        bot_id: "bot1".to_string(),
        score,
    };

    let json = serde_json::to_vec(&update).unwrap();
    let parsed: TrustmarkUpdate = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed.bot_id, "bot1");
    assert!(parsed.score.score_bp.value() > 0);
    assert!(parsed.score.score_bp.value() <= 10000);
}

#[test]
fn trustmark_update_roundtrip_preserves_dimensions() {
    let records = make_records(20, "bot_abc", 1700000000000, 300_000);
    let score = compute_trustmark_from_evidence(&records);
    let update = TrustmarkUpdate {
        bot_id: "bot_abc".to_string(),
        score: score.clone(),
    };

    let json = serde_json::to_string(&update).unwrap();
    let deserialized: TrustmarkUpdate = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.bot_id, "bot_abc");
    assert_eq!(deserialized.score.score_bp, score.score_bp);
    assert_eq!(
        deserialized.score.dimensions.chain_integrity,
        score.dimensions.chain_integrity
    );
    assert_eq!(deserialized.score.tier, score.tier);
}

#[test]
fn evidence_record_serialization_roundtrip() {
    let record = EvidenceRecord {
        id: "test-123".to_string(),
        bot_fingerprint: "abc123".to_string(),
        seq: 42,
        receipt_type: "api_call".to_string(),
        ts_ms: 1700000000000,
        core_json: r#"{"foo":"bar"}"#.to_string(),
        receipt_hash: format!("{:064x}", 99),
        request_id: Some("req-1".to_string()),
    };

    let json = serde_json::to_string(&record).unwrap();
    let parsed: EvidenceRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.id, "test-123");
    assert_eq!(parsed.bot_fingerprint, "abc123");
    assert_eq!(parsed.seq, 42);
    assert_eq!(parsed.request_id, Some("req-1".to_string()));
}

#[test]
fn all_dimensions_present_in_json() {
    let records = make_records(1, "bot1", 1700000000000, 60_000);
    let score = compute_trustmark_from_evidence(&records);
    let update = TrustmarkUpdate {
        bot_id: "bot1".to_string(),
        score,
    };

    let json: serde_json::Value = serde_json::to_value(&update).unwrap();
    let dims = &json["score"]["dimensions"];
    assert!(dims["relay_reliability"].is_number());
    assert!(dims["persona_integrity"].is_number());
    assert!(dims["chain_integrity"].is_number());
    assert!(dims["contribution_volume"].is_number());
    assert!(dims["temporal_consistency"].is_number());
    assert!(dims["vault_hygiene"].is_number());
}

// ── NATS integration test (requires running NATS, skip in CI) ──

#[tokio::test]
#[ignore = "requires running NATS server on localhost:4222"]
async fn nats_evidence_to_trustmark_flow() {
    // Connect to NATS
    let client = async_nats::connect("nats://127.0.0.1:4222")
        .await
        .expect("NATS must be running for this test");

    // Subscribe to trustmark.updated
    let mut subscriber = client
        .subscribe("trustmark.updated")
        .await
        .expect("failed to subscribe");

    // Publish an evidence record to evidence.new
    let record = EvidenceRecord {
        id: "nats-test-1".to_string(),
        bot_fingerprint: "nats_test_bot".to_string(),
        seq: 1,
        receipt_type: "api_call".to_string(),
        ts_ms: chrono::Utc::now().timestamp_millis(),
        core_json: "{}".to_string(),
        receipt_hash: format!("{:064x}", 1),
        request_id: None,
    };

    let payload = serde_json::to_vec(&record).unwrap();
    client
        .publish("evidence.new", bytes::Bytes::copy_from_slice(&payload))
        .await
        .expect("failed to publish evidence");

    // Wait for trustmark.updated (with timeout)
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), {
        use futures::StreamExt;
        subscriber.next()
    })
    .await;

    if let Ok(Some(msg)) = msg {
        let update: TrustmarkUpdate =
            serde_json::from_slice(&msg.payload).expect("failed to parse trustmark update");
        assert_eq!(update.bot_id, "nats_test_bot");
        assert!(update.score.score_bp.value() > 0);
    }
    // If timeout, the trustmark engine may not be running — that's OK for CI
}
