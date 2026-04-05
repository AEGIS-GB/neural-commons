//! Cluster-side TRUSTMARK scoring from evidence records.
//!
//! This is the simplified scoring that works from receipt metadata only
//! (no adapter-side signals like persona integrity or vault hygiene).
//! Moved from `aegis-gateway::routes::compute_trustmark_from_evidence`.

use serde::{Deserialize, Serialize};

/// A receipt record as used by the cluster evidence pipeline.
///
/// Mirror of the Gateway's `EvidenceRecord` — both serialize to the same JSON
/// wire format so NATS messages are compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Receipt UUID (from ReceiptCore.id)
    pub id: String,
    /// Bot's transport pubkey (from auth middleware)
    pub bot_fingerprint: String,
    /// Monotonic sequence number
    pub seq: i64,
    /// Receipt type (snake_case string)
    pub receipt_type: String,
    /// Unix epoch milliseconds
    pub ts_ms: i64,
    /// JCS-canonicalized receipt core JSON
    pub core_json: String,
    /// Receipt hash (SHA-256 of core, lowercase hex)
    pub receipt_hash: String,
    /// Pipeline request ID (optional)
    pub request_id: Option<String>,
}

/// TRUSTMARK update message published to `trustmark.updated`.
///
/// Contains the bot ID and the full recomputed score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustmarkUpdate {
    /// Bot fingerprint (transport pubkey hex)
    pub bot_id: String,
    /// Recomputed TRUSTMARK score
    pub score: aegis_schemas::TrustmarkScore,
}

/// Compute a basic TRUSTMARK score from cluster-stored evidence.
///
/// This is a simplified cluster-side scoring that works from receipt metadata
/// only (no adapter-side signals like persona integrity or vault hygiene).
/// Dimensions backed by adapter-only data are set to conservative defaults.
pub fn compute_trustmark_from_evidence(
    records: &[EvidenceRecord],
) -> aegis_schemas::TrustmarkScore {
    let bp = |v: f64| aegis_schemas::BasisPoints::clamped((v * 10_000.0).round() as u32);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Chain integrity: check sequence is monotonic with no gaps
    let chain_integrity = if records.is_empty() {
        0.3 // no evidence yet
    } else {
        let mut sorted = records.to_vec();
        sorted.sort_by_key(|r| r.seq);
        let has_gaps = sorted.windows(2).any(|w| w[1].seq != w[0].seq + 1);
        if has_gaps {
            0.5 // gaps in sequence
        } else {
            1.0 // monotonic, no gaps
        }
    };

    // Contribution volume: receipts in last 24h vs baseline of 100
    let baseline = 100.0_f64;
    let day_ago = now_ms - 86_400_000;
    let recent_count = records.iter().filter(|r| r.ts_ms > day_ago).count() as f64;
    let contribution_volume = (recent_count / baseline).min(1.0);

    // Temporal consistency: coefficient of variation of inter-receipt intervals
    let temporal_consistency = if records.len() < 3 {
        0.5
    } else {
        let mut timestamps: Vec<i64> = records.iter().map(|r| r.ts_ms).collect();
        timestamps.sort();
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .collect();
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean == 0.0 {
            0.5
        } else {
            let variance =
                intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
            let cv = variance.sqrt() / mean;
            (1.0 - (cv - 0.5).max(0.0) / 1.5).clamp(0.2, 1.0)
        }
    };

    // Dimensions only observable from adapter side -- conservative defaults
    let persona_integrity = 0.5; // unknown from cluster
    let vault_hygiene = 0.5; // unknown from cluster
    let relay_reliability = 0.5; // mesh not active

    // Weighted sum (same weights as D13)
    let total = persona_integrity * 0.25
        + chain_integrity * 0.20
        + vault_hygiene * 0.15
        + temporal_consistency * 0.15
        + relay_reliability * 0.15
        + contribution_volume * 0.10;

    let tier = if total >= 0.40 {
        aegis_schemas::trustmark::Tier::Tier3
    } else if total >= 0.20 {
        aegis_schemas::trustmark::Tier::Tier2
    } else {
        aegis_schemas::trustmark::Tier::Tier1
    };

    aegis_schemas::TrustmarkScore {
        score_bp: bp(total),
        dimensions: aegis_schemas::trustmark::TrustmarkDimensions {
            relay_reliability: bp(relay_reliability),
            persona_integrity: bp(persona_integrity),
            chain_integrity: bp(chain_integrity),
            contribution_volume: bp(contribution_volume),
            temporal_consistency: bp(temporal_consistency),
            vault_hygiene: bp(vault_hygiene),
        },
        tier,
        computed_at_ms: now_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_records_returns_conservative_score() {
        let score = compute_trustmark_from_evidence(&[]);
        assert!(score.score_bp.value() > 0);
        // Chain integrity defaults to 0.3 for no evidence
        assert_eq!(score.dimensions.chain_integrity.value(), 3000);
    }

    #[test]
    fn single_record() {
        let records = vec![EvidenceRecord {
            id: "r-0".to_string(),
            bot_fingerprint: "bot1".to_string(),
            seq: 1,
            receipt_type: "api_call".to_string(),
            ts_ms: 1700000000000,
            core_json: "{}".to_string(),
            receipt_hash: format!("{:064x}", 0),
            request_id: None,
        }];
        let score = compute_trustmark_from_evidence(&records);
        assert!(score.score_bp.value() > 0);
        // Single record: perfect chain (no gaps possible)
        assert_eq!(score.dimensions.chain_integrity.value(), 10000);
        // Temporal consistency defaults to 0.5 for < 3 records
        assert_eq!(score.dimensions.temporal_consistency.value(), 5000);
    }

    #[test]
    fn perfect_chain_no_gaps() {
        let records: Vec<EvidenceRecord> = (0..100)
            .map(|i| EvidenceRecord {
                id: format!("r-{i}"),
                bot_fingerprint: "bot1".to_string(),
                seq: i + 1,
                receipt_type: "api_call".to_string(),
                ts_ms: 1700000000000 + i * 300_000, // 5 min apart
                core_json: "{}".to_string(),
                receipt_hash: format!("{:064x}", i),
                request_id: None,
            })
            .collect();
        let score = compute_trustmark_from_evidence(&records);
        assert_eq!(score.dimensions.chain_integrity.value(), 10000);
    }

    #[test]
    fn broken_chain_with_gaps() {
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
                seq: 5, // gap: seq jumps from 1 to 5
                receipt_type: "api_call".to_string(),
                ts_ms: 1700000060000,
                core_json: "{}".to_string(),
                receipt_hash: format!("{:064x}", 1),
                request_id: None,
            },
        ];
        let score = compute_trustmark_from_evidence(&records);
        // Chain integrity should be 0.5 (gaps detected)
        assert_eq!(score.dimensions.chain_integrity.value(), 5000);
    }

    #[test]
    fn trustmark_update_serialization_roundtrip() {
        let records: Vec<EvidenceRecord> = (0..5)
            .map(|i| EvidenceRecord {
                id: format!("r-{i}"),
                bot_fingerprint: "bot1".to_string(),
                seq: i + 1,
                receipt_type: "api_call".to_string(),
                ts_ms: 1700000000000 + i * 60_000,
                core_json: "{}".to_string(),
                receipt_hash: format!("{:064x}", i),
                request_id: None,
            })
            .collect();

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
    fn all_dimensions_present() {
        let records = vec![EvidenceRecord {
            id: "r-0".to_string(),
            bot_fingerprint: "bot1".to_string(),
            seq: 1,
            receipt_type: "api_call".to_string(),
            ts_ms: 1700000000000,
            core_json: "{}".to_string(),
            receipt_hash: format!("{:064x}", 0),
            request_id: None,
        }];

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

    #[test]
    fn tier_assignment() {
        // Empty records should still get a valid tier
        let score = compute_trustmark_from_evidence(&[]);
        // With conservative defaults, total ~ 0.3+, so should be Tier2 or Tier3
        let tier_json = serde_json::to_value(score.tier).unwrap();
        let tier_str = tier_json.as_str().unwrap();
        assert!(
            tier_str == "tier1" || tier_str == "tier2" || tier_str == "tier3",
            "unexpected tier: {tier_str}"
        );
    }
}
