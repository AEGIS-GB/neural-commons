//! NATS Bridge — translates HTTP/WSS to internal NATS (D3)
//!
//! Edge Gateway is the SOLE adapter-facing entry point.
//! NATS is internal only — adapters never touch it directly.
//!
//! Translation:
//!   HTTP POST /evidence → NATS publish evidence.new
//!   HTTP POST /rollup → NATS publish evidence.rollup
//!   NATS trustmark.updated → WSS push to bot
//!   NATS broadcast.* → WSS push to all connected bots

use std::sync::Arc;

use async_nats::Client;
use futures::StreamExt;

use crate::routes::compute_trustmark_from_evidence;
use crate::store::EvidenceStore;

// Re-exported from axum (which re-exports from hyper/http-body/bytes)
type Bytes = axum::body::Bytes;

/// Bridge between the Gateway HTTP layer and internal NATS messaging.
///
/// NATS is optional — the Gateway runs without it for local/test deployments.
/// When connected, evidence submissions are published to the EVIDENCE stream
/// for downstream consumers (trustmark-scorer, ledger, etc.).
pub struct NatsBridge {
    client: Client,
}

impl NatsBridge {
    /// Connect to a NATS server at the given URL.
    ///
    /// Returns a connected bridge ready to publish/subscribe.
    pub async fn connect(url: &str) -> Result<Self, async_nats::ConnectError> {
        let client = async_nats::connect(url).await?;
        tracing::info!(url, "connected to NATS");
        Ok(Self { client })
    }

    /// Publish a single evidence receipt to `evidence.new`.
    ///
    /// Downstream consumers (trustmark-scorer) pick this up to recompute scores.
    pub async fn publish_evidence(
        &self,
        receipt_json: &[u8],
    ) -> Result<(), async_nats::PublishError> {
        self.client
            .publish("evidence.new", Bytes::copy_from_slice(receipt_json))
            .await
    }

    /// Publish an evidence rollup to `evidence.rollup`.
    ///
    /// Rollups are Merkle-aggregated batches used by the ledger consumer.
    pub async fn publish_evidence_rollup(
        &self,
        rollup_json: &[u8],
    ) -> Result<(), async_nats::PublishError> {
        self.client
            .publish("evidence.rollup", Bytes::copy_from_slice(rollup_json))
            .await
    }

    /// Publish an updated TRUSTMARK score to `trustmark.updated`.
    ///
    /// Other Gateway instances and downstream consumers subscribe to this
    /// to keep caches and dashboards in sync.
    pub async fn publish_trustmark_update(
        &self,
        bot_id: &str,
        score_json: &[u8],
    ) -> Result<(), async_nats::PublishError> {
        tracing::debug!(bot_id, "publishing trustmark update");
        self.client
            .publish("trustmark.updated", Bytes::copy_from_slice(score_json))
            .await
    }

    /// Subscribe to `evidence.new` and recompute TRUSTMARK for each incoming receipt.
    ///
    /// For each evidence message, the subscriber:
    /// 1. Parses the receipt JSON to extract `bot_fingerprint`
    /// 2. Fetches all evidence for that bot from the store
    /// 3. Recomputes the TRUSTMARK score
    /// 4. Publishes the updated score to `trustmark.updated`
    ///
    /// This runs in a background task and never returns under normal operation.
    pub async fn subscribe_evidence<S: EvidenceStore>(
        &self,
        store: Arc<S>,
    ) -> Result<(), async_nats::SubscribeError> {
        let mut subscriber = self.client.subscribe("evidence.new").await?;
        let client = self.client.clone();

        tokio::spawn(async move {
            tracing::info!("evidence subscriber started on evidence.new");
            while let Some(msg) = subscriber.next().await {
                // Parse receipt to extract bot_fingerprint
                let bot_fingerprint =
                    match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                        Ok(val) => match val.get("bot_fingerprint").and_then(|v| v.as_str()) {
                            Some(fp) => fp.to_string(),
                            None => {
                                tracing::warn!("evidence message missing bot_fingerprint field");
                                continue;
                            }
                        },
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to parse evidence message as JSON");
                            continue;
                        }
                    };

                // Fetch all evidence for this bot and recompute TRUSTMARK
                match store.get_for_bot(&bot_fingerprint).await {
                    Ok(records) => {
                        let score = compute_trustmark_from_evidence(&records);
                        let update = TrustmarkUpdate {
                            bot_id: bot_fingerprint.clone(),
                            score,
                        };
                        match serde_json::to_vec(&update) {
                            Ok(json) => {
                                if let Err(e) = client
                                    .publish("trustmark.updated", Bytes::copy_from_slice(&json))
                                    .await
                                {
                                    tracing::warn!(
                                        bot_id = %bot_fingerprint,
                                        error = %e,
                                        "failed to publish trustmark update"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    bot_id = %bot_fingerprint,
                                    error = %e,
                                    "failed to serialize trustmark update"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            bot_id = %bot_fingerprint,
                            error = %e,
                            "failed to fetch evidence for trustmark recomputation"
                        );
                    }
                }
            }
            tracing::warn!("evidence subscriber ended unexpectedly");
        });

        Ok(())
    }
}

/// TRUSTMARK update message published to `trustmark.updated`.
///
/// Contains the bot ID and the full recomputed score.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustmarkUpdate {
    /// Bot fingerprint (transport pubkey hex)
    pub bot_id: String,
    /// Recomputed TRUSTMARK score
    pub score: aegis_schemas::TrustmarkScore,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{EvidenceRecord, MemoryStore};

    #[test]
    fn nats_bridge_struct_is_send_sync() {
        // NatsBridge must be Send + Sync for use in Arc<> shared state
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NatsBridge>();
    }

    #[tokio::test]
    async fn connect_to_nonexistent_nats_returns_error() {
        // Connecting to a non-existent server should fail (not panic)
        let result = NatsBridge::connect("nats://127.0.0.1:14222").await;
        assert!(
            result.is_err(),
            "should fail to connect to non-running NATS"
        );
    }

    #[test]
    fn trustmark_update_serializes_correctly() {
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
    fn trustmark_update_roundtrip() {
        let records: Vec<EvidenceRecord> = (0..20)
            .map(|i| EvidenceRecord {
                id: format!("receipt-{i}"),
                bot_fingerprint: "bot_abc".to_string(),
                seq: i + 1,
                receipt_type: "api_call".to_string(),
                ts_ms: 1700000000000 + i * 300_000,
                core_json: "{}".to_string(),
                receipt_hash: format!("{:064x}", i),
                request_id: None,
            })
            .collect();

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

    #[tokio::test]
    async fn compute_trustmark_from_store_data() {
        // Test that the TRUSTMARK computation works correctly from store data
        // without any NATS involvement
        let store = MemoryStore::new();
        let bot_id = "test_bot_123";

        // Insert evidence records
        for i in 0..10 {
            let record = EvidenceRecord {
                id: format!("receipt-{i}"),
                bot_fingerprint: bot_id.to_string(),
                seq: i + 1,
                receipt_type: "api_call".to_string(),
                ts_ms: 1700000000000 + i * 60_000,
                core_json: serde_json::json!({
                    "bot_fingerprint": bot_id,
                    "id": format!("receipt-{i}"),
                })
                .to_string(),
                receipt_hash: format!("{:064x}", i),
                request_id: None,
            };
            store.insert(record).await.unwrap();
        }

        // Fetch and compute
        let records = store.get_for_bot(bot_id).await.unwrap();
        assert_eq!(records.len(), 10);

        let score = compute_trustmark_from_evidence(&records);
        assert!(score.score_bp.value() > 0);
        // Chain should be perfect (no gaps, seq 1..10)
        assert_eq!(score.dimensions.chain_integrity.value(), 10000);
    }

    #[test]
    fn trustmark_update_contains_all_dimensions() {
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
}
