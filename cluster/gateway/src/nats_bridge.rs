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

use std::collections::HashMap;
use std::sync::Arc;

use async_nats::Client;
use futures::StreamExt;
use tokio::sync::RwLock;

use crate::botawiki::BotawikiStore;
use crate::mesh_routes::{RelayEvent, RelayLog};
use crate::store::EvidenceStore;
use crate::ws::DeadDropStore;

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

    /// Get a reference to the underlying NATS client.
    ///
    /// Used by embedded mode to pass the connection to in-process services.
    pub fn client(&self) -> &Client {
        &self.client
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

    /// Set up JetStream streams for durable persistence.
    /// Creates streams if they don't exist, or verifies existing ones.
    pub async fn setup_jetstream(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let jetstream = async_nats::jetstream::new(self.client.clone());

        // EVIDENCE stream — file-backed, 30-day retention
        let _ = jetstream
            .get_or_create_stream(async_nats::jetstream::stream::Config {
                name: "EVIDENCE".to_string(),
                subjects: vec!["evidence.>".to_string()],
                retention: async_nats::jetstream::stream::RetentionPolicy::Limits,
                max_age: std::time::Duration::from_secs(30 * 24 * 3600), // 30 days
                storage: async_nats::jetstream::stream::StorageType::File,
                ..Default::default()
            })
            .await?;

        // MESH stream — relay events, claims, dead-drops
        let _ = jetstream
            .get_or_create_stream(async_nats::jetstream::stream::Config {
                name: "MESH".to_string(),
                subjects: vec!["mesh.>".to_string(), "botawiki.>".to_string()],
                retention: async_nats::jetstream::stream::RetentionPolicy::Limits,
                max_age: std::time::Duration::from_secs(7 * 24 * 3600), // 7 days
                storage: async_nats::jetstream::stream::StorageType::File,
                ..Default::default()
            })
            .await?;

        // TRUSTMARK stream — latest scores only
        let _ = jetstream
            .get_or_create_stream(async_nats::jetstream::stream::Config {
                name: "TRUSTMARK".to_string(),
                subjects: vec!["trustmark.>".to_string()],
                retention: async_nats::jetstream::stream::RetentionPolicy::Limits,
                max_age: std::time::Duration::from_secs(7 * 24 * 3600),
                storage: async_nats::jetstream::stream::StorageType::File,
                ..Default::default()
            })
            .await?;

        tracing::info!("JetStream streams configured (EVIDENCE, MESH, TRUSTMARK)");
        Ok(())
    }

    /// Publish a mesh event (relay, claim, dead-drop) to a NATS subject.
    ///
    /// JetStream captures these via subject matching on the MESH stream.
    pub async fn publish_mesh_event(
        &self,
        subject: &str,
        payload: &[u8],
    ) -> Result<(), async_nats::PublishError> {
        self.client
            .publish(subject.to_string(), Bytes::copy_from_slice(payload))
            .await
    }

    /// Replay JetStream streams to rebuild in-memory state.
    /// Called once on Gateway startup after JetStream setup.
    /// Replays MESH stream (relay log, Botawiki claims) and EVIDENCE stream (evidence store).
    pub async fn replay_mesh_stream<S: EvidenceStore>(
        &self,
        botawiki_store: Arc<BotawikiStore>,
        relay_log: Arc<RelayLog>,
        _dead_drop_store: Arc<DeadDropStore>,
        evidence_store: Option<S>,
        trustmark_cache: Option<Arc<TrustmarkCache>>,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let jetstream = async_nats::jetstream::new(self.client.clone());
        let mut total_replayed = 0usize;

        // Replay MESH stream (relay log + Botawiki claims)
        if let Ok(mut stream) = jetstream.get_stream("MESH").await {
            let info = stream.info().await?;
            tracing::info!(messages = info.state.messages, "replaying MESH stream");

            let consumer = stream
                .create_consumer(async_nats::jetstream::consumer::pull::Config {
                    deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
                    ack_policy: async_nats::jetstream::consumer::AckPolicy::None,
                    name: Some(format!("replay-mesh-{}", std::process::id())),
                    ..Default::default()
                })
                .await?;

            let mut messages = consumer.messages().await?;
            while let Ok(Some(msg)) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                futures::StreamExt::next(&mut messages),
            )
            .await
            {
                if let Ok(msg) = msg {
                    let subject = msg.subject.as_str();
                    match subject {
                        "mesh.relay" => {
                            if let Ok(event) = serde_json::from_slice::<RelayEvent>(&msg.payload) {
                                relay_log.push(event);
                            }
                        }
                        "botawiki.claim.stored" => {
                            if let Ok(stored) =
                                serde_json::from_slice::<crate::botawiki::StoredClaim>(&msg.payload)
                            {
                                botawiki_store.restore(stored).await;
                            }
                        }
                        _ => {}
                    }
                    total_replayed += 1;
                }
            }
        } else {
            tracing::info!("MESH stream not found, nothing to replay");
        }

        // Replay EVIDENCE stream (rebuild evidence store + TRUSTMARK cache)
        if let (Some(store), Some(cache)) = (&evidence_store, &trustmark_cache)
            && let Ok(mut stream) = jetstream.get_stream("EVIDENCE").await
        {
            let info = stream.info().await?;
            tracing::info!(messages = info.state.messages, "replaying EVIDENCE stream");

            let consumer = stream
                .create_consumer(async_nats::jetstream::consumer::pull::Config {
                    deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
                    ack_policy: async_nats::jetstream::consumer::AckPolicy::None,
                    name: Some(format!("replay-evidence-{}", std::process::id())),
                    ..Default::default()
                })
                .await?;

            let mut messages = consumer.messages().await?;
            let mut evidence_count = 0u64;
            let mut bot_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

            while let Ok(Some(msg)) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                futures::StreamExt::next(&mut messages),
            )
            .await
            {
                if let Ok(msg) = msg {
                    // Parse the submitted receipt and insert into store
                    if let Ok(receipt) =
                        serde_json::from_slice::<crate::routes::SubmittedReceipt>(&msg.payload)
                    {
                        // Extract bot_fingerprint from the receipt's context
                        // The receipt was published with the full JSON; we need the bot_fingerprint
                        // which is stored in the evidence record, not the receipt itself.
                        // Use the bot_fingerprint field if present, otherwise try to extract from JSON
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&msg.payload)
                            && let Some(fp) = val.get("bot_fingerprint").and_then(|v| v.as_str())
                        {
                            bot_ids.insert(fp.to_string());
                            let record = crate::store::EvidenceRecord {
                                id: receipt.id.clone(),
                                bot_fingerprint: fp.to_string(),
                                seq: receipt.seq,
                                receipt_type: receipt.receipt_type.clone(),
                                ts_ms: receipt.ts_ms,
                                core_json: String::from_utf8_lossy(&msg.payload).to_string(),
                                receipt_hash: receipt.receipt_hash.clone(),
                                request_id: receipt.request_id.clone(),
                            };
                            let _ = store.insert(record).await;
                            evidence_count += 1;
                        }
                    }
                    total_replayed += 1;
                }
            }

            tracing::info!(
                evidence_count,
                bots = bot_ids.len(),
                "evidence replay complete"
            );

            // Recompute TRUSTMARK for all seen bots
            for bot_id in &bot_ids {
                if let Ok(records) = store.get_for_bot(bot_id).await
                    && !records.is_empty()
                {
                    let score = crate::routes::compute_trustmark_from_evidence(&records);
                    let cached = CachedScore {
                        score_bp: score.score_bp.value(),
                        dimensions: serde_json::to_value(&score.dimensions).unwrap_or_default(),
                        tier: serde_json::to_value(score.tier)
                            .map(|v| v.as_str().unwrap_or("tier1").to_string())
                            .unwrap_or_else(|_| "tier1".to_string()),
                        computed_at_ms: score.computed_at_ms,
                    };
                    cache.insert(bot_id.clone(), cached).await;
                    tracing::debug!(
                        bot_id,
                        score_bp = score.score_bp.value(),
                        "TRUSTMARK recomputed from evidence replay"
                    );
                }
            }
        }

        tracing::info!(total_replayed, "stream replay complete");
        Ok(total_replayed)
    }

    /// Subscribe to `mesh.relay.screened` and `mesh.relay.quarantined` for
    /// delivery of screened relay messages from the Mesh Relay service.
    ///
    /// - `mesh.relay.screened`: message passed screening — deliver via WSS or dead-drop
    /// - `mesh.relay.quarantined`: message failed screening — update stats/log
    pub async fn subscribe_relay_delivery(
        &self,
        wss_registry: Arc<crate::ws::WssConnectionRegistry>,
        dead_drop_store: Arc<DeadDropStore>,
        relay_stats_counters: Arc<crate::mesh_routes::RelayStats>,
        relay_log: Arc<RelayLog>,
        nats_bridge: Option<Arc<NatsBridge>>,
    ) -> Result<(), async_nats::SubscribeError> {
        // Subscribe to screened messages — deliver to recipients
        let mut screened_sub = self.client.subscribe("mesh.relay.screened").await?;
        let wss = wss_registry.clone();
        let dd = dead_drop_store.clone();
        let stats = relay_stats_counters.clone();
        let log = relay_log.clone();
        let bridge = nats_bridge.clone();

        tokio::spawn(async move {
            tracing::info!("relay delivery subscriber started on mesh.relay.screened");
            while let Some(msg) = screened_sub.next().await {
                if let Ok(screened) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                    let from = screened["from"].as_str().unwrap_or_default();
                    let to = screened["to"].as_str().unwrap_or_default();
                    let body = screened["body"].as_str().unwrap_or_default();
                    let msg_type = screened["msg_type"].as_str().unwrap_or("relay");

                    let _ = crate::routes::deliver_relay_message(
                        from, to, body, msg_type, &wss, &dd, &stats, &log, &bridge,
                    )
                    .await;
                } else {
                    tracing::warn!("malformed mesh.relay.screened message");
                }
            }
            tracing::warn!("relay delivery subscriber ended unexpectedly");
        });

        // Subscribe to quarantined messages — update stats/log
        let mut quarantined_sub = self.client.subscribe("mesh.relay.quarantined").await?;
        let stats2 = relay_stats_counters;
        let log2 = relay_log;

        tokio::spawn(async move {
            tracing::info!("relay quarantine subscriber started on mesh.relay.quarantined");
            while let Some(msg) = quarantined_sub.next().await {
                if let Ok(quarantined) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                    let from = quarantined["from"].as_str().unwrap_or_default().to_string();
                    let to = quarantined["to"].as_str().unwrap_or_default().to_string();
                    let reason = quarantined["reason"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let msg_type = quarantined["msg_type"]
                        .as_str()
                        .unwrap_or("relay")
                        .to_string();
                    let body = quarantined["body"].as_str().unwrap_or_default().to_string();

                    stats2
                        .quarantined
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let relay_event = RelayEvent {
                        from,
                        to,
                        status: "quarantined".into(),
                        msg_type,
                        ts_ms: chrono::Utc::now().timestamp_millis(),
                        reason,
                        body_preview: body,
                    };
                    log2.push(relay_event);
                    tracing::warn!("relay message quarantined by Mesh Relay service");
                } else {
                    tracing::warn!("malformed mesh.relay.quarantined message");
                }
            }
            tracing::warn!("relay quarantine subscriber ended unexpectedly");
        });

        Ok(())
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

    // TRUSTMARK recomputation from evidence.new has been extracted to the
    // aegis-trustmark-engine service (Phase 2). The Gateway no longer subscribes
    // to evidence.new for inline recomputation — the TRUSTMARK Engine handles it.

    /// Subscribe to `trustmark.updated` and update the local cache.
    ///
    /// This implements the `gateway-cache` consumer pattern from the NATS topology:
    /// push delivery, ack-none. Each incoming message updates the in-memory
    /// cache so `GET /trustmark/:bot_id` can serve cached scores.
    pub async fn subscribe_trustmark(
        &self,
        cache: Arc<TrustmarkCache>,
    ) -> Result<(), async_nats::SubscribeError> {
        let mut subscriber = self.client.subscribe("trustmark.updated").await?;

        tokio::spawn(async move {
            tracing::info!("trustmark cache subscriber started on trustmark.updated");
            while let Some(msg) = subscriber.next().await {
                match serde_json::from_slice::<TrustmarkUpdate>(&msg.payload) {
                    Ok(update) => {
                        let cached = CachedScore {
                            score_bp: update.score.score_bp.value(),
                            dimensions: serde_json::to_value(&update.score.dimensions)
                                .unwrap_or_default(),
                            tier: serde_json::to_value(update.score.tier)
                                .map(|v| v.as_str().unwrap_or("tier1").to_string())
                                .unwrap_or_else(|_| "tier1".to_string()),
                            computed_at_ms: update.score.computed_at_ms,
                        };
                        tracing::debug!(bot_id = %update.bot_id, score_bp = cached.score_bp, "cache updated");
                        cache.insert(update.bot_id, cached).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse trustmark.updated message");
                    }
                }
            }
            tracing::warn!("trustmark cache subscriber ended unexpectedly");
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

/// Cached TRUSTMARK score entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedScore {
    /// Overall score in basis points
    pub score_bp: u32,
    /// Per-dimension breakdown (serialized for flexibility)
    pub dimensions: serde_json::Value,
    /// Tier string
    pub tier: String,
    /// Unix epoch milliseconds when this score was computed
    pub computed_at_ms: i64,
}

/// In-memory cache of TRUSTMARK scores, updated via NATS subscription.
///
/// The cache is populated by `subscribe_trustmark` which listens for
/// `trustmark.updated` messages. The `GET /trustmark/:bot_id` handler
/// checks this cache first before falling back to evidence-based computation.
#[derive(Debug, Clone, Default)]
pub struct TrustmarkCache {
    scores: Arc<RwLock<HashMap<String, CachedScore>>>,
}

impl TrustmarkCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a cached score for a bot.
    pub async fn insert(&self, bot_id: String, score: CachedScore) {
        self.scores.write().await.insert(bot_id, score);
    }

    /// Look up a cached score for a bot.
    pub async fn get(&self, bot_id: &str) -> Option<CachedScore> {
        self.scores.read().await.get(bot_id).cloned()
    }

    /// Return the number of cached entries.
    pub async fn len(&self) -> usize {
        self.scores.read().await.len()
    }

    /// Check if the cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.scores.read().await.is_empty()
    }

    /// Return the top N bot IDs by score_bp, excluding a given bot_id.
    /// Used for validator/evaluator selection.
    pub async fn top_scores(&self, n: usize, exclude: &str) -> Vec<(String, u32)> {
        let scores = self.scores.read().await;
        let mut entries: Vec<(String, u32)> = scores
            .iter()
            .filter(|(id, _)| id.as_str() != exclude)
            .map(|(id, s)| (id.clone(), s.score_bp))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(n);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::compute_trustmark_from_evidence;
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

    #[tokio::test]
    async fn setup_jetstream_without_nats() {
        // Verify graceful failure when NATS is not running
        let result = NatsBridge::connect("nats://127.0.0.1:14222").await;
        assert!(result.is_err(), "should fail without NATS server");
        // The Gateway handles this by skipping JetStream setup entirely
        // when NatsBridge::connect fails. This test verifies the connect
        // path returns Err (not panic) so the caller can handle it.
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
