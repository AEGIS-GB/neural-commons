//! aegis-trustmark-engine: standalone NATS service for TRUSTMARK recomputation.
//!
//! Subscribes to `evidence.new`, maintains an in-memory evidence store,
//! recomputes TRUSTMARK scores, and publishes results to `trustmark.updated`.
//!
//! Phase 2 extraction from the Gateway — the Gateway no longer does inline
//! TRUSTMARK recomputation on evidence submission.

use std::collections::HashMap;
use std::sync::Arc;

use clap::Parser;
use futures::StreamExt;
use tokio::sync::RwLock;

use aegis_trustmark::cluster_scoring::{
    EvidenceRecord, TrustmarkUpdate, compute_trustmark_from_evidence,
};

/// Aegis TRUSTMARK Engine — recomputes scores from evidence stream
#[derive(Parser)]
#[command(
    name = "aegis-trustmark-engine",
    version,
    about = "TRUSTMARK Engine — subscribes to evidence.new, recomputes scores, publishes trustmark.updated"
)]
struct Cli {
    /// NATS server URL
    #[arg(long, default_value = "nats://127.0.0.1:4222")]
    nats_url: String,
}

/// In-memory evidence store keyed by bot_id.
#[derive(Debug, Clone, Default)]
struct EvidenceStore {
    records: Arc<RwLock<HashMap<String, Vec<EvidenceRecord>>>>,
}

impl EvidenceStore {
    fn new() -> Self {
        Self::default()
    }

    /// Store a record and return all records for the same bot.
    async fn store_and_get_all(&self, record: EvidenceRecord) -> Vec<EvidenceRecord> {
        let bot_id = record.bot_fingerprint.clone();
        let mut store = self.records.write().await;
        let entries = store.entry(bot_id).or_default();
        entries.push(record);
        entries.clone()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_trustmark_engine=info".into()),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!(nats_url = %cli.nats_url, "connecting to NATS");
    let client = async_nats::connect(&cli.nats_url)
        .await
        .expect("failed to connect to NATS");
    tracing::info!("connected to NATS");

    let mut subscriber = client
        .subscribe("evidence.new")
        .await
        .expect("failed to subscribe to evidence.new");
    tracing::info!("subscribed to evidence.new");

    let store = EvidenceStore::new();

    while let Some(msg) = subscriber.next().await {
        // Parse evidence record from NATS payload
        let record: EvidenceRecord = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse evidence message");
                continue;
            }
        };

        let bot_id = record.bot_fingerprint.clone();

        // Store and retrieve all records for this bot
        let all_records = store.store_and_get_all(record).await;

        // Recompute TRUSTMARK
        let score = compute_trustmark_from_evidence(&all_records);
        let update = TrustmarkUpdate {
            bot_id: bot_id.clone(),
            score,
        };

        match serde_json::to_vec(&update) {
            Ok(json) => {
                if let Err(e) = client
                    .publish("trustmark.updated", bytes::Bytes::copy_from_slice(&json))
                    .await
                {
                    tracing::warn!(
                        bot_id = %bot_id,
                        error = %e,
                        "failed to publish trustmark update"
                    );
                } else {
                    tracing::debug!(
                        bot_id = %bot_id,
                        score_bp = update.score.score_bp.value(),
                        "published trustmark update"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    bot_id = %bot_id,
                    error = %e,
                    "failed to serialize trustmark update"
                );
            }
        }
    }

    tracing::warn!("evidence.new subscriber ended unexpectedly");
}
