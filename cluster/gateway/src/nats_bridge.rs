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

use async_nats::Client;

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
