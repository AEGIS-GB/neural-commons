//! Task 4: Botawiki pattern sync.
//!
//! Every 10 minutes, fetches all canonical Botawiki claims from the
//! Gateway and incorporates new patterns into the local pattern store.
//! Skills (b/skills) are added as screening-relevant patterns;
//! lore (b/lore) is stored for informational queries.

use std::sync::Arc;
use std::time::Duration;

use crate::gateway_client::GatewayClient;
use crate::state::AdapterState;

use super::AutonomousConfig;
use super::state::{AutonomousState, LearnedPattern};

/// Spawn the Botawiki sync task.
pub fn spawn(
    adapter_state: Arc<AdapterState>,
    gateway_client: Arc<GatewayClient>,
    auto_state: Arc<AutonomousState>,
    config: AutonomousConfig,
) {
    let interval_secs = config.sync_interval_secs;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // skip immediate tick

        loop {
            interval.tick().await;

            match gateway_client.get_json("/botawiki/claims/all").await {
                Ok(data) => {
                    process_claims(&data, &auto_state, &adapter_state).await;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "sync: gateway unreachable for botawiki sync");
                }
            }
        }
    });
    tracing::info!(interval_secs, "autonomous: botawiki sync task started");
}

async fn process_claims(
    data: &serde_json::Value,
    auto_state: &Arc<AutonomousState>,
    _adapter_state: &Arc<AdapterState>,
) {
    let claims = match data.get("claims").and_then(|c| c.as_array()) {
        Some(arr) => arr,
        None => {
            tracing::debug!("sync: no claims array in botawiki response");
            return;
        }
    };

    let mut store = auto_state.pattern_store.write().await;
    let mut new_count = 0u32;

    for claim in claims {
        let namespace = claim
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("");
        let claim_id = claim.get("claim_id").and_then(|c| c.as_str()).unwrap_or("");
        let content = claim.get("content").and_then(|c| c.as_str()).unwrap_or("");
        let attester = claim
            .get("attester_id")
            .and_then(|a| a.as_str())
            .unwrap_or("unknown");

        if claim_id.is_empty() || content.is_empty() {
            continue;
        }

        let evidence_hash = format!("bw:{claim_id}");
        if store.contains_hash(&evidence_hash) {
            continue;
        }

        let pattern_type = if namespace.starts_with("b/skills") {
            "skill"
        } else if namespace.starts_with("b/lore") {
            "lore"
        } else {
            "canonical"
        };

        store.append(LearnedPattern {
            pattern_type: pattern_type.to_string(),
            excerpt: content.chars().take(500).collect(),
            source: "botawiki_sync".to_string(),
            source_bot_id: attester.to_string(),
            evidence_hash,
            learned_at_ms: now_ms(),
            severity_bp: 0,
        });
        new_count += 1;
    }

    if new_count > 0 {
        tracing::info!(
            new_count,
            total = store.patterns.len(),
            "sync: new botawiki patterns learned"
        );
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
