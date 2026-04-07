//! Task 5: Novel pattern claim submission (harvest).
//!
//! Every 1 hour, scans the screening log for quarantined entries that
//! were caught by the classifier (layer 2) or SLM (layer 3) but would
//! NOT have been caught by heuristic patterns (layer 1). These novel
//! detections are submitted as Botawiki claims for the mesh to learn from.
//!
//! This is the KEY data pipeline for fine-tuning: the screening_log +
//! harvested claims = training data.

use std::sync::Arc;
use std::time::Duration;

use crate::gateway_client::GatewayClient;
use crate::state::AdapterState;

use super::AutonomousConfig;
use super::state::{AutonomousState, ClaimSubmittedRecord};

/// Spawn the harvest task.
pub fn spawn(
    adapter_state: Arc<AdapterState>,
    gateway_client: Arc<GatewayClient>,
    auto_state: Arc<AutonomousState>,
    config: AutonomousConfig,
) {
    let interval_secs = config.harvest_interval_secs;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // skip immediate tick

        loop {
            interval.tick().await;

            let now = now_ms();
            let one_hour_ago = now - (interval_secs as i64 * 1000);

            // Collect novel detections from screening log
            let candidates = {
                let log = auto_state.screening_log.read().await;
                log.entries_since(one_hour_ago)
                    .into_iter()
                    .filter(|e| e.verdict == "quarantine" && e.layer >= 2)
                    .collect::<Vec<_>>()
            };

            if candidates.is_empty() {
                tracing::debug!("harvest: no novel patterns in last window");
                continue;
            }

            // Check which are truly novel (dedup against submitted_claims)
            let mut submitted = auto_state.submitted_claims.write().await;
            let mut submit_count = 0u32;

            for entry in &candidates {
                if submitted.contains(&entry.evidence_hash) {
                    continue;
                }

                // Build claim payload
                let claim = serde_json::json!({
                    "namespace": "b/skills",
                    "content": format!(
                        "Novel detection [layer {}]: {}",
                        entry.layer,
                        &entry.body_preview
                    ),
                    "evidence_hash": entry.evidence_hash,
                    "metadata": {
                        "layer": entry.layer,
                        "patterns": entry.patterns,
                        "verdict": entry.verdict,
                    }
                });

                match gateway_client.post_json("/botawiki/claim", &claim).await {
                    Ok(_) => {
                        submitted.insert(entry.evidence_hash.clone());

                        // Persist submission record
                        ClaimSubmittedRecord {
                            ts_ms: now,
                            evidence_hash: entry.evidence_hash.clone(),
                            pattern_type: entry
                                .patterns
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "unknown".to_string()),
                            excerpt_preview: entry.body_preview.chars().take(100).collect(),
                            layer: entry.layer,
                        }
                        .persist(&adapter_state.data_dir);

                        submit_count += 1;
                        tracing::info!(
                            evidence_hash = %entry.evidence_hash,
                            layer = entry.layer,
                            "harvest: novel pattern submitted as claim"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            evidence_hash = %entry.evidence_hash,
                            "harvest: failed to submit claim"
                        );
                    }
                }
            }

            if submit_count > 0 {
                tracing::info!(
                    submit_count,
                    candidates = candidates.len(),
                    "harvest: novel patterns submitted"
                );
            }
        }
    });
    tracing::info!(interval_secs, "autonomous: harvest task started");
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
