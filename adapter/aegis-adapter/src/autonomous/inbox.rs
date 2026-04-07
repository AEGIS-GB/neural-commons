//! Task 3: Inbox poll + process.
//!
//! Every 30 seconds, reads unread relay messages, parses them as typed
//! mesh messages, and dispatches by type (peer status update, threat
//! intel ingestion, vote request handling, etc.).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use crate::gateway_client::GatewayClient;
use crate::state::{AdapterState, DashboardAlert};

use super::AutonomousConfig;
use super::state::{AutonomousState, LearnedPattern, PeerInfo};
use super::types::TypedRelayMessage;
use super::vote;

/// Spawn the inbox polling task.
pub fn spawn(
    adapter_state: Arc<AdapterState>,
    relay_inbox: Arc<aegis_proxy::cognitive_bridge::RelayInbox>,
    gateway_client: Arc<GatewayClient>,
    auto_state: Arc<AutonomousState>,
    alert_tx: broadcast::Sender<DashboardAlert>,
    config: AutonomousConfig,
) {
    let interval_secs = config.inbox_poll_interval_secs;
    let min_trust_bp = config.min_trust_for_intel_bp;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // skip immediate tick

        loop {
            interval.tick().await;

            let messages = relay_inbox.list();
            let unread: Vec<_> = messages.iter().filter(|m| !m.read).collect();
            if unread.is_empty() {
                continue;
            }

            tracing::debug!(count = unread.len(), "inbox: processing unread messages");

            for msg in &unread {
                // Try to parse as typed relay message
                match serde_json::from_str::<TypedRelayMessage>(&msg.body) {
                    Ok(typed) => {
                        process_typed(
                            &typed,
                            &msg.from,
                            &adapter_state,
                            &gateway_client,
                            &auto_state,
                            &alert_tx,
                            min_trust_bp,
                        )
                        .await;
                    }
                    Err(_) => {
                        // Backward compat: treat as free text
                        tracing::debug!(
                            from = %msg.from,
                            body_len = msg.body.len(),
                            "inbox: free text message (unparseable as typed)"
                        );
                    }
                }
            }

            // Mark all as read after processing
            relay_inbox.mark_all_read();
        }
    });
    tracing::info!(interval_secs, "autonomous: inbox poll task started");
}

async fn process_typed(
    msg: &TypedRelayMessage,
    from: &str,
    adapter_state: &Arc<AdapterState>,
    gateway_client: &Arc<GatewayClient>,
    auto_state: &Arc<AutonomousState>,
    alert_tx: &broadcast::Sender<DashboardAlert>,
    min_trust_bp: u32,
) {
    match msg {
        TypedRelayMessage::PeerStatus {
            trustmark_bp,
            chain_seq,
            uptime_ms,
            screening,
        } => {
            let info = PeerInfo {
                bot_id: from.to_string(),
                trustmark_bp: *trustmark_bp,
                chain_seq: *chain_seq,
                last_seen_ms: now_ms(),
                screening_stats: Some(screening.clone()),
            };
            auto_state
                .peer_cache
                .write()
                .await
                .insert(from.to_string(), info);
            tracing::debug!(
                from,
                trustmark_bp,
                chain_seq,
                uptime_ms,
                "inbox: peer status updated"
            );
        }

        TypedRelayMessage::ThreatIntel {
            pattern_type,
            excerpt,
            evidence_hash,
            severity_bp,
        } => {
            // Validate sender trust
            let sender_trust = auto_state
                .peer_cache
                .read()
                .await
                .get(from)
                .map(|p| p.trustmark_bp)
                .unwrap_or(0);

            if sender_trust < min_trust_bp {
                tracing::warn!(
                    from,
                    sender_trust,
                    min_trust_bp,
                    "inbox: rejected threat intel from low-trust peer"
                );
                return;
            }

            // Check dedup
            let mut store = auto_state.pattern_store.write().await;
            if store.contains_hash(evidence_hash) {
                tracing::debug!(evidence_hash, "inbox: threat intel already known");
                return;
            }

            store.append(LearnedPattern {
                pattern_type: pattern_type.clone(),
                excerpt: excerpt.clone(),
                source: "threat_intel".to_string(),
                source_bot_id: from.to_string(),
                evidence_hash: evidence_hash.clone(),
                learned_at_ms: now_ms(),
                severity_bp: *severity_bp,
            });

            tracing::info!(
                from,
                pattern_type,
                severity_bp,
                "inbox: new threat intel pattern learned"
            );

            // Dashboard alert for high-severity intel
            if *severity_bp >= 8000 {
                let _ = alert_tx.send(DashboardAlert {
                    kind: "threat_intel".to_string(),
                    message: format!(
                        "High-severity threat intel from {from}: {pattern_type} ({severity_bp}bp)"
                    ),
                    ts_ms: now_ms() as u64,
                    receipt_seq: 0,
                });
            }
        }

        TypedRelayMessage::KnowledgeShare {
            namespace,
            claim_id,
            content,
        } => {
            let mut store = auto_state.pattern_store.write().await;
            let hash = format!("ks:{claim_id}");
            if !store.contains_hash(&hash) {
                store.append(LearnedPattern {
                    pattern_type: "knowledge".to_string(),
                    excerpt: content.chars().take(500).collect(),
                    source: "knowledge_share".to_string(),
                    source_bot_id: from.to_string(),
                    evidence_hash: hash,
                    learned_at_ms: now_ms(),
                    severity_bp: 0,
                });
                tracing::debug!(from, namespace, claim_id, "inbox: knowledge share stored");
            }
        }

        TypedRelayMessage::ChainVerifyRequest { start_seq, end_seq } => {
            // Export receipts from our evidence chain
            let receipts = match adapter_state
                .evidence
                .export(Some(*start_seq), Some(*end_seq))
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(from, start_seq, end_seq, error = %e, "inbox: chain verify export failed");
                    return;
                }
            };

            let receipt_values: Vec<serde_json::Value> = receipts
                .iter()
                .filter_map(|r| serde_json::to_value(&r.core).ok())
                .collect();

            let response = TypedRelayMessage::ChainVerifyResponse {
                receipts: receipt_values,
            };

            // Send response back via gateway relay
            if let Ok(body) = serde_json::to_string(&response)
                && let Err(e) = gateway_client
                    .post_json(
                        "/mesh/send",
                        &serde_json::json!({
                            "to": from,
                            "msg_type": "chain_verify_response",
                            "body": body,
                        }),
                    )
                    .await
            {
                tracing::warn!(from, error = %e, "inbox: failed to send chain verify response");
            }
        }

        TypedRelayMessage::ChainVerifyResponse { receipts } => {
            tracing::info!(
                from,
                receipt_count = receipts.len(),
                "inbox: received chain verify response (stored for analysis)"
            );
            // Future: verify receipts against our local chain
        }

        TypedRelayMessage::VoteRequest {
            claim_id,
            attester_id,
            namespace,
            payload,
        } => {
            vote::handle_vote_request(
                claim_id,
                attester_id,
                namespace,
                payload,
                adapter_state,
                gateway_client,
                auto_state,
            )
            .await;
        }

        TypedRelayMessage::FreeText { body } => {
            tracing::debug!(from, body_len = body.len(), "inbox: free text message");
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
