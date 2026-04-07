//! Task 6: Claim validation (vote).
//!
//! Event-driven — called by the inbox processor when a VoteRequest is
//! received. All validation checks are deterministic (no LLM calls).
//!
//! Validation checks:
//! 1. Attester bot_id in peer_cache (they need to be in the mesh)
//! 2. Attester TRUSTMARK >= 4000bp (must be Tier 3)
//! 3. Claim has evidence_hash (provenance required)
//! 4. Not a duplicate (check pattern_store)
//!
//! Decision: all pass => APPROVE, any fail => REJECT with reason.
//! Result is POSTed to Gateway as a Botawiki vote.

use std::sync::Arc;

use crate::gateway_client::GatewayClient;
use crate::state::AdapterState;

use super::state::{AutonomousState, VoteCastRecord};

/// Minimum TRUSTMARK in basis points for an attester to be trusted.
const MIN_ATTESTER_TRUST_BP: u32 = 4000;

/// Handle a vote request from the mesh.
pub async fn handle_vote_request(
    claim_id: &str,
    attester_id: &str,
    namespace: &str,
    payload: &serde_json::Value,
    adapter_state: &Arc<AdapterState>,
    gateway_client: &Arc<GatewayClient>,
    auto_state: &Arc<AutonomousState>,
) {
    let (decision, reason) = validate(claim_id, attester_id, payload, auto_state).await;

    tracing::info!(
        claim_id,
        attester_id,
        namespace,
        decision,
        reason = %reason,
        "vote: validation complete"
    );

    // Persist vote record
    let record = VoteCastRecord {
        ts_ms: now_ms(),
        claim_id: claim_id.to_string(),
        attester_id: attester_id.to_string(),
        namespace: namespace.to_string(),
        decision: decision.to_string(),
        reason: reason.clone(),
    };
    record.persist(&adapter_state.data_dir);

    // Submit vote to Gateway
    let vote_payload = serde_json::json!({
        "claim_id": claim_id,
        "vote": decision,
        "reason": reason,
    });

    if let Err(e) = gateway_client
        .post_json("/botawiki/vote", &vote_payload)
        .await
    {
        tracing::warn!(
            claim_id,
            error = %e,
            "vote: failed to submit vote to gateway"
        );
    }
}

/// Run deterministic validation checks on a claim.
///
/// Returns (decision, reason) where decision is "approve" or "reject".
pub async fn validate(
    _claim_id: &str,
    attester_id: &str,
    payload: &serde_json::Value,
    auto_state: &Arc<AutonomousState>,
) -> (&'static str, String) {
    let peer_cache = auto_state.peer_cache.read().await;

    // Check 1: Attester in peer_cache
    let peer = match peer_cache.get(attester_id) {
        Some(p) => p,
        None => {
            return (
                "reject",
                format!("attester {attester_id} not in mesh peer cache"),
            );
        }
    };

    // Check 2: Attester TRUSTMARK >= 4000bp (Tier 3)
    if peer.trustmark_bp < MIN_ATTESTER_TRUST_BP {
        return (
            "reject",
            format!(
                "attester trust {}bp < {}bp minimum",
                peer.trustmark_bp, MIN_ATTESTER_TRUST_BP
            ),
        );
    }

    // Check 3: Claim has evidence_hash
    let evidence_hash = payload
        .get("evidence_hash")
        .and_then(|h| h.as_str())
        .unwrap_or("");
    if evidence_hash.is_empty() {
        return ("reject", "claim missing evidence_hash".to_string());
    }

    // Check 4: Not a duplicate
    let store = auto_state.pattern_store.read().await;
    if store.contains_hash(evidence_hash) {
        return (
            "reject",
            format!("duplicate evidence_hash: {evidence_hash}"),
        );
    }

    ("approve", "all checks passed".to_string())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autonomous::state::{AutonomousState, PeerInfo};
    use crate::autonomous::types::ScreeningStats;
    use tempfile::TempDir;

    async fn make_auto_state() -> (TempDir, Arc<AutonomousState>) {
        let tmp = TempDir::new().unwrap();
        let state = Arc::new(AutonomousState::new(tmp.path()));
        (tmp, state)
    }

    #[tokio::test]
    async fn vote_reject_unknown_attester() {
        let (_tmp, state) = make_auto_state().await;
        let payload = serde_json::json!({"evidence_hash": "h1"});
        let (decision, reason) = validate("c1", "unknown-bot", &payload, &state).await;
        assert_eq!(decision, "reject");
        assert!(reason.contains("not in mesh"));
    }

    #[tokio::test]
    async fn vote_reject_low_trust() {
        let (_tmp, state) = make_auto_state().await;
        state.peer_cache.write().await.insert(
            "bot-low".to_string(),
            PeerInfo {
                bot_id: "bot-low".to_string(),
                trustmark_bp: 2000,
                chain_seq: 1,
                last_seen_ms: 0,
                screening_stats: None,
            },
        );
        let payload = serde_json::json!({"evidence_hash": "h1"});
        let (decision, reason) = validate("c1", "bot-low", &payload, &state).await;
        assert_eq!(decision, "reject");
        assert!(reason.contains("2000bp"));
    }

    #[tokio::test]
    async fn vote_reject_missing_evidence_hash() {
        let (_tmp, state) = make_auto_state().await;
        state.peer_cache.write().await.insert(
            "bot-ok".to_string(),
            PeerInfo {
                bot_id: "bot-ok".to_string(),
                trustmark_bp: 5000,
                chain_seq: 1,
                last_seen_ms: 0,
                screening_stats: None,
            },
        );
        let payload = serde_json::json!({"content": "test"});
        let (decision, reason) = validate("c1", "bot-ok", &payload, &state).await;
        assert_eq!(decision, "reject");
        assert!(reason.contains("missing evidence_hash"));
    }

    #[tokio::test]
    async fn vote_reject_duplicate() {
        let (_tmp, state) = make_auto_state().await;
        state.peer_cache.write().await.insert(
            "bot-ok".to_string(),
            PeerInfo {
                bot_id: "bot-ok".to_string(),
                trustmark_bp: 5000,
                chain_seq: 1,
                last_seen_ms: 0,
                screening_stats: Some(ScreeningStats {
                    screened: 0,
                    quarantined: 0,
                    admitted: 0,
                    window_secs: 0,
                }),
            },
        );
        // Add pattern with same hash
        {
            use crate::autonomous::state::LearnedPattern;
            let mut store = state.pattern_store.write().await;
            store.append(LearnedPattern {
                pattern_type: "test".to_string(),
                excerpt: "test".to_string(),
                source: "test".to_string(),
                source_bot_id: "x".to_string(),
                evidence_hash: "existing-hash".to_string(),
                learned_at_ms: 0,
                severity_bp: 0,
            });
        }

        let payload = serde_json::json!({"evidence_hash": "existing-hash"});
        let (decision, reason) = validate("c1", "bot-ok", &payload, &state).await;
        assert_eq!(decision, "reject");
        assert!(reason.contains("duplicate"));
    }

    #[tokio::test]
    async fn vote_approve_all_checks_pass() {
        let (_tmp, state) = make_auto_state().await;
        state.peer_cache.write().await.insert(
            "bot-good".to_string(),
            PeerInfo {
                bot_id: "bot-good".to_string(),
                trustmark_bp: 7000,
                chain_seq: 50,
                last_seen_ms: 0,
                screening_stats: None,
            },
        );
        let payload = serde_json::json!({"evidence_hash": "new-hash"});
        let (decision, reason) = validate("c1", "bot-good", &payload, &state).await;
        assert_eq!(decision, "approve");
        assert!(reason.contains("all checks passed"));
    }
}
