//! Botawiki claim storage — quarantine, voting, and canonical promotion (D2, D22).
//!
//! Claims enter quarantine on submission. Validators (top TRUSTMARK) vote;
//! 2/3 approval transitions the claim to canonical. 2/3 rejection tombstones it.
//! This quorum is crash-fault tolerant only (not BFT).

use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use aegis_schemas::Claim;

/// Summary of Botawiki claim state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSummary {
    pub quarantine: u32,
    pub canonical: u32,
    pub tombstoned: u32,
    pub disputed: u32,
    pub pending_votes: Vec<PendingVote>,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingVote {
    pub claim_id: Uuid,
    pub votes_cast: usize,
    pub validators_total: usize,
    pub namespace: String,
}

/// Status of a stored claim in quarantine pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Quarantine,
    Canonical,
    Disputed,
    Tombstoned,
}

/// A vote cast by a validator on a quarantined claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub validator_id: String,
    pub approve: bool,
    pub ts_ms: i64,
}

/// Internal stored claim with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredClaim {
    pub claim: Claim,
    pub status: ClaimStatus,
    pub votes: Vec<Vote>,
    pub validators: Vec<String>,
    pub submitted_at_ms: i64,
}

/// View struct for the full claim list endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct StoredClaimView {
    pub id: Uuid,
    pub claim_type: serde_json::Value,
    pub namespace: String,
    pub attester_id: String,
    pub confidence_bp: u32,
    pub status: ClaimStatus,
    pub votes: Vec<Vote>,
    pub validators: Vec<String>,
    pub submitted_at_ms: i64,
    pub payload: serde_json::Value,
}

/// In-memory Botawiki claim store.
#[derive(Debug, Clone, Default)]
pub struct BotawikiStore {
    claims: Arc<RwLock<HashMap<Uuid, StoredClaim>>>,
}

impl BotawikiStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a claim into quarantine. Returns the claim ID.
    pub async fn submit(&self, claim: Claim, validators: Vec<String>) -> Uuid {
        let id = claim.id;
        let stored = StoredClaim {
            claim,
            status: ClaimStatus::Quarantine,
            votes: Vec::new(),
            validators,
            submitted_at_ms: now_ms(),
        };
        self.claims.write().await.insert(id, stored);
        id
    }

    /// Record a vote on a quarantined claim. Returns the (possibly updated) status.
    pub async fn vote(
        &self,
        claim_id: &Uuid,
        validator_id: &str,
        approve: bool,
    ) -> Result<ClaimStatus, String> {
        let mut claims = self.claims.write().await;
        let stored = claims
            .get_mut(claim_id)
            .ok_or_else(|| format!("claim {claim_id} not found"))?;

        // Only quarantined claims accept votes
        if stored.status != ClaimStatus::Quarantine {
            return Err(format!(
                "claim {claim_id} is {:?}, not quarantined",
                stored.status
            ));
        }

        // Verify voter is a selected validator
        if !stored.validators.contains(&validator_id.to_string()) {
            return Err(format!("{validator_id} is not a selected validator"));
        }

        // Prevent double voting
        if stored.votes.iter().any(|v| v.validator_id == validator_id) {
            return Err(format!("{validator_id} has already voted"));
        }

        stored.votes.push(Vote {
            validator_id: validator_id.to_string(),
            approve,
            ts_ms: now_ms(),
        });

        // Adaptive quorum: 2/3 of selected validators, minimum 1.
        // With 1 validator: quorum = 1 (single approval suffices)
        // With 2 validators: quorum = 2 (both must agree)
        // With 3+ validators: quorum = 2 (standard 2/3)
        let approve_count = stored.votes.iter().filter(|v| v.approve).count();
        let reject_count = stored.votes.iter().filter(|v| !v.approve).count();
        let validator_count = stored.validators.len();
        let quorum = if validator_count == 0 {
            1 // edge case — shouldn't happen
        } else {
            (validator_count * 2).div_ceil(3) // ceiling of 2/3
        };

        if approve_count >= quorum {
            stored.status = ClaimStatus::Canonical;
        } else if reject_count >= quorum {
            stored.status = ClaimStatus::Tombstoned;
        }

        Ok(stored.status.clone())
    }

    /// Restore a stored claim from replay (used during startup).
    pub async fn restore(&self, stored: StoredClaim) {
        self.claims.write().await.insert(stored.claim.id, stored);
    }

    /// Get a stored claim by ID.
    pub async fn get(&self, id: &Uuid) -> Option<StoredClaim> {
        self.claims.read().await.get(id).cloned()
    }

    /// Return a summary of all claims by status.
    pub async fn summary(&self) -> ClaimSummary {
        let claims = self.claims.read().await;
        let mut quarantine = 0u32;
        let mut canonical = 0u32;
        let mut tombstoned = 0u32;
        let mut disputed = 0u32;
        let mut pending_votes = Vec::new();

        for (id, stored) in claims.iter() {
            match stored.status {
                ClaimStatus::Quarantine => {
                    quarantine += 1;
                    pending_votes.push(PendingVote {
                        claim_id: *id,
                        votes_cast: stored.votes.len(),
                        validators_total: stored.validators.len(),
                        namespace: stored.claim.namespace.clone(),
                    });
                }
                ClaimStatus::Canonical => canonical += 1,
                ClaimStatus::Tombstoned => tombstoned += 1,
                ClaimStatus::Disputed => disputed += 1,
            }
        }

        let total = quarantine + canonical + tombstoned + disputed;
        ClaimSummary {
            quarantine,
            canonical,
            tombstoned,
            disputed,
            pending_votes,
            total,
        }
    }

    /// Return all stored claims with full metadata.
    pub async fn list_all(&self) -> Vec<StoredClaimView> {
        let claims = self.claims.read().await;
        claims
            .iter()
            .map(|(id, sc)| StoredClaimView {
                id: *id,
                claim_type: serde_json::to_value(&sc.claim.claim_type).unwrap_or_default(),
                namespace: sc.claim.namespace.clone(),
                attester_id: sc.claim.attester_id.clone(),
                confidence_bp: sc.claim.confidence_bp.value(),
                status: sc.status.clone(),
                votes: sc.votes.clone(),
                validators: sc.validators.clone(),
                submitted_at_ms: sc.submitted_at_ms,
                payload: sc.claim.payload.clone(),
            })
            .collect()
    }

    /// Query canonical claims by namespace and optional claim_type.
    pub async fn query(
        &self,
        namespace: Option<&str>,
        claim_type: Option<&str>,
        limit: usize,
    ) -> Vec<Claim> {
        let claims = self.claims.read().await;
        claims
            .values()
            .filter(|sc| sc.status == ClaimStatus::Canonical)
            .filter(|sc| namespace.map(|ns| sc.claim.namespace == ns).unwrap_or(true))
            .filter(|sc| {
                claim_type
                    .map(|ct| {
                        let serialized =
                            serde_json::to_value(&sc.claim.claim_type).unwrap_or_default();
                        serialized.as_str().map(|s| s == ct).unwrap_or(false)
                    })
                    .unwrap_or(true)
            })
            .take(limit)
            .map(|sc| sc.claim.clone())
            .collect()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ─── NATS service types ─────────────────────────────────────────

/// NATS message for claim submission.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimSubmitMsg {
    pub claim: Claim,
    pub validators: Vec<String>,
}

/// NATS message for a vote on a claim.
#[derive(Debug, Serialize, Deserialize)]
pub struct VoteMsg {
    pub claim_id: Uuid,
    pub validator_id: String,
    pub approve: bool,
}

/// NATS message for claim state change notification.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimStoredMsg {
    pub claim_id: Uuid,
    pub status: ClaimStatus,
    pub stored: StoredClaim,
}

// ─── Botawiki service loop ──────────────────────────────────────

/// Run the Botawiki service as an async loop.
///
/// Subscribes to `botawiki.claim.submit` and `botawiki.vote`, processes
/// claims through quarantine/voting/adaptive quorum, and publishes state
/// changes to `botawiki.claim.stored`. This function runs forever and can
/// be called from both the standalone binary and the Gateway's embedded mode.
pub async fn run_botawiki_service(client: async_nats::Client) {
    let store = Arc::new(BotawikiStore::new());

    let mut claim_sub = match client.subscribe("botawiki.claim.submit").await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to subscribe to botawiki.claim.submit: {e}");
            return;
        }
    };
    tracing::info!("subscribed to botawiki.claim.submit");

    let mut vote_sub = match client.subscribe("botawiki.vote").await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to subscribe to botawiki.vote: {e}");
            return;
        }
    };
    tracing::info!("subscribed to botawiki.vote");

    let client_claim = client.clone();
    let store_claim = Arc::clone(&store);

    let claim_task = tokio::spawn(async move {
        while let Some(msg) = claim_sub.next().await {
            let submit: ClaimSubmitMsg = match serde_json::from_slice(&msg.payload) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to parse claim submit message");
                    continue;
                }
            };

            let claim_id = submit.claim.id;
            let id = store_claim.submit(submit.claim, submit.validators).await;
            tracing::info!(claim_id = %id, "claim submitted to quarantine");

            if let Some(stored) = store_claim.get(&claim_id).await {
                let notification = ClaimStoredMsg {
                    claim_id,
                    status: stored.status.clone(),
                    stored,
                };
                match serde_json::to_vec(&notification) {
                    Ok(json) => {
                        if let Err(e) = client_claim
                            .publish(
                                "botawiki.claim.stored",
                                bytes::Bytes::copy_from_slice(&json),
                            )
                            .await
                        {
                            tracing::warn!(claim_id = %claim_id, error = %e, "failed to publish claim.stored");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(claim_id = %claim_id, error = %e, "failed to serialize claim.stored");
                    }
                }
            }
        }
        tracing::warn!("botawiki.claim.submit subscriber ended");
    });

    let client_vote = client.clone();
    let store_vote = Arc::clone(&store);

    let vote_task = tokio::spawn(async move {
        while let Some(msg) = vote_sub.next().await {
            let vote: VoteMsg = match serde_json::from_slice(&msg.payload) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to parse vote message");
                    continue;
                }
            };

            match store_vote
                .vote(&vote.claim_id, &vote.validator_id, vote.approve)
                .await
            {
                Ok(status) => {
                    tracing::info!(
                        claim_id = %vote.claim_id,
                        validator = %vote.validator_id,
                        approve = vote.approve,
                        ?status,
                        "vote recorded"
                    );

                    if let Some(stored) = store_vote.get(&vote.claim_id).await {
                        let notification = ClaimStoredMsg {
                            claim_id: vote.claim_id,
                            status: stored.status.clone(),
                            stored,
                        };
                        match serde_json::to_vec(&notification) {
                            Ok(json) => {
                                if let Err(e) = client_vote
                                    .publish(
                                        "botawiki.claim.stored",
                                        bytes::Bytes::copy_from_slice(&json),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        claim_id = %vote.claim_id,
                                        error = %e,
                                        "failed to publish claim.stored after vote"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    claim_id = %vote.claim_id,
                                    error = %e,
                                    "failed to serialize claim.stored after vote"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        claim_id = %vote.claim_id,
                        validator = %vote.validator_id,
                        error = %e,
                        "vote rejected"
                    );
                }
            }
        }
        tracing::warn!("botawiki.vote subscriber ended");
    });

    tokio::select! {
        _ = claim_task => tracing::error!("claim handler exited unexpectedly"),
        _ = vote_task => tracing::error!("vote handler exited unexpectedly"),
    }
}
