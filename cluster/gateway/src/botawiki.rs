//! Botawiki claim storage — quarantine, voting, and canonical promotion (D2, D22).
//!
//! Claims enter quarantine on submission. Three validators (top TRUSTMARK)
//! vote; 2/3 approval transitions the claim to canonical. 2/3 rejection
//! tombstones it. This quorum is crash-fault tolerant only (not BFT).

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use aegis_schemas::Claim;

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

        // Check quorum (2/3)
        let approve_count = stored.votes.iter().filter(|v| v.approve).count();
        let reject_count = stored.votes.iter().filter(|v| !v.approve).count();
        let quorum = 2;

        if approve_count >= quorum {
            stored.status = ClaimStatus::Canonical;
        } else if reject_count >= quorum {
            stored.status = ClaimStatus::Tombstoned;
        }

        Ok(stored.status.clone())
    }

    /// Get a stored claim by ID.
    pub async fn get(&self, id: &Uuid) -> Option<StoredClaim> {
        self.claims.read().await.get(id).cloned()
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
            .filter(|sc| {
                namespace
                    .map(|ns| sc.claim.namespace == ns)
                    .unwrap_or(true)
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_schemas::{BasisPoints, claim::TemporalScope};

    fn sample_claim() -> Claim {
        Claim {
            id: Uuid::now_v7(),
            claim_type: aegis_schemas::claim::ClaimType::Lore,
            namespace: "b/lore".to_string(),
            attester_id: "bot_a".to_string(),
            confidence_bp: BasisPoints::clamped(8000),
            temporal_scope: TemporalScope {
                start_ms: 1700000000000,
                end_ms: None,
            },
            provenance: vec![],
            schema_version: 1,
            confabulation_score_bp: None,
            temporal_coherence_flag: None,
            distinct_warden_count: None,
            payload: serde_json::json!({"key": "value"}),
        }
    }

    #[tokio::test]
    async fn submit_creates_quarantined_claim() {
        let store = BotawikiStore::new();
        let claim = sample_claim();
        let id = claim.id;
        let validators = vec!["v1".into(), "v2".into(), "v3".into()];
        store.submit(claim, validators).await;

        let stored = store.get(&id).await.unwrap();
        assert_eq!(stored.status, ClaimStatus::Quarantine);
        assert_eq!(stored.validators.len(), 3);
    }

    #[tokio::test]
    async fn two_approvals_makes_canonical() {
        let store = BotawikiStore::new();
        let claim = sample_claim();
        let id = claim.id;
        let validators = vec!["v1".into(), "v2".into(), "v3".into()];
        store.submit(claim, validators).await;

        let status = store.vote(&id, "v1", true).await.unwrap();
        assert_eq!(status, ClaimStatus::Quarantine);

        let status = store.vote(&id, "v2", true).await.unwrap();
        assert_eq!(status, ClaimStatus::Canonical);
    }

    #[tokio::test]
    async fn two_rejections_tombstones() {
        let store = BotawikiStore::new();
        let claim = sample_claim();
        let id = claim.id;
        let validators = vec!["v1".into(), "v2".into(), "v3".into()];
        store.submit(claim, validators).await;

        store.vote(&id, "v1", false).await.unwrap();
        let status = store.vote(&id, "v2", false).await.unwrap();
        assert_eq!(status, ClaimStatus::Tombstoned);
    }

    #[tokio::test]
    async fn non_validator_vote_rejected() {
        let store = BotawikiStore::new();
        let claim = sample_claim();
        let id = claim.id;
        let validators = vec!["v1".into(), "v2".into(), "v3".into()];
        store.submit(claim, validators).await;

        let result = store.vote(&id, "intruder", true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a selected validator"));
    }

    #[tokio::test]
    async fn double_vote_rejected() {
        let store = BotawikiStore::new();
        let claim = sample_claim();
        let id = claim.id;
        let validators = vec!["v1".into(), "v2".into(), "v3".into()];
        store.submit(claim, validators).await;

        store.vote(&id, "v1", true).await.unwrap();
        let result = store.vote(&id, "v1", true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already voted"));
    }

    #[tokio::test]
    async fn query_returns_only_canonical() {
        let store = BotawikiStore::new();
        let validators = vec!["v1".into(), "v2".into(), "v3".into()];

        // Submit and approve one
        let claim1 = sample_claim();
        let id1 = claim1.id;
        store.submit(claim1, validators.clone()).await;
        store.vote(&id1, "v1", true).await.unwrap();
        store.vote(&id1, "v2", true).await.unwrap();

        // Submit but leave quarantined
        let claim2 = sample_claim();
        store.submit(claim2, validators).await;

        let results = store.query(Some("b/lore"), None, 50).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, id1);
    }
}
