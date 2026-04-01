//! Evaluator service — Tier 3 admission via peer voting (D22).
//!
//! A Tier 2 bot with TRUSTMARK >= 0.4 and evidence >= 72h can request
//! Tier 3 admission. Three evaluators (top TRUSTMARK >= 0.5, excluding
//! requester) vote; 2/3 approval grants Tier 3.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Status of a Tier 3 admission request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionStatus {
    Pending,
    Admitted,
    Denied,
}

/// A vote cast by an evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatorVote {
    pub evaluator_id: String,
    pub approve: bool,
    pub ts_ms: i64,
}

/// An admission request for Tier 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub bot_id: String,
    pub evaluators: Vec<String>,
    pub votes: Vec<EvaluatorVote>,
    pub status: AdmissionStatus,
    pub requested_at_ms: i64,
}

/// In-memory evaluator service for Tier 3 admission.
#[derive(Debug, Clone, Default)]
pub struct EvaluatorService {
    requests: Arc<RwLock<HashMap<String, AdmissionRequest>>>,
}

impl EvaluatorService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an admission request. Returns the evaluator IDs.
    pub async fn request_admission(
        &self,
        bot_id: &str,
        evaluators: Vec<String>,
    ) -> Result<Vec<String>, String> {
        let mut requests = self.requests.write().await;

        // Check if there's already a pending request
        if let Some(existing) = requests.get(bot_id) {
            if existing.status == AdmissionStatus::Pending {
                return Err("admission request already pending".to_string());
            }
        }

        let request = AdmissionRequest {
            bot_id: bot_id.to_string(),
            evaluators: evaluators.clone(),
            votes: Vec::new(),
            status: AdmissionStatus::Pending,
            requested_at_ms: now_ms(),
        };
        requests.insert(bot_id.to_string(), request);
        Ok(evaluators)
    }

    /// Record an evaluator vote. Returns the (possibly updated) status.
    pub async fn vote(
        &self,
        bot_id: &str,
        evaluator_id: &str,
        approve: bool,
    ) -> Result<AdmissionStatus, String> {
        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(bot_id)
            .ok_or_else(|| format!("no admission request for {bot_id}"))?;

        if request.status != AdmissionStatus::Pending {
            return Err(format!(
                "admission request for {bot_id} is {:?}, not pending",
                request.status
            ));
        }

        // Verify voter is a selected evaluator
        if !request.evaluators.contains(&evaluator_id.to_string()) {
            return Err(format!("{evaluator_id} is not a selected evaluator"));
        }

        // Prevent double voting
        if request
            .votes
            .iter()
            .any(|v| v.evaluator_id == evaluator_id)
        {
            return Err(format!("{evaluator_id} has already voted"));
        }

        request.votes.push(EvaluatorVote {
            evaluator_id: evaluator_id.to_string(),
            approve,
            ts_ms: now_ms(),
        });

        // Check quorum (2/3)
        let approve_count = request.votes.iter().filter(|v| v.approve).count();
        let reject_count = request.votes.iter().filter(|v| !v.approve).count();
        let quorum = 2;

        if approve_count >= quorum {
            request.status = AdmissionStatus::Admitted;
        } else if reject_count >= quorum {
            request.status = AdmissionStatus::Denied;
        }

        Ok(request.status.clone())
    }

    /// Get an admission request by bot_id.
    pub async fn get(&self, bot_id: &str) -> Option<AdmissionRequest> {
        self.requests.read().await.get(bot_id).cloned()
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

    #[tokio::test]
    async fn request_admission_creates_pending() {
        let svc = EvaluatorService::new();
        let evaluators = svc
            .request_admission("bot_a", vec!["e1".into(), "e2".into(), "e3".into()])
            .await
            .unwrap();
        assert_eq!(evaluators.len(), 3);

        let req = svc.get("bot_a").await.unwrap();
        assert_eq!(req.status, AdmissionStatus::Pending);
    }

    #[tokio::test]
    async fn two_approvals_admits() {
        let svc = EvaluatorService::new();
        svc.request_admission("bot_a", vec!["e1".into(), "e2".into(), "e3".into()])
            .await
            .unwrap();

        let status = svc.vote("bot_a", "e1", true).await.unwrap();
        assert_eq!(status, AdmissionStatus::Pending);

        let status = svc.vote("bot_a", "e2", true).await.unwrap();
        assert_eq!(status, AdmissionStatus::Admitted);
    }

    #[tokio::test]
    async fn two_rejections_denies() {
        let svc = EvaluatorService::new();
        svc.request_admission("bot_a", vec!["e1".into(), "e2".into(), "e3".into()])
            .await
            .unwrap();

        svc.vote("bot_a", "e1", false).await.unwrap();
        let status = svc.vote("bot_a", "e2", false).await.unwrap();
        assert_eq!(status, AdmissionStatus::Denied);
    }

    #[tokio::test]
    async fn non_evaluator_vote_rejected() {
        let svc = EvaluatorService::new();
        svc.request_admission("bot_a", vec!["e1".into(), "e2".into(), "e3".into()])
            .await
            .unwrap();

        let result = svc.vote("bot_a", "intruder", true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a selected evaluator"));
    }

    #[tokio::test]
    async fn duplicate_pending_request_rejected() {
        let svc = EvaluatorService::new();
        svc.request_admission("bot_a", vec!["e1".into(), "e2".into(), "e3".into()])
            .await
            .unwrap();

        let result = svc
            .request_admission("bot_a", vec!["e1".into(), "e2".into(), "e3".into()])
            .await;
        assert!(result.is_err());
    }
}
