//! aegis-botawiki-service: standalone NATS service for Botawiki claim management.
//!
//! Subscribes to `botawiki.claim.submit` and `botawiki.vote`, processes claims
//! through quarantine/voting/adaptive quorum, and publishes state changes to
//! `botawiki.claim.stored` so the Gateway can update its local cache.
//!
//! Phase 3 extraction from the Gateway — the Gateway becomes a thin HTTP proxy
//! that forwards claim/vote operations to this service via NATS.

use std::sync::Arc;

use clap::Parser;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aegis_botawiki::{BotawikiStore, ClaimStatus};

/// Aegis Botawiki Service — manages Botawiki claim state via NATS
#[derive(Parser)]
#[command(
    name = "aegis-botawiki-service",
    version,
    about = "Botawiki Service — subscribes to claim/vote events, manages quarantine and quorum"
)]
struct Cli {
    /// NATS server URL
    #[arg(long, default_value = "nats://127.0.0.1:4222")]
    nats_url: String,
}

/// NATS message for claim submission.
#[derive(Debug, Serialize, Deserialize)]
struct ClaimSubmitMsg {
    pub claim: aegis_schemas::Claim,
    pub validators: Vec<String>,
}

/// NATS message for a vote on a claim.
#[derive(Debug, Serialize, Deserialize)]
struct VoteMsg {
    pub claim_id: Uuid,
    pub validator_id: String,
    pub approve: bool,
}

/// NATS message for claim state change notification.
#[derive(Debug, Serialize, Deserialize)]
struct ClaimStoredMsg {
    pub claim_id: Uuid,
    pub status: ClaimStatus,
    pub stored: aegis_botawiki::StoredClaim,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_botawiki_service=info".into()),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!(nats_url = %cli.nats_url, "connecting to NATS");
    let client = async_nats::connect(&cli.nats_url)
        .await
        .expect("failed to connect to NATS");
    tracing::info!("connected to NATS");

    let store = Arc::new(BotawikiStore::new());

    // Subscribe to claim submissions
    let mut claim_sub = client
        .subscribe("botawiki.claim.submit")
        .await
        .expect("failed to subscribe to botawiki.claim.submit");
    tracing::info!("subscribed to botawiki.claim.submit");

    // Subscribe to votes
    let mut vote_sub = client
        .subscribe("botawiki.vote")
        .await
        .expect("failed to subscribe to botawiki.vote");
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

            // Publish stored state so Gateway (and other consumers) can update
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

                    // Publish updated state
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

    // Wait for either task to finish (shouldn't happen in normal operation)
    tokio::select! {
        _ = claim_task => tracing::error!("claim handler exited unexpectedly"),
        _ = vote_task => tracing::error!("vote handler exited unexpectedly"),
    }
}
