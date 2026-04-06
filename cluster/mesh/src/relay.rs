//! Mesh relay NATS message types and relay processor.
//!
//! Defines the wire types for relay messages flowing through NATS:
//! - `RelayRequest`: published by Gateway to `mesh.relay.incoming`
//! - `RelayScreened`: published by Mesh Relay to `mesh.relay.screened`
//! - `RelayQuarantined`: published by Mesh Relay to `mesh.relay.quarantined`

use std::sync::Arc;

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::screening::{ScreeningEngines, ScreeningVerdict};

// ─── NATS subjects ───���───────────────────────────────────────────

pub const SUBJECT_INCOMING: &str = "mesh.relay.incoming";
pub const SUBJECT_SCREENED: &str = "mesh.relay.screened";
pub const SUBJECT_QUARANTINED: &str = "mesh.relay.quarantined";

// ─── Wire types ─────────────��────────────────────────────────────

/// Gateway → Mesh Relay (published to `mesh.relay.incoming`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRequest {
    pub from: String,
    pub to: String,
    pub body: String,
    pub msg_type: String,
    pub sender_trustmark_bp: u32,
    pub sender_tier: String,
}

/// Mesh Relay → Gateway (published to `mesh.relay.screened`)
/// Gateway delivers this to the recipient via WSS or dead-drop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayScreened {
    pub from: String,
    pub to: String,
    pub body: String,
    pub msg_type: String,
    pub ts_ms: i64,
    pub screening: ScreeningVerdict,
}

/// Mesh Relay → Gateway (published to `mesh.relay.quarantined`)
/// Gateway updates relay stats/log but does NOT deliver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayQuarantined {
    pub from: String,
    pub to: String,
    pub body: String,
    pub msg_type: String,
    pub ts_ms: i64,
    pub reason: String,
    pub screening: ScreeningVerdict,
}

// ─── Relay service loop ─────────────────────────────────────────

/// Run the relay screening processor as an async loop.
///
/// Subscribes to `mesh.relay.incoming`, screens each message with the
/// provided engines, and publishes results to `mesh.relay.screened` or
/// `mesh.relay.quarantined`. This function runs forever (until the
/// subscription ends) and can be called from both the standalone binary
/// and the Gateway's embedded mode.
pub async fn run_relay_processor(client: async_nats::Client, engines: Arc<ScreeningEngines>) {
    let mut subscriber = match client.subscribe(SUBJECT_INCOMING).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to subscribe to {SUBJECT_INCOMING}: {e}");
            return;
        }
    };
    info!("Subscribed to {SUBJECT_INCOMING}, ready to screen relay messages");

    while let Some(msg) = subscriber.next().await {
        let request: RelayRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("Malformed relay request: {e}");
                continue;
            }
        };

        info!(
            from = %request.from,
            to = %request.to,
            msg_type = %request.msg_type,
            sender_bp = request.sender_trustmark_bp,
            "Screening relay message"
        );

        let engines = engines.clone();
        let client = client.clone();
        tokio::spawn(async move {
            match process_relay(&engines, &request) {
                Ok(screened) => {
                    let payload = serde_json::to_vec(&screened).unwrap_or_default();
                    if let Err(e) = client.publish(SUBJECT_SCREENED, payload.into()).await {
                        error!("Failed to publish screened result: {e}");
                    } else {
                        info!(
                            from = %screened.from,
                            to = %screened.to,
                            "Relay message admitted"
                        );
                    }
                }
                Err(quarantined) => {
                    let payload = serde_json::to_vec(&quarantined).unwrap_or_default();
                    if let Err(e) = client.publish(SUBJECT_QUARANTINED, payload.into()).await {
                        error!("Failed to publish quarantine result: {e}");
                    } else {
                        warn!(
                            from = %quarantined.from,
                            to = %quarantined.to,
                            reason = %quarantined.reason,
                            "Relay message quarantined"
                        );
                    }
                }
            }
        });
    }

    warn!("{SUBJECT_INCOMING} subscriber ended unexpectedly");
}

// ─── Relay processor ────────────────────────────────────────────

/// Process a single relay request: screen and produce either
/// a `RelayScreened` or `RelayQuarantined` result.
pub fn process_relay(
    engines: &ScreeningEngines,
    request: &RelayRequest,
) -> Result<RelayScreened, Box<RelayQuarantined>> {
    let verdict = engines.screen(&request.body, request.sender_trustmark_bp);
    let ts_ms = chrono::Utc::now().timestamp_millis();

    if verdict.is_quarantined() {
        Err(Box::new(RelayQuarantined {
            from: request.from.clone(),
            to: request.to.clone(),
            body: request.body.clone(),
            msg_type: request.msg_type.clone(),
            ts_ms,
            reason: verdict.reason.clone(),
            screening: verdict,
        }))
    } else {
        Ok(RelayScreened {
            from: request.from.clone(),
            to: request.to.clone(),
            body: request.body.clone(),
            msg_type: request.msg_type.clone(),
            ts_ms,
            screening: verdict,
        })
    }
}
