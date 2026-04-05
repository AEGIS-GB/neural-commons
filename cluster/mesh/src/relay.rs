//! Mesh relay NATS message types and relay processor.
//!
//! Defines the wire types for relay messages flowing through NATS:
//! - `RelayRequest`: published by Gateway to `mesh.relay.incoming`
//! - `RelayScreened`: published by Mesh Relay to `mesh.relay.screened`
//! - `RelayQuarantined`: published by Mesh Relay to `mesh.relay.quarantined`

use serde::{Deserialize, Serialize};

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

// ─── Relay processor ──────────────────��──────────────────────────

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
