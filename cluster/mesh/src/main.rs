//! Aegis Mesh Relay — standalone NATS service for relay message screening.
//!
//! Subscribes to `mesh.relay.incoming`, screens with 3-layer cascade,
//! publishes to `mesh.relay.screened` or `mesh.relay.quarantined`.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use futures::StreamExt;
use tracing::{error, info, warn};

use aegis_mesh::relay::{self, RelayRequest, SUBJECT_INCOMING, process_relay};
use aegis_mesh::screening::ScreeningEngines;

#[derive(Parser)]
#[command(name = "aegis-mesh-relay", about = "Mesh Relay screening service")]
struct Args {
    /// NATS server URL
    #[arg(long, default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// Path to PromptGuard ONNX model directory (Layer 2)
    #[arg(long)]
    prompt_guard_model_dir: Option<PathBuf>,

    /// OpenAI-compatible SLM server URL for Layer 3 (e.g., http://localhost:1234)
    #[arg(long)]
    slm_url: Option<String>,

    /// SLM model name (e.g., qwen/qwen3-30b-a3b)
    #[arg(long)]
    slm_model: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_mesh=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    // Initialize screening engines
    let engines = Arc::new(ScreeningEngines::new(
        #[cfg(feature = "prompt-guard")]
        args.prompt_guard_model_dir.as_deref(),
        args.slm_url.as_deref(),
        args.slm_model.as_deref(),
    ));

    info!("Connecting to NATS at {}", args.nats_url);
    let client = async_nats::connect(&args.nats_url).await?;
    info!("Connected to NATS");

    // Subscribe to incoming relay messages
    let mut subscriber = client.subscribe(SUBJECT_INCOMING).await?;
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
                    if let Err(e) = client
                        .publish(relay::SUBJECT_SCREENED, payload.into())
                        .await
                    {
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
                    if let Err(e) = client
                        .publish(relay::SUBJECT_QUARANTINED, payload.into())
                        .await
                    {
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

    Ok(())
}
