//! Aegis Mesh Relay — standalone NATS service for relay message screening.
//!
//! Subscribes to `mesh.relay.incoming`, screens with 3-layer cascade,
//! publishes to `mesh.relay.screened` or `mesh.relay.quarantined`.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::info;

use aegis_mesh::relay::run_relay_processor;
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
        args.prompt_guard_model_dir.as_deref(),
        args.slm_url.as_deref(),
        args.slm_model.as_deref(),
    ));

    info!("Connecting to NATS at {}", args.nats_url);
    let client = async_nats::connect(&args.nats_url).await?;
    info!("Connected to NATS");

    run_relay_processor(client, engines).await;

    Ok(())
}
