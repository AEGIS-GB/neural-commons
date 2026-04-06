//! aegis-trustmark-engine: standalone NATS service for TRUSTMARK recomputation.
//!
//! Subscribes to `evidence.new`, maintains an in-memory evidence store,
//! recomputes TRUSTMARK scores, and publishes results to `trustmark.updated`.
//!
//! Phase 2 extraction from the Gateway — the Gateway no longer does inline
//! TRUSTMARK recomputation on evidence submission.

use clap::Parser;

use aegis_trustmark::cluster_scoring::run_trustmark_engine;

/// Aegis TRUSTMARK Engine — recomputes scores from evidence stream
#[derive(Parser)]
#[command(
    name = "aegis-trustmark-engine",
    version,
    about = "TRUSTMARK Engine — subscribes to evidence.new, recomputes scores, publishes trustmark.updated"
)]
struct Cli {
    /// NATS server URL
    #[arg(long, default_value = "nats://127.0.0.1:4222")]
    nats_url: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_trustmark_engine=info".into()),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!(nats_url = %cli.nats_url, "connecting to NATS");
    let client = async_nats::connect(&cli.nats_url)
        .await
        .expect("failed to connect to NATS");
    tracing::info!("connected to NATS");

    run_trustmark_engine(client).await;
}
