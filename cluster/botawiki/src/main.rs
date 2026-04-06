//! aegis-botawiki-service: standalone NATS service for Botawiki claim management.
//!
//! Subscribes to `botawiki.claim.submit` and `botawiki.vote`, processes claims
//! through quarantine/voting/adaptive quorum, and publishes state changes to
//! `botawiki.claim.stored` so the Gateway can update its local cache.
//!
//! Phase 3 extraction from the Gateway — the Gateway becomes a thin HTTP proxy
//! that forwards claim/vote operations to this service via NATS.

use clap::Parser;

use aegis_botawiki::run_botawiki_service;

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

    run_botawiki_service(client).await;
}
