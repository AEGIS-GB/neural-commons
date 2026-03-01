//! Server startup orchestration — composes all adapter subsystems.
//!
//! Startup sequence:
//! 1. Load configuration (TOML file or defaults)
//! 2. Initialize data directory
//! 3. Generate or load signing key
//! 4. Initialize evidence recorder (SQLite + hash chain)
//! 5. Create middleware hooks (evidence, vault, barrier, SLM)
//! 6. Start memory monitor (background task)
//! 7. Start proxy server with dashboard mounted
//!
//! Shutdown:
//! - Ctrl+C signal → graceful shutdown
//! - All background tasks cancelled via tokio::CancellationToken

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use aegis_crypto::ed25519::{self, SigningKey};
use aegis_evidence::EvidenceRecorder;
use aegis_proxy::config::{ProxyConfig, ProxyMode};
use aegis_proxy::middleware::MiddlewareHooks;
use tracing::{info, warn};

use crate::config::AdapterConfig;
use crate::hooks::{BarrierHookImpl, EvidenceHookImpl, SlmHookImpl, VaultHookImpl};
use crate::mode::ModeController;
use crate::replay::{MonotonicCounter, NonceRegistry};
use crate::state::AdapterState;
use crate::Mode;

/// Errors from server startup.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("config error: {0}")]
    Config(String),

    #[error("evidence store error: {0}")]
    Evidence(String),

    #[error("key generation error: {0}")]
    KeyGen(String),

    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Start the full adapter server.
///
/// This is the main entry point called by the CLI when no subcommand
/// is provided. It composes all subsystems and starts the proxy.
pub async fn start(
    config: AdapterConfig,
    mode_override: Option<Mode>,
) -> Result<(), StartupError> {
    let start_time = Instant::now();

    // 1. Determine operating mode
    let mode = mode_override.unwrap_or_else(|| config.mode.clone().into());
    let mode_controller = Arc::new(ModeController::new(mode));

    info!(mode = ?mode, "aegis adapter starting");

    // 2. Initialize data directory
    let data_dir = config.data_dir.clone();
    std::fs::create_dir_all(&data_dir).map_err(|e| {
        StartupError::Config(format!(
            "failed to create data directory {}: {e}",
            data_dir.display()
        ))
    })?;
    info!(data_dir = %data_dir.display(), "data directory ready");

    // 3. Generate or load signing key
    let signing_key = load_or_generate_key(&data_dir)?;
    let bot_id = ed25519::pubkey_hex(&signing_key.verifying_key());
    info!(bot_id = %bot_id, "identity loaded");

    // 4. Initialize evidence recorder
    let evidence_db = data_dir.join("evidence.db");
    let recorder = EvidenceRecorder::new(&evidence_db, signing_key)
        .map_err(|e| StartupError::Evidence(format!("{e}")))?;
    let recorder = Arc::new(recorder);

    let chain_head = recorder.chain_head();
    info!(
        seq = chain_head.head_seq,
        receipts = chain_head.receipt_count,
        "evidence chain loaded"
    );

    // 5. Create shared state
    let adapter_state = Arc::new(AdapterState {
        evidence: recorder.clone(),
        mode: mode_controller.clone(),
        request_counter: MonotonicCounter::new(),
        nonce_registry: std::sync::Mutex::new(NonceRegistry::new()),
        start_time,
        data_dir: data_dir.clone(),
        listen_addr: config.proxy.listen_addr.clone(),
        upstream_url: config.proxy.upstream_url.clone(),
    });

    // 6. Create middleware hooks
    let hooks = create_middleware_hooks(recorder.clone(), mode);

    // 7. Build proxy config
    let proxy_config = ProxyConfig {
        upstream_url: config.proxy.upstream_url.clone(),
        listen_addr: config.proxy.listen_addr.clone(),
        max_body_size: config.proxy.max_body_size,
        rate_limit_per_minute: config.proxy.rate_limit_per_minute,
        mode: match mode {
            Mode::PassThrough => ProxyMode::PassThrough,
            Mode::ObserveOnly => ProxyMode::ObserveOnly,
            Mode::Enforce => ProxyMode::Enforce,
        },
    };

    // 8. Print startup banner
    print_banner(&config, mode, &bot_id, &adapter_state);

    // 9. Record startup receipt
    if let Err(e) = adapter_state.evidence.record_simple(
        aegis_schemas::ReceiptType::ModeChange,
        "adapter_startup",
        &format!("mode={mode:?}"),
    ) {
        warn!("failed to record startup receipt: {e}");
    }

    // 10. Start proxy server (blocks until shutdown)
    info!(
        listen = %proxy_config.listen_addr,
        upstream = %proxy_config.upstream_url,
        "proxy server starting"
    );

    aegis_proxy::proxy::start(proxy_config, hooks)
        .await
        .map_err(|e| StartupError::Proxy(format!("{e}")))?;

    // 11. Record shutdown receipt
    if let Err(e) = adapter_state.evidence.record_simple(
        aegis_schemas::ReceiptType::ModeChange,
        "adapter_shutdown",
        "graceful",
    ) {
        warn!("failed to record shutdown receipt: {e}");
    }

    info!("aegis adapter stopped");
    Ok(())
}

/// Create the middleware hooks container with real implementations.
fn create_middleware_hooks(
    recorder: Arc<EvidenceRecorder>,
    mode: Mode,
) -> MiddlewareHooks {
    match mode {
        Mode::PassThrough => {
            // Pass-through: no hooks at all (the proxy skips them anyway,
            // but we don't even allocate them)
            info!("pass-through mode: all middleware disabled");
            MiddlewareHooks::default()
        }
        _ => {
            info!("middleware hooks: evidence=yes vault=yes barrier=stub slm=stub");
            MiddlewareHooks {
                evidence: Some(Arc::new(EvidenceHookImpl { recorder })),
                barrier: Some(Arc::new(BarrierHookImpl)),
                slm: Some(Arc::new(SlmHookImpl)),
                vault: Some(Arc::new(VaultHookImpl)),
            }
        }
    }
}

/// Load a signing key from disk or generate a new one.
fn load_or_generate_key(data_dir: &PathBuf) -> Result<SigningKey, StartupError> {
    let key_path = data_dir.join("identity.key");

    if key_path.exists() {
        // Load existing key
        let key_bytes = std::fs::read(&key_path).map_err(|e| {
            StartupError::KeyGen(format!(
                "failed to read key file {}: {e}",
                key_path.display()
            ))
        })?;

        if key_bytes.len() != 32 {
            return Err(StartupError::KeyGen(format!(
                "invalid key file: expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let key = SigningKey::from_bytes(&key_arr);
        info!(path = %key_path.display(), "loaded existing identity key");
        Ok(key)
    } else {
        // Generate new key
        let key = ed25519::generate_keypair();
        let key_bytes = key.to_bytes();

        std::fs::write(&key_path, key_bytes).map_err(|e| {
            StartupError::KeyGen(format!(
                "failed to write key file {}: {e}",
                key_path.display()
            ))
        })?;

        info!(path = %key_path.display(), "generated new identity key");
        warn!("⚠ Back up your identity key! Loss means loss of evidence chain continuity.");
        Ok(key)
    }
}

/// Print a startup banner to stderr.
fn print_banner(config: &AdapterConfig, mode: Mode, bot_id: &str, state: &AdapterState) {
    let mode_label = match mode {
        Mode::ObserveOnly => "OBSERVE-ONLY (warn, don't block)",
        Mode::Enforce => "ENFORCE (blocks on violations)",
        Mode::PassThrough => "PASS-THROUGH (zero inspection)",
    };

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════╗");
    eprintln!("║           aegis adapter — neural commons         ║");
    eprintln!("╚══════════════════════════════════════════════════╝");
    eprintln!();
    eprintln!("  mode:       {}", mode_label);
    eprintln!("  listen:     {}", config.proxy.listen_addr);
    eprintln!("  upstream:   {}", config.proxy.upstream_url);
    eprintln!("  bot id:     {}...{}", &bot_id[..8], &bot_id[bot_id.len()-8..]);
    eprintln!("  data dir:   {}", config.data_dir.display());
    eprintln!("  dashboard:  {}", state.dashboard_url());
    eprintln!("  chain seq:  {}", state.chain_head_seq());
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();

        // Generate
        let key1 = load_or_generate_key(&data_dir).unwrap();
        let pubkey1 = ed25519::pubkey_hex(&key1.verifying_key());

        // Load
        let key2 = load_or_generate_key(&data_dir).unwrap();
        let pubkey2 = ed25519::pubkey_hex(&key2.verifying_key());

        assert_eq!(pubkey1, pubkey2, "loaded key should match generated key");
    }

    #[test]
    fn create_hooks_observe_only() {
        let key = ed25519::generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let hooks = create_middleware_hooks(recorder, Mode::ObserveOnly);
        assert!(hooks.evidence.is_some());
        assert!(hooks.barrier.is_some());
        assert!(hooks.slm.is_some());
        assert!(hooks.vault.is_some());
    }

    #[test]
    fn create_hooks_pass_through() {
        let key = ed25519::generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let hooks = create_middleware_hooks(recorder, Mode::PassThrough);
        assert!(hooks.evidence.is_none());
        assert!(hooks.barrier.is_none());
        assert!(hooks.slm.is_none());
        assert!(hooks.vault.is_none());
    }
}
