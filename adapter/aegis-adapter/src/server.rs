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

    let (alert_tx, _alert_rx) = tokio::sync::broadcast::channel::<aegis_dashboard::DashboardAlert>(32);

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
        dashboard_path: config.dashboard.path.clone(),
        alert_tx: alert_tx.clone(),
    });

    // 5b. Build dashboard shared state
    let dashboard_state = Arc::new(aegis_dashboard::DashboardSharedState {
        alert_tx: alert_tx.clone(),
        evidence: recorder.clone(),
        mode_fn: Arc::new({
            let mc = mode_controller.clone();
            move || match mc.current() {
                crate::Mode::ObserveOnly => "observe_only",
                crate::Mode::Enforce => "enforce",
                crate::Mode::PassThrough => "pass_through",
            }
        }),
        observe_mode_checks_fn: Arc::new({
            let enforcement = config.enforcement.clone();
            move || {
                let mut checks = vec![];
                if enforcement.write_barrier.is_observe() {
                    checks.push("write_barrier".to_string());
                }
                if enforcement.slm_reject.is_observe() {
                    checks.push("slm_reject".to_string());
                }
                checks
            }
        }),
        start_time,
    });
    let dashboard_router = aegis_dashboard::routes::routes(dashboard_state);
    let dashboard_path = config.dashboard.path.clone();

    // 6. Start memory monitor background task
    if mode != Mode::PassThrough {
        let mem_config = aegis_memory::config::MemoryConfig {
            memory_paths: config.memory.memory_paths.clone(),
            include_defaults: true,
            hash_interval_secs: config.memory.hash_interval_secs,
        };
        let screener: Arc<dyn aegis_memory::screen::MemoryScreener> =
            Arc::new(aegis_memory::screen::HeuristicScreener);
        let workspace_root = std::env::current_dir().unwrap_or_default();
        let monitor = aegis_memory::monitor::MemoryMonitor::new(
            mem_config,
            screener,
            workspace_root,
        );
        let monitor_recorder = recorder.clone();
        let monitor_alert_tx = alert_tx.clone();

        tokio::spawn(async move {
            monitor.run(move |events| {
                for event in &events {
                    match event {
                        aegis_memory::monitor::MemoryEvent::FileChanged { path, screen_verdict, .. } => {
                            let action = format!("memory_change {}", path.display());
                            let outcome = format!("verdict={screen_verdict:?}");
                            if let Err(e) = monitor_recorder.record_simple(
                                aegis_schemas::ReceiptType::MemoryIntegrity,
                                &action,
                                &outcome,
                            ) {
                                tracing::warn!("failed to record memory event: {e}");
                            }

                            if matches!(screen_verdict, aegis_memory::screen::ScreenVerdict::Blocked) {
                                let alert = aegis_dashboard::DashboardAlert {
                                    ts_ms: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64,
                                    kind: "memory_injection".to_string(),
                                    message: format!("Suspicious memory change: {}", path.display()),
                                    receipt_seq: monitor_recorder.chain_head().head_seq,
                                };
                                let _ = monitor_alert_tx.send(alert);
                            }
                        }
                        aegis_memory::monitor::MemoryEvent::FileDeleted { path, .. } => {
                            let action = format!("memory_deleted {}", path.display());
                            if let Err(e) = monitor_recorder.record_simple(
                                aegis_schemas::ReceiptType::MemoryIntegrity,
                                &action,
                                "file deleted",
                            ) {
                                tracing::warn!("failed to record memory deletion: {e}");
                            }
                        }
                        _ => {}
                    }
                }
            }).await;
        });
        info!("memory monitor started (interval={}s)", config.memory.hash_interval_secs);
    }

    // 6b. Start barrier filesystem watcher (Layer 1 detection)
    if mode != Mode::PassThrough {
        let barrier_protected = Arc::new(std::sync::Mutex::new(
            aegis_barrier::protected_files::ProtectedFileManager::new(),
        ));
        let barrier_recorder = recorder.clone();
        let barrier_alert_tx = alert_tx.clone();
        let watcher_workspace = std::env::current_dir().unwrap_or_default();

        tokio::spawn(async move {
            use notify::{Watcher, RecursiveMode, Config};
            use aegis_barrier::watcher::{FileWatcher, map_notify_event, is_excluded};
            use aegis_barrier::types::DebounceConfig;

            let (tx, mut rx) = tokio::sync::mpsc::channel(256);

            let mut watcher = match notify::RecommendedWatcher::new(
                move |res: Result<notify::Event, notify::Error>| {
                    if let Ok(event) = res {
                        let _ = tx.blocking_send(event);
                    }
                },
                Config::default(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("barrier watcher failed to start: {e}");
                    return;
                }
            };

            if let Err(e) = watcher.watch(&watcher_workspace, RecursiveMode::Recursive) {
                tracing::error!("barrier watcher failed to watch {}: {e}", watcher_workspace.display());
                return;
            }

            tracing::info!(path = %watcher_workspace.display(), "barrier filesystem watcher started");

            let mut file_watcher = FileWatcher::new(DebounceConfig::default());

            while let Some(event) = rx.recv().await {
                let watch_events = map_notify_event(&event);
                for we in watch_events {
                    if is_excluded(&we.path) {
                        continue;
                    }
                    if !file_watcher.should_process(&we.path, we.timestamp_ms) {
                        continue;
                    }

                    // Check if this is a protected file
                    let relative = we.path.strip_prefix(&watcher_workspace)
                        .unwrap_or(&we.path);
                    let is_protected = barrier_protected.lock()
                        .map(|mgr| mgr.is_protected(relative))
                        .unwrap_or(false);
                    let is_critical = barrier_protected.lock()
                        .map(|mgr| mgr.is_critical(relative))
                        .unwrap_or(false);

                    if is_protected {
                        let action = format!("filesystem_change {} {:?}", relative.display(), we.kind);
                        let outcome = if is_critical {
                            "critical_protected_file_modified"
                        } else {
                            "protected_file_modified"
                        };

                        if let Err(e) = barrier_recorder.record_simple(
                            aegis_schemas::ReceiptType::WriteBarrier,
                            &action,
                            outcome,
                        ) {
                            tracing::warn!("failed to record barrier event: {e}");
                        }

                        if is_critical {
                            let alert = aegis_dashboard::DashboardAlert {
                                ts_ms: we.timestamp_ms,
                                kind: "structural_write".to_string(),
                                message: format!("Critical file modified: {}", relative.display()),
                                receipt_seq: barrier_recorder.chain_head().head_seq,
                            };
                            let _ = barrier_alert_tx.send(alert);
                        }

                        tracing::warn!(
                            path = %relative.display(),
                            critical = is_critical,
                            kind = ?we.kind,
                            "barrier: protected file change detected"
                        );
                    }
                }
            }
        });
        info!("barrier filesystem watcher started");
    }

    // 7. Create middleware hooks
    let slm_config = aegis_slm::loopback::LoopbackConfig {
        ollama_url: config.slm.ollama_url.clone(),
        model: config.slm.model.clone(),
        fallback_to_heuristics: config.slm.fallback_to_heuristics,
    };
    let slm_enabled = config.slm.enabled;
    let hooks = create_middleware_hooks(recorder.clone(), mode, alert_tx.clone(), slm_config, slm_enabled);

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
        provider: aegis_proxy::config::Provider::Anthropic,
        allow_any_provider: config.proxy.allow_any_provider,
    };

    // 8. Warn if upstream is still the default (common misconfiguration)
    if config.proxy.upstream_url == "https://api.anthropic.com" {
        info!("upstream_url is the default (https://api.anthropic.com) — set [proxy] upstream_url in config.toml if needed");
    }

    // 9. Print startup banner
    print_banner(&config, mode, &bot_id, &adapter_state);

    // 10. Record startup receipt
    if let Err(e) = adapter_state.evidence.record_simple(
        aegis_schemas::ReceiptType::ModeChange,
        "adapter_startup",
        &format!("mode={mode:?}"),
    ) {
        warn!("failed to record startup receipt: {e}");
    }

    // 11. Start proxy server (blocks until shutdown)
    info!(
        listen = %proxy_config.listen_addr,
        upstream = %proxy_config.upstream_url,
        dashboard = %dashboard_path,
        "proxy server starting"
    );

    aegis_proxy::proxy::start(
        proxy_config,
        hooks,
        Some((dashboard_path, dashboard_router)),
    )
        .await
        .map_err(|e| StartupError::Proxy(format!("{e}")))?;

    // 12. Record shutdown receipt
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
    alert_tx: tokio::sync::broadcast::Sender<aegis_dashboard::DashboardAlert>,
    slm_config: aegis_slm::loopback::LoopbackConfig,
    slm_enabled: bool,
) -> MiddlewareHooks {
    match mode {
        Mode::PassThrough => {
            // Pass-through: no hooks at all (the proxy skips them anyway,
            // but we don't even allocate them)
            info!("pass-through mode: all middleware disabled");
            MiddlewareHooks::default()
        }
        _ => {
            let protected_files = Arc::new(std::sync::Mutex::new(
                aegis_barrier::protected_files::ProtectedFileManager::new(),
            ));
            let slm_hook: Option<Arc<dyn aegis_proxy::middleware::SlmHook>> = if slm_enabled {
                info!(
                    ollama_url = %slm_config.ollama_url,
                    model = %slm_config.model,
                    fallback = slm_config.fallback_to_heuristics,
                    "middleware hooks: evidence=yes vault=yes barrier=real slm=real"
                );
                Some(Arc::new(SlmHookImpl { config: slm_config }))
            } else {
                info!("middleware hooks: evidence=yes vault=yes barrier=real slm=disabled");
                None
            };
            MiddlewareHooks {
                evidence: Some(Arc::new(EvidenceHookImpl { recorder: recorder.clone(), alert_tx: alert_tx.clone() })),
                barrier: Some(Arc::new(BarrierHookImpl {
                    protected_files,
                    recorder,
                    alert_tx,
                })),
                slm: slm_hook,
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

    fn test_slm_config() -> aegis_slm::loopback::LoopbackConfig {
        aegis_slm::loopback::LoopbackConfig {
            ollama_url: "http://127.0.0.1:11434".to_string(),
            model: "test-model".to_string(),
            fallback_to_heuristics: true,
        }
    }

    #[test]
    fn create_hooks_observe_only() {
        let key = ed25519::generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let (alert_tx, _) = tokio::sync::broadcast::channel(32);
        let hooks = create_middleware_hooks(recorder, Mode::ObserveOnly, alert_tx, test_slm_config(), true);
        assert!(hooks.evidence.is_some());
        assert!(hooks.barrier.is_some());
        assert!(hooks.slm.is_some());
        assert!(hooks.vault.is_some());
    }

    #[test]
    fn create_hooks_observe_only_no_slm() {
        let key = ed25519::generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let (alert_tx, _) = tokio::sync::broadcast::channel(32);
        let hooks = create_middleware_hooks(recorder, Mode::ObserveOnly, alert_tx, test_slm_config(), false);
        assert!(hooks.evidence.is_some());
        assert!(hooks.barrier.is_some());
        assert!(hooks.slm.is_none());
        assert!(hooks.vault.is_some());
    }

    #[test]
    fn create_hooks_pass_through() {
        let key = ed25519::generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let (alert_tx, _) = tokio::sync::broadcast::channel(32);
        let hooks = create_middleware_hooks(recorder, Mode::PassThrough, alert_tx, test_slm_config(), true);
        assert!(hooks.evidence.is_none());
        assert!(hooks.barrier.is_none());
        assert!(hooks.slm.is_none());
        assert!(hooks.vault.is_none());
    }
}
