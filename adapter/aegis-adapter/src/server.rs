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

use crate::Mode;
use crate::config::AdapterConfig;
use crate::hooks::{BarrierHookImpl, EvidenceHookImpl, SlmHookImpl, VaultHookImpl};
use crate::mode::ModeController;
use crate::replay::{MonotonicCounter, NonceRegistry};
use crate::state::AdapterState;

/// Auto-detect the ProtectAI classifier model directory.
/// Searches standard locations for model.onnx + tokenizer.json.
fn detect_prompt_guard_model() -> Option<String> {
    let candidates = [
        // Relative to working directory
        "models/protectai-v2",
        // Aegis data directory
        ".aegis/models/protectai-v2",
    ];
    // Also check home-relative paths
    let home_candidates: Vec<PathBuf> = if let Ok(home) = std::env::var("HOME") {
        vec![PathBuf::from(&home).join(".aegis/models/protectai-v2")]
    } else {
        vec![]
    };

    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.join("tokenizer.json").exists()
            && (path.join("model.onnx").exists() || path.join("model.quant.onnx").exists())
        {
            info!(path = %path.display(), "ProtectAI classifier model found");
            return Some(path.to_string_lossy().to_string());
        }
    }
    for path in &home_candidates {
        if path.join("tokenizer.json").exists()
            && (path.join("model.onnx").exists() || path.join("model.quant.onnx").exists())
        {
            info!(path = %path.display(), "ProtectAI classifier model found");
            return Some(path.to_string_lossy().to_string());
        }
    }
    info!(
        "ProtectAI classifier model not found — classifier layer disabled (use `aegis slm recommend` for setup guidance, or `aegis --no-slm` to silence)"
    );
    None
}

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
pub async fn start(config: AdapterConfig, mode_override: Option<Mode>) -> Result<(), StartupError> {
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
    let verifying_key = signing_key.verifying_key();
    let bot_id = ed25519::pubkey_hex(&verifying_key);
    // Clone signing key for manifest use (before evidence recorder consumes it)
    let manifest_signing_key = SigningKey::from_bytes(&signing_key.to_bytes());
    info!(bot_id = %bot_id, "identity loaded");

    // 4. Initialize evidence recorder
    let evidence_db = data_dir.join("evidence.db");
    let recorder = EvidenceRecorder::new(&evidence_db, signing_key)
        .map_err(|e| StartupError::Evidence(format!("{e}")))?;
    let recorder = Arc::new(recorder);

    let (alert_tx, _alert_rx) =
        tokio::sync::broadcast::channel::<aegis_dashboard::DashboardAlert>(32);

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

    // 5b. Create traffic store (in-memory ring buffer for dashboard inspector)
    let traffic_store = Arc::new(aegis_dashboard::TrafficStore::new(200));

    // 5c. Build dashboard shared state
    let dashboard_state = Arc::new(aegis_dashboard::DashboardSharedState {
        alert_tx: alert_tx.clone(),
        evidence: recorder.clone(),
        traffic: traffic_store.clone(),
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
        data_dir: data_dir.clone(),
        auth_token: generate_dashboard_token(&config),
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
        let monitor =
            aegis_memory::monitor::MemoryMonitor::new(mem_config, screener, workspace_root);
        let monitor_recorder = recorder.clone();
        let monitor_alert_tx = alert_tx.clone();

        tokio::spawn(async move {
            monitor
                .run(move |events| {
                    for event in &events {
                        match event {
                            aegis_memory::monitor::MemoryEvent::FileChanged {
                                path,
                                screen_verdict,
                                ..
                            } => {
                                let action = format!("memory_change {}", path.display());
                                let outcome = format!("verdict={screen_verdict:?}");
                                if let Err(e) = monitor_recorder.record_simple(
                                    aegis_schemas::ReceiptType::MemoryIntegrity,
                                    &action,
                                    &outcome,
                                ) {
                                    tracing::warn!("failed to record memory event: {e}");
                                }

                                if matches!(
                                    screen_verdict,
                                    aegis_memory::screen::ScreenVerdict::Blocked
                                ) {
                                    let alert = aegis_dashboard::DashboardAlert {
                                        ts_ms: std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_millis()
                                            as u64,
                                        kind: "memory_injection".to_string(),
                                        message: format!(
                                            "Suspicious memory change: {}",
                                            path.display()
                                        ),
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
                            aegis_memory::monitor::MemoryEvent::FileAppeared {
                                path,
                                screen_verdict,
                                ..
                            } => {
                                let action = format!("memory_appeared {}", path.display());
                                let outcome = format!("verdict={screen_verdict:?}");
                                if let Err(e) = monitor_recorder.record_simple(
                                    aegis_schemas::ReceiptType::MemoryIntegrity,
                                    &action,
                                    &outcome,
                                ) {
                                    tracing::warn!("failed to record memory appeared: {e}");
                                }
                            }
                            aegis_memory::monitor::MemoryEvent::FileTracked {
                                path,
                                content_hash,
                                ..
                            } => {
                                let action = format!("memory_tracked {}", path.display());
                                let outcome =
                                    format!("hash={}", &content_hash[..16.min(content_hash.len())]);
                                if let Err(e) = monitor_recorder.record_simple(
                                    aegis_schemas::ReceiptType::MemoryIntegrity,
                                    &action,
                                    &outcome,
                                ) {
                                    tracing::warn!("failed to record memory tracked: {e}");
                                }
                            }
                            _ => {}
                        }
                    }
                })
                .await;
        });
        info!(
            "memory monitor started (interval={}s)",
            config.memory.hash_interval_secs
        );
    }

    // 6b. Start barrier filesystem watcher (Layer 1 detection + enforce revert)
    if mode != Mode::PassThrough {
        let barrier_protected = Arc::new(std::sync::Mutex::new(
            aegis_barrier::protected_files::ProtectedFileManager::new(),
        ));
        let barrier_recorder = recorder.clone();
        let barrier_alert_tx = alert_tx.clone();
        let watcher_workspace = std::env::current_dir().unwrap_or_default();
        let barrier_mode = mode;

        // Between-session manifest check: compare disk against last known-good state.
        // Detects tampering that happened while Aegis was offline.
        if let Some(prev_manifest) = aegis_barrier::manifest::FileManifest::load_from(&data_dir) {
            if prev_manifest.verify_signature(&verifying_key) {
                let discrepancies = prev_manifest.compare_against_disk(&watcher_workspace);
                let tamperings: Vec<_> = discrepancies
                    .iter()
                    .filter(|r| !matches!(r, aegis_barrier::manifest::ManifestCheckResult::Match))
                    .collect();
                if tamperings.is_empty() {
                    info!(
                        "manifest: all files match previous session — no between-session tampering"
                    );
                } else {
                    for result in &tamperings {
                        let (msg, action) = match result {
                            aegis_barrier::manifest::ManifestCheckResult::HashChanged {
                                path,
                                expected,
                                actual,
                            } => (
                                format!(
                                    "BETWEEN-SESSION TAMPERING: {} (expected={} actual={})",
                                    path.display(),
                                    &expected[..16.min(expected.len())],
                                    &actual[..16.min(actual.len())]
                                ),
                                format!("between_session_tamper {}", path.display()),
                            ),
                            aegis_barrier::manifest::ManifestCheckResult::Missing { path } => (
                                format!("BETWEEN-SESSION DELETION: {}", path.display()),
                                format!("between_session_delete {}", path.display()),
                            ),
                            _ => continue,
                        };
                        warn!("manifest: {msg}");
                        if let Err(e) = barrier_recorder.record_simple(
                            aegis_schemas::ReceiptType::WriteBarrier,
                            &action,
                            "between_session_tampering_detected",
                        ) {
                            warn!("failed to record between-session tampering: {e}");
                        }
                        let alert = aegis_dashboard::DashboardAlert {
                            ts_ms: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                            kind: "between_session_tamper".to_string(),
                            message: msg,
                            receipt_seq: barrier_recorder.chain_head().head_seq,
                        };
                        let _ = alert_tx.send(alert);
                    }
                    warn!(
                        count = tamperings.len(),
                        "manifest: between-session tampering detected!"
                    );
                }
            } else {
                warn!(
                    "manifest: previous session manifest has INVALID SIGNATURE — possible manifest tampering"
                );
                if let Err(e) = barrier_recorder.record_simple(
                    aegis_schemas::ReceiptType::WriteBarrier,
                    "manifest_signature_invalid",
                    "previous manifest signature verification failed",
                ) {
                    warn!("failed to record manifest signature failure: {e}");
                }
            }
        }

        // Snapshot critical files at startup for enforce-mode restore.
        // No git dependency — restores from in-memory copy.
        let critical_paths: Vec<std::path::PathBuf> = barrier_protected
            .lock()
            .map(|mgr| {
                mgr.list_all()
                    .iter()
                    .filter(|e| e.critical)
                    .filter(|e| e.scope == aegis_barrier::types::FileScope::WorkspaceRoot)
                    .map(|e| std::path::PathBuf::from(&e.pattern))
                    .collect()
            })
            .unwrap_or_default();
        let snapshot_store = Arc::new(aegis_barrier::snapshot::SnapshotStore::load(
            &watcher_workspace,
            &critical_paths,
        ));

        // Write signed manifest for between-session persistence.
        // On next startup, this manifest is compared against disk to detect offline tampering.
        let manifest = aegis_barrier::manifest::FileManifest::from_snapshot(
            &snapshot_store,
            &manifest_signing_key,
        );
        if let Err(e) = manifest.write_to(&data_dir) {
            warn!("failed to write file manifest: {e}");
        }
        let barrier_manifest = Arc::new(std::sync::Mutex::new(manifest));
        let barrier_signing_key = Arc::new(manifest_signing_key);
        let barrier_data_dir = data_dir.clone();

        // Layer 2: Periodic hash verification (60s safety net).
        // If inotify drops events (overflow, race), this catches tampering.
        let layer2_snapshot = snapshot_store.clone();
        let layer2_workspace = watcher_workspace.clone();
        let layer2_recorder = barrier_recorder.clone();
        let layer2_alert_tx = barrier_alert_tx.clone();
        let layer2_mode = barrier_mode;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip immediate first tick

            loop {
                interval.tick().await;
                let mismatches = layer2_snapshot.verify_all(&layer2_workspace);
                for (rel_path, mismatch) in &mismatches {
                    let mismatch_desc = match mismatch {
                        aegis_barrier::snapshot::SnapshotMismatch::HashChanged {
                            expected,
                            actual,
                        } => {
                            format!(
                                "hash_changed expected={} actual={}",
                                &expected[..16.min(expected.len())],
                                &actual[..16.min(actual.len())]
                            )
                        }
                        aegis_barrier::snapshot::SnapshotMismatch::Missing => {
                            "file_missing".to_string()
                        }
                    };

                    // In enforce mode, restore from snapshot
                    let reverted = if layer2_mode == Mode::Enforce {
                        match layer2_snapshot.restore(&layer2_workspace, rel_path) {
                            Ok(true) => {
                                tracing::warn!(
                                    path = %rel_path.display(),
                                    layer = 2,
                                    "barrier: RESTORED critical file from snapshot (periodic check)"
                                );
                                true
                            }
                            Ok(false) => false,
                            Err(e) => {
                                tracing::error!(path = %rel_path.display(), error = %e, "barrier: Layer 2 restore failed");
                                false
                            }
                        }
                    } else {
                        false
                    };

                    let action = format!("periodic_hash_check {}", rel_path.display());
                    let outcome = if reverted {
                        format!("{mismatch_desc} reverted=true")
                    } else {
                        format!("{mismatch_desc} reverted=false")
                    };

                    if let Err(e) = layer2_recorder.record_simple(
                        aegis_schemas::ReceiptType::WriteBarrier,
                        &action,
                        &outcome,
                    ) {
                        tracing::warn!("failed to record Layer 2 barrier event: {e}");
                    }

                    let msg = if reverted {
                        format!(
                            "Layer 2: Critical file tampered and REVERTED: {} ({})",
                            rel_path.display(),
                            mismatch_desc
                        )
                    } else {
                        format!(
                            "Layer 2: Critical file tampered: {} ({})",
                            rel_path.display(),
                            mismatch_desc
                        )
                    };
                    let alert = aegis_dashboard::DashboardAlert {
                        ts_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64,
                        kind: "periodic_hash_check".to_string(),
                        message: msg,
                        receipt_seq: layer2_recorder.chain_head().head_seq,
                    };
                    let _ = layer2_alert_tx.send(alert);
                }
                if !mismatches.is_empty() {
                    tracing::warn!(
                        count = mismatches.len(),
                        "Layer 2 periodic check found mismatches"
                    );
                }
            }
        });
        info!("barrier Layer 2 periodic hash check started (60s interval)");

        // Clone refs for the Layer 1 watcher (needs manifest + signing key for trust-tier updates)
        let watcher_manifest = barrier_manifest.clone();
        let watcher_signing_key = barrier_signing_key.clone();
        let watcher_data_dir = barrier_data_dir.clone();

        tokio::spawn(async move {
            use aegis_barrier::types::DebounceConfig;
            use aegis_barrier::watcher::{FileWatcher, is_excluded, map_notify_event};
            use notify::{Config, RecursiveMode, Watcher};

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
                tracing::error!(
                    "barrier watcher failed to watch {}: {e}",
                    watcher_workspace.display()
                );
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
                    let relative = we.path.strip_prefix(&watcher_workspace).unwrap_or(&we.path);
                    let is_protected = barrier_protected
                        .lock()
                        .map(|mgr| mgr.is_protected(relative))
                        .unwrap_or(false);
                    let is_critical = barrier_protected
                        .lock()
                        .map(|mgr| mgr.is_critical(relative))
                        .unwrap_or(false);

                    if is_protected {
                        let action =
                            format!("filesystem_change {} {:?}", relative.display(), we.kind);

                        // Trust-tier-aware decision: check active channel trust level.
                        // Trusted/Full → allow change, update manifest (warden or authorized agent)
                        // Public/Unknown/Restricted → potential prompt injection, block/alert
                        // No channel → no active session, treat as suspicious
                        let channel_trust =
                            aegis_proxy::cognitive_bridge::get_registered_channel_trust();
                        let is_trusted_channel = channel_trust
                            .as_ref()
                            .map(|ct| {
                                matches!(
                                    ct.trust_level,
                                    aegis_schemas::TrustLevel::Full
                                        | aegis_schemas::TrustLevel::Trusted
                                )
                            })
                            .unwrap_or(false);

                        let trust_label = channel_trust
                            .as_ref()
                            .map(|ct| format!("{:?}", ct.trust_level))
                            .unwrap_or_else(|| "no_channel".to_string());

                        // Decision: revert only if untrusted channel AND enforce mode AND critical
                        let should_revert =
                            barrier_mode == Mode::Enforce && is_critical && !is_trusted_channel;

                        let reverted = if should_revert {
                            match snapshot_store.restore(&watcher_workspace, relative) {
                                Ok(true) => {
                                    tracing::warn!(
                                        path = %relative.display(),
                                        trust = %trust_label,
                                        "barrier: RESTORED critical file (untrusted channel, enforce mode)"
                                    );
                                    true
                                }
                                Ok(false) => {
                                    tracing::warn!(
                                        path = %relative.display(),
                                        "barrier: no snapshot available for restore"
                                    );
                                    false
                                }
                                Err(e) => {
                                    tracing::error!(
                                        path = %relative.display(),
                                        error = %e,
                                        "barrier: failed to restore file from snapshot"
                                    );
                                    false
                                }
                            }
                        } else {
                            false
                        };

                        // If trusted channel and not reverted, update the manifest
                        // to accept the new file state as legitimate.
                        if is_trusted_channel
                            && !reverted
                            && let Ok(content) = std::fs::read(watcher_workspace.join(relative))
                        {
                            let new_hash = hex::encode(aegis_crypto::hash(&content));
                            if let Ok(mut m) = watcher_manifest.lock() {
                                m.update_file(
                                    &relative.to_string_lossy(),
                                    &new_hash,
                                    &watcher_signing_key,
                                );
                                if let Err(e) = m.write_to(&watcher_data_dir) {
                                    tracing::warn!("failed to update manifest: {e}");
                                }
                            }
                            tracing::info!(
                                path = %relative.display(),
                                trust = %trust_label,
                                "barrier: accepted change from trusted channel, manifest updated"
                            );
                        }

                        let outcome = if reverted {
                            format!("critical_file_reverted trust={trust_label}")
                        } else if is_trusted_channel {
                            format!("trusted_change_accepted trust={trust_label}")
                        } else if is_critical {
                            format!("critical_file_modified trust={trust_label}")
                        } else {
                            format!("protected_file_modified trust={trust_label}")
                        };

                        if let Err(e) = barrier_recorder.record_simple(
                            aegis_schemas::ReceiptType::WriteBarrier,
                            &action,
                            &outcome,
                        ) {
                            tracing::warn!("failed to record barrier event: {e}");
                        }

                        if is_critical && !is_trusted_channel {
                            let msg = if reverted {
                                format!(
                                    "Critical file modified and REVERTED: {} (channel: {})",
                                    relative.display(),
                                    trust_label
                                )
                            } else {
                                format!(
                                    "Critical file modified: {} (channel: {})",
                                    relative.display(),
                                    trust_label
                                )
                            };
                            let alert = aegis_dashboard::DashboardAlert {
                                ts_ms: we.timestamp_ms,
                                kind: "structural_write".to_string(),
                                message: msg,
                                receipt_seq: barrier_recorder.chain_head().head_seq,
                            };
                            let _ = barrier_alert_tx.send(alert);
                        }

                        tracing::warn!(
                            path = %relative.display(),
                            critical = is_critical,
                            reverted = reverted,
                            trust = %trust_label,
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
    let prompt_guard_dir = config
        .slm
        .prompt_guard_model_dir
        .clone()
        .or_else(detect_prompt_guard_model);
    // P0: Cache the ProtectAI classifier at startup (~950ms once, ~5ms per-request)
    aegis_slm::loopback::init_prompt_guard(prompt_guard_dir.as_deref());
    let slm_config = aegis_slm::loopback::LoopbackConfig {
        engine: config.slm.engine.clone(),
        server_url: config.slm.server_url.clone(),
        model: config.slm.model.clone(),
        fallback_to_heuristics: config.slm.fallback_to_heuristics,
        prompt_guard_model_dir: prompt_guard_dir,
    };
    let slm_enabled = config.slm.enabled;
    // Vault allowlist: intentionally empty. Plaintext credentials in config.toml
    // is worse than the detection noise it would suppress. The real fix is
    // context-aware scanning (issue #104) — distinguishing authorized credential
    // usage in tool call results from actual exfiltration. Until then, the scanner
    // flags everything and the warden interprets the results.
    let vault_allowlist: Vec<String> = Vec::new();
    let hooks = create_middleware_hooks(
        recorder.clone(),
        mode,
        alert_tx.clone(),
        slm_config,
        slm_enabled,
        vault_allowlist,
        config.slm.slm_timeout_secs,
    );

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
        provider: config
            .proxy
            .provider
            .as_deref()
            .and_then(|p| serde_json::from_value(serde_json::Value::String(p.to_string())).ok())
            .unwrap_or_else(|| aegis_proxy::config::Provider::from_url(&config.proxy.upstream_url)),
        allow_any_provider: config.proxy.allow_any_provider,
        metaprompt_hardening: config.slm.metaprompt_hardening,
        slm_max_content_chars: config.slm.slm_max_content_chars,
        rate_limit_burst: 50,
    };

    // 8. Warn if upstream is still the default (common misconfiguration)
    if config.proxy.upstream_url == "https://api.anthropic.com" {
        info!(
            "upstream_url is the default (https://api.anthropic.com) — set [proxy] upstream_url in config.toml if needed"
        );
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

    // 10b. Record initial TRUSTMARK snapshot and start periodic recording (every hour)
    {
        let tm_data_dir = data_dir.clone();
        let tm_recorder = recorder.clone();
        tokio::spawn(async move {
            // Initial snapshot at startup
            let signals = aegis_trustmark::gather::gather_local_signals(&tm_data_dir);
            let score = aegis_trustmark::scoring::TrustmarkScore::compute(&signals);
            if let Err(e) = aegis_trustmark::persist::record_snapshot(&tm_recorder, &score) {
                tracing::warn!("failed to record initial TRUSTMARK snapshot: {e}");
            } else {
                tracing::info!(
                    score = format!("{:.3}", score.total),
                    "TRUSTMARK snapshot recorded"
                );
            }

            // Hourly snapshots
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.tick().await; // skip immediate tick
            loop {
                interval.tick().await;
                let signals = aegis_trustmark::gather::gather_local_signals(&tm_data_dir);
                let score = aegis_trustmark::scoring::TrustmarkScore::compute(&signals);
                if let Err(e) = aegis_trustmark::persist::record_snapshot(&tm_recorder, &score) {
                    tracing::warn!("failed to record TRUSTMARK snapshot: {e}");
                } else {
                    tracing::info!(
                        score = format!("{:.3}", score.total),
                        "TRUSTMARK hourly snapshot"
                    );
                }
            }
        });
        info!("TRUSTMARK scoring started (snapshot every 1h)");
    }

    // 11. Start proxy server (blocks until shutdown)
    info!(
        listen = %proxy_config.listen_addr,
        upstream = %proxy_config.upstream_url,
        dashboard = %dashboard_path,
        "proxy server starting"
    );

    let traffic_recorder: Arc<aegis_proxy::proxy::TrafficRecorder> = {
        let ts = traffic_store.clone();
        Arc::new(
            move |method: &str,
                  path: &str,
                  status: u16,
                  req: &[u8],
                  resp: &[u8],
                  dur: u64,
                  streaming: bool,
                  slm_verdict: Option<&aegis_proxy::middleware::SlmVerdict>,
                  channel: Option<&str>,
                  trust_level: Option<&str>,
                  model: Option<&str>,
                  context: Option<&str>,
                  slm_detail: Option<serde_json::Value>| {
                let (slm_dur, slm_action, slm_score) = match slm_verdict {
                    Some(v) => (
                        Some(v.screening_ms),
                        Some(v.action.as_str()),
                        Some(v.threat_score),
                    ),
                    None => (None, None, None),
                };
                ts.record(
                    method,
                    path,
                    status,
                    req,
                    resp,
                    dur,
                    streaming,
                    slm_dur,
                    slm_action,
                    slm_score,
                    channel,
                    trust_level,
                    model,
                    context,
                    slm_detail,
                );
                ts.last_id()
            },
        )
    };

    let traffic_slm_updater: Arc<aegis_proxy::proxy::TrafficSlmUpdater> = {
        let ts = traffic_store.clone();
        Arc::new(
            move |entry_id: u64, verdict: &aegis_proxy::middleware::SlmVerdict| {
                if let Ok(json) = serde_json::to_value(verdict) {
                    ts.update_slm(entry_id, &json);
                }
            },
        )
    };

    // Build trust config from adapter config
    let trust_config = {
        use aegis_proxy::channel_trust::{TrustConfig, parse_trust_level};
        let tc = &config.trust;

        // Channel trust (access control — by source IP)
        let channels: Vec<(String, aegis_schemas::TrustLevel)> = tc
            .channels
            .iter()
            .map(|cp| (cp.identity.clone(), parse_trust_level(&cp.level)))
            .collect();

        // Context patterns (OpenClaw metadata — observability only)
        let contexts: Vec<(String, aegis_schemas::TrustLevel)> = tc
            .contexts
            .iter()
            .map(|cp| {
                (
                    cp.pattern.clone(),
                    parse_trust_level(cp.label.as_deref().unwrap_or("unknown")),
                )
            })
            .collect();

        let signing_pubkey = tc
            .signing_pubkey
            .as_ref()
            .and_then(|hex_str| hex::decode(hex_str).ok());

        if channels.is_empty() {
            tracing::info!(
                "No [[trust.channels]] configured — all sources default to '{}'",
                tc.default_level
            );
        }

        TrustConfig {
            default_level: parse_trust_level(&tc.default_level),
            signing_pubkey,
            channels,
            contexts,
        }
    };

    aegis_proxy::proxy::start_with_traffic_full(
        proxy_config,
        hooks,
        Some((dashboard_path, dashboard_router)),
        Some(traffic_recorder),
        Some(traffic_slm_updater),
        Some(trust_config),
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
    vault_allowlist: Vec<String>,
    slm_timeout_secs: u64,
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
                    engine = %slm_config.engine,
                    server_url = %slm_config.server_url,
                    model = %slm_config.model,
                    fallback = slm_config.fallback_to_heuristics,
                    "middleware hooks: evidence=yes vault=yes barrier=real slm=real"
                );
                Some(Arc::new(SlmHookImpl {
                    config: slm_config,
                    recorder: recorder.clone(),
                    alert_tx: alert_tx.clone(),
                    timeout_secs: slm_timeout_secs,
                }))
            } else {
                info!("middleware hooks: evidence=yes vault=yes barrier=real slm=disabled");
                None
            };
            MiddlewareHooks {
                evidence: Some(Arc::new(EvidenceHookImpl {
                    recorder: recorder.clone(),
                    alert_tx: alert_tx.clone(),
                })),
                barrier: Some(Arc::new(BarrierHookImpl {
                    protected_files,
                    recorder,
                    alert_tx,
                })),
                slm: slm_hook,
                vault: Some(Arc::new(VaultHookImpl {
                    allowlist: vault_allowlist,
                })),
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
/// Generate or retrieve the dashboard auth token.
/// If configured in config.toml, use that. Otherwise generate and log it.
fn generate_dashboard_token(config: &AdapterConfig) -> Option<String> {
    if let Some(ref token) = config.dashboard.auth_token {
        if !token.is_empty() {
            info!("dashboard auth: token configured");
            return Some(token.clone());
        }
    }

    // Auto-generate a token
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = format!("aegis_dk_{}", hex::encode(bytes));
    info!(
        token = %token,
        "dashboard auth: token auto-generated (add to [dashboard] auth_token in config.toml to persist)"
    );
    Some(token)
}

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
    eprintln!(
        "  bot id:     {}...{}",
        &bot_id[..8],
        &bot_id[bot_id.len() - 8..]
    );
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
            engine: "ollama".to_string(),
            server_url: "http://127.0.0.1:11434".to_string(),
            model: "test-model".to_string(),
            fallback_to_heuristics: true,
            prompt_guard_model_dir: None,
        }
    }

    #[test]
    fn create_hooks_observe_only() {
        let key = ed25519::generate_keypair();
        let recorder = Arc::new(EvidenceRecorder::new_in_memory(key).unwrap());
        let (alert_tx, _) = tokio::sync::broadcast::channel(32);
        let hooks = create_middleware_hooks(
            recorder,
            Mode::ObserveOnly,
            alert_tx,
            test_slm_config(),
            true,
            vec![],
            15,
        );
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
        let hooks = create_middleware_hooks(
            recorder,
            Mode::ObserveOnly,
            alert_tx,
            test_slm_config(),
            false,
            vec![],
            15,
        );
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
        let hooks = create_middleware_hooks(
            recorder,
            Mode::PassThrough,
            alert_tx,
            test_slm_config(),
            true,
            vec![],
            15,
        );
        assert!(hooks.evidence.is_none());
        assert!(hooks.barrier.is_none());
        assert!(hooks.slm.is_none());
        assert!(hooks.vault.is_none());
    }
}
