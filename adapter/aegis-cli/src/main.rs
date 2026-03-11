//! aegis CLI — the main user-facing command
//!
//! Usage:
//!   aegis                        — start adapter (default: observe-only)
//!   aegis --observe-only         — force observe-only mode (panic switch)
//!   aegis --pass-through         — dumb forwarder, zero inspection
//!   aegis --enforce              — enable enforcement mode
//!   aegis --no-slm              — disable SLM screening entirely
//!   aegis status                 — show current adapter state
//!   aegis scan                   — run credential + vulnerability scan
//!   aegis export                 — export evidence chain as JSON
//!   aegis export --verify        — verify exported chain integrity
//!   aegis vault list             — list vault secrets (masked)
//!   aegis vault scan             — scan for plaintext credentials
//!   aegis memory status          — show memory file health
//!   aegis dashboard              — open dashboard URL in browser
//!   aegis version                — show version

use std::path::Path;

use clap::{Parser, Subcommand};

use aegis_adapter::config::AdapterConfig;
use aegis_adapter::Mode;

#[derive(Parser)]
#[command(
    name = "aegis",
    about = "Neural Commons Aegis Adapter — trust infrastructure for bot wardens",
    version,
    long_about = "Aegis protects your bot with evidence recording, credential vault, \
                  write barriers, memory integrity monitoring, and SLM screening.\n\n\
                  Default mode: observe-only (warn, don't block).\n\
                  Use --pass-through for zero inspection.\n\
                  Use --enforce to enable blocking."
)]
struct Cli {
    /// Set write_barrier and slm_reject to observe mode (warn only, no blocking).
    /// Does not affect vault encryption, memory revert, identity check, or failure rollback.
    #[arg(long, global = true, conflicts_with_all = ["pass_through", "enforce"])]
    observe_only: bool,

    /// Dumb forwarder mode — zero inspection, metadata-only receipts
    #[arg(long, global = true, conflicts_with_all = ["observe_only", "enforce"])]
    pass_through: bool,

    /// Enable enforcement mode — blocks on policy violations
    #[arg(long, global = true, conflicts_with_all = ["observe_only", "pass_through"])]
    enforce: bool,

    /// Path to configuration file
    #[arg(short, long, default_value = ".aegis/config.toml")]
    config: String,

    /// Upstream LLM provider URL (overrides config)
    #[arg(short, long)]
    upstream: Option<String>,

    /// Listen address (overrides config)
    #[arg(short, long)]
    listen: Option<String>,

    /// Disable SLM screening entirely (no Ollama, no heuristic fallback)
    #[arg(long)]
    no_slm: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show current adapter status
    Status,

    /// Run a credential and vulnerability scan
    Scan {
        /// Directory to scan (default: current directory)
        #[arg(default_value = ".")]
        path: String,
    },

    /// Export evidence chain
    Export {
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Verify chain integrity of the export
        #[arg(long)]
        verify: bool,

        /// Export only receipts within a time range (epoch ms)
        #[arg(long)]
        from: Option<i64>,

        /// Export only receipts up to this time (epoch ms)
        #[arg(long)]
        to: Option<i64>,
    },

    /// Credential vault operations
    Vault {
        #[command(subcommand)]
        action: VaultCommands,
    },

    /// Memory integrity operations
    Memory {
        #[command(subcommand)]
        action: MemoryCommands,
    },

    /// Configure a bot framework to use aegis
    Setup {
        #[command(subcommand)]
        target: SetupTarget,
    },

    /// Open the dashboard in a browser
    Dashboard,

    /// Show version information
    Version,
}

#[derive(Subcommand)]
enum SetupTarget {
    /// Configure OpenClaw (Claude Code) to route through aegis
    Openclaw {
        /// Show what would change without applying
        #[arg(long)]
        dry_run: bool,
        /// Revert to original configuration
        #[arg(long)]
        revert: bool,
        /// Proxy URL to configure (default: http://127.0.0.1:3141)
        #[arg(long, default_value = "http://127.0.0.1:3141")]
        proxy_url: String,
    },
}

#[derive(Subcommand)]
enum VaultCommands {
    /// List stored secrets (masked values)
    List {
        /// Show decrypted values (requires vault key)
        #[arg(long)]
        decrypt: bool,
    },
    /// Get a specific secret by ID
    Get {
        /// Secret ID
        id: String,
    },
    /// Delete a stored secret
    Delete {
        /// Secret ID
        id: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Scan for plaintext credentials in files
    Scan {
        /// Directory to scan
        #[arg(default_value = ".")]
        path: String,
        /// File extensions to scan (e.g. env,toml,json)
        #[arg(short, long)]
        extensions: Option<String>,
    },
    /// Show vault summary
    Summary,
}

#[derive(Subcommand)]
enum MemoryCommands {
    /// Show memory file health status
    Status,
    /// Acknowledge a memory file change
    Acknowledge {
        /// Path to the memory file
        path: String,
    },
    /// List tracked memory files
    List,
}

fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose {
        "debug"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Determine mode override from CLI flags
    let mode_override = if cli.pass_through {
        Some(Mode::PassThrough)
    } else if cli.enforce {
        Some(Mode::Enforce)
    } else if cli.observe_only {
        Some(Mode::ObserveOnly)
    } else {
        None
    };

    // Note: --observe-only flag is wired to EnforcementConfig after config load (below).

    let mode_label = match mode_override {
        Some(Mode::PassThrough) => "pass-through",
        Some(Mode::Enforce) => "enforce",
        Some(Mode::ObserveOnly) | None => "observe-only",
    };

    // Load configuration
    let mut config = if Path::new(&cli.config).exists() {
        AdapterConfig::from_file(Path::new(&cli.config)).unwrap_or_else(|e| {
            eprintln!("warning: failed to load config: {e}");
            eprintln!("using defaults");
            AdapterConfig::default()
        })
    } else {
        AdapterConfig::default()
    };

    // Apply CLI overrides
    if let Some(ref upstream) = cli.upstream {
        config.proxy.upstream_url = upstream.clone();
    }
    if let Some(ref listen) = cli.listen {
        config.proxy.listen_addr = listen.clone();
    }

    // D30: --observe-only sets write_barrier + slm_reject to observe.
    // Does NOT affect vault_block, memory_write, identity_check, failure_rollback.
    if cli.observe_only {
        config.enforcement.apply_observe_only_flag();
    }

    // --no-slm disables SLM screening entirely (no Ollama, no heuristic fallback)
    if cli.no_slm {
        config.slm.enabled = false;
        config.slm.fallback_to_heuristics = false;
    }

    match cli.command {
        None => {
            // Start the full adapter server
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(async {
                if let Err(e) = aegis_adapter::server::start(config, mode_override).await {
                    tracing::error!("adapter failed: {e}");
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            });
        }

        Some(Commands::Status) => {
            eprintln!("aegis status:");
            eprintln!("  mode:     {}", mode_label);
            eprintln!("  config:   {}", cli.config);
            eprintln!("  version:  {}", env!("CARGO_PKG_VERSION"));
            eprintln!("  listen:   {}", config.proxy.listen_addr);
            eprintln!("  upstream: {}", config.proxy.upstream_url);
            eprintln!("  data dir: {}", config.data_dir.display());

            // Try to read evidence chain state
            let db_path = config.data_dir.join("evidence.db");
            if db_path.exists() {
                match aegis_evidence::EvidenceStore::open(&db_path) {
                    Ok(store) => {
                        if let Ok(chain) = store.get_chain_state() {
                            eprintln!("  chain seq:     {}", chain.head_seq);
                            eprintln!("  receipts:      {}", chain.receipt_count);
                            eprintln!(
                                "  chain hash:    {}...{}",
                                &chain.head_hash[..8],
                                &chain.head_hash[chain.head_hash.len() - 8..]
                            );
                        }
                    }
                    Err(e) => eprintln!("  chain: error reading ({e})"),
                }
            } else {
                eprintln!("  chain: not initialized (no evidence.db)");
            }
        }

        Some(Commands::Scan { path }) => {
            eprintln!("scanning {} for credentials...", path);
            let extensions = &[
                "env", "toml", "json", "yaml", "yml", "cfg", "conf", "ini", "txt",
            ];
            match aegis_vault::scanner::scan_directory(Path::new(&path), extensions) {
                Ok(results) => {
                    if results.is_empty() {
                        eprintln!("  no credentials found");
                    } else {
                        let total_findings: usize =
                            results.iter().map(|(_, r)| r.findings.len()).sum();
                        eprintln!(
                            "  found {} credential(s) in {} file(s):",
                            total_findings,
                            results.len()
                        );
                        for (path, result) in &results {
                            for finding in &result.findings {
                                eprintln!(
                                    "  {} [{}] line {} -- {} ({})",
                                    path.display(),
                                    finding.credential_type,
                                    finding.location.line.unwrap_or(0),
                                    finding.masked_preview,
                                    match finding.confidence {
                                        aegis_vault::scanner::Confidence::High => "high",
                                        aegis_vault::scanner::Confidence::Medium => "medium",
                                        aegis_vault::scanner::Confidence::Low => "low",
                                    }
                                );
                            }
                        }
                    }
                }
                Err(e) => eprintln!("scan error: {e}"),
            }
        }

        Some(Commands::Export {
            output,
            verify,
            from: _from,
            to: _to,
        }) => {
            let db_path = config.data_dir.join("evidence.db");
            if !db_path.exists() {
                eprintln!(
                    "error: no evidence database found at {}",
                    db_path.display()
                );
                eprintln!("hint: start the adapter first to create an evidence chain");
                std::process::exit(1);
            }

            // Load the key to create a recorder
            let key_path = config.data_dir.join("identity.key");
            if !key_path.exists() {
                eprintln!("error: no identity key found at {}", key_path.display());
                std::process::exit(1);
            }

            let key_bytes = std::fs::read(&key_path).expect("failed to read identity key");
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key_bytes);
            let signing_key = aegis_crypto::ed25519::SigningKey::from_bytes(&key_arr);

            let recorder = aegis_evidence::EvidenceRecorder::new(&db_path, signing_key)
                .expect("failed to open evidence store");

            if verify {
                eprintln!("verifying evidence chain integrity...");
                match recorder.verify_chain() {
                    Ok(true) => {
                        let head = recorder.chain_head();
                        eprintln!(
                            "  chain integrity VALID ({} receipts, seq {})",
                            head.receipt_count, head.head_seq
                        );
                    }
                    Ok(false) => {
                        eprintln!("  chain integrity INVALID -- chain has been tampered with");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("error verifying chain: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                let target = output.as_deref().unwrap_or("stdout");
                eprintln!("exporting evidence chain to {}...", target);

                match recorder.export(None, None) {
                    Ok(receipts) => {
                        let json = serde_json::to_string_pretty(&receipts)
                            .expect("failed to serialize receipts");
                        if let Some(ref out_path) = output {
                            std::fs::write(out_path, &json)
                                .expect("failed to write export file");
                            eprintln!(
                                "  exported {} receipts to {}",
                                receipts.len(),
                                out_path
                            );
                        } else {
                            println!("{json}");
                        }
                    }
                    Err(e) => {
                        eprintln!("export error: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }

        Some(Commands::Setup { target }) => match target {
            SetupTarget::Openclaw { dry_run, revert, proxy_url } => {
                setup_openclaw(dry_run, revert, &proxy_url);
            }
        },

        Some(Commands::Vault { action }) => match action {
            VaultCommands::List { decrypt } => {
                let storage = open_vault_storage(&config);
                match storage.list_entries() {
                    Ok(entries) => {
                        if entries.is_empty() {
                            eprintln!("vault: no secrets stored");
                            return;
                        }
                        eprintln!("vault: {} secret(s) stored", entries.len());
                        for entry in &entries {
                            if decrypt {
                                match storage.get_secret(&entry.id) {
                                    Ok(secret) => {
                                        let value = String::from_utf8_lossy(&secret.plaintext);
                                        eprintln!(
                                            "  {} [{}] {} = {}",
                                            entry.id, entry.credential_type, entry.label, value
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "  {} [{}] {} (decrypt error: {e})",
                                            entry.id, entry.credential_type, entry.label
                                        );
                                    }
                                }
                            } else {
                                eprintln!(
                                    "  {} [{}] {} -- {}",
                                    entry.id,
                                    entry.credential_type,
                                    entry.label,
                                    entry.masked_preview
                                );
                                if let Some(ref src) = entry.source_file {
                                    eprintln!("    source: {src}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("vault: failed to list secrets: {e}");
                        std::process::exit(1);
                    }
                }
            }
            VaultCommands::Get { id } => {
                let storage = open_vault_storage(&config);
                match storage.get_secret(&id) {
                    Ok(secret) => {
                        let value = String::from_utf8_lossy(&secret.plaintext);
                        eprintln!("vault secret: {}", secret.entry.id);
                        eprintln!("  label:  {}", secret.entry.label);
                        eprintln!("  type:   {}", secret.entry.credential_type);
                        eprintln!("  value:  {}", value);
                        if let Some(ref src) = secret.entry.source_file {
                            eprintln!("  source: {src}");
                        }
                        eprintln!("  created: {} ms", secret.entry.created_ms);
                        eprintln!("  updated: {} ms", secret.entry.updated_ms);
                    }
                    Err(aegis_vault::VaultError::NotFound(_)) => {
                        eprintln!("vault: secret '{id}' not found");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("vault: failed to retrieve secret: {e}");
                        std::process::exit(1);
                    }
                }
            }
            VaultCommands::Delete { id, force } => {
                let storage = open_vault_storage(&config);
                // Show what we're about to delete
                if !force {
                    match storage.get_entry(&id) {
                        Ok(entry) => {
                            eprintln!(
                                "vault: delete {} [{}] {} ?",
                                entry.id, entry.credential_type, entry.label
                            );
                            eprint!("  confirm (y/N): ");
                            let mut input = String::new();
                            if std::io::stdin().read_line(&mut input).is_err() || !input.trim().eq_ignore_ascii_case("y") {
                                eprintln!("  cancelled");
                                return;
                            }
                        }
                        Err(aegis_vault::VaultError::NotFound(_)) => {
                            eprintln!("vault: secret '{id}' not found");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("vault: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                match storage.delete_secret(&id) {
                    Ok(true) => eprintln!("vault: deleted secret '{id}'"),
                    Ok(false) => {
                        eprintln!("vault: secret '{id}' not found");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("vault: failed to delete: {e}");
                        std::process::exit(1);
                    }
                }
            }
            VaultCommands::Scan { path, extensions } => {
                let exts_str =
                    extensions.as_deref().unwrap_or("env,toml,json,yaml,yml,cfg,conf,ini");
                let exts: Vec<&str> = exts_str.split(',').collect();
                eprintln!(
                    "scanning {} for credentials (extensions: {})...",
                    path, exts_str
                );
                match aegis_vault::scanner::scan_directory(Path::new(&path), &exts) {
                    Ok(results) => {
                        if results.is_empty() {
                            eprintln!("  no credentials found");
                        } else {
                            let total: usize =
                                results.iter().map(|(_, r)| r.findings.len()).sum();
                            eprintln!(
                                "  found {} credential(s) in {} file(s)",
                                total,
                                results.len()
                            );
                            for (path, result) in &results {
                                for finding in &result.findings {
                                    eprintln!(
                                        "  {} [{}] line {} -- {}",
                                        path.display(),
                                        finding.credential_type,
                                        finding.location.line.unwrap_or(0),
                                        finding.masked_preview,
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("scan error: {e}"),
                }
            }
            VaultCommands::Summary => {
                let storage = open_vault_storage(&config);
                match storage.summary() {
                    Ok(summary) => {
                        eprintln!("vault summary:");
                        eprintln!("  total secrets: {}", summary.total_secrets);
                        if !summary.by_type.is_empty() {
                            eprintln!("  by type:");
                            for (cred_type, count) in &summary.by_type {
                                eprintln!("    {}: {}", cred_type, count);
                            }
                        }
                        if let Some(oldest) = summary.oldest_ms {
                            eprintln!("  oldest: {} ms", oldest);
                        }
                        if let Some(newest) = summary.newest_ms {
                            eprintln!("  newest: {} ms", newest);
                        }
                    }
                    Err(e) => {
                        eprintln!("vault: failed to get summary: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Some(Commands::Memory { action }) => match action {
            MemoryCommands::Status => {
                let mem_config = aegis_memory::config::MemoryConfig {
                    memory_paths: config.memory.memory_paths.clone(),
                    include_defaults: true,
                    hash_interval_secs: config.memory.hash_interval_secs,
                };
                let current_dir = std::env::current_dir().unwrap_or_default();
                let files = mem_config.find_memory_files(&current_dir);
                eprintln!("memory integrity status:");
                eprintln!("  tracked patterns: {:?}", mem_config.all_patterns());
                eprintln!("  found files:      {}", files.len());
                for f in &files {
                    eprintln!("    {}", f.display());
                }
                eprintln!("  hash interval:    {}s", mem_config.hash_interval_secs);
            }
            MemoryCommands::Acknowledge { path } => {
                eprintln!("acknowledging change to: {}", path);
                eprintln!("acknowledged (requires running adapter)");
            }
            MemoryCommands::List => {
                let mem_config = aegis_memory::config::MemoryConfig {
                    memory_paths: config.memory.memory_paths.clone(),
                    include_defaults: true,
                    hash_interval_secs: config.memory.hash_interval_secs,
                };
                let current_dir = std::env::current_dir().unwrap_or_default();
                let files = mem_config.find_memory_files(&current_dir);
                eprintln!("tracked memory files ({}):", files.len());
                for f in &files {
                    eprintln!("  {}", f.display());
                }
                if files.is_empty() {
                    eprintln!("  (no memory files found)");
                    eprintln!("  patterns: {:?}", mem_config.all_patterns());
                }
            }
        },

        Some(Commands::Dashboard) => {
            let url = format!(
                "http://{}/dashboard",
                cli.listen
                    .as_deref()
                    .unwrap_or(&config.proxy.listen_addr)
            );
            eprintln!("dashboard URL: {}", url);
            // Attempt to open in browser
            #[cfg(target_os = "linux")]
            {
                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
            }
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("open").arg(&url).spawn();
            }
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("cmd")
                    .args(["/C", "start", &url])
                    .spawn();
            }
        }

        Some(Commands::Version) => {
            println!("aegis {}", env!("CARGO_PKG_VERSION"));
            println!("neural-commons adapter");
            println!("mode: {}", mode_label);
        }
    }
}

/// Open the vault storage, deriving the vault key from the identity key.
///
/// Exits the process if the identity key is missing or vault cannot be opened.
fn open_vault_storage(config: &AdapterConfig) -> aegis_vault::storage::VaultStorage {
    let key_path = config.data_dir.join("identity.key");
    if !key_path.exists() {
        eprintln!("error: no identity key found at {}", key_path.display());
        eprintln!("hint: start the adapter first to generate an identity key");
        std::process::exit(1);
    }

    let key_bytes = std::fs::read(&key_path).unwrap_or_else(|e| {
        eprintln!("error: failed to read identity key: {e}");
        std::process::exit(1);
    });
    let mut key_arr = [0u8; 32];
    if key_bytes.len() < 32 {
        eprintln!("error: identity key too short ({} bytes, need 32)", key_bytes.len());
        std::process::exit(1);
    }
    key_arr.copy_from_slice(&key_bytes[..32]);

    let signing_key = aegis_crypto::ed25519::SigningKey::from_bytes(&key_arr);
    let fingerprint = aegis_crypto::ed25519::fingerprint_hex(&signing_key.verifying_key());

    let vault_key = aegis_vault::kdf::derive_vault_key(&key_arr, &fingerprint).unwrap_or_else(|e| {
        eprintln!("error: vault key derivation failed: {e}");
        std::process::exit(1);
    });

    let db_path = config.data_dir.join("vault.db");
    aegis_vault::storage::VaultStorage::open(&db_path, vault_key).unwrap_or_else(|e| {
        eprintln!("error: failed to open vault storage: {e}");
        std::process::exit(1);
    })
}

/// Configure OpenClaw (Claude Code) to route through the aegis proxy.
fn setup_openclaw(dry_run: bool, revert: bool, proxy_url: &str) {
    let home = dirs::home_dir().unwrap_or_else(|| {
        eprintln!("error: cannot determine home directory");
        std::process::exit(1);
    });

    let config_path = home.join(".openclaw").join("openclaw.json");

    if revert {
        let backup_path = config_path.with_extension("json.aegis-backup");
        if !backup_path.exists() {
            eprintln!("error: no backup found at {}", backup_path.display());
            eprintln!("hint: aegis setup openclaw creates a backup before modifying");
            std::process::exit(1);
        }

        if dry_run {
            eprintln!("[dry-run] would restore {} from backup", config_path.display());
            return;
        }

        std::fs::copy(&backup_path, &config_path).unwrap_or_else(|e| {
            eprintln!("error: failed to restore backup: {e}");
            std::process::exit(1);
        });
        eprintln!("reverted openclaw config from backup");
        return;
    }

    if !config_path.exists() {
        // Create default config
        let parent = config_path.parent().unwrap();
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("error: cannot create {}: {e}", parent.display());
            std::process::exit(1);
        });

        let default_config = serde_json::json!({
            "baseUrl": proxy_url
        });

        if dry_run {
            eprintln!("[dry-run] would create {} with:", config_path.display());
            eprintln!("  baseUrl: {}", proxy_url);
            return;
        }

        let json = serde_json::to_string_pretty(&default_config).unwrap();
        std::fs::write(&config_path, &json).unwrap_or_else(|e| {
            eprintln!("error: failed to write {}: {e}", config_path.display());
            std::process::exit(1);
        });
        eprintln!("created {} with baseUrl={}", config_path.display(), proxy_url);
        return;
    }

    // Read existing config
    let content = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("error: failed to read {}: {e}", config_path.display());
        std::process::exit(1);
    });

    let mut config_json: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("error: invalid JSON in {}: {e}", config_path.display());
        std::process::exit(1);
    });

    let old_url = config_json.get("baseUrl")
        .and_then(|v| v.as_str())
        .unwrap_or("(not set)")
        .to_string();

    if dry_run {
        eprintln!("[dry-run] would modify {}:", config_path.display());
        eprintln!("  baseUrl: {} -> {}", old_url, proxy_url);
        return;
    }

    // Backup
    let backup_path = config_path.with_extension("json.aegis-backup");
    std::fs::copy(&config_path, &backup_path).unwrap_or_else(|e| {
        eprintln!("error: failed to create backup: {e}");
        std::process::exit(1);
    });
    eprintln!("backup: {}", backup_path.display());

    // Update
    config_json["baseUrl"] = serde_json::Value::String(proxy_url.to_string());
    let json = serde_json::to_string_pretty(&config_json).unwrap();
    std::fs::write(&config_path, &json).unwrap_or_else(|e| {
        eprintln!("error: failed to write {}: {e}", config_path.display());
        std::process::exit(1);
    });

    eprintln!("updated {}", config_path.display());
    eprintln!("  baseUrl: {} -> {}", old_url, proxy_url);
    eprintln!("  revert with: aegis setup openclaw --revert");
}
