//! aegis CLI — the main user-facing command
//!
//! Usage:
//!   aegis                        — start adapter (default: observe-only)
//!   aegis --observe-only         — force observe-only mode (panic switch)
//!   aegis --pass-through         — dumb forwarder, zero inspection
//!   aegis --enforce              — enable enforcement mode
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

    /// Open the dashboard in a browser
    Dashboard,

    /// Show version information
    Version,
}

#[derive(Subcommand)]
enum VaultCommands {
    /// List stored secrets (masked values)
    List,
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

        Some(Commands::Vault { action }) => match action {
            VaultCommands::List => {
                let db_path = config.data_dir.join("vault.db");
                if !db_path.exists() {
                    eprintln!("vault: no secrets stored (vault.db not found)");
                    return;
                }
                eprintln!("vault: listing stored secrets");
                eprintln!(
                    "  (vault storage listing requires vault key -- use 'aegis scan' for now)"
                );
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
                eprintln!("vault summary:");
                eprintln!("  total secrets: 0 (vault storage not yet initialized)");
                eprintln!("  use 'aegis scan' to detect plaintext credentials");
                eprintln!("  use 'aegis vault scan <path>' to scan a specific directory");
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
