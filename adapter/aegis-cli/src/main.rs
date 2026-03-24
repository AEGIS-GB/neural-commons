//! aegis CLI — the main user-facing command
//!
//! Usage:
//!   aegis                        — start adapter (default: observe-only)
//!   aegis --observe-only         — force observe-only mode (panic switch)
//!   aegis --pass-through         — dumb forwarder, zero inspection
//!   aegis --enforce              — enable enforcement mode
//!   aegis --no-slm              — disable SLM screening entirely
//!   aegis start                  — start as background service (systemd)
//!   aegis stop                   — stop background service
//!   aegis restart                — restart background service
//!   aegis status                 — show current adapter state
//!   aegis scan                   — run credential + vulnerability scan
//!   aegis export                 — export evidence chain as JSON
//!   aegis export --verify        — verify exported chain integrity
//!   aegis vault list             — list vault secrets (masked)
//!   aegis vault scan             — scan for plaintext credentials
//!   aegis memory status          — show memory file health
//!   aegis slm status             — show current SLM configuration
//!   aegis slm use <model>        — switch SLM model
//!   aegis slm engine <engine>    — switch SLM engine (ollama/openai)
//!   aegis slm server <url>       — set SLM server URL
//!   aegis trust register <ch>    — register a channel with signed cert
//!   aegis trust unregister <ch>  — remove a channel from the registry
//!   aegis trust context          — show current channel trust context
//!   aegis trust pubkey           — show the signing public key
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

    /// Override SLM model (e.g. --slm-model qwen/qwen3-30b-a3b)
    #[arg(long)]
    slm_model: Option<String>,

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

    /// Start aegis as a background service (via systemd)
    Start,

    /// Stop the aegis background service
    Stop,

    /// Restart the aegis background service
    Restart,

    /// SLM screening configuration
    Slm {
        #[command(subcommand)]
        action: SlmCommands,
    },

    /// Channel trust operations
    Trust {
        #[command(subcommand)]
        action: TrustCommands,
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
enum SlmCommands {
    /// Show current SLM configuration
    Status,
    /// Detect hardware and recommend the best SLM model for this machine
    Recommend,
    /// Switch the SLM model (e.g. aegis slm use qwen/qwen3-30b-a3b)
    Use {
        /// Model name (e.g. qwen/qwen3-30b-a3b, qwen/qwen3-8b)
        model: String,
    },
    /// Switch the SLM engine (ollama, openai, or anthropic)
    Engine {
        /// Engine type: "ollama" or "openai" (OpenAI-compatible: LM Studio, vLLM, etc.)
        engine: String,
    },
    /// Set the SLM server URL
    Server {
        /// Server URL (e.g. http://localhost:11434 for Ollama, http://localhost:1234 for LM Studio)
        url: String,
    },
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

#[derive(Subcommand)]
enum TrustCommands {
    /// Register a channel with a signed Ed25519 certificate
    ///
    /// Examples:
    ///   aegis trust register openclaw:web:session1
    ///   aegis trust register telegram:dm:owner --user telegram:user:12345
    ///   aegis trust register cli:local:test
    Register {
        /// Channel identifier (e.g. "openclaw:web:session1", "telegram:dm:owner")
        channel: String,
        /// User identifier (e.g. "telegram:user:12345")
        #[arg(short, long, default_value = "cli:user:local")]
        user: String,
        /// Aegis proxy URL
        #[arg(long, default_value = "http://127.0.0.1:3141")]
        aegis_url: String,
    },
    /// Unregister a channel from the trust registry
    ///
    /// Examples:
    ///   aegis trust unregister openclaw:web:default
    ///   aegis trust unregister telegram:dm:owner
    Unregister {
        /// Channel identifier to remove
        channel: String,
        /// Aegis proxy URL
        #[arg(long, default_value = "http://127.0.0.1:3141")]
        aegis_url: String,
    },
    /// Show the current active channel trust context
    Context {
        /// Aegis proxy URL
        #[arg(long, default_value = "http://127.0.0.1:3141")]
        aegis_url: String,
    },
    /// Show the signing public key (hex) for configuring [trust] signing_pubkey
    Pubkey,
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

    // --slm-model overrides the SLM model from CLI
    if let Some(ref model) = cli.slm_model {
        config.slm.model = model.clone();
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

        Some(Commands::Slm { action }) => match action {
            SlmCommands::Status => {
                eprintln!("slm configuration:");
                eprintln!("  enabled:              {}", config.slm.enabled);
                eprintln!("  engine:               {}", config.slm.engine);
                eprintln!("  model:                {}", config.slm.model);
                eprintln!("  server url:           {}", config.slm.server_url);
                eprintln!("  heuristic fallback:   {}", config.slm.fallback_to_heuristics);
                eprintln!("  metaprompt hardening: {}", config.slm.metaprompt_hardening);
                eprintln!("  screening:            2-pass (injection + reconnaissance)");
            }
            SlmCommands::Recommend => {
                eprintln!("detecting hardware...\n");
                let hw = aegis_slm::hardware::detect_hardware();
                eprintln!("hardware:");
                eprintln!("{}", aegis_slm::hardware::format_hardware_info(&hw));
                eprintln!();

                let rec = aegis_slm::hardware::recommend(&hw);
                eprintln!("recommendation:");
                eprintln!("{}", aegis_slm::hardware::format_recommendation(&rec));
                eprintln!();

                // Hardware tier table
                eprintln!("all tiers:");
                eprintln!("  {:12} {:8} {:28} {:12} {:10}", "TIER", "VRAM", "MODEL", "DETECTION", "LATENCY");
                eprintln!("  {:=<12} {:=>8} {:=<28} {:=>12} {:=>10}", "", "", "", "", "");
                eprintln!("  {:12} {:>8} {:28} {:>12} {:>10}", "optimal", "12GB+", "qwen/qwen3-30b-a3b (MoE 3B)", "100%", "3-8s");
                eprintln!("  {:12} {:>8} {:28} {:>12} {:>10}", "good", "6-12GB", "qwen/qwen3-8b", "~70%", "4-10s");
                eprintln!("  {:12} {:>8} {:28} {:>12} {:>10}", "basic", "3-6GB", "qwen/qwen3-1.7b", "~45%", "1-3s");
                eprintln!("  {:12} {:>8} {:28} {:>12} {:>10}", "cpu-only", "none", "heuristic + classifier only", "~65%", "<10ms");
                eprintln!("  {:12} {:>8} {:28} {:>12} {:>10}", "api", "cloud", "claude-haiku-4-5-20251001", "~95%", "0.5-2s");
                eprintln!();
                eprintln!("  * cpu-only uses no LLM — heuristic patterns + ProtectAI classifier.");
                eprintln!("  * api tier uses Anthropic Haiku — no local GPU needed, requires ANTHROPIC_API_KEY.");
                eprintln!("  * All tiers include heuristic + classifier. SLM adds on top.");
                eprintln!("  * Metaprompt hardening is always available regardless of tier.");
                eprintln!("  * Apple Silicon uses unified memory — 32GB Mac ≈ 24GB effective for models.");
            }
            SlmCommands::Use { model } => {
                update_slm_config(&cli.config, "model", &model);
            }
            SlmCommands::Engine { engine } => {
                if engine != "ollama" && engine != "openai" && engine != "anthropic" {
                    eprintln!("error: engine must be 'ollama', 'openai', or 'anthropic'");
                    eprintln!("  ollama     — Ollama API (http://localhost:11434)");
                    eprintln!("  openai     — OpenAI-compatible API (LM Studio, vLLM, llama.cpp, LocalAI)");
                    eprintln!("  anthropic  — Anthropic Messages API (requires ANTHROPIC_API_KEY)");
                    std::process::exit(1);
                }
                update_slm_config(&cli.config, "engine", &engine);
                if engine == "anthropic" {
                    eprintln!("hint: set ANTHROPIC_API_KEY env var for authentication");
                    eprintln!("hint: default server: https://api.anthropic.com");
                    eprintln!("hint: recommended model: claude-haiku-4-5-20251001");
                }
            }
            SlmCommands::Server { url } => {
                update_slm_config(&cli.config, "server_url", &url);
            }
        },

        Some(Commands::Trust { action }) => match action {
            TrustCommands::Register { channel, user, aegis_url } => {
                trust_register(&config, &channel, &user, &aegis_url);
            }
            TrustCommands::Unregister { channel, aegis_url } => {
                trust_unregister(&channel, &aegis_url);
            }
            TrustCommands::Context { aegis_url } => {
                trust_context(&aegis_url);
            }
            TrustCommands::Pubkey => {
                trust_pubkey(&config);
            }
        },

        Some(Commands::Start) => {
            run_systemctl("start");
        }

        Some(Commands::Stop) => {
            run_systemctl("stop");
        }

        Some(Commands::Restart) => {
            run_systemctl("restart");
        }

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

/// Register a channel with a signed Ed25519 certificate.
fn trust_register(config: &AdapterConfig, channel: &str, user: &str, aegis_url: &str) {
    use aegis_crypto::ed25519::{Signer, SigningKey};

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
    if key_bytes.len() != 32 {
        eprintln!("error: identity key is {} bytes (expected 32)", key_bytes.len());
        std::process::exit(1);
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key_arr);

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Build canonical payload — keys MUST be alphabetically sorted
    // to match Rust's BTreeMap ordering in verify_cert
    let payload = serde_json::json!({
        "channel": channel,
        "trust": "",
        "ts": ts,
        "user": user,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    let signature = signing_key.sign(&payload_bytes);
    let sig_hex = aegis_crypto::ed25519::signature_hex(&signature);

    let body = serde_json::json!({
        "channel": channel,
        "user": user,
        "ts": ts,
        "sig": sig_hex,
    });

    eprintln!("registering channel...");
    eprintln!("  channel: {channel}");
    eprintln!("  user:    {user}");
    eprintln!("  ts:      {ts}");
    eprintln!("  sig:     {}...{}", &sig_hex[..16], &sig_hex[sig_hex.len()-16..]);

    // POST to Aegis
    let rt = tokio::runtime::Runtime::new().expect("failed to create runtime");
    let result = rt.block_on(async {
        let client = reqwest::Client::new();
        client
            .post(format!("{aegis_url}/aegis/register-channel"))
            .json(&body)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
    });

    match result {
        Ok(resp) => {
            let status = resp.status();
            let body_text = rt.block_on(resp.text()).unwrap_or_default();
            if status.is_success() {
                let json: serde_json::Value = serde_json::from_str(&body_text).unwrap_or_default();
                let trust_level = json.get("trust_level").and_then(|v| v.as_str()).unwrap_or("unknown");
                let ssrf = json.get("ssrf_allowed").and_then(|v| v.as_bool()).unwrap_or(false);
                eprintln!();
                eprintln!("  registered!");
                eprintln!("  trust_level:  {trust_level}");
                eprintln!("  ssrf_allowed: {ssrf}");
            } else {
                eprintln!();
                eprintln!("  registration failed: HTTP {status}");
                eprintln!("  {body_text}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("error: failed to connect to Aegis at {aegis_url}: {e}");
            eprintln!("hint: is Aegis running? (aegis --upstream ...)");
            std::process::exit(1);
        }
    }
}

/// Unregister a channel from the trust registry.
fn trust_unregister(channel: &str, aegis_url: &str) {
    eprintln!("unregistering channel...");
    eprintln!("  channel: {channel}");

    let rt = tokio::runtime::Runtime::new().expect("failed to create runtime");
    let result = rt.block_on(async {
        let client = reqwest::Client::new();
        client
            .post(format!("{aegis_url}/aegis/unregister-channel"))
            .json(&serde_json::json!({ "channel": channel }))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
    });

    match result {
        Ok(resp) => {
            let status = resp.status();
            let body_text = rt.block_on(resp.text()).unwrap_or_default();
            if status.is_success() {
                eprintln!("\n  unregistered!");
            } else {
                eprintln!("\n  failed: {body_text}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("error: failed to connect to Aegis at {aegis_url}: {e}");
            std::process::exit(1);
        }
    }
}

/// Show the current channel trust context from Aegis.
fn trust_context(aegis_url: &str) {
    let rt = tokio::runtime::Runtime::new().expect("failed to create runtime");
    let result = rt.block_on(async {
        let client = reqwest::Client::new();
        client
            .get(format!("{aegis_url}/aegis/channel-context"))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
    });

    match result {
        Ok(resp) => {
            let body_text = rt.block_on(resp.text()).unwrap_or_default();
            let json: serde_json::Value = serde_json::from_str(&body_text).unwrap_or_default();
            let pretty = serde_json::to_string_pretty(&json).unwrap_or(body_text);
            eprintln!("channel trust context:");
            eprintln!("{pretty}");
        }
        Err(e) => {
            eprintln!("error: failed to connect to Aegis at {aegis_url}: {e}");
            std::process::exit(1);
        }
    }
}

/// Show the signing public key (for configuring [trust] signing_pubkey in config.toml).
fn trust_pubkey(config: &AdapterConfig) {
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
    key_arr.copy_from_slice(&key_bytes[..32]);

    let signing_key = aegis_crypto::ed25519::SigningKey::from_bytes(&key_arr);
    let pubkey = signing_key.verifying_key();
    let pubkey_hex = aegis_crypto::ed25519::pubkey_hex(&pubkey);

    eprintln!("signing public key (Ed25519):");
    eprintln!("  {pubkey_hex}");
    eprintln!();
    eprintln!("add to .aegis/config.toml:");
    eprintln!("  [trust]");
    eprintln!("  signing_pubkey = \"{pubkey_hex}\"");
}

/// Run a systemctl command against the aegis service.
fn run_systemctl(action: &str) {
    // Check for updates on start/restart
    if action == "start" || action == "restart" {
        check_for_update();
    }

    // Try user service first, fall back to system service
    let user_output = std::process::Command::new("systemctl")
        .args(["--user", action, "aegis"])
        .output();

    let success = match user_output {
        Ok(o) if o.status.success() => {
            eprintln!("aegis service {action}ed");
            true
        }
        _ => {
            // Fall back to system service
            let sys_output = std::process::Command::new("systemctl")
                .args([action, "aegis"])
                .output();
            match sys_output {
                Ok(o) if o.status.success() => {
                    eprintln!("aegis service {action}ed");
                    true
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if stderr.contains("not found") || stderr.contains("not loaded") {
                        eprintln!("error: aegis systemd service not installed");
                        eprintln!("hint: run 'aegis setup service' to install the systemd service");
                    } else {
                        eprintln!("error: systemctl {action} failed");
                        eprint!("{}", stderr);
                    }
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("error: failed to run systemctl: {e}");
                    eprintln!("hint: systemd is required for aegis start/stop/restart");
                    std::process::exit(1);
                }
            }
        }
    };

    // Show status after start/restart
    if success && action != "stop" {
        std::thread::sleep(std::time::Duration::from_secs(2));
        // Try user service status first
        let status = std::process::Command::new("systemctl")
            .args(["--user", "status", "aegis", "--no-pager", "-l"])
            .output();
        match status {
            Ok(o) if o.status.success() || o.status.code() == Some(3) => {
                // code 3 = inactive, still show it
                eprint!("{}", String::from_utf8_lossy(&o.stdout));
            }
            _ => {
                let _ = std::process::Command::new("systemctl")
                    .args(["status", "aegis", "--no-pager", "-l"])
                    .status();
            }
        }
    }
}

/// Check GitHub for a newer release and suggest updating.
fn check_for_update() {
    let current = env!("CARGO_PKG_VERSION");

    // Quick non-blocking check — don't delay startup if it fails
    let output = std::process::Command::new("gh")
        .args(["release", "view", "--repo", "LCatGA12/neural-commons", "--json", "tagName", "--jq", ".tagName"])
        .output();

    if let Ok(o) = output {
        if o.status.success() {
            let latest_tag = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let latest_ver = latest_tag.trim_start_matches('v');

            if latest_ver != current {
                eprintln!("╔══════════════════════════════════════════════════╗");
                eprintln!("║  Update available: v{current} → {latest_tag}");
                eprintln!("║  Run: aegis-update");
                eprintln!("╚══════════════════════════════════════════════════╝");
                eprintln!();
            }
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

/// Update a single field in the [slm] section of the config TOML.
///
/// Creates the config file with defaults if it doesn't exist.
fn update_slm_config(config_path: &str, field: &str, value: &str) {
    let path = Path::new(config_path);

    // If the config file doesn't exist, create one with defaults
    if !path.exists() {
        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("error: cannot create {}: {e}", parent.display());
            std::process::exit(1);
        });

        let default_config = AdapterConfig::default();
        let toml_str = toml::to_string_pretty(&default_config).unwrap_or_else(|e| {
            eprintln!("error: failed to serialize default config: {e}");
            std::process::exit(1);
        });
        std::fs::write(path, &toml_str).unwrap_or_else(|e| {
            eprintln!("error: failed to write {}: {e}", path.display());
            std::process::exit(1);
        });
        eprintln!("created default config at {}", path.display());
    }

    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("error: failed to read {}: {e}", path.display());
        std::process::exit(1);
    });

    let mut doc: toml::Value = toml::from_str(&content).unwrap_or_else(|e| {
        eprintln!("error: invalid TOML in {}: {e}", path.display());
        std::process::exit(1);
    });

    // Ensure [slm] table exists
    let table = doc.as_table_mut().unwrap();
    if !table.contains_key("slm") {
        table.insert("slm".to_string(), toml::Value::Table(toml::map::Map::new()));
    }
    let slm = table.get_mut("slm").unwrap().as_table_mut().unwrap();

    let old_value = slm
        .get(field)
        .and_then(|v| v.as_str())
        .unwrap_or("(not set)")
        .to_string();

    slm.insert(field.to_string(), toml::Value::String(value.to_string()));

    let toml_str = toml::to_string_pretty(&doc).unwrap_or_else(|e| {
        eprintln!("error: failed to serialize config: {e}");
        std::process::exit(1);
    });

    std::fs::write(path, &toml_str).unwrap_or_else(|e| {
        eprintln!("error: failed to write {}: {e}", path.display());
        std::process::exit(1);
    });

    let friendly_name = match field {
        "model" => "model",
        "engine" => "engine",
        "server_url" => "server url",
        _ => field,
    };

    eprintln!("slm {}: {} -> {}", friendly_name, old_value, value);
    eprintln!("config: {}", path.display());

    if field == "engine" && value == "openai" {
        eprintln!("hint: set the server URL with: aegis slm server http://localhost:1234");
    }
    if field == "model" {
        eprintln!("hint: make sure the model is pulled/available on your SLM server");
    }
}
