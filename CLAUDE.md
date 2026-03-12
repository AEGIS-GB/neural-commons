# Aegis Adapter — Claude Code Context

## Project Overview

Aegis is a **Rust HTTP proxy** that sits between an OpenClaw bot agent and its upstream LLM provider (Anthropic, OpenAI). It listens on **port 3141** (`127.0.0.1:3141`), intercepts every API call, records tamper-evident evidence receipts, and optionally screens for prompt injection, credential leaks, and unauthorized file writes.

Default mode is **observe-only** — Aegis logs and warns but never blocks. The proxy forwards traffic unchanged.

## Repo Structure

```
neural-commons/
├── adapter/                        # Stream A — the local proxy
│   ├── aegis-adapter/              # Server orchestration, hooks, config     (33 tests)
│   │   └── src/
│   │       ├── server.rs           # Startup: key, evidence, hooks, monitors, proxy
│   │       ├── hooks.rs            # 4 middleware hooks bridging proxy ↔ subsystems
│   │       ├── config.rs           # AdapterConfig (TOML deserialization)
│   │       ├── mode.rs             # ModeController (observe/enforce/passthrough)
│   │       ├── state.rs            # AdapterState (shared across subsystems)
│   │       └── replay.rs           # MonotonicCounter, NonceRegistry
│   ├── aegis-barrier/              # Write barrier — filesystem watcher       (198 tests)
│   │   └── src/
│   │       ├── protected_files.rs  # ProtectedFileManager, pattern matching
│   │       ├── watcher.rs          # FileWatcher, notify event mapping
│   │       └── types.rs            # FileScope, SensitivityClass, EXCLUDED_DIRS
│   ├── aegis-evidence/             # Evidence chain — hash chain + SQLite     (26 tests)
│   │   └── src/
│   │       ├── chain.rs            # SHA-256 hash chain, receipt creation
│   │       ├── store.rs            # SQLite WAL storage, append/query/verify
│   │       └── lib.rs              # EvidenceRecorder (top-level API)
│   ├── aegis-vault/                # Credential scanner                       (38 tests)
│   │   └── src/
│   │       └── scanner.rs          # scan_text() — regex-based secret detection
│   ├── aegis-memory/               # Memory file monitor                      (23 tests)
│   │   └── src/
│   │       ├── monitor.rs          # MemoryMonitor, MemoryEvent
│   │       ├── screen.rs           # HeuristicScreener, ScreenVerdict
│   │       └── config.rs           # MemoryConfig (paths, interval)
│   ├── aegis-slm/                  # SLM injection screening                  (18 tests)
│   │   └── src/
│   │       └── ollama.rs           # Ollama HTTP client, heuristic fallback
│   ├── aegis-proxy/                # Core proxy engine                        (21 tests)
│   │   └── src/
│   │       ├── proxy.rs            # forward_request(), SSE streaming, build_router()
│   │       ├── config.rs           # ProxyConfig, ProxyMode, Provider
│   │       ├── middleware.rs       # Hook traits (EvidenceHook, VaultHook, etc.)
│   │       ├── rate_limit.rs       # Token-bucket rate limiter
│   │       ├── anthropic.rs        # Provider detection, request parsing
│   │       └── cognitive_bridge.rs # /aegis/* tool endpoints
│   ├── aegis-dashboard/            # Embedded web dashboard                   (4 tests)
│   │   └── src/
│   │       ├── routes.rs           # 8 API endpoints + SSE stream
│   │       └── assets.rs           # Embedded HTML/JS
│   ├── aegis-cli/                  # CLI binary entry point
│   │   └── src/main.rs            # clap commands, flags
│   ├── aegis-failure/              # Error types                              (8 tests)
│   └── aegis-gateway/              # Gateway types                            (4 tests)
├── shared/
│   ├── aegis-crypto/               # Ed25519 + SHA-256 helpers                (10 tests)
│   └── aegis-schemas/              # Receipt, ReceiptCore, ReceiptType        (27 contract tests)
├── tests/
│   ├── contract/                   # Layer 1: schema round-trip tests
│   └── e2e/smoke_test.sh          # 10-step, 17-check end-to-end test
├── docs/
│   ├── QUICKSTART.md               # Warden onboarding guide
│   └── tier1/
│       ├── TIER1_DECISIONS.md      # Decision register
│       ├── TIER1_DEFERRALS_AND_ROADMAP.md
│       └── Tier1_Implementation_Plan_FINAL.md
├── .github/workflows/
│   ├── ci.yml                      # Push/PR: cargo test + smoke test
│   └── release.yml                 # v* tags: cross-compile + GitHub Release
└── DECISIONS.md                    # Full decision register (D0–D34)
```

**Total: 406 unit tests** (aegis-barrier 198, aegis-evidence 26, aegis-vault 38, aegis-memory 23, aegis-slm 18, aegis-proxy 21, aegis-adapter 33, aegis-crypto 10, contract-tests 27, aegis-failure 8, aegis-gateway 4)

## Request Lifecycle

```
OpenClaw POST /v1/messages
  → proxy.rs forward_request()
    → Provider detection (anthropic.rs detect_provider — 422 for unknown)
    → Rate limiter check (token bucket, keyed by Ed25519 fingerprint, 1000/min burst 50)
    → SLM hook screens input (hooks.rs SlmHookImpl → Ollama HTTP or heuristic fallback)
    → Forward request to upstream (reqwest, 5min timeout)
    → SSE streaming detection:
        Content-Type: text/event-stream OR Transfer-Encoding: chunked
        → spawn background task: read chunks → incremental SHA-256 → forward to client
        → oneshot channel delivers final hash+size for evidence recording
    → Non-streaming: buffer full response
    → Vault hook scans response body (hooks.rs VaultHookImpl → scanner::scan_text)
    → Evidence hook records receipt (hooks.rs EvidenceHookImpl → EvidenceRecorder)
    → Response returned unchanged (observe mode) or blocked (enforce mode)
```

## Debugging Map

| Symptom | File to check | What to look for |
|---------|---------------|------------------|
| Streaming freezes | `aegis-proxy/src/proxy.rs` L296–385 | SSE branch: `is_sse \|\| is_chunked`, chunk_tx/rx channel, background hasher task |
| SLM admits everything | `aegis-adapter/src/hooks.rs` L216–251 | `SlmHookImpl::screen()` — check Ollama URL reachable, `fallback_to_heuristics`, `spawn_blocking` |
| Dashboard unreachable | `aegis-adapter/src/server.rs` L139–141 | `dashboard_router` mounting: `aegis_dashboard::routes::routes(dashboard_state)` |
| No evidence receipts | `aegis-adapter/src/hooks.rs` L48–110 | `EvidenceHookImpl::on_request/on_response` — check `recorder.record_simple()` errors |
| Barrier doesn't alert | `aegis-adapter/src/server.rs` L206–303 | Barrier watcher spawn: `notify::RecommendedWatcher`, `barrier_alert_tx.send()` |
| Rate limiting not working | `aegis-proxy/src/proxy.rs` L155–167 | `state.rate_limiter`, identity fingerprint key |
| Provider detection wrong | `aegis-proxy/src/proxy.rs` L147–152 | `anthropic::detect_provider(&headers)`, `allow_any_provider` config |
| Vault misses secrets | `aegis-adapter/src/hooks.rs` L120–148 | `VaultHookImpl::scan()` → `scanner::scan_text()` |
| Memory monitor silent | `aegis-adapter/src/server.rs` L142–204 | Memory monitor spawn, `mode != PassThrough` guard |
| Config not loading | `aegis-adapter/src/config.rs` | `AdapterConfig` TOML deserialization, default values |

## 10 Key Source Files (Read First)

1. **`adapter/aegis-adapter/src/server.rs`** — Startup orchestration: loads config, generates keys, initializes evidence, creates hooks, spawns memory monitor + barrier watcher, starts proxy with dashboard
2. **`adapter/aegis-adapter/src/hooks.rs`** — 4 middleware hook implementations bridging proxy traits to subsystem crates (EvidenceHookImpl, VaultHookImpl, BarrierHookImpl, SlmHookImpl)
3. **`adapter/aegis-proxy/src/proxy.rs`** — Core proxy: `forward_request()`, SSE streaming passthrough with incremental hashing, provider detection, rate limiting
4. **`adapter/aegis-proxy/src/config.rs`** — ProxyConfig (upstream URL, listen addr, mode, provider, rate limit), ProxyMode enum
5. **`adapter/aegis-barrier/src/protected_files.rs`** — ProtectedFileManager: system defaults (SOUL.md, AGENTS.md, etc.), warden-added files, pattern matching, 50-path cap
6. **`adapter/aegis-evidence/src/chain.rs`** — SHA-256 hash chain: `create_receipt()`, `advance_chain_state()`, `compute_receipt_hash()`
7. **`adapter/aegis-evidence/src/store.rs`** — SQLite WAL storage: `append_receipt()`, `get_receipt_by_seq()`, `verify_full_chain()`
8. **`adapter/aegis-slm/src/ollama.rs`** — Ollama HTTP client for SLM screening, heuristic regex fallback
9. **`adapter/aegis-dashboard/src/routes.rs`** — 8 dashboard API endpoints + SSE alert stream
10. **`adapter/aegis-dashboard/src/assets.rs`** — Embedded HTML/JS dashboard

## Locked Decisions

| Decision | Value |
|----------|-------|
| Wire format | RFC 8785 JCS (canonical JSON) — bytes signed = bytes on wire |
| Timestamps | `i64` epoch milliseconds |
| Scores | Basis points 0–10000 |
| Default mode | observe-only (warn, don't block) |
| Upstream default | `https://api.anthropic.com` |
| Listen address | `127.0.0.1:3141` |
| SLM engine | Ollama HTTP (`http://127.0.0.1:11434`) |
| SLM model | `llama3.2:1b` |
| Protected files | SOUL.md, AGENTS.md, IDENTITY.md, TOOLS.md, BOOT.md, MEMORY.md, `*.memory.md`, `.env*`, config.toml |
| Memory monitored | MEMORY.md, `memory/*.md`, HEARTBEAT.md, USER.md |
| Providers | Anthropic + OpenAI (422 for unknown) |
| Rate limit | 1000/min burst 50 (keyed by Ed25519 fingerprint) |
| Binary hosting | GitHub Releases |
| Evidence storage | SQLite WAL mode |
| Identity | Ed25519, BIP-39 / SLIP-0010 derivation |
| Vault encryption | AES-256-GCM, HKDF-SHA256 |
| Enforcement (D30) | `write_barrier` and `slm_reject` default observe; `vault_block` and `memory_write` always enforce |

## Building

```bash
cargo check --workspace            # Quick type-check both workspaces
cargo test --workspace             # Run all 406 tests
cargo build --release --bin aegis  # Release binary
cargo test -p aegis-barrier        # Test a specific crate (198 tests)
cargo test -p aegis-contract-tests # Layer 1 contract tests (27 tests)
./tests/e2e/smoke_test.sh         # 10-step, 17-check end-to-end test
```

## CI/CD

- **`ci.yml`** — Runs on push and PR to main: `cargo test --workspace` + smoke test
- **`release.yml`** — Runs on `v*` tags: cross-compiles 4 platforms (linux-x86_64, darwin-x86_64, darwin-aarch64, windows-x86_64), generates SHA-256 checksums, publishes GitHub Release

## Config Reference (`~/.aegis/config/config.toml`)

```toml
mode = "observe_only"              # "observe_only" | "enforce" | "pass_through"

[proxy]
listen_addr = "127.0.0.1:3141"
upstream_url = "https://api.anthropic.com"
max_body_size = 10485760           # 10MB
rate_limit_per_minute = 1000
allow_any_provider = false         # true to skip provider detection

[slm]
enabled = true
ollama_url = "http://127.0.0.1:11434"
model = "llama3.2:1b"
fallback_to_heuristics = true      # regex fallback when Ollama unavailable

[memory]
memory_paths = []                  # additional paths to monitor
hash_interval_secs = 30

[enforcement]                      # D30 enforcement overrides
write_barrier = "observe"          # "observe" (warn) or "enforce" (block)
slm_reject = "observe"
vault_block = "enforce"            # always enforce
memory_write = "enforce"           # always enforce

[dashboard]
path = "/dashboard"
```

## CLI Quick Reference

```bash
aegis                              # Start proxy (observe-only, port 3141)
aegis --enforce                    # Start with blocking enabled
aegis --no-slm                    # Start without SLM screening (no Ollama)
aegis --pass-through               # Dumb forwarder, zero inspection
aegis --config /path/to/config.toml

aegis setup openclaw               # Configure OpenClaw → Aegis proxy
aegis setup openclaw --dry-run     # Preview changes
aegis setup openclaw --revert      # Undo configuration

aegis scan                         # Scan workspace for credentials
aegis scan /path/to/dir            # Scan specific directory

aegis status                       # Show adapter status
aegis vault summary                # Credential vault overview
aegis memory status                # Memory file health
aegis export                       # Export evidence chain as JSON
aegis export --verify              # Export with integrity check
aegis dashboard                    # Open dashboard in browser
```

## Dashboard API Endpoints

All mounted under the dashboard path (default `/dashboard`):

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML dashboard page |
| `GET /api/status` | Mode, uptime, receipt count, health |
| `GET /api/evidence` | Receipt count, chain head, last receipt timestamp |
| `GET /api/memory` | Tracked files, changes detected |
| `GET /api/vault` | Detected secrets (masked), by type |
| `GET /api/access` | Last 50 API call entries |
| `GET /api/alerts` | Recent critical alerts (REST fallback) |
| `GET /api/alerts/stream` | SSE stream for real-time critical alerts |

## Dogfooding: Route Claude Code Through Aegis

Anthropic officially supports routing Claude Code through LLM gateways using the `ANTHROPIC_BASE_URL` environment variable. See [Anthropic LLM Gateway docs](https://docs.anthropic.com/en/docs/claude-code/llm-gateway).

**2-terminal setup:**

```bash
# Terminal 1: Start Aegis
aegis --no-slm
# Proxy is now listening on 127.0.0.1:3141
# Dashboard at http://localhost:3141/dashboard
```

```bash
# Terminal 2: Run Claude Code through Aegis
export ANTHROPIC_BASE_URL=http://127.0.0.1:3141
claude
```

**Safety notes:**
- The `ANTHROPIC_BASE_URL` env var is per-shell — it only affects the terminal where you set it
- To escape, close the terminal or `unset ANTHROPIC_BASE_URL`
- Aegis runs in observe-only mode by default — it will never block Claude Code requests
- Use `--no-slm` to avoid SLM screening overhead on Claude's own traffic

**What to watch for:**
- Streaming should work — Aegis detects SSE (`text/event-stream`) and chunked responses, forwarding them transparently while hashing incrementally
- Evidence receipts should appear on the dashboard at `http://localhost:3141/dashboard`
- Check `aegis export --verify` to confirm the evidence chain is intact

**Troubleshooting:**
- If Claude Code hangs: check that Aegis is running and `ANTHROPIC_BASE_URL` is set correctly
- If streaming feels slow: ensure `--no-slm` is set (SLM screening adds latency)
- If receipts are missing: check Aegis logs for evidence hook errors

## Further Reading

- [docs/tier1/TIER1_DECISIONS.md](docs/tier1/TIER1_DECISIONS.md) — Decision register with rationale
- [docs/tier1/TIER1_DEFERRALS_AND_ROADMAP.md](docs/tier1/TIER1_DEFERRALS_AND_ROADMAP.md) — Deferred items and roadmap
- [docs/QUICKSTART.md](docs/QUICKSTART.md) — Warden onboarding guide
