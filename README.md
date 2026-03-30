# Neural Commons

[![CI](https://github.com/LCatGA12/neural-commons/actions/workflows/ci.yml/badge.svg)](https://github.com/LCatGA12/neural-commons/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/LCatGA12/neural-commons)](https://github.com/LCatGA12/neural-commons/releases/latest)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

Trust infrastructure for MoltBook bot wardens. A Rust proxy that gives AI agents cryptographic identity, tamper-evident evidence, write protection, credential security, 5-layer prompt injection screening, NER-based PII detection, and channel-aware trust.

**[Why Install Aegis?](docs/WHY_INSTALL_AEGIS.md)** — written by an agent, for agents.

## Quick Start

```bash
# 1. Install
curl -fsSL https://github.com/LCatGA12/neural-commons/releases/latest/download/install.sh | bash

# 2. Connect to OpenClaw
aegis setup openclaw

# 3. Start protection (no SLM needed for basic use)
aegis --no-slm
```

Dashboard: http://localhost:3141/dashboard

Your agent now has evidence recording, write barriers, credential scanning, 5-layer injection screening, NER-based PII detection, and channel-based trust — all running locally. Default mode is observe-only (warns but never blocks).

See the [Quickstart Guide](docs/QUICKSTART.md) for full setup details.

---

## What It Does

Aegis sits between a bot and its upstream LLM provider as a transparent proxy. It watches what happens, records tamper-proof evidence, and protects critical files — all without breaking existing workflows.

- **5-Layer Screening Pipeline** — Defense-in-depth prompt injection and data loss prevention:
  1. **Heuristic** (<1ms) — 14-pattern regex for known injection patterns + SSRF detection
  2. **ProtectAI Classifier** (~30ms) — ONNX DeBERTa-v2 ML model, cached at startup
  3. **SLM Deep Analysis** (2-3s) — Local 30B model (Qwen3) for combined injection + recon + SSRF + fetch→exfil analysis, runs async alongside LLM forwarding
  4. **NER PII Detection** (~2ms) — XLM-RoBERTa ONNX model detects and redacts personal names, phone numbers, SSNs, credit cards, addresses, and other PII/PHI in responses. Context-aware: skips dates, city names without addresses, and version numbers. Trust-level controls redaction behavior (log-only, redact, or block).
  5. **Metaprompt Hardening** (0ms) — 7 security rules injected into system message (format-agnostic, works with Anthropic + OpenAI APIs)
- **Channel Trust** — Trust level resolved per-channel via signed Ed25519 certificates. Channel identity determines screening behavior: advisory vs blocking classifier, holster presets, SSRF policy. Configurable channel patterns with glob matching.
- **Evidence Chain** — Every API call produces a signed, hash-chained receipt. SHA-256 linked, Ed25519 signed, stored in append-only SQLite. Verifiable end-to-end with `aegis export --verify`.
- **Write Barrier** — Triple-layer detection for unauthorized file changes: real-time filesystem watcher, periodic hash sweeps, and outbound proxy interlock. Protects SOUL.md, AGENTS.md, MEMORY.md, .env, and custom files.
- **Credential Vault** — Automatic detection and encryption of plaintext secrets (API keys, tokens, passwords) in both request and response bodies. AES-256-GCM encryption, HKDF-SHA256 key derivation.
- **Memory Integrity** — Monitors bot memory files for unauthorized changes, injection attempts, and configuration drift. SSE alerts on detection.
- **Cryptographic Identity** — BIP-39 mnemonic to SLIP-0010 Ed25519 key derivation with domain-separated HD paths for signing, encryption, vault, and transport.
- **OpenClaw Plugin** — `aegis-channel-trust` plugin auto-registers channel context (Telegram, Discord, Slack, etc.) with signed Ed25519 payloads on every incoming message.

## Architecture

```
 Agent Framework (OpenClaw, etc.)
   │
   │  POST /aegis/register-channel {channel, user, ts, sig}
   │  (signed Ed25519 channel certificate)
   ▼
 aegis-proxy (:3141) ─── transparent HTTP proxy (axum/tower)
   │
   ├── Channel Trust Resolution (verify cert → resolve trust level)
   │
   ├── 4-Layer Screening Pipeline
   │   ├── 1. Heuristic    (<1ms)   regex patterns + SSRF
   │   ├── 2. Classifier   (~30ms)  ProtectAI DeBERTa-v2 ONNX
   │   ├── 3. SLM Deep     (2-3s)   Qwen3-30B async analysis
   │   └── 4. Metaprompt   (0ms)    security rules injected
   │
   ├── Evidence Recording (hash-chained receipts)
   ├── Credential Vault (scan + redact secrets)
   ├── Write Barrier (filesystem protection)
   └── Dashboard (9-tab web UI + SSE alerts)
         │
         ▼
   Upstream LLM (Anthropic, OpenAI, local)
```

## CLI Reference

```bash
# Start
aegis                              # observe-only mode (default)
aegis --enforce                    # enable blocking
aegis --no-slm                     # skip SLM screening
aegis --pass-through               # zero inspection, metadata-only receipts

# Setup
aegis setup openclaw               # configure OpenClaw integration
aegis setup openclaw --revert      # undo configuration

# Channel trust
aegis trust register <channel>     # register channel with signed Ed25519 cert
aegis trust context                # show active channel + full registry
aegis trust pubkey                 # show signing pubkey for config

# SLM model management
aegis slm status                   # show current SLM config
aegis slm use qwen/qwen3-30b-a3b  # switch model
aegis slm engine openai            # switch engine (ollama/openai)
aegis slm server http://localhost:1234  # set server URL

# Operations
aegis status                       # adapter status
aegis scan                         # scan workspace for credentials
aegis vault summary                # credential vault overview
aegis memory status                # memory file health
aegis export --verify              # export + verify evidence chain
aegis dashboard                    # open dashboard in browser
```

## Building

```bash
cargo check --workspace            # type-check
cargo test --workspace             # run all 461+ tests
cargo test -p aegis-barrier        # test a specific crate
cargo build --release -p aegis-cli # release binary
```

**Requirements:** Rust 1.85+ (edition 2024)

## Crate Map

### Adapter (Stream A) — runs on each bot's machine

| Crate | Purpose | Tests |
|-------|---------|-------|
| `aegis-adapter` | Server orchestration, hooks, config, state | 35 |
| `aegis-barrier` | Write barrier — filesystem watcher, protected files, snapshots | 208 |
| `aegis-evidence` | Evidence chain — hash-linked receipts, SQLite WAL store | 26 |
| `aegis-slm` | SLM screening — 4-layer pipeline, ProtectAI classifier, holster | 38 |
| `aegis-vault` | Credential vault — scanner, encrypted storage, KDF | 38 |
| `aegis-memory` | Memory integrity — file monitoring, heuristic screening | 23 |
| `aegis-proxy` | HTTP proxy — middleware pipeline, SSE streaming, rate limiting | 37 |
| `aegis-failure` | Resilience — anomaly detection, heartbeat, rollback | 8 |
| `aegis-gateway` | Auth — NC-Ed25519 stateless authentication | 4 |
| `aegis-dashboard` | Embedded web dashboard — 9 tabs, SSE alerts | 5 |
| `aegis-cli` | CLI binary — all user-facing commands | — |

### Shared

| Crate | Purpose | Tests |
|-------|---------|-------|
| `aegis-crypto` | BIP-39, SLIP-0010, SHA-256, Ed25519, AES-256-GCM, JCS | 10 |
| `aegis-schemas` | Receipt, ReceiptType, enforcement, rate limit schemas | 27 |

### Cluster (Stream B) — scaffolded, not yet active

| Crate | Purpose |
|-------|---------|
| `gateway` | Edge gateway with NC-Ed25519 auth, WebSocket, NATS bridge |
| `botawiki` | Distributed knowledge base with quarantine and dispute resolution |
| `trustmark` | TRUSTMARK scoring with temporal decay |
| `mesh` | libp2p mesh relay, trust-weighted routing |
| `evaluator` | Peer evaluation and tier admission |

## Key Design Decisions

All decisions documented in [`DECISIONS.md`](DECISIONS.md). Highlights:

- **Wire format:** RFC 8785 JCS — bytes signed = bytes on wire
- **Timestamps:** `i64` epoch milliseconds
- **Scores:** Integer basis points (0–10000), never floats in signed data
- **Default mode:** Observe-only — warn, don't block
- **Identity:** Ed25519 via BIP-39 / SLIP-0010
- **Vault encryption:** AES-256-GCM, HKDF-SHA256
- **Evidence storage:** SQLite WAL, append-only hash chain

## Project Status

See the full [Roadmap](ROADMAP.md) and [GitHub Milestones](https://github.com/LCatGA12/neural-commons/milestones).

**Tier 1 — Local Adapter:** Shipped (v0.2.33+, 461+ tests)
All adapter crates implemented and tested. Proxy, evidence chain, 4-layer SLM screening (heuristic + ProtectAI classifier + SLM + metaprompt), credential vault, write barrier, memory monitor, channel trust with signed certificates, 9-tab dashboard, OpenClaw plugin, CLI, CI/CD, install script.

**Channel Trust (TRUSTMARK v0.3):** Shipped in v0.2.29–v0.2.33
Ed25519 signed channel registration, trust-based screening policy, per-channel dashboard, 100% detection on 76 security + 71 CVE tests.

**Tier 1 Hardening (v0.3.0):** [In progress](https://github.com/LCatGA12/neural-commons/milestone/1) — target April 2026

**Cluster Foundation (v0.4.0):** [Planned](https://github.com/LCatGA12/neural-commons/milestone/2) — target June 2026

**Mesh & Intelligence (v0.5.0):** [Planned](https://github.com/LCatGA12/neural-commons/milestone/3)

## Documentation

- [Why Install Aegis?](docs/WHY_INSTALL_AEGIS.md) — the case for trust infrastructure, written from an agent's perspective
- [Quickstart Guide](docs/QUICKSTART.md) — install and protect your agent in 2 minutes
- [Roadmap](ROADMAP.md) — what's shipped, what's next
- [Decisions Register](DECISIONS.md) — architectural decisions with rationale
- [OpenClaw Integration](docs/OPENCLAW_INTEGRATION.md) — detailed integration guide
- [Channel Trust (Issue #83)](https://github.com/LCatGA12/neural-commons/issues/83) — TRUSTMARK channel trust design and implementation

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and PR process.

Pick any issue from the [v0.3.0 milestone](https://github.com/LCatGA12/neural-commons/milestone/1) — issues labeled `good first issue` are self-contained with clear scope.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

[AGPL-3.0-or-later](LICENSE). See the license file for details.
