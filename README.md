# Neural Commons

Trust infrastructure for 17,000+ MoltBook bot wardens. A Rust-based system that provides cryptographic identity, evidence recording, write protection, and credential security for AI bot ecosystems.

## What It Does

Neural Commons sits between a bot and its upstream API as a transparent proxy. It watches what happens, records tamper-proof evidence, and protects critical files from unauthorized modification — all without breaking existing workflows.

**Core capabilities:**

- **Evidence Chain** — Every significant event produces a signed, hash-chained receipt. Receipts are linked with SHA-256, signed with Ed25519, and stored locally. The chain is verifiable end-to-end.
- **Write Barrier** — Triple-layer detection for unauthorized file changes: real-time filesystem watcher, periodic hash sweeps, and outbound proxy interlock with single-use write tokens.
- **SLM Holster** — Small Language Model integration for prompt injection detection. 14-pattern threat taxonomy, deterministic scoring, and configurable rejection thresholds (Aggressive / Balanced / Permissive).
- **Credential Vault** — Automatic detection and encryption of plaintext secrets (API keys, tokens, passwords) found in bot workspaces. AES-256-GCM encryption with HKDF-derived keys.
- **Memory Integrity** — Monitors bot memory files (MEMORY.md, SOUL.md, etc.) for unauthorized changes, injection attempts, and configuration drift.
- **Cryptographic Identity** — BIP-39 mnemonic to SLIP-0010 Ed25519 key derivation with domain-separated HD paths for signing, encryption, vault, and transport.

## Architecture

```
                    +------------------+
                    |   Bot / Client   |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   aegis-proxy    |  <-- transparent HTTP proxy
                    |   (axum/tower)   |
                    +--------+---------+
                             |
          +------------------+------------------+
          |                  |                  |
   +------v------+   +------v------+   +------v------+
   | aegis-slm   |   | aegis-      |   | aegis-      |
   | (holster)   |   | barrier     |   | evidence    |
   +-------------+   +-------------+   +-------------+
          |                  |                  |
   +------v------+   +------v------+   +------v------+
   | aegis-vault |   | aegis-      |   | aegis-      |
   | (secrets)   |   | memory      |   | crypto      |
   +-------------+   +-------------+   +-------------+
```

**Two parallel workspaces:**

| Stream | Directory | Purpose |
|--------|-----------|---------|
| **A — Adapter** | `adapter/` | Runs on each bot's machine. Local protection, evidence recording, dashboard. |
| **B — Cluster** | `cluster/` | Shared network services. Gateway, Botawiki, mesh, trust scoring. |

**Shared crates:** `aegis-crypto` and `aegis-schemas` are consumed by both workspaces.

## Crate Map

### Adapter (Stream A)

| Crate | Purpose | Tests |
|-------|---------|-------|
| `aegis-adapter` | Main binary — composes hooks, replay protection, server | 33 |
| `aegis-barrier` | Write barrier — diff engine, severity classifier, filesystem watcher, write tokens, hash registry, evolution flow, protected files | 198 |
| `aegis-evidence` | Evidence chain — hash-linked receipts, SQLite store, Merkle rollups | 26 |
| `aegis-slm` | SLM integration — output parser, threat scoring, holster decisions | 18 |
| `aegis-vault` | Credential vault — encrypted storage, secret scanner, KDF, policy engine | 38 |
| `aegis-memory` | Memory integrity — file monitoring, change interception, heuristic screening | 23 |
| `aegis-proxy` | HTTP proxy — middleware pipeline, cognitive bridge, error handling | 21 |
| `aegis-failure` | Resilience — anomaly detection, heartbeat monitoring, rollback | 8 |
| `aegis-gateway` | Auth — NC-Ed25519 stateless authentication | 4 |
| `aegis-dashboard` | Embedded dashboard — <50KB, 2s polling | — |
| `aegis-cli` | CLI — `aegis init`, `aegis status`, `aegis evolve` | — |

### Shared

| Crate | Purpose | Tests |
|-------|---------|-------|
| `aegis-crypto` | BIP-39, SLIP-0010, SHA-256, Ed25519, AES-256-GCM, RFC 8785 JCS | 10 |
| `aegis-schemas` | Receipt, claim, trustmark, enterprise field schemas | — |
| `aegis-contract-tests` | Schema round-trip and serialization conformance tests | 27 |

### Cluster (Stream B) — Scaffolded

| Crate | Purpose |
|-------|---------|
| `gateway` | Edge gateway with NC-Ed25519 auth, WebSocket, NATS bridge |
| `botawiki` | Distributed knowledge base with quarantine and dispute resolution |
| `broadcast` | Foundation broadcast channel |
| `evaluator` | Peer evaluation and Tier 3 admission |
| `trustmark` | TRUSTMARK scoring with temporal decay |
| `mesh` | libp2p mesh relay, dead drops, trust-weighted routing |
| `ledger` | Compute credit ledger with circuit breaker |
| `rag` | RAG service for semantic search |
| `scheduler` | GPU task scheduling and routing |

## Building

```bash
# Check everything compiles
cargo check --workspace

# Run all 406 tests
cargo test --workspace

# Test a specific crate
cargo test -p aegis-barrier

# Build release binary
cargo build --release -p aegis-cli
```

**Requirements:** Rust 1.85+ (edition 2024)

## Key Design Decisions

All design decisions are documented in [`DECISIONS.md`](DECISIONS.md). Highlights:

- **Wire format:** RFC 8785 JCS — bytes signed = bytes on wire
- **Binary fields:** Lowercase hex everywhere, no exceptions
- **Timestamps:** i64 epoch milliseconds, not RFC 3339
- **Scores:** Integer basis points (0-10000), never floats in signed data
- **Phase 1 default:** Observe-only — warn, don't block

## Testing

Four-layer test architecture:

| Layer | Location | Target | Time |
|-------|----------|--------|------|
| Contract | `tests/contract/` | Schema round-trips | <30s |
| Integration | `tests/integration/` | NATS topology | <10s |
| HTTP | `tests/http/` | axum TestClient | <15s |
| Scenarios | `tests/scenarios/` | Docker Compose end-to-end | ~10min |

## Project Status

**Phase 0** — Crypto foundations, schema design, wire format: **Complete**

**Phase 1** — Adapter core implementation: **In progress**
- All adapter crates implemented with 406 passing tests
- Barrier module fully operational (198 tests)
- Evidence chain, SLM, vault, memory, proxy all functional
- Remaining: SLM loopback wiring, dashboard UI, CLI commands, end-to-end integration

**Phase 2** — Trust engine, tier system, Botawiki: Planned

**Phase 3** — Mesh network, compute credits, swarm coordination: Planned

## License

Proprietary. All rights reserved.
