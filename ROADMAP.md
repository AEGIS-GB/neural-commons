# Aegis Roadmap

> Current release: **v0.2.7** (Tier 1 — Local Adapter)
> Tracking: [GitHub Milestones](https://github.com/LCatGA12/neural-commons/milestones)

## What's Shipped (v0.2.x — Tier 1) ✅

The local adapter is feature-complete with 412+ unit tests and 94 end-to-end tests passing.

- **Core proxy** — HTTP forwarding with SSE streaming, incremental SHA-256 hashing, provider detection (Anthropic + OpenAI)
- **Evidence chain** — SHA-256 hash chain in append-only SQLite WAL. Tamper-evident. Verifiable with `aegis export --verify`
- **Credential vault** — Regex-based scanner, AES-256-GCM encryption, HKDF-SHA256 key derivation (D9), request + response scanning, VaultDetection receipts
- **Write barrier** — Filesystem watcher on identity/memory files, snapshot-based restore in enforce mode, severity heuristics
- **SLM screening** — Ollama HTTP + heuristic fallback, 14-pattern taxonomy, configurable holster presets
- **Memory monitor** — Change detection on MEMORY.md, memory/*.md, HEARTBEAT.md, SSE push
- **Dashboard** — 7-tab web UI (Status, Evidence, Memory, Alerts, Vault, Access, Traffic), SSE alert stream
- **CLI** — `aegis start/stop/restart`, `setup openclaw`, `scan`, `vault`, `export`, `update`
- **CI/CD** — Auto-release on merge, cross-platform builds (Linux, macOS x86/ARM, Windows), SHA-256 checksums

---

## v0.3.0 — Tier 1 Hardening

[Milestone](https://github.com/LCatGA12/neural-commons/milestone/1) · Target: April 2026

Stability, security, and developer experience improvements. No new subsystems.

### Quick Wins (~2 days)

| Issue | What | Effort |
|-------|------|--------|
| [#36](https://github.com/LCatGA12/neural-commons/issues/36) | Graceful shutdown — flush receipts on Ctrl+C | 2h |
| [#37](https://github.com/LCatGA12/neural-commons/issues/37) | Holster presets from config TOML | 2h |
| [#38](https://github.com/LCatGA12/neural-commons/issues/38) | Snapshot store for `.env*` and glob files | 2h |
| [#39](https://github.com/LCatGA12/neural-commons/issues/39) | Update snapshots after file evolution | 1h |
| [#40](https://github.com/LCatGA12/neural-commons/issues/40) | Vault scanning for SSE/streamed responses | 1d |
| [#41](https://github.com/LCatGA12/neural-commons/issues/41) | Structured error codes | 4h |
| [#55](https://github.com/LCatGA12/neural-commons/issues/55) | `aegis setup slm` — guided Ollama + model install | 2h |

### Medium Effort (~3 days)

| Issue | What | Effort |
|-------|------|--------|
| [#42](https://github.com/LCatGA12/neural-commons/issues/42) | Dashboard HTML/JS as separate files | 4h |
| [#43](https://github.com/LCatGA12/neural-commons/issues/43) | Binary signature verification | 1-2d |
| [#44](https://github.com/LCatGA12/neural-commons/issues/44) | WebSocket proxy support | 2-3d |
| [#45](https://github.com/LCatGA12/neural-commons/issues/45) | Dashboard authentication | 4h |

---

## v0.4.0 — Cluster Foundation

[Milestone](https://github.com/LCatGA12/neural-commons/milestone/2) · Target: June 2026

First cluster infrastructure. Adapters connect to the mesh. Trust scoring begins.

| Issue | What | Decisions |
|-------|------|-----------|
| [#46](https://github.com/LCatGA12/neural-commons/issues/46) | Edge Gateway routes | D3, D24 |
| [#47](https://github.com/LCatGA12/neural-commons/issues/47) | TRUSTMARK scoring engine | D13, D14, D15 |
| [#48](https://github.com/LCatGA12/neural-commons/issues/48) | Evaluator system | D20 |
| [#49](https://github.com/LCatGA12/neural-commons/issues/49) | Botawiki read API | D22, D28, D29 |
| [#50](https://github.com/LCatGA12/neural-commons/issues/50) | NATS bridge | D3 v3 |
| [#56](https://github.com/LCatGA12/neural-commons/issues/56) | Standalone SLM — bundle ONNX model, drop Ollama dependency | D4 |

**Depends on:** All v0.3.0 hardening complete. Gateway auth already implemented (Ed25519 stateless).

---

## v0.5.0 — Mesh & Intelligence

[Milestone](https://github.com/LCatGA12/neural-commons/milestone/3) · Target: TBD

ML-powered anomaly detection, multi-bot coordination, shared knowledge.

| Issue | What | Decisions |
|-------|------|-----------|
| [#51](https://github.com/LCatGA12/neural-commons/issues/51) | Centaur anomaly detection | D34 |
| [#52](https://github.com/LCatGA12/neural-commons/issues/52) | Swarm coordination | D33 |
| [#53](https://github.com/LCatGA12/neural-commons/issues/53) | Botawiki write path + disputes | — |
| [#54](https://github.com/LCatGA12/neural-commons/issues/54) | Foundation broadcast | — |

**Depends on:** v0.4.0 cluster foundation (Gateway, TRUSTMARK, Evaluator, Botawiki read).

---

## Decision Register

All architectural decisions are tracked in [DECISIONS.md](DECISIONS.md).

| Phase | Decisions | Status |
|-------|-----------|--------|
| Phase 0 (Foundation) | D0–D5 | LOCKED ✅ |
| Phase 1 (Tier 1) | D6–D12, D30–D31 | LOCKED ✅ |
| Phase 2 (Cluster) | D13–D29, D32–D35 | Decided, not implemented |

---

## Contributing

Pick any issue from the [v0.3.0 milestone](https://github.com/LCatGA12/neural-commons/milestone/1). The quick wins (#36-#41) are good first issues — each is self-contained with clear scope.

```bash
# Build and test
cargo test --workspace
./tests/e2e/smoke_test.sh
```
