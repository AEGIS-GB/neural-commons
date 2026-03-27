# Aegis Roadmap

> Current release: **v0.2.33** (Tier 1 — Local Adapter + Channel Trust)
> Tracking: [GitHub Milestones](https://github.com/AEGIS-GB/neural-commons/milestones)

## What's Shipped (v0.2.x — Tier 1)

The local adapter is feature-complete with 461+ unit tests, 94 end-to-end tests, 76 security tests, and 71 CVE attack simulations passing.

- **4-layer screening pipeline** — Defense-in-depth prompt injection detection:
  1. Heuristic (<1ms) — 14-pattern regex + SSRF detection (internal IPs, cloud metadata, fetch→exfil)
  2. ProtectAI Classifier (~30ms) — ONNX DeBERTa-v2 model, cached at startup via `OnceLock`
  3. SLM Deep Analysis (2-3s) — Local 30B model (Qwen3) async alongside LLM forwarding
  4. Metaprompt Hardening (0ms) — 7 security rules injected into system message (format-agnostic)
- **Channel trust (TRUSTMARK v0.3)** — Trust level resolved per-channel via signed Ed25519 certificates. Configurable channel patterns with glob matching. Trust determines classifier policy (blocking vs advisory), holster presets, and SSRF policy. [Issue #83](https://github.com/AEGIS-GB/neural-commons/issues/83)
- **OpenClaw plugin** — `aegis-channel-trust` plugin auto-registers channel context on every incoming Telegram/Discord/Slack message with Ed25519 signed payloads
- **Cognitive bridge** — `/aegis/register-channel`, `/aegis/channel-context` tool endpoints for agent frameworks
- **Core proxy** — HTTP forwarding with SSE streaming, incremental SHA-256 hashing, provider detection (Anthropic + OpenAI), format-agnostic metaprompt injection
- **Evidence chain** — SHA-256 hash chain in append-only SQLite WAL. Tamper-evident. Verifiable with `aegis export --verify`. Channel trust tagged on every receipt
- **Credential vault** — Regex-based scanner, AES-256-GCM encryption, HKDF-SHA256 key derivation (D9), request + response scanning, VaultDetection receipts
- **Write barrier** — Filesystem watcher on identity/memory files, snapshot-based restore in enforce mode, severity heuristics
- **Memory monitor** — Change detection on MEMORY.md, memory/*.md, HEARTBEAT.md, SSE push
- **Dashboard** — 9-tab web UI (Overview, Evidence, Vault, Access, Memory, SLM Screening, Channel Trust, Traffic, Alerts), SSE alert stream, unified request view with screening pipeline visualization
- **CLI** — `aegis start/stop/restart`, `setup openclaw`, `scan`, `vault`, `export`, `update`, `slm use/engine/server`
- **CI/CD** — Auto-release on merge, cross-platform builds (Linux, macOS x86/ARM, Windows), SHA-256 checksums

---

## v0.3.0 — Tier 1 Hardening

[Milestone](https://github.com/AEGIS-GB/neural-commons/milestone/1) · Target: April 2026

Stability, security, and developer experience improvements. Channel trust hardening.

### Quick Wins (~2 days)

| Issue | What | Effort |
|-------|------|--------|
| [#36](https://github.com/AEGIS-GB/neural-commons/issues/36) | Graceful shutdown — flush receipts on Ctrl+C | 2h |
| [#37](https://github.com/AEGIS-GB/neural-commons/issues/37) | Holster presets from config TOML | 2h |
| [#38](https://github.com/AEGIS-GB/neural-commons/issues/38) | Snapshot store for `.env*` and glob files | 2h |
| [#39](https://github.com/AEGIS-GB/neural-commons/issues/39) | Update snapshots after file evolution | 1h |
| [#40](https://github.com/AEGIS-GB/neural-commons/issues/40) | Vault scanning for SSE/streamed responses | 1d |
| [#41](https://github.com/AEGIS-GB/neural-commons/issues/41) | Structured error codes | 4h |
| [#55](https://github.com/AEGIS-GB/neural-commons/issues/55) | `aegis setup slm` — guided Ollama + model install | 2h |

### Medium Effort (~3 days)

| Issue | What | Effort |
|-------|------|--------|
| [#42](https://github.com/AEGIS-GB/neural-commons/issues/42) | Dashboard HTML/JS as separate files | 4h |
| [#43](https://github.com/AEGIS-GB/neural-commons/issues/43) | Binary signature verification | 1-2d |
| [#44](https://github.com/AEGIS-GB/neural-commons/issues/44) | WebSocket proxy support | 2-3d |
| [#45](https://github.com/AEGIS-GB/neural-commons/issues/45) | Dashboard authentication | 4h |

---

## v0.4.0 — Cluster Foundation

[Milestone](https://github.com/AEGIS-GB/neural-commons/milestone/2) · Target: June 2026

First cluster infrastructure. Adapters connect to the mesh. Full TRUSTMARK scoring.

| Issue | What | Decisions |
|-------|------|-----------|
| [#46](https://github.com/AEGIS-GB/neural-commons/issues/46) | Edge Gateway routes | D3, D24 |
| [#47](https://github.com/AEGIS-GB/neural-commons/issues/47) | TRUSTMARK scoring engine (6-dimension, temporal decay) | D13, D14, D15 |
| [#48](https://github.com/AEGIS-GB/neural-commons/issues/48) | Evaluator system | D20 |
| [#49](https://github.com/AEGIS-GB/neural-commons/issues/49) | Botawiki read API | D22, D28, D29 |
| [#50](https://github.com/AEGIS-GB/neural-commons/issues/50) | NATS bridge | D3 v3 |
| [#56](https://github.com/AEGIS-GB/neural-commons/issues/56) | Standalone SLM — bundle ONNX model, drop Ollama dependency | D4 |
| [#83](https://github.com/AEGIS-GB/neural-commons/issues/83) | TRUSTMARK v0.4 — effective trust formula, per-channel scoring, distributed trust | D13-D15 |

**Depends on:** All v0.3.0 hardening complete. Channel trust foundation shipped in v0.2.x. Gateway auth already implemented (Ed25519 stateless).

---

## v0.5.0 — Mesh & Intelligence

[Milestone](https://github.com/AEGIS-GB/neural-commons/milestone/3) · Target: TBD

ML-powered anomaly detection, multi-bot coordination, shared knowledge.

| Issue | What | Decisions |
|-------|------|-----------|
| [#51](https://github.com/AEGIS-GB/neural-commons/issues/51) | Centaur anomaly detection | D34 |
| [#52](https://github.com/AEGIS-GB/neural-commons/issues/52) | Swarm coordination | D33 |
| [#53](https://github.com/AEGIS-GB/neural-commons/issues/53) | Botawiki write path + disputes | — |
| [#54](https://github.com/AEGIS-GB/neural-commons/issues/54) | Foundation broadcast | — |

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

Pick any issue from the [v0.3.0 milestone](https://github.com/AEGIS-GB/neural-commons/milestone/1). The quick wins (#36-#41) are good first issues — each is self-contained with clear scope.

```bash
# Build and test
cargo test --workspace
./tests/e2e/smoke_test.sh
```
