# Tier 1 Deferrals & Future Roadmap

**Document Date:** 2026-03-10  
**Status:** COMMITTED — These decisions are locked for Tier 1  
**Purpose:** Track what we're NOT doing in Tier 1 and why, so nothing gets lost

---

## Related Documents

| Document | Purpose |
|----------|---------|
| **TIER1_DECISIONS.md** | Quick reference spec — all locked decisions, config, CLI |
| **This document** | What's NOT in Tier 1 — deferrals, limitations, tech debt |
| **Tier1_Implementation_Plan_FINAL.md** | Detailed implementation guide with code examples |

---

## How to Read This Document

- **DEFERRED** = Consciously pushed to a later phase. We know we need it.
- **LIMITATION** = Tier 1 ships with this constraint. Wardens should know.
- **TECH DEBT** = Shortcuts we took that need cleanup.
- **FUTURE** = Ideas discussed but not yet scheduled.

---

## Phase 2 Deferrals

These items were explicitly discussed and deferred to Phase 2.

### D-001: WebSocket Support

**What:** Proxy passthrough for WebSocket connections (protocol upgrade, bidirectional streaming).

**Why Deferred:** SSE covers the main streaming use case. WebSocket adds significant complexity (connection lifecycle, frame handling, heartbeats). Phase 2 after SSE is stable.

**Impact:** Bots using WebSocket-based APIs will not work through aegis in Tier 1.

**Blocked By:** SSE streaming must be stable first.

**Estimated Effort:** 2-3 days

---

### D-002: Binary Signature Verification

**What:** Ed25519 signature verification of downloaded binaries in install script.

**Why Deferred:** Requires Foundation keypair generation, secure key storage, CI/CD integration for signing releases. Too much infrastructure for initial launch.

**Impact:** Wardens must manually verify checksums. Log warning displayed during install.

**Mitigation:** 
- Install script prints: "Binary signature verification not yet implemented. Verify checksums manually."
- README includes checksum verification instructions.

**Estimated Effort:** 1-2 days (plus CI/CD setup)

---

### D-003: Package Manager Distribution

**What:** Distribution via brew, apt, pacman, etc.

**Why Deferred:** Each package manager has its own packaging requirements, review process, and maintenance burden. Focus on direct install first.

**Impact:** Wardens must use install script or manual download.

**Estimated Effort:** 1 day per package manager

---

### D-004: GPU Acceleration Configuration

**What:** Explicit GPU configuration options (CUDA, ROCm, Metal selection).

**Why Deferred:** Ollama handles GPU auto-detection. Explicit config only needed for edge cases.

**Impact:** None for most users. Edge cases (multi-GPU, specific backend selection) not supported.

**Note:** Auto-detection IS enabled in Tier 1. This deferral is only for manual override config.

**Estimated Effort:** 4 hours

---

### D-005: Vault Scanning for Streamed Responses

**What:** Real-time credential scanning of SSE/chunked responses as they stream.

**Why Deferred:** Adds complexity to streaming pipeline. Credentials in LLM output streams are rare. Non-streamed responses ARE scanned.

**Impact:** Credentials in streamed responses may not be detected until post-hoc analysis.

**Note (2026-03-12):** Vault redaction is now implemented for non-streaming responses (`scanner::redact_text()`). Streaming vault scanning remains deferred.

**Estimated Effort:** 1 day

---

### D-006: Additional Provider Support

**What:** Support for providers beyond Anthropic and OpenAI (Cohere, Mistral, Google, local models).

**Why Deferred:** Each provider has different auth patterns, headers, and API shapes. Focus on the two most common first.

**Impact:** Wardens using other providers must set `allow_any_provider: true` and lose provider-specific optimizations.

**Workaround:** `allow_any_provider: true` in config.toml enables passthrough for any API.

**Estimated Effort:** 4 hours per provider

---

### D-007: Dashboard Authentication

**What:** Optional authentication for dashboard access (basic auth, token-based).

**Why Deferred:** Dashboard is localhost-only in Tier 1. Auth adds friction for solo wardens.

**Impact:** Anyone with localhost access can view dashboard. Not suitable for shared machines.

**Prerequisite for:** Remote dashboard access (Phase 3+).

**Estimated Effort:** 4 hours

---

### D-008: Configurable Rate Limit Persistence

**What:** Option to persist rate limit state across restarts.

**Why Deferred:** Adds SQLite writes on every request. Restarts are rare. Simple in-memory is sufficient.

**Impact:** Rate limits reset on adapter restart. Could allow burst after restart.

**Estimated Effort:** 2 hours

---

### D-009: Advanced OpenClaw Config Fields

**What:** Setting timeout, retry, and other OpenClaw config fields via `aegis setup openclaw`.

**Why Deferred:** `baseUrl` is the critical field. Other fields are advanced tuning most wardens won't need.

**Impact:** Wardens needing custom timeouts must edit config manually.

**Estimated Effort:** 1 hour

---

## Tier 1 Known Limitations

These are constraints wardens should be aware of when using Tier 1.

### L-001: Observe-Only Default

**What:** All enforcement points default to warn-only mode. Nothing is blocked.

**Why:** Safety-first approach. Wardens can evaluate before enabling blocking.

**To Enable Blocking:** Set `mode = "enforce"` in config.toml or run with `--enforce` flag.

---

### L-002: SLM Requires Ollama

**What:** The SLM (injection detection) requires Ollama to be installed and running.

**Why:** Ollama provides the simplest cross-platform model serving. Native embedding would significantly increase binary size and complexity.

**Fallback:** If Ollama unavailable, heuristic pattern matching is used (less accurate).

**Headless Mode:** Use `--no-slm` flag to disable SLM entirely.

---

### L-003: Single Upstream Provider

**What:** Each aegis instance proxies to one upstream URL.

**Why:** Simplifies routing and evidence chain. Multi-upstream is a mesh concern.

**Workaround:** Run multiple aegis instances on different ports for different providers.

---

### L-004: No Remote Dashboard

**What:** Dashboard only accessible via localhost.

**Why:** Security. Remote access requires authentication (deferred).

**Workaround:** SSH tunnel (`ssh -L 3141:localhost:3141 warden@host`).

---

### L-005: Memory Events May Be Noisy

**What:** ALL memory file changes push to SSE alerts, not just critical ones.

**Why:** Wardens requested full visibility. Can be filtered in dashboard UI later.

**Future:** Add severity filtering to SSE subscription.

---

### L-006: Evidence Chain is Local-Only

**What:** Evidence chain stored in local SQLite. No sync to cluster in Tier 1.

**Why:** Tier 1 is standalone. Cluster sync is Tier 2.

**Impact:** Evidence is lost if disk fails. Wardens should backup `~/.aegis/data/evidence.db`.

---

### L-007: Llama 3.2 1B Accuracy

**What:** Default SLM model (1B) has lower accuracy than 3B.

**Why:** 1B runs on resource-constrained devices (Raspberry Pi). Accessibility over accuracy.

**Recommendation:** Use `llama3.2:3b` for better detection. Set `slm_model = "llama3.2:3b"` in config.

---

## Technical Debt

Shortcuts taken for Tier 1 that should be cleaned up.

### TD-001: Hardcoded Holster Presets

**What:** Holster presets (cautious/balanced/permissive) are hardcoded in Rust.

**Should Be:** Loadable from config file for warden customization.

**Impact:** Wardens cannot tune thresholds without code changes.

**Effort:** 2 hours

---

### TD-002: Dashboard HTML in Rust String

**What:** Dashboard HTML/CSS/JS embedded as string literals in `assets.rs`.

**Should Be:** Separate files, bundled at build time.

**Impact:** Hard to edit dashboard, no syntax highlighting, no minification. Growing larger with traffic inspector tab.

**Effort:** 4 hours

---

### TD-003: No Graceful Shutdown Coordination

**What:** Background tasks (memory monitor, barrier watcher) not coordinated on shutdown.

**Should Be:** CancellationToken propagated to all tasks, graceful drain.

**Impact:** Possible receipt loss on Ctrl+C during active request.

**Effort:** 2 hours

---

### TD-004: Fixture Generation Not Automated

**What:** Test fixtures are manually created.

**Should Be:** Record mode in proxy to capture real traffic as fixtures.

**Impact:** Fixtures may drift from real API behavior. Traffic inspector now captures live traffic (in-memory ring buffer, 200 entries) — this could be extended to export fixtures.

**Effort:** 1 day

---

### TD-005: Error Messages Not Structured

**What:** Many error messages are plain strings.

**Should Be:** Structured error types with codes, for programmatic handling.

**Impact:** Hard to parse errors in automation.

**Effort:** 4 hours

---

### TD-006: Snapshot Store Only Captures WorkspaceRoot Files

**What:** `SnapshotStore::load()` only snapshots critical files with `FileScope::WorkspaceRoot` (SOUL.md, AGENTS.md, etc.). Glob-pattern files (`.env*`, `*.memory.md`) and depth-limited files are not snapshotted.

**Should Be:** Enumerate and snapshot all files matching all critical patterns at startup, including glob expansions.

**Impact:** In enforce mode, tampered `.env` or `*.memory.md` files cannot be auto-restored. They still generate alerts and receipts.

**Effort:** 2 hours

---

### TD-007: Snapshot Store is Immutable After Startup

**What:** Snapshots are captured once at startup and never updated. If a warden legitimately evolves a protected file (via `aegis evolve`), the snapshot still holds the original content.

**Should Be:** Evolution flow should update the snapshot to the new known-good state.

**Impact:** After a legitimate evolution, the next tamper detection would restore to the pre-evolution state instead of the evolved state.

**Effort:** 1 hour

---

## Future Ideas (Not Yet Scheduled)

Ideas discussed but not committed to any phase.

### F-001: Browser Extension

Dashboard as browser extension for easier access.

### F-002: Mobile Companion App

Push notifications for critical alerts.

### F-003: Multi-Language CLI

Localized CLI output for non-English wardens.

### F-004: Plugin System

Allow wardens to add custom scanning patterns, hooks.

### F-005: Anomaly Detection (Centaur)

ML-based pattern detection across evidence chain. Per architecture docs, this is Phase 2/3.

### F-006: Swarm Coordination

Multi-bot coordination and shared threat intelligence. Phase 3+.

### F-007: TRUSTMARK Integration

Reputation scoring across the mesh. Phase 2+.

---

## Decision Change Log

Track any changes to these deferrals.

| Date | Item | Change | Reason |
|------|------|--------|--------|
| 2026-03-10 | Initial | Document created | All Tier 1 decisions locked |
| 2026-03-12 | D-005 | Updated: vault redaction implemented for non-streaming | `scanner::redact_text()` replaces detected credentials before forwarding |
| 2026-03-12 | TD-002 | Updated: dashboard growing with traffic inspector tab | 7 tabs now, `assets.rs` increasingly large |
| 2026-03-12 | TD-004 | Updated: traffic inspector captures live traffic | Ring buffer could be extended to fixture export |
| 2026-03-12 | TD-006 | Added: snapshot store for barrier enforce-mode restore | Replaces git-based revert with in-memory snapshots |

---

## Review Schedule

This document should be reviewed:
- After Tier 1 ships (prioritize Phase 2 items)
- Before each phase planning session
- When wardens report pain points that map to deferred items

---

*Maintainer: Update this document when deferrals are resolved or new ones are added.*
