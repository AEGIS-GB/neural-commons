# Request Lifecycle — Full Data Flow

> From HTTP arrival to response return, every entity mutation, every screening layer, every receipt.

This document traces a complete request through the Aegis proxy, documenting every data transformation, entity mutation, and evidence receipt along the way.

## Overview

```
Agent (OpenClaw) ──POST /v1/messages──> aegis-proxy:3141 ──forward──> Upstream LLM
                 <──response/SSE──────  aegis-proxy:3141 <──response──  Upstream LLM
```

The proxy sits on localhost between the agent framework and the LLM provider. In **observe-only** mode (default), it inspects everything but never blocks. In **enforce** mode, it can reject requests that fail screening.

## Complete Request Flow

### Phase 1: Request Arrival

```
HTTP POST arrives at :3141
  |
  v
[1] Body extraction (max 10MB)
    - body_bytes cloned for recording
    - Returns 413 if over limit
  |
  v
[2] Provider detection
    - Anthropic: requires anthropic-version header
    - OpenAI: Authorization: Bearer header
    - Unknown: returns 422
  |
  v
[3] Channel trust resolution
    - Read from per-request req_info.channel_trust
    - Set by plugin via POST /aegis/register-channel (Ed25519 signed)
    - Determines: holster sensitivity, SSRF policy, classifier mode
  |
  v
[4] Rate limiting
    - Token bucket per Ed25519 fingerprint
    - 1000 req/min default, burst 50
    - Fails closed on mutex poison (returns 429 with 60s retry)
```

### Phase 2: Pre-Request Middleware Chain

Hook execution order (established in PR #127):

```
[5] VAULT SCAN (runs first — before evidence recording)
    |
    |  Scans request body for credentials:
    |    - API keys (sk-*, AKIA*, xoxb-*)
    |    - Bearer tokens, JWTs
    |    - PII (SSNs, credit cards, phone numbers)
    |
    |  If credentials found:
    |    + VaultDetection receipt APPENDED to evidence chain
    |    + SSE alert SENT to dashboard
    |    + If webhook_url configured: POST alert to webhook
    |    (vault_block is ALWAYS enforced — not configurable)
    |
    v
[6] EVIDENCE RECORDING (request direction)
    |
    |  Creates ApiCall receipt with:
    |    - body_hash: SHA-256 of the body AFTER any stripping (PR #157)
    |    - body_size, method, path
    |    - Blinding nonce (32 random bytes)
    |    - Ed25519 signature over canonical JSON
    |
    |  Chain state mutated:
    |    + chain_state.head_seq INCREMENTED
    |    + chain_state.head_hash = hash(prev_hash || receipt)
    |    + SQLite WAL APPENDED
    |
    v
[7] BARRIER CHECK (write protection)
    |
    |  Layer 3a: Does the request PATH match a protected file?
    |    - SOUL.md, AGENTS.md, IDENTITY.md, MEMORY.md, .env, etc.
    |    - If yes in enforce mode: returns 403
    |    - Fails closed on lock poison (PR #146)
    |
    |  Layer 3b: Does the request BODY reference protected filenames?
    |    - Case-insensitive scan (pre-computed uppercase, PR #140)
    |    - Warn only — body references are normal (agent's own SOUL.md)
    |
    |  If triggered:
    |    + WriteBarrier receipt APPENDED
    |    + SSE alert SENT
    |
    v
[8] SLM SCREENING (4-layer injection detection)
    |
    |  See "The 4-Layer Screening Pipeline" section below
    |
    |  If blocked (enforce mode):
    |    - Returns 403 with reason
    |  If flagged (observe mode):
    |    - Logged, receipt recorded, request proceeds
    |
    v
[9] BODY MODIFICATION (pre-forwarding)
    |
    |  [9a] Strip privileged roles (trust-based)
    |    - Removes system messages from untrusted channels
    |    - body_hash RECOMPUTED after stripping (PR #157)
    |
    |  [9b] Metaprompt injection (Layer 4, if enabled)
    |    - 7 security rules prepended to system message
    |    - Default: ON (changed in PR #128)
    |    - Format-agnostic (works with any provider)
```

### Phase 3: Upstream Forwarding

```
[10] FORWARD TO LLM PROVIDER
     |
     |  Rebuilt request forwarded to:
     |    - api.anthropic.com (Anthropic)
     |    - api.openai.com (OpenAI)
     |    - localhost:11434 (Ollama/local)
     |
     |  Provider detected by host-based matching (PR #138)
     |  5-minute timeout for long LLM responses
```

### Phase 4: Response Processing

```
[11] RESPONSE ARRIVES
     |
     |  Detect response type:
     |    - SSE streaming (content-type: text/event-stream)
     |    - JSON buffered (everything else)
     |
     v
[12] VAULT SCAN (response direction)
     |
     |  Scans response body for credentials leaked by LLM
     |  Same scanner as request direction
     |
     |  Streaming: scans accumulated text at chunk boundaries + final
     |  Buffered: scans complete response body
     |
     |  If found:
     |    + VaultDetection receipt APPENDED
     |    + Credentials redacted from response
     |
     v
[13] DLP / PII SCREENING (response)
     |
     |  NER-based screening for:
     |    - Personal names, addresses, phone numbers
     |    - Medical records (PHI), financial data
     |    - Agent system prompts, identity leaks
     |    - Tool call results with sensitive paths
     |
     |  Trust-level dependent:
     |    - Full: log only
     |    - Trusted: redact PII
     |    - Public/Unknown: redact + block tool results
     |
     v
[14] EVIDENCE RECORDING (response direction)
     |
     |  Creates second ApiCall receipt with:
     |    - Response status, body_size, duration_ms
     |    - Response body hash
     |
     |  Chain state mutated (same as step 6)
     |
     v
[15] TRAFFIC RECORDING (dashboard)
     |
     |  Ring buffer entry (200 max, 32KB body cap)
     |  Includes: request, response, SLM verdict, DLP result
     |  Deduplicated via handler_recorded flag
     |
     v
[16] DEFERRED SLM UPDATE (trusted channels only)
     |
     |  If deep SLM was deferred (step 8, trusted channel):
     |    - Async task runs after response is sent
     |    - Updates traffic entry with final verdict
     |    - Does NOT block the response
     |
     v
[17] RESPONSE RETURNED TO AGENT
```

## The 4-Layer Screening Pipeline

The SLM screening (step 8) is split into **fast layers** and a **deep layer** for latency optimization:

### Architecture

```
                    FAST LAYERS (<15ms)                    DEEP LAYER (2-3s)
               ┌─────────────────────────┐          ┌─────────────────────────┐
               │                         │          │                         │
    Content ──>│ Layer 1: HEURISTIC      │──clean──>│ Layer 3: SLM            │
               │   14 regex patterns     │          │   Qwen3 30B via Ollama  │
               │   <1ms                  │          │   Structured JSON output│
               │                         │          │   2-3 seconds           │
               │ Layer 2: CLASSIFIER     │          │                         │
               │   ProtectAI DeBERTa-v2  │          └────────────┬────────────┘
               │   ONNX, ~5-15ms         │                       │
               │   Binary: inject/benign │                       │
               └────────────┬────────────┘                       │
                            │                                    │
                       threat found?                        threat found?
                            │                                    │
                            v                                    v
                    ┌───────────────┐                    ┌───────────────┐
                    │   SCORING     │                    │   SCORING     │
                    │ (deterministic│                    │ (deterministic│
                    │  severity     │                    │  severity     │
                    │  lookup)      │                    │  lookup)      │
                    └───────┬───────┘                    └───────┬───────┘
                            │                                    │
                            v                                    v
                    ┌───────────────┐                    ┌───────────────┐
                    │   HOLSTER     │                    │   HOLSTER     │
                    │ (private      │                    │ (private      │
                    │  threshold)   │                    │  threshold)   │
                    └───────┬───────┘                    └───────┬───────┘
                            │                                    │
                            v                                    v
                     Admit/Quarantine/                    Admit/Quarantine/
                     Reject                              Reject

Layer 4: METAPROMPT HARDENING (separate from screening)
   Injected into system message before forwarding — not a detection layer.
   7 security rules instructing upstream LLM to resist attacks.
```

### Layer Details

| Layer | Engine | Latency | What It Does | When It Runs |
|-------|--------|---------|--------------|--------------|
| **1. Heuristic** | `HeuristicEngine` (regex) | <1ms | 14 pattern families: `system_override`, `role_hijack`, `context_smuggle`, `instruction_inject`, `boundary_probe`, `encoding_abuse`, `chain_of_thought_hijack`, `tool_misuse`, `data_exfil`, `persistence_attempt`, `multi_turn_manipulation`, `social_engineering`, `memory_poisoning`, `capability_escalation`. Also decodes ROT13/base64/hex before scanning. | Always (if `fallback_to_heuristics` enabled) |
| **2. Classifier** | `PromptGuardEngine` (ONNX DeBERTa-v2) | ~5-15ms | Binary classification: injection probability 0.0-1.0. Quarantines if prob > 0.5. For trusted channels, runs in advisory mode (logs but doesn't block, passes advisory to deep layer). | When ONNX model is loaded |
| **3. SLM Deep** | Ollama/OpenAI-compat/Anthropic | 2-3s | Sends structured prompt to local 30B model (Qwen3 recommended). Returns JSON annotations: `[{pattern, excerpt, explanation}]`. Only runs if Layers 1+2 found nothing. | Conditional (see scheduling below) |
| **4. Metaprompt** | None (text injection) | 0ms | 7 security rules prepended to system message. Not a detection layer. | Always (if `metaprompt_hardening` enabled, default: true) |

### Trust-Based Scheduling

The **deep layer** (Layer 3) timing depends on channel trust level:

| Trust Level | Fast Layers | Deep Layer | Rationale |
|-------------|-------------|------------|-----------|
| **Full** (owner) | Run, advisory only | Deferred (after response) | Trusted channels never block; avoid GPU contention |
| **Trusted** | Run, advisory only | Deferred (after response) | Same as Full |
| **Public** | Run, blocking | Sequential (before forward) | May need to block; must have verdict first |
| **Unknown** | Run, blocking | Sequential (before forward) | Default — strictest screening |
| **Restricted** | Run, blocking | Sequential (before forward) | Explicitly restricted |

### The 3-Stage Decision Pipeline (D4)

Each detection layer produces raw output that flows through:

1. **Detection** (qualitative) — the engine says "I found pattern X at excerpt Y"
2. **Scoring** (deterministic) — `enrich()` converts annotations to `threat_score` using fixed severity lookup tables. Compound bonus for >=3 patterns. All scores in integer basis points (0-10000).
3. **Holster** (private decision) — `apply_holster()` compares score against trust-level-adjusted threshold. Produces: Admit / Quarantine / Reject.

This separation ensures a compromised SLM cannot bypass scoring — it can only produce annotations, not decisions.

## Entity Mutation Map

### Entities Mutated Per Request

| Entity | When | Mutation | Paths |
|--------|------|----------|-------|
| **Evidence Chain** | Steps 5,6,7,8,12,14 | Receipt appended, chain_state updated | Single path via `record_receipt()` helper |
| **Rate Limiter** | Step 4 | Token consumed from per-identity bucket | 1 path |
| **Request Body** | Step 9 | Stripped/metaprompt injected | 2 optional paths |
| **Response Body** | Steps 12,13 | Vault redaction, DLP redaction | 2 sequential paths |
| **Traffic Record** | Step 15 | Ring buffer entry | 3 mutually exclusive paths (deduplicated) |
| **Channel Registry** | Plugin hook | Entry added/updated | Via POST /aegis/register-channel |
| **SLM Verdict** | Step 8 | Created by fast or deep layer | Trust stamped once at convergence (PR #158) |

### Evidence Receipts Per Request Cycle

| Receipt Type | Min | Max | Created By |
|---|---|---|---|
| `ApiCall` | 2 | 2 | EvidenceHook (request + response) |
| `VaultDetection` | 0 | 3 | VaultHook (request + response buffered + streaming) |
| `WriteBarrier` | 0 | 1 | BarrierHook (if protected path/file referenced) |
| `SlmAnalysis` | 0 | 2 | SlmHook (fast layer + deep layer) |
| **Total** | **2** | **8** | |

Each receipt is:
- Hash-chained (SHA-256 linking to previous receipt)
- Ed25519 signed
- Appended to SQLite (WAL mode, append-only)
- Immutable after creation

### Background Processes (Independent of Request)

| Process | Interval | Entity Mutated | Receipt Type |
|---------|----------|----------------|--------------|
| Filesystem watcher | Real-time (inotify) | HashRegistry | WriteBarrier |
| Periodic hash sweep | 60s | HashRegistry | WriteBarrier |
| Memory monitor | Periodic | Evidence chain | MemoryIntegrity |
| Automatic rollup | 60s check | Evidence chain | MerkleRollup |
| SQLite integrity check | Startup | None (read-only) | None |

## Concurrency Model

### Lock Ordering

The evidence recorder enforces strict lock ordering to prevent deadlock:

```
1. chain_state   (acquired first)
2. store         (acquired second)
3. last_rollup_seq (acquired third)
```

All methods (`record()`, `rollup()`, `export()`, `verify_chain()`) follow this order.

### Fail-Closed Behavior

All mutex-protected security components fail closed on lock poisoning:
- **Rate limiter**: Returns 429 with 60s retry-after
- **Nonce registry**: Rejects the request (returns false)
- **Barrier hooks**: Returns `Block("barrier lock poisoned")`

### Per-Request Isolation

- Channel trust context is per-request (via `req_info.channel_trust`), not global
- SLM verdicts are per-request (trust stamped once at path convergence)
- Rate limiting is per-identity (Ed25519 fingerprint), not per-connection

## Configuration Reference

| Config Key | Default | Effect on Flow |
|---|---|---|
| `mode` | `observe_only` | observe: log only. enforce: can block. pass_through: skip all. |
| `metaprompt_hardening` | `true` | Layer 4 security rules in system message |
| `slm.engine` | `ollama` | Which SLM engine for Layer 3 |
| `slm.fallback_to_heuristics` | `true` | Enable Layer 1 regex pre-filter |
| `slm.prompt_guard_model_dir` | None | Enable Layer 2 ONNX classifier |
| `slm.slm_timeout_secs` | 15 | Deep SLM timeout before quarantine |
| `rate_limit_per_minute` | 1000 | Per-identity rate limit |
| `webhook_url` | None | POST critical alerts to external URL |
