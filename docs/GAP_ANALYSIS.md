# Gap Analysis: Current Implementation vs Target Architecture

> As of v0.12.2 (2026-04-06)

## Executive Summary

The Aegis cluster has **4 working services** (Gateway, Mesh Relay, TRUSTMARK Engine, Botawiki) running in embedded mode from a single binary. The adapter protection pipeline is production-ready with 5-layer screening. The core bot-to-bot relay, trust scoring, and knowledge sharing work end-to-end.

**What's missing:** PostgreSQL persistence, Centaur inference, RAG/semantic search, credit economy, peer-attested TRUSTMARK, MinIO dead-drops, embedding pool, broadcast system, and the operator CLI. All current storage is in-memory with NATS JetStream replay as the only durability layer.

---

## 1. Node-by-Node Gap Analysis

### Node 1: NATS Primary + Evidence Ingestion + PostgreSQL + Embedding A

| Component | Target | Current | Gap |
|-----------|--------|---------|-----|
| NATS JetStream Primary | Raft leader, file-backed | Running, single node (not clustered) | Need 3-node Raft cluster |
| Evidence Ingestion | Rust service, consumes evidence.new, writes PostgreSQL | TRUSTMARK Engine subscribes to evidence.new, stores in-memory | No PostgreSQL, no separate ingestion service |
| PostgreSQL Primary | 30GB RAM, streaming WAL | Not installed | Full gap — need schema, migrations, sqlx integration |
| Embedding Service A | GPU A, all-MiniLM-L6-v2, FastAPI + llama.cpp | Not built | Full gap — no embedding service, no GPU pool |

### Node 2: Gateway + TRUSTMARK Engine + PostgreSQL Replica + Centaur B

| Component | Target | Current | Gap |
|-----------|--------|---------|-----|
| Edge Gateway | Axum, NC-Ed25519, all HTTP/WSS routes | Fully implemented, embedded mode | Done |
| TRUSTMARK Engine | Subscribes evidence.new, recomputes, publishes | Implemented (embedded + standalone) | Done |
| PostgreSQL Replica | 20GB, read-only | Not installed | Full gap |
| Centaur B | llama.cpp, backup inference | Not built | Full gap — no LLM inference service |

### Node 3: Botawiki + Mesh Relay + RAG + pgvector + Embedding B

| Component | Target | Current | Gap |
|-----------|--------|---------|-----|
| Botawiki Service | Claims, quarantine, voting, pgvector search | Claims/voting work, no pgvector | Need semantic search, dispute resolution |
| Mesh Relay | 3-layer screening, trust-weighted routing | Screening works, routing is stub | Need trust-weighted multi-path routing |
| RAG Service | Embed question, pgvector search, retrieve context | Stub (2 lines) | Full gap |
| PostgreSQL + pgvector | 30GB + 3GB HNSW | Not installed | Full gap |
| Embedding Service B | GPU B, RAG + overflow | Not built | Full gap |

### Node 4: Centaur Primary + GPU Scheduler

| Component | Target | Current | Gap |
|-----------|--------|---------|-----|
| Centaur Primary | llama.cpp, Llama 2 70B, KV cache 80GB | Not built | Full gap — using Ollama/LM Studio as substitute |
| GPU Scheduler | Rust, TRUSTMARK priority, credit check, queue cap 50 | Stub (2 lines) | Full gap |

### Node 5: Centaur Failover + MinIO

| Component | Target | Current | Gap |
|-----------|--------|---------|-----|
| Centaur Failover | Hot-pin standby | Not built | Full gap |
| MinIO | 10TB NVMe, AES-256-GCM, 72h TTL dead-drops | Not installed, dead-drops in-memory VecDeque | Full gap |

---

## 2. Service Implementation Status

| Service | Status | What Works | What's Missing |
|---------|--------|------------|----------------|
| **Gateway** | Done | HTTP/WSS, auth, rate limiting, tier gates, NATS bridge, embedded mode | PostgreSQL backend, embedding load balancer |
| **Mesh Relay** | 80% | 3-layer screening, NATS relay, trust-aware cascade | Trust-weighted routing (D21), content sanitization, MinIO dead-drops |
| **TRUSTMARK Engine** | 70% | Evidence→score pipeline, 6 dimensions, warden mode | Peer attestation (#228), mesh mode, PostgreSQL persistence |
| **Botawiki** | 60% | Claim submit, quarantine, voting, adaptive quorum | Dispute resolution, pgvector semantic search, structured read API |
| **Evaluator** | 30% | Basic voting in Gateway evaluator.rs | Accountability (D20), standalone service, evaluator selection |
| **Scheduler** | 0% | Stub | Everything — queue, routing, credit check, NATS integration |
| **RAG** | 0% | Stub | Everything — embedding, pgvector, privacy model |
| **Broadcast** | 0% | Stub | Everything — policy distribution, emergency alerts |
| **Ledger** | 0% | Stub | Everything — credit economy, balance tracking, circuit breaker |
| **Operator CLI** | 0% | Exit stub | Everything — nc status, drain, rotate, backup, broadcast |
| **Common** | 0% | Stub | PostgreSQL pool, NATS helpers, bundle verification |

---

## 3. Persistence Gap (Critical)

**Current state:** Everything is in-memory. NATS JetStream provides replay on restart, but:
- Gateway restart loses all evidence records (replay rebuilds from NATS, but adapter push intervals mean gaps)
- TRUSTMARK scores recomputed on restart (correct, but slow with large evidence sets)
- Botawiki claims survive via NATS replay, but no query index
- Dead-drops are in-memory VecDeque (100 capacity) — lost on restart
- No semantic search (no pgvector)
- No credit balances persist

**Target state:** PostgreSQL on 3 nodes + MinIO for dead-drops + NATS for messaging only.

**Decision needed:** Do we add PostgreSQL now (full target) or use SQLite as an intermediate step for single-node deployments?

**Recommendation:** PostgreSQL. SQLite was considered and rejected earlier (doesn't bring us closer to the end state). For single-node/embedded deployments, run PostgreSQL locally. The sqlx crate handles both single and clustered PostgreSQL identically.

---

## 4. NATS Topology Gap

| Stream | Target | Current | Gap |
|--------|--------|---------|-----|
| EVIDENCE | File, 30 days | Implemented, working | Done |
| TRUSTMARK | File, 7 days | Implemented, working | Done |
| MESH | Memory, 32MB | File, 7 days (overprovisioned) | Should be memory-only per D3 v3 |
| BOTAWIKI | File, 90 days | Shares MESH stream (mesh.> + botawiki.>) | Should be separate stream |
| SCHEDULER | Memory, WorkQueue | Not implemented | Full gap |
| BROADCAST | File, 365 days | Not implemented | Full gap |

**Fix:** Separate BOTAWIKI into its own stream. Change MESH to memory-only. Add SCHEDULER and BROADCAST streams.

---

## 5. Open Issues — Decisions & Relevance

### Issues to CLOSE (already implemented)

| Issue | Title | Status | Action |
|-------|-------|--------|--------|
| #46 | Edge Gateway routes | All routes implemented | Close |
| #47 | TRUSTMARK scoring engine | Full 6-dimension scoring works | Close |
| #50 | NATS bridge for cluster messaging | JetStream with 3 streams | Close |
| #232 | Mesh Relay service extraction | Already closed | Done |
| #231 | Architecture: extract screening to Mesh Relay | Mesh Relay extracted, hybrid model documented | Close |
| #236 | Mesh intelligence: trust API, agent tools | Trust API, relay inbox, OpenClaw tools all work | Close |
| #55 | aegis setup slm | Smart SLM installer with aegis-screen:4b | Close |
| #60 | SLM: decode base64 and normalize Unicode | Heuristic engine decodes ROT13/base64/hex, normalizes leet-speak | Close |
| #239 | KB-enriched screening research | aegis-screen:4b shipped, replaces 30B | Close (research complete) |

### Issues that are PARTIALLY done

| Issue | Title | What's Done | What's Left |
|-------|-------|-------------|-------------|
| #49 | Botawiki read API | GET /botawiki/query and /botawiki/claims/all work | No semantic search (needs pgvector) |
| #53 | Botawiki write path + disputes | Write + quarantine + voting work | Disputes not implemented |
| #48 | Evaluator system | Basic 2/3 voting in Gateway | Standalone service, accountability (D20), evaluator selection |
| #103 | Dynamic TRUSTMARK → channel trust | TRUSTMARK health circuit breaker works | Wire screening pipeline scores into channel trust dynamically |
| #228 | Peer-attested TRUSTMARK | Design documented | No implementation — need peer observation protocol |

### Issues that are FUTURE work (not started)

| Issue | Title | Priority | Depends On |
|-------|-------|----------|------------|
| #54 | Foundation broadcast system | Medium | BROADCAST NATS stream |
| #51 | Centaur anomaly detection | Low | Centaur service (Nodes 4-5) |
| #52 | Swarm coordination | Low | Multiple adapters + relay |
| #233 | Broadcast policy distribution | Medium | Broadcast service |
| #76 | CVE advisory feed | Low | Broadcast + screening integration |
| #56 | Standalone SLM (bundle ONNX) | Low | aegis-screen:4b solves this differently |
| #119 | GLiNER NER for semantic PII | Medium | Better NER model evaluation |
| #105 | Cross-agent receipt verification | Medium | Peer attestation (#228) |

### Issues that are RESEARCH / NICE-TO-HAVE

| Issue | Title | Decision |
|-------|-------|----------|
| #106 | Benchmark: local vs cloud LLMs | Informational, no code needed |
| #82 | OpenClaw CVE attack simulation | Already done (26/26 caught), keep open for regression |
| #74 | Benchmark: proxy performance impact | Should be done but not blocking |
| #107 | Red-team identity file verification | Audit task |
| #110 | Time-delayed activation pattern | Research — future screening improvement |
| #104 | Response-side behavioral analysis | Research — future detection layer |
| #112 | Per-request channel identification | Partially done (pipeline state), close or update |

### Issues to CLOSE as WON'T DO or SUPERSEDED

| Issue | Title | Reason |
|-------|-------|--------|
| #56 | Standalone SLM — bundle ONNX | Superseded by aegis-screen:4b via Ollama |
| #58 | SLM per-model profiles | Partially done (engine profiles exist), low value remaining |
| #117 | PT Summary v0.3.0→v0.5.1 | Historical, already resolved |
| #218 | v0.7.0 cluster layer complete | Milestone tracking, already past v0.12 |

### Technical debt issues (adapter-side)

| Issue | Title | Priority | Decision |
|-------|-------|----------|----------|
| #37 | Load holster presets from config | Low | Nice-to-have, current defaults work |
| #36 | Graceful shutdown coordination | Medium | Should fix — clean NATS disconnect |
| #38 | Snapshot store for glob-pattern files | Low | Deferred |
| #39 | Update snapshots after file evolution | Low | Deferred |
| #40 | Vault scanning for SSE/streamed responses | Medium | Real gap — streaming responses bypass vault |
| #41 | Structured error codes | Low | Nice-to-have |
| #42 | Extract dashboard HTML/JS from string literals | Low | Code quality |
| #43 | Binary signature verification | Medium | Security feature |
| #44 | WebSocket proxy support | Medium | Real gap — WS traffic not proxied |
| #45 | Dashboard authentication | Low | Auth token exists, basic auth works |

---

## 6. Implementation Plan — Path to Target Architecture

### Phase 4: PostgreSQL Persistence (estimated: 2-3 sessions)

**Goal:** Replace all in-memory stores with PostgreSQL. Single-node first, then replication.

1. Add `sqlx` PostgreSQL pool to `cluster/common/src/db.rs`
2. Create migration files for: evidence_receipts, trustmark_scores, botawiki_claims, mesh_dead_drops, rate_limit_buckets
3. Implement `PostgresStore` for `EvidenceStore` trait (replace MemoryStore)
4. Implement PostgreSQL-backed BotawikiStore
5. Implement PostgreSQL-backed DeadDropStore
6. Implement PostgreSQL-backed TrustmarkCache
7. Gateway config: `database_url = "postgres://..."` — falls back to in-memory if not set
8. Run migrations on startup (sqlx::migrate!)
9. Tests: all existing tests pass with both in-memory and PostgreSQL backends
10. Docker Compose: add PostgreSQL to `infra/docker-compose.yml`

### Phase 5: pgvector + Semantic Search (estimated: 1-2 sessions)

**Goal:** Botawiki semantic search via pgvector embeddings.

1. Add pgvector extension to PostgreSQL
2. Implement `POST /botawiki/claim` → compute embedding → store with vector
3. Implement `GET /botawiki/query` with semantic similarity search
4. Embedding: use all-MiniLM-L6-v2 ONNX (384 dimensions)
5. HNSW index on `botawiki_claims.embedding`
6. Async indexing via `botawiki.embed` NATS subject

### Phase 6: MinIO Dead-Drops (estimated: 1 session)

**Goal:** Replace in-memory dead-drop VecDeque with MinIO object storage.

1. Add MinIO client (aws-sdk-s3 or minio-rs)
2. Implement MinIO-backed DeadDropStore
3. Object key: `dead-drop/{recipient}/{sender}/{ts_ms}`
4. AES-256-GCM encryption at rest
5. 72h TTL via MinIO lifecycle rule
6. 500 objects per recipient quota
7. Docker Compose: add MinIO to infra/

### Phase 7: Credit Economy + Ledger (estimated: 1-2 sessions)

**Goal:** Implement the credit system (D19).

1. Implement `cluster/ledger/` — balance tracking, credit/debit
2. PostgreSQL table: `credit_balances(bot_id, balance, last_updated)`
3. Credit check at Gateway before Centaur/RAG/embedding requests
4. 402 response on insufficient credits
5. Earning: Botawiki canonical (+10), validation (+5), relay (+0.1/KB)
6. Spending: Centaur (-10), RAG (-5), embedding (-1)
7. Zero-balance circuit breaker

### Phase 8: Peer-Attested TRUSTMARK (estimated: 2-3 sessions)

**Goal:** Replace self-reported scores with peer observations (Issue #228).

1. Design peer observation protocol (signed attestations)
2. Implement observation collection via relay
3. Implement cross-bot score corroboration
4. Switch from warden mode (self-attested) to mesh mode (peer-verified)
5. Evaluator accountability (D20): penalize evaluators if admittees misbehave

### Phase 9: Centaur + GPU Scheduler (estimated: 2-3 sessions)

**Goal:** LLM inference service for Tier 3 bots.

1. Implement `cluster/scheduler/` — NATS WorkQueue, TRUSTMARK priority, credit check
2. Implement Centaur wrapper around llama.cpp server
3. Queue cap: 50 concurrent, 503 on overflow
4. Hot-pin logic: >50 daily queries → keep model loaded
5. Failover: Node 4 primary, Node 5 backup

### Phase 10: RAG + Embedding Pool (estimated: 2 sessions)

**Goal:** Semantic search pipeline with GPU-accelerated embeddings.

1. Implement `cluster/rag/` — embed question → pgvector search → retrieve
2. Implement embedding pool — Gateway load-balances across GPU A (N1) + GPU B (N3)
3. Direct embedding: HTTP, round-robin
4. RAG embedding: local call on N3
5. Botawiki async: NATS botawiki.embed

### Phase 11: Broadcast + Operator CLI (estimated: 1 session)

**Goal:** Network-wide policy distribution and admin tools.

1. Implement `cluster/broadcast/` — NATS broadcast.*, Ed25519 signed
2. Implement `nc` operator CLI — status, drain, rotate, backup
3. BROADCAST NATS stream (file, 365-day retention)

---

## 7. Priority Order (what to build next)

| Priority | Phase | Rationale |
|----------|-------|-----------|
| **P0** | Phase 4: PostgreSQL | All data is volatile — one restart loses everything. This is the biggest operational risk. |
| **P1** | Phase 6: MinIO dead-drops | Dead-drops are capped at 100 in-memory. Offline bots lose messages on Gateway restart. |
| **P2** | Phase 5: pgvector | Botawiki is useless without search. Bots can submit claims but nobody can find them. |
| **P3** | Phase 7: Credit economy | No cost control — any Tier 3 bot can spam Centaur/RAG indefinitely. |
| **P4** | Phase 8: Peer attestation | TRUSTMARK is self-reported — a bot can lie about its own health. |
| **P5** | Phase 9: Centaur | Currently using Ollama as substitute. Real Centaur needs dedicated GPU nodes. |
| **P6** | Phase 10: RAG + embedding | Depends on pgvector (Phase 5) and GPU hardware. |
| **P7** | Phase 11: Broadcast + operator | Nice-to-have, not blocking core functionality. |

---

## 8. Decisions Needed

### D-PENDING-1: PostgreSQL vs SQLite for single-node

**Question:** For embedded mode (single machine), should we use PostgreSQL or SQLite?

**Recommendation:** PostgreSQL. SQLite was rejected earlier because it doesn't bring us closer to the distributed target. PostgreSQL works identically in single-node and clustered modes. Use Docker for local PostgreSQL (`docker run -d postgres:16`).

### D-PENDING-2: Embedding model for pgvector

**Question:** Which embedding model for Botawiki semantic search?

**Options:**
- all-MiniLM-L6-v2 (384 dims, fast, standard)
- nomic-embed-text (768 dims, better quality)
- BGE-small-en (384 dims, good quality/speed tradeoff)

**Recommendation:** all-MiniLM-L6-v2 — already specified in architecture docs, 384 dimensions, ONNX available, fast CPU inference. No GPU needed for embeddings at our scale.

### D-PENDING-3: Centaur model

**Question:** The architecture says Llama 2 70B but that's outdated. What model for Centaur?

**Recommendation:** This decision can be deferred until Phase 9. The Centaur wrapper is model-agnostic (llama.cpp serves any GGUF). Current substitute: aegis-screen:4b via Ollama works for screening. Centaur is for bot-to-bot reasoning, not screening.

### D-PENDING-4: NATS clustering timeline

**Question:** When do we go from single NATS node to 3-node Raft cluster?

**Recommendation:** Not until we have 3 physical nodes. Single NATS with JetStream file storage is sufficient for development and single-machine production. NATS clustering is a deployment concern, not a code concern.

### D-PENDING-5: Close stale issues

**Decision:** Close the 9 issues identified as "already implemented" above. Update 5 partially-done issues with current status. Close 4 superseded issues.
