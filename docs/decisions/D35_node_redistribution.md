# D35: Node Service Redistribution — Activate Idle GPUs

**Status:** ✅ ANSWERED
**Phase:** 3 (must be applied before Phase 3 build begins)
**Blocks:** All Phase 3 service deployment configs, D24, D25, D27, D34

---

## What

Redistribute cluster services across all five nodes to activate three idle Radeon 8060S GPUs (Nodes 1, 2, 3) that the original architecture left unused. Move the Edge Gateway from Node 5 to Node 2, split embedding into a two-GPU pool on Nodes 1 and 3, dedicate Nodes 4 and 5 entirely to Centaur, and migrate dead-drop storage from NATS JetStream to MinIO.

---

## Why It Matters

During D24 (Edge Gateway Rate Limits) hardware simulation, analysis revealed that the original node layout created three compounding problems:

**Problem 1 — GPU contention on Node 4.**
Embedding and Centaur were co-located on the same Radeon 8060S (40 CU). Every embedding request competed with Centaur for GPU memory, causing KV cache evictions mid-inference. This reduced effective Centaur throughput from theoretical maximum to approximately 0.20 queries/sec (720/hr), far below the hardware ceiling of ~0.54/sec (1,944/hr).

**Problem 2 — Two cross-node hops for RAG queries.**
A RAG query followed the path: Gateway (Node 5) → embedding (Node 4) → pgvector search (Node 3). Each NATS hop added ~8–9ms. Total overhead: ~17ms before the query reached the database. At scale, this compounds across every knowledge query.

**Problem 3 — NATS dead-drop storage limit.**
Dead-drop mesh messages were stored in NATS JetStream `MESH` stream with `max_file: 1GB`. At 1,000 active mesh bots, each sending ~1KB messages at the allowed rate, this storage fills within hours. The NATS memory limit is structural — it cannot be solved by configuration alone.

All three problems are resolved by D35 at zero additional hardware cost. Every node in the cluster already has a Radeon 8060S GPU. The original design simply wasn't using three of them.

---

## Node Assignment: Before and After

| Node | **Old Services** | **New Services** |
|------|-----------------|-----------------|
| Node 1 | NATS Primary, Evidence Ingestion, PG Primary | **SAME + Embedding GPU A** (idle GPU activated) |
| Node 2 | NATS Secondary, TRUSTMARK Engine, PG Replica | **SAME + Edge Gateway** (moved from Node 5) |
| Node 3 | NATS Tertiary, Botawiki, Mesh Relay, PG+pgvector | **SAME + Embedding GPU B** (co-located with pgvector) |
| Node 4 | Centaur Primary, Embedding, GPU Scheduler | **Centaur Primary ONLY + GPU Scheduler** (embedding removed) |
| Node 5 | Edge Gateway, Centaur Failover, MinIO | **Centaur Failover ONLY + MinIO** (Gateway removed) |

---

## RAM Safety Check

All nodes within 128GB limit.

| Node | Services | RAM Usage | Headroom |
|------|---------|-----------|---------|
| Node 1 | PG 30GB + NATS 4GB + Go 1GB + Embedding 0.1GB | ~35GB | 93GB free |
| Node 2 | PG 20GB + NATS 2GB + Go 1GB + Gateway 0.1GB | ~23GB | 105GB free |
| Node 3 | PG 30GB + pgvector HNSW 3GB + NATS 4GB + Go 2GB + Embedding 0.1GB | ~39GB | 89GB free |
| Node 4 | Centaur model 40GB + KV cache up to 80GB + Go 1GB | ~43–120GB dynamic | RAM safe |
| Node 5 | Centaur model 40GB + MinIO 2GB + dead-drop objects ~6GB at 1K bots | ~48GB | 80GB free |

Node 4 is the only node with variable RAM pressure. The KV cache grows with concurrent request load. At 128GB node RAM, and with Centaur as the sole GPU consumer, the cache can expand to ~80GB before the OS is under pressure — sufficient for the T3 bot ceiling defined below.

---

## Centaur Capacity Impact

**Old layout (embedding competing on Node 4):**
- KV cache evictions mid-inference reduced throughput to ~0.20 queries/sec
- Per hour: 0.20 × 3600 = **720 queries/hr**
- At 30 queries/hr per active T3 bot, 60% utilisation: 720 × 0.6 / 30 = **~36 safe active T3 bots**

**New layout (Nodes 4 and 5 dedicated to Centaur):**
- No GPU contention. Centaur achieves near-theoretical throughput: ~0.54 queries/sec
- Per hour: 0.54 × 3600 = **1,944 queries/hr**
- At 30 queries/hr per active T3 bot, 60% utilisation: 1,944 × 0.6 / 30 = **~108 safe active T3 bots**

Capacity improvement: **2.7× — no new hardware required.**

---

## RAG Latency Impact

**Old path:** Gateway (Node 5) → embedding request via NATS → Node 4 (~8ms hop) → pgvector search via NATS → Node 3 (~9ms hop) → result back.
- Total cross-node overhead: ~17ms
- Embedding latency on shared GPU: ~25ms (GPU) or ~150ms (CPU fallback when evicted)
- **Total RAG latency: ~42ms GPU / ~167ms CPU fallback**

**New path:** Gateway (Node 2) → embedding request to GPU B (Node 3, co-located with pgvector) → pgvector search local to Node 3 → result back. Single NATS hop Gateway→Node 3.
- Cross-node overhead: ~8ms (one hop only)
- Embedding latency on dedicated GPU: **~8ms always** (no contention, no fallback path needed)
- **Total RAG latency: ~16ms — no CPU fallback path required**

Latency improvement: **~62% reduction. CPU fallback path eliminated entirely.**

---

## Embedding Pool Architecture

Two dedicated embedding GPUs form a load-balanced pool:

- **GPU A — Node 1:** General embedding requests (direct embedding calls from bots)
- **GPU B — Node 3:** RAG embedding + general overflow (co-located with pgvector)

Routing rules (enforced in GPU Scheduler on Node 4):

1. **Direct embedding calls** (bots requesting embeddings directly): round-robin across GPU A and GPU B
2. **RAG embedding calls** (embedding step in a RAG query): always routed to GPU B on Node 3 — this eliminates the cross-node hop to pgvector entirely
3. **Fallback:** if GPU B is saturated, RAG embedding overflows to GPU A with a single cross-node hop (accepted as exceptional case)

Both GPUs run the same model (`all-MiniLM-L6-v2`, see D34). The pool appears as a single logical embedding endpoint to callers. GPU Scheduler handles the routing decision internally.

---

## Dead-Drop Storage Migration: NATS → MinIO

**Problem:** NATS JetStream `MESH` stream was storing dead-drop messages with a 1GB file limit. At 1,000 mesh bots this fills in hours. NATS is not an object store — it is a message bus. Storing multi-hour-TTL objects in NATS is architectural misuse.

**Solution:** Dead-drop messages are stored as objects in MinIO on Node 5.

- Bucket: `nc-dead-drops`
- Object key: `dead-drop/{recipient_key_id}/{sender_key_id}/{ts_ms}`
- Encryption: AES-256-GCM (same as all MinIO objects in this cluster)
- TTL: 72 hours (matching D25 default) — implemented via MinIO lifecycle rule
- Per-identity quota: 500 objects per recipient (enforced at Gateway)
- Storage capacity: MinIO has 10TB NVMe on Node 5 — the 1GB NATS limit no longer applies

The `MESH` NATS stream becomes a **pure live relay** — ephemeral messages only, no persistence beyond in-flight relay. See `infra/minio/dead_drop_lifecycle.md` for full lifecycle policy.

---

## Influenced Decisions

This decision changes the physical context assumed by several other decisions. Each must note D35 as a prerequisite:

| Decision | What Changes |
|---------|-------------|
| **D24** (Gateway Rate Limits) | Rate limit matrix, safe bot ceilings, and the [`d24_analysis.html`](../visualizations/d24_analysis.html) simulator were all derived assuming the D35 layout (Gateway on Node 2, embedding pool, dedicated Centaur). D35 is a **hard prerequisite** of D24. |
| **D25** (Dead-Drop TTL) | TTL mechanism changes from NATS stream expiry to MinIO object lifecycle policy. The 72h default is unchanged but the implementation is different. |
| **D27** (Centaur Hot-Pin) | Nodes 4 and 5 are now fully dedicated to Centaur with no embedding model competing for GPU memory. The KV cache budget is larger. Hot-pin threshold and node count must be re-evaluated with the new layout. |
| **D34** (Embedding Model Choice) | Embedding service now runs on Nodes 1 and 3, not Node 4. Deployment notes must reflect the two-GPU pool architecture. |
| **[NC_System_Architecture.md](../architecture/NC_System_Architecture.md)** | Cluster diagram and node assignment table updated to reflect D35 layout. |
| **NATS_TOPOLOGY.md** | `MESH` stream updated: dead-drop TTL retention removed, stream is pure live relay, MinIO lifecycle note added. |

---

## Answer: New Node Layout (Locked)

| Node | Services |
|------|---------|
| **Node 1** | NATS Primary, Evidence Ingestion, PG Primary, **Embedding GPU A** |
| **Node 2** | NATS Secondary, TRUSTMARK Engine, PG Replica, **Edge Gateway** |
| **Node 3** | NATS Tertiary, Botawiki, Mesh Relay, PG+pgvector, **Embedding GPU B** |
| **Node 4** | **Centaur Primary**, GPU Scheduler |
| **Node 5** | **Centaur Failover**, MinIO (dead-drop storage) |

Dead-drop storage: **MinIO on Node 5** (not NATS JetStream).
Embedding: **GPU pool — Node 1 (GPU A) + Node 3 (GPU B)**, round-robin for direct calls, always GPU B for RAG.

---

## Developer Checklist — Before Phase 3 Build Begins

These five steps must be completed before any Phase 3 service implementation starts. Node assignments affect where each service's deployment config points.

1. **Update deployment configs.** Every service deployment config that references a node must be updated to the D35 layout. Specifically: move Edge Gateway config from Node 5 → Node 2; move Embedding service config from Node 4 → Nodes 1 and 3; ensure Centaur deployment targets only Nodes 4 and 5.

2. **Implement the embedding pool in GPU Scheduler.** The scheduler (`cluster/scheduler/`) must implement the two-GPU pool routing: round-robin for direct embedding calls, always GPU B (Node 3) for RAG embedding calls. The pool must present a single logical endpoint.

3. **Implement dead-drop storage in MinIO.** The mesh dead-drop implementation (`cluster/mesh/src/dead_drop.rs`) must write to MinIO (`nc-dead-drops` bucket) using the key format `dead-drop/{recipient_key_id}/{sender_key_id}/{ts_ms}`. Remove any NATS JetStream dead-drop writes.

4. **Configure MinIO lifecycle rule.** Apply the 72-hour expiry rule on the `nc-dead-drops` bucket as documented in `infra/minio/dead_drop_lifecycle.md`. Verify the Gateway enforces the 500-object-per-recipient quota before writing.

5. **Update NATS server config.** Remove dead-drop TTL retention from the MESH stream. The stream should retain only the live relay config: Memory storage, small buffer (32MB), no TTL — in-flight messages only. Apply the config in `infra/nats/nats-server.conf`.
