# Neural Commons — System Architecture

## Cluster Node Layout (D35)

```mermaid
graph TB
  subgraph "Node 1 — NATS Primary + Evidence + Embedding A"
    N1_NATS[NATS JetStream Primary]
    N1_EVID[Evidence Ingestion — Rust]
    N1_PG[(PostgreSQL Primary)]
    N1_EMB[Embedding Service A — GPU A]
  end

  subgraph "Node 2 — Gateway + TRUSTMARK + Centaur B"
    N2_NATS[NATS JetStream Secondary]
    N2_GW[Edge Gateway — Rust]
    N2_TM[TRUSTMARK Engine — Rust]
    N2_PG[(PostgreSQL Replica)]
    N2_CENT[Centaur B — llama.cpp]
  end

  subgraph "Node 3 — Botawiki + RAG + Embedding B"
    N3_NATS[NATS JetStream Tertiary]
    N3_BW[Botawiki Service — Rust]
    N3_MESH[Mesh Relay — Rust]
    N3_RAG[RAG Service — Rust]
    N3_PG[(PostgreSQL + pgvector)]
    N3_EMB[Embedding Service B — GPU B]
  end

  subgraph "Node 4 — Centaur Primary + Scheduler"
    N4_CENT[Centaur Primary — llama.cpp]
    N4_SCHED[GPU Scheduler — Rust]
  end

  subgraph "Node 5 — Centaur Failover + MinIO"
    N5_CENT[Centaur Failover — llama.cpp]
    N5_MINIO[(MinIO — dead-drop storage 10TB)]
  end

  N1_NATS <-->|Raft| N2_NATS
  N2_NATS <-->|Raft| N3_NATS
  N2_GW -->|load balancer| N1_EMB
  N2_GW -->|load balancer| N3_EMB
  N3_RAG -->|local call| N3_EMB
  N3_RAG -->|local search| N3_PG

  style N2_CENT fill:#78350f,color:#fbbf24
  style N4_CENT fill:#78350f,color:#fbbf24
  style N5_CENT fill:#78350f,color:#fbbf24
  style N1_EMB  fill:#14532d,color:#4ade80
  style N3_EMB  fill:#14532d,color:#4ade80
  style N2_GW   fill:#1e3a5f,color:#60a5fa
```

## NATS Topic Topology (D3 v3)

| Stream | Subjects | Publishers | Subscribers | Retention | Note |
|---|---|---|---|---|---|
| EVIDENCE | evidence.new, evidence.rollup | Evidence Ingestion | TRUSTMARK Engine, archiver | File, 30 days | |
| TRUSTMARK | trustmark.updated | TRUSTMARK Engine | Gateway cache, tier-gate | File, 7 days | |
| BOTAWIKI | botawiki.claim.new, botawiki.quarantine.vote, botawiki.dispute.new, botawiki.embed | Botawiki Service | quarantine-validator, dispute-handler, embed-indexer | File, 90 days | botawiki.embed is the async background indexing subject — Embedding Service Node 3 consumes it |
| MESH | mesh.relay, mesh.key.update | Mesh Relay | mesh-router, key-directory | Memory, 72h | Dead-drops go to MinIO (Node 5), not this stream |
| SCHEDULER | scheduler.request, scheduler.assigned, scheduler.heartbeat, scheduler.completed | GPU Scheduler | Centaur nodes (2, 4, 5) | Memory, WorkQueue | Option B: Centaur only. Direct embedding uses Gateway load balancer — NOT this stream. Option C: embedding added here when Nodes 1+3 also run Centaur. |
| BROADCAST | broadcast.emergency, broadcast.policy | Policy Distribution | All connected adapters via Gateway WSS | File, 365 days | |

### Embedding Routing — Three Scenarios (D3 v3 + D35)

| Scenario | Transport | NATS? | Latency | Rate limit ticks? |
|---|---|---|---|---|
| RAG — embed the question | Local call, Node 3 in-process | No | ~2ms | No (internal) |
| POST /embedding from bot | Gateway load balancer → Node 1 or 3 | No | ~15ms | Yes — embedding counter +1 |
| Botawiki write — index claim | NATS async botawiki.embed → Node 3 | Yes | seconds (background) | No (internal) |

Principle: NATS is used only where work is genuinely async. The
load balancer at the Gateway handles direct embedding — round-robin
or least-connections across Nodes 1 and 3.

Option C: when Centaur is added to Nodes 1+3 (escalation config),
the GPU Scheduler is also used for embedding routing. Config change,
not code change.

## Tech Stack Summary

| Component | Technology | Notes |
|-----------|-----------|-------|
| Adapter transport | HTTPS + WSS to Edge Gateway | D3 v2 — no NATS dependency on client. Standard reqwest + tokio-tungstenite. NATS internal only. |
| Internal messaging | NATS JetStream (all 5 nodes) | Async fan-out, persistence, subject ACLs. Used for evidence, TRUSTMARK, Botawiki pipeline, mesh, Centaur scheduling, broadcast. NOT used for synchronous embedding paths (load balancer instead). |
