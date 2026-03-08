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

## Tech Stack Summary

| Component | Technology | Notes |
|-----------|-----------|-------|
| Adapter transport | HTTPS + WSS to Edge Gateway | D3 v2 — no NATS dependency on client. Standard reqwest + tokio-tungstenite. NATS internal only. |
| Internal messaging | NATS JetStream (all 5 nodes) | Async fan-out, persistence, subject ACLs. Used for evidence, TRUSTMARK, Botawiki pipeline, mesh, Centaur scheduling, broadcast. NOT used for synchronous embedding paths (load balancer instead). |
