# Neural Commons — Decision Log

Chronological log of decision amendments and addenda.

---

### D3 v3 Addendum: Internal NATS Scope
**Status: LOCKED (extends v2)**
**Locked:** 2026-03-08

v2 established adapter transport (HTTPS+WSS, no NATS on client).
v3 narrows internal NATS usage after embedding pipeline analysis.

Finding: the GPU Scheduler was over-specified as the router for
direct embedding calls. This introduced NATS into a synchronous
user-facing path where a simple load balancer is sufficient and
significantly simpler to debug.

Three embedding scenarios analysed:

1. RAG query — embed the question before pgvector search
   Transport: local in-process call (Node 3, same process as pgvector)
   NATS: No
   Reason: D35 co-locates RAG Service + Embedding GPU B + pgvector
   on Node 3. Zero network hop. ~2ms. No routing needed.

2. Direct POST /embedding from bot adapter
   Transport: Gateway → HTTP → least-connections load balancer
              → Embedding Service on Node 1 or Node 3
   NATS: No (Option B) / Yes via Scheduler (Option C only)
   Reason: In Option B, Nodes 1+3 are dedicated embedding nodes.
   No GPU-state awareness needed. Round-robin/least-connections
   is sufficient. NATS + Scheduler added async complexity to a
   synchronous path with no benefit in Option B.

3. Botawiki write — background vector indexing
   Transport: NATS async, subject botawiki.embed
   NATS: Yes — correct and intentional
   Reason: Bot is done, has received ACK, has moved on. Embedding
   is a background side effect with no user waiting. Retry on
   failure via JetStream. This is the one genuine async case.

Principle: NATS is correct when work is genuinely async (no user
waiting, retry semantics needed). Direct HTTP + load balancer is
correct when a user is waiting synchronously.

Consequence for D24/D19:
  Rate limit counter and credit counter both tick only at the
  Gateway. Internal calls (RAG local embed, Botawiki async embed)
  never reach the Gateway and are invisible to both systems.
  The double-count problem is structurally eliminated.
