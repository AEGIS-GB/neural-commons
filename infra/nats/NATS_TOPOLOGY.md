# NATS Topology Specification

Phase 0 deliverable. Extended per phase as new topics are added.
Layer 2 tests implement this document.

## JetStream Stream Definitions

### `EVIDENCE` Stream
- **Subjects:** `evidence.new`, `evidence.rollup`
- **Storage:** File (disk persistence)
- **Retention:** Limits (max 10GB, max 30 days)
- **Consumers:**
  - `trustmark-scorer` (push, ack-explicit, max-deliver 3) — triggers TRUSTMARK recalculation
  - `evidence-archiver` (pull, ack-explicit) — periodic batch archival
- **Replicas:** 1 (single-node Phase 0; scale to 3 later)

### `TRUSTMARK` Stream
- **Subjects:** `trustmark.updated`, `trustmark.query`
- **Storage:** File
- **Retention:** Limits (max 1GB, max 7 days — latest score is what matters)
- **Consumers:**
  - `gateway-cache` (push, ack-none) — cache latest scores for rate limiting
  - `tier-gate` (push, ack-explicit, max-deliver 3) — evaluate tier transitions

### `BOTAWIKI` Stream
- **Subjects:** `botawiki.claim.new`, `botawiki.quarantine.vote`, `botawiki.dispute.new`
- **Storage:** File
- **Retention:** Limits (max 5GB, max 90 days)
- **Consumers:**
  - `quarantine-validator` (push, ack-explicit, max-deliver 3) — trigger validation
  - `dispute-handler` (push, ack-explicit, max-deliver 5) — handle disputes

### `MESH` Stream
- **Subjects:** `mesh.relay`, `mesh.key.update`
- **Storage:** Memory (ephemeral — relay messages don't need persistence)
- **Retention:** Limits (max 256MB, max 72h for dead-drop TTL alignment)
- **Consumers:**
  - `mesh-router` (push, ack-none) — fire-and-forget relay
  - `key-directory` (push, ack-explicit, max-deliver 3) — update key directory

### `SCHEDULER` Stream
- **Subjects:** `scheduler.request`, `scheduler.assigned`
- **Storage:** Memory
- **Retention:** WorkQueue (consumed once)
- **Consumers:**
  - `gpu-router` (pull, ack-explicit, max-deliver 1) — assign to GPU node

### `BROADCAST` Stream
- **Subjects:** `broadcast.emergency`, `broadcast.policy`
- **Storage:** File (Foundation messages must persist)
- **Retention:** Limits (max 100MB, max 365 days)
- **Consumers:**
  - `broadcast-relay` (push, ack-explicit, max-deliver 10) — ensure delivery to all nodes
  - `adapter-poller` (pull, ack-explicit) — adapters pull on connect

## Failure/Recovery Behavior

### Subscriber crash
- Push consumers with ack-explicit: unacked messages redelivered after ack-wait (30s default)
- max-deliver prevents infinite redelivery loops
- Dead letter: after max-deliver exhausted, message logged and dropped

### NATS restart
- File-backed streams: full recovery from disk
- Memory-backed streams: messages lost (acceptable for ephemeral relay/scheduler)
- JetStream leader election: N/A for single-node (relevant when scaling to 3)

### Message replay
- New consumers can replay from stream start or specific sequence
- Trustmark consumers replay from last acked sequence on restart
- Evidence consumers replay from last committed rollup sequence

## Topic Hierarchy (D3)

```
evidence.new              — new receipt submitted
evidence.rollup           — Merkle rollup computed
trustmark.updated         — TRUSTMARK score recalculated
trustmark.query           — request TRUSTMARK for a bot
botawiki.claim.new        — new claim submitted
botawiki.quarantine.vote  — validator vote on quarantined claim
botawiki.dispute.new      — dispute filed against a claim
mesh.relay                — mesh message relay
mesh.key.update           — key rotation broadcast
scheduler.request         — GPU compute request
scheduler.assigned        — GPU compute assigned
broadcast.emergency       — Foundation emergency broadcast
broadcast.policy          — Foundation policy distribution
```

## Phase Extensions

| Phase | New Topics | New Streams |
|-------|-----------|-------------|
| 0 | evidence.*, trustmark.* | EVIDENCE, TRUSTMARK |
| 1 | (adapter-only, no NATS) | — |
| 2 | botawiki.claim.new, broadcast.* | BOTAWIKI, BROADCAST |
| 3 | mesh.*, botawiki.quarantine.*, botawiki.dispute.*, scheduler.* | MESH, SCHEDULER |
| 4 | (no new topics) | — |
