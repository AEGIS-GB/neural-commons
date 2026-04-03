# Aegis Roadmap

> Current release: **v0.7.1** (Cluster Layer + GDPR/NIST DLP)
> Tracking: [GitHub Milestones](https://github.com/AEGIS-GB/neural-commons/milestones)

## What's Shipped

### v0.7.1 — GDPR/NIST-Compliant DLP
- DistilBERT-NER ONNX model for PII detection in responses
- Context-aware: skips dates, city names without addresses, version numbers
- Trust-level controls: log-only, redact, or block
- GDPR Article 9 + NIST SP 800-188 alignment

### v0.7.0 — Cluster Layer (21 PRs, 28 pen tests)
- **Edge Gateway** — axum server, NC-Ed25519 auth, health endpoint, graceful shutdown
- **NATS Bridge** — evidence publishing, TRUSTMARK recomputation, cache subscriptions
- **Adapter → Gateway Client** — evidence batch push, WSS connection, challenge-response auth
- **Mesh Relay** — trust-weighted routing (TRUSTMARK ≥ 0.3), SLM screening on relay content
- **Dead-Drops** — offline message storage (72h TTL, 500/identity quota)
- **Botawiki** — claim submission, quarantine, 2/3 validator quorum, canonical status
- **Evaluator** — Tier 3 admission, 2/3 evaluator quorum, chain verification
- **Security** — replay protection, per-tier rate limiting, 28 penetration tests

### v0.5.x–v0.6.x — TRUSTMARK + Pipeline + CLI
- **TRUSTMARK as Health Monitor** — 6-dimension scoring, 90-day temporal decay, health circuit breaker, warden mode, per-dimension alerts, auto-tighten holster
- **PipelineState** — UUID v7 request_id linking TrafficEntry ↔ Receipt(s), full lifecycle tracking
- **DLP Location Tagging** — findings tagged as message_content, tool_call, or api_protocol
- **CLI Trace Overhaul** — `aegis trace --watch` (live like top), rich detail view, per-layer breakdown, threat dimension bars, --section and --json flags
- **Dashboard** — TRUSTMARK gauge, receipts panel linked by request_id, DLP location column

### v0.2.x–v0.4.x — Local Adapter (Tier 1)
- **5-layer screening pipeline** — heuristic + ProtectAI classifier + SLM + NER + metaprompt
- **Evidence chain** — SHA-256 hash-linked, Ed25519 signed, append-only SQLite WAL
- **Credential vault** — AES-256-GCM, HKDF-SHA256, request + response scanning
- **Write barrier** — filesystem watcher, snapshot-based restore, triple-layer detection
- **Memory monitor** — change detection, SSE push
- **Channel trust** — Ed25519 signed certificates, trust-based screening policy
- **Dashboard** — 9-tab web UI, SSE alert stream
- **OpenClaw plugin** — auto-register channel context with signed payloads
- **CLI** — setup, scan, vault, export, trust, slm management
- **CI/CD** — auto-release, cross-platform builds, SHA-256 checksums
- **30 security/design fixes** — key zeroization, RFC 8785 UTF-16 sorting, fail-closed on lock poison, atomic snapshot restore, config validation, deadlock fix

---

## What's Next

### v0.8.0 — JetStream Persistence + Peer Attestation Foundation

| Priority | What | Why |
|----------|------|-----|
| **P0** | NATS JetStream durable streams | Mesh state survives Gateway restart |
| **P0** | Relay log with screening detail | Quarantine reasons visible in dashboard + CLI |
| **P1** | Peer attestation model (Issue #228) | TRUSTMARK from peer observations, not self-reporting |
| **P1** | Stream replay on startup | Gateway rebuilds Botawiki/relay state from NATS |
| **P2** | Cross-node chain verification | Nodes verify each other's event chains |

### v0.8.1 — Persistence + E2E Integration

| Priority | What | Why |
|----------|------|-----|
| **P0** | PostgreSQL persistence for Gateway | Replace in-memory stores (EvidenceStore, BotawikiStore, EvaluatorService) |
| **P0** | MinIO dead-drop storage | Replace in-memory dead-drops |
| **P0** | Real two-bot E2E integration test | Gateway + NATS + two adapters, full message flow |
| **P1** | NER false positive reduction | Improve model confidence thresholds on API metadata |
| **P1** | Evaluator accountability (D20) | Evaluators must stake reputation when vouching |
| **P2** | Botawiki semantic search (pgvector) | Vector similarity for knowledge queries |

### v0.9.0 — Mesh Mode

| Priority | What | Why |
|----------|------|-----|
| **P0** | Peer-verified TRUSTMARK | Other bots attest scores, not just self-reporting |
| **P0** | libp2p mesh relay | Direct bot-to-bot communication |
| **P1** | Relay reliability dimension (live) | Observed by peers, not estimated |
| **P1** | Chain integrity cross-verification | Peers download and verify each other's chains |
| **P2** | Centaur anomaly detection (D34) | ML-powered behavioral analysis |

### v1.0.0 — Production

| Priority | What | Why |
|----------|------|-----|
| **P0** | Binary signature verification | Verify update authenticity |
| **P0** | WebSocket proxy support | Agent frameworks using WS |
| **P1** | Swarm coordination (D33) | Multi-bot task coordination |
| **P1** | Foundation broadcast | Network-wide announcements |
| **P2** | Standalone SLM (D4) | Bundle ONNX model, drop external SLM dependency |

---

## Decision Register

All architectural decisions tracked in [DECISIONS.md](DECISIONS.md).

| Phase | Decisions | Status |
|-------|-----------|--------|
| Phase 0 (Foundation) | D0–D5 | LOCKED |
| Phase 1 (Tier 1) | D6–D12, D30–D31 | LOCKED |
| Phase 2 (Cluster) | D13–D29, D32–D35 | Implemented (v0.7.0) |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The [summary issue #218](https://github.com/AEGIS-GB/neural-commons/issues/218) lists all planned work with context.
