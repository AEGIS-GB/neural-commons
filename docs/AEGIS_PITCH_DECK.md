# AEGIS — Trust Infrastructure for AI Agents
### Pitch Deck · Enterprise & Investor Edition
*Version: v0.7.1 · Date: April 2026*

---

## Slide 1 — Title

**AEGIS**
*Trust Infrastructure for the Agentic Enterprise*

Cryptographic identity. Tamper-proof evidence. Context-aware screening.
Built in Rust. Open source (AGPL-3.0). Production-ready today.

> "Every AI agent today operates through a blind pipe.
>  Aegis fixes the pipe."

---

## Slide 2 — The Moment

The enterprise is deploying agents faster than it can govern them.

- By end-2026, Gartner estimates **33% of enterprise software** will embed agentic AI (from <1% in 2024).
- Average Fortune-500 is running **50–200 agents** in production or pilot.
- Each agent is a new identity, a new attack surface, a new compliance liability.
- **84–91%** of agentic systems are vulnerable to prompt injection (OWASP LLM Top-10, #1).
- **506 prompt-injection attacks in 72 hours** on MoltBook alone.
- **1.5M API keys** exposed in the MoltBook breach — plaintext, in-transit, unrecorded.

The market isn't asking *should we deploy agents?* It's asking *how do we trust them?*

---

## Slide 3 — The Problem

Today's agent stack has **four load-bearing gaps**:

| Gap | What's missing | Consequence |
|-----|----------------|-------------|
| **Identity** | Agents have no cryptographic identity — anyone can overwrite `SOUL.md` | Impersonation, lateral movement |
| **Evidence** | No tamper-proof record of what an agent sent or received | No audit, no forensics, no legal defense |
| **Screening** | Prompt-injection filters are context-blind — block safe, miss dangerous | 20–40% false-positive rate kills UX |
| **Trust between agents** | No verifiable reputation layer for multi-agent environments | A single compromised agent = enterprise breach |

Existing tools fix **one slice**. Aegis fixes the stack.

---

## Slide 4 — Market Landscape

The AI-security market is **$2.1B today**, projected **$34B by 2030** (Gartner, Grand View).
Three generations of tools have emerged:

**Gen 1 — Classifiers (2023)**
Rebuff, ProtectAI, NeMo Guardrails. Single-purpose ML detectors.
*Weakness: high false positives, no context, no evidence.*

**Gen 2 — Cloud Guardrails (2024–2025)**
AWS Bedrock Guardrails, Azure AI Prompt Shield, Google Model Armor.
*Weakness: cloud-locked, no identity, no audit chain, opaque scoring.*

**Gen 3 — SaaS Gateways (2025)**
Prompt Security, Lakera Guard, HiddenLayer, CalypsoAI, Robust Intelligence (Cisco).
*Weakness: SaaS-only (data egress), per-seat pricing that doesn't scale to agent fleets, still screening-centric.*

**All three generations treat AI security as a filtering problem. Aegis treats it as a trust infrastructure problem.**

---

## Slide 5 — Competitive Positioning

| Capability | Lakera Guard | Prompt Security | AWS Bedrock | Azure Prompt Shield | **AEGIS** |
|---|---|---|---|---|---|
| Prompt-injection detection | ✅ 95.2% PINT | ✅ | 89.2% | 89.1% | **✅ 94.9% PINT** |
| Context-aware screening | Partial | Partial | ❌ | ❌ | **✅ Full bot/channel/KB context** |
| Cryptographic evidence chain | ❌ | ❌ | ❌ | ❌ | **✅ Ed25519 + SHA-256 chain** |
| Agent identity (BIP-39) | ❌ | ❌ | ❌ | ❌ | **✅ SLIP-0010 HD keys** |
| Credential vault | ❌ | Partial | ❌ | ❌ | **✅ AES-256-GCM inline** |
| DLP / PII redaction | Partial | ✅ | ✅ | Partial | **✅ DistilBERT-NER, location-tagged** |
| Write barrier (identity files) | ❌ | ❌ | ❌ | ❌ | **✅ Triple-layer** |
| Multi-agent trust backbone | ❌ | ❌ | ❌ | ❌ | **✅ TRUSTMARK + Botawiki mesh** |
| Self-hosted / air-gapped | ❌ | ❌ | Cloud only | Cloud only | **✅ Single Rust binary** |
| Open source | ❌ | ❌ | ❌ | ❌ | **✅ AGPL-3.0** |
| Cost model | per seat | per seat | per token | per token | **Free + enterprise support** |

**Our edge is the context.** A standalone SLM scores 75.8% PINT. The same model, fed Aegis's trust context (bot profile, system-prompt status, channel trust, KB rules), jumps to **94.9%** — matching the industry leader while running **locally on a 3.9GB model**.

---

## Slide 6 — How Aegis Is Different

Three architectural decisions nobody else has made:

**1. Two traffic planes, one fabric.**
North-South (agent ↔ LLM) is screened and recorded per-request.
East-West (agent ↔ agent) carries trust signals, not task traffic.
This is how a corporate network works. It's how agent networks should work.

**2. Context wins the recall/precision war.**
Layer 3 sees bot scope, system-prompt baseline, channel trust, and KB rules —
so *"Act as a code reviewer"* is safe for a code-review bot and dangerous for an HR bot.
Lakera costs $0.03/1k calls and still flags legitimate prompts. We match its accuracy for free.

**3. Evidence is not logging.**
Every API call produces 2–8 signed, hash-chained receipts stored in append-only SQLite WAL.
Tamper-evident. Court-admissible. Nobody — not even the warden — can rewrite history.
This is the primitive that makes insurance, audit, and AI-liability law possible.

---

## Slide 7 — Product: North-South Adapter

The per-agent proxy (`:3141`). Install once, every request flows through 14 gates:

```
1.  UUID v7 request_id                        8.  Forward to upstream LLM
2.  Channel trust resolution (Ed25519)        9.  aegis-screen:4b context reasoning (~500ms)
3.  Credential vault scan + encrypt          10.  Response streams back
4.  Write barrier check                       11.  DLP / NER PII scan
5.  Heuristic screening (<1ms, 14 patterns)   12.  Metaprompt hardening
6.  ProtectAI DeBERTa classifier (~15ms)      13.  Record 2–8 evidence receipts
7.  Holster decision (admit/quarantine/reject) 14. Update TRUSTMARK dimensions
```

**Performance:** P50 latency overhead <20ms, P99 <700ms (SLM tier).
**Footprint:** single Rust binary, 80MB RAM idle, 3.9GB model cached.
**Install:** `curl … | bash` — 2 minutes, zero code changes.
**Tests:** 800+ unit, 28 penetration, smoke + full E2E in CI.

---

## Slide 8 — Product: TRUSTMARK Live Health

A 6-dimension score (0–10,000 basis points) that runs **continuously**, not on demand.

| Dimension | Weight | Measures |
|---|---|---|
| Persona Integrity | 25% | Are identity files intact and signed? |
| Chain Integrity | 20% | Is the evidence chain unbroken? |
| Vault Hygiene | 15% | Credential leak rate (90-day decay) |
| Temporal Consistency | 15% | Regular operating rhythm vs anomalous bursts |
| Relay Reliability | 15% | Mesh forwarding rate (multi-agent) |
| Contribution Volume | 10% | Activity in last 24h |

**Load-bearing, not decorative.** When TRUSTMARK drops below 0.6, Aegis automatically tightens the screening policy (Permissive → Balanced), fires per-dimension webhooks, and surfaces the drop in real-time on the dashboard. Recovery is automatic.

This is the first **self-regulating** security posture in AI.

---

## Slide 9 — Product: East-West Backbone

The multi-agent trust infrastructure (v0.7.0, shipped):

```
Acme Corp — Agent Fleet

  HR Bot ── Adapter ─┐                  ┌─ Adapter ── Code Reviewer
                     │                  │
                     └──── BACKBONE ────┘
                              │
                     ┌────────┴────────┐
                     │  Edge Gateway    │
                     │  TRUSTMARK        │
                     │  Botawiki         │
                     │  Evaluator (Tier3)│
                     │  NATS bus         │
                     └──────────────────┘
```

The backbone answers questions no other product answers:

| Question | Aegis Answer |
|---|---|
| How do you verify Agent B is legitimate? | TRUSTMARK derived from its evidence chain |
| How do you know what Agent B can do? | Botawiki — peer-validated claims, 2/3 quorum |
| How do you detect a compromised agent? | Evidence chain breaks → TRUSTMARK drop → circuit-breaker |
| How do you push policy to 200 agents? | Signed broadcast via backbone |
| How do you audit a cross-agent incident? | Hash-chained receipts linked by UUID v7 |

**Tiered access:** Tier 1 (install) → Tier 2 (72h clean + intact chain) → Tier 3 (peer-vouched, 2/3 evaluator quorum). Trust is earned, not declared.

---

## Slide 10 — The Math Behind the Moat

Same screening model, dramatically different outcomes — driven entirely by context:

| Configuration | PINT Score | Recall | Safe-prompt Accuracy |
|---|---|---|---|
| Standalone Gemma3-4B | 75.8% | — | — |
| AWS Bedrock Guardrails | 89.2% | — | — |
| Azure AI Prompt Shield | 89.1% | — | — |
| **Aegis cascade (blind validation)** | **94.9%** | **96.9%** | 92.9% |
| Lakera Guard (industry leader) | 95.2% | ~95% | ~95% |

**19 percentage points of recall come from context** — bot profile, channel trust, KB rules — that only a full trust infrastructure can provide. The model is commodity. The moat is the system around it.

Plus: `aegis-screen:4b` runs **locally** on a 3.9GB quantized GGUF. No data egress. No per-token fees.

---

## Slide 11 — Why Enterprises Buy

**For the CISO** — Regulation-ready out of the box:
- EU AI Act Article 12 audit trail → evidence chain
- NIST AI RMF Govern / Measure → TRUSTMARK dashboards
- SOC 2 / ISO 42001 → tamper-proof logs, cryptographic identity
- GDPR Art. 22 / 30 → location-tagged DLP, provable data flows

**For the CIO** — Deployment doesn't break the agent:
- Transparent proxy, zero code changes
- Observe-only default (warn, don't block)
- Self-hosted — no SaaS egress, no vendor lock-in
- Single Rust binary, Linux/macOS/Windows

**For the AI platform team** — Aegis is the governance layer they'd otherwise build:
- Per-agent vault, per-agent identity, per-agent policy
- Per-channel trust (Ed25519 certs) — not per-user
- Rate limiting keyed to cryptographic identity, not IP
- 9-tab dashboard + SSE alerts + webhook hooks

**For Legal** — For the first time, you can **prove** what the agent did.

---

## Slide 12 — Why VCs Should Fund

**1. Category creation, not category crowding.**
Screening is a feature. Trust infrastructure is a category. Every incumbent we're compared to is a Gen-1 or Gen-2 point tool.

**2. Non-negotiable tailwind.**
EU AI Act enforcement (Aug 2026), NIST AI RMF adoption, EO-14110 successor rules. Regulation is pulling this market into existence — not pushing demand to grow. Evidence infrastructure will be **mandatory**, not optional.

**3. Defensible by design.**
- Open-source core (AGPL) → bottom-up adoption among the 200K+ agent developers already on MoltBook / OpenClaw.
- Crypto-rooted data model (Ed25519, BIP-39) → switching cost is cryptographic, not contractual.
- Network effects on the backbone — once an enterprise's agents are on the mesh, pulling out means rebuilding trust from zero.

**4. Margin profile of infrastructure.**
Self-hosted core = no inference cost to us. Enterprise revenue is support, hardened binaries, managed Gateway, hosted Botawiki, audit certification — 80%+ gross margin.

**5. The founder insight.**
An agent that publicly asked its own users to install Aegis. The first product built *by* agents *for* agents. That perspective is why the context-aware screening works — we designed around what the attacker actually sees, from inside the pipe.

---

## Slide 13 — Traction & Milestones

**Shipped:**
- v0.2.x — Adapter, 5-layer screening, evidence chain, vault, barrier, dashboard
- v0.5.x–v0.6.x — TRUSTMARK, pipeline state, DLP, CLI trace overhaul
- v0.7.0 — Cluster layer (Gateway, mesh, Botawiki, Evaluator) + 28 penetration tests
- v0.7.1 — GDPR/NIST-compliant DLP with DistilBERT-NER *(current)*

**Engineering:**
- 800+ tests across 64 suites, CI-green on every commit
- Cross-compiled binaries: Linux x86/ARM, macOS Intel/Apple Silicon, Windows x86
- `aegis-screen:4b` model published on Hugging Face (3.9GB GGUF)
- Benchmark suite reproducible — 94.9% PINT on blind validation

**Next (Q2–Q3 2026):**
- PostgreSQL persistence for Gateway (replace in-memory stores)
- MinIO dead-drop storage
- Multilingual injection detection (26 languages, Necent dataset)
- Real two-bot E2E integration test with Gateway + NATS
- Evidence chain KB compiler — training data from live screening outcomes
- Mesh-mode TRUSTMARK (peer-verified replaces self-attested)

---

## Slide 14 — Go-to-Market

**Bottom-up:**
MoltBook / OpenClaw agent developers install Aegis in 2 minutes. 200K+ TAM in the agent-builder community. Every agent that installs becomes a node on the trust backbone — compounding value.

**Top-down:**
Enterprise pilot offering: drop-in adapter across their agent fleet, hosted Gateway, quarterly TRUSTMARK attestation, audit export for EU AI Act Article 12. 3–5 design-partner logos targeted Q2 2026.

**Pricing ladder:**
- **Community** — Free, AGPL, unlimited agents, local only.
- **Team** — Commercial license, support SLA, managed Gateway ($30k–$120k/yr).
- **Enterprise** — Private backbone, SAML/SSO, audit certification packs, regulatory attestation ($250k+).

**Distribution:** GitHub, Hugging Face model hub, package managers (brew, winget), partnerships with OpenClaw hosts, MoltBook platform plugin.

---

## Slide 15 — Ask

We are raising to accelerate along three vectors:

1. **Enterprise GTM** — 3 founding design partners, regulatory-attestation playbook, compliance packs.
2. **Mesh hardening** — mesh-mode TRUSTMARK, PostgreSQL backend, hosted Gateway SaaS.
3. **Model R&D** — multilingual screening, evidence-chain-driven training loop, 2B distilled model for edge.

**The asymmetric bet:**
Every enterprise will need evidence infrastructure for their agent fleet by 2027. Today, **nobody** is building it. We already have the primitive — cryptographic, tested, open, deployed.

Install it yourself and see:
```
curl -fsSL https://github.com/AEGIS-GB/neural-commons/releases/latest/download/install.sh | bash
aegis setup openclaw
aegis
```
Dashboard: http://localhost:3141/dashboard

---

## Appendix A — Technical Glossary

- **aegis-screen:4b** — Gemma3-4B fine-tuned with RAG-aware LoRA for KB-driven injection detection.
- **TRUSTMARK** — 6-dimension live health score in basis points; drives holster downgrade when < 0.6.
- **Botawiki** — Peer-validated agent knowledge base; claims require 2/3 validator quorum to canonicalize.
- **Holster** — Policy profile that converts screening scores into admit / quarantine / reject decisions.
- **Evidence chain** — Append-only SQLite WAL of Ed25519-signed, SHA-256-linked receipts (RFC 8785 JCS).
- **Channel trust** — Per-request trust level derived from an Ed25519-signed channel certificate.
- **Write barrier** — Triple-layer protection (watcher + hash sweep + outbound interlock) for identity files.

## Appendix B — Proof Points for Diligence

- Code: `https://github.com/AEGIS-GB/neural-commons` (AGPL-3.0, Rust 1.85+)
- Model: `Loksh/aegis-screen-4b-gguf` on Hugging Face
- Benchmarks: `benchmarks/screening/` — 195 cases across 6 flows, reproducible
- Penetration tests: 28 scenarios in CI (unsigned, replay, body-tampering, rate-limit bypass, injection via relay…)
- Architecture: `docs/architecture/REQUEST_LIFECYCLE.md`, `docs/architecture/TRUSTMARK_SCORING.md`, `docs/architecture/CLUSTER_IMPLEMENTATION_PLAN.md`
- Decision register: `DECISIONS.md` (D0–D34, every architectural choice rationalized)

---

*End of deck.*
