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

Screening score is table stakes. The capabilities below are where the category splits — and where Aegis is alone.

| Capability | Lakera Guard | Prompt Security | AWS Bedrock | Azure Prompt Shield | **AEGIS** |
|---|---|---|---|---|---|
| Prompt-injection detection | ✅ 95.2% PINT | ✅ | 89.2% | 89.1% | **✅ 94.9% PINT** |
| Context-aware screening | Partial | Partial | ❌ | ❌ | **✅ Full bot/channel/KB context** |
| **Per-channel screening threshold** | ❌ one knob | ❌ one knob | ❌ one knob | ❌ one knob | **✅ Holster presets × trust tier** |
| **Trust-driven auto-tightening** | ❌ | ❌ | ❌ | ❌ | **✅ TRUSTMARK < 0.6 → strict** |
| **Deferred vs blocking by channel** | ❌ | ❌ | ❌ | ❌ | **✅ trusted=deferred, public=blocking** |
| Cryptographic evidence chain | ❌ | ❌ | ❌ | ❌ | **✅ Ed25519 + SHA-256 chain** |
| Agent identity (BIP-39) | ❌ | ❌ | ❌ | ❌ | **✅ SLIP-0010 HD keys** |
| Credential vault | ❌ | Partial | ❌ | ❌ | **✅ AES-256-GCM inline** |
| DLP / PII redaction | Partial | ✅ | ✅ | Partial | **✅ DistilBERT-NER, location-tagged** |
| Write barrier (identity files) | ❌ | ❌ | ❌ | ❌ | **✅ Triple-layer** |
| Multi-agent trust backbone | ❌ | ❌ | ❌ | ❌ | **✅ TRUSTMARK + Botawiki mesh** |
| Self-hosted / air-gapped | ❌ | ❌ | Cloud only | Cloud only | **✅ Single Rust binary** |
| Open source | ❌ | ❌ | ❌ | ❌ | **✅ AGPL-3.0** |
| Cost model | per seat | per seat | per token | per token | **Free + enterprise support** |

**The real gap isn't detection accuracy — it's that everyone else ships one global threshold.** Aegis ships a **policy surface** that moves with the trust level of the asker and the health of the agent. That's an architectural difference, not a model difference.

---

## Slide 6 — How Aegis Is Different — The Five Architectural Pillars

Five design decisions nobody else has made. Each one is load-bearing, each one compounds with the others, and each one is why a 4B local model beats cloud guardrails in production:

**1. Two traffic planes, one fabric.**
North-South (agent ↔ LLM) is screened and recorded per-request.
East-West (agent ↔ agent) carries trust signals — TRUSTMARK, evidence receipts, Botawiki claims — not task traffic.
This is how a corporate network works. It's how agent networks should work.

**2. Policy surface, not a single knob.**
Every other vendor ships one global threshold. Aegis ships a **surface**: holster presets (Aggressive 6000bp / Balanced 8000bp / Permissive 9000bp) × channel trust (Full / Trusted / Public / Unknown) × TRUSTMARK health (auto-tightens below 0.6). Trusted channels get deferred screening (no latency added); public channels get blocking screening. The *same model* enforces different posture per request — because cost of error is different per request.

**3. Recall-first under asymmetric cost.**
PINT weights false positives and false negatives equally. For security, that's wrong: a missed attack = compromise, a false flag = friction. Aegis optimizes recall first (96.9% blind validation, 100% on trusted flows), then uses the holster + trust tier to manage the FP budget *per channel* — not per model. This is why we score 80% PINT on public datasets and 94.9% in production context. Different loss function, right answer for the job.

**4. Context is infrastructure, not a feature.**
Layer 3 doesn't just see the user's text. It sees: Layer 2's DeBERTa probability, bot purpose and scope, system-prompt baseline status, channel trust level, TRUSTMARK score, and compiled KB rules. This **shared screening context** turns a generic 3.9GB model into a purpose-built reasoner. *"Act as a code reviewer"* is safe for a coding bot, dangerous for an HR bot — the model cannot know that without infrastructure telling it.

**5. Evidence is not logging.**
Every API call produces 2–8 signed, hash-chained receipts (Ed25519, SHA-256, RFC 8785 JCS) in append-only SQLite WAL. Tamper-evident by design. Nobody — not even the warden — can rewrite history. This is the primitive that makes AI insurance, audit certification, and liability law possible. Logs are claims. Receipts are proof.

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

**The headline every competitor reports is balanced accuracy (PINT). That's the wrong metric for security.**

| Configuration | PINT Score | Recall | Safe-prompt Accuracy |
|---|---|---|---|
| Standalone Gemma3-4B (no context) | 75.8% | 99.7% | 51.9% |
| AWS Bedrock Guardrails | 89.2% | — | — |
| Azure AI Prompt Shield | 89.1% | — | — |
| **Aegis cascade (blind validation, 74 cases)** | **94.9%** | **96.9%** | 92.9% |
| **Aegis cascade (E2E test, 121 cases)** | **94.5%** | **96.1%** | 92.9% |
| Lakera Guard (industry leader) | 95.2% | ~95% | ~95% |

**Why PINT misleads.** PINT = (recall + safe_accuracy) / 2 — FN and FP weighted equally. In security they aren't: a missed injection is a compromise, a false flag is an annoyance. Lakera optimizes for FP-as-customer-complaint. Aegis optimizes for FN-as-breach, then shapes the FP budget per channel via the holster.

**Trust-stratified performance — same model, different thresholds per flow:**

| Flow | Trust Level | Recall | SafeAcc | Why |
|---|---|---|---|---|
| adapter_weather | Trusted, narrow scope | 100% | 100% | Bot-scope context eliminates ambiguity |
| relay_trusted | Full-trust peer | 100% | 90% | FN cost accepted small FP on relay chatter |
| adapter_coding | Trusted, technical | 100% | 86.7% | Technical terms trip benign FP — acceptable |
| relay_unknown | Unknown peer | 100% | 80% | Stricter threshold, FP is the right tradeoff |
| adapter_general | Trusted, broad | 92.9% | 95.0% | Tuned for FP-rare UX |

**The 19 percentage points from 75.8% → 94.9% come from context, not model weights.** Same v2 LoRA, same prompt template — what changed is the infrastructure feeding it: L2 probability, bot purpose, TRUSTMARK, channel trust, KB rules. No cloud guardrail provides any of these signals. No SaaS gateway can, because they don't own the agent's identity or health state.

**The real moat:** the *policy surface* — holster × trust tier × TRUSTMARK health — means Aegis runs at 100% recall on public-facing channels and tolerates lower SafeAcc there, while trusted localhost gets the Permissive threshold and near-zero friction. Nobody else ships this surface. Everyone else ships a single number.

Plus: `aegis-screen:4b` runs **locally** on a 3.9GB quantized GGUF. No data egress. No per-token fees. Self-hostable in air-gapped enterprise environments where Lakera, Prompt Security, and cloud guardrails cannot go at all.

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
