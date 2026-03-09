//! GPU Scheduler — Centaur inference orchestration (Rust)
//!
//! SCOPE IN OPTION B (Phase 3 launch config):
//!   Handles CENTAUR REQUESTS ONLY via NATS scheduler.* subjects.
//!   Direct embedding calls (POST /embedding) bypass this scheduler
//!   entirely — they are load-balanced at the Edge Gateway.
//!   RAG embedding is a local call on Node 3 — never reaches here.
//!
//! SCOPE IN OPTION C (escalation — config change only):
//!   When Centaur is added to Nodes 1+3, this scheduler also handles
//!   embedding routing with GPU-busy awareness. Enable by editing
//!   cluster/scheduler/config.toml and sending SIGHUP.
//!   No code change required for Option B → C transition.
//!
//! Routing algorithm (Centaur, both options):
//!   1. Tier check — Centaur from T1/T2 → 403 TierInsufficient
//!   2. Credit check at queue ENTRY — balance ≤ 0 → 402
//!   3. Global queue cap = 50 — depth ≥ 50 → 503 QueueFull
//!   4. Route to shortest queue among active Centaur nodes
//!   5. TRUSTMARK score breaks ties (higher score = shorter wait)
//!
//! Hot-pin threshold: D27 (pending — stubbed in config.toml)

pub mod registry;
pub mod router;

// TODO(D27): Confirm Centaur hot-pin threshold
