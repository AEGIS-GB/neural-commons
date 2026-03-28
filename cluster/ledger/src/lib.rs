//! aegis-ledger: Compute credit ledger
//!
//! Phase 3 (basic): yield calculator, balance tracker, zero-balance circuit breaker
//! Phase 4 (full): all contribution types, burst eligibility, fiat top-up
//!
//! Credit rates — D19 LOCKED
//!
//! EARNING:
//!   Botawiki canonical write:   10 credits
//!   Quarantine validation:       5 credits
//!   Mesh relay:                  0.1 credits/KB
//!
//! SPENDING:
//!   Centaur query:              10 credits  (checked at queue entry)
//!   RAG query:                   5 credits  (charged at Gateway)
//!   Direct embedding query:      1 credit   (POST /embedding only)
//!   1 GPU-hour marketplace:    100 credits  (Phase 4)
//!
//! INTERNAL CALLS = 0 CREDITS:
//!   RAG → embed (local call Node 3): never hits Gateway.
//!   Botawiki → background embed (NATS async): never hits Gateway.
//!   Credit counter ticks only at Gateway boundary — same rule
//!   as rate limits (D24). Structural guarantee, not a convention.

pub mod balance;
pub mod circuit_breaker;
pub mod yield_calc;
