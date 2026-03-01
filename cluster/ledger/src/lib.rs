//! aegis-ledger: Compute credit ledger
//!
//! Phase 3 (basic): yield calculator, balance tracker, zero-balance circuit breaker
//! Phase 4 (full): all contribution types, burst eligibility, fiat top-up
//!
//! Credit rates (D19): 1 GPU-hour = 100 credits, embedding = 1, RAG = 5

pub mod balance;
pub mod yield_calc;
pub mod circuit_breaker;

// TODO(D19): Confirm credit earn/spend rates
