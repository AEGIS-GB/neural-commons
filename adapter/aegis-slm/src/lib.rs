//! aegis-slm: Small Language Model loopback + holster (D4)
//!
//! Three-way separation:
//!   SLM detects — qualitative, low-token, no arithmetic
//!   Adapter scores — deterministic, versioned tables, testable
//!   Holster decides — private coefficients + warden config, never leaves device
//!
//! All scores in integer basis points (0-10000). No floats in signed data.
//!
//! Enforcement mode (D30):
//!   slm_reject is switchable — "observe" (summary receipt only, request
//!   forwarded regardless of score) or "enforce" (receipt + request dropped
//!   if score exceeds holster threshold). Default: observe for external wardens.
//!   Warn-mode receipt is summary only: aggregate score + action. No per-pattern
//!   breakdown in Phase 1 (SlmReceiptDetail::Summary).

pub mod engine;
pub mod holster;
pub mod loopback;
pub mod parser;
pub mod prompt;
pub mod scoring;
pub mod types;
