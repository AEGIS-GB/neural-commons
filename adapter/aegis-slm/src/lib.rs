//! aegis-slm: Small Language Model loopback + holster (D4)
//!
//! Three-way separation:
//!   SLM detects — qualitative, low-token, no arithmetic
//!   Adapter scores — deterministic, versioned tables, testable
//!   Holster decides — private coefficients + warden config, never leaves device
//!
//! All scores in integer basis points (0-10000). No floats in signed data.

pub mod loopback;
pub mod holster;
pub mod parser;
pub mod scoring;
pub mod types;
