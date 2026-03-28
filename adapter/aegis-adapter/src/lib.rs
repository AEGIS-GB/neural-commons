//! aegis-adapter: Main composition crate
//!
//! Composes all adapter modules into a single binary:
//! proxy → evidence → barrier → memory → SLM → vault → failure → dashboard
//!
//! Modules:
//!   config  — TOML configuration loading
//!   mode    — runtime mode controller (observe-only / enforce / pass-through)
//!   hooks   — middleware hook implementations bridging proxy traits to subsystems
//!   replay  — replay prevention (monotonic counter + nonce registry)
//!   state   — shared adapter state accessible to all subsystems
//!   server  — server startup orchestration
//!
//! Modes:
//!   observe-only (default): full inspection + receipts, but no blocking
//!   enforce: full inspection + receipts + blocking
//!   pass-through: zero inspection, metadata-only receipt logging

pub mod config;
pub mod hooks;
pub mod mode;
pub mod replay;
pub mod server;
pub mod state;

/// Adapter operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum Mode {
    /// Full inspection + receipts, no blocking (default)
    #[default]
    ObserveOnly,
    /// Full inspection + receipts + blocking
    Enforce,
    /// Zero inspection, transparent forwarding, metadata-only receipts
    PassThrough,
}

