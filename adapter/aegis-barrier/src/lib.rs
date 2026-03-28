//! aegis-barrier: Write barrier with triple-layer detection (D5)
//!
//! Triple-layer detection:
//!   Layer 1: Filesystem watcher (real-time, debounced 2s)
//!   Layer 2: Periodic hash verification (60s safety net)
//!   Layer 3: Outbound proxy interlock (before every LLM request)
//!
//! WriteToken: time-windowed authorization for bot-initiated writes.
//! HashRegistry: signed by bot identity key, inode tracking, encrypted SQLite.
//! Quarantine: never destroy — unauthorized changes moved to quarantine dir.
//!
//! Enforcement mode (D30):
//!   Controlled by the top-level adapter mode (observe_only / enforce).
//!   observe = receipt only, no revert. enforce = receipt + revert.
//!   Receipt includes `enforcement_mode` field for TRUSTMARK weighting.

pub mod diff;
pub mod evolution;
pub mod manifest;
pub mod protected_files;
pub mod registry;
pub mod severity;
pub mod snapshot;
pub mod types;
pub mod watcher;
pub mod write_token;
