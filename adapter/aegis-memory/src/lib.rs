//! aegis-memory: Memory integrity monitoring (D11)
//!
//! Monitors "memory files" for unauthorized changes.
//!
//! Capabilities:
//!   - Write interception: tool-mediated inline + filesystem watcher for external
//!   - Memory SLM screen: dedicated SLM analysis (Clean/Suspicious/Blocked)
//!   - State reconciliation: periodic hash vs warden-acknowledged state (Phase 2)
//!   - Provenance index: map every line to its authorizing receipt (Phase 2)
//!
//! Default memory file patterns (D11):
//!   MEMORY.md, *.memory.md, memory/*.md, SOUL.md
//!   + any paths in config.json -> memory_paths[]

pub mod config;
pub mod interception;
pub mod monitor;
pub mod screen;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("file watch error: {0}")]
    WatchError(String),
    #[error("hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("memory file not found: {0}")]
    FileNotFound(String),
    #[error("screen error: {0}")]
    ScreenError(String),
}
