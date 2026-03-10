//! aegis-proxy: Transparent HTTP/WS/SSE proxy with tower middleware
//!
//! Intercepts all traffic between the bot client and the LLM provider.
//! Middleware chain: rate limit -> size limit -> evidence -> barrier -> SLM -> vault -> forward
//! Defaults to observe-only (receipts without blocking).
//!
//! Modes:
//!   pass-through: zero inspection, transparent forwarding
//!   observe-only: full inspection + receipts, no blocking (default)
//!   enforce: full inspection + receipts + blocking

pub mod anthropic;
pub mod proxy;
pub mod middleware;
pub mod cognitive_bridge;
pub mod config;
pub mod error;
