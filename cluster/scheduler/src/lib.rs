//! aegis-scheduler: GPU scheduler
//!
//! Model registry, request router across GPU nodes
//! Centaur on-demand loading: cold start <30s, hot-pin at >50 daily queries (D27)
//! Phase 4 only

pub mod registry;
pub mod router;

// TODO(D27): Confirm Centaur hot-pin threshold
