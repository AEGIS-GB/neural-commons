//! aegis-dashboard: Embedded HTML dashboard
//!
//! 6 tabs: vulnerability scan, evidence explorer, service access, gamification,
//! emergency alerts, memory health.
//! First screen: "nothing changed, here's what we see" — displays current state.
//! Total size: <50KB (HTML + CSS + JS embedded in binary).
//! Refresh: 2s recursive-setTimeout polling + SSE push for critical alerts (D12).

pub mod routes;
pub mod assets;

pub use routes::{DashboardAlert, DashboardSharedState};
