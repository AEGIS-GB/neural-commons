//! aegis-dashboard: Embedded HTML dashboard
//!
//! 7 tabs: vulnerability scan, evidence explorer, service access, traffic inspector,
//! gamification, emergency alerts, memory health.
//! First screen: "nothing changed, here's what we see" — displays current state.
//! Total size: <50KB (HTML + CSS + JS embedded in binary).
//! Refresh: 2s recursive-setTimeout polling + SSE push for critical alerts (D12).

pub mod assets;
pub mod routes;
pub mod traffic;

pub use routes::{DashboardAlert, DashboardSharedState};
pub use traffic::TrafficStore;
