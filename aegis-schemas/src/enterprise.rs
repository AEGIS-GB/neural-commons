//! Enterprise fields (BRD §47)
//!
//! D1 change: Enterprise fields are now nested inside ReceiptContext,
//! not flattened at the receipt top level. This file re-exports
//! EnterpriseContext from receipt.rs for backward compatibility
//! and provides standalone enterprise types for non-receipt use cases.

// The primary EnterpriseContext type is defined in receipt.rs
// and used as ReceiptContext.enterprise: Option<EnterpriseContext>
pub use crate::receipt::EnterpriseContext;
