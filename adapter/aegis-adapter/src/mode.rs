//! Runtime mode management
//!
//! Handles mode transitions:
//!   observe-only ↔ enforce ↔ pass-through
//!
//! Mode changes produce receipts and are reflected on the dashboard.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::Mode;

/// Thread-safe mode controller.
///
/// Allows runtime mode switching via CLI or dashboard.
pub struct ModeController {
    current: AtomicU8,
}

impl ModeController {
    pub fn new(initial: Mode) -> Self {
        Self {
            current: AtomicU8::new(mode_to_u8(initial)),
        }
    }

    /// Get the current operating mode.
    pub fn current(&self) -> Mode {
        u8_to_mode(self.current.load(Ordering::Relaxed))
    }

    /// Switch to a new mode. Returns the previous mode.
    pub fn switch(&self, new_mode: Mode) -> Mode {
        let prev = self.current.swap(mode_to_u8(new_mode), Ordering::Relaxed);
        u8_to_mode(prev)
    }

    /// Switch to observe-only mode (panic switch).
    pub fn observe_only(&self) -> Mode {
        self.switch(Mode::ObserveOnly)
    }

    /// Switch to pass-through mode (dumb forwarder).
    pub fn pass_through(&self) -> Mode {
        self.switch(Mode::PassThrough)
    }

    /// Switch to enforce mode.
    pub fn enforce(&self) -> Mode {
        self.switch(Mode::Enforce)
    }

    /// Check if currently in pass-through mode.
    pub fn is_pass_through(&self) -> bool {
        self.current() == Mode::PassThrough
    }

    /// Check if enforcement is active.
    pub fn is_enforcing(&self) -> bool {
        self.current() == Mode::Enforce
    }
}

impl Default for ModeController {
    fn default() -> Self {
        Self::new(Mode::default())
    }
}

fn mode_to_u8(mode: Mode) -> u8 {
    match mode {
        Mode::ObserveOnly => 0,
        Mode::Enforce => 1,
        Mode::PassThrough => 2,
    }
}

fn u8_to_mode(val: u8) -> Mode {
    match val {
        0 => Mode::ObserveOnly,
        1 => Mode::Enforce,
        2 => Mode::PassThrough,
        _ => Mode::ObserveOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_observe_only() {
        let mc = ModeController::default();
        assert_eq!(mc.current(), Mode::ObserveOnly);
    }

    #[test]
    fn switch_mode() {
        let mc = ModeController::new(Mode::ObserveOnly);
        let prev = mc.switch(Mode::Enforce);
        assert_eq!(prev, Mode::ObserveOnly);
        assert_eq!(mc.current(), Mode::Enforce);
    }

    #[test]
    fn observe_only_panic_switch() {
        let mc = ModeController::new(Mode::Enforce);
        mc.observe_only();
        assert_eq!(mc.current(), Mode::ObserveOnly);
    }

    #[test]
    fn pass_through_mode() {
        let mc = ModeController::new(Mode::ObserveOnly);
        mc.pass_through();
        assert!(mc.is_pass_through());
        assert!(!mc.is_enforcing());
    }

    #[test]
    fn mode_round_trip() {
        for mode in [Mode::ObserveOnly, Mode::Enforce, Mode::PassThrough] {
            let val = mode_to_u8(mode);
            assert_eq!(u8_to_mode(val), mode);
        }
    }
}
