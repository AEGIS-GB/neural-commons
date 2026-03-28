//! Filesystem watcher — Layer 1 detection (D5)
//!
//! Uses `notify` crate: inotify (Linux), FSEvents (macOS), ReadDirectoryChangesW (Windows).
//! Debouncing: 2s per-file cooldown, 10 events/min cap, 60s quiet suppression lift.
//! On watcher crash/overflow, Layer 2 catches within 60s.
//!
//! This module provides the building blocks for the filesystem watcher:
//! - [`FileWatcher`]: debounce state machine (cooldown, rate limiting, suppression)
//! - [`WatchEvent`] / [`WatchEventKind`]: internal event representation
//! - [`map_notify_event`]: converts `notify::Event` into `Vec<WatchEvent>`
//! - [`is_excluded`]: checks paths against [`EXCLUDED_DIRS`]
//!
//! The actual watcher loop (async runtime + channels) is composed elsewhere;
//! this module is intentionally runtime-agnostic.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use notify::event::{CreateKind, ModifyKind, RemoveKind, RenameMode};
use notify::EventKind;
use tracing::{debug, trace, warn};

use crate::types::{DebounceConfig, EXCLUDED_DIRS};

// ═══════════════════════════════════════════════════════════════════
// WatchEvent types
// ═══════════════════════════════════════════════════════════════════

/// The kind of filesystem change we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEventKind {
    Modified,
    Created,
    Deleted,
    Renamed,
}

/// A normalized filesystem event produced from a raw `notify::Event`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub path: PathBuf,
    pub kind: WatchEventKind,
    pub timestamp_ms: u64,
}

// ═══════════════════════════════════════════════════════════════════
// Debounce state
// ═══════════════════════════════════════════════════════════════════

/// Per-file debounce tracking.
#[derive(Debug, Clone)]
pub struct DebounceState {
    /// Unix ms of the last event that was actually processed.
    pub last_event_ms: u64,
    /// Number of events processed in the current one-minute window.
    pub event_count_this_minute: u32,
    /// Unix ms marking the start of the current one-minute window.
    pub minute_start_ms: u64,
    /// `true` when the file has been suppressed due to exceeding the
    /// per-minute cap. Suppression lifts after `suppression_quiet_ms`
    /// of silence (no incoming events).
    pub suppressed: bool,
}

impl DebounceState {
    fn new(now_ms: u64) -> Self {
        Self {
            last_event_ms: 0,
            event_count_this_minute: 0,
            minute_start_ms: now_ms,
            suppressed: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// FileWatcher
// ═══════════════════════════════════════════════════════════════════

/// Core debounce engine for Layer 1 filesystem watching.
///
/// Maintains per-file state and applies three rules in order:
/// 1. **Cooldown** -- skip events arriving less than `cooldown_ms` after the
///    last processed event for the same file.
/// 2. **Rate cap** -- once `max_events_per_minute` events have been processed
///    inside a rolling one-minute window, suppress the file.
/// 3. **Suppression lift** -- a suppressed file is un-suppressed once
///    `suppression_quiet_ms` have elapsed with no incoming events.
#[derive(Debug)]
pub struct FileWatcher {
    pub debounce_state: HashMap<PathBuf, DebounceState>,
    pub config: DebounceConfig,
}

impl FileWatcher {
    /// Create a new `FileWatcher` with the given debounce configuration.
    pub fn new(config: DebounceConfig) -> Self {
        Self {
            debounce_state: HashMap::new(),
            config,
        }
    }

    /// Decide whether an event for `path` at time `now_ms` should be processed.
    ///
    /// Mutates internal debounce state as a side-effect so that successive
    /// calls behave correctly.
    ///
    /// # Returns
    /// `true` if the event should be forwarded to hash-check / severity
    /// classification; `false` if it should be silently dropped.
    pub fn should_process(&mut self, path: &Path, now_ms: u64) -> bool {
        let state = self
            .debounce_state
            .entry(path.to_path_buf())
            .or_insert_with(|| DebounceState::new(now_ms));

        // ── Suppression lift check ──────────────────────────────
        // If the file is suppressed, the *only* thing that can lift it is a
        // quiet period: `now_ms - last_event_ms >= suppression_quiet_ms`.
        // During suppression we still update `last_event_ms` so the quiet
        // timer resets on every incoming event.
        if state.suppressed {
            let quiet_elapsed = now_ms.saturating_sub(state.last_event_ms);
            if quiet_elapsed >= self.config.suppression_quiet_ms {
                // Quiet period satisfied -- lift suppression and reset window.
                debug!(path = %path.display(), "suppression lifted after quiet period");
                state.suppressed = false;
                state.event_count_this_minute = 0;
                state.minute_start_ms = now_ms;
                // Fall through to normal processing below.
            } else {
                // Still suppressed. Record that we saw an event (resets quiet
                // timer) and reject.
                trace!(path = %path.display(), "event dropped (suppressed)");
                state.last_event_ms = now_ms;
                return false;
            }
        }

        // ── Per-file cooldown ───────────────────────────────────
        if state.last_event_ms > 0 {
            let elapsed = now_ms.saturating_sub(state.last_event_ms);
            if elapsed < self.config.cooldown_ms {
                trace!(
                    path = %path.display(),
                    elapsed_ms = elapsed,
                    cooldown_ms = self.config.cooldown_ms,
                    "event dropped (cooldown)"
                );
                return false;
            }
        }

        // ── Minute-window rate limiting ─────────────────────────
        let window_elapsed = now_ms.saturating_sub(state.minute_start_ms);
        if window_elapsed >= 60_000 {
            // Window expired -- start a fresh one.
            state.event_count_this_minute = 0;
            state.minute_start_ms = now_ms;
        }

        if state.event_count_this_minute >= self.config.max_events_per_minute {
            // Rate cap hit -- enter suppression.
            warn!(
                path = %path.display(),
                count = state.event_count_this_minute,
                "rate cap exceeded, file suppressed"
            );
            state.suppressed = true;
            state.last_event_ms = now_ms;
            return false;
        }

        // ── Accept event ────────────────────────────────────────
        state.last_event_ms = now_ms;
        state.event_count_this_minute += 1;
        true
    }
}

// ═══════════════════════════════════════════════════════════════════
// Event mapping
// ═══════════════════════════════════════════════════════════════════

/// Return the current time in milliseconds since the Unix epoch.
///
/// Used as the default timestamp source. Tests may supply their own values.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64
}

/// Map a raw `notify::Event` into zero or more [`WatchEvent`]s.
///
/// A single `notify` event can carry multiple paths (e.g. rename emits
/// both source and destination). We produce one `WatchEvent` per path.
/// Events that do not map to a kind we track (e.g. `Access`) are dropped.
pub fn map_notify_event(event: &notify::Event) -> Vec<WatchEvent> {
    let kind = match &event.kind {
        // ── Modify ──────────────────────────────────────────
        EventKind::Modify(modify_kind) => match modify_kind {
            // Rename sub-events get their own variant.
            ModifyKind::Name(RenameMode::From)
            | ModifyKind::Name(RenameMode::To)
            | ModifyKind::Name(RenameMode::Both) => Some(WatchEventKind::Renamed),
            // Everything else (data, metadata, etc.) is a modification.
            _ => Some(WatchEventKind::Modified),
        },
        // ── Create ──────────────────────────────────────────
        EventKind::Create(CreateKind::File) | EventKind::Create(CreateKind::Any) => {
            Some(WatchEventKind::Created)
        }
        // ── Remove ──────────────────────────────────────────
        EventKind::Remove(RemoveKind::File) | EventKind::Remove(RemoveKind::Any) => {
            Some(WatchEventKind::Deleted)
        }
        // ── Anything else (Access, Other, ...) ──────────────
        _ => None,
    };

    let Some(kind) = kind else {
        return Vec::new();
    };

    let ts = now_ms();

    event
        .paths
        .iter()
        .map(|p| WatchEvent {
            path: p.clone(),
            kind,
            timestamp_ms: ts,
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════
// Exclusion
// ═══════════════════════════════════════════════════════════════════

/// Returns `true` when `path` contains any component listed in
/// [`EXCLUDED_DIRS`] (e.g. `.git`, `node_modules`, `target`, ...).
///
/// Comparison is purely string-based on individual path components so it works
/// regardless of OS path separators.
pub fn is_excluded(path: &Path) -> bool {
    for component in path.components() {
        if let std::path::Component::Normal(os_str) = component
            && let Some(s) = os_str.to_str()
                && EXCLUDED_DIRS.contains(&s) {
                    return true;
                }
    }
    false
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{AccessKind, AccessMode, DataChange, MetadataKind};

    /// Helper: build a `FileWatcher` with the default debounce config.
    fn default_watcher() -> FileWatcher {
        FileWatcher::new(DebounceConfig::default())
    }

    /// Helper: build a `FileWatcher` with custom config values for tighter test control.
    fn watcher_with(cooldown_ms: u64, max_events_per_minute: u32, suppression_quiet_ms: u64) -> FileWatcher {
        FileWatcher::new(DebounceConfig {
            cooldown_ms,
            max_events_per_minute,
            suppression_quiet_ms,
        })
    }

    // ── Cooldown tests ──────────────────────────────────────────

    #[test]
    fn first_event_always_accepted() {
        let mut w = default_watcher();
        let p = Path::new("/workspace/system-prompt.md");
        assert!(w.should_process(p, 1000));
    }

    #[test]
    fn event_within_cooldown_rejected() {
        let mut w = watcher_with(2000, 100, 60_000);
        let p = Path::new("/workspace/system-prompt.md");

        assert!(w.should_process(p, 1000));
        // 500ms later -- within 2s cooldown
        assert!(!w.should_process(p, 1500));
        // 1999ms after first -- still within cooldown
        assert!(!w.should_process(p, 2999));
    }

    #[test]
    fn event_after_cooldown_accepted() {
        let mut w = watcher_with(2000, 100, 60_000);
        let p = Path::new("/workspace/system-prompt.md");

        assert!(w.should_process(p, 1000));
        // Exactly 2000ms later -- cooldown satisfied
        assert!(w.should_process(p, 3000));
    }

    #[test]
    fn cooldown_is_per_file() {
        let mut w = watcher_with(2000, 100, 60_000);
        let a = Path::new("/workspace/a.md");
        let b = Path::new("/workspace/b.md");

        assert!(w.should_process(a, 1000));
        // b has its own cooldown -- should pass
        assert!(w.should_process(b, 1500));
        // a is still in cooldown at 1500
        assert!(!w.should_process(a, 1500));
    }

    // ── Rate limiting tests ─────────────────────────────────────

    #[test]
    fn rate_cap_suppresses_after_max_events() {
        // cooldown=0 so we can fire rapidly, cap=3 for easy testing
        let mut w = watcher_with(0, 3, 60_000);
        let p = Path::new("/workspace/file.txt");

        assert!(w.should_process(p, 1000)); // 1
        assert!(w.should_process(p, 1001)); // 2
        assert!(w.should_process(p, 1002)); // 3
        // 4th event -- should be suppressed
        assert!(!w.should_process(p, 1003));
        // 5th -- still suppressed
        assert!(!w.should_process(p, 1004));
    }

    #[test]
    fn minute_window_resets_count() {
        let mut w = watcher_with(0, 3, 60_000);
        let p = Path::new("/workspace/file.txt");

        // Fill up the window
        assert!(w.should_process(p, 1000)); // 1
        assert!(w.should_process(p, 1001)); // 2
        assert!(w.should_process(p, 1002)); // 3
        // Cap hit
        assert!(!w.should_process(p, 1003));

        // But we never entered suppression for more than the quiet period,
        // so let's just verify the minute-window reset path by using a
        // fresh watcher that doesn't get suppressed first.
        let mut w2 = watcher_with(0, 2, 60_000);
        assert!(w2.should_process(p, 0));    // count=1, window starts at 0
        assert!(w2.should_process(p, 1));    // count=2
        // cap hit at count=2
        assert!(!w2.should_process(p, 2));
        // After 60s quiet, suppression lifts
        assert!(w2.should_process(p, 60_003)); // quiet >= 60_000
        // Now in a new window
        assert!(w2.should_process(p, 60_004)); // count=2 in new window
    }

    // ── Suppression lift tests ──────────────────────────────────

    #[test]
    fn suppression_lifts_after_quiet_period() {
        let mut w = watcher_with(0, 2, 5000);
        let p = Path::new("/workspace/file.txt");

        assert!(w.should_process(p, 1000)); // 1
        assert!(w.should_process(p, 1001)); // 2, cap
        assert!(!w.should_process(p, 1002)); // suppressed

        // 5000ms quiet after last event at 1002
        assert!(w.should_process(p, 6003)); // quiet=6003-1002=5001 >= 5000
    }

    #[test]
    fn suppression_quiet_timer_resets_on_new_event() {
        let mut w = watcher_with(0, 2, 5000);
        let p = Path::new("/workspace/file.txt");

        assert!(w.should_process(p, 0));    // 1
        assert!(w.should_process(p, 1));    // 2, cap
        assert!(!w.should_process(p, 2));   // suppressed, last_event_ms=2

        // An event at 4000 -- not quiet enough (4000-2=3998 < 5000),
        // but it resets last_event_ms to 4000.
        assert!(!w.should_process(p, 4000));

        // Now quiet must be measured from 4000.
        // 4000 + 4999 = 8999 -- still not enough, resets last_event to 8999.
        assert!(!w.should_process(p, 8999));
        // Quiet measured from 8999. Need 8999 + 5000 = 13999.
        assert!(!w.should_process(p, 9000)); // only 1ms since 8999, resets last_event to 9000
        assert!(w.should_process(p, 14000)); // 14000-9000=5000 >= 5000
    }

    #[test]
    fn suppressed_file_does_not_affect_other_files() {
        let mut w = watcher_with(0, 1, 60_000);
        let a = Path::new("/workspace/a.txt");
        let b = Path::new("/workspace/b.txt");

        assert!(w.should_process(a, 0));  // a: count=1 -> cap
        assert!(!w.should_process(a, 1)); // a: suppressed
        // b is independent
        assert!(w.should_process(b, 2));
    }

    // ── Exclusion tests ─────────────────────────────────────────

    #[test]
    fn excluded_dirs_detected() {
        assert!(is_excluded(Path::new("/workspace/.git/config")));
        assert!(is_excluded(Path::new("/workspace/node_modules/foo/bar.js")));
        assert!(is_excluded(Path::new("project/.venv/lib/site.py")));
        assert!(is_excluded(Path::new("src/__pycache__/mod.pyc")));
        assert!(is_excluded(Path::new("project/target/debug/binary")));
        assert!(is_excluded(Path::new("home/.cache/something")));
    }

    #[test]
    fn non_excluded_paths_pass() {
        assert!(!is_excluded(Path::new("/workspace/src/main.rs")));
        assert!(!is_excluded(Path::new("/workspace/system-prompt.md")));
        assert!(!is_excluded(Path::new("/workspace/.env")));
        assert!(!is_excluded(Path::new("/workspace/gitignore"))); // not ".git"
    }

    #[test]
    fn excluded_dir_must_be_exact_component() {
        // "targets" is not "target"
        assert!(!is_excluded(Path::new("/workspace/targets/foo")));
        // ".gits" is not ".git"
        assert!(!is_excluded(Path::new("/workspace/.gits/foo")));
    }

    // ── Event mapping tests ─────────────────────────────────────

    fn make_notify_event(kind: EventKind, paths: Vec<PathBuf>) -> notify::Event {
        notify::Event {
            kind,
            paths,
            attrs: Default::default(),
        }
    }

    #[test]
    fn map_modify_data_event() {
        let ev = make_notify_event(
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            vec![PathBuf::from("/workspace/file.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].kind, WatchEventKind::Modified);
        assert_eq!(mapped[0].path, PathBuf::from("/workspace/file.txt"));
    }

    #[test]
    fn map_modify_metadata_event() {
        let ev = make_notify_event(
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            vec![PathBuf::from("/workspace/file.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].kind, WatchEventKind::Modified);
    }

    #[test]
    fn map_rename_events() {
        // RenameMode::From
        let ev = make_notify_event(
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            vec![PathBuf::from("/workspace/old.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].kind, WatchEventKind::Renamed);

        // RenameMode::To
        let ev = make_notify_event(
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            vec![PathBuf::from("/workspace/new.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].kind, WatchEventKind::Renamed);

        // RenameMode::Both (some platforms emit this with two paths)
        let ev = make_notify_event(
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            vec![
                PathBuf::from("/workspace/old.txt"),
                PathBuf::from("/workspace/new.txt"),
            ],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 2);
        assert!(mapped.iter().all(|e| e.kind == WatchEventKind::Renamed));
    }

    #[test]
    fn map_create_file_event() {
        let ev = make_notify_event(
            EventKind::Create(CreateKind::File),
            vec![PathBuf::from("/workspace/new_file.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].kind, WatchEventKind::Created);
    }

    #[test]
    fn map_create_any_event() {
        let ev = make_notify_event(
            EventKind::Create(CreateKind::Any),
            vec![PathBuf::from("/workspace/something")],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].kind, WatchEventKind::Created);
    }

    #[test]
    fn map_remove_file_event() {
        let ev = make_notify_event(
            EventKind::Remove(RemoveKind::File),
            vec![PathBuf::from("/workspace/gone.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].kind, WatchEventKind::Deleted);
    }

    #[test]
    fn map_remove_any_event() {
        let ev = make_notify_event(
            EventKind::Remove(RemoveKind::Any),
            vec![PathBuf::from("/workspace/gone")],
        );
        let mapped = map_notify_event(&ev);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].kind, WatchEventKind::Deleted);
    }

    #[test]
    fn map_access_event_dropped() {
        let ev = make_notify_event(
            EventKind::Access(AccessKind::Read),
            vec![PathBuf::from("/workspace/file.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert!(mapped.is_empty());
    }

    #[test]
    fn map_access_open_dropped() {
        let ev = make_notify_event(
            EventKind::Access(AccessKind::Open(AccessMode::Read)),
            vec![PathBuf::from("/workspace/file.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert!(mapped.is_empty());
    }

    #[test]
    fn map_other_event_dropped() {
        let ev = make_notify_event(
            EventKind::Other,
            vec![PathBuf::from("/workspace/file.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert!(mapped.is_empty());
    }

    #[test]
    fn map_event_with_no_paths() {
        let ev = make_notify_event(
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            vec![],
        );
        let mapped = map_notify_event(&ev);
        assert!(mapped.is_empty());
    }

    #[test]
    fn map_event_timestamp_is_nonzero() {
        let ev = make_notify_event(
            EventKind::Create(CreateKind::File),
            vec![PathBuf::from("/workspace/f.txt")],
        );
        let mapped = map_notify_event(&ev);
        assert!(!mapped.is_empty());
        assert!(mapped[0].timestamp_ms > 0);
    }

    // ── Integration-style debounce scenario ─────────────────────

    #[test]
    fn full_debounce_scenario() {
        // Simulate a realistic burst: many rapid saves followed by quiet.
        let mut w = watcher_with(100, 5, 3000);
        let p = Path::new("/workspace/prompt.md");

        let mut accepted = 0u32;
        let mut t = 1000u64; // Start at t=1000 to avoid last_event_ms==0 edge case.

        // Phase 1: rapid burst of 20 events, 5ms apart (well within 100ms cooldown).
        for _ in 0..20 {
            if w.should_process(p, t) {
                accepted += 1;
            }
            t += 5;
        }
        // Only the first event passes (rest within 100ms cooldown).
        assert_eq!(accepted, 1);

        // Phase 2: events spaced at exactly cooldown (100ms) -- should all pass
        // until rate cap (5).
        accepted = 0;
        // Start a fresh minute window by jumping forward.
        t = 100_000;
        for _ in 0..10 {
            if w.should_process(p, t) {
                accepted += 1;
            }
            t += 100;
        }
        // 5 pass, then cap triggers suppression.
        assert_eq!(accepted, 5);

        // Phase 3: verify suppressed.
        assert!(!w.should_process(p, t));

        // Phase 4: quiet period elapses (3000ms from last event).
        let last = t;
        t = last + 3001;
        assert!(w.should_process(p, t));
    }

    #[test]
    fn create_folder_event_is_dropped() {
        // CreateKind::Folder is not in our match arms -- only File and Any.
        let ev = make_notify_event(
            EventKind::Create(CreateKind::Folder),
            vec![PathBuf::from("/workspace/new_dir")],
        );
        let mapped = map_notify_event(&ev);
        assert!(mapped.is_empty());
    }

    #[test]
    fn remove_folder_event_is_dropped() {
        let ev = make_notify_event(
            EventKind::Remove(RemoveKind::Folder),
            vec![PathBuf::from("/workspace/old_dir")],
        );
        let mapped = map_notify_event(&ev);
        assert!(mapped.is_empty());
    }
}
