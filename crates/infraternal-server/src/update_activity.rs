//! When someone last typed or attached a terminal, for the update quiet window (#211 S4, D251).
//!
//! D251 applies a staged update only "in a quiet window (the server is idle for a few
//! minutes: no typing, no attach in progress)". The terminal input and attach paths
//! call [`note`]. The updater asks [`idle_for`] how long it has been since then.
//!
//! **Frozen during a switch (J1085).** From the moment the server starts the D295
//! database copy until it execs the new release, terminal input, attach and open are
//! refused ([`frozen`]): the socket closes, and the browser keeps its unacknowledged
//! input and sends it again to the next process. Otherwise input acknowledged after
//! the copy would be rewound by an undo while the shim keeps the newer cursor, and
//! the session would refuse to reattach.
//!
//! **Cost.** [`note`] runs on every terminal input frame. It reads the coarse monotonic
//! clock (a vDSO read with no system call, a few nanoseconds) and does one relaxed
//! atomic store. Nothing waits on it and nothing is allocated.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(feature = "release", test))]
use std::time::Duration;

/// Set while an update switch is between its database copy and its exec.
static FROZEN: AtomicBool = AtomicBool::new(false);

/// Refuse (or admit again) terminal input, attach and open for an update switch.
#[cfg(any(feature = "release", test))]
pub(crate) fn freeze(frozen: bool) {
    FROZEN.store(frozen, Ordering::Relaxed);
}

/// Whether terminal input, attach and open must be refused now (see the module docs).
#[must_use]
pub(crate) fn frozen() -> bool {
    FROZEN.load(Ordering::Relaxed)
}

/// The coarse monotonic second of the last terminal input or attach; 0 means none yet.
static LAST: AtomicU64 = AtomicU64::new(0);

/// The coarse monotonic clock in whole seconds (never 0, so 0 can mean "never").
fn seconds() -> u64 {
    #[cfg(target_os = "linux")]
    let clock = nix::time::ClockId::CLOCK_MONOTONIC_COARSE;
    #[cfg(not(target_os = "linux"))]
    let clock = nix::time::ClockId::CLOCK_MONOTONIC;
    nix::time::clock_gettime(clock)
        .ok()
        .and_then(|now| u64::try_from(now.tv_sec()).ok())
        .unwrap_or(0)
        .max(1)
}

/// Record terminal activity now: a keystroke or other input frame, or an attach.
pub(crate) fn note() {
    LAST.store(seconds(), Ordering::Relaxed);
}

/// How long the server has been quiet: the time since the last [`note`], or since the
/// process started its clock when nothing was noted yet.
#[cfg(any(feature = "release", test))]
#[must_use]
pub(crate) fn idle_for() -> Duration {
    let last = LAST.load(Ordering::Relaxed);
    Duration::from_secs(seconds().saturating_sub(last))
}

/// Unit checks for the quiet-window clock.
#[cfg(test)]
mod tests {
    use super::*;

    /// A note resets the idle time to (about) zero; without new notes it only grows.
    #[test]
    fn a_note_resets_the_idle_time() {
        note();
        assert!(idle_for() <= Duration::from_secs(1));
        let first = idle_for();
        assert!(idle_for() >= first);
    }

    /// The switch freeze is on only between `freeze(true)` and `freeze(false)`.
    #[test]
    fn the_switch_freeze_turns_on_and_off() {
        assert!(!frozen());
        freeze(true);
        assert!(frozen());
        freeze(false);
        assert!(!frozen());
    }
}
