//! When someone last typed or attached a terminal, for the update quiet window (#211 S4, D251).
//!
//! D251 applies a staged update only "in a quiet window (the server is idle for a few
//! minutes: no typing, no attach in progress)". The terminal input and attach paths
//! call [`note`]. The updater asks [`idle_for`] how long it has been since then.
//!
//! **Cost.** [`note`] runs on every terminal input frame. It reads the coarse monotonic
//! clock (a vDSO read with no system call, a few nanoseconds) and does one relaxed
//! atomic store. Nothing waits on it and nothing is allocated.
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

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
}
