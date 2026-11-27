//! The one-test-at-a-time lock of the server's auth tests, with a limit on how long a test may keep it (#596).
//!
//! Many tests share process-wide budgets (for example two Argon2 slots) and take turns through one lock. A test that
//! never finishes therefore stops every test queued behind it, and the whole test run with them: one gate sat idle for
//! an hour that way. A future cannot be abandoned from outside while its runtime may be blocked or its clock paused,
//! so the limit is kept by a plain thread: when it expires, the thread names the test on stderr and stops the test
//! binary. Cargo reports that binary as failed and the run goes on.

use std::{
    io::Write,
    sync::mpsc::{self, RecvTimeoutError},
    time::Duration,
};
use tokio::sync::{Mutex, MutexGuard};

/// How long one test may keep the lock. Only a hang bound, set far above honest tests, because a false stop costs a
/// whole gate. The slowest holder, the Mesh snapshot headroom test, took 54 to 119 s in full runs on a build host at
/// load 10 to 30, and a busier host is slower still. The tests' own waits end long before this, so they report first
/// with a better message.
const HOLD_LIMIT: Duration = Duration::from_mins(15);

/// A fair async lock whose holder is watched; see the module documentation.
pub(crate) struct SerialLock(Mutex<()>);

/// Proof of holding a [`SerialLock`]. Dropping it stands the watching thread down and lets the next test in.
pub(crate) struct SerialGuard<'a> {
    /// Declared before the lock so the watch ends before the next holder starts.
    _watch: Option<HoldWatch>,
    _lock: MutexGuard<'a, ()>,
}

impl SerialLock {
    /// A free lock, usable in a `static`.
    pub(crate) const fn new() -> Self {
        Self(Mutex::const_new(()))
    }

    /// Wait for a turn, then hold it for at most [`HOLD_LIMIT`]. Waiting does not count. Use this in every test that
    /// runs in the ordinary suite.
    pub(crate) async fn lock(&self) -> SerialGuard<'_> {
        let lock = self.0.lock().await;
        SerialGuard {
            _watch: Some(HoldWatch::start(HOLD_LIMIT, stop_the_test_binary)),
            _lock: lock,
        }
    }

    /// Wait for a turn and hold it without a limit. Only for `#[ignore]`d measurements and soaks, which a person starts
    /// by name and which may run for as long as their settings ask.
    pub(crate) async fn lock_for_measurement(&self) -> SerialGuard<'_> {
        SerialGuard {
            _lock: self.0.lock().await,
            _watch: None,
        }
    }
}

/// A thread that calls `expired` with the starting thread's name (libtest names it after the test) unless this value is
/// dropped within the limit.
struct HoldWatch(
    /// Never sent on: dropping it wakes the watching thread at once.
    #[allow(dead_code)]
    mpsc::Sender<()>,
);

impl HoldWatch {
    /// Start watching the current thread's test for `limit`.
    fn start(limit: Duration, expired: impl FnOnce(&str) + Send + 'static) -> Self {
        let (release, released) = mpsc::channel();
        let test = std::thread::current()
            .name()
            .unwrap_or("unnamed test")
            .to_owned();
        std::thread::spawn(move || {
            if released.recv_timeout(limit) == Err(RecvTimeoutError::Timeout) {
                expired(&test);
            }
        });
        Self(release)
    }
}

/// Report the stuck test and end the process. `eprintln!` would go to the test's captured output, which dies with the
/// process, so this writes to the real stderr.
fn stop_the_test_binary(test: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "\nHUNG TEST: {test} held the auth test lock for more than {} s; stopping this test binary (#596)",
        HOLD_LIMIT.as_secs()
    );
    std::process::abort();
}

/// The watch itself, with short limits and a report channel in place of stopping the process.
#[cfg(test)]
mod tests {
    use super::*;

    /// A test that keeps the lock past its limit is reported by name.
    #[test]
    fn an_overdue_holder_is_named() {
        let (report, reported) = mpsc::channel();
        let _watch = HoldWatch::start(Duration::from_millis(1), move |test| {
            report.send(test.to_owned()).unwrap();
        });
        let name = reported
            .recv_timeout(Duration::from_secs(30))
            .expect("the watch never expired");
        assert!(name.ends_with("an_overdue_holder_is_named"), "{name}");
    }

    /// A released lock is never reported: the watching thread ends and drops its report channel unused.
    #[test]
    fn a_released_holder_is_not_reported() {
        let (report, reported) = mpsc::channel::<()>();
        drop(HoldWatch::start(Duration::from_secs(600), move |_| {
            report.send(()).unwrap();
        }));
        assert_eq!(
            reported.recv_timeout(Duration::from_secs(30)),
            Err(RecvTimeoutError::Disconnected)
        );
    }
}
