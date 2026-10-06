//! Owns long-lived PTY sessions across browser drops and agent upgrades [13].
//!
//! PTY syscalls will need audited unsafe blocks. Unsafe code remains denied here
//! until those syscalls exist, and each future block must document its safety
//! invariant and receive focused review.
#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod frame;
pub mod ring;
// The PTY API is wired into the session pump in the next implementation step.
#[allow(dead_code)]
mod pty;
/// Double-fork and setsid startup for hosts without an init scope.
/// Call only during single-threaded startup, before threads or PTYs exist.
/// # Errors
/// Returns syscall failures during detachment.
pub fn detach() -> std::io::Result<bool> {
    pty::detach()
}
// Repaint state becomes reachable through the following session implementation.
#[allow(dead_code)]
mod terminal;
