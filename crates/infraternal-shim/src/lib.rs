//! Long-lived local PTY sessions with frozen v1 resume semantics [13][17].
//!
//! Unsafe code is confined to the audited PTY/process and Ghostty FFI boundaries; data modules
//! forbid it. Each boundary documents descriptor, pointer and fork invariants.
#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod ended;
pub mod frame;
mod locale;
mod pty;
pub mod ring;

/// Resolve locale variables for a scrubbed login shell [#161].
///
/// The host locale files and installed locale list are read once per caller
/// process, so a long-lived session launcher does not repeat discovery per PTY.
#[must_use]
pub fn session_locale_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    locale::environment()
}

/// Restore default child signal policy before exec, without changing the parent.
/// Attach this before any caller-specific pre-exec setup.
pub fn prepare_child(command: &mut std::process::Command) {
    pty::prepare_child(command);
}

/// Apply child signal policy and close the trusted fd3 before direct exec.
/// This avoids an intermediate shell changing `/proc/self/exe` for anonymous images.
pub fn prepare_child_without_control(command: &mut std::process::Command) {
    pty::prepare_child_without_control(command);
}

/// Apply the same default child signal policy to a POSIX spawn launcher.
/// # Errors
/// Returns errors while configuring the spawn attributes, before spawning.
pub fn prepare_spawn(attributes: &mut nix::spawn::PosixSpawnAttr) -> nix::Result<()> {
    attributes.set_sigmask(&nix::sys::signal::SigSet::empty())?;
    attributes.set_sigdefault(&nix::sys::signal::SigSet::all())?;
    attributes.set_flags(
        attributes.flags()?
            | nix::spawn::PosixSpawnFlags::POSIX_SPAWN_SETSIGMASK
            | nix::spawn::PosixSpawnFlags::POSIX_SPAWN_SETSIGDEF,
    )
}

/// Double-fork and setsid startup for hosts without an init scope.
/// Call only during single-threaded startup, before threads or PTYs exist.
/// # Errors
/// Returns syscall failures during detachment.
pub fn detach() -> std::io::Result<bool> {
    pty::detach()
}
#[cfg(all(test, feature = "process-per-user"))]
#[path = "../tests/unit/heap_accounting.rs"]
mod heap_accounting;
mod session;
mod terminal;
#[cfg(feature = "process-per-user")]
mod terminal_limits;
#[cfg(feature = "process-per-user")]
mod terminal_memory;
mod terminal_native;
pub use session::{Config, run, run_with_retention};

#[cfg(feature = "ca-handoff")]
pub mod locked_bytes;

/// Open the kernel lifetime descriptor for an authenticated Linux shim [D81].
/// No signals or ptrace permissions are requested. The caller owns registration
/// and must revalidate process identity to exclude PID reuse during opening.
/// # Errors
/// Returns invalid PID, unsupported-kernel, permission or descriptor-limit errors.
#[cfg(target_os = "linux")]
pub fn process_exit_descriptor(pid: u32) -> std::io::Result<std::os::fd::OwnedFd> {
    pty::process_exit_descriptor(pid)
}
#[cfg(feature = "ca-handoff")]
pub mod openssl_secure;

#[cfg(feature = "process-per-user")]
pub use session::user_host::{run_host, run_host_accounted};

#[cfg(feature = "process-per-user")]
pub use pty::handoff::{receive_masters, send_masters};
