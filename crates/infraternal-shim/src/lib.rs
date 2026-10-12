//! Long-lived local PTY sessions with frozen v1 resume semantics [13][17].
//!
//! Unsafe code is confined to the audited PTY/process and Ghostty FFI boundaries; data modules
//! forbid it. Each boundary documents descriptor, pointer and fork invariants.
#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod ended;
pub mod frame;
mod pty;
pub mod ring;

/// Restore default child signal policy before exec, without changing the parent.
/// Attach this before any caller-specific pre-exec setup.
pub fn prepare_child(command: &mut std::process::Command) {
    pty::prepare_child(command);
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
mod session;
mod terminal;
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
