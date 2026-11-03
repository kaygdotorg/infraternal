//! Long-lived local PTY sessions with frozen v1 resume semantics [13][17].
//!
//! Unsafe code is confined to the audited PTY/process, parent-bound child, readiness and Ghostty FFI boundaries;
//! data modules forbid it. Each boundary documents descriptor, pointer and fork invariants.
#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
mod child;
#[cfg(feature = "host-login")]
mod cleanup;
#[cfg(feature = "host-diagnostics")]
mod host_trace;
// All arguments disappear from normal builds, including timestamp calls.
macro_rules! trace_host {
    ($stage:ident, $session:expr, $fd:expr, $offset:expr, $bytes:expr) => {
        trace_host!($stage, $session, $fd, $offset, $bytes, 0);
    };
    ($stage:ident, $session:expr, $fd:expr, $offset:expr, $bytes:expr, $extra:expr) => {
        #[cfg(feature = "host-diagnostics")]
        crate::host_trace::record(
            crate::host_trace::Stage::$stage,
            $session,
            $fd,
            $offset,
            $bytes,
            $extra,
        );
    };
}
pub mod ended;
pub mod frame;
mod locale;
#[cfg(feature = "host-login")]
pub mod login;
#[cfg(feature = "host-login")]
pub mod login_handoff;
#[cfg(feature = "host-login")]
pub mod login_ready;
mod pty;
#[cfg(feature = "async-fd")]
pub mod readiness;
pub mod ring;
mod shell_startup;
pub mod startup;

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

/// Whether atomic replacement would drop extended attributes, including access-control lists.
/// # Errors
/// Returns the kernel metadata-query error. Callers refuse replacement when present.
pub fn startup_file_has_attributes(file: &std::fs::File) -> std::io::Result<bool> {
    pty::file_has_attributes(file)
}

/// Transfer a pinned process directory through an owned child descriptor.
/// Return its child-local path, avoiding cross-process inspection of a
/// nondumpable parent and collisions with Command's private exec-error pipe.
/// # Errors
/// Refuses an invalid pin or descriptor duplication failure.
#[cfg(feature = "host-login")]
pub fn inherit_login_process(
    command: &mut std::process::Command,
    process: &std::fs::File,
) -> std::io::Result<std::path::PathBuf> {
    pty::inherit_login_process(command, process)
}

/// Keep the inherited process pin private to this shim and explicit proxy execs.
/// # Errors
/// Returns a descriptor-policy error when reserved descriptor 5 is absent.
#[cfg(feature = "host-login")]
pub fn protect_login_process() -> std::io::Result<()> {
    pty::protect_login_process()
}

/// Keep a dynamic inherited process pin private to the shim after startup.
/// External controller-held paths require no child descriptor-policy change.
/// # Errors
/// Rejects malformed child-local descriptor paths or descriptor-policy errors.
#[cfg(feature = "host-login")]
pub fn protect_login_process_at(path: &std::path::Path) -> std::io::Result<()> {
    pty::protect_login_process_at(path)
}

/// Apply child signal policy and close the trusted fd3 before direct exec.
/// This avoids an intermediate shell changing `/proc/self/exe` for anonymous images.
pub fn prepare_child_without_control(command: &mut std::process::Command) {
    pty::prepare_child_without_control(command);
}

/// Ensure a Linux child exits if its infraternal owner exits before the child.
///
/// The pre-exec boundary installs the parent-death signal before checking the
/// parent identity, closing the fork-to-exec race within the audited shim.
#[cfg(target_os = "linux")]
pub fn prepare_parent_bound_child(command: &mut std::process::Command) {
    pty::prepare_parent_bound_child(command);
}

/// Prepare a proxy child with descriptor-only access and a dedicated rootful identity.
///
/// Descriptors are duplicated to reserved child slots before credentials are dropped. The
/// working directory is entered while the parent still has permission to traverse its path.
/// # Errors
/// Rejects invalid descriptor mappings; operating-system setup errors are returned by spawn.
#[cfg(unix)]
pub fn prepare_proxy_child(
    command: &mut std::process::Command,
    working_directory: &std::fs::File,
    descriptors: &[(std::os::fd::RawFd, std::os::fd::RawFd)],
    identity: Option<(u32, u32)>,
) -> std::io::Result<()> {
    pty::prepare_proxy_child(command, working_directory, descriptors, identity)
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

/// Exclude the borrowed leg-B descriptor at exec and reset child signal state.
/// Unlike closing fd3 before exec, CLOEXEC preserves a possible spawn-error
/// pipe using that slot. The caller keeps ownership of its original descriptor.
pub fn prepare_isolated_child(command: &mut std::process::Command) {
    pty::prepare_isolated_child(command);
}

/// Establish a controller-owned child's independent session before fresh exec.
/// Standard handles must be configured by the caller; no parent-death signal
/// is installed. Only async-signal-safe syscalls run between fork and exec.
pub fn prepare_independent_session(command: &mut std::process::Command) {
    pty::prepare_independent_session(command);
}

/// Double-fork and setsid startup for hosts without an init scope.
/// Call only during single-threaded startup, before threads or PTYs exist.
/// # Errors
/// Returns syscall failures during detachment.
pub fn detach() -> std::io::Result<bool> {
    pty::detach()
}
/// Width in columns of the terminal on standard output, or `None` when it is not a terminal.
/// The CLI sizes its tables from this before it falls back to `$COLUMNS`.
#[must_use]
pub fn stdout_columns() -> Option<u16> {
    pty::stdout_columns()
}
/// Make SIGINT write `notice` to standard output, restore the default SIGINT action and re-raise
/// the signal (the CLI's one-envelope contract in JSON mode, D305/#239).
pub fn exit_on_interrupt(notice: Vec<u8>) {
    pty::exit_on_interrupt(notice);
}

/// Tell the SIGINT handler that the final JSON result is about to be written.
pub fn begin_final_output() {
    pty::begin_final_output();
}

/// Tell the SIGINT handler that the final JSON result has finished writing.
pub fn finish_final_output() {
    pty::finish_final_output();
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
#[cfg(feature = "host-login")]
pub use session::{run_with_login_group, run_with_prestarted_login};

#[cfg(feature = "ca-handoff")]
pub mod locked_bytes;

#[cfg(all(test, feature = "host-login"))]
#[path = "../tests/unit/login_lifecycle.rs"]
mod login_lifecycle;
/// Open the kernel lifetime descriptor for an authenticated Linux shim [D81].
/// No signals or ptrace permissions are requested. The caller owns registration
/// and must revalidate process identity to exclude PID reuse during opening.
/// # Errors
/// Returns invalid PID, unsupported-kernel, permission or descriptor-limit errors.
#[cfg(target_os = "linux")]
pub fn process_exit_descriptor(pid: u32) -> std::io::Result<std::os::fd::OwnedFd> {
    pty::process_exit_descriptor(pid)
}
/// Signal the process behind a descriptor from [`process_exit_descriptor`].
/// A PID reused after the named process exited is never signalled.
/// # Errors
/// Returns `ESRCH` once the process has exited, or a permission error.
#[cfg(target_os = "linux")]
pub fn signal_process_descriptor(
    process: std::os::fd::BorrowedFd<'_>,
    signal: nix::sys::signal::Signal,
) -> std::io::Result<()> {
    pty::signal_process_descriptor(process, signal)
}
#[cfg(feature = "ca-handoff")]
pub mod openssl_secure;

#[cfg(feature = "process-per-user")]
pub use session::user_host::{run_host, run_host_accounted};

#[cfg(feature = "process-per-user")]
pub use pty::handoff::{receive_masters, send_masters};

#[cfg(all(test, feature = "process-per-user"))]
#[path = "../tests/unit/fixture_state.rs"]
mod fixture_state;
