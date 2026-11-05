//! Long-lived local PTY sessions with frozen v1 resume semantics [13][17].
//!
//! Unsafe code is confined to the audited PTY/process, parent-bound child, readiness and Ghostty FFI boundaries;
//! data modules forbid it. Each boundary documents descriptor, pointer and fork invariants.
#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
#[cfg(target_os = "linux")]
mod child;
#[cfg(all(feature = "host-login", target_os = "linux"))]
mod cleanup;
#[cfg(all(feature = "host-diagnostics", target_os = "linux"))]
mod host_trace;
// All arguments disappear from normal builds, including timestamp calls.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
mod locale;
#[cfg(all(feature = "host-login", target_os = "linux"))]
pub mod login;
#[cfg(all(feature = "host-login", target_os = "linux"))]
pub mod login_handoff;
#[cfg(feature = "host-login")]
pub mod login_ready;
#[cfg(target_os = "linux")]
mod pty;
#[cfg(feature = "async-fd")]
pub mod readiness;
pub mod ring;
#[cfg(target_os = "linux")]
mod shell_startup;
pub mod startup;

// The shared daemon API is compiled on Darwin, but its Linux PTY/session
// implementation is not. These inert compatibility hooks keep unrelated CLI
// and agent code type-checking; actual Darwin child/session policy stays out of
// this slice and remains tracked in #300.

/// Resolve locale variables for a scrubbed login shell [#161].
///
/// The host locale files and installed locale list are read once per caller
/// process, so a long-lived session launcher does not repeat discovery per PTY.
#[must_use]
#[cfg(target_os = "linux")]
pub fn session_locale_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    locale::environment()
}

/// Restore default child signal policy before exec, without changing the parent.
/// Attach this before any caller-specific pre-exec setup.
#[cfg(target_os = "linux")]
pub fn prepare_child(command: &mut std::process::Command) {
    pty::prepare_child(command);
}
#[cfg(target_os = "macos")]
pub fn prepare_child(_command: &mut std::process::Command) {}

/// Whether atomic replacement would drop extended attributes, including access-control lists.
/// # Errors
/// Returns the kernel metadata-query error. Callers refuse replacement when present.
#[cfg(target_os = "linux")]
pub fn startup_file_has_attributes(file: &std::fs::File) -> std::io::Result<bool> {
    pty::file_has_attributes(file)
}
#[cfg(target_os = "macos")]
pub fn startup_file_has_attributes(_file: &std::fs::File) -> std::io::Result<bool> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Transfer a pinned process directory through an owned child descriptor.
/// Return its child-local path, avoiding cross-process inspection of a
/// nondumpable parent and collisions with Command's private exec-error pipe.
/// # Errors
/// Refuses an invalid pin or descriptor duplication failure.
#[cfg(all(feature = "host-login", target_os = "linux"))]
pub fn inherit_login_process(
    command: &mut std::process::Command,
    process: &std::fs::File,
) -> std::io::Result<std::path::PathBuf> {
    pty::inherit_login_process(command, process)
}

/// Keep the inherited process pin private to this shim and explicit proxy execs.
/// # Errors
/// Returns a descriptor-policy error when reserved descriptor 5 is absent.
#[cfg(all(feature = "host-login", target_os = "linux"))]
pub fn protect_login_process() -> std::io::Result<()> {
    pty::protect_login_process()
}

/// Keep a dynamic inherited process pin private to the shim after startup.
/// External controller-held paths require no child descriptor-policy change.
/// # Errors
/// Rejects malformed child-local descriptor paths or descriptor-policy errors.
#[cfg(all(feature = "host-login", target_os = "linux"))]
pub fn protect_login_process_at(path: &std::path::Path) -> std::io::Result<()> {
    pty::protect_login_process_at(path)
}

/// Apply child signal policy and close the trusted fd3 before direct exec.
/// This avoids an intermediate shell changing `/proc/self/exe` for anonymous images.
#[cfg(target_os = "linux")]
pub fn prepare_child_without_control(command: &mut std::process::Command) {
    pty::prepare_child_without_control(command);
}
#[cfg(target_os = "macos")]
pub fn prepare_child_without_control(_command: &mut std::process::Command) {}

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
/// With `cgroup_procs` (an open, write-only `cgroup.procs` of the child's own leaf), the child
/// moves itself into that cgroup first, before it can exec or fork, so nothing it starts is
/// ever outside the leaf. The caller keeps the file open until spawn returns.
/// # Errors
/// Rejects invalid descriptor mappings; operating-system setup errors are returned by spawn.
#[cfg(target_os = "linux")]
pub fn prepare_proxy_child(
    command: &mut std::process::Command,
    working_directory: &std::fs::File,
    descriptors: &[(std::os::fd::RawFd, std::os::fd::RawFd)],
    identity: Option<(u32, u32)>,
    cgroup_procs: Option<&std::fs::File>,
) -> std::io::Result<()> {
    pty::prepare_proxy_child(
        command,
        working_directory,
        descriptors,
        identity,
        cgroup_procs,
    )
}
/// Darwin has no audited descriptor and identity boundary for the proxy child
/// yet, so the proxy cannot start one there. This fails at spawn setup instead
/// of starting a child with the parent's descriptors and credentials.
/// # Errors
/// Always `Unsupported`.
#[cfg(target_os = "macos")]
pub fn prepare_proxy_child(
    _command: &mut std::process::Command,
    _working_directory: &std::fs::File,
    _descriptors: &[(std::os::fd::RawFd, std::os::fd::RawFd)],
    _identity: Option<(u32, u32)>,
) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
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
#[cfg(target_os = "linux")]
pub fn prepare_isolated_child(command: &mut std::process::Command) {
    pty::prepare_isolated_child(command);
}
#[cfg(target_os = "macos")]
pub fn prepare_isolated_child(_command: &mut std::process::Command) {}

/// Establish a controller-owned child's independent session before fresh exec.
/// Standard handles must be configured by the caller; no parent-death signal
/// is installed. Only async-signal-safe syscalls run between fork and exec.
#[cfg(target_os = "linux")]
pub fn prepare_independent_session(command: &mut std::process::Command) {
    pty::prepare_independent_session(command);
}
#[cfg(target_os = "macos")]
pub fn prepare_independent_session(_command: &mut std::process::Command) {}

/// Double-fork and setsid startup for hosts without an init scope.
/// Call only during single-threaded startup, before threads or PTYs exist.
/// # Errors
/// Returns syscall failures during detachment.
#[cfg(target_os = "linux")]
pub fn detach() -> std::io::Result<bool> {
    pty::detach()
}
#[cfg(target_os = "macos")]
pub fn detach() -> std::io::Result<bool> {
    Err(std::io::ErrorKind::Unsupported.into())
}
/// Width in columns of the terminal on standard output, or `None` when it is not a terminal.
/// The CLI sizes its tables from this before it falls back to `$COLUMNS`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn stdout_columns() -> Option<u16> {
    pty::stdout_columns()
}
#[cfg(target_os = "macos")]
#[must_use]
pub fn stdout_columns() -> Option<u16> {
    None
}
/// Make SIGINT write `notice` to standard output, restore the default SIGINT action and re-raise
/// the signal (the CLI's one-envelope contract in JSON mode, D305/#239).
#[cfg(target_os = "linux")]
pub fn exit_on_interrupt(notice: Vec<u8>) {
    pty::exit_on_interrupt(notice);
}
#[cfg(target_os = "macos")]
pub fn exit_on_interrupt(_notice: Vec<u8>) {}

/// Restore SIGTERM's default action and re-raise it, after a process handled
/// SIGTERM to finish its shutdown steps (#221).
#[cfg(target_os = "linux")]
pub fn terminate_by_default() -> ! {
    pty::terminate_by_default()
}

/// Tell the SIGINT handler that the final JSON result is about to be written.
#[cfg(target_os = "linux")]
pub fn begin_final_output() {
    pty::begin_final_output();
}
#[cfg(target_os = "macos")]
pub fn begin_final_output() {}

/// Tell the SIGINT handler that the final JSON result has finished writing.
#[cfg(target_os = "linux")]
pub fn finish_final_output() {
    pty::finish_final_output();
}
#[cfg(target_os = "macos")]
pub fn finish_final_output() {}
#[cfg(all(test, feature = "process-per-user"))]
#[path = "../tests/unit/heap_accounting.rs"]
mod heap_accounting;
#[cfg(target_os = "linux")]
mod session;
#[cfg(target_os = "linux")]
mod terminal;
#[cfg(all(feature = "process-per-user", target_os = "linux"))]
mod terminal_limits;
#[cfg(all(feature = "process-per-user", target_os = "linux"))]
mod terminal_memory;
#[cfg(target_os = "linux")]
mod terminal_native;
#[cfg(target_os = "linux")]
pub use session::{Config, run, run_with_retention};
#[cfg(all(feature = "host-login", target_os = "linux"))]
pub use session::{run_with_login_group, run_with_prestarted_login};

#[cfg(all(feature = "ca-handoff", target_os = "linux"))]
pub mod locked_bytes;

#[cfg(all(test, feature = "host-login", target_os = "linux"))]
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

#[cfg(all(feature = "process-per-user", target_os = "linux"))]
pub use session::user_host::{run_host, run_host_accounted};

#[cfg(all(feature = "process-per-user", target_os = "linux"))]
pub use pty::handoff::{receive_masters, send_masters};

#[cfg(all(test, feature = "process-per-user", target_os = "linux"))]
#[path = "../tests/unit/fixture_state.rs"]
mod fixture_state;
