//! Answers only the scoped OpenSSH askpass socket protocol; no async runtime, diagnostics or secret argv [23].

use std::process::ExitCode;

pub(crate) fn run() -> ExitCode {
    // This private SSH helper never imports CA material. Its parent verifies
    // the exact executable through /proc, requiring the existing dumpable
    // helper policy. Detach stdin before restoring that policy; retain the
    // executable/direct-parent checks rather than weakening authorization.
    let detached = std::fs::File::open("/dev/null")
        .and_then(|null| nix::unistd::dup2_stdin(null).map_err(std::io::Error::from));
    if detached.is_err() {
        let _ = nix::unistd::close(0);
        return ExitCode::FAILURE;
    }
    if !allow_parent_inspection() {
        return ExitCode::FAILURE;
    }

    if infraternal_plugin_ssh::credentials::askpass_reply().is_ok() {
        ExitCode::SUCCESS
    } else {
        // stdout belongs exclusively to OpenSSH's private reply pipe.
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
/// Whether the askpass parent check can read the caller; macOS has no /proc, so it refuses.
///
/// Becoming dumpable is what lets the parent read our /proc entry, but it would
/// also let a crash write a core file holding the secret this helper relays.
/// A hard core limit of 0 is set first (#559 L2). The kernel enforces it only
/// for core files it writes itself: when `core_pattern` pipes dumps to a
/// handler, the kernel ignores the limit (core(5)), and the root-owned
/// handler (systemd-coredump, apport) is trusted to honour the limit it is
/// given and not store the dump.
fn allow_parent_inspection() -> bool {
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0).is_ok()
        && nix::sys::prctl::set_dumpable(true).is_ok()
}

/// The parent's executable check reads /proc, which macOS lacks, so it could
/// never authorize this helper there: refuse before connecting (#320).
#[cfg(not(target_os = "linux"))]
fn allow_parent_inspection() -> bool {
    false
}
