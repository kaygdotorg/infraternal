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
    if nix::sys::prctl::set_dumpable(true).is_err() {
        return ExitCode::FAILURE;
    }

    if infraternal_plugin_ssh::credentials::askpass_reply().is_ok() {
        ExitCode::SUCCESS
    } else {
        // stdout belongs exclusively to OpenSSH's private reply pipe.
        ExitCode::FAILURE
    }
}
