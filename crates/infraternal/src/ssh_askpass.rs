//! Answers only the scoped OpenSSH askpass socket protocol; no async runtime, diagnostics or secret argv [23].

use std::process::ExitCode;

pub(crate) fn run() -> ExitCode {
    if infraternal_plugin_ssh::credentials::askpass_reply().is_ok() {
        ExitCode::SUCCESS
    } else {
        // stdout belongs exclusively to OpenSSH's private reply pipe.
        ExitCode::FAILURE
    }
}
