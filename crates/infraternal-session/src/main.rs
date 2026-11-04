//! Runs only the verified shim and SSH bridge, sharing startup and replay with the installed host (D255).
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::{io, process::ExitCode};

/// Entry point of the private session image.
///
/// The image is started with a private first argument that selects one
/// role, `__shim` or `__ssh-session`.
/// Anything else is refused before any state is opened, so this binary can
/// never act as the operator-facing CLI.
///
/// Exit codes: `0` when the selected role ran to completion, `2` when the
/// arguments do not select a role, `1` when hardening or the role failed.
/// Diagnostics are fixed strings on purpose: private paths and terminal
/// bytes must never reach stderr.
fn main() -> ExitCode {
    if harden_startup().is_err() {
        return ExitCode::FAILURE;
    }
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let Some(invocation) = invocation(&arguments) else {
        eprintln!("Invalid session startup arguments");
        return ExitCode::from(2);
    };
    if invocation.run().is_ok() {
        ExitCode::SUCCESS
    } else {
        // Neither private paths nor terminal bytes belong in diagnostics.
        eprintln!("Session startup failed");
        ExitCode::FAILURE
    }
}

/// Marks the process non-dumpable and names it `infraternal`.
///
/// Must run first, before arguments are parsed or private state is opened:
/// `exec` resets the dumpable flag, so a fresh image starts out dumpable and
/// could otherwise be inspected through ptrace or a core file while it holds
/// session secrets. Returns the `prctl` error if either call fails, and the
/// caller then exits without doing any work.
fn harden_startup() -> nix::Result<()> {
    // Exec resets dumpability; close it before parsing or opening private state.
    nix::sys::prctl::set_dumpable(false)?;
    nix::sys::prctl::set_name(c"infraternal")
}

/// The one role this image was asked to play, with its decoded options.
enum Invocation {
    /// `__shim`: host a session's pseudo-terminal and replay buffer.
    Shim(infraternal_shim::startup::Options),
    /// `__ssh-session`: run the SSH bridge for a session.
    Bridge(infraternal_plugin_ssh::session_bridge::Options),
}

impl Invocation {
    /// Runs the selected role until it finishes. Blocks the calling thread.
    /// Errors are returned without detail; `main` prints a fixed message.
    fn run(self) -> io::Result<()> {
        match self {
            Self::Shim(options) => options.run(),
            Self::Bridge(options) => options.run_image(),
        }
    }
}

/// Picks the role from the arguments after the program name.
///
/// The first argument must be exactly `__shim` or `__ssh-session`; the rest is
/// handed to that role's own decoder. Returns `None` for no arguments, an
/// unknown command, or options the role refuses, so malformed requests never
/// start a role.
fn invocation(arguments: &[std::ffi::OsString]) -> Option<Invocation> {
    let (command, arguments) = arguments.split_first()?;
    if command == "__shim" {
        return infraternal_shim::startup::Options::spawned(arguments).map(Invocation::Shim);
    }
    if command == "__ssh-session" {
        return infraternal_plugin_ssh::session_bridge::Options::decode(arguments)
            .map(Invocation::Bridge);
    }
    None
}

#[cfg(test)]
mod tests {
    //! Private entrypoints refuse operator and malformed startup requests before side effects.
    use super::*;

    #[test]
    fn unsupported_commands_cannot_start_operator_roles_or_open_state() {
        for arguments in [
            &[][..],
            &["server", "init"],
            &["agent", "run"],
            &["__ssh-connect", "host", "22"],
            &["__ssh-session"],
            &[
                "__ssh-session",
                "--state",
                "/unused",
                "--session",
                "invalid",
            ],
            &["__shim", "--session", "invalid"],
        ] {
            let arguments: Vec<_> = arguments.iter().map(std::ffi::OsString::from).collect();
            assert!(invocation(&arguments).is_none());
        }
    }

    #[test]
    fn fresh_exec_closes_dumpability_before_private_startup() {
        const NAME: &str = "tests::fresh_exec_closes_dumpability_before_private_startup";
        if std::env::var_os("INFRATERNAL_DUMP_TEST").is_some() {
            harden_startup().unwrap();
            assert!(!nix::sys::prctl::get_dumpable().unwrap());
            return;
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME])
            .env("INFRATERNAL_DUMP_TEST", "1")
            .stdin(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(result.success());
    }
}
