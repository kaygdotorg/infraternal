//! Runs only the verified shim and SSH bridge, sharing startup and replay with the installed host (D255).
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::{io, process::ExitCode};

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

fn harden_startup() -> nix::Result<()> {
    // Exec resets dumpability; close it before parsing or opening private state.
    nix::sys::prctl::set_dumpable(false)?;
    nix::sys::prctl::set_name(c"infraternal")
}

enum Invocation {
    Shim(infraternal_shim::startup::Options),
    Bridge(infraternal_plugin_ssh::session_bridge::Options),
}

impl Invocation {
    fn run(self) -> io::Result<()> {
        match self {
            Self::Shim(options) => options.run(),
            Self::Bridge(options) => options.run_image(),
        }
    }
}

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
