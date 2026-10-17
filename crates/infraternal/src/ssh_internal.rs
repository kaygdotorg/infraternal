//! Dispatches the fixed-shape internal SSH helper commands before the public CLI parser (D243, #189).
//!
//! `__ssh-connect <host> <port>` and `__ssh-session --state <dir> [--session <uuid>]`
//! are spawned only by this binary with exactly these shapes. Matching them
//! here keeps two hidden subcommands out of the generated public parser; any
//! other shape is refused with the usage status, never reinterpreted.

use std::{ffi::OsString, process::ExitCode};

/// Run an internal SSH helper when argv names one; `None` leaves argv to the CLI.
pub(crate) fn run_if_requested() -> Option<ExitCode> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let command = args.first()?.to_str()?;
    match command {
        "__ssh-connect" => Some(connect(&args[1..]).unwrap_or(ExitCode::from(2))),
        #[cfg(feature = "remote")]
        "__ssh-session" => Some(session(&args[1..]).unwrap_or(ExitCode::from(2))),
        _ => None,
    }
}

fn connect(args: &[OsString]) -> Option<ExitCode> {
    let [host, port] = args else { return None };
    let host = host.to_str()?;
    let port = port.to_str()?.parse::<u16>().ok()?;
    if infraternal_plugin_ssh::socket_connector::handoff(host, port, &std::io::stdin()).is_ok() {
        Some(ExitCode::SUCCESS)
    } else {
        // Fixed transport classification only; no endpoint or raw error.
        eprintln!("ssh: connect to host: Connection failed");
        Some(ExitCode::FAILURE)
    }
}

#[cfg(feature = "remote")]
fn session(args: &[OsString]) -> Option<ExitCode> {
    let (state, session) = match args {
        [flag, state] if flag == "--state" => (state, None),
        [flag, state, option, id] if flag == "--state" && option == "--session" => {
            (state, Some(uuid::Uuid::parse_str(id.to_str()?).ok()?))
        }
        _ => return None,
    };
    Some(crate::ssh_session::run(state.into(), session))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn connect_requires_exactly_a_host_and_numeric_port() {
        for invalid in [
            &[][..],
            &["host"],
            &["host", "port"],
            &["host", "22", "x"],
            &["host", "70000"],
        ] {
            assert!(connect(&os(invalid)).is_none(), "{invalid:?}");
        }
    }

    #[cfg(feature = "remote")]
    #[test]
    fn session_accepts_only_the_two_spawned_shapes() {
        for invalid in [
            &[][..],
            &["--state"],
            &["--session", "x", "--state", "/s"],
            &["--state", "/s", "--session", "not-a-uuid"],
            &["--state", "/s", "--session"],
            &["--state", "/s", "--extra", "x"],
        ] {
            assert!(session(&os(invalid)).is_none(), "{invalid:?}");
        }
    }
}
