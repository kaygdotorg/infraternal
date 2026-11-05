//! Dispatches the fixed-shape internal SSH helper commands before the public CLI parser (D243, #189).
//!
//! `__ssh-connect <host> <port>` and `__ssh-session --state <dir> [--session <uuid>]`
//! are spawned only by this binary with exactly these shapes. Matching them
//! here keeps two hidden subcommands out of the generated public parser; any
//! other shape is refused with the usage status, never reinterpreted.

use std::{ffi::OsString, process::ExitCode};

/// Run an internal SSH helper when argv names one; `None` leaves argv to the CLI.
pub(crate) fn run_if_requested() -> Option<ExitCode> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next()?;
    let command = first.to_str()?;
    // Public invocations keep their arguments with the public parser. Only a
    // recognized private helper needs an owned argument list.
    if !recognizes(command) {
        return None;
    }
    let args: Vec<OsString> = arguments.collect();
    match command {
        #[cfg(feature = "ssh")]
        "__ssh-connect" => Some(connect(&args).unwrap_or(ExitCode::from(2))),
        "__ssh-session" => Some(session(&args).unwrap_or(ExitCode::from(2))),
        _ => None,
    }
}

fn recognizes(command: &str) -> bool {
    // The initiating executable supplies ProxyCommand. Uploaded session images
    // never dial SSH, so they must not retain its resolver or descriptor handoff.
    command == "__ssh-session" || (cfg!(feature = "ssh") && command == "__ssh-connect")
}

#[cfg(feature = "ssh")]
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

#[cfg(target_os = "linux")]
fn session(args: &[OsString]) -> Option<ExitCode> {
    let options = infraternal_plugin_ssh::session_bridge::Options::decode(args)?;
    Some(if options.run().is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// SSH sessions run in the Linux session daemon, which macOS does not build
/// (#320). The shape stays recognized so it is refused, not parsed as public.
#[cfg(not(target_os = "linux"))]
fn session(_args: &[OsString]) -> Option<ExitCode> {
    Some(ExitCode::FAILURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn connector_is_available_only_on_the_initiating_build() {
        assert!(recognizes("__ssh-session"));
        assert_eq!(recognizes("__ssh-connect"), cfg!(feature = "ssh"));
        assert!(!recognizes("__ssh-connect-extra"));
    }

    #[test]
    #[cfg(feature = "ssh")]
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
