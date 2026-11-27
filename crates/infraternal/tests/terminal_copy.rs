//! Pins common CLI refusals on a terminal and a pipe, including the JSON seam.

#![cfg(all(
    target_os = "linux",
    feature = "remote",
    feature = "plugin-mesh",
    feature = "plugin-server"
))]
#![allow(clippy::expect_used)] // A fixture that cannot start must fail the test.

use std::{
    fs::File,
    io::{self, Read as _},
    process::{Command, Stdio},
};

/// Use a real terminal configuration without inheriting the build account's locale.
fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_infraternal"));
    cmd.args(args)
        .env("TERM", "xterm-256color")
        .env("LC_ALL", "C.UTF-8")
        .env("COLUMNS", "100")
        .env("NO_COLOR", "1");
    cmd
}

/// Capture the CLI from a PTY, merging its two output streams.
fn terminal(mut cmd: Command) -> (i32, String) {
    let pair = nix::pty::openpty(
        Some(&nix::pty::Winsize {
            ws_row: 28,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )
    .expect("allocate PTY");
    let reader = File::from(pair.master);
    let writer = File::from(pair.slave);
    let mut child = cmd
        .stdout(Stdio::from(writer.try_clone().expect("clone PTY writer")))
        .stderr(Stdio::from(writer))
        .spawn()
        .expect("start infraternal");
    drop(cmd);
    let mut output = Vec::new();
    // Linux returns EIO at PTY EOF after the child closes the last slave fd.
    if let Err(error) = (&reader).read_to_end(&mut output) {
        assert_eq!(error.raw_os_error(), Some(nix::libc::EIO), "{error}");
    }
    let status = child.wait().expect("wait for infraternal");
    (
        status.code().expect("normal exit"),
        String::from_utf8(output)
            .expect("UTF-8 CLI output")
            .replace("\r\n", "\n"),
    )
}

/// Usage mistakes are safe to log and point to help for the command being used.
#[test]
fn common_commands_have_plain_and_terminal_refusal_goldens() {
    for path in [
        &["status"][..],
        &["up"],
        &["mesh", "peers"],
        &["server", "init"],
        &["agent", "join"],
        &["sign-in"],
    ] {
        let mut args = path.to_vec();
        args.push("--bad-option=private-test-value");
        let full = format!("infraternal {}", path.join(" "));
        let follow_up = format!("See the available options with {full} --help.");
        let plain = format!("Unknown option --bad-option.\n\n- {follow_up}\n");
        let output = command(&args).output().expect("run with redirected output");
        assert_eq!(output.status.code(), Some(2), "{full}");
        assert!(output.stdout.is_empty(), "{full}");
        assert_eq!(output.stderr, plain.as_bytes(), "{full}");

        let (status, text) = terminal(command(&args));
        assert_eq!(status, 2, "{full}");
        let expected = format!("✕ Unknown option --bad-option.\n\n• {follow_up}\n");
        assert_eq!(text, expected, "{full}");

        args.push("--json");
        let output = command(&args).output().expect("run with JSON");
        assert_eq!(output.status.code(), Some(2), "{full}");
        assert!(output.stderr.is_empty(), "{full}");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
        assert_eq!(
            json["message"],
            format!("{full} has no option --bad-option.")
        );
        assert_eq!(json["next_step"], format!("{full} --help"));
        assert_eq!(json["error"]["argument"], "--bad-option");
    }
}

/// An ASCII locale or a dumb terminal uses the same copy and markers as a pipe.
#[test]
fn unsupported_terminals_use_ascii_copy() -> io::Result<()> {
    let args = ["status", "--bad-option"];
    let plain = command(&args).output()?;
    for (variable, value) in [("TERM", "dumb"), ("LC_ALL", "C")] {
        let mut run = command(&args);
        run.env(variable, value);
        assert_eq!(
            terminal(run),
            (2, String::from_utf8_lossy(&plain.stderr).into_owned())
        );
    }
    Ok(())
}
