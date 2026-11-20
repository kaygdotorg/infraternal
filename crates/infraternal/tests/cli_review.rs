//! Independent break-it review of the CLI overhaul (#239, D202, D299, D303, D304).
//!
//! Every test here states what the contract says and FAILS on the reviewed head, so the
//! failure is the finding. None of them changes state on the machine: they run in a throw-away
//! HOME, with option values that fail at the parser or before any socket is touched.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    io::Read,
    os::{
        fd::AsFd,
        unix::{fs::PermissionsExt, net::UnixListener, process::ExitStatusExt},
    },
    process::{Command, Output, Stdio},
    time::Duration,
};

use nix::poll::{PollFd, PollFlags, poll};
use serde_json::Value;

fn home(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cli-review-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cli(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("NO_COLOR")
        .stdin(Stdio::null())
        .output()
        .expect("run the real CLI")
}

fn stdout_lines(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
        .collect()
}

/// Run `args` on a pseudo-terminal (through `script`), so the CLI believes it has a terminal.
fn on_terminal(home: &std::path::Path, env: &[(&str, &str)], args: &[&str]) -> Option<String> {
    let line = format!("{} {}", env!("CARGO_BIN_EXE_infraternal"), args.join(" "));
    let mut command = Command::new("script");
    command
        .args(["-qec", &line, "/dev/null"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env_remove("NO_COLOR")
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ---- colour and terminal ---------------------------------------------------------------

#[test]
fn a_dumb_terminal_gets_neither_colour_nor_marks() {
    let home = home("dumb");
    let Some(text) = on_terminal(&home, &[("TERM", "dumb")], &["status"]) else {
        return;
    };
    assert!(
        !text.contains('\u{1b}'),
        "TERM=dumb got ANSI escapes: {text:?}"
    );
    assert!(
        !text.contains(['●', '○', '✕']),
        "TERM=dumb got marks: {text:?}"
    );
}

#[test]
fn an_empty_no_color_is_ignored() {
    // https://no-color.org: only a NON-EMPTY value turns colour off. The parser's own errors
    // already follow that, so the two halves of one binary must agree.
    let home = home("nocolor-empty");
    let Some(ours) = on_terminal(&home, &[("TERM", "xterm"), ("NO_COLOR", "")], &["status"]) else {
        return;
    };
    let Some(parser) = on_terminal(&home, &[("TERM", "xterm"), ("NO_COLOR", "")], &["bogus"])
    else {
        return;
    };
    assert_eq!(
        ours.contains('\u{1b}'),
        parser.contains('\u{1b}'),
        "status and the parser disagree about NO_COLOR=\"\""
    );
}

// ---- JSON envelope ---------------------------------------------------------------------

#[test]
fn a_failing_command_in_json_mode_prints_exactly_one_envelope() {
    // `agent join` reads its invitation from stdin; with none it fails before any network call.
    let home = home("one-envelope");
    let output = cli(
        &home,
        &["--json", "agent", "join", "https://example.invalid/enroll"],
    );
    assert_ne!(output.status.code(), Some(0));
    assert_eq!(
        stdout_lines(&output).len(),
        1,
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn json_help_and_version_are_envelopes_too() {
    let home = home("json-help");
    for args in [["--json", "--help"], ["status", "--help"]] {
        let mut args = args.to_vec();
        args.push("--json");
        let output = cli(&home, &args);
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            serde_json::from_str::<Value>(text.lines().next().unwrap_or("")).is_ok(),
            "{args:?} printed non-JSON on stdout: {text:.80}"
        );
    }
}

/// Reap the disposable CLI even when request readiness or interrupt handling fails.
struct InterruptChild(std::process::Child);

impl Drop for InterruptChild {
    /// Close out the owned subprocess on both successful and panicking test paths.
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Interrupt an accepted request and require one complete JSON envelope and SIGINT termination.
#[test]
fn ctrl_c_in_json_mode_ends_with_an_interrupted_envelope_and_exit_130() {
    // A local socket that accepts the call and never answers keeps `mesh status` waiting.
    let home = home("sigint");
    let state = home.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(state.join("plugins.sock")).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_infraternal"));
    command
        .args([
            "--json",
            "mesh",
            "status",
            "--state",
            state.to_str().unwrap(),
        ])
        .env("HOME", &home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Background test runners inherit SIG_IGN, which the CLI correctly preserves.
    // This fixture models a foreground command without changing the runner's signals.
    infraternal_shim::prepare_child(&mut command);
    let mut child = InterruptChild(command.spawn().unwrap());
    // Receiving request bytes proves startup and handler installation have finished.
    // These timeouts only bound a broken fixture; they do not assert startup speed.
    let mut incoming = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
    assert_eq!(poll(&mut incoming, 5000_u16).unwrap(), 1, "no CLI request");
    let (mut request, _) = listener.accept().unwrap();
    request
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    request.read_exact(&mut [0_u8; 1]).unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
        nix::sys::signal::Signal::SIGINT,
    )
    .unwrap();
    // HUP arrives when the CLI closes stdout on exit. Wait for that event rather
    // than sleeping or consuming a partial envelope before the process finishes.
    let mut completed = [PollFd::new(
        child.0.stdout.as_ref().unwrap().as_fd(),
        PollFlags::POLLHUP,
    )];
    assert_eq!(
        poll(&mut completed, 5000_u16).unwrap(),
        1,
        "still running after SIGINT"
    );
    let code = child.0.wait().unwrap();
    let mut out = String::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    // A shell reports 130 for SIGINT termination; a direct process wait sees signal 2.
    assert_eq!(code.signal(), Some(2), "unexpected end: {code:?}");
    let envelope: Value = serde_json::from_str(&out)
        .unwrap_or_else(|_| panic!("JSON mode must say it was interrupted; stdout was {out:?}"));
    assert_eq!(envelope["error"]["code"], "interrupted");
}

// ---- exit codes (D303) -----------------------------------------------------------------

#[test]
fn an_unknown_skill_is_not_found_exit_4() {
    let home = home("skill-missing");
    let output = cli(&home, &["skill", "no-such-command", "--json"]);
    assert_eq!(output.status.code(), Some(4), "D303: 4 not found");
}

#[test]
fn a_malformed_host_id_is_a_usage_error_exit_2() {
    let home = home("bad-uuid");
    let output = cli(
        &home,
        &[
            "remove-host",
            "--server",
            "https://example.invalid",
            "not-a-uuid",
            "--json",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "D303: a wrong command line is 2"
    );
}

#[test]
fn status_is_not_down_when_the_service_manager_cannot_be_asked() {
    // `status` exits 5 only for installed-but-down. With no service manager to ask, the
    // state is unknown: the report may say so, but it must not claim a service is down.
    let home = home("status-unknown");
    let units = home.join("config/systemd/user");
    std::fs::create_dir_all(&units).unwrap();
    std::fs::write(
        units.join("infraternal-agent.service"),
        "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(["status", "--json"])
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("PATH", "/nonexistent")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_ne!(
        output.status.code(),
        Some(5),
        "an unanswerable service manager is not a service that is down: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_missing_runtime_directory_is_not_called_a_bad_reply() {
    // No XDG_RUNTIME_DIR: the CLI cannot find the infraternal agent. It must say that, not
    // that "it sent a reply this command does not understand", and it is "off or unreachable".
    let home = home("no-runtime");
    let output = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(["mesh", "status", "--json"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/nonexistent")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("sent a reply"), "{text}");
    assert_eq!(output.status.code(), Some(5), "{text}");
}

// ---- words and values ------------------------------------------------------------------

#[test]
fn user_facing_text_never_says_agent_alone() {
    // CLAUDE.md vocabulary: "agent" alone is forbidden where it could mean either kind.
    let home = home("vocabulary");
    let loose = home.join("loose");
    std::fs::create_dir_all(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
    let missing = home.join("missing");
    for state in [&missing, &loose] {
        let output = cli(
            &home,
            &["mesh", "status", "--state", state.to_str().unwrap()],
        );
        let text = String::from_utf8_lossy(&output.stderr).to_lowercase();
        for (at, _) in text.match_indices("agent") {
            let before = &text[..at];
            assert!(
                before.ends_with("infraternal ") || before.ends_with("ai "),
                "bare \"agent\" in: {text}"
            );
        }
    }
}

#[test]
fn a_usage_error_in_text_mode_does_not_echo_the_odd_input() {
    // The JSON path drops values on purpose (usage.rs); people at a terminal see them in clap's
    // own text, and that text is logged by shells and CI. Values must not be echoed there either.
    let home = home("echo");
    let output = cli(&home, &["https://user:SECRETTOKEN@example.invalid/x"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRETTOKEN"));
}

// ---- help accuracy and layout ----------------------------------------------------------

#[test]
fn a_subcommand_does_not_advertise_options_it_ignores() {
    let home = home("help-inherited");
    for args in [
        ["server", "setup-token", "--help"],
        ["server", "channel", "--help"],
    ] {
        let output = cli(&home, &args);
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            !text.contains("--tls-cert") && !text.contains("--remote-listen"),
            "{args:?} lists server options that it silently ignores"
        );
    }
}

#[test]
fn root_help_fits_80_columns() {
    let home = home("help-width");
    let output = cli(&home, &["--help"]);
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        assert!(
            line.chars().count() <= 80,
            "{} columns: {line}",
            line.chars().count()
        );
    }
}

#[test]
fn root_help_lists_server_init() {
    let home = home("help-server-init");
    let output = cli(&home, &["--help"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.lines().any(|line| line.contains("server init")),
        "top-level help should expose the first server setup command"
    );
}

#[test]
fn a_dry_run_plan_keeps_its_line_breaks() {
    let home = home("dry-run");
    let output = cli(&home, &["server", "init", "--dry-run"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !text
            .lines()
            .any(|line| line.contains("[Service]") && line.contains("Type=simple")),
        "the unit file was reflowed into prose:\n{text}"
    );
}

#[test]
fn a_group_with_one_command_says_so_in_the_singular() {
    let home = home("plural");
    let output = cli(&home, &["server", "release"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("has 1 commands"), "{text}");
}

// ---- repository hygiene ----------------------------------------------------------------

#[test]
fn no_compiled_python_is_tracked() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("git")
        .args(["ls-files", "*.pyc", "*__pycache__*"])
        .current_dir(root)
        .output()
        .unwrap();
    let list = String::from_utf8_lossy(&output.stdout);
    assert!(list.trim().is_empty(), "committed build output:\n{list}");
}
