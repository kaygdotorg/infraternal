//! Delta review of SIGINT disposition and output ownership for #239 (D299/D303/D305).
//! Disposable subprocesses isolate signal masks from the parallel test runner.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    io::Read,
    os::fd::AsFd,
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
    time::Duration,
};

use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::signal::{SigSet, Signal, raise};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_infraternal");
const FIXTURE: &str = "INFRATERNAL_REVIEW_R3_SIGNAL";

/// Exercise the pending-interrupt fixture in an otherwise ordinary test process.
#[test]
fn signal_fixture() {
    let Ok(mode) = std::env::var(FIXTURE) else {
        return;
    };
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGINT);
    blocked.thread_block().unwrap();
    infraternal_shim::exit_on_interrupt(b"{\"error\":\"interrupted\"}\n".to_vec());
    if mode == "final" {
        infraternal_shim::begin_final_output();
    }
    raise(Signal::SIGINT).unwrap();
    blocked.thread_unblock().unwrap();
    if mode == "final" {
        println!("{{\"result\":true}}");
        infraternal_shim::finish_final_output();
    }
    std::process::exit(42);
}

/// Run the signal fixture with the default foreground signal disposition.
fn fixture(mode: &str) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "signal_fixture", "--nocapture"])
        .env(FIXTURE, mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Concurrent Cargo invocations may run as background jobs, whose children
    // inherit SIG_IGN. The fixture must start with SIGINT enabled to test its handler.
    infraternal_shim::prepare_child(&mut command);
    let mut child = command.spawn().unwrap();
    drop(command);
    let mut completed = [PollFd::new(
        child.stdout.as_ref().unwrap().as_fd(),
        PollFlags::POLLHUP,
    )];
    assert_eq!(
        poll(&mut completed, 5000_u16).unwrap(),
        1,
        "signal fixture did not exit"
    );
    let status = child.wait().unwrap();
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

/// A pending SIGINT before final output emits one notice and ends by the signal.
#[test]
fn a_pending_blocked_interrupt_emits_notice_and_terminates_by_sigint() {
    let output = fixture("before");
    assert_eq!(output.status.signal(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("{\"error\":\"interrupted\"}").count(), 1);
}

/// A pending SIGINT during final output keeps the result whole and ends by the signal.
#[test]
fn a_pending_interrupt_during_final_output_preserves_result_and_sigint_status() {
    let output = fixture("final");
    assert_eq!(output.status.signal(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("{\"result\":true}").count(), 1);
    assert!(!stdout.contains("interrupted"), "{stdout}");
}

#[test]
fn inherited_ignored_sigint_stays_ignored_during_cli_output() {
    // An asynchronous shell command inherits SIG_IGN. A full pipe holds the CLI in its
    // final write, after handler installation, without relying on startup scheduling.
    let (mut reader, writer) = std::io::pipe().unwrap();
    nix::fcntl::fcntl(&writer, nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096)).unwrap();
    let mut child = Command::new("sh")
        .args(["-c", "trap '' INT; exec \"$@\"", "review-r3", BIN])
        .args(["skill", "server", "init", "--json"])
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut prefix = [0_u8; 1];
    reader.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix[0], b'{');
    assert!(child.try_wait().unwrap().is_none());
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap()),
        Signal::SIGINT,
    )
    .unwrap();
    // Let the signal run while the writer remains blocked; this is a functional race fixture.
    std::thread::sleep(Duration::from_millis(100));
    let mut rest = String::new();
    reader.read_to_string(&mut rest).unwrap();
    let status = child.wait().unwrap();
    let stdout = format!("{}{rest}", char::from(prefix[0]));
    let envelope: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert!(
        status.success(),
        "inherited SIG_IGN was replaced: {status:?}"
    );
}
