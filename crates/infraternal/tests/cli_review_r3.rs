//! Delta review of SIGINT disposition and output ownership for #239 (D299/D303/D305).
//! Disposable subprocesses isolate signal masks from the parallel test runner.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    io::Read,
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
    time::Duration,
};

use nix::sys::signal::{SigSet, Signal, raise};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_infraternal");
const FIXTURE: &str = "INFRATERNAL_REVIEW_R3_SIGNAL";

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

fn fixture(mode: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "signal_fixture", "--nocapture"])
        .env(FIXTURE, mode)
        .output()
        .unwrap()
}

#[test]
fn a_pending_blocked_interrupt_emits_notice_and_terminates_by_sigint() {
    let output = fixture("before");
    assert_eq!(output.status.signal(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("{\"error\":\"interrupted\"}").count(), 1);
}

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
