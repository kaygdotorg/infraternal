//! Fault-injection review of private companion I/O deadlines using real pipes [D203,#146].
#![cfg(feature = "desktop")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

// Exercise the production stdio owner on Linux; its implementation uses only
// portable process/pipe APIs, although its usual caller is macOS-only.
use infraternal_plugin_desktop::protocol;
#[allow(dead_code)]
#[path = "../src/native.rs"]
mod native;

/// Publish an existing executable without opening its inode for writing. Parallel
/// child launches can inherit a transient writer until exec closes it; keeping
/// fixture code read-only avoids that executable-publication race altogether.
/// Exclusive directories also keep an earlier run's PID receipt out of this run.
fn fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::{fs, io, os::unix::fs::DirBuilderExt, path::PathBuf};
    let root =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| PathBuf::from("target"), PathBuf::from);
    fs::create_dir_all(&root).unwrap();
    let mut attempt = 0_u64;
    loop {
        let dir = root.join(format!(
            "desktop-native-{name}-{}-{attempt}",
            std::process::id()
        ));
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {
                let executable = dir.join(name);
                let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/native-pipe-faults.py");
                std::os::unix::fs::symlink(source, &executable).unwrap();
                return (dir, executable);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                attempt = attempt.checked_add(1).expect("fixture namespace exhausted");
            }
            Err(error) => panic!("cannot create private native fixture: {error}"),
        }
    }
}

#[test]
fn unresponsive_native_pixel_reader_obeys_operation_deadline() {
    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use std::{fs, sync::mpsc, time::Duration};

    let (dir, executable) = fixture("pixel-reader.py");
    let mut companion = native::Native::spawn(&executable).unwrap();
    let pid_file = executable.with_extension("py.pid");
    let ready_deadline = std::time::Instant::now() + Duration::from_secs(3);
    let pid = loop {
        if let Ok(text) = fs::read_to_string(&pid_file)
            && let Ok(pid) = text.parse::<i32>()
        {
            break Pid::from_raw(pid);
        }
        assert!(
            std::time::Instant::now() < ready_deadline,
            "fixture did not start"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let (sent, received) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let result = companion.encode(&vec![0; 512 * 512 * 4], 512, 512, 1, true);
        let _ = sent.send(result);
    });
    // Allow one second beyond the documented three-second companion timeout.
    // Terminate the fixture before joining so a failed deadline cannot hang CI.
    let completed = received.recv_timeout(Duration::from_secs(4));
    let _ = kill(pid, Signal::SIGKILL);
    writer.join().unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert!(
        completed.is_ok(),
        "native encode remains blocked past its deadline when the child does not read pixels"
    );
    assert!(
        completed.unwrap().is_err(),
        "unresponsive child must return an error"
    );
}

#[test]
fn timed_out_native_reply_cannot_answer_the_next_command() {
    use std::fs;
    let (dir, executable) = fixture("reply-ordering.py");
    let mut companion = native::Native::spawn(&executable).unwrap();
    let first = companion.call(protocol::Kind::List, b"{}");
    let second = companion.call(protocol::Kind::Status, b"{}");
    drop(companion);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(first.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    // Either retire the failed companion or preserve reply correlation. Accepting
    // the old inventory as a new status response shifts subsequent side effects.
    assert!(
        second
            .as_ref()
            .map_or(true, |(kind, _)| *kind == protocol::Kind::State),
        "status received a superseded inventory reply: {second:?}"
    );
}
