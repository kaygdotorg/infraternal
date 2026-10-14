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

#[test]
fn unresponsive_native_pixel_reader_obeys_operation_deadline() {
    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::mpsc, time::Duration};

    let root =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| PathBuf::from("target"), PathBuf::from);
    let dir = root.join(format!("desktop-native-deadline-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("native-fixture.py");
    fs::write(
        &executable,
        r"#!/usr/bin/env python3
# Role: emulate a native framework child that has stopped draining its input.
import os, signal, sys
with open(sys.argv[0] + '.pid', 'w') as output:
    output.write(str(os.getpid()))
signal.pause()
",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
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
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    let root =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| PathBuf::from("target"), PathBuf::from);
    let dir = root.join(format!("desktop-native-ordering-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let executable = dir.join("native-fixture.py");
    fs::write(
        &executable,
        r"#!/usr/bin/env python3
# Role: withhold the first reply until a subsequent command arrives.
import struct, sys
source = sys.stdin.buffer
sink = sys.stdout.buffer
def request():
    prefix = source.read(4)
    if len(prefix) != 4:
        sys.exit(0)
    length, = struct.unpack('>I', prefix)
    body = source.read(length)
    if len(body) != length:
        sys.exit(0)
request()
request()
sink.write(struct.pack('>IBB', 4, 1, 65) + b'{}')
sink.write(struct.pack('>IBB', 4, 1, 68) + b'{}')
sink.flush()
",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
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
