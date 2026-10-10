//! Real login shell, socket replay, bounded flow control and init survival tests [13][41].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_shim::frame::{Decoder, Frame};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Session {
    state: PathBuf,
    id: String,
    child: Option<Child>,
    pid: u32,
}
impl Session {
    fn new(ring: usize, detach: bool) -> Self {
        Self::start(ring, detach, None)
    }
    fn start(ring: usize, detach: bool, units: Option<(&str, &str)>) -> Self {
        Self::start_retention(ring, detach, units, 600_000)
    }
    fn start_retention(
        ring: usize,
        detach: bool,
        units: Option<(&str, &str)>,
        retention_ms: u64,
    ) -> Self {
        let counter = NEXT.fetch_add(1, Ordering::Relaxed);
        let id = format!("{:016x}{counter:016x}", std::process::id());
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/session-bounds/t{}-{counter}",
            std::process::id()
        ));
        let mut command = if let Some((parent, scope)) = units {
            let mut command = Command::new("systemd-run");
            command.args(["--user","--quiet","--unit",parent,"--property","KillMode=control-group","--working-directory"])
                .arg(std::env::current_dir().unwrap())
                .arg(format!("--setenv=ZDOTDIR={}/tests/profile",env!("CARGO_MANIFEST_DIR")))
                .args(["/bin/sh","-c","scope=$1; shift; systemd-run --user --quiet --scope --unit=\"$scope\" \"$@\" & wait","shim-parent",scope,env!("CARGO_BIN_EXE_infraternal")]);
            command
        } else if detach {
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "\"$@\"; exec sleep 300",
                "shim-parent",
                env!("CARGO_BIN_EXE_infraternal"),
            ]);
            command
        } else {
            Command::new(env!("CARGO_BIN_EXE_infraternal"))
        };
        command
            .env(
                "ZDOTDIR",
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/profile"),
            )
            .args([
                "__shim",
                "--session",
                &id,
                "--uid",
                &nix::unistd::Uid::effective().as_raw().to_string(),
                "--cols",
                "200",
                "--rows",
                "60",
                "--ring-capacity",
                &ring.to_string(),
                "--state",
            ])
            .arg(&state);
        command
            .arg("--exit-retention-ms")
            .arg(retention_ms.to_string());
        if detach {
            command.arg("--detach");
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut session = Self {
            state,
            id,
            child: Some(child),
            pid: 0,
        };
        let mut peer = session.connect();
        if let Frame::Hello { pid, .. } = read(&mut peer) {
            session.pid = pid;
        } else {
            panic!("no Hello");
        }
        session
    }
    fn path(&self) -> PathBuf {
        self.state
            .join("sessions")
            .join(format!("{}.sock", self.id))
    }
    fn connect(&self) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match UnixStream::connect(self.path()) {
                Ok(peer) => {
                    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    peer.set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    return peer;
                }
                Err(e) => {
                    assert!(Instant::now() < deadline, "shim socket: {e}");
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
    fn attach(&self, seq: u64) -> UnixStream {
        let mut peer = self.connect();
        assert!(matches!(read(&mut peer), Frame::Hello { version: 1, .. }));
        send(&mut peer, Frame::Attach(0));
        send(&mut peer, Frame::ReadFrom(seq));
        peer
    }
    fn finish(&mut self, mut peer: UnixStream, mut seq: u64) {
        send(&mut peer, Frame::Input(b"exit 7\n".to_vec()));
        loop {
            match read(&mut peer) {
                Frame::Output(offset, bytes) => {
                    assert_eq!(offset, seq);
                    seq += bytes.len() as u64;
                }
                Frame::Exited(status, final_seq) => {
                    assert_eq!(status, 7);
                    assert_eq!(seq, final_seq);
                    break;
                }
                frame => panic!("unexpected {frame:?}"),
            }
        }
        drop(peer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.path().exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        if let Some(child) = &mut self.child {
            assert!(child.wait().unwrap().success());
        }
        self.pid = 0;
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if self.pid != 0 {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(self.pid).unwrap()),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.state);
    }
}
/// Read the shim's current output offset without attaching a viewer.
fn output_head(session: &Session) -> u64 {
    let mut probe = session.connect();
    let Frame::Hello { head, .. } = read(&mut probe) else {
        panic!("no Hello while sampling output progress");
    };
    head
}

/// Wait until an unread attached viewer holds the output head below the producer's completion point.
fn wait_for_stalled_head(session: &Session, minimum: u64, limit: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut previous = None;
    let mut unchanged = 0;
    loop {
        let head = output_head(session);
        assert!(
            head < limit,
            "attached producer passed the backpressure limit: {head}"
        );
        if head >= minimum && previous == Some(head) {
            unchanged += 1;
            if unchanged == 64 {
                return head;
            }
        } else {
            unchanged = 0;
        }
        assert!(
            Instant::now() < deadline,
            "attached producer never stalled at head {head} (minimum {minimum})"
        );
        previous = Some(head);
        thread::sleep(Duration::from_millis(1));
    }
}

/// Wait for the detached shell's completion marker, then read the retained terminal state.
fn wait_for_detached_completion(session: &Session, marker: &Path) -> (u64, String) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "detached producer did not write its completion marker"
        );
        thread::sleep(Duration::from_millis(1));
    }
    // The completion marker is written only after the shell has emitted the flood and final line.
    // Reattach once after completion, so observation cannot create progress while it is detached.
    let mut peer = session.attach(0);
    peer.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut seq = 0;
    let mut screen = vt100::Parser::new(60, 200, 10000);
    loop {
        match read(&mut peer) {
            Frame::Snapshot(offset, bytes) | Frame::SnapshotWithFlags(offset, _, bytes) => {
                seq = offset;
                screen.process(&bytes);
            }
            Frame::Output(offset, bytes) => {
                assert_eq!(offset, seq);
                seq += bytes.len() as u64;
                screen.process(&bytes);
            }
            frame => panic!("unexpected frame while awaiting detached output: {frame:?}"),
        }
        if seq > 1_000_000 && screen.screen().contents().contains("DETACHED_DONE") {
            return (seq, screen.screen().contents());
        }
        assert!(
            Instant::now() < deadline,
            "detached output marker is not in retained terminal state"
        );
    }
}

#[allow(clippy::needless_pass_by_value)]
fn send(peer: &mut UnixStream, frame: Frame) {
    peer.write_all(&frame.encode().unwrap()).unwrap();
}
fn read(peer: &mut UnixStream) -> Frame {
    let mut prefix = [0; 4];
    peer.read_exact(&mut prefix).unwrap();
    let len = u32::from_le_bytes(prefix) as usize;
    assert!(len <= 1024 * 1024);
    let mut bytes = vec![0; len];
    peer.read_exact(&mut bytes).unwrap();
    Frame::decode(&bytes).unwrap()
}
fn until(peer: &mut UnixStream, seq: &mut u64, needle: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    while !output.windows(needle.len()).any(|w| w == needle) {
        match read(peer) {
            Frame::Output(offset, bytes) => {
                assert_eq!(offset, *seq);
                *seq += bytes.len() as u64;

                output.extend(bytes);
            }
            other => panic!("expected Output, got {other:?}"),
        }
    }
    output
}
#[test]
fn real_shell_reconnect_resize_and_delivered_exit() {
    let mut session = Session::new(8 * 1024 * 1024, false);
    assert_eq!(
        fs::metadata(session.state.join("sessions")).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::metadata(session.path()).unwrap().mode() & 0o777, 0o600);
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(&mut peer, Frame::Input(b"echo hi\n".to_vec()));
    until(&mut peer, &mut seq, b"hi\r\n");
    send(
        &mut peer,
        Frame::Resize {
            cols: 91,
            rows: 31,
            px_w: 0,
            px_h: 0,
        },
    );
    send(
        &mut peer,
        Frame::Input(b"stty size; sleep .1; printf 'RESUME_%s\\n' OK\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"31 91\r\n");
    drop(peer);
    thread::sleep(Duration::from_millis(200));
    let mut peer = session.attach(seq);
    until(&mut peer, &mut seq, b"RESUME_OK\r\n");
    session.finish(peer, seq);
}
#[test]
fn ring_wrap_snapshot_repaints_real_vim() {
    let mut session = Session::new(1024, false);
    let mut peer = session.attach(0);
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../infraternal-shim/tests/fixtures/capture.py");
    let command = format!(
        "printf '\\033c'; seq 1 4000; vim -u NONE -i NONE -n '{}'\n",
        fixture.display()
    );
    send(&mut peer, Frame::Input(command.into_bytes()));
    let mut expected = vt100::Parser::new(60, 200, 10000);
    let mut original_seq = 0;
    expected.process(&until(
        &mut peer,
        &mut original_seq,
        b"Capture real full-screen",
    ));
    // Let vim finish its terminal queries while continuing to collect raw VT.
    // A fresh independent VT then has an oracle for every visible cell, rather
    // than checking only a filename or marker in the resulting repaint.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut decoder = Decoder::default();
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    while Instant::now() < deadline {
        let mut bytes = [0; 16384];
        match peer.read(&mut bytes) {
            Ok(0) => panic!("vim peer closed"),
            Ok(n) => {
                for frame in decoder.feed(&bytes[..n]).unwrap() {
                    let Frame::Output(offset, data) = frame else {
                        panic!("unexpected frame")
                    };
                    assert_eq!(offset, original_seq);
                    original_seq += data.len() as u64;
                    expected.process(&data);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("vim output: {e}"),
        }
    }
    drop(peer);
    let mut peer = session.attach(0);
    let Frame::Snapshot(mut seq, bytes) = read(&mut peer) else {
        panic!("wrapped ring did not snapshot")
    };
    assert_eq!(seq, original_seq);
    let mut screen = vt100::Parser::new(60, 200, 10000);
    screen.process(&bytes);
    assert!(screen.screen().alternate_screen());
    assert_eq!(
        screen.screen().cursor_position(),
        expected.screen().cursor_position()
    );
    for row in 0..60 {
        for col in 0..200 {
            let actual = screen.screen().cell(row, col).unwrap();
            let original = expected.screen().cell(row, col).unwrap();
            // A painted blank and an erased cell have identical visible content.
            assert_eq!(
                actual.contents().trim_end_matches(' '),
                original.contents().trim_end_matches(' '),
                "vim repaint {row}:{col}"
            );
            assert_eq!(
                (
                    actual.fgcolor(),
                    actual.bgcolor(),
                    actual.bold(),
                    actual.dim(),
                    actual.italic(),
                    actual.underline(),
                    actual.inverse()
                ),
                (
                    original.fgcolor(),
                    original.bgcolor(),
                    original.bold(),
                    original.dim(),
                    original.italic(),
                    original.underline(),
                    original.inverse()
                ),
                "vim style {row}:{col}"
            );
        }
    }
    send(&mut peer, Frame::Input(b"\x1b:q!\r".to_vec()));
    until(&mut peer, &mut seq, b"shim-test");
    send(
        &mut peer,
        Frame::Input(b"printf 'AFTER_%s\\n' VIM\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"AFTER_VIM\r\n");
    session.finish(peer, seq);
}
#[test]
fn replacement_connection_and_malformed_limit() {
    let mut session = Session::new(8192, false);
    let mut old = session.attach(0);
    let mut new = session.attach(0);
    let mut seq = 0;
    send(
        &mut new,
        Frame::Input(b"printf 'REPLACE_%s\\n' OK\n".to_vec()),
    );
    until(&mut new, &mut seq, b"REPLACE_OK\r\n");
    // Bytes already queued in the old socket may still be readable after its
    // replacement. Drain that bounded backlog and require EOF or reset.
    let mut backlog = Vec::new();
    let outcome = old.read_to_end(&mut backlog);
    assert!(
        outcome.is_ok()
            || outcome.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    new.write_all(&(1_048_577_u32).to_le_bytes()).unwrap();
    thread::sleep(Duration::from_millis(50));
    drop(new);
    let peer = session.attach(seq);
    session.finish(peer, seq);
}
#[test]
fn double_fork_survives_parent_death() {
    let mut session = Session::new(8192, true);
    let mut parent = session.child.take().unwrap();
    parent.kill().unwrap();
    assert!(!parent.wait().unwrap().success());
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(
        &mut peer,
        Frame::Input(b"printf 'ORPHAN_%s\\n' ALIVE\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"ORPHAN_ALIVE\r\n");
    session.finish(peer, seq);
}

/// Always remove only this test's transient units, including on assertion failure.
struct Units(Vec<String>);
impl Drop for Units {
    fn drop(&mut self) {
        for unit in &self.0 {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
#[test]
fn user_scope_survives_parent_unit_stop() {
    if !Command::new("systemctl")
        .args(["--user", "show-environment"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        eprintln!("SKIP user_scope_survives_parent_unit_stop: no systemd user manager");
        return;
    }
    let parent = format!("infraternal-test-parent-{}", std::process::id());
    let scope = format!("infraternal-session-test-{}", std::process::id());
    let _units = Units(vec![format!("{parent}.service"), format!("{scope}.scope")]);
    let mut session = Session::start(8192, false, Some((&parent, &scope)));
    assert!(
        Command::new("systemctl")
            .args(["--user", "stop", &format!("{parent}.service")])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("systemctl")
            .args(["--user", "is-active", &format!("{scope}.scope")])
            .status()
            .unwrap()
            .success()
    );
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(
        &mut peer,
        Frame::Input(b"printf 'SCOPE_%s\\n' ALIVE\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"SCOPE_ALIVE\r\n");
    session.finish(peer, seq);
}

#[test]
fn attached_backpressure_and_detached_progress() {
    let mut session = Session::new(8192, false);
    let completion_marker = session
        .state
        .canonicalize()
        .unwrap()
        .join("detached-complete");
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(
        &mut peer,
        Frame::Input(b"printf 'READY_%s\\n' YES\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"READY_YES\r\n");
    send(
        &mut peer,
        Frame::Input(
            format!(
                "printf '\\033cFLOOD_%s\\n' START; seq 1 200000; printf 'DETACHED_%s\\n' DONE; : > '{}'\n",
                completion_marker.display()
            )
            .into_bytes(),
        ),
    );
    until(&mut peer, &mut seq, b"FLOOD_START\r\n");
    // Replacing a stalled reader must be prompt, even with queued PTY output.
    let start = Instant::now();
    let mut probe = session.connect();
    let Frame::Hello { head: stalled, .. } = read(&mut probe) else {
        panic!("no Hello")
    };
    assert!(start.elapsed() < Duration::from_millis(300));
    let stalled = wait_for_stalled_head(&session, stalled.max(seq.saturating_add(1024)), 1_000_000);
    assert!(
        stalled < 1_000_000,
        "attached producer must backpressure before completing"
    );
    drop(peer);
    drop(probe);
    let (seq, contents) = wait_for_detached_completion(&session, &completion_marker);
    assert!(
        seq > 1_000_000,
        "detached producer must finish without a viewer"
    );
    assert!(contents.contains("DETACHED_DONE"));
    let peer = session.attach(seq);
    session.finish(peer, seq);
}
#[test]
fn disallowed_signal_only_disconnects_peer() {
    let mut session = Session::new(8192, false);
    let mut peer = session.attach(0);
    send(&mut peer, Frame::Signal(19));
    drop(peer);
    thread::sleep(Duration::from_millis(30));
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(
        &mut peer,
        Frame::Input(b"printf 'SIGNAL_%s\\n' ALIVE\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"SIGNAL_ALIVE\r\n");
    session.finish(peer, seq);
}

/// A dead detached shell cannot retain its shim process or rendezvous socket.
#[test]
fn detached_shell_exit_reaps_shim_within_one_second() {
    let mut session = Session::new(8192, false);
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(
        &mut peer,
        Frame::Input(b"printf 'READY_%s\\n' REAP\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"READY_REAP\r\n");
    drop(peer);
    let children = fs::read_to_string(format!(
        "/proc/{}/task/{}/children",
        session.pid, session.pid
    ))
    .unwrap();
    let shell: i32 = children.split_whitespace().next().unwrap().parse().unwrap();
    let start = Instant::now();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(shell),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    while session.path().exists() {
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "dead shim socket retained"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(session.child.as_mut().unwrap().wait().unwrap().success());
    session.pid = 0;
}

/// A descendant holding the PTY slave cannot retain a dead shell's shim.
#[test]
fn detached_shell_exit_reaps_even_with_a_live_background_descendant() {
    let mut session = Session::new(8192, false);
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(
        &mut peer,
        Frame::Input(b"(trap '' HUP; exec sleep 5) & printf 'READY_%s\\n' REAP\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"READY_REAP\r\n");
    drop(peer);
    let children = fs::read_to_string(format!(
        "/proc/{}/task/{}/children",
        session.pid, session.pid
    ))
    .unwrap();
    let shell: i32 = children.split_whitespace().next().unwrap().parse().unwrap();
    let start = Instant::now();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(shell),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    while session.path().exists() {
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "dead shim socket retained"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(session.child.as_mut().unwrap().wait().unwrap().success());
    session.pid = 0;
}

/// Ownership-only peers retain exited shells without consuming a data cursor.
fn owner(session: &Session) -> UnixStream {
    let mut peer = session.connect();
    assert!(
        matches!(read(&mut peer), Frame::Hello { caps, .. } if caps & infraternal_shim::frame::SESSION_OWNER != 0)
    );
    send(
        &mut peer,
        Frame::Attach(infraternal_shim::frame::SESSION_OWNER),
    );
    send(&mut peer, Frame::InputStateRequest);
    assert_eq!(read(&mut peer), Frame::InputState(0, 0));
    peer
}

/// A control-only request exits the real shell; no output link masks ownership.
fn exit_without_viewer(session: &Session) {
    let mut peer = session.connect();
    assert!(matches!(read(&mut peer), Frame::Hello { .. }));
    send(
        &mut peer,
        Frame::Attach(
            infraternal_shim::frame::SEQUENCED_INPUT | infraternal_shim::frame::MULTI_WRITER,
        ),
    );
    send(&mut peer, Frame::SelectWriter(999_999));
    send(
        &mut peer,
        Frame::SequencedInput(0, b"printf 'FINAL_%s\\n' OUTPUT; exit 7\n".to_vec()),
    );
    // Keep the control connection until the shell disappears: write_all is not
    // proof the shim consumed the request, and control peers cannot retain exit.
    let children = format!("/proc/{}/task/{}/children", session.pid, session.pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read_to_string(&children).is_ok_and(|value| !value.trim().is_empty()) {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn owned_exit_releases_promptly_on_window_close() {
    let session = Session::new(8192, false);
    let ownership = owner(&session);
    exit_without_viewer(&session);
    thread::sleep(Duration::from_millis(350));
    assert!(
        session.path().exists(),
        "data disconnect must not release ownership"
    );
    drop(ownership);
    let deadline = Instant::now() + Duration::from_secs(1);
    while session.path().exists() {
        assert!(
            Instant::now() < deadline,
            "closed owner retained a dead shim"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        infraternal_shim::ended::read(&session.path())
            .unwrap()
            .unwrap()
            .0,
        7
    );
}

#[test]
fn owned_exit_maximum_retires_with_status_even_with_an_unread_data_peer() {
    let session = Session::start_retention(8192, false, None, 700);
    let _ownership = owner(&session);
    let _stalled = session.attach(0);
    exit_without_viewer(&session);
    assert!(
        session.path().exists(),
        "owner must retain exit before bound"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while session.path().exists() {
        assert!(
            Instant::now() < deadline,
            "owner/data peer extended the maximum"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let (status, seq) = infraternal_shim::ended::read(&session.path())
        .unwrap()
        .unwrap();
    assert_eq!(status, 7);
    assert!(seq > 0);
    assert_eq!(
        fs::metadata(session.path().with_extension("ended"))
            .unwrap()
            .len(),
        17
    );
}

#[test]
fn delivered_exit_cannot_release_another_owning_window() {
    let session = Session::new(8192, false);
    let first = owner(&session);
    let second = owner(&session);
    exit_without_viewer(&session);
    let mut data = session.attach(0);
    let mut seq = 0;
    loop {
        match read(&mut data) {
            Frame::Output(offset, bytes) => {
                assert_eq!(offset, seq);
                seq += bytes.len() as u64;
            }
            Frame::Exited(status, final_seq) => {
                assert_eq!((status, final_seq), (7, seq));
                break;
            }
            frame => panic!("unexpected {frame:?}"),
        }
    }
    drop(data);
    drop(first);
    thread::sleep(Duration::from_millis(350));
    assert!(
        session.path().exists(),
        "the sibling window still owns final output"
    );
    drop(second);
    let deadline = Instant::now() + Duration::from_secs(1);
    while session.path().exists() {
        assert!(
            Instant::now() < deadline,
            "all owners released but shim remains"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
