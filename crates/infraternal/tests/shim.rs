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
/// The descriptor number a lifelined test shim receives its lifeline on.
const LIFELINE_FD: i32 = 9;
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
        Self::start_configured(ring, detach, units, retention_ms, false)
    }
    fn start_configured(
        ring: usize,
        detach: bool,
        units: Option<(&str, &str)>,
        retention_ms: u64,
        readiness: bool,
    ) -> Self {
        Self::start_lifelined(ring, detach, units, retention_ms, readiness, None)
    }
    /// Start a shim, optionally handing it a launch lifeline (the write end of a pipe) as
    /// descriptor `LIFELINE_FD`, named by `--lifeline-fd`.
    fn start_lifelined(
        ring: usize,
        detach: bool,
        units: Option<(&str, &str)>,
        retention_ms: u64,
        readiness: bool,
        lifeline: Option<&std::os::fd::OwnedFd>,
    ) -> Self {
        let counter = NEXT.fetch_add(1, Ordering::Relaxed);
        let id = format!("{:016x}{counter:016x}", std::process::id());
        // Socket names include the full state path; keep gate fixtures under its per-job root.
        let state = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
            || {
                PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
                    ".cache/codex-scratch/session-bounds/t{}-{counter}",
                    std::process::id()
                ))
            },
            |root| PathBuf::from(root).join(format!("s{counter}")),
        );
        let mut command = if let Some((parent, scope)) = units {
            let mut command = Command::new("systemd-run");
            command.args(["--user","--quiet","--unit",parent,"--property","KillMode=control-group","--working-directory"])
                .arg(std::env::current_dir().unwrap())
                .arg(format!("--setenv=ZDOTDIR={}/tests/profile",env!("CARGO_MANIFEST_DIR")))
                .args(["/bin/sh","-c","scope=$1; shift; systemd-run --user --quiet --scope --unit=\"$scope\" \"$@\" & wait","shim-parent",scope,env!("CARGO_BIN_EXE_infraternal")]);
            command
        } else if let Some(_write_end) = lifeline {
            // The pipe arrives as this process's stdout; the shell copies it to the lifeline descriptor,
            // points stdout at /dev/null, and replaces itself with the launcher, so no extra holder remains.
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                &format!("exec \"$@\" {LIFELINE_FD}>&1 1>/dev/null"),
                "shim-lifeline",
                env!("CARGO_BIN_EXE_infraternal"),
            ]);
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
        if readiness {
            command.arg("--readiness");
        }
        if lifeline.is_some() {
            command.arg("--lifeline-fd").arg(LIFELINE_FD.to_string());
        }
        let stdout = lifeline.map_or_else(Stdio::null, |write_end| {
            Stdio::from(write_end.try_clone().unwrap())
        });
        let child = command.stdin(Stdio::null()).stdout(stdout).spawn().unwrap();
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
        // Parallel fixture forks can retain this readiness connection until
        // exec. Shut down its shared socket state so those inherited aliases
        // cannot consume one of the peer-limit test's admission slots.
        peer.shutdown(std::net::Shutdown::Both).unwrap();
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
        self.attach_with_caps(seq, 0)
    }
    fn attach_with_caps(&self, seq: u64, caps: u64) -> UnixStream {
        let mut peer = self.connect();
        assert!(matches!(read(&mut peer), Frame::Hello { version: 1, .. }));
        send(&mut peer, Frame::Attach(caps));
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
    wait_for_detached_completion_with_caps(session, marker, 0)
}

fn wait_for_detached_completion_with_caps(
    session: &Session,
    marker: &Path,
    caps: u64,
) -> (u64, String) {
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
    let mut peer = session.attach_with_caps(0, caps);
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
fn vim_path() -> PathBuf {
    // Resolve in the test runner: login shells deliberately scrub the inherited toolchain PATH.
    let vim = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join("vim"))
        .find(|path| {
            fs::metadata(path)
                .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
        })
        .expect("Vim must be available in the verification toolchain");
    fs::canonicalize(vim).unwrap()
}
#[test]
fn ring_wrap_snapshot_repaints_real_vim() {
    let vim = vim_path().to_str().unwrap().replace('\'', "'\\''");
    let mut session = Session::new(1024, false);
    let mut peer = session.attach(0);
    let mut original_seq = 0;
    // Session::new waits for the shim, not for the login shell; wait for
    // shell-generated output so the first command cannot race shell startup.
    send(
        &mut peer,
        Frame::Input(b"printf 'shell-ready-%s\\n' check\n".to_vec()),
    );
    until(&mut peer, &mut original_seq, b"shell-ready-check");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../infraternal-shim/tests/fixtures/capture.py");
    let command = format!(
        "printf '\\033c'; seq 1 4000; '{vim}' -u NONE -i NONE -n '{}'; printf 'vim-exited-%s\\n' check\n",
        fixture.display()
    );
    send(&mut peer, Frame::Input(command.into_bytes()));
    let mut expected = vt100::Parser::new(60, 200, 10000);
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
    // The command's trailing marker is emitted by the shell after Vim exits,
    // avoiding both shell-specific prompt text and a second-input race.
    until(&mut peer, &mut seq, b"vim-exited-check");
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
    // Any byte past the consumed marker proves the flood began. The stall point
    // itself is not a contract: an AF_UNIX stream refuses further writes after
    // a fixed number of skbs (278 on the build VMs), whatever their size, and
    // each Output frame carries one PTY read. When the shim keeps pace with a
    // line-buffered `seq`, the unread socket fills with ~1 KiB of payload (#334).
    let stalled = wait_for_stalled_head(&session, stalled.max(seq.saturating_add(1)), 1_000_000);
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

/// Hang guard for a shim that should exit on its own. It only detects a hang;
/// the reap tests assert what happened when the shim exited, never how fast.
const REAP_HANG_BOUND: Duration = Duration::from_secs(60);

/// Kill the session's shell, wait for the shim process to exit, and check that
/// it exited cleanly and removed its rendezvous socket first.
fn kill_shell_and_await_reap(session: &mut Session) {
    let children = fs::read_to_string(format!(
        "/proc/{}/task/{}/children",
        session.pid, session.pid
    ))
    .unwrap();
    let shell: i32 = children.split_whitespace().next().unwrap().parse().unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(shell),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    let child = session.child.as_mut().unwrap();
    let deadline = Instant::now() + REAP_HANG_BOUND;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "shim outlived its dead shell");
        thread::sleep(Duration::from_millis(5));
    };
    assert!(status.success(), "shim exit: {status}");
    assert!(!session.path().exists(), "dead shim socket retained");
    session.pid = 0;
}

/// A dead detached shell cannot retain its shim process or rendezvous socket.
#[test]
fn detached_shell_exit_reaps_shim() {
    let mut session = Session::new(8192, false);
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(
        &mut peer,
        Frame::Input(b"printf 'READY_%s\\n' REAP\n".to_vec()),
    );
    until(&mut peer, &mut seq, b"READY_REAP\r\n");
    drop(peer);
    kill_shell_and_await_reap(&mut session);
}

/// True while `pid` is a live process (not missing, not a zombie) whose
/// command is `comm`, so a recycled PID never counts.
fn running_as(pid: i32, comm: &str) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.split_once(" (")
            .and_then(|(_, rest)| rest.rsplit_once(") "))
            .is_some_and(|(name, tail)| name == comm && !tail.starts_with('Z'))
    })
}

/// Stops the test's background `sleep` on every exit path, including a panic
/// in the middle of the test, and only while that PID is still the sleeper.
struct Sleeper(i32);
impl Drop for Sleeper {
    fn drop(&mut self) {
        if running_as(self.0, "sleep") {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(self.0),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}

/// A descendant holding the PTY slave cannot retain a dead shell's shim. The
/// descendant would hold it for 600 s, far past the reap hang guard, so a shim
/// that waited for it fails instead of passing slowly. The descendant must be
/// alive when the shell dies, so the case is really exercised. At shim exit,
/// the product's rule decides its fate: a non-root shim with host login
/// (`plugin-agent` builds) adopts the terminal's jobs and retires them before
/// it records the end; otherwise the descendant outlives the shim.
#[test]
fn detached_shell_exit_reaps_even_with_a_live_background_descendant() {
    let mut session = Session::new(8192, false);
    let mut peer = session.attach(0);
    let mut seq = 0;
    send(
        &mut peer,
        Frame::Input(b"(trap '' HUP; exec sleep 600) & printf 'READY_%s_PID\\n' $!\n".to_vec()),
    );
    let output = until(&mut peer, &mut seq, b"_PID\r\n");
    let output = String::from_utf8_lossy(&output);
    let descendant: i32 = output
        .rsplit_once("READY_")
        .and_then(|(_, tail)| tail.split_once("_PID"))
        .and_then(|(pid, _)| pid.parse().ok())
        .expect("background descendant PID");
    let _sleeper = Sleeper(descendant);
    drop(peer);
    // `$!` is printed right after the fork; wait for the subshell's exec of
    // `sleep`, so the descendant is provably live when the shell dies.
    let deadline = Instant::now() + REAP_HANG_BOUND;
    while !running_as(descendant, "sleep") {
        assert!(
            Instant::now() < deadline,
            "the PTY-holding descendant never started sleeping"
        );
        thread::sleep(Duration::from_millis(5));
    }
    kill_shell_and_await_reap(&mut session);
    let adopts = cfg!(feature = "plugin-agent") && !nix::unistd::Uid::effective().is_root();
    assert_eq!(
        running_as(descendant, "sleep"),
        !adopts,
        "descendant after shim exit (shim adopts and retires jobs: {adopts})"
    );
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
fn unowned_normal_exit_retires_promptly_and_records_status() {
    let mut session = Session::new(8192, false);
    exit_without_viewer(&session);
    let deadline = Instant::now() + Duration::from_secs(1);
    while session.path().exists() {
        assert!(
            Instant::now() < deadline,
            "unowned exit retained a dead shim"
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
    assert!(session.child.as_mut().unwrap().wait().unwrap().success());
    session.pid = 0;
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

#[test]
fn readiness_does_not_advertise_durable_ownership() {
    let session = Session::start_configured(8192, false, None, 600_000, true);
    let mut peer = session.connect();
    let Frame::Hello { caps, .. } = read(&mut peer) else {
        panic!("no readiness Hello");
    };
    // A private probe retires after output delivery without an ended record.
    // Ownership EOF must not race its ordered output and exit notification.
    assert_eq!(caps & infraternal_shim::frame::SESSION_OWNER, 0);
}

#[test]
fn readiness_exit_waits_for_a_real_output_cursor() {
    let session = Session::start_configured(8192, false, None, 600_000, true);
    let mut control = session.connect();
    assert!(matches!(read(&mut control), Frame::Hello { .. }));
    send(
        &mut control,
        Frame::Attach(
            infraternal_shim::frame::SEQUENCED_INPUT | infraternal_shim::frame::MULTI_WRITER,
        ),
    );
    send(&mut control, Frame::SelectWriter(77));
    send(&mut control, Frame::SequencedInput(0, b"\n".to_vec()));
    // Wait for the actual child to be reaped while no output cursor exists.
    // An input-capable control peer cannot prove the fixed output was delivered.
    let children = format!("/proc/{}/task/{}/children", session.pid, session.pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read_to_string(&children).is_ok_and(|value| !value.trim().is_empty()) {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let mut data = session.connect();
    assert!(matches!(read(&mut data), Frame::Hello { .. }));
    send(&mut data, Frame::Attach(0));
    send(&mut data, Frame::ReadFrom(0));
    let mut output = Vec::new();
    loop {
        match read(&mut data) {
            Frame::Output(_, bytes) => output.extend_from_slice(&bytes),
            Frame::Exited(_, _) => break,
            _ => {}
        }
    }
    assert!(
        output
            .windows(b"infraternal-ready".len())
            .any(|bytes| bytes == b"infraternal-ready")
    );
}
/// Raw additive selection keeps this regression runnable against older shims.
fn shared_selector_frame(writer: u32) -> Vec<u8> {
    let mut wire = vec![5, 0, 0, 0, 0x1d];
    wire.extend_from_slice(&writer.to_le_bytes());
    wire
}

/// Send the additive selector on a peer whose Attach was admitted.
fn shared_selector(peer: &mut UnixStream, writer: u32) {
    peer.write_all(&shared_selector_frame(writer)).unwrap();
}

fn writer_peer(session: &Session, writer: u32, shared: bool) -> UnixStream {
    let mut peer = session.connect();
    let Frame::Hello {
        version: 1, caps, ..
    } = read(&mut peer)
    else {
        panic!("missing shim Hello");
    };
    assert!(!shared || caps & 16 != 0, "shared mode must be negotiated");
    send(&mut peer, Frame::Attach(if shared { 19 } else { 3 }));
    if shared {
        shared_selector(&mut peer, writer);
    } else {
        send(&mut peer, Frame::SelectWriter(writer));
    }
    peer
}

fn writer_state(peer: &mut UnixStream) -> (u64, u64) {
    send(peer, Frame::InputStateRequest);
    loop {
        match read(peer) {
            Frame::InputState(written, accepted) => return (written, accepted),
            Frame::InputAck(_) => {}
            other => panic!("unexpected writer state reply: {other:?}"),
        }
    }
}

fn writer_output(peer: &mut UnixStream, cursor: &mut u64, marker: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    while !output.windows(marker.len()).any(|bytes| bytes == marker) {
        match read(peer) {
            Frame::Output(offset, bytes) => {
                assert_eq!(offset, *cursor);
                *cursor += bytes.len() as u64;
                output.extend(bytes);
            }
            Frame::InputAck(_) => {}
            other => panic!("unexpected writer output: {other:?}"),
        }
    }
    output
}

fn peer_closed(peer: &mut UnixStream) {
    let mut backlog = Vec::new();
    let result = peer.read_to_end(&mut backlog);
    assert!(
        result.is_ok()
            || result.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset),
        "replaced/refused peer must close"
    );
}

#[test]
fn shared_writer_coexists_and_replayed_input_is_written_once() {
    let session = Session::new(8192, false);
    let mut active = writer_peer(&session, 7, false);
    send(&mut active, Frame::ReadFrom(0));
    let setup = b"stty raw -echo; exec python3 -u -c 'import os; os.write(1,bytes.fromhex(\"52454144597c\")); exec(\"while True:\\n b=os.read(0,4096)\\n if not b: break\\n os.write(1,b)\")'\r";
    send(&mut active, Frame::SequencedInput(0, setup.to_vec()));
    let mut cursor = 0;
    writer_output(&mut active, &mut cursor, b"READY|");
    let mut shared = writer_peer(&session, 7, true);
    assert_eq!(
        writer_state(&mut shared),
        (setup.len() as u64, setup.len() as u64)
    );
    send(
        &mut active,
        Frame::SequencedInput(setup.len() as u64, b"once|".to_vec()),
    );
    assert_eq!(writer_output(&mut active, &mut cursor, b"once|"), b"once|");
    send(
        &mut shared,
        Frame::SequencedInput(setup.len() as u64, b"once|twice|".to_vec()),
    );
    assert_eq!(
        writer_output(&mut active, &mut cursor, b"twice|"),
        b"twice|"
    );
    let expected = setup.len() as u64 + 11;
    assert_eq!(writer_state(&mut active), (expected, expected));
    assert_eq!(writer_state(&mut shared), (expected, expected));
    // No ReadFrom was issued on the parked peer: only bounded input replies.
    drop(shared);
    send(
        &mut active,
        Frame::SequencedInput(expected, b"alive|".to_vec()),
    );
    assert_eq!(
        writer_output(&mut active, &mut cursor, b"alive|"),
        b"alive|"
    );
}

#[test]
fn writer_replacement_is_per_mode_and_fresh_ordinary_writers_stay_optional() {
    let session = Session::new(8192, false);
    let mut ordinary = writer_peer(&session, 7, false);
    assert_eq!(writer_state(&mut ordinary), (0, 0));
    let mut shared = writer_peer(&session, 7, true);
    assert_eq!(writer_state(&mut shared), (0, 0));
    let mut next_ordinary = writer_peer(&session, 7, false);
    assert_eq!(writer_state(&mut next_ordinary), (0, 0));
    peer_closed(&mut ordinary);
    assert_eq!(writer_state(&mut shared), (0, 0));
    let mut next_shared = writer_peer(&session, 7, true);
    assert_eq!(writer_state(&mut next_shared), (0, 0));
    peer_closed(&mut shared);
    assert_eq!(writer_state(&mut next_ordinary), (0, 0));
    drop(next_ordinary);
    let mut fresh = session.connect();
    read(&mut fresh);
    send(&mut fresh, Frame::Attach(19));
    send(&mut fresh, Frame::SelectWriter(9));
    assert_eq!(writer_state(&mut fresh), (0, 0));
    assert_eq!(writer_state(&mut next_shared), (0, 0));
}

#[test]
fn shared_writer_refusals_and_full_peer_limit_preserve_the_live_writer() {
    let session = Session::new(8192, false);
    let mut active = writer_peer(&session, 7, false);
    assert_eq!(writer_state(&mut active), (0, 0));
    for (caps, writer) in [(16, 7), (17, 7), (18, 7), (3, 7), (19, 0), (19, 99)] {
        let mut refused = session.connect();
        read(&mut refused);
        // Invalid Attach may close immediately. Supply both frames together so
        // the fixture does not require a second write after a valid refusal.
        let mut coalesced = Frame::Attach(caps).encode().unwrap();
        coalesced.extend_from_slice(&shared_selector_frame(writer));
        refused.write_all(&coalesced).unwrap();
        peer_closed(&mut refused);
        assert_eq!(writer_state(&mut active), (0, 0));
    }
    let mut repeated = writer_peer(&session, 7, true);
    assert_eq!(writer_state(&mut repeated), (0, 0));
    shared_selector(&mut repeated, 7);
    peer_closed(&mut repeated);
    assert_eq!(writer_state(&mut active), (0, 0));
    let mut before_attach = session.connect();
    read(&mut before_attach);
    shared_selector(&mut before_attach, 7);
    peer_closed(&mut before_attach);
    assert_eq!(writer_state(&mut active), (0, 0));
    let mut peers = Vec::new();
    for _ in 0..31 {
        let mut peer = session.connect();
        assert!(matches!(read(&mut peer), Frame::Hello { .. }));
        peers.push(peer);
    }
    let mut refused = session.connect();
    peer_closed(&mut refused);
    assert_eq!(writer_state(&mut active), (0, 0));
}

#[test]
fn malformed_shared_successor_does_not_evict_the_live_shared_peer() {
    let session = Session::new(8192, false);
    let mut active = writer_peer(&session, 7, false);
    assert_eq!(writer_state(&mut active), (0, 0));
    let mut shared = writer_peer(&session, 7, true);
    assert_eq!(writer_state(&mut shared), (0, 0));
    let mut refused = session.connect();
    read(&mut refused);
    let mut coalesced = Frame::Attach(19).encode().unwrap();
    for _ in 0..2 {
        coalesced.extend_from_slice(&[5, 0, 0, 0, 0x1d, 7, 0, 0, 0]);
    }
    refused.write_all(&coalesced).unwrap();
    peer_closed(&mut refused);
    assert_eq!(writer_state(&mut active), (0, 0));
    assert_eq!(writer_state(&mut shared), (0, 0));
}

#[test]
fn shared_writer_restores_durable_geometry_after_another_writer_types() {
    let session = Session::new(8192, false);
    let mut ordinary = writer_peer(&session, 7, false);
    assert_eq!(writer_state(&mut ordinary), (0, 0));
    let mut shared = writer_peer(&session, 7, true);
    assert_eq!(writer_state(&mut shared), (0, 0));
    send(
        &mut ordinary,
        Frame::Resize {
            cols: 120,
            rows: 40,
            px_w: 0,
            px_h: 0,
        },
    );
    let mut other = writer_peer(&session, 8, false);
    send(&mut other, Frame::ReadFrom(0));
    send(
        &mut other,
        Frame::Resize {
            cols: 50,
            rows: 20,
            px_w: 0,
            px_h: 0,
        },
    );
    let command = b"printf 'ACTIVE8_%s\\n' OK\n";
    send(&mut other, Frame::SequencedInput(0, command.to_vec()));
    let mut cursor = 0;
    writer_output(&mut other, &mut cursor, b"ACTIVE8_OK\r\n");
    let mut shared_cursor = output_head(&session);
    send(&mut shared, Frame::ReadFrom(shared_cursor));
    let command = b"printf 'GEOMETRY7_%s|END|\\n' \"$(stty size | tr ' ' '_')\"\n";
    send(&mut shared, Frame::SequencedInput(0, command.to_vec()));
    let output = writer_output(&mut shared, &mut shared_cursor, b"|END|\r\n");
    let expected = b"GEOMETRY7_40_120|END|\r\n";
    assert!(
        output
            .windows(expected.len())
            .any(|bytes| bytes == expected),
        "shared input must use writer7 remembered geometry"
    );
}

#[test]
fn parked_shared_writer_does_not_stop_detached_pty_progress() {
    let session = Session::new(8192, false);
    // Keep final output owned until this late observer finishes [55][178].
    let _owner = owner(&session);
    let mut active = writer_peer(&session, 7, false);
    send(&mut active, Frame::ReadFrom(0));
    let marker = std::env::current_dir()
        .unwrap()
        .join(&session.state)
        .join("parked-complete");
    let setup = format!(
        "stty raw -echo; exec python3 -u -c 'import os; os.write(1,b\"READY|\"); os.read(0,1); os.write(1,b\"x\"*1048576+b\"\\nDETACHED_DONE\\n\"); open(\"{}\",\"w\").write(\"done\")'\r",
        marker.display()
    );
    send(
        &mut active,
        Frame::SequencedInput(0, setup.as_bytes().to_vec()),
    );
    let mut cursor = 0;
    writer_output(&mut active, &mut cursor, b"READY|");
    let mut parked = writer_peer(&session, 7, true);
    assert_eq!(writer_state(&mut parked).1, setup.len() as u64);
    drop(active);
    // The input-only parked peer remains live, without an output read request.
    send(
        &mut parked,
        Frame::SequencedInput(setup.len() as u64, b"!".to_vec()),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "parked input-only peer stopped detached PTY output"
        );
        thread::sleep(Duration::from_millis(1));
    }
    // Observing output only after completion cannot create the progress asserted above.
    // The long wrapped flood need not fit faithful history provenance; this
    // observer explicitly opts into the existing bounded approximate repaint.
    let (head, screen) = wait_for_detached_completion_with_caps(&session, &marker, 4);
    assert!(head > 1_000_000);
    assert!(screen.contains("DETACHED_DONE"));
    assert_eq!(writer_state(&mut parked).1, setup.len() as u64 + 1);
}

#[test]
fn shared_input_waits_for_global_queue_space_without_losing_the_suffix() {
    assert_shared_queue_pressure(7, 0, QueueProbe::None);
}

#[test]
fn independent_shared_writers_wait_for_the_same_global_queue() {
    assert_shared_queue_pressure(8, 0, QueueProbe::None);
}

#[test]
fn dropped_deferred_peers_release_slots_before_the_pty_drains() {
    assert_shared_queue_pressure(7, 40, QueueProbe::None);
}

#[test]
fn legacy_output_subscription_unblocks_deferred_shared_input() {
    assert_shared_queue_pressure(7, 0, QueueProbe::LegacyOutput);
}

#[test]
fn fresh_shared_peer_negotiates_while_another_shared_input_is_deferred() {
    assert_shared_queue_pressure(7, 0, QueueProbe::FreshShared);
}

#[derive(Clone, Copy)]
enum QueueProbe {
    None,
    LegacyOutput,
    FreshShared,
}

#[allow(clippy::too_many_lines)]
fn assert_shared_queue_pressure(writer: u32, replacements: usize, probe: QueueProbe) {
    let legacy_output = matches!(probe, QueueProbe::LegacyOutput);
    let session = Session::new(8192, false);
    let root = std::env::current_dir().unwrap().join(&session.state);
    let release = root.join("input-release");
    let result = root.join("input-result");
    let mut active = writer_peer(&session, 7, false);
    send(&mut active, Frame::ReadFrom(0));
    let flood = if legacy_output {
        "os.write(1,b\"x\"*1048576+bytes.fromhex(\"4c45474143595f50524f47524553537c\")); "
    } else {
        ""
    };
    let setup = format!(
        "stty raw -echo; exec python3 -u -c 'import os,time; os.write(1,bytes.fromhex(\"52454144597c\")); exec(\"while not os.path.exists(\\\"{}\\\"):\\n time.sleep(.001)\"); {flood}data=bytearray(); exec(\"while len(data)<1100000:\\n data.extend(os.read(0,1100000-len(data)))\"); open(\"{}\",\"w\").write(str(data.count(65))+\",\"+str(data.count(66)))'\r",
        release.display(),
        result.display()
    );
    send(
        &mut active,
        Frame::SequencedInput(0, setup.as_bytes().to_vec()),
    );
    let mut cursor = 0;
    writer_output(&mut active, &mut cursor, b"READY|");
    let mut legacy = legacy_output.then(|| writer_peer(&session, 9, false));
    if let Some(peer) = &mut legacy {
        assert_eq!(writer_state(peer), (0, 0));
    }
    if matches!(probe, QueueProbe::FreshShared) {
        let mut seed = writer_peer(&session, 10, false);
        assert_eq!(writer_state(&mut seed), (0, 0));
    }
    if writer != 7 {
        let mut seed = writer_peer(&session, writer, false);
        assert_eq!(writer_state(&mut seed), (0, 0));
    }
    let mut shared = writer_peer(&session, writer, true);
    assert_eq!(
        writer_state(&mut shared).1,
        if writer == 7 { setup.len() as u64 } else { 0 }
    );
    send(
        &mut active,
        Frame::SequencedInput(setup.len() as u64, vec![b'A'; 900_000]),
    );
    assert_eq!(writer_state(&mut active).1, setup.len() as u64 + 900_000);
    // The PTY kernel buffer cannot absorb the remaining 200KiB while Python waits.
    let sequence = if writer == 7 {
        setup.len() as u64 + 900_000
    } else {
        0
    };
    send(
        &mut shared,
        Frame::SequencedInput(sequence, vec![b'B'; 200_000]),
    );
    for _ in 0..replacements {
        drop(shared);
        shared = writer_peer(&session, writer, true);
        assert_eq!(writer_state(&mut shared).1, sequence);
        send(
            &mut shared,
            Frame::SequencedInput(sequence, vec![b'B'; 200_000]),
        );
    }
    // A duplicate suffix and the state request remain ordered behind deferral.
    send(
        &mut shared,
        Frame::SequencedInput(sequence + 199_997, b"BBB".to_vec()),
    );
    if matches!(probe, QueueProbe::FreshShared) {
        // The oldest shared peer stays alive, and the backend still cannot read.
        thread::sleep(Duration::from_millis(100));
        let mut fresh = writer_peer(&session, 10, true);
        assert_eq!(writer_state(&mut fresh), (0, 0));
    }
    if let Some(peer) = &mut legacy {
        // Let the shim reach capacity deferral before issuing the ordinary
        // subscription. The backend remains blocked on its external release.
        thread::sleep(Duration::from_millis(100));
        send(
            peer,
            Frame::Resize {
                cols: 91,
                rows: 31,
                px_w: 0,
                px_h: 0,
            },
        );
        send(peer, Frame::ReadFrom(cursor));
    }
    let release_task = thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        fs::write(release, b"go").unwrap();
    });
    if let Some(peer) = &mut legacy {
        assert_eq!(writer_state(peer), (0, 0));
        // Only this reader drains the flood; the original reader stays stalled.
        writer_output(peer, &mut cursor, b"LEGACY_PROGRESS|");
    }
    assert_eq!(writer_state(&mut shared).1, sequence + 200_000);
    release_task.join().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read_to_string(&result)
        .ok()
        .is_none_or(|text| text.is_empty())
    {
        assert!(
            Instant::now() < deadline,
            "deferred input never reached the real PTY"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(fs::read_to_string(result).unwrap(), "900000,200000");
}

/// A fresh lifeline: the pipe's read end stays with the test, the write end goes to the shim.
fn lifeline() -> (std::fs::File, std::os::fd::OwnedFd) {
    let (read, write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    (std::fs::File::from(read), write)
}

/// Whether the lifeline's read end has hit end-of-file, waiting at most `limit` (a hang bound, not a
/// speed claim): true only when every holder of the write end is gone.
fn lifeline_eof_within(read: &std::fs::File, limit: Duration) -> bool {
    use std::os::fd::AsFd as _;
    let deadline = Instant::now() + limit;
    loop {
        let mut poll = [nix::poll::PollFd::new(
            read.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        let left = deadline.saturating_duration_since(Instant::now());
        let millis = u16::try_from(left.as_millis().min(1000)).unwrap();
        if nix::poll::poll(&mut poll, nix::poll::PollTimeout::from(millis)).unwrap() > 0 {
            let mut byte = [0_u8; 8];
            match (&*read).read(&mut byte) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(error) => panic!("lifeline read: {error}"),
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
    }
}

/// The launcher forks, the original exits, the shim lives on holding the lifeline: no EOF while it
/// runs, and EOF as soon as it is killed (whatever its shell is doing).
#[test]
fn lifeline_reaches_eof_when_the_shim_is_killed_and_not_before() {
    let (read, write) = lifeline();
    let session = Session::start_lifelined(8192, true, None, 600_000, false, Some(&write));
    drop(write);
    assert!(
        !lifeline_eof_within(&read, Duration::from_millis(300)),
        "the lifeline reached EOF while the shim was alive"
    );
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(session.pid).unwrap()),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    assert!(
        lifeline_eof_within(&read, Duration::from_secs(10)),
        "a killed shim still held the lifeline"
    );
}

/// A shim that exits by itself, when its shell exits, releases the lifeline too.
#[test]
fn lifeline_reaches_eof_when_the_shim_exits_normally() {
    let (read, write) = lifeline();
    let mut session = Session::start_lifelined(8192, true, None, 200, false, Some(&write));
    drop(write);
    let mut peer = session.attach(0);
    send(&mut peer, Frame::Input(b"exit 0\n".to_vec()));
    // Keep reading until the shim sends its exit and retires.
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    while !matches!(try_read(&mut peer), None | Some(Frame::Exited(..))) {}
    drop(peer);
    assert!(
        lifeline_eof_within(&read, Duration::from_secs(15)),
        "an exited shim still held the lifeline"
    );
    session.pid = 0;
}

/// The shell, and anything it starts, never holds the lifeline: only the shim does.
#[test]
fn the_shell_and_its_children_never_hold_the_lifeline() {
    let (read, write) = lifeline();
    let session = Session::start_lifelined(8192, true, None, 600_000, false, Some(&write));
    drop(write);
    let mut peer = session.attach(0);
    let mut seq = 0;
    // The digits are computed, so the terminal's echo of this line never contains the answer.
    let command = format!(
        "a=0; [ -e /proc/$$/fd/{LIFELINE_FD} ] && a=1; sleep 1 & b=0; \\
         [ -e /proc/$!/fd/{LIFELINE_FD} ] && b=1; printf 'RES%sULT\\n' \"$a$b\"\n"
    );
    send(&mut peer, Frame::Input(command.into_bytes()));
    let output = until(&mut peer, &mut seq, b"ULT\r\n");
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("RES00ULT"),
        "the shell or its child held the lifeline: {text}"
    );
    // And the shim itself still holds it.
    assert!(!lifeline_eof_within(&read, Duration::from_millis(200)));
}

/// Without its lifeline a shim refuses to run, instead of letting the launch's proof of death lie.
#[test]
fn a_missing_lifeline_descriptor_stops_the_shim_before_it_runs() {
    let state = std::env::temp_dir().join(format!("lifeline-missing-{}", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args([
            "__shim",
            "--session",
            "0123456789abcdef0123456789abcdef",
            "--uid",
            &nix::unistd::Uid::effective().as_raw().to_string(),
            "--state",
        ])
        .arg(&state)
        .args(["--lifeline-fd", "77"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&state);
    let message = String::from_utf8_lossy(&status.stderr);
    assert!(!status.status.success(), "a shim ran without its lifeline");
    assert!(
        message.contains("Bad file descriptor"),
        "the shim refused for another reason: {message}"
    );
}

/// One frame, or `None` at end of stream or on a read timeout.
fn try_read(peer: &mut UnixStream) -> Option<Frame> {
    let mut prefix = [0; 4];
    peer.read_exact(&mut prefix).ok()?;
    let len = u32::from_le_bytes(prefix) as usize;
    let mut bytes = vec![0; len];
    peer.read_exact(&mut bytes).ok()?;
    Frame::decode(&bytes).ok()
}
