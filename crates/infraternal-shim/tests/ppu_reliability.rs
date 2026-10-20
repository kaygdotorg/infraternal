//! Real shared-host fault regressions runnable without the CLI or release fault hooks [D270].
#![cfg(all(feature = "process-per-user", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_shim::frame::Frame;
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

// Compile the same feature/target/profile once, inside the caller's build
// slot. Running a standalone main is essential: a test harness has another
// thread which may consume process-directed child signals.
fn fixture_binary() -> &'static PathBuf {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = format!(
            "{}-unknown-linux-{}",
            std::env::consts::ARCH,
            if cfg!(target_env = "musl") {
                "musl"
            } else {
                "gnu"
            }
        );
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let target_dir =
            std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
        let target_dir = if target_dir.is_absolute() {
            target_dir
        } else {
            root.join(target_dir)
        };
        let mut build = Command::new(env!("CARGO"));
        build.current_dir(&root).args([
            "build",
            "--locked",
            "-p",
            "infraternal-shim",
            "--example",
            "ppu_host_fixture",
            "--features",
            match (
                cfg!(feature = "compact-history"),
                cfg!(feature = "host-diagnostics"),
            ) {
                (true, true) => "compact-history,host-diagnostics",
                (false, true) => "host-diagnostics",
                (true, false) => "compact-history",
                (false, false) => "process-per-user",
            },
            "--target",
            &target,
        ]);
        if profile == "release" {
            build.arg("--release");
        }
        assert!(
            build.status().unwrap().success(),
            "standalone host fixture build failed"
        );
        target_dir
            .join(target)
            .join(profile)
            .join("examples/ppu_host_fixture")
    })
}

struct Host {
    child: Child,
    root: PathBuf,
}

impl Host {
    fn new() -> Self {
        Self::with_ignored_child_notifications(false)
    }

    fn with_ignored_child_notifications(ignored: bool) -> Self {
        Self::with_child_notifications(ignored, false)
    }

    fn with_child_notifications(ignored: bool, handler: bool) -> Self {
        Self::with_launch(ignored, handler, false)
    }

    fn with_launch(ignored: bool, handler: bool, trace: bool) -> Self {
        // Leave enough room for the 32-digit session ID in Linux sun_path.
        let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/ppu-soak/r{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.parent().unwrap()).unwrap();
        let mut command = if ignored {
            // Ignored dispositions survive exec. Confine this policy to the
            // standalone fixture rather than mutate the threaded test process.
            let mut launcher = Command::new("python3");
            launcher
                .args(["-c", "import os, signal, sys; signal.signal(signal.SIGCHLD, signal.SIG_IGN); os.execv(sys.argv[1], sys.argv[1:])"])
                .arg(fixture_binary());
            launcher
        } else {
            Command::new(fixture_binary())
        };
        let child = command
            .env("PPU_RELIABILITY_STATE", &root)
            .env("PPU_RELIABILITY_TRACE", if trace { "1" } else { "0" })
            .env(
                "PPU_RELIABILITY_CHILD_HANDLER",
                if handler { "1" } else { "0" },
            )
            .env(
                "ZDOTDIR",
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../infraternal/tests/profile"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self { child, root }
    }

    fn connect(&mut self, id: u128) -> UnixStream {
        self.connect_with_caps(id, infraternal_shim::frame::APPROXIMATE_SNAPSHOT)
    }

    fn connect_with_caps(&mut self, id: u128, requested: u64) -> UnixStream {
        let id = id.to_le_bytes();
        let name = format!("{:032x}", u128::from_be_bytes(id));
        let path = self.root.join("sessions").join(format!("{name}.sock"));
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut peer = loop {
            if let Ok(peer) = UnixStream::connect(&path) {
                break peer;
            }
            assert!(self.child.try_wait().unwrap().is_none(), "fixture exited");
            assert!(Instant::now() < deadline, "fixture startup stalled");
            std::thread::sleep(Duration::from_millis(10));
        };
        peer.set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        assert!(
            matches!(read(&mut peer), Frame::Hello { pid, caps, .. } if pid == self.child.id() && caps & requested == requested)
        );
        send(&mut peer, &Frame::Attach(requested));
        send(&mut peer, &Frame::ReadFrom(0));
        peer
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // Only direct children of this live fixture can be its session shells.
        if self.child.try_wait().ok().flatten().is_none() {
            if let Ok(children) = fs::read_to_string(format!(
                "/proc/{}/task/{}/children",
                self.child.id(),
                self.child.id()
            )) {
                for pid in children.split_whitespace() {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid.parse().unwrap()),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn read(peer: &mut UnixStream) -> Frame {
    let mut length = [0; 4];
    peer.read_exact(&mut length).unwrap();
    let length = u32::from_le_bytes(length) as usize;
    assert!((1..=infraternal_shim::frame::MAX_FRAME).contains(&length));
    let mut bytes = vec![0; length];
    peer.read_exact(&mut bytes).unwrap();
    Frame::decode(&bytes).unwrap()
}

fn send(peer: &mut UnixStream, frame: &Frame) {
    peer.write_all(&frame.encode().unwrap()).unwrap();
}

fn input_and_marker(peer: &mut UnixStream, prefix: &[u8], marker: &[u8]) {
    let mut command = prefix.to_vec();
    command.extend_from_slice(b"printf '");
    for byte in marker {
        command.extend_from_slice(format!("\\{byte:03o}").as_bytes());
    }
    command.extend_from_slice(b"\\n'\n");
    send(peer, &Frame::Input(command));
    let mut tail = Vec::new();
    loop {
        match read(peer) {
            Frame::Output(_, bytes) => {
                tail.extend_from_slice(&bytes);
                if tail.windows(marker.len()).any(|part| part == marker) {
                    return;
                }
                let retain = tail.len().saturating_sub(marker.len());
                tail.drain(..retain);
            }
            Frame::Error(code, _) => panic!("fixture refused input: {code}"),
            Frame::Exited(code, _) => panic!("fixture shell exited: {code}"),
            _ => {}
        }
    }
}

#[test]
fn abrupt_shell_exit_and_ignored_hup_leave_sibling_accepting_input() {
    let mut host = Host::new();
    let mut victim = host.connect(1);
    let mut sibling = host.connect(2);
    input_and_marker(&mut victim, b"stty -echo; ", b"victim-ready");
    input_and_marker(&mut sibling, b"stty -echo; trap '' HUP; ", b"sibling-ready");
    send(&mut sibling, &Frame::Signal(1));
    input_and_marker(&mut sibling, b"", b"after-hup");
    send(&mut victim, &Frame::Input(b"kill -9 $$\n".to_vec()));
    loop {
        if let Frame::Exited(code, _) = read(&mut victim) {
            assert_eq!(code, -9);
            break;
        }
    }
    input_and_marker(&mut sibling, b"", b"after-sibling-exit");
    assert!(host.child.try_wait().unwrap().is_none());
}

#[test]
fn terminal_corpus_and_unusual_output_leave_both_sessions_accepting_input() {
    let mut host = Host::new();
    let mut victim = host.connect(1);
    let mut sibling = host.connect(2);
    input_and_marker(&mut victim, b"stty -echo; ", b"corpus-ready");
    input_and_marker(&mut sibling, b"stty -echo; ", b"corpus-sibling-ready");
    let payload = host.root.join("corpus.vt");
    let mut bytes = Vec::new();
    for entry in
        fs::read_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")).unwrap()
    {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "vt") {
            bytes.extend_from_slice(&fs::read(path).unwrap());
            bytes.extend_from_slice(b"\x18\x1bc");
        }
    }
    bytes.extend_from_slice(b"\x1b]0;");
    bytes.extend_from_slice(&vec![b'x'; 131_072]);
    bytes.extend_from_slice(b"\x07\x1b[");
    bytes.extend_from_slice(&b"123456789;".repeat(4096));
    bytes.extend_from_slice(b"m\xff\xfe\xc0\xaf\x18\x1bc");
    fs::write(&payload, bytes).unwrap();
    input_and_marker(
        &mut victim,
        format!("cat '{}'; ", payload.display()).as_bytes(),
        b"after-corpus",
    );
    input_and_marker(&mut sibling, b"", b"sibling-after-corpus");
    assert!(host.child.try_wait().unwrap().is_none());
}

// A launch which cannot retain child status must refuse before publishing PTYs.
#[test]
fn review_ignored_child_notifications_do_not_lose_terminal_exit() {
    let mut host = Host::with_ignored_child_notifications(true);
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = host.child.try_wait().unwrap() {
            assert!(
                !status.success(),
                "invalid startup must be an explicit refusal"
            );
            let sessions = host.root.join("sessions");
            assert!(
                !sessions.exists() || fs::read_dir(sessions).unwrap().next().is_none(),
                "refused startup left session rendezvous files"
            );
            return;
        }
        if host.root.join("sessions").exists() {
            break;
        }
        assert!(Instant::now() < until, "startup did not complete or refuse");
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut victim = host.connect(1);
    let mut sibling = host.connect(2);
    input_and_marker(&mut victim, b"stty -echo; ", b"child-status-ready");
    input_and_marker(&mut sibling, b"stty -echo; ", b"child-status-sibling");
    send(&mut victim, &Frame::Input(b"exit 7\n".to_vec()));
    loop {
        if let Frame::Exited(status, _) = read(&mut victim) {
            assert_eq!(status, 7, "exit status must survive the host launch policy");
            break;
        }
    }
    input_and_marker(&mut sibling, b"", b"after-child-status");
}

// A caught disposition is installed inside main: exec would reset it before
// reaching run_host and would leave the custom-handler case untested.
#[test]
fn inherited_child_dispositions_are_reset_before_sessions_start() {
    for (ignored, handler) in [(true, false), (false, true)] {
        let mut host = Host::with_child_notifications(ignored, handler);
        let mut victim = host.connect(1);
        let mut sibling = host.connect(2);
        let status = fs::read_to_string(format!("/proc/{}/status", host.child.id())).unwrap();
        for field in ["SigIgn:", "SigCgt:"] {
            let mask = status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .unwrap();
            let mask = u64::from_str_radix(mask.trim(), 16).unwrap();
            assert_eq!(mask & (1 << (nix::libc::SIGCHLD - 1)), 0, "{field}");
        }
        input_and_marker(&mut victim, b"stty -echo; ", b"reset-ready");
        input_and_marker(&mut sibling, b"stty -echo; ", b"reset-sibling");
        send(&mut victim, &Frame::Input(b"exit 7\n".to_vec()));
        loop {
            if let Frame::Exited(status, _) = read(&mut victim) {
                assert_eq!(status, 7);
                break;
            }
        }
        input_and_marker(&mut sibling, b"", b"reset-after-exit");
    }
}

// The collector's signal is accepted only in an explicitly instrumented image.
#[cfg(feature = "host-diagnostics")]
#[test]
fn diagnostic_flush_records_numeric_stages_without_terminal_content() {
    let mut host = Host::with_launch(false, false, true);
    let mut peer = host.connect(1);
    input_and_marker(&mut peer, b"stty -echo; ", b"private-diagnostic-marker");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(host.child.id().try_into().unwrap()),
        nix::sys::signal::Signal::SIGUSR1,
    )
    .unwrap();
    // The signal is consumed before a later input fence in the same reactor.
    input_and_marker(&mut peer, b"", b"diagnostic-flush-fence");
    let text = fs::read_to_string(host.root.join("stages.log")).unwrap();
    assert!(text.starts_with("{\"kind\":\"stage-format\",\"version\":1,"));
    for stage in [2, 4, 5, 6, 7, 8, 9, 14] {
        assert!(
            text.contains(&format!("\"stage\":{stage},")),
            "missing numeric stage {stage}"
        );
    }
    assert!(!text.contains("private-diagnostic-marker"));
    assert!(!text.contains("printf"));
}

#[test]
fn shared_host_advertises_and_routes_isolated_terminal_replies() {
    let mut host = Host::new();
    let mut peer = host.connect_with_caps(
        1,
        infraternal_shim::frame::APPROXIMATE_SNAPSHOT | infraternal_shim::frame::QUERY_REPLIES,
    );
    input_and_marker(&mut peer, b"stty -echo; ", b"reply-ready");
    // A comment consumes reply bytes without executing a command; later typing
    // proves that the negotiated reply did not disconnect or replace its writer.
    send(
        &mut peer,
        &Frame::QueryReply(b"# terminal reply\n".to_vec()),
    );
    input_and_marker(&mut peer, b"", b"typing-after-reply");
    assert!(host.child.try_wait().unwrap().is_none());
}

#[test]
fn merge_review_reply_bytes_reach_pty_and_caps_zero_peer_still_works() {
    let mut host = Host::new();
    let mut peer = host.connect_with_caps(1, infraternal_shim::frame::QUERY_REPLIES);
    input_and_marker(&mut peer, b"stty -echo; ", b"merge-ready");
    // Echo is off: the marker proves execution of reply bytes in the real
    // PTY, rather than merely proving that the data connection stayed open.
    send(
        &mut peer,
        &Frame::QueryReply(b"printf 'reply-reached-pty\\n'\n".to_vec()),
    );
    let marker = b"reply-reached-pty";
    let mut tail = Vec::new();
    loop {
        match read(&mut peer) {
            Frame::Output(_, bytes) => {
                tail.extend(bytes);
                if tail.windows(marker.len()).any(|part| part == marker) {
                    break;
                }
            }
            frame @ (Frame::Error(..) | Frame::Exited(..)) => {
                panic!("reply ended the data connection: {frame:?}");
            }
            _ => {}
        }
    }
    input_and_marker(&mut peer, b"", b"typing-still-works");
    let mut legacy = host.connect_with_caps(2, 0);
    input_and_marker(&mut legacy, b"", b"caps-zero-still-works");
}
