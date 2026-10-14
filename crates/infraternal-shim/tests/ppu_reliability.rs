//! Real shared-host fault regressions runnable without the CLI or release fault hooks [D270].
#![cfg(all(feature = "process-per-user", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_shim::{Config, frame::Frame, run_host};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

// Run the production reactor in a fresh process: it owns signal masks and must
// never install them inside the multithreaded Rust test runner.
#[test]
#[ignore = "subprocess fixture; selected only by the parent reliability test"]
fn fixture_entry() {
    let Some(root) = std::env::var_os("PPU_RELIABILITY_STATE") else {
        return;
    };
    let configs = (1_u128..=2)
        .map(|id| {
            let mut config = Config::new(id.to_le_bytes(), nix::unistd::Uid::effective().as_raw());
            config.state = Some(PathBuf::from(&root));
            config.ring_capacity = 65536;
            config
        })
        .collect();
    run_host(configs).unwrap();
}

struct Host {
    child: Child,
    root: PathBuf,
}

impl Host {
    fn new() -> Self {
        // Leave enough room for the 32-digit session ID in Linux sun_path.
        let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/ppu-soak/r{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "fixture_entry", "--nocapture"])
            .env("PPU_RELIABILITY_STATE", &root)
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
        assert!(matches!(read(&mut peer), Frame::Hello { pid, .. } if pid == self.child.id()));
        send(
            &mut peer,
            &Frame::Attach(infraternal_shim::frame::APPROXIMATE_SNAPSHOT),
        );
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
