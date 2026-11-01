//! Real allocator refusal, peer ordering and PTY continuation for resize recovery [13][40].
use super::*;
use crate::terminal_native::allocation::{PREFIX, with_refusing_engine};

struct ChildGuard(Pty);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.child.kill();
        let _ = self.0.child.wait();
    }
}

#[test]
fn native_resize_refusal_preserves_peer_and_pty() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let evidence = root.join("target/review-vt3-fixes");
    fs::create_dir_all(&evidence).unwrap();
    for case in ["exact", "gap", "readfrom", "control", "queued"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "session::resize_checks::resize_refusal_session_probe",
                "--ignored",
                "--test-threads=1",
            ])
            .env("VT_SESSION_RECOVERY_CASE", case)
            .env("ZDOTDIR", root.join("crates/infraternal/tests/profile"))
            .output()
            .unwrap();
        let ran = String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed");
        fs::write(
            evidence.join(format!("t3-session-{case}.stdout.log")),
            output.stdout,
        )
        .unwrap();
        fs::write(
            evidence.join(format!("t3-session-{case}.stderr.log")),
            output.stderr,
        )
        .unwrap();
        assert!(
            output.status.success() && ran,
            "session recovery probe failed: {case}"
        );
    }
}

#[test]
#[ignore = "isolated session probe invoked by its parent with a controlled shell profile"]
// Keep the ordered refusal, notice and PTY continuation on the same peer.
#[allow(clippy::too_many_lines)]
fn resize_refusal_session_probe() {
    let case = std::env::var("VT_SESSION_RECOVERY_CASE").unwrap();
    with_refusing_engine(2, |engine| {
        let uid = Uid::effective().as_raw();
        let mut child = ChildGuard(Pty::spawn(uid, 80, 24).unwrap());
        let mut terminal = Terminal::allocation_fixture(engine, PREFIX);
        let mut ring = Ring::new(if case == "gap" || case == "control" || case == "queued" {
            4
        } else {
            4096
        });
        ring.append(PREFIX).unwrap();
        let (stream, _reader) = UnixStream::pair().unwrap();
        let mut peer = Peer {
            stream,
            decoder: Decoder::default(),
            trailing: Vec::new(),
            deferred: None,
            attached: true,
            caps: APPROXIMATE_SNAPSHOT,
            input_reply: None,
            writer: Some(0),
            shared_writer: false,
            ack_queued: 0,
            size: (80, 24, 0, 0),
            cursor: Some(ring.head()),
            pending: Vec::new(),
            written: 0,
            exited_sent: false,
            stopping: false,
            request: None,
        };
        if case == "control" {
            peer.cursor = None;
            peer.caps |= SEQUENCED_INPUT;
        }
        if case == "queued" {
            peer.cursor = None;
            peer.request = Some(Request::Read(ring.head()));
        }
        let mut config = Config::new([0; 16], uid);
        let mut input = VecDeque::new();
        let mut cursors = Inputs::with_geometry(peer.size);
        if case == "readfrom" {
            // The terminal can lose state while no peer remains to receive the
            // initial recovery repaint. A new peer requesting the current head
            // still needs the approximate notice, even with full byte coverage.
            assert!(terminal.resize(0, 24).is_err());
        } else {
            let result = handle(
                Frame::Resize {
                    cols: 20_000,
                    rows: 2,
                    px_w: 0,
                    px_h: 0,
                },
                &mut peer,
                &mut child.0,
                &mut terminal,
                &ring,
                &mut config,
                &mut input,
                &mut cursors,
                false,
                false,
            );
            assert!(
                result.is_ok(),
                "native resize error must keep the peer usable"
            );
            assert_eq!((config.cols, config.rows), (80, 24));
            assert_eq!(cursors.get(Some(0)).unwrap().requested_size, (80, 24, 0, 0));
            assert_eq!(cursors.get(Some(0)).unwrap().accepted_size, (80, 24, 0, 0));
            if case == "control" {
                assert!(
                    peer.request.is_none(),
                    "control-only peer must not receive unsolicited repaint before its State fence"
                );
                handle(
                    Frame::InputStateRequest,
                    &mut peer,
                    &mut child.0,
                    &mut terminal,
                    &ring,
                    &mut config,
                    &mut input,
                    &mut cursors,
                    false,
                    false,
                )
                .unwrap();
                assert!(matches!(peer.input_reply, Some(InputReply::State)));
                // Replacement discards per-peer replies, never provenance.
                peer.input_reply = None;
                peer.caps = APPROXIMATE_SNAPSHOT;
            } else {
                assert!(matches!(peer.request, Some(Request::Snapshot)));
            }
        }
        handle(
            Frame::ReadFrom(ring.head()),
            &mut peer,
            &mut child.0,
            &mut terminal,
            &ring,
            &mut config,
            &mut input,
            &mut cursors,
            false,
            false,
        )
        .unwrap();
        let approximate = case != "exact";
        assert_eq!(terminal.requires_approximation(), approximate);
        if approximate {
            assert!(
                matches!(peer.request, Some(Request::Snapshot)),
                "current-head ReadFrom must not suppress recovery notice"
            );
        } else {
            assert!(
                matches!(peer.request, Some(Request::Read(_))),
                "exact reconstruction preserves raw replay priority"
            );
        }
        peer.snapshot(&terminal, ring.head()).unwrap();
        let frames = Decoder::default().feed(&peer.pending).unwrap();
        assert!(if approximate {
            matches!(&frames[0], Frame::SnapshotWithFlags(head, 1, _) if *head == ring.head())
        } else {
            matches!(&frames[0], Frame::Snapshot(head, _) if *head == ring.head())
        });
        if approximate {
            peer.caps = 0;
            peer.snapshot(&terminal, ring.head()).unwrap();
            let frames = Decoder::default().feed(&peer.pending).unwrap();
            assert!(
                matches!(&frames[0], Frame::Error(2, _)),
                "legacy recovery must stay explicit"
            );
        }
        // Read real shell output rather than relying on an unchanged config.
        // Split the marker so echoed input cannot satisfy the continuation test.
        handle(
            Frame::Input(b"stty size; printf 'FLOW_%s\\n' OK\n".to_vec()),
            &mut peer,
            &mut child.0,
            &mut terminal,
            &ring,
            &mut config,
            &mut input,
            &mut cursors,
            false,
            false,
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut output = Vec::new();
        while !output.windows(7).any(|value| value == b"FLOW_OK") {
            assert!(
                std::time::Instant::now() < deadline,
                "PTY continuation did not finish"
            );
            let mut bytes = [0; CHUNK];
            match child.0.master.read(&mut bytes) {
                Ok(n) => {
                    terminal.process(&bytes[..n]);
                    ring.append(&bytes[..n]).unwrap();
                    output.extend_from_slice(&bytes[..n]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("PTY continuation read refused: {error}"),
            }
        }
        assert!(
            output.windows(5).any(|value| value == b"24 80"),
            "PTY must return to last-good geometry"
        );
        assert!(input.is_empty(), "continued input must reach the PTY");
    });
}
