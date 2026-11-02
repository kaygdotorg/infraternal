//! Reproduces a blocked fallback writer filling the shared reply queue; dispatcher admission must remain bounded [130], #78.

use super::*;
use std::sync::atomic::Ordering;
#[cfg(feature = "remote")]
use std::sync::{Mutex, atomic::AtomicBool};

#[test]
fn replay_prefix_stops_at_the_shim_hello_head() {
    assert_eq!(replay_prefix_len(100, 50, Some(125)), 25);
    assert_eq!(replay_prefix_len(125, 50, Some(125)), 0);
    assert_eq!(replay_prefix_len(130, 50, Some(125)), 0);
    assert_eq!(replay_prefix_len(100, 50, None), 50);
}

#[tokio::test]
async fn replay_complete_preserves_the_full_output_cursor_as_decimal() {
    let id = [0x5a; 16];
    let (tx, mut messages) = mpsc::channel(1);
    replay_complete(&tx, 17, id, u64::MAX, (80, 24))
        .await
        .unwrap();
    let Some(Message::Event(stream, json)) = messages.recv().await else {
        panic!("replay completion was not emitted as an Event");
    };
    let event: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(stream, 17);
    assert_eq!(event["type"], "terminal.replay_complete");
    assert_eq!(event["session_id"], uuid::Uuid::from_bytes(id).to_string());
    assert_eq!(event["out_seq"], u64::MAX.to_string());
    assert_eq!(event["cols"], 80);
    assert_eq!(event["rows"], 24);
}

#[test]
fn fixture_fence_processes_messages_before_the_control_pong() {
    let scripts = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
    let source = r#"
import struct
import sys
sys.path.insert(0, sys.argv[1])
from agent_fixture import Binary
binary = object.__new__(Binary)
binary.fence_nonce = 0
preceding = (1, 0x11, struct.pack("<Q", 0) + b"x")
frames = iter([preceding, (0, 0x09, struct.pack("<QQ", 1, 0))])
binary.read = lambda: next(frames)
binary.send = lambda *args: None
seen = []
binary.process = lambda credit=True, frame=None: seen.append(frame)
binary.fence()
assert seen == [preceding], seen
"#;
    let result = std::process::Command::new("python3")
        .arg("-c")
        .arg(source)
        .arg(scripts)
        .output()
        .expect("Python must be available for the real-binary fixture tests");
    assert!(
        result.status.success(),
        "fixture fence discarded a preceding frame: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(feature = "remote")]
struct StalledWriter {
    input: Mutex<(Vec<u8>, usize)>,
    greeted: AtomicBool,
    retired: AtomicBool,
    release: tokio::sync::Semaphore,
    written: mpsc::UnboundedSender<Vec<u8>>,
}
#[cfg(feature = "remote")]
impl Channel for StalledWriter {
    fn retire(&self) {
        self.retired.store(true, Ordering::Relaxed);
    }
    async fn read(&self, destination: &mut [u8]) -> io::Result<usize> {
        let copied = {
            let mut input = self.input.lock().unwrap();
            let count = destination.len().min(input.0.len() - input.1);
            destination[..count].copy_from_slice(&input.0[input.1..input.1 + count]);
            input.1 += count;
            count
        };
        if copied != 0 {
            return Ok(copied);
        }
        std::future::pending().await
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if !self.greeted.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        self.release.acquire().await.unwrap().forget();
        self.written.send(bytes.to_vec()).unwrap();
        Ok(())
    }
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn saturated_ping_replies_preserve_connection() {
    saturated_replies_preserve_connection(false).await;
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn saturated_action_replies_preserve_connection() {
    saturated_replies_preserve_connection(true).await;
}

/// Remove only this fixture's state after its dispatcher has been cancelled.
#[cfg(feature = "remote")]
struct ReplyState(PathBuf);
#[cfg(feature = "remote")]
impl Drop for ReplyState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(feature = "remote")]
async fn saturated_replies_preserve_connection(action: bool) {
    let mut wire = Vec::new();
    let mut encoded = Vec::new();
    let frames = std::iter::once(Frame::Hello {
        version: 1,
        caps: 0,
        client_info: "test",
    })
    .chain((0..32).map(|nonce| {
        if action {
            Frame::Call {
                call_id: u32::try_from(nonce).unwrap(),
                action_id: "terminal.open",
                input_json: b"{}",
            }
        } else {
            Frame::Ping { nonce, sent_us: 0 }
        }
    }));
    for frame in frames {
        infraternal_protocol::encode_muxed_frame_into(0, &frame, &mut encoded).unwrap();
        wire.extend_from_slice(&encoded);
    }
    let (written, mut frames) = mpsc::unbounded_channel();
    let channel = StalledWriter {
        input: Mutex::new((wire, 0)),
        greeted: AtomicBool::new(false),
        retired: AtomicBool::new(false),
        release: tokio::sync::Semaphore::new(0),
        written,
    };
    // Keep Unix socket paths short inside the caller's own build scratch root.
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/infraternal/target")
            .into_os_string()
    }));
    let state = ReplyState(target.parent().unwrap().join(format!(
        "rp{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )));
    {
        let running = run_authenticated(
            &channel,
            Some(state.0.clone()),
            nix::unistd::Uid::effective().as_raw(),
        );
        tokio::pin!(running);
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut running).await;
        assert!(
            result.is_err(),
            "local queue saturation retired the connection: {result:?}"
        );
        assert!(!channel.retired.load(Ordering::Relaxed));
        // Release the same writer, then prove that all replies survive in order.
        channel.release.add_permits(64);
        let drain = async {
            let mut expected = 0;
            while expected < 32 {
                let wire = frames.recv().await.unwrap();
                let decoded = infraternal_protocol::decode_muxed_frame(&wire).unwrap();
                match decoded.frame {
                    Frame::Pong { nonce, .. } if !action => {
                        assert_eq!(nonce, expected);
                        expected += 1;
                    }
                    Frame::Result {
                        call_id, ok: false, ..
                    } if action => {
                        assert_eq!(u64::from(call_id), expected);
                        expected += 1;
                    }
                    Frame::Event { .. } => {}
                    other => panic!("unexpected reply {other:?}"),
                }
            }
        };
        tokio::select! {
            result = &mut running => panic!("dispatcher ended before replies drained: {result:?}"),
            result = tokio::time::timeout(std::time::Duration::from_secs(5), drain) => result.unwrap(),
        }
    }
}

struct Capture(mpsc::UnboundedSender<Vec<u8>>);
impl Channel for Capture {
    async fn read(&self, _: &mut [u8]) -> io::Result<usize> {
        std::future::pending().await
    }
    fn write(&self, bytes: &[u8]) -> impl std::future::Future<Output = io::Result<()>> + Send {
        std::future::ready(
            self.0
                .send(bytes.to_vec())
                .map_err(|_| io::ErrorKind::BrokenPipe.into()),
        )
    }
}

#[tokio::test]
async fn mux_greeting_omits_cached_native_provider_capabilities() {
    let (bulk, bulk_rx) = mpsc::channel(1);
    drop(bulk);
    let (written, mut frames) = mpsc::unbounded_channel();
    writer(&Capture(written), bulk_rx, None, true, false, 64)
        .await
        .unwrap();
    let bytes = frames.recv().await.unwrap();
    let greeting = infraternal_protocol::decode_muxed_frame(&bytes).unwrap();
    assert!(
        matches!(greeting.frame, Frame::Hello { caps, .. } if caps & 64 == 0),
        "TCP/inherited channels cannot open native provider lanes"
    );
}

#[tokio::test]
async fn control_precedes_bulk_without_reordering_snapshot_notice() {
    let (bulk, bulk_rx) = mpsc::channel(8);
    let (control, control_rx) = mpsc::channel(8);
    assert!(
        bulk.try_send(Message::Event(
            42,
            b"{\"approximate_snapshot\":true}".to_vec()
        ))
        .is_ok()
    );
    assert!(
        bulk.try_send(Message::Shim(
            42,
            Shim::SnapshotWithFlags(123, 1, b"repaint".to_vec())
        ))
        .is_ok()
    );
    assert!(control.try_send(Message::Pong(0, 456, 0)).is_ok());
    let (written, mut frames) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        writer(
            &Capture(written),
            bulk_rx,
            Some(control_rx),
            false,
            false,
            0,
        )
        .await
    });
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), frames.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&first)
            .unwrap()
            .frame,
        Frame::Pong { nonce: 456, .. }
    ));
    let notice = tokio::time::timeout(std::time::Duration::from_secs(2), frames.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&notice)
            .unwrap()
            .frame,
        Frame::Event { .. }
    ));
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(2), frames.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&snapshot)
            .unwrap()
            .frame,
        Frame::Snapshot {
            out_seq: 123,
            bytes: b"repaint"
        }
    ));
    drop((bulk, control));
    task.await.unwrap().unwrap();
}

#[test]
#[ignore = "queue-only scale diagnostic; run alone without build/browser overlap, not whole-daemon memory"]
fn reply_lane_memory_at_1000_channels() {
    let baseline = rss();
    let mut bulk = Vec::with_capacity(1000);
    for nonce in 0..1000 {
        let (tx, rx) = mpsc::channel(8);
        assert!(tx.try_send(Message::Pong(0, nonce, 0)).is_ok());
        bulk.push((tx, rx));
    }
    let one_lane = rss();
    let started = Instant::now();
    let mut control = Vec::with_capacity(1000);
    for nonce in 0..1000 {
        let (tx, rx) = mpsc::channel(8);
        assert!(tx.try_send(Message::Pong(0, nonce, 0)).is_ok());
        control.push((tx, rx));
    }
    let elapsed = started.elapsed().as_micros();
    let two_lanes = rss();
    std::hint::black_box((&bulk, &control));
    println!(
        "reply_lane_diagnostic channels=1000 message_bytes={} baseline_rss_kib={baseline} one_lane_rss_kib={one_lane} two_lane_rss_kib={two_lanes} added_control_rss_kib_at1000={} added_control_rss_bytes_per_channel={} create_and_first_enqueue_us_at1000={elapsed} load={}",
        std::mem::size_of::<Message>(),
        two_lanes.saturating_sub(one_lane),
        two_lanes.saturating_sub(one_lane) * 1024 / 1000,
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}

fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn uninstall_handoff_runs_only_after_a_successful_real_socket_write() {
    use std::sync::atomic::AtomicUsize;
    use std::{os::fd::AsRawFd, sync::Arc};
    let count = Arc::new(AtomicUsize::new(0));
    for healthy in [false, true] {
        let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let socket = Socket::inherited(writer.as_raw_fd()).unwrap();
        // A concurrent fork can retain the peer briefly before exec closes its
        // CLOEXEC descriptor. Keep an alias to reproduce that window reliably.
        let _inherited_reader = reader.try_clone().unwrap();
        if !healthy {
            // Shut the socket itself down: a child that a concurrent test
            // forks holds a copy of `reader` until it execs, so dropping this
            // descriptor alone may leave the peer open (#234 break-it r2).
            reader.shutdown(std::net::Shutdown::Both).unwrap();
            drop(reader);
        }
        let effect = count.clone();
        let reply = infraternal_plugin_api::ActionReply {
            json: b"{}".to_vec(),
            after_write: Some(Box::new(move || {
                effect.fetch_add(1, Ordering::SeqCst);
            })),
        };
        let result = deferred_reply(&mut Transmit::default(), &socket, 0, 1, reply).await;
        assert_eq!(result.is_ok(), healthy);
        assert_eq!(count.load(Ordering::SeqCst), usize::from(healthy));
    }
}

#[tokio::test]
async fn census_and_open_result_share_fifo_order() {
    let (bulk, bulk_rx) = mpsc::channel(8);
    let (control, control_rx) = mpsc::channel(8);
    let mut published = None;
    assert!(
        publish_session_snapshot(
            &control,
            &crate::lifecycle::Registry::default(),
            &mut published
        )
        .unwrap()
    );
    reply(&control, Message::Result(0, 1, true, b"{}".to_vec())).unwrap();
    let (written, mut frames) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        writer(
            &Capture(written),
            bulk_rx,
            Some(control_rx),
            false,
            false,
            0,
        )
        .await
    });
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), frames.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&first)
            .unwrap()
            .frame,
        Frame::Event { .. }
    ));
    let second = tokio::time::timeout(std::time::Duration::from_secs(2), frames.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&second)
            .unwrap()
            .frame,
        Frame::Result {
            call_id: 1,
            ok: true,
            ..
        }
    ));
    drop((bulk, control));
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_saturated_census_queue_cannot_establish_the_open_fence() {
    let (control, mut receiver) = mpsc::channel(1);
    reply(&control, Message::Pong(0, 1, 0)).unwrap();
    let registry = crate::lifecycle::Registry::default();
    let mut published = None;
    assert!(!publish_session_snapshot(&control, &registry, &mut published).unwrap());
    assert!(published.is_none());
    receiver.recv().await.unwrap();
    assert!(publish_session_snapshot(&control, &registry, &mut published).unwrap());
    assert!(matches!(
        receiver.recv().await.unwrap(),
        Message::Event(0, _)
    ));
}

/// Break-it #234 r2: why `uninstall_handoff_runs_only_after_a_successful_real_socket_write`
/// used to flake. Its unhealthy case assumed `drop(reader)` closes the peer, so
/// the write must fail. That holds only while no other descriptor refers to the
/// reader's socket. Every child forked by a concurrently running test holds a
/// copy of every fd from fork until exec (CLOEXEC acts only at exec), so the
/// socket stayed open and the write succeeded into its buffer. `Socket` never
/// closes its fd (transport.rs), so it was not a double close. The fix shuts
/// the socket down, which acts on the socket rather than on one descriptor:
/// with a copy held the way a fork holds it, the write must still fail.
#[tokio::test]
async fn a_shut_down_peer_refuses_the_write_while_a_forked_copy_holds_it() {
    use std::os::fd::AsRawFd;
    let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let socket = Socket::inherited(writer.as_raw_fd()).unwrap();
    // What a child between fork and exec holds: another reference to the file.
    let forked_copy = reader.try_clone().unwrap();
    reader.shutdown(std::net::Shutdown::Both).unwrap();
    drop(reader);
    let reply = infraternal_plugin_api::ActionReply {
        json: b"{}".to_vec(),
        after_write: None,
    };
    let result = deferred_reply(&mut Transmit::default(), &socket, 0, 1, reply).await;
    drop(forked_copy);
    assert!(
        result.is_err(),
        "a shut-down peer must refuse the write even while a copy is open"
    );
}

/// The same race without a hand-made copy: the unhealthy pattern, with its
/// shutdown, while another thread spawns short children, as the parallel test
/// binary does.
#[tokio::test]
async fn the_unhealthy_handoff_case_survives_concurrent_spawns() {
    use std::os::fd::AsRawFd;
    use std::sync::atomic::AtomicBool;
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let spawner = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut children = 0u32;
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut child) = std::process::Command::new("true").spawn() {
                    let _ = child.wait();
                    children += 1;
                }
            }
            children
        })
    };
    let mut unexpected = 0;
    let rounds = 20_000;
    for _ in 0..rounds {
        let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let socket = Socket::inherited(writer.as_raw_fd()).unwrap();
        reader.shutdown(std::net::Shutdown::Both).unwrap();
        drop(reader);
        let reply = infraternal_plugin_api::ActionReply {
            json: b"{}".to_vec(),
            after_write: None,
        };
        if deferred_reply(&mut Transmit::default(), &socket, 0, 1, reply)
            .await
            .is_ok()
        {
            unexpected += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let children = spawner.join().unwrap();
    println!(
        "unhealthy_handoff_race rounds={rounds} spawned={children} write_succeeded={unexpected}"
    );
    assert_eq!(
        unexpected, 0,
        "a shut-down peer accepted {unexpected} of {rounds} writes"
    );
}

#[tokio::test]
async fn replay_geometry_is_frozen_before_queued_resize_and_delayed_output() {
    use infraternal_shim::frame::MULTI_WRITER;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = crate::test_state_root().join(&uuid::Uuid::new_v4().simple().to_string()[..8]);
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let shim = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        sessions::send(
            &mut peer,
            &Shim::Hello {
                version: 1,
                caps: SEQUENCED_INPUT | MULTI_WRITER,
                session: id,
                pid: std::process::id(),
                cols: 80,
                rows: 24,
                created: 0,
                head: 3,
                start: 0,
            },
        )
        .await
        .unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut peer).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(reader.read(&mut peer).await.unwrap(), Shim::SelectWriter(2));
        assert_eq!(
            reader.read(&mut peer).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut peer, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(reader.read(&mut peer).await.unwrap(), Shim::ReadFrom(0));
        // Hold replay until the attaching viewer's Resize has been processed.
        assert_eq!(
            reader.read(&mut peer).await.unwrap(),
            Shim::Resize {
                cols: 120,
                rows: 40,
                px_w: 0,
                px_h: 0
            }
        );
        sessions::send(&mut peer, &Shim::Output(0, b"abc".to_vec()))
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(8);
    let relay = tokio::spawn(terminal(path, id, 2, 0, 0, receiver, tx));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    commands.try_send(Command::Resize(120, 40, 0, 0)).unwrap();
    commands.try_send(Command::Credit(3)).unwrap();
    let check = async {
        assert!(
            matches!(messages.recv().await, Some(Message::Shim(2, Shim::Output(0, bytes))) if bytes == b"abc")
        );
        let Some(Message::Event(2, bytes)) = messages.recv().await else {
            panic!("missing replay fence");
        };
        let event: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(event["out_seq"], "3");
        assert_eq!(
            (event["cols"].as_u64(), event["rows"].as_u64()),
            (Some(80), Some(24))
        );
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), check).await;
    relay.abort();
    shim.abort();
    let _ = tokio::join!(relay, shim);
    std::fs::remove_dir_all(state).unwrap();
    result.unwrap();
}
