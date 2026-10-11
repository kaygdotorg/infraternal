//! Reproduces a blocked fallback writer filling the shared reply queue; dispatcher admission must remain bounded [130], #78.

use super::*;
#[cfg(feature = "remote")]
use std::sync::{Mutex, atomic::AtomicBool};

#[cfg(feature = "remote")]
struct StalledWriter {
    input: Mutex<(Vec<u8>, usize)>,
    greeted: AtomicBool,
    retired: AtomicBool,
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
    async fn write(&self, _: &[u8]) -> io::Result<()> {
        if !self.greeted.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        std::future::pending().await
    }
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn saturated_replies_retire_connection_without_awaiting_writer_capacity() {
    let mut wire = Vec::new();
    let mut encoded = Vec::new();
    let frames = std::iter::once(Frame::Hello {
        version: 1,
        caps: 0,
        client_info: "test",
    })
    .chain((0..32).map(|nonce| Frame::Ping { nonce, sent_us: 0 }));
    for frame in frames {
        infraternal_protocol::encode_muxed_frame_into(0, &frame, &mut encoded).unwrap();
        wire.extend_from_slice(&encoded);
    }
    let channel = StalledWriter {
        input: Mutex::new((wire, 0)),
        greeted: AtomicBool::new(false),
        retired: AtomicBool::new(false),
    };
    let state = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".cache/codex-scratch/remote-agents")
        .join(format!("readiness-{}", uuid::Uuid::new_v4()));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        run_authenticated(
            &channel,
            Some(state.clone()),
            nix::unistd::Uid::effective().as_raw(),
        ),
    )
    .await;
    let _ = std::fs::remove_dir_all(state);
    assert_eq!(
        result
            .expect("shared dispatcher stalled behind writer capacity")
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(channel.retired.load(Ordering::Relaxed));
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
    assert!(control.try_send(Message::Pong(456, 0)).is_ok());
    let (written, mut frames) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        writer(&Capture(written), bulk_rx, Some(control_rx), false, false).await
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
        assert!(tx.try_send(Message::Pong(nonce, 0)).is_ok());
        bulk.push((tx, rx));
    }
    let one_lane = rss();
    let started = Instant::now();
    let mut control = Vec::with_capacity(1000);
    for nonce in 0..1000 {
        let (tx, rx) = mpsc::channel(8);
        assert!(tx.try_send(Message::Pong(nonce, 0)).is_ok());
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
        if !healthy {
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
        writer(&Capture(written), bulk_rx, Some(control_rx), false, false).await
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
    reply(&control, Message::Pong(1, 0)).unwrap();
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
