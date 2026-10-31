//! Independent #158 review: a native attachment must deliver the final session-gone answer before retirement.

use super::*;

struct SocketFixture {
    path: std::path::PathBuf,
}

impl Drop for SocketFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn socket_fixture_base(id: uuid::Uuid) -> SocketFixture {
    use std::os::unix::fs::DirBuilderExt as _;

    // Job-specific state roots can exceed AF_UNIX's 108-byte path limit after the rendezvous suffix.
    // A private UUID directory in /tmp keeps this socket fixture short and isolates parallel test runs.
    let path = std::path::PathBuf::from("/tmp").join(format!("if-{}", id.simple()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    SocketFixture { path }
}

/// A native peer that accepts `AttachTerm` but never consumes the final reply.
struct BlockedNative {
    attach: std::sync::Mutex<Option<Vec<u8>>>,
    retired: std::sync::atomic::AtomicBool,
}

impl crate::channel::Channel for BlockedNative {
    fn native_stream_id(&self) -> Option<u32> {
        Some(42)
    }
    fn retire(&self) {
        self.retired
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    async fn read(&self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let attach = self.attach.lock().unwrap().take();
        if let Some(attach) = attach {
            bytes[..attach.len()].copy_from_slice(&attach);
            return Ok(attach.len());
        }
        std::future::pending().await
    }
    async fn write(&self, _: &[u8]) -> std::io::Result<()> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn vanished_native_session_bounds_final_reply_drain_for_a_stuck_peer() {
    let id = uuid::Uuid::new_v4();
    let base = socket_fixture_base(id);
    let state = State {
        path: sessions::state(Some(
            base.path
                .join(format!("b{}", &id.simple().to_string()[..8])),
        ))
        .unwrap(),
        pid: None,
    };
    let mut attach = Vec::new();
    infraternal_protocol::encode_frame_into(
        &Frame::AttachTerm {
            session_id: id.as_bytes(),
            last_out_seq: 0,
            last_in_seq: 0,
        },
        &mut attach,
    )
    .unwrap();
    let channel = BlockedNative {
        attach: std::sync::Mutex::new(Some(attach)),
        retired: std::sync::atomic::AtomicBool::new(false),
    };
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        daemon::run_bound_terminal(&channel, Some(state.path.clone())),
    )
    .await
    .expect("a stuck peer pinned the final reply drain");
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(channel.retired.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn vanished_native_session_delivers_final_close_before_stream_retirement() {
    let id = uuid::Uuid::new_v4();
    let base = socket_fixture_base(id);
    let path = sessions::state(Some(
        base.path
            .join(format!("n{}", &id.simple().to_string()[..8])),
    ))
    .unwrap();
    let state = State { path, pid: None };
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let host = NativeChannel::terminal(host.unwrap()).unwrap();
    let path = state.path.clone();
    let task = tokio::spawn(async move { daemon::run_bound_terminal(&host, Some(path)).await });
    let channel = NativeChannel::terminal(server.unwrap()).unwrap();
    Transmit::default()
        .send(
            &channel,
            42,
            &Frame::AttachTerm {
                session_id: id.as_bytes(),
                last_out_seq: 0,
                last_in_seq: 0,
            },
        )
        .await
        .unwrap();
    let mut receive = Receive::default();
    let result = tokio::time::timeout(Duration::from_secs(20), receive.next(&channel)).await;
    // Join before asserting so every owned task is cleaned up on a failed assertion.
    let finished = tokio::time::timeout(Duration::from_secs(20), task).await;
    assert!(
        matches!(finished, Ok(Ok(Ok(())))),
        "native relay result: {finished:?}"
    );
    let decoded = result
        .expect("native final answer timed out")
        .expect("native stream retired before its final answer");
    assert_eq!(decoded.stream_id, 42);
    assert_eq!(
        decoded.frame,
        Frame::Close {
            code: infraternal_protocol::CLOSE_SESSION_GONE,
            reason: infraternal_protocol::SESSION_GONE_REASON,
        }
    );
}

#[tokio::test]
async fn retired_native_session_delivers_saved_status_then_final_close_before_retirement() {
    let id = uuid::Uuid::new_v4();
    let base = socket_fixture_base(id);
    let state = State {
        path: sessions::state(Some(
            base.path
                .join(format!("r{}", &id.simple().to_string()[..8])),
        ))
        .unwrap(),
        pid: None,
    };
    infraternal_shim::ended::record(&sessions::rendezvous(&state.path, *id.as_bytes()), 7, 42)
        .unwrap();
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let host = NativeChannel::terminal(host.unwrap()).unwrap();
    let path = state.path.clone();
    let task = tokio::spawn(async move { daemon::run_bound_terminal(&host, Some(path)).await });
    let channel = NativeChannel::terminal(server.unwrap()).unwrap();
    Transmit::default()
        .send(
            &channel,
            42,
            &Frame::AttachTerm {
                session_id: id.as_bytes(),
                last_out_seq: 0,
                last_in_seq: 0,
            },
        )
        .await
        .unwrap();
    let mut receive = Receive::default();
    tokio::time::timeout(Duration::from_secs(20), async {
        let decoded = receive.next(&channel).await.unwrap();
        assert_eq!(decoded.stream_id, 42);
        let Frame::Event { sub_id: 0, event_json } = decoded.frame else { panic!("missing saved exit notice") };
        let event: serde_json::Value = serde_json::from_slice(event_json).unwrap();
        assert_eq!(event, serde_json::json!({"type":"terminal.exited","session_id":id,"status":7,"final_seq":42,"retired":true}));
        let decoded = receive.next(&channel).await.unwrap();
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.frame, Frame::Close {
            code: infraternal_protocol::CLOSE_SESSION_GONE,
            reason: infraternal_protocol::SESSION_GONE_REASON,
        });
    }).await.expect("saved exit or final close lost before native retirement");
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(20), task).await,
        Ok(Ok(Ok(())))
    ));
}

/// Queued native commands race a real retiring shim; a slow write models leg-B backpressure.
struct QueuedNative {
    input: std::sync::Mutex<Vec<u8>>,
    output: std::sync::Mutex<Vec<u8>>,
}
impl crate::channel::Channel for QueuedNative {
    fn native_stream_id(&self) -> Option<u32> {
        Some(42)
    }
    async fn read(&self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let length = {
            let mut input = self.input.lock().unwrap();
            let length = input.len().min(bytes.len());
            bytes[..length].copy_from_slice(&input[..length]);
            input.drain(..length);
            length
        };
        if length == 0 {
            std::future::pending().await
        } else {
            Ok(length)
        }
    }
    async fn write(&self, bytes: &[u8]) -> std::io::Result<()> {
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.output.lock().unwrap().extend_from_slice(bytes);
        Ok(())
    }
}

#[tokio::test]
async fn retiring_native_handshake_preserves_final_answer_with_inflight_commands() {
    let id = uuid::Uuid::new_v4();
    let base = socket_fixture_base(id);
    let state = State {
        path: sessions::state(Some(
            base.path
                .join(format!("q{}", &id.simple().to_string()[..8])),
        ))
        .unwrap(),
        pid: None,
    };
    let socket = sessions::rendezvous(&state.path, *id.as_bytes());
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    infraternal_shim::ended::record(&socket, 7, 42).unwrap();
    let retiring = tokio::spawn(async move {
        drop(listener.accept().await.unwrap());
    });
    let mut input = Vec::new();
    infraternal_protocol::encode_frame_into(
        &Frame::AttachTerm {
            session_id: id.as_bytes(),
            last_out_seq: 0,
            last_in_seq: 0,
        },
        &mut input,
    )
    .unwrap();
    let mut credit = Vec::new();
    infraternal_protocol::encode_frame_into(&Frame::Credit { bytes: 1 }, &mut credit).unwrap();
    for _ in 0..16 {
        input.extend_from_slice(&credit);
    }
    let channel = QueuedNative {
        input: std::sync::Mutex::new(input),
        output: std::sync::Mutex::new(Vec::new()),
    };
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        daemon::run_bound_terminal(&channel, Some(state.path.clone())),
    )
    .await;
    retiring.await.unwrap();
    assert!(
        matches!(result, Ok(Ok(()))),
        "in-flight command cancelled the saved final answer: {result:?}"
    );
    let output = channel.output.lock().unwrap();
    let notice = infraternal_protocol::decode_frame(&output).unwrap();
    let Frame::Event { event_json, .. } = notice.frame else {
        panic!("missing saved event")
    };
    let event: serde_json::Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(event["status"], 7);
    assert_eq!(event["retired"], true);
    let ended = infraternal_protocol::decode_frame(&output[notice.wire_len..]).unwrap();
    assert!(matches!(ended.frame, Frame::Close { code: 4404, .. }));
}

#[tokio::test]
async fn retired_native_status_bounds_final_reply_drain_for_a_stuck_peer() {
    let id = uuid::Uuid::new_v4();
    let base = socket_fixture_base(id);
    let state = State {
        path: sessions::state(Some(
            base.path
                .join(format!("t{}", &id.simple().to_string()[..8])),
        ))
        .unwrap(),
        pid: None,
    };
    infraternal_shim::ended::record(&sessions::rendezvous(&state.path, *id.as_bytes()), 7, 42)
        .unwrap();
    let mut attach = Vec::new();
    infraternal_protocol::encode_frame_into(
        &Frame::AttachTerm {
            session_id: id.as_bytes(),
            last_out_seq: 0,
            last_in_seq: 0,
        },
        &mut attach,
    )
    .unwrap();
    let channel = BlockedNative {
        attach: std::sync::Mutex::new(Some(attach)),
        retired: std::sync::atomic::AtomicBool::new(false),
    };
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        daemon::run_bound_terminal(&channel, Some(state.path.clone())),
    )
    .await
    .expect("saved exit pinned the final reply drain");
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(channel.retired.load(std::sync::atomic::Ordering::Relaxed));
}
