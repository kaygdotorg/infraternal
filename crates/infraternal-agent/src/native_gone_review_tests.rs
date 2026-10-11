//! Independent #158 review: a native attachment must deliver the final session-gone answer before retirement.

use super::*;

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
    let base = PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/codex-scratch/fds");
    std::fs::create_dir_all(&base).unwrap();
    let state = State {
        path: sessions::state(Some(
            base.join(format!("b{}", &id.simple().to_string()[..8])),
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
    let base = PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/codex-scratch/fds");
    std::fs::create_dir_all(&base).unwrap();
    let path = sessions::state(Some(
        base.join(format!("n{}", &id.simple().to_string()[..8])),
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
