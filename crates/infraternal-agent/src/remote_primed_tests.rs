//! Tests negotiated native priming over real QUIC with a controlled Unix shim peer; real PTY coexistence is covered by shim integration [215], #129.
use super::*;
use crate::sessions::Reader;
use infraternal_shim::frame::{Frame as Shim, MULTI_WRITER, SEQUENCED_INPUT, SHARED_WRITER};
use std::{os::unix::fs::DirBuilderExt, path::PathBuf};
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};

struct Fixture {
    state: PathBuf,
    task: JoinHandle<()>,
    seen: mpsc::Receiver<Shim>,
    id: [u8; 16],
    size: std::sync::Arc<std::sync::atomic::AtomicU32>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.state);
    }
}
impl Fixture {
    fn new() -> Self {
        let state = crate::test_state_root()
            .join("mc")
            .join(&uuid::Uuid::new_v4().simple().to_string()[..8]);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state.join("sessions"))
            .unwrap();
        let id = *uuid::Uuid::new_v4().as_bytes();
        let socket = state
            .join("sessions")
            .join(format!("{}.sock", uuid::Uuid::from_bytes(id).simple()));
        assert!(socket.as_os_str().len() <= 107);
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        let (observed, seen) = mpsc::channel(8);
        let size = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0x0050_0018));
        let geometry = size.clone();
        let task = tokio::spawn(async move {
            let mut peers = JoinSet::new();
            loop {
                let (mut peer, _) = listener.accept().await.unwrap();
                let observed = observed.clone();
                let size = geometry.load(std::sync::atomic::Ordering::SeqCst);
                peers.spawn(async move {
                    peer.write_all(
                        &Shim::Hello {
                            version: 1,
                            caps: SEQUENCED_INPUT | MULTI_WRITER | SHARED_WRITER,
                            session: id,
                            pid: std::process::id(),
                            created: 0,
                            cols: u16::try_from(size >> 16).unwrap(),
                            rows: u16::try_from(size & 0xffff).unwrap(),
                            head: 9,
                            start: 0,
                        }
                        .encode()
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                    let mut reader = Reader::default();
                    while let Ok(frame) = reader.read(&mut peer).await {
                        observed.send(frame.clone()).await.unwrap();
                        let reply = match frame {
                            Shim::InputStateRequest => Some(Shim::InputState(0, 0)),
                            Shim::ReadFrom(seq) => Some(Shim::Output(seq, b"abc".to_vec())),
                            Shim::SequencedInput(seq, bytes) => {
                                Some(Shim::InputAck(seq + bytes.len() as u64))
                            }
                            _ => None,
                        };
                        if let Some(reply) = reply {
                            peer.write_all(&reply.encode().unwrap()).await.unwrap();
                        }
                    }
                });
            }
        });
        Self {
            state,
            task,
            seen,
            id,
            size,
        }
    }
}

async fn terminal(pair: &Pair) -> (NativeChannel, NativeChannel) {
    let server = pair.binding(true);
    let host = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server, 42),
        remote_quic::accept_bound(&host)
    );
    (
        NativeChannel::terminal(server.unwrap()).unwrap(),
        NativeChannel::terminal(host.unwrap()).unwrap(),
    )
}

#[tokio::test]
async fn primed_writer_acknowledges_before_reading_credit_funded_cursor() {
    let pair = Pair::new().await;
    let (server, host) = terminal(&pair).await;
    let mut fixture = Fixture::new();
    let state = fixture.state.clone();
    let daemon = tokio::spawn(async move {
        crate::daemon::run_negotiated_bound_terminal(&host, Some(state)).await
    });
    let mut tx = Transmit::default();
    tx.send(
        &server,
        42,
        &Frame::Call {
            call_id: 0,
            action_id: "transport.prime",
            input_json: b"{}",
        },
    )
    .await
    .unwrap();
    tx.send(
        &server,
        42,
        &Frame::AttachTerm {
            session_id: &fixture.id,
            last_out_seq: 9,
            last_in_seq: 0,
        },
    )
    .await
    .unwrap();
    let mut rx = Receive::default();
    assert_eq!(
        rx.next(&server).await.unwrap().frame,
        Frame::Ack { in_seq_acked: 0 }
    );
    assert!(
        matches!(fixture.seen.recv().await.unwrap(), Shim::Attach(caps) if caps & SHARED_WRITER != 0)
    );
    assert_eq!(
        fixture.seen.recv().await.unwrap(),
        Shim::SelectSharedWriter(42)
    );
    assert_eq!(fixture.seen.recv().await.unwrap(), Shim::InputStateRequest);
    tx.send(&server, 42, &Frame::Credit { bytes: 3 })
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), fixture.seen.recv())
            .await
            .is_err(),
        "priming must not serialize output before a delivered cursor"
    );
    fixture
        .size
        .store(0x0078_0028, std::sync::atomic::Ordering::SeqCst);
    tx.send(
        &server,
        42,
        &Frame::Call {
            call_id: 0,
            action_id: "transport.cursor",
            input_json: br#"{"out_seq":9}"#,
        },
    )
    .await
    .unwrap();
    tx.send(&server, 42, &Frame::Credit { bytes: 3 })
        .await
        .unwrap();
    tx.send(
        &server,
        42,
        &Frame::Input {
            in_seq: 0,
            bytes: b"x",
        },
    )
    .await
    .unwrap();
    let mut output = false;
    let mut ack = false;
    let mut replay_complete = false;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !output || !ack || !replay_complete {
            match rx.next(&server).await.unwrap().frame {
                Frame::Output { out_seq: 9, bytes } if bytes == b"abc" => {
                    assert!(!output);
                    assert!(replay_complete, "live output must follow the replay fence");
                    output = true;
                }
                Frame::Ack { in_seq_acked: 1 } => ack = true,
                Frame::Event {
                    sub_id: 0,
                    event_json,
                } => {
                    assert!(!output && !replay_complete);
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(event_json).unwrap(),
                        serde_json::json!({
                            "type": "terminal.replay_complete",
                            "session_id": uuid::Uuid::from_bytes(fixture.id),
                            "out_seq": "9",
                            "cols": 120,
                            "rows": 40,
                        })
                    );
                    replay_complete = true;
                }
                other => panic!("unexpected primed response: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    daemon.abort();
    let _ = daemon.await;
    assert!(
        pair.client.close_reason().is_none(),
        "cancelling one writer must preserve sibling transport"
    );
}

#[tokio::test]
async fn ordinary_native_writer_refuses_the_additive_cursor_request() {
    let pair = Pair::new().await;
    let (server, host) = terminal(&pair).await;
    let fixture = Fixture::new();
    let state = fixture.state.clone();
    let daemon =
        tokio::spawn(async move { crate::daemon::run_bound_terminal(&host, Some(state)).await });
    let mut tx = Transmit::default();
    tx.send(
        &server,
        42,
        &Frame::AttachTerm {
            session_id: &fixture.id,
            last_out_seq: 9,
            last_in_seq: 0,
        },
    )
    .await
    .unwrap();
    let mut rx = Receive::default();
    assert_eq!(
        rx.next(&server).await.unwrap().frame,
        Frame::Ack { in_seq_acked: 0 }
    );
    tx.send(
        &server,
        42,
        &Frame::Call {
            call_id: 0,
            action_id: "transport.cursor",
            input_json: br#"{"out_seq":9}"#,
        },
    )
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), daemon)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn negotiated_connection_keeps_unmarked_new_writers_ordinary() {
    let pair = Pair::new().await;
    let (server, host) = terminal(&pair).await;
    let mut fixture = Fixture::new();
    let state = fixture.state.clone();
    let daemon = tokio::spawn(async move {
        crate::daemon::run_negotiated_bound_terminal(&host, Some(state)).await
    });
    Transmit::default()
        .send(
            &server,
            42,
            &Frame::AttachTerm {
                session_id: &fixture.id,
                last_out_seq: 9,
                last_in_seq: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        Receive::default().next(&server).await.unwrap().frame,
        Frame::Ack { in_seq_acked: 0 }
    );
    assert!(matches!(
        fixture.seen.recv().await.unwrap(),
        Shim::Attach(_)
    ));
    assert_eq!(fixture.seen.recv().await.unwrap(), Shim::SelectWriter(42));
    daemon.abort();
    let _ = daemon.await;
}

#[tokio::test]
async fn prime_marker_is_canonical_and_requires_negotiated_permission() {
    for (allowed, call_id, input_json) in [
        (false, 0, b"{}".as_slice()),
        (true, 1, b"{}".as_slice()),
        (true, 0, b"{} ".as_slice()),
        (true, 0, b"{\"writer\":42}".as_slice()),
    ] {
        let pair = Pair::new().await;
        let (server, host) = terminal(&pair).await;
        let fixture = Fixture::new();
        let state = fixture.state.clone();
        let daemon = tokio::spawn(async move {
            if allowed {
                crate::daemon::run_negotiated_bound_terminal(&host, Some(state)).await
            } else {
                crate::daemon::run_bound_terminal(&host, Some(state)).await
            }
        });
        Transmit::default()
            .send(
                &server,
                42,
                &Frame::Call {
                    call_id,
                    action_id: "transport.prime",
                    input_json,
                },
            )
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), daemon)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(pair.client.close_reason().is_none());
    }
}
