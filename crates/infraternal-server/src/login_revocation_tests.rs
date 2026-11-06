//! Verifies host login cleanup acknowledgements survive delayed writes and retryable refusals [D240,D247].
use super::*;
use bytes::{Buf, BytesMut};
use infraternal_protocol::{DecodeError, Frame, decode_muxed_frame, encode_muxed_frame_into};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

/// A bounded protocol fixture refuses the requested number of cleanup attempts, then acknowledges.
async fn cleanup_peer(mut socket: UnixStream, refusals: usize) {
    let mut input = BytesMut::new();
    let mut output = Vec::new();
    let mut calls = 0;
    loop {
        let frame = loop {
            match decode_muxed_frame(&input) {
                Ok(frame) => break frame,
                Err(DecodeError::Incomplete) => {
                    if socket.read_buf(&mut input).await.unwrap() == 0 {
                        return;
                    }
                }
                Err(error) => panic!("invalid cleanup fixture: {error:?}"),
            }
        };
        let size = frame.wire_len;
        let reply = match frame.frame {
            Frame::Hello { .. } => Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "cleanup-fixture",
            },
            Frame::Call {
                call_id,
                action_id,
                input_json,
            } => {
                assert_eq!(action_id, "terminal.login.revoke");
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(input_json).unwrap()["person"],
                    Uuid::from_u128(0x99).to_string()
                );
                calls += 1;
                // This is a functional delayed-ack fixture, not a latency measurement.
                if refusals == 0 && calls == 1 {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Frame::Result {
                    call_id,
                    ok: true,
                    json: if calls <= refusals {
                        br#"{"revoked":false}"#
                    } else {
                        br#"{"revoked":true}"#
                    },
                }
            }
            _ => panic!("unexpected cleanup frame"),
        };
        encode_muxed_frame_into(frame.stream_id, &reply, &mut output).unwrap();
        if socket.write_all(&output).await.is_err() {
            return;
        }
        input.advance(size);
    }
}

/// Route a retained cleanup through the production receipt helper and require eventual acknowledgement.
async fn confirmed_cleanup(refusals: usize) {
    let (socket, peer) = UnixStream::pair().unwrap();
    let task = tokio::spawn(cleanup_peer(peer, refusals));
    let actor = crate::embedded::EmbeddedAgent::from_test_socket(socket);
    let revocations = Revocations::default();
    let host = Uuid::new_v4();
    let signal = revocations.register(host).unwrap();
    *signal.login_actor.lock().unwrap() = Some(actor.downgrade());
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            revocations.revoke_login(host, Uuid::from_u128(0x99))
        )
        .await
        .unwrap(),
        "host removal abandoned an unconfirmed login cleanup"
    );
    drop(actor);
    task.abort();
    let _ = task.await;
}

/// A delayed durable receipt must keep host removal waiting.
#[tokio::test]
async fn host_removal_waits_for_delayed_cleanup_acknowledgement() {
    confirmed_cleanup(0).await;
}

/// A retryable refusal does not abandon the server's retained intent.
#[tokio::test]
async fn host_removal_retries_a_refused_cleanup() {
    confirmed_cleanup(1).await;
}
/// Busy replies retain backpressure instead of exhausting a finite retry budget.
#[tokio::test]
async fn host_removal_keeps_backpressure_beyond_three_busy_replies() {
    confirmed_cleanup(4).await;
}
/// Answers Hello, holds every `review.pending` call unanswered, and signals
/// once `ordinary` of them arrived. Cleanup calls are acknowledged unless
/// `hold_cleanups`, in which case they too stay pending and are signalled
/// after the `cleanups`-th one, so a test can fill the cleanup reserve.
async fn capacity_peer(
    mut peer: UnixStream,
    ordinary: usize,
    hold_cleanups: Option<usize>,
    full: tokio::sync::oneshot::Sender<()>,
    reserve_full: tokio::sync::oneshot::Sender<()>,
) {
    let mut input = BytesMut::new();
    let mut output = Vec::new();
    let (mut seen, mut cleanups) = (0, 0);
    let (mut full, mut reserve_full) = (Some(full), Some(reserve_full));
    loop {
        let frame = loop {
            match decode_muxed_frame(&input) {
                Ok(frame) => break frame,
                Err(DecodeError::Incomplete) => {
                    if peer.read_buf(&mut input).await.unwrap() == 0 {
                        return;
                    }
                }
                Err(error) => panic!("invalid capacity fixture: {error:?}"),
            }
        };
        let size = frame.wire_len;
        let reply = match frame.frame {
            Frame::Hello { .. } => Some(Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "capacity-fixture",
            }),
            Frame::Call {
                call_id,
                action_id: "terminal.login.revoke",
                ..
            } => match hold_cleanups {
                None => Some(Frame::Result {
                    call_id,
                    ok: true,
                    json: br#"{"revoked":true}"#,
                }),
                Some(limit) => {
                    cleanups += 1;
                    if cleanups == limit {
                        reserve_full.take().unwrap().send(()).unwrap();
                    }
                    (cleanups > limit).then_some(Frame::Result {
                        call_id,
                        ok: true,
                        json: br#"{"revoked":true}"#,
                    })
                }
            },
            Frame::Call {
                action_id: "review.pending",
                ..
            } => {
                seen += 1;
                if seen == ordinary {
                    full.take().unwrap().send(()).unwrap();
                }
                assert!(seen <= ordinary, "ordinary control capacity exceeded");
                None
            }
            _ => panic!("unexpected capacity fixture frame"),
        };
        if let Some(reply) = reply {
            output.clear();
            encode_muxed_frame_into(frame.stream_id, &reply, &mut output).unwrap();
            if peer.write_all(&output).await.is_err() {
                return;
            }
        }
        input.advance(size);
    }
}

/// Fills `capacity` ordinary control slots with unanswered calls on a real
/// Unix socket, then returns the actor, the calls and the peer task.
async fn saturated_actor(
    capacity: usize,
    hold_cleanups: Option<usize>,
) -> (
    crate::embedded::EmbeddedAgent,
    Vec<tokio::task::JoinHandle<Result<Vec<u8>, crate::embedded::AgentError>>>,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (socket, peer) = UnixStream::pair().unwrap();
    let (full_tx, full_rx) = tokio::sync::oneshot::channel();
    let (reserve_tx, reserve_rx) = tokio::sync::oneshot::channel();
    let peer_task = tokio::spawn(capacity_peer(
        peer,
        capacity,
        hold_cleanups,
        full_tx,
        reserve_tx,
    ));
    let actor = crate::embedded::EmbeddedAgent::from_test_socket(socket);
    let mut calls = Vec::new();
    for _ in 0..capacity {
        let actor = actor.clone();
        calls.push(tokio::spawn(async move {
            actor.call("review.pending".into(), b"{}".to_vec()).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(10), full_rx)
        .await
        .unwrap()
        .unwrap();
    (actor, calls, peer_task, reserve_rx)
}

async fn cleanup_with_pending_calls(capacity: usize) -> bool {
    // A burst of legitimate operations may fill the 64 ordinary control slots.
    // Access removal must still reach a connected host before its channel retires.
    let (actor, calls, peer_task, _) = saturated_actor(capacity, None).await;
    let revocations = Revocations::default();
    let host = Uuid::new_v4();
    let signal = revocations.register(host).unwrap();
    *signal.login_actor.lock().unwrap() = Some(actor.downgrade());
    let confirmed = tokio::time::timeout(
        Duration::from_secs(5),
        revocations.revoke_login(host, Uuid::from_u128(0x99)),
    )
    .await
    .unwrap();
    for call in calls {
        call.abort();
        let _ = call.await;
    }
    peer_task.abort();
    let _ = peer_task.await;
    eprintln!("ordinary_pending={capacity} cleanup_confirmed={confirmed}");
    confirmed
}

#[tokio::test]
async fn connected_host_cleanup_is_admitted_when_ordinary_control_calls_are_full() {
    assert!(
        cleanup_with_pending_calls(63).await,
        "connected host cleanup failed below capacity"
    );
    assert!(
        cleanup_with_pending_calls(64).await,
        "all three cleanup attempts were refused by ordinary control capacity on a connected host"
    );
}

/// Unanswered cleanup requests cannot turn the former reserve into a new quota.
#[tokio::test]
async fn cleanup_remains_admitted_beyond_the_former_reserve_limit() {
    const RESERVE: usize = 16;
    let (actor, calls, peer_task, reserve_full) = saturated_actor(64, Some(RESERVE)).await;
    // Ordinary call 65 is refused: the reserve is not ordinary capacity.
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(5),
            actor.call("review.pending".into(), b"{}".to_vec())
        )
        .await
        .unwrap(),
        Err(crate::embedded::AgentError::Unavailable)
    );
    let weak = actor.downgrade();
    let mut held = Vec::new();
    for _ in 0..RESERVE {
        let weak = weak.clone();
        held.push(tokio::spawn(async move {
            weak.revoke_login(Uuid::from_u128(0x99)).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(10), reserve_full)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..RESERVE {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), weak.revoke_login(Uuid::new_v4()))
                .await
                .unwrap(),
            Ok(())
        );
    }
    for task in held {
        task.abort();
        let _ = task.await;
    }
    for call in calls {
        call.abort();
        let _ = call.await;
    }
    assert!(!peer_task.is_finished(), "fixture rejected a frame");
    peer_task.abort();
    let _ = peer_task.await;
}
