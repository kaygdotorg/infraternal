//! Exercises actual terminal actor routing and confirmed output forms used by SSH readiness.
use super::*;
use bytes::{Buf, BytesMut};
use infraternal_protocol::{DecodeError, Frame, decode_muxed_frame, encode_muxed_frame_into};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

async fn terminal_peer(
    mut socket: UnixStream,
    snapshot: bool,
    fail_attach: bool,
    mut cleaned: Option<tokio::sync::oneshot::Sender<()>>,
) {
    let mut pending = BytesMut::new();
    let mut reply = Vec::new();
    loop {
        let frame = loop {
            match decode_muxed_frame(&pending) {
                Ok(frame) => break frame,
                Err(DecodeError::Incomplete) => {
                    if socket.read_buf(&mut pending).await.unwrap() == 0 {
                        return;
                    }
                }
                Err(error) => panic!("invalid fixture frame: {error:?}"),
            }
        };
        let length = frame.wire_len;
        let response = match frame.frame {
            Frame::Hello { .. } => Some(Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "readiness-peer",
            }),
            Frame::Call {
                call_id,
                action_id,
                input_json,
            } => {
                if action_id == "terminal.open" {
                    let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
                    assert_eq!(input["readiness"], true, "canary must bypass login startup");
                }
                Some(Frame::Result {
                    call_id,
                    ok: true,
                    json: br#"{"session_id":"11111111111111111111111111111111"}"#,
                })
            }
            Frame::AttachTerm { .. } if fail_attach && frame.stream_id == 2 => Some(Frame::Close {
                code: 1,
                reason: "fixture attachment failure",
            }),
            Frame::AttachTerm { .. } => Some(Frame::Ack { in_seq_acked: 0 }),
            _ => None,
        };
        if let Some(response) = response {
            encode_muxed_frame_into(frame.stream_id, &response, &mut reply).unwrap();
            socket.write_all(&reply).await.unwrap();
        }
        if let Frame::Input { bytes, .. } = frame.frame {
            // The controlled peer emits a marker only after the actual actor forwards the input.
            assert_eq!(bytes, b"\n");
            if frame.stream_id == 2 && cleaned.is_some() && !fail_attach {
                // A held private command lets cancellation land after ownership.
                pending.advance(length);
                continue;
            }
            if frame.stream_id == 4 {
                if let Some(cleaned) = cleaned.take() {
                    let _ = cleaned.send(());
                }
                encode_muxed_frame_into(
                    4,
                    &Frame::Event {
                        sub_id: 0,
                        event_json: br#"{"type":"terminal.exited","session_id":"11111111111111111111111111111111","status":0,"final_seq":0}"#,
                    },
                    &mut reply,
                )
                .unwrap();
                socket.write_all(&reply).await.unwrap();
            }
            let marker = "infraternal-ready";
            let response = if snapshot {
                Frame::Snapshot {
                    out_seq: marker.len() as u64,
                    bytes: marker.as_bytes(),
                }
            } else {
                Frame::Output {
                    out_seq: 0,
                    bytes: marker.as_bytes(),
                }
            };
            encode_muxed_frame_into(frame.stream_id, &response, &mut reply).unwrap();
            socket.write_all(&reply).await.unwrap();
        }
        pending.advance(length);
    }
}

#[tokio::test]
async fn readiness_input_preserves_the_terminal_actor_and_host_connection() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let task = tokio::spawn(terminal_peer(peer, false, false, None));
    let actor = EmbeddedAgent::from_test_socket(socket);
    tokio::time::timeout(Duration::from_secs(5), canary(&actor))
        .await
        .unwrap()
        .unwrap();
    assert!(
        actor
            .call("host.facts.read".into(), b"{}".to_vec())
            .await
            .is_ok()
    );
    drop(actor);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn readiness_accepts_authoritative_snapshot_output() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let task = tokio::spawn(terminal_peer(peer, true, false, None));
    let actor = EmbeddedAgent::from_test_socket(socket);
    tokio::time::timeout(Duration::from_secs(5), canary(&actor))
        .await
        .unwrap()
        .unwrap();
    drop(actor);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn failed_attachment_finishes_the_private_command() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let (cleaned, done) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(terminal_peer(peer, false, true, Some(cleaned)));
    let actor = EmbeddedAgent::from_test_socket(socket);
    let failure = canary(&actor).await.unwrap_err();
    assert_eq!(
        serde_json::to_value(&failure).unwrap()["failed_step"],
        "readiness"
    );
    tokio::time::timeout(Duration::from_secs(1), done)
        .await
        .expect("failed canary left its private session open")
        .unwrap();
    task.abort();
}

#[tokio::test]
async fn cancellation_keeps_the_owned_session_available_for_cleanup() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let (cleaned, done) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(terminal_peer(peer, false, false, Some(cleaned)));
    let actor = EmbeddedAgent::from_test_socket(socket);
    let (opened, session) = tokio::sync::oneshot::channel();
    let proof_actor = actor.clone();
    let proof = tokio::spawn(async move {
        canary_registered(&proof_actor, |id| {
            opened.send(id).unwrap();
            Ok(())
        })
        .await
    });
    let id = session.await.unwrap();
    proof.abort();
    let _ = proof.await;
    finish_canary(&actor, id).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), done)
        .await
        .unwrap()
        .unwrap();
    task.abort();
}
