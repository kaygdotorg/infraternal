//! Exercises actual terminal actor routing and confirmed output forms used by SSH readiness.
use super::*;
use bytes::{Buf, BytesMut};
use infraternal_protocol::{DecodeError, Frame, decode_muxed_frame, encode_muxed_frame_into};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

// Controlled replies keep fixed PTY readiness separate from login admission,
// while asserting the exact trusted person/preferred-account payload.
fn call_response(
    call_id: u32,
    action_id: &str,
    input_json: &[u8],
    restoration: Option<&'static [u8]>,
    preparation: Option<bool>,
) -> Frame<'static> {
    if action_id == "terminal.open" {
        let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
        assert_eq!(input["readiness"], true, "canary must bypass login startup");
    }
    let json = if action_id == "terminal.login.restore" {
        let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
        assert_eq!(input["person"], Uuid::from_u128(0x88).to_string());
        restoration.expect("unexpected restoration request")
    } else {
        br#"{"session_id":"11111111111111111111111111111111"}"#
    };
    if action_id == "terminal.login.prepare" {
        let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
        assert_eq!(input["person"], Uuid::from_u128(0x88).to_string());
        assert_eq!(input["account"], "deploy");
        Frame::Result {
            call_id,
            ok: preparation.expect("unexpected login preparation"),
            json: br#"{"prepared":true}"#,
        }
    } else {
        Frame::Result {
            call_id,
            ok: true,
            json,
        }
    }
}

#[derive(Clone, Copy)]
enum Retirement {
    Available,
    Retired,
}

async fn terminal_peer(
    mut socket: UnixStream,
    snapshot: bool,
    retirement: Retirement,
    fail_attach: bool,
    restoration: Option<&'static [u8]>,
    preparation: Option<bool>,
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
            } => Some(call_response(
                call_id,
                action_id,
                input_json,
                restoration,
                preparation,
            )),
            Frame::AttachTerm { .. }
                if matches!(retirement, Retirement::Retired) && frame.stream_id == 4 =>
            {
                Some(Frame::Close {
                    code: 1,
                    reason: "fixture private session retired during attachment",
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
                exited_notice(&mut socket, 4).await;
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
            if frame.stream_id == 2 {
                exited_notice(&mut socket, 2).await;
            }
        }
        pending.advance(length);
    }
}

async fn exited_notice(socket: &mut UnixStream, stream: u32) {
    let mut reply = Vec::new();
    encode_muxed_frame_into(
        stream,
        &Frame::Event {
            sub_id: 0,
            event_json: br#"{"type":"terminal.exited","session_id":"11111111111111111111111111111111","status":0,"final_seq":16}"#,
        },
        &mut reply,
    )
    .unwrap();
    socket.write_all(&reply).await.unwrap();
}

#[tokio::test]
async fn readiness_input_preserves_the_terminal_actor_and_host_connection() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let task = tokio::spawn(terminal_peer(
        peer,
        false,
        Retirement::Available,
        false,
        None,
        None,
        None,
    ));
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
    let task = tokio::spawn(terminal_peer(
        peer,
        true,
        Retirement::Available,
        false,
        None,
        None,
        None,
    ));
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
    let task = tokio::spawn(terminal_peer(
        peer,
        false,
        Retirement::Available,
        true,
        None,
        None,
        Some(cleaned),
    ));
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
    let task = tokio::spawn(terminal_peer(
        peer,
        false,
        Retirement::Available,
        false,
        None,
        None,
        Some(cleaned),
    ));
    let actor = EmbeddedAgent::from_test_socket(socket);
    let (opened, session) = tokio::sync::oneshot::channel();
    let proof_actor = actor.clone();
    let proof = tokio::spawn(async move {
        canary_registered(&proof_actor, [2, 4], |id| {
            opened.send(id).unwrap();
            Ok(())
        })
        .await
    });
    let id = session.await.unwrap();
    proof.abort();
    let _ = proof.await;
    finish_canary(&actor, id, 4).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), done)
        .await
        .unwrap()
        .unwrap();
    task.abort();
}

#[tokio::test]
async fn reenrollment_requires_exact_restoration_acknowledgement() {
    for (json, success) in [
        (br#"{"restored":true}"#.as_slice(), true),
        (br#"{"restored":false}"#.as_slice(), false),
        (br"[true]".as_slice(), false),
        (br#"{"restored":true,"extra":1}"#.as_slice(), false),
        (br#"{"revoked":true}"#.as_slice(), false),
    ] {
        let (socket, peer) = UnixStream::pair().unwrap();
        let task = tokio::spawn(terminal_peer(
            peer,
            false,
            Retirement::Available,
            false,
            Some(json),
            None,
            None,
        ));
        let actor = EmbeddedAgent::from_test_socket(socket);
        let outcome = restore_login_access(&actor, Uuid::from_u128(0x88)).await;
        assert_eq!(outcome.is_ok(), success);
        drop(actor);
        task.abort();
        let _ = task.await;
    }
}

#[tokio::test]
async fn readiness_refuses_a_host_whose_preferred_login_path_fails() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let task = tokio::spawn(terminal_peer(
        peer,
        false,
        Retirement::Available,
        false,
        None,
        Some(false),
        None,
    ));
    let actor = EmbeddedAgent::from_test_socket(socket);
    assert!(
        confirm_preferred_login(
            &actor,
            Uuid::from_u128(0x88),
            "deploy".into(),
            crate::embedded::LoginGrant::default(),
        )
        .await
        .is_err()
    );
    drop(actor);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn readiness_prepares_the_same_person_and_preferred_account_as_terminals() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let task = tokio::spawn(terminal_peer(
        peer,
        false,
        Retirement::Available,
        false,
        None,
        Some(true),
        None,
    ));
    let actor = EmbeddedAgent::from_test_socket(socket);
    confirm_preferred_login(
        &actor,
        Uuid::from_u128(0x88),
        "deploy".into(),
        crate::embedded::LoginGrant {
            accounts: ["deploy".to_owned()].into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    drop(actor);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn readiness_accepts_primary_exit_without_reattaching_to_a_retired_session() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let task = tokio::spawn(terminal_peer(
        peer,
        false,
        Retirement::Retired,
        false,
        None,
        None,
        None,
    ));
    let actor = EmbeddedAgent::from_test_socket(socket);
    tokio::time::timeout(Duration::from_secs(5), canary(&actor))
        .await
        .unwrap()
        .unwrap();
    task.abort();
}

#[tokio::test]
async fn private_writers_reserve_the_browser_allocator_without_publishing_sessions() {
    let (_, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    assert_eq!(canary_writers(&pool).await.unwrap(), [2, 4]);
    assert_eq!(canary_writers(&pool).await.unwrap(), [6, 8]);
    let sequence: i64 =
        sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name='terminal_writers'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        sequence, 4,
        "the next browser must receive a fresh writer id"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "private readiness is never a public session");
    sqlx::query("UPDATE sqlite_sequence SET seq=2147483646 WHERE name='terminal_writers'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(canary_writers(&pool).await.is_err());
}
