//! A session whose shim is gone gets one final stream Close, and the channel lives on (#158).
//!
//! Before this, an `AttachTerm` for an id the registry did not hold failed the whole
//! embedded channel. The server reconnected by spawning a new infraternal agent and
//! re-sent the same attachment, so one dead session restarted the process about twice
//! a second and cut every sibling stream each time.

use super::*;
use infraternal_protocol::{CLOSE_SESSION_GONE, decode_muxed_frame, encode_muxed_frame_into};
use std::os::fd::IntoRawFd;
use tokio::io::AsyncReadExt;

/// What the server side of the channel saw, owned so the read buffer can move on.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Pong(u64),
    Close(u32, u16, String),
    Other,
}

async fn next(peer: &mut tokio::net::UnixStream, buffer: &mut Vec<u8>) -> Seen {
    loop {
        if let Ok(decoded) = decode_muxed_frame(buffer) {
            let seen = match decoded.frame {
                Frame::Pong { nonce, .. } => Seen::Pong(nonce),
                Frame::Close { code, reason } => {
                    Seen::Close(decoded.stream_id, code, reason.to_owned())
                }
                _ => Seen::Other,
            };
            buffer.drain(..decoded.wire_len);
            return seen;
        }
        let mut chunk = [0_u8; 4096];
        let read = peer.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "the infraternal agent closed its channel");
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn send(wire: &mut Vec<u8>, stream: u32, frame: &Frame<'_>) {
    let mut encoded = Vec::new();
    encode_muxed_frame_into(stream, frame, &mut encoded).unwrap();
    wire.extend_from_slice(&encoded);
}

#[tokio::test]
async fn a_vanished_session_gets_a_final_close_and_the_channel_stays_up() {
    // Leave room for sessions/<32 hex digits>.sock under a HOME-cache TMPDIR.
    // A 96-bit random fixture name preserves isolation without spending the
    // Unix socket path budget on a descriptive directory prefix.
    let state = std::env::temp_dir().join(format!(
        "g{}",
        &uuid::Uuid::new_v4().simple().to_string()[..24]
    ));
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let state = sessions::state(Some(state)).unwrap();
    // Two ways a session is gone: no rendezvous at all, and a stale socket file
    // whose shim died without removing it (connect is refused).
    let missing = *uuid::Uuid::new_v4().as_bytes();
    let refused = *uuid::Uuid::new_v4().as_bytes();

    let (agent, server) = std::os::unix::net::UnixStream::pair().unwrap();
    agent.set_nonblocking(true).unwrap();
    server.set_nonblocking(true).unwrap();
    let socket = Socket::inherited(agent.into_raw_fd()).unwrap();
    let task_state = state.clone();
    let task = tokio::spawn(async move {
        let service = crate::plugin_control::Service::start(
            &task_state,
            crate::plugins::ExecutionMode::Embedded,
            None,
        )
        .await?;
        run_channel::<false>(
            &socket,
            task_state,
            None,
            None,
            Some(service.registry.clone()),
            None,
        )
        .await
    });
    let mut peer = tokio::net::UnixStream::from_std(server).unwrap();

    // Startup discovery would clean a stale file up; the shim must die while the
    // channel runs, so the file appears only once a Pong proves startup is done.
    let mut buffer = Vec::new();
    let mut wire = Vec::new();
    send(
        &mut wire,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "test",
        },
    );
    send(
        &mut wire,
        0,
        &Frame::Ping {
            nonce: 1,
            sent_us: 0,
        },
    );
    tokio::io::AsyncWriteExt::write_all(&mut peer, &wire)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while next(&mut peer, &mut buffer).await != Seen::Pong(1) {}
    })
    .await
    .expect("the infraternal agent did not start");
    let path = sessions::rendezvous(&state, refused);
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();

    let mut wire = Vec::new();
    for (stream, id) in [(2, &missing), (4, &refused)] {
        send(
            &mut wire,
            stream,
            &Frame::AttachTerm {
                session_id: id,
                last_out_seq: 0,
                last_in_seq: 0,
            },
        );
    }
    // A late Credit on an ended stream is ignored, never a channel failure.
    send(&mut wire, 2, &Frame::Credit { bytes: 4096 });
    tokio::io::AsyncWriteExt::write_all(&mut peer, &wire)
        .await
        .unwrap();

    let mut closes = Vec::new();
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while closes.len() < 2 {
            if let Seen::Close(stream, code, reason) = next(&mut peer, &mut buffer).await {
                closes.push((stream, code, reason));
            }
        }
        // The same channel still answers: nothing was restarted.
        let mut ping = Vec::new();
        send(
            &mut ping,
            0,
            &Frame::Ping {
                nonce: 7,
                sent_us: 0,
            },
        );
        tokio::io::AsyncWriteExt::write_all(&mut peer, &ping)
            .await
            .unwrap();
        loop {
            if next(&mut peer, &mut buffer).await == Seen::Pong(7) {
                break;
            }
        }
    })
    .await;
    let finished = task.is_finished();
    task.abort();
    let _ = std::fs::remove_dir_all(&state);
    assert!(result.is_ok(), "no final close or no pong: {closes:?}");
    assert!(!finished, "the channel ended instead of closing one stream");
    closes.sort();
    assert_eq!(
        closes,
        vec![
            (2, CLOSE_SESSION_GONE, "session ended".to_owned()),
            (4, CLOSE_SESSION_GONE, "session ended".to_owned()),
        ]
    );
}

#[path = "gone_scale_review_tests.rs"]
mod scale_review;
