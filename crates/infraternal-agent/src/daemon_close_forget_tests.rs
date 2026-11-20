//! A stream the server closes leaves no per-stream state in the shared writer (#477, J730 P3).
//!
//! The writer keeps a small "covered by a key repaint" cursor per stream id
//! (`ReplaceCursors`). Before this, only the agent's own Close and Ended
//! messages removed it; a Close sent by the server cancelled the relay task
//! and left the entry behind, so a long-lived link grew one entry per stream
//! id it ever used. These tests drive the real shared dispatcher over a socket
//! pair with a fake shim, and read the writer's entry count through the
//! test-only `TRACKED_STREAMS` task-local.

use super::*;
use crate::daemon_writer::TRACKED_STREAMS;
use crate::sessions::Reader;
use infraternal_protocol::encode_muxed_frame_into;
use infraternal_shim::frame::{MULTI_WRITER, SEQUENCED_INPUT};
use std::{
    os::fd::IntoRawFd,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::UnixStream};

/// A generous guard for a missing fixture event, never a performance assertion.
const EVENT_GUARD: Duration = Duration::from_secs(20);

/// Append one muxed frame for `stream` to `wire`.
fn send(wire: &mut Vec<u8>, stream: u32, frame: &Frame<'_>) {
    let mut encoded = Vec::new();
    encode_muxed_frame_into(stream, frame, &mut encoded).unwrap();
    wire.extend_from_slice(&encoded);
}

/// Wait until the writer reports exactly `want` tracked streams.
async fn wait_for_tracked(count: &AtomicUsize, want: usize) -> bool {
    tokio::time::timeout(EVENT_GUARD, async {
        while count.load(Ordering::Relaxed) != want {
            // sleep: polls a counter the writer updates after each item; no event to await.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// Accept the relay on the fake shim socket and complete its attach handshake.
async fn accept_shim(listener: &tokio::net::UnixListener, id: [u8; 16], stream: u32) -> UnixStream {
    let (mut peer, _) = tokio::time::timeout(EVENT_GUARD, listener.accept())
        .await
        .expect("relay did not connect to the fake shim")
        .unwrap();
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
            head: 0,
            start: 0,
        },
    )
    .await
    .unwrap();
    let mut reader = Reader::default();
    let mut expected = vec![];
    for _ in 0..3 {
        expected.push(
            tokio::time::timeout(EVENT_GUARD, reader.read(&mut peer))
                .await
                .expect("fake shim did not receive the expected relay frame")
                .unwrap(),
        );
    }
    assert!(matches!(expected[0], Shim::Attach(_)));
    assert_eq!(expected[1], Shim::SelectWriter(stream));
    assert_eq!(expected[2], Shim::InputStateRequest);
    sessions::send(&mut peer, &Shim::InputState(0, 0))
        .await
        .unwrap();
    peer
}

/// The server's Close for a live stream removes that stream's writer state, and a
/// reattach of the same id afterwards gets its own entry, which its Close removes too.
#[tokio::test]
async fn a_server_close_removes_the_streams_writer_state() {
    // Short random state dir: sessions/<32 hex>.sock must fit SUN_LEN under TMPDIR.
    let state = std::env::temp_dir().join(format!(
        "f{}",
        &uuid::Uuid::new_v4().simple().to_string()[..24]
    ));
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let state = sessions::state(Some(state)).unwrap();
    let id = *uuid::Uuid::new_v4().as_bytes();

    let (agent, server) = std::os::unix::net::UnixStream::pair().unwrap();
    agent.set_nonblocking(true).unwrap();
    server.set_nonblocking(true).unwrap();
    let socket = Socket::inherited(agent.into_raw_fd()).unwrap();
    let tracked = Arc::new(AtomicUsize::new(0));
    let task_state = state.clone();
    let task = tokio::spawn(TRACKED_STREAMS.scope(tracked.clone(), async move {
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
    }));
    let peer = tokio::net::UnixStream::from_std(server).unwrap();
    let (mut from_agent, mut to_agent) = peer.into_split();

    // Startup discovery probes every socket in the sessions directory, so the fake
    // shim may only listen once a Pong proves startup is done.
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
    tokio::io::AsyncWriteExt::write_all(&mut to_agent, &wire)
        .await
        .unwrap();
    let mut seen = Vec::new();
    let started = tokio::time::timeout(EVENT_GUARD, async {
        loop {
            if let Ok(decoded) = infraternal_protocol::decode_muxed_frame(&seen) {
                let pong = matches!(decoded.frame, Frame::Pong { nonce: 1, .. });
                seen.drain(..decoded.wire_len);
                if pong {
                    break;
                }
                continue;
            }
            let mut chunk = [0_u8; 4096];
            let read = from_agent.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "the infraternal agent closed its channel");
            seen.extend_from_slice(&chunk[..read]);
        }
    })
    .await;
    assert!(started.is_ok(), "the infraternal agent did not start");
    let listener = tokio::net::UnixListener::bind(sessions::rendezvous(&state, id)).unwrap();
    // From here on, drain everything the agent writes so its writer never blocks on the socket.
    let drain = tokio::spawn(async move {
        let mut chunk = [0_u8; 4096];
        while from_agent.read(&mut chunk).await.is_ok_and(|read| read > 0) {}
    });

    let mut wire = Vec::new();
    let attach = Frame::AttachTerm {
        session_id: &id,
        last_out_seq: 0,
        last_in_seq: 0,
    };
    send(&mut wire, 2, &attach);
    tokio::io::AsyncWriteExt::write_all(&mut to_agent, &wire)
        .await
        .unwrap();
    let first = accept_shim(&listener, id, 2).await;
    let attached = wait_for_tracked(&tracked, 1).await;

    let close = Frame::Close {
        code: 1,
        reason: "browser left",
    };
    let mut wire = Vec::new();
    send(&mut wire, 2, &close);
    tokio::io::AsyncWriteExt::write_all(&mut to_agent, &wire)
        .await
        .unwrap();
    let forgotten = wait_for_tracked(&tracked, 0).await;

    // The same stream id again: a new relay, a new entry, and its Close clears it too.
    let mut wire = Vec::new();
    send(&mut wire, 2, &attach);
    tokio::io::AsyncWriteExt::write_all(&mut to_agent, &wire)
        .await
        .unwrap();
    let second = accept_shim(&listener, id, 2).await;
    let reattached = wait_for_tracked(&tracked, 1).await;
    let mut wire = Vec::new();
    send(&mut wire, 2, &close);
    tokio::io::AsyncWriteExt::write_all(&mut to_agent, &wire)
        .await
        .unwrap();
    let forgotten_again = wait_for_tracked(&tracked, 0).await;

    let finished = task.is_finished();
    task.abort();
    drain.abort();
    drop((first, second));
    let _ = std::fs::remove_dir_all(&state);
    assert!(attached, "the relay's attachment never reached the writer");
    assert!(forgotten, "the closed stream's writer state stayed behind");
    assert!(reattached, "the reattached stream got no writer state");
    assert!(forgotten_again, "the second close left writer state behind");
    assert!(!finished, "the channel ended instead of closing one stream");
}
