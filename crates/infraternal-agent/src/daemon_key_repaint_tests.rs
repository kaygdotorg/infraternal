//! Exercises key-triggered screen repaint ordering and per-session credit isolation [D381, #477].

use super::*;
use crate::sessions::Reader;
use infraternal_shim::frame::{MULTI_WRITER, SEQUENCED_INPUT};
use std::{path::PathBuf, time::Duration};
use tokio::{io::AsyncReadExt, net::UnixStream, sync::mpsc, task::JoinHandle};

/// The ordinary raw-output allowance retained beside the repaint reserve.
const BULK_CREDIT: u32 = 1024 * 1024;
/// The initial client grant includes this extra, repaint-only amount.
const REPAINT_CREDIT: u32 = 64 * 1024;
/// The complete starting grant for a client that supports reserved repaints.
const INITIAL_CREDIT: u32 = BULK_CREDIT + REPAINT_CREDIT;
/// A forwarded frame that leaves bulk credit available but remains unreturned.
const PARTIAL_BULK_OUTPUT: usize = 64 * 1024;
/// A small quiet write does not represent a credit-blocked flood backlog.
const QUIET_OUTPUT: usize = 4 * 1024;
/// A frame larger than either credit pool makes starvation deterministic.
const STARVING_OUTPUT: usize = 128 * 1024;
/// Each spam repaint consumes one quarter of the finite reserve.
const SPAM_SNAPSHOT: usize = REPAINT_CREDIT as usize / 4;
/// A generous guard for a missing fixture event, never a performance assertion.
const EVENT_GUARD: Duration = Duration::from_secs(3);

/// One terminal relay paired with a fake shim data socket.
struct RelayFixture {
    root: PathBuf,
    id: [u8; 16],
    stream: u32,
    listener: tokio::net::UnixListener,
    peer: UnixStream,
    reader: Reader,
    commands: Option<session_commands::Sender>,
    messages: mpsc::Receiver<Message>,
    task: Option<JoinHandle<io::Result<()>>>,
}

/// Start one relay and complete the real Unix-socket shim handshake.
async fn start_relay(stream: u32) -> RelayFixture {
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = std::env::temp_dir().join(format!(
        "k{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root.clone())).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (commands, receiver) = session_commands::channel();
    let (tx, messages) = mpsc::channel(16);
    let task = tokio::spawn(terminal(path, id, stream, 0, 0, receiver, tx));
    let (mut peer, _) = tokio::time::timeout(EVENT_GUARD, listener.accept())
        .await
        .expect("terminal relay did not connect to the fake shim")
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
    assert!(matches!(
        read_shim(&mut reader, &mut peer).await,
        Shim::Attach(_)
    ));
    assert_eq!(
        read_shim(&mut reader, &mut peer).await,
        Shim::SelectWriter(stream)
    );
    assert_eq!(
        read_shim(&mut reader, &mut peer).await,
        Shim::InputStateRequest
    );
    sessions::send(&mut peer, &Shim::InputState(0, 0))
        .await
        .unwrap();
    assert_eq!(read_shim(&mut reader, &mut peer).await, Shim::ReadFrom(0));

    let mut fixture = RelayFixture {
        root,
        id,
        stream,
        listener,
        peer,
        reader,
        commands: Some(commands),
        messages,
        task: Some(task),
    };
    assert!(matches!(
        next_message(&mut fixture).await,
        Message::Shim(id, Shim::InputAck(0)) if id == stream
    ));
    assert!(matches!(
        next_message(&mut fixture).await,
        Message::Event(id, _) if id == stream
    ));
    fixture
}

/// Read the next complete shim frame under a deadlock guard.
async fn read_shim(reader: &mut Reader, peer: &mut UnixStream) -> Shim {
    tokio::time::timeout(EVENT_GUARD, reader.read(peer))
        .await
        .expect("fake shim did not receive the expected relay frame")
        .unwrap()
}

/// Read the next message emitted by the relay under a deadlock guard.
async fn next_message(fixture: &mut RelayFixture) -> Message {
    tokio::time::timeout(EVENT_GUARD, fixture.messages.recv())
        .await
        .expect("relay did not emit the expected client message")
        .expect("terminal relay closed its message channel")
}

/// Wait until the ordinary starvation timer has detached the current shim link.
async fn wait_for_link_close(fixture: &mut RelayFixture) {
    tokio::time::timeout(EVENT_GUARD, async {
        let mut bytes = [0_u8; 4096];
        loop {
            if fixture.peer.read(&mut bytes).await.unwrap() == 0 {
                break;
            }
        }
    })
    .await
    .expect("the 250 ms starvation recovery did not detach its shim link");
}

/// Accept a replacement shim link and complete its ordered input-state fence.
async fn accept_relinked_peer(fixture: &mut RelayFixture) {
    let (mut peer, _) = tokio::time::timeout(EVENT_GUARD, fixture.listener.accept())
        .await
        .expect("input did not reconnect the detached shim link")
        .unwrap();
    let mut reader = Reader::default();
    sessions::send(
        &mut peer,
        &Shim::Hello {
            version: 1,
            caps: SEQUENCED_INPUT | MULTI_WRITER,
            session: fixture.id,
            pid: std::process::id(),
            cols: 80,
            rows: 24,
            created: 0,
            head: u64::from(BULK_CREDIT) + u64::try_from(STARVING_OUTPUT).unwrap(),
            start: 0,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_shim(&mut reader, &mut peer).await,
        Shim::Attach(_)
    ));
    assert_eq!(
        read_shim(&mut reader, &mut peer).await,
        Shim::SelectWriter(fixture.stream)
    );
    assert_eq!(
        read_shim(&mut reader, &mut peer).await,
        Shim::InputStateRequest
    );
    sessions::send(&mut peer, &Shim::InputState(0, 0))
        .await
        .unwrap();
    fixture.peer = peer;
    fixture.reader = reader;
}

/// Forward a message read until the requested `InputAck`, skipping already-sent flood bytes.
async fn wait_for_input_ack(fixture: &mut RelayFixture, written: u64) -> bool {
    loop {
        match tokio::time::timeout(EVENT_GUARD, fixture.messages.recv()).await {
            Ok(Some(Message::Shim(stream, Shim::InputAck(acked))))
                if stream == fixture.stream && acked >= written =>
            {
                return true;
            }
            Ok(Some(Message::Shim(stream, Shim::InputAck(_)))) if stream == fixture.stream => {}
            Ok(Some(Message::Shim(stream, Shim::Output(..)))) if stream == fixture.stream => {}
            Ok(Some(Message::Event(stream, _))) if stream == fixture.stream => {}
            Ok(Some(_) | None) | Err(_) => return false,
        }
    }
}

/// Fund one stream, send a full bulk window, then leave a later raw frame parked.
async fn fill_bulk_window(fixture: &mut RelayFixture) {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(INITIAL_CREDIT))
        .unwrap();
    for (seq, length) in [
        (0, 900_000_usize),
        (900_000, BULK_CREDIT as usize - 900_000),
    ] {
        sessions::send(&mut fixture.peer, &Shim::Output(seq, vec![b'f'; length]))
            .await
            .unwrap();
        let Some(Message::Shim(stream, Shim::Output(received_seq, bytes))) =
            tokio::time::timeout(EVENT_GUARD, fixture.messages.recv())
                .await
                .expect("bulk output was not forwarded")
        else {
            panic!("relay did not forward raw flood bytes");
        };
        assert_eq!(stream, fixture.stream);
        assert_eq!(received_seq, seq);
        assert_eq!(bytes.len(), length);
    }
    sessions::send(
        &mut fixture.peer,
        &Shim::Output(u64::from(BULK_CREDIT), vec![b'f'; STARVING_OUTPUT]),
    )
    .await
    .unwrap();
}

/// Spend the legacy 1 MiB raw window while keeping its opening reserve unconfirmed.
async fn fill_bulk_window_without_repaint_reserve(fixture: &mut RelayFixture) {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(BULK_CREDIT))
        .unwrap();
    for (seq, length) in [
        (0, 900_000_usize),
        (900_000, BULK_CREDIT as usize - 900_000),
    ] {
        sessions::send(&mut fixture.peer, &Shim::Output(seq, vec![b'f'; length]))
            .await
            .unwrap();
        let Some(Message::Shim(stream, Shim::Output(received_seq, bytes))) =
            tokio::time::timeout(EVENT_GUARD, fixture.messages.recv())
                .await
                .expect("legacy bulk output was not forwarded")
        else {
            panic!("relay did not forward legacy raw output");
        };
        assert_eq!(stream, fixture.stream);
        assert_eq!(received_seq, seq);
        assert_eq!(bytes.len(), length);
    }

    sessions::send(
        &mut fixture.peer,
        &Shim::Output(u64::from(BULK_CREDIT), vec![b'f'; STARVING_OUTPUT]),
    )
    .await
    .unwrap();
}

/// Leave only a small raw backlog in flight while retaining the rest of the granted bulk window.
async fn fill_partial_bulk_backlog(fixture: &mut RelayFixture, length: usize) {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(INITIAL_CREDIT))
        .unwrap();
    sessions::send(&mut fixture.peer, &Shim::Output(0, vec![b'f'; length]))
        .await
        .unwrap();
    let Some(Message::Shim(stream, Shim::Output(0, bytes))) =
        tokio::time::timeout(EVENT_GUARD, fixture.messages.recv())
            .await
            .expect("partial bulk output was not forwarded")
    else {
        panic!("relay did not forward the partial backlog");
    };
    assert_eq!(stream, fixture.stream);
    assert_eq!(bytes.len(), length);
}

/// Make a valid, highly styled Snapshot whose payload is at least `length` bytes.
fn styled_snapshot_at_least(length: usize) -> Vec<u8> {
    let mut styled = Vec::with_capacity(length);
    while styled.len() < length {
        styled.extend_from_slice(b"\x1b[38;2;255;0;0mX\x1b[38;2;0;0;255mY");
    }
    styled
}

/// Submit a key and wait until the shim confirms its PTY write.
async fn type_key_and_wait_for_ack(fixture: &mut RelayFixture, seq: u64) -> bool {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Input(seq, vec![b'k']))
        .unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SequencedInput(seq, vec![b'k'])
    );
    sessions::send(&mut fixture.peer, &Shim::InputAck(seq + 1))
        .await
        .unwrap();
    wait_for_input_ack(fixture, seq + 1).await
}

/// Submit a key, confirm its PTY write, and report whether the relay requested a repaint.
async fn type_key_and_wait_for_repaint_request(fixture: &mut RelayFixture, seq: u64) -> bool {
    if !type_key_and_wait_for_ack(fixture, seq).await {
        return false;
    }
    matches!(
        tokio::time::timeout(EVENT_GUARD, fixture.reader.read(&mut fixture.peer)).await,
        Ok(Ok(Shim::SnapshotRequest))
    )
}

/// Read the repaint frame after the shim handles a requested screen capture.
async fn wait_for_repaint(fixture: &mut RelayFixture) -> Option<(u64, Vec<u8>)> {
    loop {
        match tokio::time::timeout(EVENT_GUARD, fixture.messages.recv()).await {
            Ok(Some(Message::Shim(stream, Shim::Snapshot(seq, bytes))))
                if stream == fixture.stream =>
            {
                return Some((seq, bytes));
            }
            Ok(Some(Message::Shim(stream, Shim::Output(..)))) if stream == fixture.stream => {}
            Ok(Some(Message::Event(stream, _))) if stream == fixture.stream => {}
            Ok(Some(_) | None) | Err(_) => return None,
        }
    }
}

/// Let a relay observe closed client commands and remove this test's short socket directory.
async fn stop_relay(fixture: &mut RelayFixture) {
    fixture.commands.take();
    if let Some(task) = fixture.task.take() {
        let _ = task.await;
    }
    drop(fixture.peer.shutdown().await);
    let _ = std::fs::remove_dir_all(&fixture.root);
}

/// A key must be written and acknowledged before the shim captures its echo.
#[tokio::test]
async fn key_repaint_waits_for_its_input_ack_and_contains_the_echo() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window(&mut fixture).await;
    let requested = type_key_and_wait_for_repaint_request(&mut fixture, 0).await;
    let repaint = if requested {
        sessions::send(
            &mut fixture.peer,
            &Shim::Snapshot(u64::from(BULK_CREDIT) + 1, b"echo:k".to_vec()),
        )
        .await
        .unwrap();
        wait_for_repaint(&mut fixture).await
    } else {
        None
    };
    stop_relay(&mut fixture).await;
    assert!(
        requested,
        "the key's InputAck must release a repaint request"
    );
    assert_eq!(
        repaint,
        Some((u64::from(BULK_CREDIT) + 1, b"echo:k".to_vec()))
    );
}

/// Send a highly styled repaint larger than 64 KiB through credit reclaimed by dropping the flood queue.
#[tokio::test]
async fn key_repaint_funds_a_large_styled_snapshot_from_dropped_bulk_credit() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window_without_repaint_reserve(&mut fixture).await;
    let requested = type_key_and_wait_for_repaint_request(&mut fixture, 0).await;
    let styled = styled_snapshot_at_least(128 * 1024);
    assert!(styled.len() > REPAINT_CREDIT as usize);
    assert!(styled.len() < infraternal_shim::frame::MAX_FRAME - 9);
    if requested {
        sessions::send(
            &mut fixture.peer,
            &Shim::Snapshot(u64::from(BULK_CREDIT) + 1, styled.clone()),
        )
        .await
        .unwrap();
    }
    let repaint = if requested {
        wait_for_repaint(&mut fixture).await
    } else {
        None
    };
    stop_relay(&mut fixture).await;

    assert!(requested, "the flooded stream must request its key repaint");
    assert_eq!(
        repaint.map(|(seq, bytes)| (seq, bytes.len())),
        Some((u64::from(BULK_CREDIT) + 1, styled.len())),
        "a faithful styled Snapshot above the small reserve must use only reclaimed or reserved credit"
    );
}

/// Use the unused granted bulk window when a valid large Snapshot replaces a small raw backlog.
#[tokio::test]
async fn key_repaint_funds_a_large_snapshot_from_unused_bulk_credit() {
    let mut fixture = start_relay(2).await;
    let backlog = usize::try_from(relay::KEY_REPAINT_BACKLOG).unwrap();
    fill_partial_bulk_backlog(&mut fixture, backlog).await;
    let requested = type_key_and_wait_for_repaint_request(&mut fixture, backlog as u64).await;
    let styled = styled_snapshot_at_least(128 * 1024);
    let seq = u64::try_from(backlog + 1).unwrap();
    if requested {
        sessions::send(&mut fixture.peer, &Shim::Snapshot(seq, styled.clone()))
            .await
            .unwrap();
    }
    let repaint = if requested {
        wait_for_repaint(&mut fixture).await
    } else {
        None
    };
    stop_relay(&mut fixture).await;

    assert!(requested, "the raw backlog must request its key repaint");
    assert_eq!(
        repaint.map(|(seq, bytes)| (seq, bytes.len())),
        Some((seq, styled.len())),
        "a valid large Snapshot may use the unused client grant after dropping queued bulk"
    );
}

/// Give the PTY program one frame to render its response before the repaint captures the screen.
#[tokio::test(start_paused = true)]
async fn key_repaint_waits_a_frame_for_pty_echo_after_input_ack() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window(&mut fixture).await;
    assert!(type_key_and_wait_for_ack(&mut fixture, 0).await);
    tokio::task::yield_now().await;

    let early = tokio::time::timeout(
        KEY_REPAINT_GRACE.saturating_sub(Duration::from_millis(1)),
        fixture.reader.read(&mut fixture.peer),
    )
    .await;
    let requested_early = matches!(early, Ok(Ok(Shim::SnapshotRequest)));
    let repaint = if requested_early {
        None
    } else {
        sessions::send(
            &mut fixture.peer,
            &Shim::Output(u64::from(BULK_CREDIT), b"echo:k".to_vec()),
        )
        .await
        .unwrap();
        tokio::task::yield_now().await;
        // sleep: advance through the final millisecond of the PTY screen-update grace.
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        let requested = matches!(
            tokio::time::timeout(EVENT_GUARD, fixture.reader.read(&mut fixture.peer)).await,
            Ok(Ok(Shim::SnapshotRequest))
        );
        if requested {
            sessions::send(
                &mut fixture.peer,
                &Shim::Snapshot(u64::from(BULK_CREDIT) + 6, b"echo:k".to_vec()),
            )
            .await
            .unwrap();
            wait_for_repaint(&mut fixture).await
        } else {
            None
        }
    };
    stop_relay(&mut fixture).await;

    assert!(
        !requested_early,
        "a key repaint must leave one PTY frame for the application's echo before capture"
    );
    assert_eq!(
        repaint,
        Some((u64::from(BULK_CREDIT) + 6, b"echo:k".to_vec()))
    );
}

/// A key still preempts raw bytes that are in flight before the bulk window empties.
#[tokio::test]
async fn key_repaint_preempts_unreturned_bulk_before_window_is_empty() {
    let mut fixture = start_relay(2).await;
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(INITIAL_CREDIT))
        .unwrap();
    sessions::send(
        &mut fixture.peer,
        &Shim::Output(0, vec![b'f'; PARTIAL_BULK_OUTPUT]),
    )
    .await
    .unwrap();
    let Some(Message::Shim(stream, Shim::Output(0, bytes))) =
        tokio::time::timeout(EVENT_GUARD, fixture.messages.recv())
            .await
            .expect("partially funded bulk output was not forwarded")
    else {
        panic!("relay did not forward the partial bulk frame");
    };
    assert_eq!(stream, fixture.stream);
    assert_eq!(bytes.len(), PARTIAL_BULK_OUTPUT);

    let requested = type_key_and_wait_for_repaint_request(&mut fixture, 0).await;
    let repaint = if requested {
        sessions::send(
            &mut fixture.peer,
            &Shim::Snapshot(
                u64::try_from(PARTIAL_BULK_OUTPUT).unwrap() + 1,
                b"echo:k".to_vec(),
            ),
        )
        .await
        .unwrap();
        wait_for_repaint(&mut fixture).await
    } else {
        None
    };
    stop_relay(&mut fixture).await;

    assert!(
        requested,
        "unreturned raw output must not let the key spend the whole bulk window"
    );
    assert_eq!(
        repaint,
        Some((
            u64::try_from(PARTIAL_BULK_OUTPUT).unwrap() + 1,
            b"echo:k".to_vec()
        ))
    );
}

/// Keep a small fully forwarded quiet write from turning the next key into a repaint.
#[tokio::test]
async fn fully_forwarded_quiet_output_does_not_trigger_a_key_repaint() {
    let mut fixture = start_relay(2).await;
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(INITIAL_CREDIT))
        .unwrap();
    sessions::send(
        &mut fixture.peer,
        &Shim::Output(0, vec![b'q'; QUIET_OUTPUT]),
    )
    .await
    .unwrap();
    let Some(Message::Shim(stream, Shim::Output(0, bytes))) =
        tokio::time::timeout(EVENT_GUARD, fixture.messages.recv())
            .await
            .expect("quiet output was not forwarded")
    else {
        panic!("relay did not forward the quiet output");
    };
    assert_eq!(stream, fixture.stream);
    assert_eq!(bytes.len(), QUIET_OUTPUT);
    assert!(type_key_and_wait_for_ack(&mut fixture, 0).await);

    let early_request = tokio::time::timeout(
        Duration::from_millis(25),
        fixture.reader.read(&mut fixture.peer),
    )
    .await;
    stop_relay(&mut fixture).await;

    assert!(
        early_request.is_err(),
        "a repaint is only needed when output is waiting for credit"
    );
}

/// Keep a key-triggered repaint alive when the ordinary starvation path detached first.
#[tokio::test]
async fn key_after_starvation_detach_still_requests_its_repaint() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window(&mut fixture).await;
    wait_for_link_close(&mut fixture).await;

    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Input(0, vec![b'k']))
        .unwrap();
    accept_relinked_peer(&mut fixture).await;
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SequencedInput(0, vec![b'k'])
    );
    sessions::send(&mut fixture.peer, &Shim::InputAck(1))
        .await
        .unwrap();
    assert!(wait_for_input_ack(&mut fixture, 1).await);
    let request = tokio::time::timeout(EVENT_GUARD, fixture.reader.read(&mut fixture.peer))
        .await
        .expect("the acknowledged key should request a repaint")
        .unwrap();
    let requested = request == Shim::SnapshotRequest;
    if !requested && request == Shim::InputStateRequest {
        sessions::send(&mut fixture.peer, &Shim::InputState(1, 1))
            .await
            .unwrap();
        let _ = wait_for_input_ack(&mut fixture, 1).await;
    }
    if requested {
        sessions::send(
            &mut fixture.peer,
            &Shim::Snapshot(
                u64::from(BULK_CREDIT) + u64::try_from(STARVING_OUTPUT).unwrap(),
                b"echo:k".to_vec(),
            ),
        )
        .await
        .unwrap();
    }
    let repaint = if requested {
        wait_for_repaint(&mut fixture).await
    } else {
        None
    };
    stop_relay(&mut fixture).await;

    assert!(
        requested,
        "a detached relay must keep the replacement link through the key repaint"
    );
    assert_eq!(
        repaint,
        Some((
            u64::from(BULK_CREDIT) + u64::try_from(STARVING_OUTPUT).unwrap(),
            b"echo:k".to_vec()
        ))
    );
}

/// Keep a coalesced key pending until client credit funds its follow-up repaint.
#[tokio::test]
async fn coalesced_keys_wait_for_returned_reserve_before_follow_up_repaint() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window(&mut fixture).await;
    let first_requested = type_key_and_wait_for_repaint_request(&mut fixture, 0).await;
    let second_acked = type_key_and_wait_for_ack(&mut fixture, 1).await;
    sessions::send(
        &mut fixture.peer,
        &Shim::Snapshot(
            u64::from(BULK_CREDIT) + 1,
            vec![b's'; REPAINT_CREDIT as usize],
        ),
    )
    .await
    .unwrap();
    let first_repaint = wait_for_repaint(&mut fixture).await;
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(REPAINT_CREDIT))
        .unwrap();
    let follow_up_requested = matches!(
        tokio::time::timeout(EVENT_GUARD, fixture.reader.read(&mut fixture.peer)).await,
        Ok(Ok(Shim::SnapshotRequest))
    );
    let follow_up_repaint = if follow_up_requested {
        sessions::send(
            &mut fixture.peer,
            &Shim::Snapshot(u64::from(BULK_CREDIT) + 2, b"echo:kk".to_vec()),
        )
        .await
        .unwrap();
        wait_for_repaint(&mut fixture).await
    } else {
        None
    };
    stop_relay(&mut fixture).await;

    assert!(first_requested, "the first key must request a repaint");
    assert!(
        second_acked,
        "the second key must be acknowledged while capture is in flight"
    );
    assert_eq!(
        first_repaint.map(|(seq, bytes)| (seq, bytes.len())),
        Some((u64::from(BULK_CREDIT) + 1, REPAINT_CREDIT as usize))
    );
    assert!(
        follow_up_requested,
        "a coalesced key must remain pending until returned credit funds its repaint"
    );
    assert_eq!(
        follow_up_repaint,
        Some((u64::from(BULK_CREDIT) + 2, b"echo:kk".to_vec()))
    );
}

/// A key-triggered repaint on one stream must leave a sibling stream's credit and output alone.
#[tokio::test]
async fn key_repaint_does_not_interrupt_sibling_session_output() {
    let mut flood = start_relay(2).await;
    let mut sibling = start_relay(4).await;
    fill_bulk_window(&mut flood).await;
    let requested = type_key_and_wait_for_repaint_request(&mut flood, 0).await;

    sibling
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(4096))
        .unwrap();
    sessions::send(
        &mut sibling.peer,
        &Shim::Output(0, b"other session".to_vec()),
    )
    .await
    .unwrap();
    let sibling_output = next_message(&mut sibling).await;
    stop_relay(&mut flood).await;
    stop_relay(&mut sibling).await;

    assert!(
        requested,
        "the flooded session must request its own repaint"
    );
    assert!(matches!(
        sibling_output,
        Message::Shim(4, Shim::Output(0, bytes)) if bytes == b"other session"
    ));
}

/// Input spam cannot replenish the repaint reserve without returned client credit.
#[tokio::test]
async fn key_spam_cannot_mint_repaint_credit() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window(&mut fixture).await;
    let mut repaints = 0;
    let mut request_seen = true;
    for index in 0..4_u64 {
        request_seen = type_key_and_wait_for_repaint_request(&mut fixture, index).await;
        if !request_seen {
            break;
        }
        let sequence = u64::from(BULK_CREDIT) + index + 1;
        sessions::send(
            &mut fixture.peer,
            &Shim::Snapshot(sequence, vec![b's'; SPAM_SNAPSHOT]),
        )
        .await
        .unwrap();
        if wait_for_repaint(&mut fixture).await.is_some() {
            repaints += 1;
        } else {
            break;
        }
    }
    let fifth_request = if repaints == 4 {
        type_key_and_wait_for_repaint_request(&mut fixture, 4).await
    } else {
        false
    };
    stop_relay(&mut fixture).await;

    assert!(request_seen, "the initial key must use the reserved credit");
    assert_eq!(repaints, 4, "64 KiB pays for exactly four 16 KiB repaints");
    assert!(
        !fifth_request,
        "keys alone must not mint a fifth repaint's credit"
    );
}
