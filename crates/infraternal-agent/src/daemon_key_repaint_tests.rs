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
pub(super) const EVENT_GUARD: Duration = Duration::from_secs(3);
/// Allow the paused timer and shim socket to report expiry and EOF.
const CAPTURE_EXPIRY_OBSERVATION_SLACK: Duration = Duration::from_millis(8);

/// Include a credit-starved shim frame even when returned output left no bytes in flight.
#[test]
fn a_pending_output_frame_triggers_repaint_from_reserved_credit() {
    let mut output = relay::Output::attach_with_repaint_reserve(0);
    output.grant(INITIAL_CREDIT).unwrap();
    output.reset_cursor(0);
    output.grant(REPAINT_CREDIT).unwrap();

    assert_eq!(output.unreturned_output_credit(), 0);
    assert_eq!(output.reserved_credit(), u64::from(REPAINT_CREDIT));
    assert!(output.bulk_starved());
    let pending = Shim::Output(0, vec![b'f'; STARVING_OUTPUT]);

    assert!(
        super::output_waiting_for_key_repaint(Some(&pending), None, &output),
        "a raw shim frame parked for bulk credit is flood output even with no older bytes in flight"
    );
}

/// Keep the next key's echo visible when only its protected repaint budget remains.
#[test]
fn a_repaint_budget_triggers_when_bulk_credit_is_empty_without_a_queued_frame() {
    let mut output = relay::Output::attach_with_repaint_reserve(0);
    output.grant(INITIAL_CREDIT).unwrap();
    output.reset_cursor(0);
    output.grant(REPAINT_CREDIT).unwrap();

    assert_eq!(output.unreturned_output_credit(), 0);
    assert!(output.bulk_starved());
    assert!(output.repaint_budget() >= u64::from(REPAINT_CREDIT));
    assert!(
        super::output_waiting_for_key_repaint(None, None, &output),
        "the key itself will produce output, so a funded repaint must start before its echo waits for bulk credit"
    );
}

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

/// A fresh short state root and the rendezvous path a fake shim for `id` listens on.
///
/// The root is short because Unix socket paths are capped at 108 bytes.
pub(super) fn shim_rendezvous(id: [u8; 16]) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "k{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root.clone())).unwrap();
    let path = sessions::rendezvous(&state, id);
    (root, path)
}

/// Accept a relay's shim link on `listener` and answer its handshake up to `ReadFrom(0)`,
/// as a fresh shim with no output and no input yet. Returns the fake shim's side of the link.
pub(super) async fn greet_relay(
    listener: &tokio::net::UnixListener,
    id: [u8; 16],
    stream: u32,
) -> (UnixStream, Reader) {
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
    (peer, reader)
}

/// Start one relay and complete the real Unix-socket shim handshake.
async fn start_relay(stream: u32) -> RelayFixture {
    start_relay_with_priority(stream, None).await
}

/// Start a relay with an optional test-controlled priority lane to exercise writer backpressure.
async fn start_relay_with_priority(
    stream: u32,
    priority: Option<mpsc::Sender<PriorityMessage>>,
) -> RelayFixture {
    let id = *uuid::Uuid::new_v4().as_bytes();
    let (root, path) = shim_rendezvous(id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (commands, receiver) = session_commands::channel();
    let (tx, messages) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        if let Some(priority) = priority {
            terminal_with_priority(path, id, stream, 0, 0, receiver, tx, priority).await
        } else {
            terminal(path, id, stream, 0, 0, receiver, tx).await
        }
    });
    let (peer, reader) = greet_relay(&listener, id, stream).await;

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
    // A relay first announces its attachment to the writer (#477).
    assert!(matches!(
        next_message(&mut fixture).await,
        Message::Attached(id, ..) if id == stream
    ));
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
pub(super) async fn read_shim(reader: &mut Reader, peer: &mut UnixStream) -> Shim {
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

/// A route proof arriving while raw output waits for the client's credit must be answered at once.
///
/// The relay stops reading the shim while it holds that frame, so the shim's state reply cannot be
/// read. Waiting for the 250 ms starvation recovery let a flooded terminal outlast the server's
/// liveness budget and be closed as unresponsive (#477). The wait here is far below the 250 ms
/// recovery, a causality bound rather than a speed measurement.
#[tokio::test]
async fn route_proof_is_answered_while_output_waits_for_client_credit() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window_without_repaint_reserve(&mut fixture).await;
    // The relay holds the starving frame only after it has read it from the shim socket, and
    // nothing observable marks that moment; the 250 ms recovery timer is the bound this stays under.
    // sleep: let the relay read and park the starving frame before the route proof arrives.
    tokio::time::sleep(Duration::from_millis(60)).await;
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Ping(7, 9))
        .unwrap();
    let pong = loop {
        match tokio::time::timeout(Duration::from_millis(100), fixture.messages.recv()).await {
            Ok(Some(Message::Pong(2, nonce, sent_us))) => break Some((nonce, sent_us)),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break None,
        }
    };
    stop_relay(&mut fixture).await;
    assert_eq!(
        pong,
        Some((7, 9)),
        "the starved relay must still prove its route"
    );
}

/// A key whose PTY write is confirmed by a route proof's state reply still gets its repaint (#477).
///
/// The shim keeps one reply slot per peer. When a route proof's `InputStateRequest` is outstanding
/// as a key is written, the shim confirms the key with `InputState` instead of `InputAck`. The relay
/// discards raw output while a key repaint is pending, so a confirmation that did not start the
/// repaint's frame grace left the screen frozen under a flood with the client's credit unused
/// (traced on the production build: Ack in 1.5 ms, then no repaint and no output for 12 s).
#[tokio::test]
async fn a_key_confirmed_by_a_route_proof_state_reply_still_gets_its_repaint() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window(&mut fixture).await;
    let commands = fixture.commands.as_mut().unwrap();
    commands.try_send(Command::Input(0, vec![b'k'])).unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SequencedInput(0, vec![b'k'])
    );
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Ping(7, 9))
        .unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::InputStateRequest
    );
    // One state reply answers the route proof and confirms the key, as the real shim's single slot does.
    sessions::send(&mut fixture.peer, &Shim::InputState(1, 1))
        .await
        .unwrap();
    let requested = matches!(
        tokio::time::timeout(EVENT_GUARD, fixture.reader.read(&mut fixture.peer)).await,
        Ok(Ok(Shim::SnapshotRequest))
    );
    let mut acked = false;
    let mut ponged = false;
    let mut repaint = None;
    if requested {
        sessions::send(
            &mut fixture.peer,
            &Shim::Snapshot(u64::from(BULK_CREDIT) + 1, b"echo:k".to_vec()),
        )
        .await
        .unwrap();
        while repaint.is_none() {
            match tokio::time::timeout(EVENT_GUARD, fixture.messages.recv()).await {
                Ok(Some(Message::Shim(2, Shim::InputAck(seq)))) => acked |= seq >= 1,
                Ok(Some(Message::Pong(2, 7, 9))) => ponged = true,
                Ok(Some(Message::Shim(2, Shim::Snapshot(seq, bytes)))) => {
                    repaint = Some((seq, bytes));
                }
                Ok(Some(Message::Shim(2, Shim::Output(..)) | Message::Event(2, _))) => {}
                Ok(Some(_) | None) | Err(_) => break,
            }
        }
    }
    stop_relay(&mut fixture).await;
    assert!(
        requested,
        "a key confirmed by the route proof's state reply must still release its repaint request"
    );
    assert!(acked, "the client must see the key's acknowledgment");
    assert!(ponged, "the route proof must still be answered");
    assert_eq!(
        repaint,
        Some((u64::from(BULK_CREDIT) + 1, b"echo:k".to_vec()))
    );
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
    fill_bulk_window(&mut fixture).await;
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

/// A key from a client that granted only the legacy window keeps exact raw delivery (#477, J637).
///
/// Native clients grant 1 MiB without the repaint reserve and expect every byte once, in order.
/// The relay must not drop the parked flood frame for a repaint: after the key's Ack and returned
/// credit, that same frame is forwarded whole. Before this fix the key discarded it and requested
/// a Snapshot, which is what broke the real-binary exact-byte fixtures.
#[tokio::test]
async fn a_legacy_window_key_keeps_exact_raw_delivery() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window_without_repaint_reserve(&mut fixture).await;
    let commands = fixture.commands.as_mut().unwrap();
    commands.try_send(Command::Input(0, vec![b'k'])).unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SequencedInput(0, vec![b'k'])
    );
    // The relay holds the parked frame and does not read this Ack until credit returns.
    sessions::send(&mut fixture.peer, &Shim::InputAck(1))
        .await
        .unwrap();
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(BULK_CREDIT))
        .unwrap();
    let mut forwarded = None;
    let mut acked = false;
    while forwarded.is_none() || !acked {
        match tokio::time::timeout(EVENT_GUARD, fixture.messages.recv()).await {
            Ok(Some(Message::Shim(stream, Shim::Output(seq, bytes))))
                if stream == fixture.stream =>
            {
                forwarded = Some((seq, bytes.len()));
            }
            Ok(Some(Message::Shim(stream, Shim::InputAck(1)))) if stream == fixture.stream => {
                acked = true;
            }
            Ok(Some(Message::Shim(stream, Shim::Snapshot(..)))) if stream == fixture.stream => {
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    stop_relay(&mut fixture).await;

    assert_eq!(
        forwarded,
        Some((u64::from(BULK_CREDIT), STARVING_OUTPUT)),
        "the parked raw frame must be delivered whole, not replaced by a repaint"
    );
    assert!(acked, "the key must still be acknowledged");
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

/// Leave the PTY time to render, then request capture with time left in the frame budget.
#[tokio::test(start_paused = true)]
async fn key_repaint_leaves_time_in_the_frame_after_pty_echo_grace() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window(&mut fixture).await;
    assert!(type_key_and_wait_for_ack(&mut fixture, 0).await);
    tokio::task::yield_now().await;

    let echo_start = u64::from(BULK_CREDIT) + STARVING_OUTPUT as u64;
    let cursor = echo_start + 6;
    let early = tokio::time::timeout(
        Duration::from_millis(1),
        fixture.reader.read(&mut fixture.peer),
    )
    .await;
    let requested_early = matches!(early, Ok(Ok(Shim::SnapshotRequest)));
    let repaint = if requested_early {
        None
    } else {
        sessions::send(
            &mut fixture.peer,
            &Shim::Output(echo_start, b"echo:k".to_vec()),
        )
        .await
        .unwrap();
        tokio::task::yield_now().await;
        let requested = matches!(
            tokio::time::timeout(
                Duration::from_millis(4),
                fixture.reader.read(&mut fixture.peer)
            )
            .await,
            Ok(Ok(Shim::SnapshotRequest))
        );
        if requested {
            sessions::send(
                &mut fixture.peer,
                &Shim::Snapshot(cursor, b"echo:k".to_vec()),
            )
            .await
            .unwrap();
            let repaint = wait_for_repaint(&mut fixture).await;

            // A response can continue after capture. Returning some flood
            // credit lets the remainder follow the repaint at its cursor.
            fixture
                .commands
                .as_mut()
                .unwrap()
                .try_send(Command::Credit(REPAINT_CREDIT))
                .unwrap();
            sessions::send(&mut fixture.peer, &Shim::Output(cursor, b":tail".to_vec()))
                .await
                .unwrap();
            assert!(matches!(
                next_message(&mut fixture).await,
                Message::Shim(2, Shim::Output(seq, bytes)) if seq == cursor && bytes == b":tail"
            ));
            repaint
        } else {
            None
        }
    };
    stop_relay(&mut fixture).await;

    assert!(
        !requested_early,
        "a key repaint must leave time for the application's echo before capture"
    );
    assert_eq!(repaint, Some((cursor, b"echo:k".to_vec())));
}

/// A key arriving just before bulk starvation gets its own chance to repaint (#546).
#[tokio::test(start_paused = true)]
async fn bulk_starvation_does_not_cancel_an_acknowledged_key_repaint() {
    let mut fixture = start_relay(2).await;
    fill_partial_bulk_backlog(&mut fixture, PARTIAL_BULK_OUTPUT).await;
    let remaining = BULK_CREDIT as usize - PARTIAL_BULK_OUTPUT;
    sessions::send(
        &mut fixture.peer,
        &Shim::Output(PARTIAL_BULK_OUTPUT as u64, vec![b'f'; remaining + 1]),
    )
    .await
    .unwrap();
    // The affordable prefix is forwarded. The last byte arms the bulk timer in the same turn.
    assert!(matches!(
        next_message(&mut fixture).await,
        Message::Shim(2, Shim::Output(seq, bytes))
            if seq == PARTIAL_BULK_OUTPUT as u64 && bytes.len() == remaining
    ));
    // Leave half of the echo grace before the bulk deadline expires.
    let before_starvation = relay::STARVATION
        .checked_sub(KEY_REPAINT_GRACE / 2)
        .unwrap();
    tokio::time::advance(before_starvation).await;
    assert!(type_key_and_wait_for_ack(&mut fixture, 0).await);
    let requested = matches!(
        tokio::time::timeout(EVENT_GUARD, fixture.reader.read(&mut fixture.peer)).await,
        Ok(Ok(Shim::SnapshotRequest))
    );
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

    assert_eq!(
        repaint,
        Some((u64::from(BULK_CREDIT) + 1, b"echo:k".to_vec())),
        "the old bulk deadline must not abandon a key once the PTY acknowledged it"
    );
}

/// Returning output credit while capture is in flight must preserve the original wait bound.
#[tokio::test(start_paused = true)]
async fn capture_wait_stays_bounded_after_credit_returns() {
    let mut fixture = start_relay(2).await;
    fill_bulk_window(&mut fixture).await;
    let started = Instant::now();
    assert!(type_key_and_wait_for_repaint_request(&mut fixture, 0).await);

    let commands = fixture.commands.as_mut().unwrap();
    commands.try_send(Command::Credit(1)).unwrap();
    commands.try_send(Command::Ping(7, 9)).unwrap();
    // The ping crosses the shim socket only after the earlier credit is applied.
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::InputStateRequest
    );

    // Deliberately withhold the snapshot until the relay closes the shim link.
    let end = started + relay::STARVATION + CAPTURE_EXPIRY_OBSERVATION_SLACK;
    let closed = tokio::time::timeout_at(end, fixture.peer.read(&mut [0; 1])).await;
    stop_relay(&mut fixture).await;

    assert!(
        matches!(closed, Ok(Ok(0))),
        "returned credit disarmed the in-flight capture deadline: {closed:?}"
    );
}

/// A replacement capture needs a deadline even when the bulk window still has room.
#[tokio::test(start_paused = true)]
async fn capture_wait_stays_bounded_with_available_bulk_credit() {
    let mut fixture = start_relay(2).await;
    fill_partial_bulk_backlog(&mut fixture, PARTIAL_BULK_OUTPUT).await;
    let started = Instant::now();
    assert!(type_key_and_wait_for_repaint_request(&mut fixture, 0).await);

    // The capture replaces unreturned output. No unaffordable frame has armed a bulk timer.
    let end = started + relay::STARVATION + CAPTURE_EXPIRY_OBSERVATION_SLACK;
    let closed = tokio::time::timeout_at(end, fixture.peer.read(&mut [0; 1])).await;
    stop_relay(&mut fixture).await;

    assert!(
        matches!(closed, Ok(Ok(0))),
        "capture started without a deadline while bulk credit was available: {closed:?}"
    );
}

/// Delivering the first Snapshot must leave a deadline for the already-coalesced key.
#[tokio::test(start_paused = true)]
async fn capture_wait_stays_bounded_for_a_coalesced_follow_up() {
    let mut fixture = start_relay(2).await;
    fill_partial_bulk_backlog(&mut fixture, PARTIAL_BULK_OUTPUT).await;
    assert!(type_key_and_wait_for_repaint_request(&mut fixture, 0).await);
    assert!(type_key_and_wait_for_ack(&mut fixture, 1).await);
    let seq = PARTIAL_BULK_OUTPUT as u64 + 1;
    sessions::send(&mut fixture.peer, &Shim::Snapshot(seq, b"echo:k".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        wait_for_repaint(&mut fixture).await,
        Some((seq, b"echo:k".to_vec()))
    );
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SnapshotRequest
    );

    let end = Instant::now() + relay::STARVATION + CAPTURE_EXPIRY_OBSERVATION_SLACK;
    let closed = tokio::time::timeout_at(end, fixture.peer.read(&mut [0; 1])).await;
    if matches!(closed, Ok(Ok(0))) {
        accept_relinked_peer(&mut fixture).await;
        assert_eq!(
            read_shim(&mut fixture.reader, &mut fixture.peer).await,
            Shim::ReadFrom(seq)
        );
    }
    stop_relay(&mut fixture).await;

    assert!(
        matches!(closed, Ok(Ok(0))),
        "the coalesced follow-up must detach if its snapshot never arrives: {closed:?}"
    );
}

/// A blocked priority send must still close the shim and resume before its unqueued Snapshot.
#[tokio::test(start_paused = true)]
async fn capture_expiry_cancels_snapshot_writer_admission() {
    let (priority, mut queued) = mpsc::channel(1);
    let mut fixture = start_relay_with_priority(2, Some(priority)).await;
    fill_partial_bulk_backlog(&mut fixture, PARTIAL_BULK_OUTPUT).await;
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Input(0, vec![b'k']))
        .unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SequencedInput(0, vec![b'k'])
    );
    // The relay arms capture expiry before it writes this input frame.
    let armed_by = Instant::now();
    sessions::send(&mut fixture.peer, &Shim::InputAck(1))
        .await
        .unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SnapshotRequest
    );
    let delivered = PARTIAL_BULK_OUTPUT as u64;
    // Leave the Ack in the one-slot queue so the Snapshot cannot enter it.
    sessions::send(
        &mut fixture.peer,
        &Shim::Snapshot(delivered + 1, b"echo:k".to_vec()),
    )
    .await
    .unwrap();
    let end = armed_by + relay::STARVATION + CAPTURE_EXPIRY_OBSERVATION_SLACK;
    let closed = tokio::time::timeout_at(end, fixture.peer.read(&mut [0; 1])).await;
    assert!(matches!(
        queued.try_recv(),
        Ok(PriorityMessage::InputAck { seq: 1, .. })
    ));
    if matches!(closed, Ok(Ok(0))) {
        assert!(matches!(
            tokio::time::timeout(EVENT_GUARD, queued.recv()).await,
            Ok(Some(PriorityMessage::Release { .. }))
        ));
        accept_relinked_peer(&mut fixture).await;
        assert_eq!(
            read_shim(&mut fixture.reader, &mut fixture.peer).await,
            Shim::ReadFrom(delivered)
        );
    }
    // On an observer timeout, close the writer lane so teardown cannot wait
    // on a recovery handshake the fixture never accepted.
    drop(queued);
    stop_relay(&mut fixture).await;

    assert!(
        matches!(closed, Ok(Ok(0))),
        "writer backpressure delayed capture expiry: {closed:?}"
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

/// Flood frames that fill the relay's 16-slot writer FIFO in [`stage_the_last_bulk_frame`].
const QUEUED_FRAMES: usize = 16;
/// Each queued frame's length; with [`STAGED_FRAME`] they spend the bulk window exactly.
const QUEUED_FRAME: usize = 61_680;
/// The last frame, which finds the FIFO full and waits in `pending_bulk`.
const STAGED_FRAME: usize = BULK_CREDIT as usize - QUEUED_FRAMES * QUEUED_FRAME;
/// Bytes of the queued frames, which are all the client can actually receive.
const QUEUED_BYTES: u64 = (QUEUED_FRAMES * QUEUED_FRAME) as u64;

/// Spend the whole bulk window while the client reads nothing: the writer FIFO
/// fills, and the last frame is credit-charged but waits for the writer.
///
/// Nothing observable marks the relay staging that frame, so this waits a moment.
async fn stage_the_last_bulk_frame(fixture: &mut RelayFixture) {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(INITIAL_CREDIT))
        .unwrap();
    for frame in 0..QUEUED_FRAMES {
        sessions::send(
            &mut fixture.peer,
            &Shim::Output((frame * QUEUED_FRAME) as u64, vec![b'f'; QUEUED_FRAME]),
        )
        .await
        .unwrap();
    }
    sessions::send(
        &mut fixture.peer,
        &Shim::Output(QUEUED_BYTES, vec![b's'; STAGED_FRAME]),
    )
    .await
    .unwrap();
    // sleep: let the relay stage the last frame behind its full writer FIFO.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Type one key while the last bulk frame is staged, confirm its PTY write,
/// and wait for the relay's `SnapshotRequest`. The key discards the staged frame.
async fn key_over_a_staged_frame(fixture: &mut RelayFixture) {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Input(0, vec![b'k']))
        .unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SequencedInput(0, vec![b'k'])
    );
    sessions::send(&mut fixture.peer, &Shim::InputAck(1))
        .await
        .unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::SnapshotRequest
    );
}

/// Read every message the relay has queued, until it stays quiet for a moment,
/// and return the raw Output bytes among them (checking they are contiguous).
async fn drain_raw_output(fixture: &mut RelayFixture, mut next: u64) -> u64 {
    let start = next;
    while let Ok(Some(message)) =
        tokio::time::timeout(Duration::from_millis(400), fixture.messages.recv()).await
    {
        if let Message::Shim(stream, Shim::Output(seq, bytes)) = message {
            assert_eq!(stream, fixture.stream);
            assert_eq!(seq, next, "raw output reaches the client without a gap");
            next += bytes.len() as u64;
        }
    }
    next - start
}

/// A key that discards a staged, already-charged Output must not shrink the
/// client's window: the client never receives those bytes, so it can never
/// return their credit (#477, J794).
///
/// The client here returns exactly what it received (the queued frames and the
/// repaint). Its whole bulk window is then free again, so the relay must be
/// able to send a full bulk window of new output.
#[tokio::test]
async fn a_key_that_discards_a_staged_frame_keeps_the_whole_bulk_window() {
    let mut fixture = start_relay(2).await;
    stage_the_last_bulk_frame(&mut fixture).await;
    key_over_a_staged_frame(&mut fixture).await;
    let head = u64::from(BULK_CREDIT);
    sessions::send(&mut fixture.peer, &Shim::Snapshot(head, b"echo:k".to_vec()))
        .await
        .unwrap();
    let received = drain_raw_output(&mut fixture, 0).await;
    assert_eq!(
        received, QUEUED_BYTES,
        "the staged frame never reaches the client"
    );
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(
            u32::try_from(received).unwrap() + u32::try_from(b"echo:k".len()).unwrap(),
        ))
        .unwrap();

    // Offer more new output than one window; count what the relay forwards
    // before it stalls for credit.
    let chunk = 16 * 1024;
    let frames = (BULK_CREDIT as usize + 2 * chunk) / chunk;
    let peer = &mut fixture.peer;
    let flood = async {
        for frame in 0..frames {
            let seq = head + (frame * chunk) as u64;
            // The relay may detach once starved; later writes may then fail.
            if sessions::send(peer, &Shim::Output(seq, vec![b'n'; chunk]))
                .await
                .is_err()
            {
                break;
            }
        }
    };
    let messages = &mut fixture.messages;
    let count = async {
        let mut forwarded = 0_u64;
        while let Ok(Some(message)) =
            tokio::time::timeout(Duration::from_millis(400), messages.recv()).await
        {
            if let Message::Shim(_, Shim::Output(_, bytes)) = message {
                forwarded += bytes.len() as u64;
            }
        }
        forwarded
    };
    let ((), forwarded) = tokio::join!(flood, count);
    stop_relay(&mut fixture).await;

    assert_eq!(
        forwarded,
        u64::from(BULK_CREDIT),
        "a discarded staged frame must not leak its credit from the bulk window"
    );
}

/// A key repaint that never commits must not leave the relay's cursor past
/// bytes the client never received, or the recovery replay starts after a gap
/// (#477, J794).
///
/// Here an older shim answers the `SnapshotRequest` with "snapshot unavailable",
/// which parks the link. The 250 ms starvation timer firing before the repaint
/// commits abandons it the same way.
#[tokio::test]
async fn an_abandoned_key_repaint_never_skips_a_discarded_staged_frame() {
    let mut fixture = start_relay(2).await;
    stage_the_last_bulk_frame(&mut fixture).await;
    key_over_a_staged_frame(&mut fixture).await;
    sessions::send(&mut fixture.peer, &Shim::Error(1, "no repaint".into()))
        .await
        .unwrap();
    // The relay's notice waits behind the full writer FIFO: read it all first.
    let received = drain_raw_output(&mut fixture, 0).await;
    assert_eq!(
        received, QUEUED_BYTES,
        "the staged frame never reaches the client"
    );
    wait_for_link_close(&mut fixture).await;
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(u32::try_from(received).unwrap()))
        .unwrap();
    accept_relinked_peer(&mut fixture).await;
    let resumed = read_shim(&mut fixture.reader, &mut fixture.peer).await;
    stop_relay(&mut fixture).await;

    assert_eq!(
        resumed,
        Shim::ReadFrom(received),
        "recovery must resume at the client's last received byte, not after the discarded frame"
    );
}
