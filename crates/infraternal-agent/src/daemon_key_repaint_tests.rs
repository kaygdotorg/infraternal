//! Exercises key-triggered screen repaint ordering and per-session credit isolation [D381, #477].

use super::*;
use crate::sessions::Reader;
use infraternal_shim::frame::{MULTI_WRITER, SEQUENCED_INPUT};
use std::{path::PathBuf, time::Duration};
use tokio::{net::UnixStream, sync::mpsc, task::JoinHandle};

/// The ordinary raw-output allowance retained beside the repaint reserve.
const BULK_CREDIT: u32 = 1024 * 1024;
/// The initial client grant includes this extra, repaint-only amount.
const REPAINT_CREDIT: u32 = 64 * 1024;
/// The complete starting grant for a client that supports reserved repaints.
const INITIAL_CREDIT: u32 = BULK_CREDIT + REPAINT_CREDIT;
/// A frame larger than either credit pool makes starvation deterministic.
const STARVING_OUTPUT: usize = 128 * 1024;
/// Each spam repaint consumes one quarter of the finite reserve.
const SPAM_SNAPSHOT: usize = REPAINT_CREDIT as usize / 4;
/// A generous guard for a missing fixture event, never a performance assertion.
const EVENT_GUARD: Duration = Duration::from_secs(3);

/// One terminal relay paired with a fake shim data socket.
struct RelayFixture {
    root: PathBuf,
    stream: u32,
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
        stream,
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

/// Forward a message read until the requested `InputAck`, skipping already-sent flood bytes.
async fn wait_for_input_ack(fixture: &mut RelayFixture, written: u64) -> bool {
    loop {
        match tokio::time::timeout(EVENT_GUARD, fixture.messages.recv()).await {
            Ok(Some(Message::Shim(stream, Shim::InputAck(acked))))
                if stream == fixture.stream && acked >= written =>
            {
                return true;
            }
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
