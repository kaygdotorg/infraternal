//! A shim Output frame that crosses the replay fence must be delivered whole, with no later event needed [#324].
//!
//! `Hello.head` splits the bytes already present when a link opened from the
//! bytes produced while the attach was being established. If the shell keeps
//! printing between that Hello and the shim's handling of `ReadFrom`, the shim
//! legitimately answers with ONE frame that holds both. The relay forwards the
//! prefix up to the fence, emits `ReplayComplete`, and must then forward the
//! rest of the same frame. It used to park the remainder and wait: nothing
//! re-entered the loop while credit was available, so the tail stayed invisible
//! until an unrelated command arrived.
//!
//! The same fence must also keep its order when the shared writer is full: a
//! raw Output that waits for a writer slot must still reach the wire before
//! `ReplayComplete`, an exit notice or a Close queued after it (#477).
use super::*;

/// Bytes present at Hello (a first prompt), and the frame the shim sends later.
const HEAD: usize = 104;
const FRAME: usize = 453;
/// Hang bound only: the fixed relay delivers the tail without waiting at all.
const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// An Output frame that crosses the replay fence is delivered without the
/// relay needing another client command.
#[tokio::test]
async fn output_frame_crossing_the_replay_fence_is_delivered_without_another_command() {
    use infraternal_shim::frame::MULTI_WRITER;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "f{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let peer = tokio::spawn(async move {
        let (mut data, _) = listener.accept().await.unwrap();
        sessions::send(
            &mut data,
            &Shim::Hello {
                version: 1,
                caps: SEQUENCED_INPUT | MULTI_WRITER,
                session: id,
                pid: std::process::id(),
                cols: 80,
                rows: 24,
                created: 0,
                head: HEAD as u64,
                start: 0,
            },
        )
        .await
        .unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut data).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::SelectWriter(2));
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
        // The shell printed more after Hello: one frame, old head plus new bytes.
        sessions::send(&mut data, &Shim::Output(0, vec![b'x'; FRAME]))
            .await
            .unwrap();
        // Hold the link open until the relay is retired, like a live shim.
        assert!(reader.read(&mut data).await.is_err());
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(8);
    let task = tokio::spawn(terminal(path, id, 2, 0, 0, receiver, tx));
    // A relay first announces its attachment to the writer (#477).
    assert!(matches!(
        messages.recv().await,
        Some(Message::Attached(2, _))
    ));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    commands.try_send(Command::Credit(1 << 20)).unwrap();

    // Output parts in arrival order, and how many had arrived at ReplayComplete.
    let mut parts = Vec::new();
    let mut complete_after = None;
    while parts.iter().map(|&(_, len)| len).sum::<usize>() < FRAME {
        let message = tokio::time::timeout(HANG_BOUND, messages.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} of {FRAME} bytes were delivered; the rest of the frame stayed parked \
                     with credit available",
                    parts.iter().map(|&(_, len)| len).sum::<usize>()
                )
            });
        match message {
            Some(Message::Shim(2, Shim::Output(seq, bytes))) => parts.push((seq, bytes.len())),
            Some(Message::Event(2, _)) => complete_after = Some(parts.len()),
            _ => panic!("relay emitted an unexpected message"),
        }
    }
    drop(commands);
    task.await.unwrap().unwrap();
    peer.await.unwrap();
    std::fs::remove_dir_all(state).unwrap();
    assert_eq!(
        parts,
        [(0, HEAD), (HEAD as u64, FRAME - HEAD)],
        "the frame splits exactly at the fence and the tail follows at the fence offset"
    );
    assert_eq!(
        complete_after,
        Some(1),
        "ReplayComplete follows the prefix and precedes the tail"
    );
}

/// What the fake shim sends right after the Output that waits for the writer.
#[derive(Clone, Copy)]
enum AfterOutput {
    /// Nothing: the Output itself reaches the replay fence, so the relay's
    /// next ordered message is `ReplayComplete`.
    Nothing,
    /// The session exited after printing the Output.
    Exited,
    /// The shim refused the terminal, so the relay closes the stream.
    Refusal,
    /// The shim cannot repaint (an older shim), so the relay sends the
    /// snapshot-unavailable notice and parks the link.
    SnapshotUnavailable,
}

/// One ordered message the relay put on the shared writer FIFO, reduced to
/// what the ordering tests compare.
#[derive(Debug, PartialEq, Eq)]
enum Wire {
    /// Raw output at this cursor, with this many bytes.
    Output(u64, usize),
    /// A JSON terminal event, such as `ReplayComplete`.
    Event,
    /// The session's exit notice.
    Exited,
    /// The relay closed the stream.
    Close,
    /// The session's shim is gone: the final close.
    Ended,
    /// A new attachment marker for the writer (a cursor rewind).
    Attached,
}

/// Drive a relay whose shared writer FIFO is full when the shim's Output
/// arrives, then report the order in which its ordered messages leave.
///
/// The writer FIFO holds one message, and the test fills it with a filler
/// Pong before the shim sends the Output. The relay must stage the Output
/// (`pending_bulk`) instead of waiting, so the next message that depends on
/// the bytes before it (replay completion, exit, close) is queued while the
/// Output is still held. Only then does the test drain the FIFO. With `head`
/// equal to the frame length, the frame ends exactly at the replay fence.
async fn order_behind_a_full_writer(head: u64, after: AfterOutput) -> Vec<Wire> {
    use infraternal_shim::frame::MULTI_WRITER;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "o{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (go, start_output) = tokio::sync::oneshot::channel::<()>();
    let (sent, output_sent) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let (mut data, _) = listener.accept().await.unwrap();
        sessions::send(
            &mut data,
            &Shim::Hello {
                version: 1,
                caps: SEQUENCED_INPUT | MULTI_WRITER,
                session: id,
                pid: std::process::id(),
                cols: 80,
                rows: 24,
                created: 0,
                head,
                start: 0,
            },
        )
        .await
        .unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut data).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::SelectWriter(2));
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
        start_output.await.unwrap();
        sessions::send(&mut data, &Shim::Output(0, vec![b'x'; FRAME]))
            .await
            .unwrap();
        match after {
            AfterOutput::Nothing => {}
            AfterOutput::Exited => sessions::send(&mut data, &Shim::Exited(0, FRAME as u64))
                .await
                .unwrap(),
            AfterOutput::Refusal => sessions::send(&mut data, &Shim::Error(3, "refused".into()))
                .await
                .unwrap(),
            AfterOutput::SnapshotUnavailable => {
                sessions::send(&mut data, &Shim::Error(1, "no repaint".into()))
                    .await
                    .unwrap();
            }
        }
        sent.send(()).unwrap();
        // Hold the link open until the relay is retired, like a live shim.
        assert!(reader.read(&mut data).await.is_err());
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(1);
    let filler = tx.clone();
    let task = tokio::spawn(terminal(path, id, 2, 0, 0, receiver, tx));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Attached(2, _))
    ));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    if head == 0 {
        // An empty replay completes before any output is read.
        assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    }
    commands.try_send(Command::Credit(1 << 20)).unwrap();
    // Hold the writer: its one FIFO slot is taken before the Output exists.
    filler.send(Message::Pong(9, 0, 0)).await.unwrap();
    drop(filler);
    go.send(()).unwrap();
    output_sent.await.unwrap();
    // Nothing observable marks the moment the relay has staged the Output and
    // queued its next ordered message behind the full FIFO. The pause only
    // makes the red run reliable; the fixed relay is ordered however long the
    // test waits, so a slow host cannot make it fail.
    // sleep: let the relay stage the Output behind the held writer slot.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(matches!(
        messages.recv().await,
        Some(Message::Pong(9, 0, 0))
    ));
    let mut wire = Vec::new();
    let mut output = 0;
    loop {
        let message = tokio::time::timeout(HANG_BOUND, messages.recv())
            .await
            .expect("the relay stopped before its ordered messages arrived");
        match message {
            Some(Message::Shim(2, Shim::Output(seq, bytes))) => {
                output += bytes.len();
                wire.push(Wire::Output(seq, bytes.len()));
            }
            Some(Message::Event(2, _)) => wire.push(Wire::Event),
            Some(Message::Exited(2, _, delivered)) => {
                wire.push(Wire::Exited);
                let _ = delivered.send(());
            }
            Some(Message::Close(2, _)) => wire.push(Wire::Close),
            None => break,
            _ => panic!("relay emitted an unexpected message"),
        }
        let done = match after {
            AfterOutput::Nothing => output == FRAME && wire.contains(&Wire::Event),
            AfterOutput::Exited => wire.contains(&Wire::Exited),
            AfterOutput::Refusal => wire.contains(&Wire::Close),
            AfterOutput::SnapshotUnavailable => wire.contains(&Wire::Event),
        };
        if done {
            break;
        }
    }
    drop(commands);
    task.await.unwrap().unwrap();
    peer.await.unwrap();
    std::fs::remove_dir_all(state).unwrap();
    wire
}

/// `ReplayComplete` names the cursor the client must already hold. When the
/// replay's last Output waits for a full writer, the event must not overtake
/// it, or the client sees "replay complete at N" holding one frame less
/// (J775's P1: `real_binary_preserves_input_and_output_across_24_abrupt_stops`).
#[tokio::test]
async fn replay_complete_never_overtakes_an_output_held_for_the_writer() {
    let wire = order_behind_a_full_writer(FRAME as u64, AfterOutput::Nothing).await;
    assert_eq!(
        wire,
        [Wire::Output(0, FRAME), Wire::Event],
        "the held replay Output reaches the writer before ReplayComplete"
    );
}

/// An exit notice carries the final output cursor, so output held for the
/// writer must reach it first, or the stream ends without its last bytes.
#[tokio::test]
async fn exited_never_overtakes_an_output_held_for_the_writer() {
    let wire = order_behind_a_full_writer(0, AfterOutput::Exited).await;
    assert_eq!(
        wire,
        [Wire::Output(0, FRAME), Wire::Exited],
        "the held Output reaches the writer before the exit notice"
    );
}

/// A Close ends the stream, so output held for the writer goes first instead
/// of being dropped with the relay.
#[tokio::test]
async fn close_never_overtakes_an_output_held_for_the_writer() {
    let wire = order_behind_a_full_writer(0, AfterOutput::Refusal).await;
    assert_eq!(
        wire,
        [Wire::Output(0, FRAME), Wire::Close],
        "the held Output reaches the writer before the Close"
    );
}

/// When a frame crosses the replay fence, its prefix may be the part held for
/// the writer. `ReplayComplete` must still follow that prefix, and the tail
/// must follow the event (#477, J794: the split-frame fence site).
#[tokio::test]
async fn replay_complete_after_a_split_frame_never_overtakes_its_held_prefix() {
    let wire = order_behind_a_full_writer(HEAD as u64, AfterOutput::Nothing).await;
    assert_eq!(
        wire,
        [
            Wire::Output(0, HEAD),
            Wire::Event,
            Wire::Output(HEAD as u64, FRAME - HEAD)
        ],
        "the held prefix reaches the writer before ReplayComplete, and the tail after it"
    );
}

/// The snapshot-unavailable notice carries a cursor that already counts the
/// held bytes, so they must reach the writer first (#477, J794).
#[tokio::test]
async fn snapshot_unavailable_never_overtakes_an_output_held_for_the_writer() {
    let wire = order_behind_a_full_writer(0, AfterOutput::SnapshotUnavailable).await;
    assert_eq!(
        wire,
        [Wire::Output(0, FRAME), Wire::Event],
        "the held Output reaches the writer before the snapshot-unavailable notice"
    );
}

/// Client credit when the shim's frame arrives: the frame is larger, so only
/// this prefix is sent and the rest waits for credit.
const SHORT_CREDIT: usize = 300;

/// What happens after the starvation timer has detached the relay while a
/// credit-funded prefix still waits for the writer.
#[derive(Clone, Copy)]
enum AfterDetach {
    /// Credit returns, so the relay relinks and restarts its replay fence at
    /// the held prefix's end.
    CreditReturns,
    /// The shim is gone, and the next command finds it so: the stream ends.
    ShimGone,
}

/// Hold the writer while the relay sends a prefix of an oversized frame, let
/// the 250 ms starvation timer detach the shim link with that prefix still
/// held, then report the order of the relay's ordered messages after
/// `after` (J794: the recovery relink and detached-command relink sites).
///
/// The fake shim's replacement link reports `Hello.head` equal to the held
/// prefix's end, so a relink's restarted replay completes at once: a
/// `ReplayComplete` (or the `Ended` of a vanished shim) is what could
/// overtake the held bytes.
async fn order_after_a_starvation_detach(after: AfterDetach) -> Vec<Wire> {
    use infraternal_shim::frame::MULTI_WRITER;
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "d{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (go, start_output) = tokio::sync::oneshot::channel::<()>();
    let (detached, link_dropped) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let hello = |head| Shim::Hello {
            version: 1,
            caps: SEQUENCED_INPUT | MULTI_WRITER,
            session: id,
            pid: std::process::id(),
            cols: 80,
            rows: 24,
            created: 0,
            head,
            start: 0,
        };
        let (mut data, _) = listener.accept().await.unwrap();
        sessions::send(&mut data, &hello(0)).await.unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut data).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::SelectWriter(2));
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
        start_output.await.unwrap();
        sessions::send(&mut data, &Shim::Output(0, vec![b'x'; FRAME]))
            .await
            .unwrap();
        // The starvation timer drops this link.
        assert!(reader.read(&mut data).await.is_err());
        detached.send(()).unwrap();
        // A relink (credit returned) connects again; a vanished shim never answers.
        let Ok((mut data, _)) = listener.accept().await else {
            return;
        };
        sessions::send(&mut data, &hello(SHORT_CREDIT as u64))
            .await
            .unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut data).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::SelectWriter(2));
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(0, 0))
            .await
            .unwrap();
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::ReadFrom(SHORT_CREDIT as u64)
        );
        assert!(reader.read(&mut data).await.is_err());
    });
    let (mut commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(1);
    let filler = tx.clone();
    let task = tokio::spawn(terminal(path.clone(), id, 2, 0, 0, receiver, tx));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Attached(2, _))
    ));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    // An empty replay completes before any output is read.
    assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    commands
        .try_send(Command::Credit(u32::try_from(SHORT_CREDIT).unwrap()))
        .unwrap();
    // Hold the writer: its one FIFO slot is taken before the Output exists.
    filler.send(Message::Pong(9, 0, 0)).await.unwrap();
    drop(filler);
    go.send(()).unwrap();
    // The relay holds the funded prefix, waits 250 ms for credit for the
    // rest, then detaches the shim link. The writer stays full throughout.
    tokio::time::timeout(HANG_BOUND, link_dropped)
        .await
        .expect("the starvation timer did not detach the shim link")
        .unwrap();
    match after {
        AfterDetach::CreditReturns => commands.try_send(Command::Credit(1000)).unwrap(),
        AfterDetach::ShimGone => {
            std::fs::remove_file(&path).unwrap();
            commands.try_send(Command::Resize(80, 24, 0, 0)).unwrap();
        }
    }
    // Nothing observable marks the relay queueing its next ordered message
    // behind the held writer; the fixed relay is ordered however long this is.
    // sleep: let the relay reach its relink while the writer slot is held.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(matches!(
        messages.recv().await,
        Some(Message::Pong(9, 0, 0))
    ));
    let mut wire = Vec::new();
    loop {
        let message = tokio::time::timeout(HANG_BOUND, messages.recv())
            .await
            .expect("the relay stopped before its ordered messages arrived");
        match message {
            Some(Message::Shim(2, Shim::Output(seq, bytes))) => {
                wire.push(Wire::Output(seq, bytes.len()));
            }
            // A relink's input acknowledgment does not depend on output order.
            Some(Message::Shim(2, Shim::InputAck(_))) => {}
            Some(Message::Event(2, _)) => wire.push(Wire::Event),
            Some(Message::Ended(2)) => wire.push(Wire::Ended),
            None => break,
            _ => panic!("relay emitted an unexpected message"),
        }
        let done = match after {
            AfterDetach::CreditReturns => {
                wire.contains(&Wire::Event) && wire.contains(&Wire::Output(0, SHORT_CREDIT))
            }
            AfterDetach::ShimGone => wire.contains(&Wire::Ended),
        };
        if done {
            break;
        }
    }
    drop(commands);
    task.await.unwrap().unwrap();
    peer.abort();
    let _ = peer.await;
    std::fs::remove_dir_all(state).unwrap();
    wire
}

/// A relink after the starvation detach restarts the replay at the relay's
/// cursor, which counts the held prefix: that prefix must reach the writer
/// before the restarted replay's `ReplayComplete` (#477, J794).
#[tokio::test]
async fn a_recovery_relink_never_overtakes_an_output_held_for_the_writer() {
    let wire = order_after_a_starvation_detach(AfterDetach::CreditReturns).await;
    assert_eq!(
        wire,
        [Wire::Output(0, SHORT_CREDIT), Wire::Event],
        "the held prefix reaches the writer before the relinked replay completes"
    );
}

/// A detached relay that finds its shim gone on the next command ends the
/// stream; the prefix held for the writer must not be dropped with it (#477, J794).
#[tokio::test]
async fn ended_after_a_detached_command_never_drops_an_output_held_for_the_writer() {
    let wire = order_after_a_starvation_detach(AfterDetach::ShimGone).await;
    assert_eq!(
        wire,
        [Wire::Output(0, SHORT_CREDIT), Wire::Ended],
        "the held prefix reaches the writer before the stream ends"
    );
}

/// A remote cursor rewind starts a new attachment. Output the old attachment
/// held for the writer must reach it before the new `Attached` marker, or the
/// writer would count those old bytes as the rewound replay (#477, J794: the
/// rewind site J779 left without a test).
#[cfg(feature = "remote")]
#[tokio::test]
async fn a_cursor_rewind_marker_never_overtakes_an_output_held_for_the_writer() {
    use infraternal_shim::frame::{MULTI_WRITER, SHARED_WRITER};
    let id = *uuid::Uuid::new_v4().as_bytes();
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    )
    .join(format!(
        "r{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let state = sessions::state(Some(root)).unwrap();
    let path = sessions::rendezvous(&state, id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (go, start_output) = tokio::sync::oneshot::channel::<()>();
    let (sent, output_sent) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let hello = Shim::Hello {
            version: 1,
            caps: SEQUENCED_INPUT | MULTI_WRITER | SHARED_WRITER,
            session: id,
            pid: std::process::id(),
            cols: 80,
            rows: 24,
            created: 0,
            head: 0,
            start: 0,
        };
        let (mut data, _) = listener.accept().await.unwrap();
        sessions::send(&mut data, &hello).await.unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut data).await.unwrap(),
            Shim::Attach(_)
        ));
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::SelectSharedWriter(2)
        );
        assert_eq!(
            reader.read(&mut data).await.unwrap(),
            Shim::InputStateRequest
        );
        sessions::send(&mut data, &Shim::InputState(0, 0))
            .await
            .unwrap();
        // Each cursor command first reads replay geometry over a fresh link:
        // answer those with Hello only, in the background.
        let probes = tokio::spawn(async move {
            while let Ok((mut probe, _)) = listener.accept().await {
                let _ = sessions::send(&mut probe, &hello).await;
            }
        });
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
        start_output.await.unwrap();
        sessions::send(&mut data, &Shim::Output(0, vec![b'x'; FRAME]))
            .await
            .unwrap();
        sent.send(()).unwrap();
        // The rewind reads from its new cursor; then hold the link open.
        assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
        assert!(reader.read(&mut data).await.is_err());
        probes.abort();
    });
    let (command_tx, command_rx) = mpsc::channel(8);
    let (tx, mut messages) = mpsc::channel(1);
    let (priority, _priority_rx) = mpsc::channel(PRIORITY_CAPACITY);
    let filler = tx.clone();
    let task = tokio::spawn(terminal_mode(
        path,
        id,
        2,
        0,
        0,
        session_commands::Receiver::Native(command_rx),
        tx,
        priority,
        true,
    ));
    let Some(Message::Attached(2, first)) = messages.recv().await else {
        panic!("a relay first announces its attachment");
    };
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(2, Shim::InputAck(0)))
    ));
    // The server's first delivered cursor starts output and a fresh attachment.
    command_tx.send(Command::Cursor(0)).await.unwrap();
    let Some(Message::Attached(2, delivered)) = messages.recv().await else {
        panic!("a cursor command announces a new attachment");
    };
    assert!(delivered > first);
    assert!(matches!(messages.recv().await, Some(Message::Event(2, _))));
    command_tx.send(Command::Credit(1 << 20)).await.unwrap();
    // Hold the writer: its one FIFO slot is taken before the Output exists.
    filler.send(Message::Pong(9, 0, 0)).await.unwrap();
    drop(filler);
    go.send(()).unwrap();
    output_sent.await.unwrap();
    // sleep: let the relay stage the Output behind the held writer slot.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    command_tx.send(Command::Cursor(0)).await.unwrap();
    // sleep: let the rewind queue its marker behind the held writer slot.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(matches!(
        messages.recv().await,
        Some(Message::Pong(9, 0, 0))
    ));
    let mut wire = Vec::new();
    while !(wire.contains(&Wire::Attached) && wire.contains(&Wire::Output(0, FRAME))) {
        let message = tokio::time::timeout(HANG_BOUND, messages.recv())
            .await
            .expect("the relay stopped before its ordered messages arrived");
        match message {
            Some(Message::Shim(2, Shim::Output(seq, bytes))) => {
                wire.push(Wire::Output(seq, bytes.len()));
            }
            Some(Message::Attached(2, rewound)) => {
                assert!(rewound > delivered);
                wire.push(Wire::Attached);
            }
            Some(Message::Event(2, _)) => wire.push(Wire::Event),
            _ => panic!("relay emitted an unexpected message"),
        }
    }
    drop(command_tx);
    task.await.unwrap().unwrap();
    peer.await.unwrap();
    std::fs::remove_dir_all(state).unwrap();
    assert_eq!(
        wire,
        [Wire::Output(0, FRAME), Wire::Attached],
        "the old attachment's held Output reaches the writer before the rewind's marker"
    );
}
