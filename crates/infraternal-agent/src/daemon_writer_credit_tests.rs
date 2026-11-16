//! Runs a terminal relay into the real leg-B writer while the writer's socket is held [D381, #477].
//!
//! A key typed during a flood sends its `InputAck` and repaint on the writer's
//! priority lane, past raw output that already sits in the writer's FIFO. The
//! relay charged that output to the client's credit when it queued it, but only
//! the writer knows which of those frames end up on the wire. These tests drive
//! both halves together, the way production does, and look at what the client
//! would actually see: the frames on the wire, the credit it can return for
//! them, and where the relay's recovery replay resumes (#477, J794, J799).
//!
//! Every test uses the same layout. The writer is blocked writing the first
//! raw frame, its eight-slot FIFO is full, and those nine frames spend the
//! client's whole bulk window. A key then arrives.

use super::key_repaint_tests::{EVENT_GUARD, greet_relay, read_shim, shim_rendezvous};
use super::*;
use crate::sessions::Reader;
use infraternal_protocol::Frame;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::UnixStream,
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};

/// The ordinary raw-output allowance a reserved client grants.
const BULK_CREDIT: u32 = 1024 * 1024;
/// The extra, repaint-only part of the opening grant.
const REPAINT_CREDIT: u32 = 64 * 1024;
/// The bulk FIFO's depth, the same as the production dispatcher's.
const FIFO_SLOTS: usize = 8;
/// Each queued frame's length.
const QUEUED_FRAME: usize = 116_000;
/// The frame the writer is blocked on; with the queued frames it spends the bulk window exactly.
const FIRST_FRAME: usize = BULK_CREDIT as usize - FIFO_SLOTS * QUEUED_FRAME;
/// The relay's output cursor once the window is spent, which the key's `InputAck` covers.
const WINDOW_END: u64 = BULK_CREDIT as u64;
/// The key repaint's capture.
const SCREEN: &[u8] = b"echo:k";
/// How long the wire must stay quiet before a test treats a burst as finished.
const QUIET: Duration = Duration::from_millis(400);

/// A leg-B socket that writes only as many frames as the test allows, and keeps a copy of each.
///
/// Holding it is how a slow QUIC path or a loaded host looks to the writer: the write in progress
/// does not finish, so the writer's FIFO fills up behind it.
struct HeldSocket {
    /// One permit per frame the socket may write; `open` adds enough for the rest of the test.
    permits: Semaphore,
    /// Every frame written, in wire order.
    frames: mpsc::UnboundedSender<Vec<u8>>,
}

impl Channel for HeldSocket {
    async fn read(&self, _: &mut [u8]) -> io::Result<usize> {
        std::future::pending().await
    }

    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        self.permits
            .acquire()
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?
            .forget();
        self.frames
            .send(bytes.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

impl HeldSocket {
    /// Let every later write through at once.
    fn open(&self) {
        self.permits.add_permits(Semaphore::MAX_PERMITS / 2);
    }
}

/// What the client received, decoded from the wire.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    /// Raw output at `out_seq`, with its length.
    Output(u64, usize),
    /// An input acknowledgment.
    Ack(u64),
    /// A screen repaint through `out_seq`, with its length.
    Snapshot(u64, usize),
    /// A terminal notice (replay complete, exit, snapshot unavailable, ...).
    Event,
    /// Anything else, such as a Close.
    Other,
}

/// One relay whose messages go through the real writer to a [`HeldSocket`], plus its fake shim.
struct Fixture {
    /// The test's private state root, removed by [`stop`].
    root: PathBuf,
    /// The session's rendezvous socket, beside which a test may save an exit record.
    path: PathBuf,
    /// The fake session's id.
    id: [u8; 16],
    /// Where the relay connects its shim links.
    listener: tokio::net::UnixListener,
    /// The fake shim's side of the current data link.
    peer: UnixStream,
    /// Frame reader for `peer`.
    reader: Reader,
    /// The client's commands to the relay; `None` once the test closes them.
    commands: Option<session_commands::Sender>,
    /// The writer's held leg-B socket.
    socket: Arc<HeldSocket>,
    /// Frames the writer put on the wire, in order.
    wire: mpsc::UnboundedReceiver<Vec<u8>>,
    /// The relay task.
    relay: Option<JoinHandle<io::Result<()>>>,
    /// The writer task.
    writer: Option<JoinHandle<io::Result<()>>>,
}

/// The stream id the relay uses.
const STREAM: u32 = 2;

/// Start a relay and a writer the way the dispatcher wires them, with the socket held after the
/// relay's two opening frames (its `InputAck` and its replay completion).
async fn start() -> Fixture {
    let wiring = launch(false);
    let (peer, reader) = greet_relay(&wiring.listener, wiring.id, STREAM).await;
    let mut fixture = wiring.greeted(peer, reader);
    assert_eq!(next_seen(&mut fixture).await, Some(Seen::Ack(0)));
    assert_eq!(next_seen(&mut fixture).await, Some(Seen::Event));
    fixture
}

/// Start a relay and a writer the way a primed (standby) route wires them, the only kind of
/// relay that takes the server's cursor rewinds. Its first delivered cursor, at 0, starts its
/// output; the socket is held after the same two opening frames as [`start`].
#[cfg(feature = "remote")]
async fn start_primed() -> Fixture {
    let wiring = launch(true);
    let (mut peer, _) = tokio::time::timeout(EVENT_GUARD, wiring.listener.accept())
        .await
        .expect("the primed relay did not connect to the fake shim")
        .unwrap();
    sessions::send(&mut peer, &primed_hello(wiring.id))
        .await
        .unwrap();
    let mut reader = Reader::default();
    assert!(matches!(
        read_shim(&mut reader, &mut peer).await,
        Shim::Attach(_)
    ));
    assert_eq!(
        read_shim(&mut reader, &mut peer).await,
        Shim::SelectSharedWriter(STREAM)
    );
    assert_eq!(
        read_shim(&mut reader, &mut peer).await,
        Shim::InputStateRequest
    );
    sessions::send(&mut peer, &Shim::InputState(0, 0))
        .await
        .unwrap();
    let mut fixture = wiring.greeted(peer, reader);
    assert_eq!(next_seen(&mut fixture).await, Some(Seen::Ack(0)));
    rewind(&mut fixture, 0).await;
    assert_eq!(next_seen(&mut fixture).await, Some(Seen::Event));
    fixture
}

/// The `Hello` the fake shim sends a primed relay on every link: a fresh session with no output.
#[cfg(feature = "remote")]
fn primed_hello(id: [u8; 16]) -> Shim {
    use infraternal_shim::frame::{MULTI_WRITER, SEQUENCED_INPUT, SHARED_WRITER};
    Shim::Hello {
        version: 1,
        caps: SEQUENCED_INPUT | MULTI_WRITER | SHARED_WRITER,
        session: id,
        pid: std::process::id(),
        cols: 80,
        rows: 24,
        created: 0,
        head: 0,
        start: 0,
    }
}

/// Send the server's cursor command to a primed relay, answer the geometry probe it opens, and
/// check that its shim link then replays from `cursor`. The writer must be free to take the
/// relay's new `Attached` marker by then.
#[cfg(feature = "remote")]
async fn rewind(fixture: &mut Fixture, cursor: u64) {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Cursor(cursor))
        .unwrap();
    let (mut probe, _) = tokio::time::timeout(EVENT_GUARD, fixture.listener.accept())
        .await
        .expect("the cursor command did not probe the shim's replay geometry")
        .unwrap();
    sessions::send(&mut probe, &primed_hello(fixture.id))
        .await
        .unwrap();
    assert_eq!(
        read_shim(&mut fixture.reader, &mut fixture.peer).await,
        Shim::ReadFrom(cursor)
    );
}

/// A relay wired to the real writer whose fake shim has not answered yet (see [`launch`]).
struct Wiring {
    /// The test's private state root.
    root: PathBuf,
    /// The session's rendezvous socket.
    path: PathBuf,
    /// The fake session's id.
    id: [u8; 16],
    /// Where the relay connects its shim links.
    listener: tokio::net::UnixListener,
    /// The client's commands to the relay.
    commands: session_commands::Sender,
    /// The writer's held leg-B socket.
    socket: Arc<HeldSocket>,
    /// Frames the writer put on the wire, in order.
    wire: mpsc::UnboundedReceiver<Vec<u8>>,
    /// The relay task.
    relay: JoinHandle<io::Result<()>>,
    /// The writer task.
    writer: JoinHandle<io::Result<()>>,
}

impl Wiring {
    /// The fixture, once the fake shim has answered the relay's first link as `peer`.
    fn greeted(self, peer: UnixStream, reader: Reader) -> Fixture {
        Fixture {
            root: self.root,
            path: self.path,
            id: self.id,
            listener: self.listener,
            peer,
            reader,
            commands: Some(self.commands),
            socket: self.socket,
            wire: self.wire,
            relay: Some(self.relay),
            writer: Some(self.writer),
        }
    }
}

/// Wire a relay (primed or not) to the real writer over a [`HeldSocket`] that lets the relay's
/// two opening frames through, through `terminal_mode` as the dispatcher does. The fake shim has
/// not answered yet: the caller greets it.
fn launch(primed: bool) -> Wiring {
    let id = *uuid::Uuid::new_v4().as_bytes();
    let (root, path) = shim_rendezvous(id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (commands, receiver) = session_commands::channel();
    let (tx, messages) = mpsc::channel(FIFO_SLOTS);
    let (priority, priority_rx) = mpsc::channel(PRIORITY_CAPACITY);
    let (frames, wire) = mpsc::unbounded_channel();
    let socket = Arc::new(HeldSocket {
        permits: Semaphore::new(2),
        frames,
    });
    let writer_socket = socket.clone();
    let writer = tokio::spawn(async move {
        crate::daemon_writer::writer(
            writer_socket.as_ref(),
            messages,
            None,
            Some(priority_rx),
            false,
            false,
            false,
            0,
        )
        .await
    });
    let relay = tokio::spawn(terminal_mode(
        path.clone(),
        id,
        STREAM,
        0,
        0,
        receiver,
        tx,
        priority,
        primed,
    ));
    Wiring {
        root,
        path,
        id,
        listener,
        commands,
        socket,
        wire,
        relay,
        writer,
    }
}

/// Decode one captured mux frame.
fn seen(bytes: &[u8]) -> Seen {
    let frame = infraternal_protocol::decode_muxed_frame(bytes).unwrap();
    assert_eq!(frame.stream_id, STREAM);
    match frame.frame {
        Frame::Output { out_seq, bytes } => Seen::Output(out_seq, bytes.len()),
        Frame::Ack { in_seq_acked } => Seen::Ack(in_seq_acked),
        Frame::Snapshot { out_seq, bytes } => Seen::Snapshot(out_seq, bytes.len()),
        Frame::Event { .. } => Seen::Event,
        _ => Seen::Other,
    }
}

/// The next frame on the wire, or `None` once the wire has been quiet for [`QUIET`].
async fn next_seen(fixture: &mut Fixture) -> Option<Seen> {
    match tokio::time::timeout(QUIET, fixture.wire.recv()).await {
        Ok(Some(bytes)) => Some(seen(&bytes)),
        Ok(None) | Err(_) => None,
    }
}

/// Every frame on the wire until it stays quiet.
async fn drain(fixture: &mut Fixture) -> Vec<Seen> {
    let mut all = vec![];
    while let Some(frame) = next_seen(fixture).await {
        all.push(frame);
    }
    all
}

/// The raw bytes the client received in `frames`, checking that they arrive without a gap.
fn received_raw(frames: &[Seen]) -> u64 {
    let mut next = 0;
    for frame in frames {
        if let Seen::Output(seq, length) = frame {
            assert_eq!(
                *seq, next,
                "raw output reaches the client without a gap: {frames:?}"
            );
            next += *length as u64;
        }
    }
    next
}

/// Grant the opening window, then let the shim flood until the window is spent: the writer is
/// blocked on the first frame and the FIFO holds the other eight.
///
/// No further frame is parked for credit, so the relay's 250 ms starvation clock starts only when
/// the key arrives; a test that answers the key's capture at once is never raced by it.
async fn spend_the_window_behind_a_held_socket(fixture: &mut Fixture) {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(BULK_CREDIT + REPAINT_CREDIT))
        .unwrap();
    sessions::send(&mut fixture.peer, &Shim::Output(0, vec![b'a'; FIRST_FRAME]))
        .await
        .unwrap();
    for frame in 0..FIFO_SLOTS {
        let seq = (FIRST_FRAME + frame * QUEUED_FRAME) as u64;
        sessions::send(
            &mut fixture.peer,
            &Shim::Output(seq, vec![b'q'; QUEUED_FRAME]),
        )
        .await
        .unwrap();
    }
    // sleep: nothing observable marks the relay queueing the last frame behind the held socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Type one key, confirm its PTY write as the shim, and wait for the relay's capture request.
/// By then the key's `InputAck` waits on the writer's priority lane.
async fn type_a_key(fixture: &mut Fixture) {
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

/// Return `bytes` of credit, as the client does for frames it painted.
fn return_credit(fixture: &mut Fixture, bytes: u64) {
    fixture
        .commands
        .as_mut()
        .unwrap()
        .try_send(Command::Credit(u32::try_from(bytes).unwrap()))
        .unwrap();
}

/// Wait until the relay closes the shim link (a starvation detach or a parked link).
async fn wait_for_link_close(fixture: &mut Fixture) {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(EVENT_GUARD, async {
        let mut bytes = [0_u8; 4096];
        while fixture.peer.read(&mut bytes).await.unwrap() != 0 {}
    })
    .await
    .expect("the relay did not detach its shim link");
}

/// Accept the relay's replacement shim link, answer its handshake, and return the cursor its
/// recovery replay asks for.
async fn recovery_cursor(fixture: &mut Fixture) -> u64 {
    let (mut peer, _) = tokio::time::timeout(EVENT_GUARD, fixture.listener.accept())
        .await
        .expect("returned credit did not reconnect the detached shim link")
        .unwrap();
    let mut reader = Reader::default();
    sessions::send(
        &mut peer,
        &Shim::Hello {
            version: 1,
            caps: infraternal_shim::frame::SEQUENCED_INPUT | infraternal_shim::frame::MULTI_WRITER,
            session: fixture.id,
            pid: std::process::id(),
            cols: 80,
            rows: 24,
            created: 0,
            head: WINDOW_END,
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
        Shim::SelectWriter(STREAM)
    );
    assert_eq!(
        read_shim(&mut reader, &mut peer).await,
        Shim::InputStateRequest
    );
    sessions::send(&mut peer, &Shim::InputState(1, 1))
        .await
        .unwrap();
    let Shim::ReadFrom(cursor) = read_shim(&mut reader, &mut peer).await else {
        panic!("the recovered link did not ask for a replay");
    };
    fixture.peer = peer;
    fixture.reader = reader;
    cursor
}

/// Close the client side and wait for both tasks, then remove the test's socket directory.
async fn stop(fixture: &mut Fixture) {
    fixture.commands.take();
    fixture.socket.open();
    if let Some(relay) = fixture.relay.take() {
        let _ = tokio::time::timeout(EVENT_GUARD, relay).await;
    }
    if let Some(writer) = fixture.writer.take() {
        writer.abort();
    }
    let _ = std::fs::remove_dir_all(&fixture.root);
}

/// Offer more new output from `head` than one bulk window, and count the raw bytes that reach
/// the wire before the relay stalls for credit.
async fn forwarded_before_stall(fixture: &mut Fixture, head: u64) -> u64 {
    let chunk = 64 * 1024;
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
    let wire = &mut fixture.wire;
    let count = async {
        let mut forwarded = 0_u64;
        while let Ok(Some(bytes)) = tokio::time::timeout(QUIET, wire.recv()).await {
            if let Seen::Output(_, length) = seen(&bytes) {
                forwarded += length as u64;
            }
        }
        forwarded
    };
    let ((), forwarded) = tokio::join!(flood, count);
    forwarded
}

/// The writer drops queued raw output that a key repaint covers, which the client therefore never
/// receives and never returns credit for. The relay must get that credit back, or the client's
/// window shrinks by up to a whole FIFO of frames for the rest of the attachment (#477, J799).
#[tokio::test]
async fn a_key_repaint_that_drops_queued_output_keeps_the_whole_bulk_window() {
    let fixture = start().await;
    a_committed_key_repaint_keeps_the_whole_bulk_window(fixture).await;
}

/// The same refund on a primed relay, whose ledger and refund cell have already been replaced
/// once by the server's opening cursor: the refund must reach the relay's current cell, not the
/// one it attached with (#477; kills J799's surviving mutant "a cursor rewind keeps the old
/// refund cell", J813).
#[cfg(feature = "remote")]
#[tokio::test]
async fn a_primed_relays_key_repaint_keeps_the_whole_bulk_window() {
    let fixture = start_primed().await;
    a_committed_key_repaint_keeps_the_whole_bulk_window(fixture).await;
}

/// Spend the window behind the held socket, commit a key repaint over the queued flood, and
/// check that the relay can then forward a full bulk window again.
///
/// The client returns exactly what reached it: the first frame and the repaint. Its whole bulk
/// window is then free again, which the relay only knows if the writer refunded the dropped
/// frames to the relay's current ledger.
async fn a_committed_key_repaint_keeps_the_whole_bulk_window(mut fixture: Fixture) {
    spend_the_window_behind_a_held_socket(&mut fixture).await;
    type_a_key(&mut fixture).await;
    let head = WINDOW_END;
    sessions::send(&mut fixture.peer, &Shim::Snapshot(head, SCREEN.to_vec()))
        .await
        .unwrap();
    // sleep: nothing observable marks the relay queueing the repaint on the priority lane.
    tokio::time::sleep(Duration::from_millis(100)).await;
    fixture.socket.open();
    let wire = drain(&mut fixture).await;
    assert_eq!(
        wire,
        vec![
            Seen::Output(0, FIRST_FRAME),
            Seen::Ack(1),
            Seen::Snapshot(head, SCREEN.len()),
        ],
        "the repaint replaces the queued flood"
    );
    return_credit(&mut fixture, FIRST_FRAME as u64 + SCREEN.len() as u64);

    let forwarded = forwarded_before_stall(&mut fixture, head).await;
    stop(&mut fixture).await;

    assert_eq!(
        forwarded,
        u64::from(BULK_CREDIT),
        "output the writer dropped under a key repaint must not leak its credit from the bulk window"
    );
}

/// After an older shim answers the key's capture request with "snapshot unavailable", the key
/// repaint is abandoned. The output its `InputAck` passed must still reach the client in order,
/// and the recovery replay must resume where the client's bytes end, not after a gap (#477, J799).
#[tokio::test]
async fn an_unavailable_key_repaint_delivers_the_output_its_ack_passed() {
    let mut fixture = start().await;
    spend_the_window_behind_a_held_socket(&mut fixture).await;
    type_a_key(&mut fixture).await;
    sessions::send(&mut fixture.peer, &Shim::Error(1, "no repaint".into()))
        .await
        .unwrap();
    // The relay's "snapshot unavailable" notice waits for room in the full FIFO.
    fixture.socket.open();
    wait_for_link_close(&mut fixture).await;
    let wire = drain(&mut fixture).await;
    let received = received_raw(&wire);
    return_credit(&mut fixture, received);
    let resumed = recovery_cursor(&mut fixture).await;
    stop(&mut fixture).await;

    assert_eq!(
        received, WINDOW_END,
        "every charged byte reaches the client: {wire:?}"
    );
    // The notice reports the relay's cursor, so the bytes it counts must arrive before it, not
    // only once the starvation timer releases them later.
    let notice = wire.iter().position(|frame| *frame == Seen::Event);
    let last_output = wire
        .iter()
        .rposition(|frame| matches!(frame, Seen::Output(..)));
    assert!(
        notice > last_output,
        "the snapshot-unavailable notice follows the output it counts: {wire:?}"
    );
    assert_eq!(
        resumed, received,
        "recovery resumes at the client's last received byte"
    );
}

/// The 250 ms starvation timer can fire while a key's repaint is still outstanding, which abandons
/// it. The output that key's `InputAck` passed must still reach the client, and the recovery
/// replay must resume where the client's bytes end (#477, J799).
#[tokio::test]
async fn a_key_repaint_abandoned_by_starvation_delivers_the_output_its_ack_passed() {
    let mut fixture = start().await;
    spend_the_window_behind_a_held_socket(&mut fixture).await;
    type_a_key(&mut fixture).await;
    // The shim never answers the capture request.
    wait_for_link_close(&mut fixture).await;
    fixture.socket.open();
    let wire = drain(&mut fixture).await;
    let received = received_raw(&wire);
    return_credit(&mut fixture, received);
    let resumed = recovery_cursor(&mut fixture).await;
    stop(&mut fixture).await;

    assert_eq!(
        received, WINDOW_END,
        "every charged byte reaches the client: {wire:?}"
    );
    assert_eq!(
        resumed, received,
        "recovery resumes at the client's last received byte"
    );
}

/// When the program exits while a key's repaint is outstanding, the output that key's `InputAck`
/// passed is the program's last output: it must reach the client, before the exit notice
/// (#477, J799).
#[tokio::test]
async fn an_exit_during_a_key_repaint_delivers_the_output_its_ack_passed() {
    let mut fixture = start().await;
    spend_the_window_behind_a_held_socket(&mut fixture).await;
    type_a_key(&mut fixture).await;
    sessions::send(&mut fixture.peer, &Shim::Exited(0, WINDOW_END))
        .await
        .unwrap();
    // sleep: nothing observable marks the relay queueing the exit notice behind the held socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
    fixture.socket.open();
    let wire = drain(&mut fixture).await;
    stop(&mut fixture).await;

    assert_eq!(
        received_raw(&wire),
        WINDOW_END,
        "every charged byte reaches the client: {wire:?}"
    );
    assert_eq!(
        wire.last(),
        Some(&Seen::Event),
        "the exit notice comes last"
    );
}

/// A shim that refuses the key's capture ends the stream with a Close. The output the key's
/// `InputAck` passed still reaches the client first (#477, J799).
#[tokio::test]
async fn a_refused_capture_during_a_key_repaint_delivers_the_output_its_ack_passed() {
    let mut fixture = start().await;
    spend_the_window_behind_a_held_socket(&mut fixture).await;
    type_a_key(&mut fixture).await;
    sessions::send(&mut fixture.peer, &Shim::Error(3, "refused".into()))
        .await
        .unwrap();
    // sleep: nothing observable marks the relay queueing its Close behind the held socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
    fixture.socket.open();
    let wire = drain(&mut fixture).await;
    stop(&mut fixture).await;

    assert_eq!(
        received_raw(&wire),
        WINDOW_END,
        "every charged byte reaches the client: {wire:?}"
    );
    assert_eq!(wire.last(), Some(&Seen::Other), "the Close comes last");
}

/// The shim link fails while a key's repaint is outstanding. The output the key's `InputAck`
/// passed still reaches the client (#477, J799).
#[tokio::test]
async fn a_failed_link_during_a_key_repaint_delivers_the_output_its_ack_passed() {
    use tokio::io::AsyncWriteExt;
    let mut fixture = start().await;
    spend_the_window_behind_a_held_socket(&mut fixture).await;
    type_a_key(&mut fixture).await;
    fixture.peer.shutdown().await.unwrap();
    // sleep: nothing observable marks the relay handling the failed link behind the held socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
    fixture.socket.open();
    let wire = drain(&mut fixture).await;
    stop(&mut fixture).await;

    assert_eq!(
        received_raw(&wire),
        WINDOW_END,
        "every charged byte reaches the client: {wire:?}"
    );
}

/// The relay can also end on an error of its own while a key's repaint is outstanding, here a
/// shim state reply that no route proof asked for. The output the key's `InputAck` passed was
/// charged and is good: it must still reach the client, ahead of the saved exit the relay then
/// reports for the session, as on every other way a pending repaint ends (#477, J813).
#[tokio::test]
async fn a_relay_error_during_a_key_repaint_delivers_the_output_its_ack_passed() {
    let mut fixture = start().await;
    spend_the_window_behind_a_held_socket(&mut fixture).await;
    type_a_key(&mut fixture).await;
    infraternal_shim::ended::record(&fixture.path, 0, WINDOW_END).unwrap();
    sessions::send(&mut fixture.peer, &Shim::InputState(1, 1))
        .await
        .unwrap();
    // sleep: nothing observable marks the relay failing behind the held socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
    fixture.socket.open();
    let wire = drain(&mut fixture).await;
    stop(&mut fixture).await;

    assert_eq!(
        received_raw(&wire),
        WINDOW_END,
        "every charged byte reaches the client: {wire:?}"
    );
    let exit = wire.iter().position(|frame| *frame == Seen::Event);
    let last_output = wire
        .iter()
        .rposition(|frame| matches!(frame, Seen::Output(..)));
    assert!(
        exit > last_output,
        "the saved exit follows the session's last output: {wire:?}"
    );
}

/// A cursor rewind resets the relay's ledger to the server's view, and the server's reissued
/// credit already counts every byte that never reached it. Raw output the old attachment queued
/// and the writer drops after the rewind must therefore not come back as a refund too, or the
/// relay could overrun the client's window by up to a whole FIFO of frames (#477, J813).
///
/// The key repaint here commits only once the rewind has reset the ledger: the writer is still
/// blocked on its first frame when the cursor command arrives, so it drops the eight queued
/// frames afterwards.
#[cfg(feature = "remote")]
#[tokio::test]
async fn a_cursor_rewind_takes_no_refund_for_output_queued_before_it() {
    let mut fixture = start_primed().await;
    spend_the_window_behind_a_held_socket(&mut fixture).await;
    type_a_key(&mut fixture).await;
    sessions::send(
        &mut fixture.peer,
        &Shim::Snapshot(WINDOW_END, SCREEN.to_vec()),
    )
    .await
    .unwrap();
    // sleep: nothing observable marks the relay queueing the repaint on the priority lane.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The client holds the first frame and the repaint, so the server rewinds to the repaint's
    // cursor and reissues the client's whole window. The relay's new `Attached` marker waits
    // behind the full FIFO until the socket opens.
    let socket = fixture.socket.clone();
    let rewound = async {
        rewind(&mut fixture, WINDOW_END).await;
        return_credit(&mut fixture, u64::from(BULK_CREDIT + REPAINT_CREDIT));
    };
    let open = async {
        // sleep: let the relay reset its ledger and block on the full FIFO first.
        tokio::time::sleep(Duration::from_millis(100)).await;
        socket.open();
    };
    tokio::join!(rewound, open);
    let wire = drain(&mut fixture).await;
    assert_eq!(
        wire,
        vec![
            Seen::Output(0, FIRST_FRAME),
            Seen::Ack(1),
            Seen::Snapshot(WINDOW_END, SCREEN.len()),
            Seen::Event,
        ],
        "the repaint replaces the queued flood, then the rewound replay completes"
    );

    let forwarded = forwarded_before_stall(&mut fixture, WINDOW_END).await;
    stop(&mut fixture).await;
    assert_eq!(
        forwarded,
        u64::from(BULK_CREDIT),
        "the reissued window alone funds output after a rewind"
    );
}
