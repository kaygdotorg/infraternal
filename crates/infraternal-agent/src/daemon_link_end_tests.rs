//! Raw output the relay staged for a full writer FIFO survives the end of its shim link [#477].
//!
//! A relay that finds the writer's FIFO full keeps one credit-charged Output in
//! `pending_bulk` (see `flush_staged`). When the shim then goes away, the relay
//! reports its saved exit record. Those bytes are the program's last output and
//! must reach the client before that exit notice (#477, J794's P3s, J799).

use super::key_repaint_tests::{EVENT_GUARD, shim_rendezvous};
use super::*;
use crate::sessions::Reader;
use infraternal_shim::frame::{MULTI_WRITER, SESSION_OWNER};
use std::{path::PathBuf, time::Duration};
use tokio::{io::AsyncReadExt, net::UnixStream, sync::mpsc, task::JoinHandle};

/// The relay's stream id.
const STREAM: u32 = 2;
/// A deliberately small writer FIFO, so a few frames fill it.
const FIFO_SLOTS: usize = 4;
/// Each frame that fills the FIFO.
const FRAME: usize = 200_000;
/// The opening grant of a client with a repaint reserve: a 1 MiB bulk window plus 64 KiB.
const OPENING_CREDIT: u32 = 1024 * 1024 + 64 * 1024;
/// Where the staged frame starts, after the frames in the FIFO.
const STAGED_SEQ: u64 = (FIFO_SLOTS * FRAME) as u64;

/// A relay connected to a fake shim that supports session ownership, as real shims do.
struct OwnedShim {
    /// The test's private state root, removed by [`stop`].
    root: PathBuf,
    /// The session's rendezvous socket, beside which an exit record is saved.
    path: PathBuf,
    /// The fake shim's data link; dropping it fails the relay's link.
    data: Option<UnixStream>,
    /// The fake shim's ownership link; dropping it is ownership EOF.
    owner: Option<UnixStream>,
    /// The client's commands to the relay.
    commands: session_commands::Sender,
    /// The relay's writer FIFO, which only [`drain`] reads.
    messages: mpsc::Receiver<Message>,
    /// The relay task.
    relay: JoinHandle<io::Result<()>>,
}

/// Start a relay with a [`FIFO_SLOTS`]-deep writer FIFO that nobody drains, and answer its data
/// and ownership handshakes as a fresh shim. The relay's three opening messages are read.
async fn start() -> OwnedShim {
    let id = *uuid::Uuid::new_v4().as_bytes();
    let (root, path) = shim_rendezvous(id);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (commands, receiver) = session_commands::channel();
    let (tx, mut messages) = mpsc::channel(FIFO_SLOTS);
    let relay = tokio::spawn(terminal(path.clone(), id, STREAM, 0, 0, receiver, tx));
    let hello = Shim::Hello {
        version: 1,
        caps: SEQUENCED_INPUT | MULTI_WRITER | SESSION_OWNER,
        session: id,
        pid: std::process::id(),
        cols: 80,
        rows: 24,
        created: 0,
        head: 0,
        start: 0,
    };
    let accept = async { tokio::time::timeout(EVENT_GUARD, listener.accept()).await };
    let (mut data, _) = accept.await.expect("no data link").unwrap();
    sessions::send(&mut data, &hello).await.unwrap();
    let mut reader = Reader::default();
    assert!(matches!(
        reader.read(&mut data).await.unwrap(),
        Shim::Attach(_)
    ));
    assert_eq!(
        reader.read(&mut data).await.unwrap(),
        Shim::SelectWriter(STREAM)
    );
    let (mut owner, _) = tokio::time::timeout(EVENT_GUARD, listener.accept())
        .await
        .expect("no ownership link")
        .unwrap();
    sessions::send(&mut owner, &hello).await.unwrap();
    let mut control = Reader::default();
    assert_eq!(
        control.read(&mut owner).await.unwrap(),
        Shim::Attach(SESSION_OWNER)
    );
    assert_eq!(
        control.read(&mut owner).await.unwrap(),
        Shim::InputStateRequest
    );
    sessions::send(&mut owner, &Shim::InputState(0, 0))
        .await
        .unwrap();
    assert_eq!(
        reader.read(&mut data).await.unwrap(),
        Shim::InputStateRequest
    );
    sessions::send(&mut data, &Shim::InputState(0, 0))
        .await
        .unwrap();
    assert_eq!(reader.read(&mut data).await.unwrap(), Shim::ReadFrom(0));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Attached(STREAM, ..))
    ));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Shim(STREAM, Shim::InputAck(0)))
    ));
    assert!(matches!(
        messages.recv().await,
        Some(Message::Event(STREAM, _))
    ));
    OwnedShim {
        root,
        path,
        data: Some(data),
        owner: Some(owner),
        commands,
        messages,
        relay,
    }
}

/// Fund the opening window, fill the FIFO, and send one more frame of `last` bytes, which the
/// relay stages (whole, or only its affordable part when `last` overspends the window).
async fn stage_a_frame(shim: &mut OwnedShim, last: usize) {
    shim.commands
        .try_send(Command::Credit(OPENING_CREDIT))
        .unwrap();
    let data = shim.data.as_mut().unwrap();
    for frame in 0..FIFO_SLOTS {
        sessions::send(
            data,
            &Shim::Output((frame * FRAME) as u64, vec![b'f'; FRAME]),
        )
        .await
        .unwrap();
    }
    sessions::send(data, &Shim::Output(STAGED_SEQ, vec![b's'; last]))
        .await
        .unwrap();
    // sleep: nothing observable marks the relay staging the last frame behind the full FIFO.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// What the client side receives once it drains the FIFO: each raw Output as `(seq, length)`,
/// and then the names of the other messages, in order.
async fn drain(shim: &mut OwnedShim) -> (Vec<(u64, usize)>, Vec<&'static str>) {
    let mut outputs = vec![];
    let mut others = vec![];
    while let Ok(Some(message)) =
        tokio::time::timeout(Duration::from_millis(400), shim.messages.recv()).await
    {
        match message {
            Message::Shim(STREAM, Shim::Output(seq, bytes)) => {
                assert!(others.is_empty(), "raw output after {others:?}");
                outputs.push((seq, bytes.len()));
            }
            Message::Event(STREAM, _) => others.push("event"),
            Message::Ended(STREAM) => others.push("ended"),
            _ => others.push("other"),
        }
    }
    (outputs, others)
}

/// Let the relay react to the shim going away while its FIFO is still full.
///
/// Draining first would free a slot, and the relay could then send its staged frame through the
/// ordinary path before it noticed the shim was gone, so the test would not reach the path it
/// is about.
async fn let_the_relay_see_it() {
    // sleep: nothing observable marks the relay handling the closed socket while it waits.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Every FIFO frame, then the staged frame of `staged` bytes.
fn all_frames(staged: usize) -> Vec<(u64, usize)> {
    let mut frames: Vec<(u64, usize)> = (0..FIFO_SLOTS)
        .map(|frame| ((frame * FRAME) as u64, FRAME))
        .collect();
    frames.push((STAGED_SEQ, staged));
    frames
}

/// Stop the relay and remove the test's socket directory.
async fn stop(shim: OwnedShim) {
    drop(shim.commands);
    let _ = tokio::time::timeout(EVENT_GUARD, shim.relay).await;
    let _ = std::fs::remove_dir_all(&shim.root);
}

/// The shim retires after the relay parked its link for credit: ownership EOF, with a saved exit
/// record. The staged frame still reaches the client, before the exit notice (#477, J794).
#[tokio::test]
async fn ownership_eof_on_a_parked_link_delivers_the_staged_frame_first() {
    let mut shim = start().await;
    // Overspend the window: the relay stages the affordable part and starves on the rest.
    stage_a_frame(&mut shim, 300_000).await;
    // The 250 ms starvation timer parks the link.
    let mut data = shim.data.take().unwrap();
    tokio::time::timeout(EVENT_GUARD, async {
        let mut bytes = [0_u8; 4096];
        while data.read(&mut bytes).await.unwrap() != 0 {}
    })
    .await
    .expect("the starved relay did not park its shim link");
    infraternal_shim::ended::record(&shim.path, 0, STAGED_SEQ + 300_000).unwrap();
    drop(shim.owner.take());
    let_the_relay_see_it().await;
    let (outputs, others) = drain(&mut shim).await;
    stop(shim).await;

    let affordable = OPENING_CREDIT as usize - 64 * 1024 - FIFO_SLOTS * FRAME;
    assert_eq!(
        outputs,
        all_frames(affordable),
        "the staged bytes reach the client"
    );
    assert_eq!(others, vec!["event", "ended"]);
}

/// The shim's data link fails while a frame is staged, and the shim left a saved exit record.
/// The staged frame still reaches the client, before the exit notice (#477, J794).
#[tokio::test]
async fn a_failed_shim_link_delivers_the_staged_frame_first() {
    let mut shim = start().await;
    // The whole last frame is affordable, so nothing waits for credit and the relay keeps
    // reading its link.
    stage_a_frame(&mut shim, FRAME).await;
    infraternal_shim::ended::record(&shim.path, 0, STAGED_SEQ + FRAME as u64).unwrap();
    drop(shim.data.take());
    let_the_relay_see_it().await;
    let (outputs, others) = drain(&mut shim).await;
    drop(shim.owner.take());
    stop(shim).await;

    assert_eq!(
        outputs,
        all_frames(FRAME),
        "the staged bytes reach the client"
    );
    assert_eq!(others, vec!["event", "ended"]);
}
