//! Inherited leg-B dispatcher and bounded session registry for the tracer bullet [9][13][41].
//!
//! Each terminal owns one pending output frame. Commands have eight slots;
//! a full queue pauses leg-B reads until capacity returns. The writer has eight slots
//! and awaits capacity, applying transport backpressure. Starved sessions close
//! their shim socket after 250 ms, then reconnect for a fresh credit-funded
//! ring replay or a flagged bounded repaint. Unviewed sessions stay disconnected so their PTYs keep progressing.
//! A closed shim or failed terminal task closes only its mux stream.
use crate::{
    relay,
    sessions::{self, Manager, Reader, Session},
    transport::{Receive, Socket, Transmit},
};
use infraternal_protocol::Frame;
use infraternal_shim::frame::{APPROXIMATE_SNAPSHOT, Frame as Shim, SEQUENCED_INPUT};
use serde::Deserialize;
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

/// Process-wide count of approximate repaints written to the leg-B socket.
/// Constant-space and content-free; metrics adapters can export this value.
static APPROXIMATE_SNAPSHOTS: AtomicU64 = AtomicU64::new(0);

/// Monotonic approximation counter for the infraternal agent metrics adapter.
#[must_use]
pub fn approximate_snapshots_total() -> u64 {
    APPROXIMATE_SNAPSHOTS.load(Ordering::Relaxed)
}
use tokio::io::AsyncWriteExt;
use tokio::{sync::mpsc, task::JoinSet};

enum Command {
    Input(u64, Vec<u8>),
    Credit(u32),
    Resize(u16, u16, u16, u16),
}
enum Message {
    Shim(u32, Shim),
    Result(u32, u32, bool, Vec<u8>),
    Event(u32, Vec<u8>),
    Pong(u64, u64),
    Close(u32, &'static str),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    uid: u32,
    cols: u16,
    rows: u16,
}

async fn writer(socket: &Socket, mut messages: mpsc::Receiver<Message>) -> io::Result<()> {
    let mut tx = Transmit::default();
    tx.send(
        socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "infraternal agent",
        },
    )
    .await?;
    while let Some(message) = messages.recv().await {
        match message {
            Message::Shim(stream, frame) => {
                let wire = match &frame {
                    Shim::Output(seq, bytes) => Frame::Output {
                        out_seq: *seq,
                        bytes,
                    },
                    Shim::Snapshot(seq, bytes) | Shim::SnapshotWithFlags(seq, _, bytes) => {
                        Frame::Snapshot {
                            out_seq: *seq,
                            bytes,
                        }
                    }
                    Shim::InputAck(seq) => Frame::Ack { in_seq_acked: *seq },
                    _ => return Err(sessions::invalid("invalid relay message")),
                };
                tx.send(socket, stream, &wire).await?;
                if matches!(frame, Shim::SnapshotWithFlags(_, flags, _) if flags & 1 != 0) {
                    APPROXIMATE_SNAPSHOTS.fetch_add(1, Ordering::Relaxed);
                }
            }
            Message::Result(stream, call_id, ok, json) => {
                tx.send(
                    socket,
                    stream,
                    &Frame::Result {
                        call_id,
                        ok,
                        json: &json,
                    },
                )
                .await?;
            }
            Message::Event(stream, json) => {
                tx.send(
                    socket,
                    stream,
                    &Frame::Event {
                        sub_id: 0,
                        event_json: &json,
                    },
                )
                .await?;
            }
            Message::Pong(nonce, sent_us) => {
                tx.send(socket, 0, &Frame::Pong { nonce, sent_us }).await?;
            }
            Message::Close(stream, reason) => {
                tx.send(socket, stream, &Frame::Close { code: 1, reason })
                    .await?;
            }
        }
    }
    Ok(())
}
async fn emit(tx: &mpsc::Sender<Message>, message: Message) -> io::Result<()> {
    tx.send(message)
        .await
        .map_err(|_| io::ErrorKind::BrokenPipe.into())
}

/// Run until the trusted server closes its inherited channel.
/// # Errors
/// Rejects invalid fd, unsafe state, malformed wire requests and resource limits.
#[allow(clippy::too_many_lines)]
pub async fn run(fd: i32, state: Option<PathBuf>) -> io::Result<()> {
    // The launch isolation wrapper closes fd 3 before exec. Other inherited
    // descriptors need their own audited CLOEXEC boundary before being supported.
    if fd != 3 {
        return Err(sessions::invalid("embedded leg B requires fd 3"));
    }
    let state = sessions::state(state)?;
    let socket = Socket::inherited(fd)?;
    let manager = Manager::detect().await;
    let exe = std::env::current_exe()?;
    let mut registry = HashMap::new();
    for session in sessions::discover(&state).await? {
        registry.insert(session.id, session.path.clone());
        // Startup discovery authenticates identity, but does not stall unviewed PTYs.
        drop(session);
    }
    let (tx, rx) = mpsc::channel(8);
    let dispatch = async {
        let mut receive = Receive::default();
        let mut streams: HashMap<u32, ([u8; 16], mpsc::Sender<Command>)> = HashMap::new();
        let mut jobs: JoinSet<(u32, io::Result<()>)> = JoinSet::new();
        let mut opens: JoinSet<(u32, u32, io::Result<Session>)> = JoinSet::new();
        loop {
            tokio::select! {
                result = jobs.join_next(), if !jobs.is_empty() => {
                    let (stream, result) = result.ok_or_else(|| sessions::invalid("missing relay task"))?.map_err(io::Error::other)?;
                    // Close/re-attach may reuse a stream before the old task exits.
                    // Its completion must not remove the replacement's live sender.
                    if streams.get(&stream).is_some_and(|(_, sender)| sender.is_closed()) {
                        streams.remove(&stream);
                        if result.is_err() {
                            emit(&tx, Message::Close(stream, "terminal shim disconnected")).await?;
                        }
                    }
                }
                result = opens.join_next(), if !opens.is_empty() => {
                    let (stream, call_id, result) = result.ok_or_else(|| sessions::invalid("missing launch task"))?.map_err(io::Error::other)?;
                    match result {
                        Ok(session) => {
                            let json = serde_json::to_vec(&serde_json::json!({"session_id": uuid::Uuid::from_bytes(session.id)}))?;
                            registry.insert(session.id, session.path.clone());
                            emit(&tx, Message::Result(stream, call_id, true, json)).await?;
                        }
                        Err(_) => emit(&tx, Message::Result(stream, call_id, false, b"{\"error\":\"terminal open refused\"}".to_vec())).await?,
                    }
                }
                decoded = receive.next(&socket) => {
                    let decoded = decoded?;
                    let stream = decoded.stream_id;
                    match decoded.frame {
                        Frame::Hello {version: 1, ..} if stream == 0 => {}
                        Frame::Ping {nonce, sent_us} if stream == 0 => emit(&tx, Message::Pong(nonce, sent_us)).await?,
                        Frame::Call {call_id, action_id: "terminal.open", input_json} => {
                            let input = serde_json::from_slice::<Open>(input_json);
                            if let Ok(input) = input && registry.len() + opens.len() < sessions::MAX_SESSIONS {
                                let exe = exe.clone(); let state = state.clone();
                                opens.spawn(async move { (stream, call_id, sessions::launch(&exe, &state, manager, input.uid, input.cols, input.rows).await) });
                            } else {
                                emit(&tx, Message::Result(stream, call_id, false, b"{\"error\":\"invalid terminal open or session limit\"}".to_vec())).await?;
                            }
                        }
                        Frame::AttachTerm {session_id, last_out_seq, last_in_seq} if stream != 0 => {
                            if streams.len() >= sessions::MAX_SESSIONS || streams.contains_key(&stream) || streams.values().any(|(id, _)| id == session_id) {
                                return Err(sessions::invalid("terminal stream already attached or limit reached"));
                            }
                            let path = registry.get(session_id).ok_or_else(|| sessions::invalid("unknown terminal session"))?.clone();
                            let id = *session_id;
                            let (commands, rx) = mpsc::channel(8);
                            streams.insert(stream, (id, commands));
                            let tx = tx.clone();
                            jobs.spawn(async move {
                                (stream, terminal(path, id, stream, last_out_seq, last_in_seq, rx, tx).await)
                            });
                        }
                        frame => {
                            let command = match frame {
                                Frame::Input {in_seq, bytes} => Command::Input(in_seq, bytes.to_vec()),
                                Frame::Credit {bytes} => Command::Credit(bytes),
                                Frame::Resize {cols, rows, px_w, px_h} => Command::Resize(cols, rows, px_w, px_h),
                                Frame::Close {..} => { streams.remove(&stream); continue; }
                                _ => return Err(sessions::invalid("unexpected leg-B request")),
                            };
                            // Await capacity without reading another leg-B frame: at
                            // most eight queued commands plus this bounded frame.
                            // The writer runs independently, so draining output
                            // remains possible while the source is backpressured.
                            if let Some((_, sender)) = streams.get(&stream) {
                                // A closed receiver is retired when its task
                                // joins, emitting Close once for an IO failure.
                                let _ = sender.send(command).await;
                            }
                            // Frames already in flight after a stream closes are
                            // ignored; the terminal task emits its own Close.
                        }
                    }
                }
            }
        }
    };
    tokio::select! { result = dispatch => result, result = writer(&socket, rx) => result }
}

/// One shim connection reuses transmit and cancellation-safe receive storage.
struct Link {
    session: Session,
    transmit: Vec<u8>,
    reader: Reader,
}
impl Link {
    async fn connect(path: PathBuf, id: [u8; 16]) -> io::Result<Self> {
        Ok(Self {
            session: sessions::connect_sequenced(path, id).await?,
            transmit: Vec::new(),
            reader: Reader::default(),
        })
    }
    async fn send(&mut self, frame: &Shim) -> io::Result<()> {
        frame.encode_into(&mut self.transmit)?;
        self.session.peer.write_all(&self.transmit).await
    }
    async fn read(&mut self) -> io::Result<Shim> {
        let frame = self.reader.read(&mut self.session.peer).await?;
        if matches!(frame, Shim::SnapshotWithFlags(..))
            && self.session.caps & APPROXIMATE_SNAPSHOT == 0
        {
            return Err(sessions::invalid("unnegotiated approximate Snapshot"));
        }
        Ok(frame)
    }
}
async fn input_state(link: &mut Link) -> io::Result<u64> {
    if link.session.caps & SEQUENCED_INPUT == 0 {
        return Err(sessions::invalid(
            "shim lacks restart-safe input capability",
        ));
    }
    // Retained accepted input can advance after capability selection and before
    // StateRequest reaches the shim. Acks may legally precede the State reply.
    // Bound the whole exchange, rather than resetting the deadline for each Ack.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        link.send(&Shim::InputStateRequest).await?;
        let mut acked = 0;
        loop {
            match link.read().await? {
                Shim::InputAck(seq) if seq >= acked => acked = seq,
                Shim::InputState(written, accepted) if acked <= written && written <= accepted => {
                    return Ok(written);
                }
                _ => return Err(sessions::invalid("invalid shim input state")),
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shim input state timed out"))?
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn terminal(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    mut commands: mpsc::Receiver<Command>,
    tx: mpsc::Sender<Message>,
) -> io::Result<()> {
    let mut session = Some(Link::connect(path.clone(), id).await?);
    if session
        .as_ref()
        .is_none_or(|s| s.session.caps & SEQUENCED_INPUT == 0)
    {
        emit(
            &tx,
            Message::Close(stream, "shim lacks restart-safe input capability"),
        )
        .await?;
        return Ok(());
    }
    let written = input_state(
        session
            .as_mut()
            .ok_or_else(|| sessions::invalid("missing shim"))?,
    )
    .await?;
    if last_input > written {
        return Err(sessions::invalid(
            "client input cursor exceeds shim write cursor",
        ));
    }
    emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
    session
        .as_mut()
        .ok_or_else(|| sessions::invalid("missing shim"))?
        .send(&Shim::ReadFrom(cursor))
        .await?;
    let mut output = relay::Output::attach(cursor);
    let mut pending: Option<Shim> = None;
    let mut deadline = None;
    loop {
        if let Some(frame) = pending.take() {
            match frame {
                Shim::Output(seq, bytes) => {
                    let range = output
                        .suffix(seq, bytes.len())
                        .map_err(|_| sessions::invalid("output gap"))?;
                    let length = range.len();
                    if length > 0 {
                        emit(
                            &tx,
                            Message::Shim(
                                stream,
                                Shim::Output(output.cursor(), bytes[range.clone()].to_vec()),
                            ),
                        )
                        .await?;
                        output
                            .forward(length)
                            .map_err(|_| sessions::invalid("output credit invariant"))?;
                    }
                    if range.end < bytes.len() {
                        pending = Some(Shim::Output(seq, bytes));
                        deadline = output
                            .pending(Instant::now())
                            .map(tokio::time::Instant::from_std);
                    }
                }
                frame @ (Shim::Snapshot(..) | Shim::SnapshotWithFlags(..)) => {
                    let (seq, length, approximate) = match &frame {
                        Shim::Snapshot(seq, bytes) => (*seq, bytes.len(), false),
                        Shim::SnapshotWithFlags(seq, flags, bytes) => {
                            (*seq, bytes.len(), flags & 1 != 0)
                        }
                        _ => return Err(sessions::invalid("invalid Snapshot variant")),
                    };
                    if seq < output.cursor() {
                        return Err(sessions::invalid("snapshot cursor regressed"));
                    }
                    if output.repaint(seq, length).is_ok() {
                        deadline = None;
                        if approximate {
                            let json = serde_json::to_vec(
                                &serde_json::json!({"type":"terminal.snapshot", "session_id":uuid::Uuid::from_bytes(id), "seq":seq, "approximate":true}),
                            )?;
                            emit(&tx, Message::Event(stream, json)).await?;
                        }
                        emit(&tx, Message::Shim(stream, frame)).await?;
                    } else {
                        pending = Some(frame);
                        // A repaint is indivisible. Positive credit below its
                        // cost needs the same bounded pause as zero-credit raw
                        // output; expiry preserves the client cursor and parks
                        // serialization until the remembered cost is affordable.
                        deadline = output
                            .pending(Instant::now())
                            .map(tokio::time::Instant::from_std);
                    }
                }
                _ => return Err(sessions::invalid("invalid pending frame")),
            }
        }
        if output.needs_snapshot() && session.is_none() {
            let mut next = Link::connect(path.clone(), id).await?;
            let written = input_state(&mut next).await?;
            emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
            // A credit deadline discards only the daemon's pending frame,
            // never the client's offset. Let the shim select retained replay
            // first, then faithful or negotiated approximate repaint on a gap.
            next.send(&Shim::ReadFrom(output.cursor())).await?;
            output.resume_replay();
            session = Some(next);
        }
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { return Ok(()); };
                match command {
                    Command::Credit(bytes) => { output.grant(bytes).map_err(|_| sessions::invalid("credit overflow"))?; if session.is_none() && bytes > 0 { output.retry_recovery(); } deadline = None; }
                    other => {
                        let detached = session.is_none();
                        if detached {
                            let mut next = Link::connect(path.clone(), id).await?;
                                            input_state(&mut next).await?;
                            session = Some(next);
                        }
                        let peer = session.as_mut().ok_or_else(|| sessions::invalid("missing shim"))?;
                        match other {
                            Command::Input(seq, bytes) => peer.send(&Shim::SequencedInput(seq, bytes)).await?,
                            Command::Resize(cols, rows, px_w, px_h) => peer.send(&Shim::Resize {cols, rows, px_w, px_h}).await?,
                            Command::Credit(_) => return Err(sessions::invalid("unexpected credit dispatch")),
                        }
                        if detached {
                            // The shim has one peer. Reconnecting can replace
                            // this socket before it reads an already-written
                            // command. An ordered State reply proves input was
                            // accepted (or resize handled) before peer loss;
                            // accepted input survives until the PTY writes it.
                            let written = input_state(peer).await?;
                            emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
                            session = None;
                            output.retry_recovery();
                        }
                    }
                }
            }
            () = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; } else { std::future::pending::<()>().await; } } => {
                output.expire(Instant::now()); session = None; pending = None; deadline = None;
            }
            frame = async {
                if let Some(session) = &mut session { session.read().await }
                else { std::future::pending().await }
            }, if pending.is_none() => {
                match frame? {
                    frame @ (Shim::Output(..) | Shim::Snapshot(..) | Shim::SnapshotWithFlags(..)) => pending = Some(frame),
                    Shim::InputAck(seq) => emit(&tx, Message::Shim(stream, Shim::InputAck(seq))).await?,
                    Shim::Exited(status, final_seq) => {
                        let json = serde_json::to_vec(&serde_json::json!({"type":"terminal.exited", "session_id":uuid::Uuid::from_bytes(id), "status":status, "final_seq":final_seq}))?;
                        // Keep shim exit until a future explicit lifecycle policy acknowledges it.
                        emit(&tx, Message::Event(stream, json)).await?;
                    }
                    Shim::Error(1 | 2, _) => {
                        // Older shims cannot negotiate approximation. Park
                        // until credit/input/resize triggers recovery: keep the
                        // live mux stream, but neither busy-loop nor block PTY.
                        let json = serde_json::to_vec(&serde_json::json!({"type":"terminal.snapshot_unavailable", "session_id":uuid::Uuid::from_bytes(id), "seq":output.cursor()}))?;
                        emit(&tx, Message::Event(stream, json)).await?;
                        session = None;
                    }
                    Shim::Error(..) => { emit(&tx, Message::Close(stream, "shim refused terminal request")).await?; return Ok(()); }
                    _ => return Err(sessions::invalid("unexpected shim relay frame")),
                }
            }
        }
    }
}
