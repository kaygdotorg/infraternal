//! Shared inherited and authenticated remote leg-B dispatcher and bounded session registry for the tracer bullet [9][13][41].
//!
//! Each terminal owns one pending output frame. Input/Resize commands have eight slots;
//! shared-stream Credit is accumulated in constant space without occupying that FIFO;
//! a full queue retires only that stream, cancelling its shim link. Unacknowledged
//! input is replayed on attachment using shim-owned per-writer cursors. Bulk output has eight slots
//! and awaits capacity. Control replies use a separate eight-slot lane, selected
//! first at frame boundaries; reply overload retires the channel without stalling dispatch. Starved sessions close
//! their shim socket after 250 ms, then reconnect for a fresh credit-funded
//! ring replay or a flagged bounded repaint. Unviewed sessions stay disconnected so their PTYs keep progressing.
//! A closed shim or failed terminal task closes only its mux stream. A session
//! whose shim is gone answers its stream with the final Close 4404 (#158).
use crate::{
    channel::Channel,
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
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

#[path = "session_commands.rs"]
mod session_commands;

enum Command {
    Input(u64, Vec<u8>),
    Credit(u32),
    Resize(u16, u16, u16, u16),
}
// Dropping cancellation retires a stalled handshake as well as queued commands.
struct Stream {
    commands: session_commands::Sender,
    _cancel: oneshot::Sender<()>,
}

#[cfg(feature = "remote")]
use crate::remote_renewal::RenewalIdentity;
// The private local-only dispatcher always supplies None in core builds.
#[cfg(not(feature = "remote"))]
type RenewalIdentity = ();
enum Message {
    Shim(u32, Shim),
    Result(u32, u32, bool, Vec<u8>),
    Deferred(u32, u32, infraternal_plugin_api::ActionReply),
    Event(u32, Vec<u8>),
    Pong(u64, u64),
    Close(u32, &'static str),
    /// The session's shim is gone: a final stream close, never retried (wire §4).
    Ended(u32),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    uid: u32,
    cols: u16,
    rows: u16,
}

// A failed or cancelled write drops the continuation without starting its effect.
async fn deferred_reply(
    tx: &mut Transmit,
    socket: &impl Channel,
    stream: u32,
    call_id: u32,
    reply: infraternal_plugin_api::ActionReply,
) -> io::Result<()> {
    tx.send(
        socket,
        stream,
        &Frame::Result {
            call_id,
            ok: true,
            json: &reply.json,
        },
    )
    .await?;
    if let Some(after_write) = reply.after_write {
        after_write();
    }
    Ok(())
}

async fn writer(
    socket: &impl Channel,
    mut messages: mpsc::Receiver<Message>,
    mut control: Option<mpsc::Receiver<Message>>,
    greeting: bool,
    renewal: bool,
) -> io::Result<()> {
    let mut tx = Transmit::default();
    if greeting {
        tx.send(
            socket,
            0,
            &Frame::Hello {
                version: 1,
                caps: (if socket.native_stream_id().is_some() {
                    infraternal_plugin_api::channel::REMOTE_WRITER_BINDING
                } else {
                    0
                }) | (if renewal {
                    infraternal_plugin_api::channel::LIVE_RENEWAL
                } else {
                    0
                }),
                client_info: "infraternal agent",
            },
        )
        .await?;
    }
    // Only dispatch owns the control sender. Its closure ends this channel;
    // bulk events retain their FIFO order, including notice before Snapshot.
    while let Some(message) = tokio::select! {
        biased;
        message = async {
            match control.as_mut() {
                Some(receiver) => receiver.recv().await,
                None => std::future::pending().await,
            }
        } => message,
        message = messages.recv() => message,
    } {
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
            Message::Deferred(stream, call_id, reply) => {
                deferred_reply(&mut tx, socket, stream, call_id, reply).await?;
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
            Message::Ended(stream) => {
                let frame = Frame::Close {
                    code: infraternal_protocol::CLOSE_SESSION_GONE,
                    reason: infraternal_protocol::SESSION_GONE_REASON,
                };
                tx.send(socket, stream, &frame).await?;
            }
        }
    }
    Ok(())
}
// Shared dispatch must never await the capacity consumed by a stalled writer.
// Unacknowledged input remains with the shim and can be replayed on reconnect.
fn reply(tx: &mpsc::Sender<Message>, message: Message) -> io::Result<()> {
    tx.try_send(message).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => {
            io::Error::new(io::ErrorKind::WouldBlock, "control reply queue full")
        }
        mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe.into(),
    })
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
    let socket = Socket::inherited(fd)?;
    run_channel(&socket, state, None, None, None).await
}

/// Dispatch an admitted remote server connection through the same session and shim path.
/// The dialer must authenticate the server and supply the locally enrolled uid;
/// neither browser JSON nor an untrusted peer can select that identity. Returning
/// drops every attachment and launch task, but never terminates surviving shims.
/// # Errors
/// Refuses invalid greeting, unsafe state, wrong uid and malformed terminal frames.
#[cfg(feature = "remote")]
pub async fn run_authenticated(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
) -> io::Result<()> {
    run_authenticated_with_renewal(channel, state, execution_uid, None).await
}

/// Dispatch remote terminal and bounded certificate control actions on one authenticated channel.
/// # Errors
/// Refuses uid, greeting, state, framing or publication failure.
#[cfg(feature = "remote")]
pub async fn run_authenticated_with_renewal(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
    renewal: Option<&RenewalIdentity>,
) -> io::Result<()> {
    run_authenticated_with_installation(channel, state, execution_uid, renewal, None).await
}

/// Supply only checked local installation coordinates, never fields from a channel request.
/// # Errors
/// Refuses the same authenticated dispatch and installation bounds.
#[cfg(feature = "remote")]
pub async fn run_authenticated_with_installation(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
    renewal: Option<&RenewalIdentity>,
    installation: Option<&infraternal_plugin_remote::uninstall::Context>,
) -> io::Result<()> {
    if channel.native_stream_id().is_some_and(|writer| writer != 0)
        || execution_uid != nix::unistd::Uid::effective().as_raw()
    {
        return Err(sessions::invalid(
            "enrolled uid differs from infraternal agent uid",
        ));
    }
    // Cancellation retires the authenticated channel as well as its task set;
    // a caller cannot reuse it with detached readers or unfinished wire writes.
    let _retire = RetireChannel(channel);
    run_channel(channel, state, Some(execution_uid), renewal, installation).await
}

#[cfg(feature = "remote")]
struct RetireChannel<'a, C: Channel>(&'a C);
#[cfg(feature = "remote")]
impl<C: Channel> Drop for RetireChannel<'_, C> {
    fn drop(&mut self) {
        self.0.retire();
    }
}

#[allow(clippy::too_many_lines)]
async fn run_channel(
    socket: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: Option<u32>,
    renewal: Option<&RenewalIdentity>,
    installation: Option<&crate::plugins::Installation>,
) -> io::Result<()> {
    let state = sessions::state(state)?;
    let mode = if execution_uid.is_some() {
        crate::plugins::ExecutionMode::Remote
    } else {
        crate::plugins::ExecutionMode::Embedded
    };
    let mut plugins = crate::plugins::registry_with_installation(mode, installation)
        .map_err(|_| sessions::invalid("invalid compiled plugin registry"))?;
    let manager = Manager::detect().await;
    let exe = std::env::current_exe()?;
    let mut registry = HashMap::new();
    for session in sessions::discover(&state).await? {
        registry.insert(session.id, session.path.clone());
        // Startup discovery authenticates identity, but does not stall unviewed PTYs.
        drop(session);
    }
    let (tx, rx) = mpsc::channel(8);
    let (control, control_rx) = mpsc::channel(8);
    let dispatch = async {
        let mut receive = Receive::default();
        if execution_uid.is_some() {
            // The whole greeting has one deadline, including an entirely silent
            // authenticated peer. Established idle channels have no timer.
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let hello = receive.next(socket).await?;
                if hello.stream_id != 0 || !matches!(hello.frame, Frame::Hello { version: 1, caps, .. } if socket.native_stream_id().is_none() || caps & infraternal_plugin_api::channel::REMOTE_WRITER_BINDING != 0) {
                    return Err(sessions::invalid("remote control Hello required"));
                }
                Ok(())
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        }
        let mut streams: HashMap<u32, Stream> = HashMap::new();
        let mut jobs: JoinSet<(u32, io::Result<()>)> = JoinSet::new();
        let mut renewals = JoinSet::new();
        let mut opens: JoinSet<(u32, u32, io::Result<Session>)> = JoinSet::new();
        loop {
            tokio::select! {
                result = jobs.join_next(), if !jobs.is_empty() => {
                    let (stream, result) = result.ok_or_else(|| sessions::invalid("missing relay task"))?.map_err(io::Error::other)?;
                    // Close/re-attach may reuse a stream before the old task exits.
                    // Its completion must not remove the replacement's live sender.
                    if streams.get(&stream).is_some_and(|entry| entry.commands.is_closed()) {
                        streams.remove(&stream);
                        if result.is_err() {
                            reply(&control, Message::Close(stream, "terminal shim disconnected"))?;
                        }
                    }
                }
                result = renewals.join_next(), if !renewals.is_empty() => {
                    let (call_id, result): (u32, io::Result<Vec<u8>>) = result.ok_or_else(|| sessions::invalid("missing renewal task"))?.map_err(io::Error::other)?;
                    let (ok, json) = match result { Ok(json) => (true, json), Err(_) => (false, b"{}".to_vec()) };
                    reply(&control, Message::Result(0, call_id, ok, json))?;
                }
                result = opens.join_next(), if !opens.is_empty() => {
                    let (stream, call_id, result) = result.ok_or_else(|| sessions::invalid("missing launch task"))?.map_err(io::Error::other)?;
                    match result {
                        Ok(session) => {
                            let json = serde_json::to_vec(&serde_json::json!({"session_id": uuid::Uuid::from_bytes(session.id)}))?;
                            registry.insert(session.id, session.path.clone());
                            reply(&control, Message::Result(stream, call_id, true, json))?;
                        }
                        Err(_) => reply(&control, Message::Result(stream, call_id, false, b"{\"error\":\"terminal open refused\"}".to_vec()))?,
                    }
                }
                decoded = receive.next(socket) => {
                    let decoded = decoded?;
                    let stream = decoded.stream_id;
                    if execution_uid.is_some() && (stream % 2 != 0 || matches!(decoded.frame, Frame::Hello { .. })) {
                        return Err(sessions::invalid("invalid remote stream or duplicate Hello"));
                    }
                    match decoded.frame {
                        Frame::Hello {version: 1, ..} if stream == 0 => {}
                        Frame::Ping {nonce, sent_us} if stream == 0 => reply(&control, Message::Pong(nonce, sent_us))?,
                        #[cfg(feature = "remote")]
                        Frame::Call {call_id, action_id, input_json} if stream == 0 && matches!(action_id, "transport.csr" | "transport.certificate") && renewal.is_some() => {
                            if !renewals.is_empty() || input_json.len() > infraternal_plugin_api::channel::MAX_CONTROL_JSON {
                                reply(&control, Message::Result(0, call_id, false, b"{}".to_vec()))?;
                            } else {
                                let renewal = renewal.ok_or_else(|| sessions::invalid("missing renewal identity"))?.clone();
                                let action = action_id.to_owned(); let input = input_json.to_vec();
                                renewals.spawn_blocking(move || (call_id, renewal.action(&action, &input)));
                            }
                        }
                        Frame::Call {call_id, action_id: "terminal.open", input_json} if execution_uid.is_none() || stream == 0 => {
                            let input = serde_json::from_slice::<Open>(input_json);
                            if let Ok(input) = input && execution_uid.is_none_or(|uid| input.uid == uid) && registry.len() + opens.len() < sessions::MAX_SESSIONS {
                                let exe = exe.clone(); let state = state.clone();
                                opens.spawn(async move { (stream, call_id, sessions::launch(&exe, &state, manager, input.uid, input.cols, input.rows).await) });
                            } else {
                                reply(&control, Message::Result(stream, call_id, false, b"{\"error\":\"invalid terminal open or session limit\"}".to_vec()))?;
                            }
                        }
                        Frame::Call {call_id, action_id, input_json} if stream == 0 => {
                            match plugins.call_with_reply(action_id, input_json) {
                                Ok(result) => reply(&control, Message::Deferred(0, call_id, result))?,
                                Err(_) => reply(&control, Message::Result(0, call_id, false, b"{\"error\":\"plugin action rejected\"}".to_vec()))?,
                            }
                        }
                        Frame::AttachTerm {session_id, last_out_seq, last_in_seq} if stream != 0 => {
                            if streams.len() >= sessions::MAX_SESSIONS || streams.contains_key(&stream) {
                                return Err(sessions::invalid("terminal stream already attached or limit reached"));
                            }
                            // The registry only caches shims this process has seen. A miss is not
                            // proof of death, and never a reason to drop every sibling stream: the
                            // rendezvous derives from the id alone, and `terminal` answers a final
                            // Close when no shim listens there (#158).
                            let path = registry.get(session_id).cloned().unwrap_or_else(|| sessions::rendezvous(&state, *session_id));
                            let id = *session_id;
                            let (commands, rx) = session_commands::channel();
                            let (cancel, cancelled) = oneshot::channel();
                            streams.insert(stream, Stream { commands, _cancel: cancel });
                            let tx = tx.clone();
                            jobs.spawn(async move {
                                let result = tokio::select! {
                                    result = terminal(path, id, stream, last_out_seq, last_in_seq, rx, tx) => result,
                                    _ = cancelled => Ok(()),
                                };
                                (stream, result)
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
                            // Never await a session's capacity in shared dispatch.
                            // Retire overload before accepting this command. Drop the
                            // cancellation sender to release even a stalled handshake;
                            // shim-owned accepted/written cursors make input replay safe.
                            let overloaded = streams.get_mut(&stream).is_some_and(|entry| {
                                matches!(entry.commands.try_send(command), Err(mpsc::error::TrySendError::Full(_)))
                            });
                            if overloaded {
                                streams.remove(&stream);
                                reply(&control, Message::Close(stream, "terminal command queue full; reattach and replay unacknowledged input"))?;
                            }
                            // Frames already in flight after a stream closes are
                            // ignored; the terminal task emits its own Close.
                        }
                    }
                }
            }
            // A coalesced request burst can consume all slots in one poll,
            // before the outer select polls an otherwise ready writer. Give
            // it one scheduling turn at the batch boundary, never wait for
            // capacity. A genuinely stalled writer still refuses the next reply.
            if control.capacity() == 0 {
                tokio::task::yield_now().await;
            }
        }
    };
    tokio::select! { result = dispatch => result, result = writer(socket, rx, Some(control_rx), true, renewal.is_some()) => result }
}

/// Run one authenticated, capability-bound native terminal using the common shim relay.
/// The connection supervisor must cancel this future when server authority is lost;
/// this function never opens a PTY, accepts a Call or creates its own writer identity.
/// # Errors
/// Refuses missing/reserved binding, a missing bounded `AttachTerm`, unknown shim,
/// malformed post-attachment traffic and overload. Returning never stops the shim.
#[allow(clippy::too_many_lines)]
#[cfg(feature = "remote")]
pub async fn run_bound_terminal(channel: &impl Channel, state: Option<PathBuf>) -> io::Result<()> {
    let writer_id = channel
        .native_stream_id()
        .filter(|id| *id != 0 && id & 1 == 0)
        .ok_or_else(|| sessions::invalid("native terminal writer binding required"))?;
    let _retire = RetireChannel(channel);
    let state = sessions::state(state)?;
    let mut receive = Receive::default();
    let (id, cursor, input) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let first = receive.next(channel).await?;
        match first.frame {
            Frame::AttachTerm {
                session_id,
                last_out_seq,
                last_in_seq,
            } => Ok((*session_id, last_out_seq, last_in_seq)),
            _ => Err(sessions::invalid("native terminal AttachTerm required")),
        }
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let path = sessions::rendezvous(&state, id);
    let (tx, rx) = mpsc::channel(8);
    let (commands, command_rx) = mpsc::channel(8);
    let dispatch = async {
        loop {
            let decoded = receive.next(channel).await?;
            let command = match decoded.frame {
                Frame::Input { in_seq, bytes } => Command::Input(in_seq, bytes.to_vec()),
                Frame::Credit { bytes } => Command::Credit(bytes),
                Frame::Resize {
                    cols,
                    rows,
                    px_w,
                    px_h,
                } => Command::Resize(cols, rows, px_w, px_h),
                Frame::Close { .. } => return Ok(()),
                _ => return Err(sessions::invalid("unexpected native terminal request")),
            };
            // This dispatcher belongs to one native stream. Awaiting its bounded
            // queue propagates QUIC flow control without parking control or any
            // sibling stream. Ordinary coalesced Credit bursts must not retire
            // an authenticated attachment while its shim handshake is pending.
            commands
                .send(command)
                .await
                .map_err(|_| sessions::invalid("native terminal command queue unavailable"))?;
        }
    };
    let writer = writer(channel, rx, None, false, false);
    tokio::pin!(writer);
    tokio::select! {
        result = dispatch => result,
        result = &mut writer => result,
        result = terminal(path, id, writer_id, cursor, input, session_commands::Receiver::Native(command_rx), tx) => {
            result?;
            // Successful terminal returns can queue a final Close (gone session,
            // unsupported shim or refused request). Its sole sender is now gone:
            // drain the FIFO before RetireChannel cancels the native writes.
            // Bound the whole drain so an unread peer cannot pin this stream.
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut writer)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        },
    }
}

/// One shim connection reuses transmit and cancellation-safe receive storage.
struct Link {
    session: Session,
    transmit: Vec<u8>,
    reader: Reader,
}
impl Link {
    async fn connect(path: PathBuf, id: [u8; 16], writer: u32) -> io::Result<Self> {
        Ok(Self {
            session: sessions::connect_writer(path, id, writer).await?,
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

/// Connects this stream to its session's shim. When nothing listens at the
/// rendezvous the shim is gone, and so is the session: the stream gets one
/// final Close and the caller ends quietly, keeping the channel and every
/// sibling stream (wire §4, #158). Other failures stay errors and transient.
async fn relink(
    path: &std::path::Path,
    id: [u8; 16],
    stream: u32,
    tx: &mpsc::Sender<Message>,
) -> io::Result<Option<Link>> {
    match Link::connect(path.to_path_buf(), id, stream).await {
        Ok(link) => Ok(Some(link)),
        Err(error) if sessions::gone(&error) => {
            emit(tx, Message::Ended(stream)).await?;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn terminal(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    mut commands: session_commands::Receiver,
    tx: mpsc::Sender<Message>,
) -> io::Result<()> {
    let Some(first) = relink(&path, id, stream, &tx).await? else {
        return Ok(());
    };
    let mut session = Some(first);
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
                        // Whole frames transfer their payload ownership to the
                        // writer. Only partial credit/overlap needs a suffix copy.
                        if range.start == 0 && range.end == bytes.len() {
                            emit(
                                &tx,
                                Message::Shim(stream, Shim::Output(output.cursor(), bytes)),
                            )
                            .await?;
                            output
                                .forward(length)
                                .map_err(|_| sessions::invalid("output credit invariant"))?;
                            continue;
                        }
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
            let Some(mut next) = relink(&path, id, stream, &tx).await? else {
                return Ok(());
            };
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
            command = commands.next() => {
                let Some(command) = command else { return Ok(()); };
                match command {
                    Command::Credit(bytes) => { output.grant(bytes).map_err(|_| sessions::invalid("credit overflow"))?; if session.is_none() && bytes > 0 { output.retry_recovery(); } deadline = None; }
                    other => {
                        let detached = session.is_none();
                        if detached {
                            let Some(mut next) = relink(&path, id, stream, &tx).await? else { return Ok(()); };
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
                            // Reconnecting the same writer can supersede
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

#[cfg(all(test, feature = "remote"))]
#[path = "daemon_remote_tests.rs"]
mod remote_tests;

#[cfg(test)]
#[path = "daemon_readiness_tests.rs"]
mod readiness_tests;

#[cfg(test)]
#[path = "daemon_gone_tests.rs"]
mod gone_tests;
