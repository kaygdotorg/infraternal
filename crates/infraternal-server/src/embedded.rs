//! Relays control calls and resumable terminal streams through local socketpair or admitted remote infraternal agents [9][13][64].

#[cfg(feature = "remote")]
use crate::remote_link::RemoteLink;
#[cfg(not(feature = "remote"))]
type RemoteLink = ();
use bytes::{Buf, Bytes, BytesMut};
use infraternal_protocol::{
    DecodeError, Frame, MAX_FRAME_LEN, decode_muxed_frame, encode_muxed_frame_into,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    net::unix::{OwnedReadHalf, OwnedWriteHalf},
    sync::{mpsc, oneshot, watch},
};

const CONTROL_STREAM: u32 = 0;
// Callers await bounded command capacity; output never waits on a browser receiver.
const COMMAND_CAPACITY: usize = 64;
// A full output queue retires only that attachment; reconnect replays from its last offset.
// A default 1MiB grant can arrive in 256 bulk PTY frames while forwarding awaits I/O.
// Credits bound payload bytes; frame slots separately bound small outputs and notices.
const OUTPUT_CAPACITY: usize = 256;
const MAX_OUTPUT_CREDIT: u64 = 8 * 1024 * 1024;
// Full input queues stop the WebSocket reader and propagate backpressure to the peer.
const INPUT_CAPACITY: usize = 4;
const READ_CHUNK: usize = 16 * 1024;
const MAX_BUFFERED_WIRE: usize = MAX_FRAME_LEN + READ_CHUNK + 10;
/// Reconnect pauses for a lost infraternal agent link, and how long a link must
/// live before a loss counts as fresh rather than as the same failure again.
const RECONNECT_FLOOR: Duration = Duration::from_millis(200);
const RECONNECT_CEILING: Duration = Duration::from_secs(30);
const STABLE_LINK: Duration = Duration::from_secs(10);

/// Protocol or process failures are deliberately independent of user input and agent log output.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum AgentError {
    /// The embedded infraternal agent could not start or stopped unexpectedly.
    #[error("embedded infraternal agent is unavailable")]
    Unavailable,
    /// The embedded infraternal agent violated the shared wire contract.
    #[error("embedded infraternal agent sent an invalid protocol frame")]
    Protocol,
    /// The terminal action was rejected by the embedded infraternal agent.
    #[error("terminal action failed")]
    Rejected,
    /// A public terminal admission refusal; transport failures remain generic.
    #[error("terminal open refused")]
    OpenRefused(infraternal_plugin_api::admission::OpenRefusal),
    /// The remote peer did not negotiate live renewal.
    #[error("remote infraternal agent lacks live renewal")]
    #[cfg(feature = "remote")]
    Unsupported,
}

/// Dimensions passed to the core terminal.open action.
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct TerminalSize {
    /// Character columns.
    pub cols: u16,
    /// Character rows.
    pub rows: u16,
    /// Pixel width.
    pub px_w: u16,
    /// Pixel height.
    pub px_h: u16,
}

/// Output returned by one attached terminal stream.
#[derive(Debug)]
pub(crate) enum TerminalOutput {
    /// PTY bytes and their absolute offset.
    Output { out_seq: u64, bytes: Bytes },
    /// Repaint bytes valid at the given absolute offset.
    Snapshot { out_seq: u64, bytes: Bytes },
    /// Ordered, session-bound recovery or lifecycle notice.
    Event { event_json: Bytes },
    /// Highest input sequence written to the PTY.
    Ack { in_seq_acked: u64 },
    /// The agent retired one terminal stream.
    Closed { code: u16 },
}

/// A single client attachment to a terminal session owned by its host infraternal agent.
pub(crate) struct TerminalAttachment {
    handle: AttachmentHandle,
    output: mpsc::Receiver<TerminalOutput>,
}

/// A cloneable attachment sender; its last drop detaches the leg-B stream.
#[derive(Clone)]
pub(crate) struct AttachmentHandle(Arc<AttachmentHandleInner>);

struct AttachmentHandleInner {
    id: u64,
    stream_id: u32,
    input: mpsc::Sender<Bytes>,
    commands: mpsc::Sender<Command>,
}

impl AttachmentHandle {
    /// The server-opened, even-numbered leg-B stream corresponding to this client attachment.
    #[must_use]
    pub fn stream_id(&self) -> u32 {
        self.0.stream_id
    }

    /// Queue one complete leg-A muxed terminal frame for forwarding to leg B.
    pub async fn send_frame(&self, frame: Bytes) -> Result<(), AgentError> {
        self.0
            .input
            .send(frame)
            .await
            .map_err(|_| AgentError::Unavailable)
    }
}

impl Drop for AttachmentHandleInner {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::Detach {
            attachment_id: self.id,
        });
    }
}

impl TerminalAttachment {
    /// Separate the cloneable input handle from its single output receiver.
    pub fn split(self) -> (AttachmentHandle, mpsc::Receiver<TerminalOutput>) {
        (self.handle, self.output)
    }
}

/// Full inventory availability from the infraternal agent, separate from session liveness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SessionInventoryState {
    /// No agent census has arrived during this server run; subscribers must hide cached rows.
    Pending,
    /// The agent link dropped; cached rows cannot be offered until a fresh census arrives.
    Unavailable,
    /// Authoritative shim identities from one complete agent census.
    Available(Arc<[[u8; 16]]>),
}

/// Bounded command sender for the embedded agent actor.
#[derive(Clone)]
pub(crate) struct EmbeddedAgent {
    commands: mpsc::Sender<Command>,
    changes: tokio::sync::watch::Receiver<()>,
    next_attachment_id: Arc<AtomicU64>,
    session_inventory: watch::Sender<SessionInventoryState>,
}

impl EmbeddedAgent {
    pub(crate) fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        let mut changes = self.changes.clone();
        changes.borrow_and_update();
        changes
    }

    /// Start the on-demand agent supervisor for the server's own executable.
    pub fn spawn(executable: PathBuf) -> Self {
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (changes, notice) = tokio::sync::watch::channel(());
        let (session_inventory, _) = watch::channel(SessionInventoryState::Pending);
        tokio::spawn(run_actor(
            Source::Embedded {
                executable,
                initial: None,
            },
            receiver,
            changes,
            session_inventory.clone(),
        ));
        Self {
            commands,
            changes: notice,
            next_attachment_id: Arc::new(AtomicU64::new(1)),
            session_inventory,
        }
    }

    /// Fail the unused embedded route in remote-only fixtures; fallback must not create local PTYs.
    #[cfg(all(test, feature = "remote"))]
    pub(crate) fn unavailable() -> Self {
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (_changes, notice) = tokio::sync::watch::channel(());
        drop(receiver);
        let (session_inventory, _) = watch::channel(SessionInventoryState::Pending);
        Self {
            commands,
            changes: notice,
            next_attachment_id: Arc::new(AtomicU64::new(1)),
            session_inventory,
        }
    }

    /// Reuse the terminal actor for an enrolled host; only admitted listeners supply links.
    #[cfg(feature = "remote")]
    pub(crate) fn remote(uid: u32) -> (Self, mpsc::Sender<RemoteLink>) {
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (changes, notice) = tokio::sync::watch::channel(());
        let (accepts, incoming) = mpsc::channel(1);
        let (session_inventory, _) = watch::channel(SessionInventoryState::Pending);
        tokio::spawn(run_actor(
            Source::Remote {
                incoming,
                uid,
                pending: None,
            },
            receiver,
            changes,
            session_inventory.clone(),
        ));
        (
            Self {
                commands,
                changes: notice,
                next_attachment_id: Arc::new(AtomicU64::new(1)),
                session_inventory,
            },
            accepts,
        )
    }

    /// A bounded control call shares the existing id allocator and reply dispatcher.
    #[cfg(feature = "remote")]
    pub(crate) async fn control_call(
        &self,
        action: &'static str,
        json: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        if json.len() > infraternal_plugin_api::channel::MAX_CONTROL_JSON {
            return Err(AgentError::Rejected);
        }
        let (reply, result) = oneshot::channel();
        tokio::time::timeout(Duration::from_secs(5), async {
            self.commands
                .send(Command::Control {
                    action,
                    json,
                    reply,
                })
                .await
                .map_err(|_| AgentError::Unavailable)?;
            result.await.map_err(|_| AgentError::Unavailable)?
        })
        .await
        .map_err(|_| AgentError::Unavailable)?
    }

    /// Open a terminal on the embedded infraternal agent's host.
    pub async fn open(&self, size: TerminalSize) -> Result<[u8; 16], AgentError> {
        self.open_with_readiness(size, false).await
    }

    /// Open a private fixed-command readiness PTY under the enrolled identity.
    #[cfg(feature = "remote")]
    pub(crate) async fn open_readiness(&self, size: TerminalSize) -> Result<[u8; 16], AgentError> {
        self.open_with_readiness(size, true).await
    }

    async fn open_with_readiness(
        &self,
        size: TerminalSize,
        readiness: bool,
    ) -> Result<[u8; 16], AgentError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Open {
                size,
                readiness,
                reply,
            })
            .await
            .map_err(|_| AgentError::Unavailable)?;
        result.await.map_err(|_| AgentError::Unavailable)?
    }

    /// Calls one bounded action declared by the embedded agent's plugin registry.
    pub async fn call(
        &self,
        action_id: String,
        input_json: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        if action_id.len() > 128 || input_json.len() > infraternal_plugin_api::MAX_ACTION_BYTES {
            return Err(AgentError::Rejected);
        }
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Call {
                action_id,
                input_json,
                reply,
            })
            .await
            .map_err(|_| AgentError::Unavailable)?;
        result.await.map_err(|_| AgentError::Unavailable)?
    }

    /// Watch the latest authoritative live-shim set reported by this infraternal agent.
    pub(crate) fn session_inventory(&self) -> watch::Receiver<SessionInventoryState> {
        self.session_inventory.subscribe()
    }

    /// Attach one device to a user-owned terminal session and request replay from its last offsets.
    pub async fn attach(
        &self,
        session_id: [u8; 16],
        last_out_seq: u64,
        last_in_seq: u64,
        stream_id: u32,
    ) -> Result<TerminalAttachment, AgentError> {
        let (output_tx, output) = mpsc::channel(OUTPUT_CAPACITY);
        let (input, input_rx) = mpsc::channel(INPUT_CAPACITY);
        let id = self
            .next_attachment_id
            .fetch_add(1, Ordering::Relaxed)
            .max(1);
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Attach {
                id,
                session_id,
                stream_id,
                last_out_seq,
                last_in_seq,
                output: output_tx,
                reply,
            })
            .await
            .map_err(|_| AgentError::Unavailable)?;
        let (id, stream_id) = result.await.map_err(|_| AgentError::Unavailable)??;
        let command_tx = self.commands.clone();
        tokio::spawn(async move {
            forward_inputs(id, input_rx, command_tx).await;
        });
        Ok(TerminalAttachment {
            handle: AttachmentHandle(Arc::new(AttachmentHandleInner {
                id,
                stream_id,
                input,
                commands: self.commands.clone(),
            })),
            output,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_socket(stream: UnixStream) -> Self {
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (changes, notice) = tokio::sync::watch::channel(());
        let (session_inventory, _) = watch::channel(SessionInventoryState::Pending);
        tokio::spawn(run_actor(
            Source::Embedded {
                executable: PathBuf::new(),
                initial: Some(stream),
            },
            receiver,
            changes,
            session_inventory.clone(),
        ));
        Self {
            commands,
            changes: notice,
            next_attachment_id: Arc::new(AtomicU64::new(1)),
            session_inventory,
        }
    }
}

enum Command {
    #[cfg(feature = "remote")]
    Control {
        action: &'static str,
        json: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, AgentError>>,
    },
    Open {
        size: TerminalSize,
        readiness: bool,
        reply: oneshot::Sender<Result<[u8; 16], AgentError>>,
    },
    Call {
        action_id: String,
        input_json: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, AgentError>>,
    },
    Attach {
        id: u64,
        session_id: [u8; 16],
        stream_id: u32,
        last_out_seq: u64,
        last_in_seq: u64,
        output: mpsc::Sender<TerminalOutput>,
        reply: oneshot::Sender<Result<(u64, u32), AgentError>>,
    },
    Input {
        attachment_id: u64,
        frame: Bytes,
    },
    Detach {
        attachment_id: u64,
    },
}

struct AttachmentState {
    session_id: [u8; 16],
    stream_id: u32,
    last_out_seq: u64,
    last_in_seq: u64,
    last_input_end: u64,
    credit: u64,
    awaiting_ack: bool,
    output: mpsc::Sender<TerminalOutput>,
}

enum Peer {
    Local {
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
    },
    #[cfg(feature = "remote")]
    Remote(Box<RemoteLink>),
}

enum Source {
    /// Already-greeted fixture links expose actor retry policy under a paused clock.
    #[cfg(test)]
    Fixture {
        connections: std::collections::VecDeque<AgentConnection>,
        attempts: mpsc::UnboundedSender<tokio::time::Instant>,
    },
    Embedded {
        executable: PathBuf,
        initial: Option<UnixStream>,
    },
    #[cfg(feature = "remote")]
    Remote {
        incoming: mpsc::Receiver<RemoteLink>,
        uid: u32,
        pending: Option<Box<RemoteLink>>,
    },
}

impl Source {
    async fn connect(&mut self) -> Result<AgentConnection, AgentError> {
        match self {
            #[cfg(test)]
            Self::Fixture {
                connections,
                attempts,
            } => {
                attempts
                    .send(tokio::time::Instant::now())
                    .map_err(|_| AgentError::Unavailable)?;
                connections.pop_front().ok_or(AgentError::Unavailable)
            }
            Self::Embedded {
                executable,
                initial,
            } => connect_agent(executable, initial.take()).await,
            #[cfg(feature = "remote")]
            Self::Remote {
                incoming,
                uid,
                pending,
            } => {
                let link = if let Some(link) = pending.take() {
                    *link
                } else {
                    incoming.recv().await.ok_or(AgentError::Unavailable)?
                };
                let mut receive = BytesMut::with_capacity(4096);
                let mut scratch = vec![0; READ_CHUNK];
                let hello = Frame::Hello {
                    version: 1,
                    caps: infraternal_agent::remote_quic::REMOTE_WRITER_BINDING,
                    client_info: "infraternal-server/0.1",
                };
                let mut encode = Vec::new();
                encode_muxed_frame_into(0, &hello, &mut encode)
                    .map_err(|_| AgentError::Protocol)?;
                let handshake = async {
                    link.write(0, &hello, &encode)
                        .await
                        .map_err(|_| AgentError::Unavailable)?;
                    loop {
                        match decode_muxed_frame(&receive) {
                            Ok(decoded) => {
                                if decoded.stream_id != 0
                                    || !matches!(decoded.frame, Frame::Hello { version: 1, .. })
                                {
                                    return Err(AgentError::Protocol);
                                }
                                link.hello(&decoded.frame)
                                    .await
                                    .map_err(|_| AgentError::Protocol)?;
                                receive.advance(decoded.wire_len);
                                return Ok(());
                            }
                            Err(DecodeError::Incomplete) => {}
                            Err(_) => return Err(AgentError::Protocol),
                        }
                        if link
                            .read(&mut receive, &mut scratch)
                            .await
                            .map_err(|_| AgentError::Unavailable)?
                            == 0
                        {
                            return Err(AgentError::Unavailable);
                        }
                    }
                };
                tokio::time::timeout(Duration::from_secs(5), handshake)
                    .await
                    .map_err(|_| AgentError::Unavailable)??;
                Ok(AgentConnection {
                    peer: Peer::Remote(Box::new(link)),
                    execution_uid: *uid,
                    pid: None,
                    receive,
                    scratch,
                    encode: Vec::new(),
                    next_call_id: 1,
                })
            }
        }
    }
    async fn replacement(&mut self) -> Option<RemoteLink> {
        match self {
            #[cfg(feature = "remote")]
            Self::Remote { incoming, .. } => incoming.recv().await,
            Self::Embedded { .. } => std::future::pending().await,
            #[cfg(test)]
            Self::Fixture { .. } => std::future::pending().await,
        }
    }
    fn closed(&self) -> bool {
        match self {
            Self::Embedded { .. } => false,
            #[cfg(test)]
            Self::Fixture { connections, .. } => connections.is_empty(),
            #[cfg(feature = "remote")]
            Self::Remote {
                incoming, pending, ..
            } => pending.is_none() && incoming.is_closed() && incoming.is_empty(),
        }
    }
    fn remote(&self) -> bool {
        #[cfg(test)]
        if matches!(self, Self::Fixture { .. }) {
            return false;
        }
        !matches!(self, Self::Embedded { .. })
    }
}

struct AgentConnection {
    peer: Peer,
    execution_uid: u32,
    pid: Option<nix::unistd::Pid>,
    receive: BytesMut,
    scratch: Vec<u8>,
    encode: Vec<u8>,
    next_call_id: u32,
}

enum Incoming {
    Hello {
        version: u16,
    },
    Result {
        call_id: u32,
        ok: bool,
        json: Vec<u8>,
    },
    Output {
        stream_id: u32,
        out_seq: u64,
        bytes: Bytes,
    },
    Snapshot {
        stream_id: u32,
        out_seq: u64,
        bytes: Bytes,
    },
    Event {
        stream_id: u32,
        event_json: Bytes,
    },
    ControlEvent,
    SessionInventory(Vec<[u8; 16]>),
    Ack {
        stream_id: u32,
        in_seq_acked: u64,
    },
    Close {
        stream_id: u32,
        code: u16,
    },
    Ping {
        nonce: u64,
        sent_us: u64,
    },
    Disconnected,
}

enum PendingCall {
    Action(oneshot::Sender<Result<Vec<u8>, AgentError>>),
    Open(oneshot::Sender<Result<[u8; 16], AgentError>>),
    #[cfg(feature = "remote")]
    Control(oneshot::Sender<Result<Vec<u8>, AgentError>>),
}
impl PendingCall {
    fn refuse(self, error: AgentError) {
        match self {
            Self::Open(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Action(reply) => {
                let _ = reply.send(Err(error));
            }
            #[cfg(feature = "remote")]
            Self::Control(reply) => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenResult {
    session_id: String,
}

async fn forward_inputs(
    attachment_id: u64,
    mut input: mpsc::Receiver<Bytes>,
    commands: mpsc::Sender<Command>,
) {
    while let Some(frame) = input.recv().await {
        if commands
            .send(Command::Input {
                attachment_id,
                frame,
            })
            .await
            .is_err()
        {
            return;
        }
    }
    let _ = commands.send(Command::Detach { attachment_id }).await;
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep link loss, capability invalidation and census publication in the same actor lifetime."
)]
async fn run_actor(
    mut source: Source,
    mut commands: mpsc::Receiver<Command>,
    changes: tokio::sync::watch::Sender<()>,
    session_inventory: watch::Sender<SessionInventoryState>,
) {
    let mut attachments = HashMap::<u64, AttachmentState>::new();
    let mut routes = HashMap::<u32, u64>::new();
    let mut pending = HashMap::<u32, PendingCall>::new();
    let mut connection: Option<AgentConnection> = None;
    let mut backoff = RECONNECT_FLOOR;
    let mut connected_at = std::time::Instant::now();
    let mut first_attempt = true;

    loop {
        if connection.is_none() {
            if source.closed() {
                return;
            }
            if commands.is_closed() {
                return;
            }
            if !first_attempt && !source.remote() {
                tokio::time::sleep(backoff).await;
            }
            first_attempt = false;
            if let Ok(mut fresh) = source.connect().await {
                if !reattach_all(&mut fresh, &mut attachments, &mut routes).await {
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    routes.clear();
                    cleanup_connection(fresh).await;
                    continue;
                }
                connection = Some(fresh);
                connected_at = std::time::Instant::now();
                changes.send_replace(());
            } else {
                tracing::warn!("infraternal agent connection failed; awaiting reconnect");
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        }

        let Some(link) = connection.as_mut() else {
            continue;
        };
        tokio::select! {
            replacement = source.replacement(), if source.remote() => {
                #[cfg(feature = "remote")]
                let Some(replacement) = replacement else { return; };
                #[cfg(not(feature = "remote"))]
                let Some(()) = replacement else { return; };
                #[cfg(feature = "remote")]
                if let Source::Remote { pending,.. } = &mut source { *pending = Some(Box::new(replacement)); }
                if let Some(old) = connection.take() {
                    connection_lost(old, &mut attachments, &mut routes, &mut pending).await;
                    session_inventory.send_replace(SessionInventoryState::Unavailable);
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { return; };
                let ok = process_command(
                    command,
                    link,
                    &mut attachments,
                    &mut routes,
                    &mut pending,
                ).await;
                if !ok {
                    let link = connection.take();
                    if let Some(link) = link {
                        connection_lost(link, &mut attachments, &mut routes, &mut pending).await;
                        session_inventory.send_replace(SessionInventoryState::Unavailable);
                        backoff = after_loss(backoff, connected_at);
                        first_attempt = false;
                    }
                }
            }
            incoming = read_incoming(link) => {
                let Some(incoming) = incoming else {
                    let link = connection.take();
                    if let Some(link) = link {
                        connection_lost(link, &mut attachments, &mut routes, &mut pending).await;
                        session_inventory.send_replace(SessionInventoryState::Unavailable);
                        backoff = after_loss(backoff, connected_at);
                        first_attempt = false;
                    }
                    continue;
                };
                // Public plugin events invalidate capability consumers; no feature
                // payload is interpreted by terminal routing. A reconnect also invalidates.
                if let Incoming::Event {stream_id:0,event_json}=&incoming
                    && serde_json::from_slice::<serde_json::Value>(event_json).is_ok_and(|value|value["type"]=="plugin.event" || value["type"]=="plugins.resync") {
                    changes.send_replace(());continue;
                }
                if let Incoming::SessionInventory(ids) = incoming {
                    session_inventory
                        .send_replace(SessionInventoryState::Available(Arc::from(ids)));
                    continue;
                }
                if !process_incoming(incoming, link, &mut attachments, &mut routes, &mut pending).await {
                    let link = connection.take();
                    if let Some(link) = link {
                        connection_lost(link, &mut attachments, &mut routes, &mut pending).await;
                        session_inventory.send_replace(SessionInventoryState::Unavailable);
                        backoff = after_loss(backoff, connected_at);
                        first_attempt = false;
                    }
                }
            }
        }
    }
}

/// The pause before the next infraternal agent start after a lost link. A link
/// that lived for a while starts over at the floor; one that died young doubles
/// the pause, up to the ceiling. Resetting on every successful connect let a
/// request that kills each new process (a dead session's re-sent `AttachTerm`
/// did) restart it about twice a second, forever (#158).
fn after_loss(backoff: Duration, connected_at: std::time::Instant) -> Duration {
    if connected_at.elapsed() >= STABLE_LINK {
        RECONNECT_FLOOR
    } else {
        (backoff * 2).min(RECONNECT_CEILING)
    }
}

async fn connect_agent(
    executable: &Path,
    initial: Option<UnixStream>,
) -> Result<AgentConnection, AgentError> {
    let (mut socket, pid) = if let Some(socket) = initial {
        (socket, None)
    } else {
        spawn_socketpair_agent(executable).map_err(|_| AgentError::Unavailable)?
    };
    let setup = async {
        let mut encode = Vec::with_capacity(128);
        encode_muxed_frame_into(
            CONTROL_STREAM,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "infraternal-server/0.1",
            },
            &mut encode,
        )
        .map_err(|_| AgentError::Protocol)?;
        socket
            .write_all(&encode)
            .await
            .map_err(|_| AgentError::Unavailable)?;
        let mut receive = BytesMut::with_capacity(4096);
        let mut scratch = vec![0_u8; READ_CHUNK];
        let incoming = read_frame_from_socket(&mut socket, &mut receive, &mut scratch).await?;
        if !matches!(incoming, Incoming::Hello { version: 1 }) {
            return Err(AgentError::Protocol);
        }
        Ok::<_, AgentError>((receive, scratch))
    };
    // Unit fixtures may be starved by host load while running both sides in one test process.
    // The deployed embedded-agent greeting keeps its fixed five-second cap.
    #[cfg(test)]
    let greeting_timeout = Duration::from_secs(30);
    #[cfg(not(test))]
    let greeting_timeout = Duration::from_secs(5);
    let Ok(Ok((receive, scratch))) = tokio::time::timeout(greeting_timeout, setup).await else {
        if let Some(pid) = pid {
            stop_child(pid).await;
        }
        return Err(AgentError::Unavailable);
    };
    let (reader, writer) = socket.into_split();
    Ok(AgentConnection {
        peer: Peer::Local { reader, writer },
        execution_uid: nix::unistd::Uid::effective().as_raw(),
        pid,
        receive,
        scratch,
        encode: Vec::with_capacity(4096),
        next_call_id: 1,
    })
}

async fn read_frame_from_socket(
    socket: &mut UnixStream,
    receive: &mut BytesMut,
    scratch: &mut [u8],
) -> Result<Incoming, AgentError> {
    loop {
        match decode_muxed_frame(receive) {
            Ok(decoded) => {
                if decoded.wire_len > receive.len() {
                    return Err(AgentError::Protocol);
                }
                if decoded.stream_id != CONTROL_STREAM
                    || !matches!(decoded.frame, Frame::Hello { version: 1, .. })
                {
                    return Err(AgentError::Protocol);
                }
                receive.advance(decoded.wire_len);
                return Ok(Incoming::Hello { version: 1 });
            }
            Err(DecodeError::Incomplete) => {}
            Err(_) => return Err(AgentError::Protocol),
        }
        if receive.len() >= MAX_BUFFERED_WIRE {
            return Err(AgentError::Protocol);
        }
        let read = socket
            .read(scratch)
            .await
            .map_err(|_| AgentError::Unavailable)?;
        if read == 0 {
            return Err(AgentError::Unavailable);
        }
        receive.extend_from_slice(&scratch[..read]);
    }
}

// The command variants mutate one shared route table, so they remain in one bounded actor turn.
#[allow(clippy::too_many_lines)]
async fn process_command(
    command: Command,
    connection: &mut AgentConnection,
    attachments: &mut HashMap<u64, AttachmentState>,
    routes: &mut HashMap<u32, u64>,
    pending: &mut HashMap<u32, PendingCall>,
) -> bool {
    match command {
        #[cfg(feature = "remote")]
        Command::Control {
            action,
            json,
            reply,
        } => {
            if reply.is_closed() {
                return true;
            }
            if !matches!(&connection.peer, Peer::Remote(link) if link.supports_renewal()) {
                let _ = reply.send(Err(AgentError::Unsupported));
                return true;
            }
            if json.len() > infraternal_plugin_api::channel::MAX_CONTROL_JSON
                || pending
                    .values()
                    .any(|call| matches!(call, PendingCall::Control(_)))
            {
                let _ = reply.send(Err(AgentError::Rejected));
                return true;
            }
            let Some(call_id) = allocate_call_id(connection, pending) else {
                let _ = reply.send(Err(AgentError::Unavailable));
                return true;
            };
            let frame = Frame::Call {
                call_id,
                action_id: action,
                input_json: &json,
            };
            if !write_frame(connection, CONTROL_STREAM, &frame).await {
                let _ = reply.send(Err(AgentError::Unavailable));
                return false;
            }
            pending.insert(call_id, PendingCall::Control(reply));
            true
        }
        Command::Open {
            size,
            readiness,
            reply,
        } => {
            #[cfg(feature = "remote")]
            if let Peer::Remote(link) = &connection.peer
                && link.admit_operation().await.is_err()
            {
                let _ = reply.send(Err(AgentError::Unavailable));
                return false;
            }
            if pending.len() >= COMMAND_CAPACITY {
                let _ = reply.send(Err(AgentError::Unavailable));
                return true;
            }
            let Some(call_id) = allocate_call_id(connection, pending) else {
                let _ = reply.send(Err(AgentError::Unavailable));
                return true;
            };
            // The trusted enrolled or local host identity never comes from browser JSON.
            // Pixel geometry is sent later through Resize; the daemon opens a
            // PTY using its approved {uid, cols, rows} action schema [9][13].
            let mut request = serde_json::json!({
                "uid": connection.execution_uid,
                "cols": size.cols,
                "rows": size.rows,
            });
            if readiness {
                request["readiness"] = serde_json::Value::Bool(true);
            }
            let Ok(json) = serde_json::to_vec(&request) else {
                let _ = reply.send(Err(AgentError::Protocol));
                return true;
            };
            let frame = Frame::Call {
                call_id,
                action_id: "terminal.open",
                input_json: &json,
            };
            if !write_frame(connection, CONTROL_STREAM, &frame).await {
                let _ = reply.send(Err(AgentError::Unavailable));
                return false;
            }
            pending.insert(call_id, PendingCall::Open(reply));
            true
        }
        Command::Call {
            action_id,
            input_json,
            reply,
        } => {
            if pending.len() >= COMMAND_CAPACITY {
                let _ = reply.send(Err(AgentError::Unavailable));
                return true;
            }
            let Some(call_id) = allocate_call_id(connection, pending) else {
                let _ = reply.send(Err(AgentError::Unavailable));
                return true;
            };
            let frame = Frame::Call {
                call_id,
                action_id: &action_id,
                input_json: &input_json,
            };
            if !write_frame(connection, CONTROL_STREAM, &frame).await {
                let _ = reply.send(Err(AgentError::Unavailable));
                return false;
            }
            pending.insert(call_id, PendingCall::Action(reply));
            true
        }
        Command::Attach {
            id: attachment_id,
            session_id,
            stream_id,
            last_out_seq,
            last_in_seq,
            output,
            reply,
        } => {
            #[cfg(feature = "remote")]
            if let Peer::Remote(link) = &connection.peer
                && link.admit_operation().await.is_err()
            {
                let _ = reply.send(Err(AgentError::Unavailable));
                return false;
            }
            if stream_id == 0 || stream_id % 2 != 0 {
                let _ = reply.send(Err(AgentError::Protocol));
                return true;
            }
            if let Some(previous) = routes.get(&stream_id).copied() {
                if attachments
                    .get(&previous)
                    .is_none_or(|old| old.session_id != session_id)
                {
                    let _ = reply.send(Err(AgentError::Protocol));
                    return true;
                }
                // A resumed browser may reclaim its writer even if a full command
                // queue prevented the old handle's best-effort Detach notification.
                attachments.remove(&previous);
                routes.remove(&stream_id);
            }
            if !send_attach(connection, stream_id, session_id, last_out_seq, last_in_seq).await {
                let _ = reply.send(Err(AgentError::Unavailable));
                return false;
            }
            routes.insert(stream_id, attachment_id);
            attachments.insert(
                attachment_id,
                AttachmentState {
                    session_id,
                    stream_id,
                    last_out_seq,
                    last_in_seq,
                    last_input_end: last_in_seq,
                    credit: 0,
                    awaiting_ack: true,
                    output,
                },
            );
            let _ = reply.send(Ok((attachment_id, stream_id)));
            true
        }
        Command::Input {
            attachment_id,
            frame,
        } => {
            let Some(attachment) = attachments.get(&attachment_id) else {
                return true;
            };
            let Ok(decoded) = decode_muxed_frame(&frame) else {
                return true;
            };
            if decoded.stream_id == CONTROL_STREAM || decoded.stream_id % 2 == 0 {
                return false;
            }
            let stream_id = attachment.stream_id;
            let b_frame = match decoded.frame {
                Frame::Input { in_seq, bytes } => {
                    let Some(end) = in_seq.checked_add(bytes.len() as u64) else {
                        return false;
                    };
                    let Some(attachment) = attachments.get_mut(&attachment_id) else {
                        return false;
                    };
                    if in_seq > attachment.last_input_end {
                        return false;
                    }
                    attachment.last_input_end = attachment.last_input_end.max(end);
                    let forward_from = in_seq.max(attachment.last_in_seq);
                    if end <= forward_from {
                        return true;
                    }
                    let Ok(skip) = usize::try_from(forward_from - in_seq) else {
                        return false;
                    };
                    let Some(bytes) = bytes.get(skip..) else {
                        return false;
                    };
                    Frame::Input {
                        in_seq: forward_from,
                        bytes,
                    }
                }
                Frame::Resize {
                    cols,
                    rows,
                    px_w,
                    px_h,
                } => Frame::Resize {
                    cols,
                    rows,
                    px_w,
                    px_h,
                },
                Frame::Credit { bytes } => {
                    let Some(attachment) = attachments.get_mut(&attachment_id) else {
                        return false;
                    };
                    let Some(credit) = attachment.credit.checked_add(u64::from(bytes)) else {
                        return false;
                    };
                    if credit > MAX_OUTPUT_CREDIT {
                        return false;
                    }
                    attachment.credit = credit;
                    Frame::Credit { bytes }
                }
                _ => return false,
            };
            write_frame(connection, stream_id, &b_frame).await
        }
        Command::Detach { attachment_id } => {
            if let Some(attachment) = attachments.remove(&attachment_id) {
                routes.remove(&attachment.stream_id);
                return write_frame(
                    connection,
                    attachment.stream_id,
                    &Frame::Close {
                        code: 1000,
                        reason: "detached",
                    },
                )
                .await;
            }
            true
        }
    }
}

fn allocate_call_id(
    connection: &mut AgentConnection,
    pending: &HashMap<u32, PendingCall>,
) -> Option<u32> {
    let start = connection.next_call_id;
    loop {
        let candidate = connection.next_call_id;
        connection.next_call_id = connection.next_call_id.wrapping_add(1).max(1);
        if !pending.contains_key(&candidate) {
            return Some(candidate);
        }
        if connection.next_call_id == start {
            return None;
        }
    }
}

async fn send_attach(
    connection: &mut AgentConnection,
    stream_id: u32,
    session_id: [u8; 16],
    last_out_seq: u64,
    last_in_seq: u64,
) -> bool {
    write_frame(
        connection,
        stream_id,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq,
            last_in_seq,
        },
    )
    .await
}

async fn reattach_all(
    connection: &mut AgentConnection,
    attachments: &mut HashMap<u64, AttachmentState>,
    routes: &mut HashMap<u32, u64>,
) -> bool {
    for (id, attachment) in attachments.iter_mut() {
        let stream_id = attachment.stream_id;
        attachment.awaiting_ack = true;
        if !send_attach(
            connection,
            stream_id,
            attachment.session_id,
            attachment.last_out_seq,
            attachment.last_in_seq,
        )
        .await
        {
            return false;
        }
        if attachment.credit != 0 {
            let Ok(bytes) = u32::try_from(attachment.credit) else {
                return false;
            };
            if !write_frame(connection, stream_id, &Frame::Credit { bytes }).await {
                return false;
            }
        }
        routes.insert(stream_id, *id);
    }
    true
}

/// Content-free notices are bounded and bound to the attached session before forwarding.
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum TerminalNotice {
    #[serde(rename = "terminal.snapshot")]
    Snapshot {
        session_id: String,
        seq: u64,
        approximate: bool,
    },
    #[serde(rename = "terminal.snapshot_unavailable")]
    Unavailable { session_id: String, seq: u64 },
    #[serde(rename = "terminal.replay_complete")]
    ReplayComplete {
        session_id: String,
        #[serde(deserialize_with = "deserialize_replay_cursor")]
        out_seq: u64,
    },
    #[serde(rename = "terminal.exited")]
    Exited {
        session_id: String,
        status: i32,
        final_seq: u64,
        #[serde(default)]
        retired: bool,
    },
}

impl TerminalNotice {
    fn session_id(&self) -> &str {
        // Cursor/status fields validate JSON shape; wire Snapshot/Ack remain authoritative.
        match self {
            Self::Snapshot {
                session_id,
                seq,
                approximate,
            } => {
                let _ = (seq, approximate);
                session_id
            }
            Self::Unavailable { session_id, seq } => {
                let _ = seq;
                session_id
            }
            Self::ReplayComplete {
                session_id,
                out_seq,
            } => {
                let _ = out_seq;
                session_id
            }
            Self::Exited {
                session_id,
                status,
                final_seq,
                retired,
            } => {
                let _ = (status, final_seq, retired);
                session_id
            }
        }
    }
}

/// Replay fences encode their full u64 cursor as canonical decimal JSON text.
fn deserialize_replay_cursor<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let decimal = String::deserialize(deserializer)?;
    if decimal.is_empty()
        || (decimal.len() > 1 && decimal.starts_with('0'))
        || !decimal.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(<D::Error as serde::de::Error>::custom(
            "invalid replay cursor",
        ));
    }
    decimal
        .parse::<u64>()
        .map_err(<D::Error as serde::de::Error>::custom)
}

// Incoming wire cases share actor-owned sequence accounting and bounded output senders.
#[allow(clippy::too_many_lines)]
async fn process_incoming(
    incoming: Incoming,
    connection: &mut AgentConnection,
    attachments: &mut HashMap<u64, AttachmentState>,
    routes: &mut HashMap<u32, u64>,
    pending: &mut HashMap<u32, PendingCall>,
) -> bool {
    match incoming {
        Incoming::Result { call_id, ok, json } => {
            let Some(call) = pending.remove(&call_id) else {
                return false;
            };
            if !ok {
                match call {
                    PendingCall::Open(reply) => {
                        let error =
                            if json.len() <= infraternal_plugin_api::channel::MAX_CONTROL_JSON {
                                serde_json::from_slice(&json)
                                    .map_or(AgentError::Rejected, AgentError::OpenRefused)
                            } else {
                                AgentError::Rejected
                            };
                        let _ = reply.send(Err(error));
                    }
                    PendingCall::Action(reply) => {
                        let _ = reply.send(Err(AgentError::Rejected));
                    }
                    #[cfg(feature = "remote")]
                    PendingCall::Control(reply) => {
                        let _ = reply.send(Err(AgentError::Rejected));
                    }
                }
                return true;
            }
            match call {
                PendingCall::Open(reply) => {
                    let session = serde_json::from_slice::<OpenResult>(&json);
                    let result = session
                        .ok()
                        .and_then(|value| decode_session_id(&value.session_id))
                        .ok_or(AgentError::Protocol);
                    let _ = reply.send(result);
                }
                #[cfg(feature = "remote")]
                PendingCall::Control(reply) => {
                    let _ = reply.send(Ok(json));
                }
                PendingCall::Action(reply) => {
                    let result = if json.len() <= infraternal_plugin_api::MAX_ACTION_BYTES {
                        Ok(json)
                    } else {
                        Err(AgentError::Protocol)
                    };
                    let _ = reply.send(result);
                }
            }
            true
        }
        Incoming::Output {
            stream_id,
            out_seq,
            bytes,
        } => {
            let Some(attachment_id) = routes.get(&stream_id).copied() else {
                return true;
            };
            let Some(attachment) = attachments.get_mut(&attachment_id) else {
                return false;
            };
            let Some(end) = out_seq.checked_add(bytes.len() as u64) else {
                return false;
            };
            if end <= attachment.last_out_seq {
                return true;
            }
            if out_seq != attachment.last_out_seq {
                return retire_slow_stream(
                    connection,
                    attachments,
                    routes,
                    attachment_id,
                    stream_id,
                )
                .await;
            }
            if end - out_seq > attachment.credit {
                return false;
            }
            if attachment
                .output
                .try_send(TerminalOutput::Output { out_seq, bytes })
                .is_err()
            {
                return retire_slow_stream(
                    connection,
                    attachments,
                    routes,
                    attachment_id,
                    stream_id,
                )
                .await;
            }
            attachment.credit -= end - out_seq;
            attachment.last_out_seq = end;
            // Ready socket bursts otherwise retire a healthy four-frame receiver before it runs.
            tokio::task::yield_now().await;
            true
        }
        Incoming::Snapshot {
            stream_id,
            out_seq,
            bytes,
        } => {
            let Some(attachment_id) = routes.get(&stream_id).copied() else {
                return true;
            };
            let Some(attachment) = attachments.get_mut(&attachment_id) else {
                return false;
            };
            if out_seq < attachment.last_out_seq {
                return false;
            }
            let length = bytes.len() as u64;
            if length > attachment.credit {
                return false;
            }
            if attachment
                .output
                .try_send(TerminalOutput::Snapshot { out_seq, bytes })
                .is_err()
            {
                return retire_slow_stream(
                    connection,
                    attachments,
                    routes,
                    attachment_id,
                    stream_id,
                )
                .await;
            }
            attachment.credit -= length;
            attachment.last_out_seq = out_seq;
            true
        }
        Incoming::Event {
            stream_id,
            event_json,
        } => {
            let Some(attachment_id) = routes.get(&stream_id).copied() else {
                return true;
            };
            let Some(attachment) = attachments.get(&attachment_id) else {
                return false;
            };
            let Ok(notice) = serde_json::from_slice::<TerminalNotice>(&event_json) else {
                return false;
            };
            if decode_session_id(notice.session_id()) != Some(attachment.session_id) {
                return false;
            }
            // The same queue preserves notice/repaint ordering and retires a slow viewer only.
            if attachment
                .output
                .try_send(TerminalOutput::Event { event_json })
                .is_err()
            {
                return retire_slow_stream(
                    connection,
                    attachments,
                    routes,
                    attachment_id,
                    stream_id,
                )
                .await;
            }
            true
        }
        Incoming::Ack {
            stream_id,
            in_seq_acked,
        } => {
            let Some(attachment_id) = routes.get(&stream_id).copied() else {
                return true;
            };
            let Some(attachment) = attachments.get_mut(&attachment_id) else {
                return false;
            };
            if in_seq_acked < attachment.last_in_seq {
                return true;
            }
            if !attachment.awaiting_ack && in_seq_acked > attachment.last_input_end {
                return false;
            }
            // The backend may have accepted input whose Ack died with the old browser.
            // Its first reattach Ack is authoritative for this same durable writer.
            attachment.last_input_end = attachment.last_input_end.max(in_seq_acked);
            attachment.awaiting_ack = false;
            attachment.last_in_seq = in_seq_acked;
            if attachment
                .output
                .try_send(TerminalOutput::Ack { in_seq_acked })
                .is_err()
            {
                return retire_slow_stream(
                    connection,
                    attachments,
                    routes,
                    attachment_id,
                    stream_id,
                )
                .await;
            }
            true
        }
        Incoming::Close { stream_id, code } => {
            let Some(attachment_id) = routes.remove(&stream_id) else {
                return true;
            };
            let Some(attachment) = attachments.remove(&attachment_id) else {
                return false;
            };
            // Retirement is local even when the consumer has already dropped or filled its queue.
            let _ = attachment.output.try_send(TerminalOutput::Closed { code });
            true
        }
        Incoming::Ping { nonce, sent_us } => {
            write_frame(connection, CONTROL_STREAM, &Frame::Pong { nonce, sent_us }).await
        }
        Incoming::ControlEvent | Incoming::SessionInventory(_) => true,
        Incoming::Disconnected | Incoming::Hello { .. } => false,
    }
}

/// A full or disconnected consumer retires only its attachment. The PTY/ring remain
/// in the shim; reconnect can catch up from the browser's last delivered offset.
async fn retire_slow_stream(
    connection: &mut AgentConnection,
    attachments: &mut HashMap<u64, AttachmentState>,
    routes: &mut HashMap<u32, u64>,
    attachment_id: u64,
    stream_id: u32,
) -> bool {
    attachments.remove(&attachment_id);
    routes.remove(&stream_id);
    write_frame(
        connection,
        stream_id,
        &Frame::Close {
            code: 1013,
            reason: "reader fell behind; reattach",
        },
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInventoryEvent {
    #[serde(rename = "type")]
    kind: String,
    session_ids: Vec<uuid::Uuid>,
}

/// Accept only the agent's bounded, full live-shim snapshot on the control stream.
fn decode_session_inventory(event: &[u8]) -> Option<Vec<[u8; 16]>> {
    let snapshot: SessionInventoryEvent = serde_json::from_slice(event).ok()?;
    if snapshot.kind != "terminal.sessions.snapshot" {
        return None;
    }
    let ids: Vec<[u8; 16]> = snapshot
        .session_ids
        .into_iter()
        .map(|id| *id.as_bytes())
        .collect();
    let unique: std::collections::HashSet<[u8; 16]> = ids.iter().copied().collect();
    (unique.len() == ids.len()).then_some(ids)
}

/// Leave other bounded control Events available for protocol extensions.
fn is_session_inventory_event(event: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(event).is_ok_and(|value| {
        value.get("type").and_then(serde_json::Value::as_str) == Some("terminal.sessions.snapshot")
    })
}

/// Keep inventory Events separate from bounded terminal notices on the data streams.
fn decode_event(stream_id: u32, sub_id: u32, event_json: &[u8], wire: &Bytes) -> Option<Incoming> {
    if sub_id != 0 {
        return None;
    }
    if stream_id == CONTROL_STREAM {
        if is_session_inventory_event(event_json) {
            return decode_session_inventory(event_json).map(Incoming::SessionInventory);
        }
        if event_json.len() > 1024 {
            return None;
        }
        // Capability notices share the control stream with full session censuses.
        // Retain their bounded payload for the actor's independent capability watch.
        if serde_json::from_slice::<serde_json::Value>(event_json)
            .is_ok_and(|value| value["type"] == "plugin.event" || value["type"] == "plugins.resync")
        {
            return Some(Incoming::Event {
                stream_id,
                event_json: share_payload(wire, event_json)?,
            });
        }
        return Some(Incoming::ControlEvent);
    }
    if event_json.len() > 1024 {
        return None;
    }
    Some(Incoming::Event {
        stream_id,
        event_json: share_payload(wire, event_json)?,
    })
}

async fn read_incoming(connection: &mut AgentConnection) -> Option<Incoming> {
    loop {
        match decode_muxed_frame(&connection.receive) {
            Ok(decoded) => {
                let wire_len = decoded.wire_len;
                let wire = connection.receive.split_to(wire_len).freeze();
                let Ok(decoded) = decode_muxed_frame(&wire) else {
                    return None;
                };
                let stream_id = decoded.stream_id;
                let frame = match decoded.frame {
                    Frame::Result { call_id, ok, json }
                        if json.len() <= infraternal_plugin_api::channel::MAX_CONTROL_JSON =>
                    {
                        Incoming::Result {
                            call_id,
                            ok,
                            json: json.to_vec(),
                        }
                    }
                    Frame::Output { out_seq, bytes } => Incoming::Output {
                        stream_id,
                        out_seq,
                        bytes: share_payload(&wire, bytes)?,
                    },
                    Frame::Snapshot { out_seq, bytes } => Incoming::Snapshot {
                        stream_id,
                        out_seq,
                        bytes: share_payload(&wire, bytes)?,
                    },
                    Frame::Event { sub_id, event_json } => {
                        decode_event(stream_id, sub_id, event_json, &wire)?
                    }
                    Frame::Ack { in_seq_acked } => Incoming::Ack {
                        stream_id,
                        in_seq_acked,
                    },
                    Frame::Close { .. } if stream_id == CONTROL_STREAM => Incoming::Disconnected,
                    Frame::Close { code, .. } => Incoming::Close { stream_id, code },
                    Frame::Ping { nonce, sent_us } if stream_id == CONTROL_STREAM => {
                        Incoming::Ping { nonce, sent_us }
                    }
                    _ => return None,
                };
                if matches!(&frame, Incoming::Result { .. }) && stream_id != CONTROL_STREAM {
                    return None;
                }
                if matches!(
                    &frame,
                    Incoming::Output { .. }
                        | Incoming::Snapshot { .. }
                        | Incoming::Ack { .. }
                        | Incoming::Close { .. }
                ) && (stream_id == CONTROL_STREAM || stream_id % 2 != 0)
                {
                    return None;
                }
                // decode_event admits only capability notices as control-stream
                // Event payloads; ordinary terminal Events still require an even stream.
                if matches!(&frame, Incoming::Event {stream_id, ..} if stream_id % 2 != 0) {
                    return None;
                }
                return Some(frame);
            }
            Err(DecodeError::Incomplete) => {}
            Err(_) => return None,
        }
        if connection.receive.len() >= MAX_BUFFERED_WIRE {
            return None;
        }
        let read = match &mut connection.peer {
            Peer::Local { reader, .. } => {
                let count = reader.read(&mut connection.scratch).await.ok()?;
                connection
                    .receive
                    .extend_from_slice(&connection.scratch[..count]);
                count
            }
            #[cfg(feature = "remote")]
            Peer::Remote(link) => link
                .read(&mut connection.receive, &mut connection.scratch)
                .await
                .ok()?,
        };
        if read == 0 {
            return Some(Incoming::Disconnected);
        }
    }
}

/// Keep terminal payloads backed by the receive allocation instead of copying each frame.
fn share_payload(wire: &Bytes, payload: &[u8]) -> Option<Bytes> {
    if payload.is_empty() {
        return Some(Bytes::new());
    }
    let start = (payload.as_ptr() as usize).checked_sub(wire.as_ptr() as usize)?;
    let end = start.checked_add(payload.len())?;
    (end <= wire.len()).then(|| wire.slice(start..end))
}

async fn write_frame(connection: &mut AgentConnection, stream_id: u32, frame: &Frame<'_>) -> bool {
    let (peer, encode) = (&mut connection.peer, &mut connection.encode);
    if encode_muxed_frame_into(stream_id, frame, encode).is_err() {
        return false;
    }
    matches!(
        tokio::time::timeout(Duration::from_secs(1), async {
            match peer {
                Peer::Local { writer, .. } => writer.write_all(encode).await,
                #[cfg(feature = "remote")]
                Peer::Remote(link) => link.write(stream_id, frame, encode).await,
            }
        })
        .await,
        Ok(Ok(()))
    )
}

async fn connection_lost(
    mut connection: AgentConnection,
    _attachments: &mut HashMap<u64, AttachmentState>,
    routes: &mut HashMap<u32, u64>,
    pending: &mut HashMap<u32, PendingCall>,
) {
    routes.clear();
    for (_, call) in pending.drain() {
        call.refuse(AgentError::Unavailable);
    }
    if let Some(pid) = connection.pid.take() {
        stop_child(pid).await;
    }
}

async fn cleanup_connection(mut connection: AgentConnection) {
    if let Some(pid) = connection.pid.take() {
        stop_child(pid).await;
    }
}

fn decode_session_id(value: &str) -> Option<[u8; 16]> {
    let parsed = uuid::Uuid::parse_str(value).ok()?;
    // Accept the real daemon's canonical UUID and the existing 32-hex core
    // result, but reject alternate spellings rather than normalizing authority.
    (value == parsed.simple().to_string() || value == parsed.hyphenated().to_string())
        .then(|| parsed.into_bytes())
}

#[cfg(unix)]
fn spawn_socketpair_agent(
    executable: &std::path::Path,
) -> Result<(UnixStream, Option<nix::unistd::Pid>), AgentError> {
    use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, posix_spawn};
    use std::{
        ffi::CString,
        os::fd::AsRawFd,
        os::unix::{ffi::OsStrExt, net::UnixStream as StdUnixStream},
    };

    let (parent, child) = StdUnixStream::pair().map_err(|_| AgentError::Unavailable)?;
    let path =
        CString::new(executable.as_os_str().as_bytes()).map_err(|_| AgentError::Unavailable)?;
    let argv = [
        path.clone(),
        CString::new("agent").map_err(|_| AgentError::Unavailable)?,
        CString::new("--fd").map_err(|_| AgentError::Unavailable)?,
        CString::new("3").map_err(|_| AgentError::Unavailable)?,
    ];
    let environment = std::env::vars_os()
        .map(|(key, value)| {
            let mut entry = key.as_os_str().as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(entry).map_err(|_| AgentError::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let envp: Vec<_> = environment.iter().collect();
    let mut actions = PosixSpawnFileActions::init().map_err(|_| AgentError::Unavailable)?;
    let child_fd = child.as_raw_fd();
    actions
        .add_dup2(child_fd, 3)
        .map_err(|_| AgentError::Unavailable)?;
    if child_fd != 3 {
        actions
            .add_close(child_fd)
            .map_err(|_| AgentError::Unavailable)?;
    }
    // The parent may still be handling an inherited private input channel.
    // Child stdin is always explicit, independent of startup import cleanup.
    actions
        .add_open(
            0,
            std::path::Path::new("/dev/null"),
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|_| AgentError::Unavailable)?;
    let mut attributes = PosixSpawnAttr::init().map_err(|_| AgentError::Unavailable)?;
    // Runtime workers inherit the server's early blocked reload mask. Child
    // roles and PTY shells must start with their own normal signal policy.
    infraternal_shim::prepare_spawn(&mut attributes).map_err(|_| AgentError::Unavailable)?;
    let pid = posix_spawn(path.as_c_str(), &actions, &attributes, &argv, &envp)
        .map_err(|_| AgentError::Unavailable)?;
    drop(child);
    parent
        .set_nonblocking(true)
        .map_err(|_| AgentError::Unavailable)?;
    let stream = UnixStream::from_std(parent).map_err(|_| AgentError::Unavailable)?;
    tracing::debug!(
        pid = pid.as_raw(),
        "started embedded infraternal agent over inherited socketpair"
    );
    Ok((stream, Some(pid)))
}

#[cfg(not(unix))]
fn spawn_socketpair_agent(
    _executable: &std::path::Path,
) -> Result<(UnixStream, Option<nix::unistd::Pid>), AgentError> {
    Err(AgentError::Unavailable)
}

#[cfg(unix)]
async fn stop_child(pid: nix::unistd::Pid) {
    use nix::sys::{
        signal::{Signal, kill},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    };
    // Keep escalation inside the blocking task: runtime cancellation may drop
    // its async waiter, but must not cancel the SIGKILL deadline or reaping.
    let _ = tokio::task::spawn_blocking(move || {
        let _ = kill(pid, Signal::SIGTERM);
        let graceful = std::time::Instant::now() + Duration::from_secs(2);
        let final_deadline = graceful + Duration::from_secs(1);
        let mut escalated = false;
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::EINTR) => {}
                // Reap only this child. On return, no later signal can target a
                // reused PID; ECHILD also retires the identity immediately.
                _ => return,
            }
            let now = std::time::Instant::now();
            if !escalated && now >= graceful {
                let _ = kill(pid, Signal::SIGKILL);
                escalated = true;
            }
            if now >= final_deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })
    .await;
}

#[cfg(not(unix))]
async fn stop_child(_pid: nix::unistd::Pid) {}

#[cfg(test)]
#[path = "embedded_regressions.rs"]
mod regressions;

#[cfg(test)]
#[path = "session_exit_latency_tests.rs"]
mod exit_latency_tests;
