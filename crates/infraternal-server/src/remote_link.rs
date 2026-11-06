//! Adapts authenticated remote transports to the existing server terminal actor, retaining durable writer ids and raw native frames [64][130], #78.

#[cfg(any(test, feature = "native-streams"))]
use crate::embedded::AgentError;
#[cfg(any(test, feature = "native-streams"))]
use crate::remote_guard::AuthorityGuard;
use axum::extract::ws::{Message as WebSocketMessage, WebSocket};
use bytes::{Bytes, BytesMut};
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use infraternal_agent::{
    channel::Channel,
    remote_native::NativeChannel,
    remote_quic::{self, BindingConnection},
    remote_tls::TcpTls,
    transport::{Receive, Transmit},
};
#[cfg(any(test, feature = "native-streams"))]
use infraternal_plugin_api::{
    Operation,
    streams::{DatagramLane, WireLane, WireStreamDef},
};
#[cfg(any(test, feature = "native-streams"))]
use infraternal_plugin_remote::wire_datagrams::NativeDatagrams;
use infraternal_protocol::{Frame, encode_muxed_frame_into};
#[cfg(any(test, feature = "native-streams"))]
use std::sync::{Weak, atomic::AtomicBool};
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, mpsc, watch},
    task::JoinSet,
};

// Tests observe existing ownership without extending a transport's lifetime.
#[cfg(test)]
static TEST_LINKS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<std::net::SocketAddr, std::sync::Weak<RemoteLink>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Remote TCP keeps the existing mux; native QUIC fans raw streams into bounded actor delivery.
enum LinkTransport {
    #[cfg(feature = "ssh")]
    Ssh {
        channel: infraternal_plugin_ssh::duplex::Duplex,
        _session: Arc<dyn infraternal_plugin_ssh::transport::SshSession>,
        prefix: Mutex<Option<Bytes>>,
    },
    Tcp {
        channel: TcpTls,
        receive: Mutex<Receive>,
        prefix: Mutex<Option<Bytes>>,
    },
    WebSocket {
        channel: WebSocketChannel,
        receive: Mutex<Receive>,
        prefix: Mutex<Option<Bytes>>,
    },
    Quic(QuicLink),
}

/// The app-listener link preserves the same bounded muxed frames as remote TCP.
struct WebSocketChannel {
    writer: Mutex<SplitSink<WebSocket, WebSocketMessage>>,
    reader: Mutex<SplitStream<WebSocket>>,
    pending: Mutex<Bytes>,
    retired: watch::Sender<bool>,
}

struct RetireWebSocketWrite<'a> {
    retired: &'a watch::Sender<bool>,
    complete: bool,
}
impl Drop for RetireWebSocketWrite<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.retired.send_replace(true);
        }
    }
}

impl WebSocketChannel {
    fn new(socket: WebSocket) -> Self {
        let (writer, reader) = socket.split();
        Self {
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
            pending: Mutex::new(Bytes::new()),
            retired: watch::channel(false).0,
        }
    }
    async fn send_control(&self, message: WebSocketMessage) -> io::Result<()> {
        let mut writer = self.writer.lock().await;
        tokio::time::timeout(Duration::from_secs(5), writer.send(message))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::other)
    }
}

impl Channel for WebSocketChannel {
    fn frame_timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(5))
    }
    fn retire(&self) {
        self.retired.send_replace(true);
    }
    async fn read(&self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut retired = self.retired.subscribe();
        if *retired.borrow() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut pending = self.pending.lock().await;
        if !pending.is_empty() {
            let count = target.len().min(pending.len());
            target[..count].copy_from_slice(&pending[..count]);
            *pending = pending.slice(count..);
            return Ok(count);
        }
        drop(pending);
        let mut reader = self.reader.lock().await;
        let mut keepalive = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(25),
            Duration::from_secs(25),
        );
        loop {
            tokio::select! {
                biased;
                _ = retired.changed() => return Err(io::ErrorKind::BrokenPipe.into()),
                _ = keepalive.tick() => self.send_control(WebSocketMessage::Ping(Bytes::new())).await?,
                message = reader.next() => match message {
                    Some(Ok(WebSocketMessage::Binary(data))) => {
                        if data.is_empty() { continue; }
                        let count = target.len().min(data.len());
                        target[..count].copy_from_slice(&data[..count]);
                        *self.pending.lock().await = data.slice(count..);
                        return Ok(count);
                    }
                    Some(Ok(WebSocketMessage::Ping(data))) => {
                        self.send_control(WebSocketMessage::Pong(data)).await?;
                    }
                    Some(Ok(WebSocketMessage::Pong(_))) => {},
                    Some(Ok(WebSocketMessage::Close(_))) | None => {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    Some(Ok(_)) => return Err(io::ErrorKind::InvalidData.into()),
                    Some(Err(error)) => return Err(io::Error::other(error)),
                }
            }
        }
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > infraternal_protocol::MAX_FRAME_LEN + 64 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut retired = self.retired.subscribe();
        if *retired.borrow() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut writer = tokio::select! {
            biased;
            _ = retired.changed() => return Err(io::ErrorKind::BrokenPipe.into()),
            writer = self.writer.lock() => writer,
        };
        let mut guard = RetireWebSocketWrite {
            retired: &self.retired,
            complete: false,
        };
        let result = tokio::select! {
            biased;
            _ = retired.changed() => Err(io::ErrorKind::BrokenPipe.into()),
            result = tokio::time::timeout(
                Duration::from_secs(5),
                writer.send(WebSocketMessage::Binary(Bytes::copy_from_slice(bytes))),
            ) => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(io::Error::other(error)),
                Err(_) => Err(io::ErrorKind::TimedOut.into()),
            },
        };
        guard.complete = result.is_ok();
        result
    }
}

/// Drain the authenticated SSH greeting prefix before reading later channel bytes.
#[cfg(feature = "ssh")]
async fn read_ssh_transport(
    channel: &infraternal_plugin_ssh::duplex::Duplex,
    prefix: &Mutex<Option<Bytes>>,
    target: &mut BytesMut,
    scratch: &mut [u8],
) -> io::Result<usize> {
    if let Some(prefix) = prefix.lock().await.take() {
        target.extend_from_slice(&prefix);
        return Ok(prefix.len());
    }
    let count = channel.read(scratch).await?;
    target.extend_from_slice(&scratch[..count]);
    Ok(count)
}

/// Preserve greeting prefixes and decode the bounded TCP-style mux for app-listener links.
async fn read_mux_transport(
    channel: &impl Channel,
    receive: &Mutex<Receive>,
    prefix: &Mutex<Option<Bytes>>,
    target: &mut BytesMut,
    observe: impl FnOnce(u32, &Frame),
) -> io::Result<usize> {
    if let Some(prefix) = prefix.lock().await.take() {
        target.extend_from_slice(&prefix);
        return Ok(prefix.len());
    }
    let mut receive = receive.lock().await;
    let decoded = receive.next(channel).await?;
    observe(decoded.stream_id, &decoded.frame);
    let mut bytes = Vec::new();
    encode_muxed_frame_into(decoded.stream_id, &decoded.frame, &mut bytes)
        .map_err(io::Error::other)?;
    let count = bytes.len();
    target.extend_from_slice(&bytes);
    Ok(count)
}

/// Authority is attached only after durable mTLS admission and guards both
/// transport directions; direct actor tests may still construct an unguarded link.
pub(crate) struct RemoteLink {
    path_proof: Option<infraternal_plugin_remote::remote_bindings::ConnectionProof>,
    // TCP has no Quinn peer accessor. Retain only its public authenticated tuple
    // in opt-in tests; this field is absent from every shipping build.
    #[cfg(all(test, feature = "mesh-transport-proof"))]
    diagnostic_peer: Option<std::net::SocketAddr>,
    transport: LinkTransport,
    authority: Option<crate::remote_guard::AuthorityGuard>,
    renewal: std::sync::atomic::AtomicBool,
    peer_caps: AtomicU64,
    greeting_sent: bool,
    priming: Arc<std::sync::Mutex<Option<crate::remote_standby::Priming>>>,
}

/// Covers cancellation while actor admission is still queued, before preparation owns it.
pub(crate) struct PrimingAdmission {
    pub(crate) state: Arc<std::sync::Mutex<Option<crate::remote_standby::Priming>>>,
    pub(crate) connection: Option<quinn::Connection>,
    pub(crate) admitted: bool,
}
impl Drop for PrimingAdmission {
    fn drop(&mut self) {
        if self.admitted {
            return;
        }
        let priming = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if priming.is_some()
            && let Some(connection) = &self.connection
        {
            connection.close(0u32.into(), b"priming admission cancelled");
        }
        // The unadmitted queue item retains no identity parking slot after this drop.
    }
}

pub(crate) struct QuicLink {
    connection: quinn::Connection,
    binding: StdMutex<Option<Arc<BindingConnection>>>,
    #[cfg(any(test, feature = "native-streams"))]
    streams: Arc<StdMutex<Streams>>,
    #[cfg(not(any(test, feature = "native-streams")))]
    streams: StdMutex<Streams>,
    // Terminal-only opens retain the serialized binding admission; only native
    // builds need caller-owned concurrent reservations and shared metadata.
    #[cfg(not(any(test, feature = "native-streams")))]
    terminal_open: Mutex<()>,
    #[cfg(any(test, feature = "native-streams"))]
    datagrams: Arc<NativeDatagrams>,
    incoming: Mutex<Incoming>,
    _control: mpsc::Sender<Packet>,
    output: mpsc::Sender<Packet>,
    pumps: Mutex<JoinSet<()>>,
    control_reads: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    delivery_validation: Mutex<()>,
}

// Native delivery retains channel identity so queued old frames cannot affect
// a rebound durable writer. The two existing queues remain bounded.
struct Packet {
    bytes: Bytes,
    source: Arc<NativeChannel>,
}

// Reliable terminal and plugin lanes share one metadata reserve. Weak plugin
// entries cannot retain a caller-owned lane or its datagram admission.
#[derive(Default)]
struct Streams {
    terminal: HashMap<u32, Arc<NativeChannel>>,
    #[cfg(any(test, feature = "native-streams"))]
    native: HashMap<u32, NativeLease>,
    #[cfg(any(test, feature = "native-streams"))]
    pending: HashMap<u32, u64>,
    closed: bool,
}
#[cfg(any(test, feature = "native-streams"))]
struct NativeLease {
    lane: Weak<dyn WireLane>,
    retired: Arc<AtomicBool>,
    capability: u64,
}
impl Streams {
    #[cfg_attr(not(any(test, feature = "native-streams")), allow(clippy::unused_self))]
    fn owns_native(&self, stream: u32) -> bool {
        #[cfg(any(test, feature = "native-streams"))]
        {
            self.native.contains_key(&stream)
        }
        #[cfg(not(any(test, feature = "native-streams")))]
        {
            let _ = stream;
            false
        }
    }
    #[cfg(any(test, feature = "native-streams"))]
    fn provider_full(&self, capability: u64, maximum: usize) -> bool {
        capability != 0
            && self
                .native
                .values()
                .filter(|lease| lease.capability == capability)
                .count()
                + self
                    .pending
                    .values()
                    .filter(|pending| **pending == capability)
                    .count()
                >= maximum
    }
    #[cfg(any(test, feature = "native-streams"))]
    fn prune(&mut self) {
        #[cfg(any(test, feature = "native-streams"))]
        self.native.retain(|_, lease| {
            lease.lane.strong_count() != 0 && !lease.retired.load(Ordering::Acquire)
        });
    }
    fn full(&self) -> bool {
        #[cfg(not(any(test, feature = "native-streams")))]
        let native = 0;
        #[cfg(any(test, feature = "native-streams"))]
        let native = self.native.len();
        #[cfg(any(test, feature = "native-streams"))]
        let pending = self.pending.len();
        #[cfg(not(any(test, feature = "native-streams")))]
        let pending = 0;
        self.terminal.len().saturating_sub(1) + native + pending
            >= infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS
    }
    fn retire(&self) {
        for channel in self.terminal.values() {
            channel.retire();
        }
        #[cfg(any(test, feature = "native-streams"))]
        for lease in self.native.values() {
            if let Some(lane) = lease.lane.upgrade() {
                lane.retire();
            }
        }
    }
}

/// A slot is owned before the asynchronous opener begins. Cancellation releases
/// the slot synchronously, without retaining the enclosing QUIC connection.
#[cfg(any(test, feature = "native-streams"))]
pub(crate) struct WireOpening {
    definition: &'static WireStreamDef,
    datagram_identity: Option<[u8; 16]>,
    reservation: Reservation,
}
#[cfg(any(test, feature = "native-streams"))]
struct Reservation {
    streams: Arc<StdMutex<Streams>>,
    stream_id: u32,
}
#[cfg(any(test, feature = "native-streams"))]
impl Drop for Reservation {
    fn drop(&mut self) {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(&self.stream_id);
    }
}
impl QuicLink {
    fn streams(&self) -> std::sync::MutexGuard<'_, Streams> {
        // This mutex protects ordinary Rust maps; unwind cannot corrupt their
        // invariants. It is never held across transport I/O or an await.
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn retire(&self) {
        let mut streams = self.streams();
        streams.closed = true;
        streams.retire();
        self.connection.close(0u32.into(), b"");
    }
    fn binding(&self) -> io::Result<Arc<BindingConnection>> {
        self.binding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
    }
    #[cfg(any(test, feature = "native-streams"))]
    fn reserve(
        &self,
        stream_id: u32,
        capability: u64,
        maximum: usize,
    ) -> Result<Reservation, AgentError> {
        let mut streams = self.streams();
        #[cfg(any(test, feature = "native-streams"))]
        streams.prune();
        if streams.closed
            || streams.full()
            || streams.terminal.contains_key(&stream_id)
            || streams.owns_native(stream_id)
            || streams.pending.contains_key(&stream_id)
            || streams.provider_full(capability, maximum)
        {
            return Err(AgentError::Rejected);
        }
        streams.pending.insert(stream_id, capability);
        Ok(Reservation {
            streams: self.streams.clone(),
            stream_id,
        })
    }
    async fn terminal_channel(
        &self,
        stream: u32,
        frame: &Frame<'_>,
        primed: bool,
    ) -> io::Result<Arc<NativeChannel>> {
        #[cfg(not(any(test, feature = "native-streams")))]
        let _opening = self.terminal_open.lock().await;
        let existing = self.streams().terminal.get(&stream).cloned();
        if let Some(channel) = existing {
            return Ok(channel);
        }
        if !matches!(frame, Frame::AttachTerm { .. }) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        #[cfg(not(any(test, feature = "native-streams")))]
        {
            let streams = self.streams();
            if streams.closed || streams.full() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        #[cfg(any(test, feature = "native-streams"))]
        let _reservation = self
            .reserve(stream, 0, 0)
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let binding = self.binding()?;
        let bound = remote_quic::open_bound(&binding, stream).await?;
        let channel = Arc::new(NativeChannel::terminal(bound)?);
        if primed {
            // Standby intent precedes Attach on this bound stream, including
            // setup that was already admitted when promotion starts.
            Transmit::default()
                .send(
                    channel.as_ref(),
                    stream,
                    &Frame::Call {
                        call_id: 0,
                        action_id: "transport.prime",
                        input_json: b"{}",
                    },
                )
                .await?;
        }

        let mut pumps = self.pumps.lock().await;
        while pumps.try_join_next().is_some() {}
        if pumps.len() > infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        {
            let mut streams = self.streams();
            if streams.closed {
                channel.retire();
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            #[cfg(any(test, feature = "native-streams"))]
            streams.pending.remove(&stream);
            streams.terminal.insert(stream, channel.clone());
        }
        pumps.spawn(pump(
            channel.clone(),
            self.output.clone(),
            self.connection.clone(),
            Receive::default(),
        ));
        Ok(channel)
    }
}

struct Incoming {
    control: mpsc::Receiver<Packet>,
    bulk: mpsc::Receiver<Packet>,
    // Actor select may cancel while channel-identity validation awaits the map.
    // Ownership stays here until delivery or explicit stale-frame retirement.
    pending: Option<Packet>,
    // A cancelled read may already own control when its outgoing FIFO fills.
    // Keep that one ordered frame while independent terminal delivery continues.
    held_control: Option<Packet>,
}

impl Drop for QuicLink {
    fn drop(&mut self) {
        self.retire();
        // JoinSet aborts every reader; no child task retains an orphaned transport.
    }
}

impl RemoteLink {
    /// The admitted logical QUIC tuple; TCP and SSH channels cannot move below their transport.
    pub(crate) fn peer_address(&self) -> Option<std::net::SocketAddr> {
        match &self.transport {
            LinkTransport::Quic(link) => Some(link.connection.remote_address()),
            LinkTransport::Tcp { .. } => None,
            LinkTransport::WebSocket { .. } => None,
            #[cfg(feature = "ssh")]
            LinkTransport::Ssh { .. } => None,
        }
    }
    /// Capacity refusals precede terminal route mutation. Pending plugin opens
    /// have already reserved their shared metadata slot in the actor turn.
    pub(crate) fn admits_terminal(&self, stream_id: u32) -> bool {
        let LinkTransport::Quic(link) = &self.transport else {
            return true;
        };
        let streams = link.streams();
        #[cfg(any(test, feature = "native-streams"))]
        let mut streams = streams;
        #[cfg(any(test, feature = "native-streams"))]
        streams.prune();
        #[cfg(any(test, feature = "native-streams"))]
        let pending = streams.pending.contains_key(&stream_id);
        #[cfg(not(any(test, feature = "native-streams")))]
        let pending = false;
        !streams.closed
            && !streams.owns_native(stream_id)
            && !pending
            && (streams.terminal.contains_key(&stream_id) || !streams.full())
    }
    /// Validate and reserve before starting an opening task. No transport I/O
    /// or ledger await can monopolize the actor or evade the shared lane bound.
    #[cfg(any(test, feature = "native-streams"))]
    pub(crate) fn prepare_wire(
        &self,
        definition: &'static WireStreamDef,
        stream_id: u32,
        opening: &[u8],
    ) -> Result<WireOpening, AgentError> {
        definition.validate().map_err(|_| AgentError::Rejected)?;
        let canonical = compiled_wire_definitions()
            .find(|compiled| same_definition(compiled, definition))
            .ok_or(AgentError::Unsupported)?;
        let LinkTransport::Quic(link) = &self.transport else {
            return Err(AgentError::Unsupported);
        };
        if self.peer_caps.load(Ordering::Acquire) & canonical.capability == 0 {
            return Err(AgentError::Unsupported);
        }
        let decoded =
            infraternal_protocol::decode_frame(opening).map_err(|_| AgentError::Rejected)?;
        let tag = opening
            .iter()
            .position(|byte| byte & 0x80 == 0)
            .and_then(|last| opening.get(last + 1));
        if decoded.wire_len != opening.len()
            || tag != Some(&canonical.opening_tag)
            || stream_id == 0
            || stream_id & 1 != 0
        {
            return Err(AgentError::Rejected);
        }
        if !self.authority.as_ref().is_some_and(AuthorityGuard::permits) {
            return Err(AgentError::Unavailable);
        }
        let datagram_identity =
            if canonical.datagram_tag.is_some() && link.connection.max_datagram_size().is_some() {
                Some(
                    canonical
                        .opening_identity
                        .and_then(|decode| decode(opening))
                        .ok_or(AgentError::Rejected)?,
                )
            } else {
                None
            };
        let reservation = link.reserve(stream_id, canonical.capability, canonical.max_streams)?;
        Ok(WireOpening {
            definition: canonical,
            datagram_identity,
            reservation,
        })
    }
    /// Finish one reserved opening off the actor's control loop. The returned
    /// owned lane has already sent its complete opening under host authority.
    #[cfg(any(test, feature = "native-streams"))]
    pub(crate) async fn open_wire(
        &self,
        admission: WireOpening,
        opening: &[u8],
    ) -> Result<Arc<dyn WireLane>, AgentError> {
        let LinkTransport::Quic(link) = &self.transport else {
            return Err(AgentError::Unsupported);
        };
        let authority = self.authority.as_ref().ok_or(AgentError::Unavailable)?;
        authority
            .admit_operation()
            .await
            .map_err(|_| AgentError::Unavailable)?;
        let canonical = admission.definition;
        let stream_id = admission.reservation.stream_id;
        let binding = link.binding().map_err(|_| AgentError::Unsupported)?;
        let bound = tokio::select! { biased;
            () = authority.cancelled() => return Err(AgentError::Unavailable),
            bound = remote_quic::open_bound(&binding, stream_id) => bound.map_err(|_| AgentError::Unavailable)?,
        };
        let channel = NativeChannel::terminal(bound).map_err(|_| AgentError::Unavailable)?;
        let datagrams = admission
            .datagram_identity
            .map(|identity| {
                let inner = link
                    .datagrams
                    .admit(canonical, identity)
                    .map_err(|_| AgentError::Rejected)?;
                Ok::<Arc<dyn DatagramLane>, AgentError>(Arc::new(GuardedDatagrams {
                    inner,
                    authority: authority.clone(),
                }))
            })
            .transpose()?;
        let retired = Arc::new(AtomicBool::new(false));
        let lane: Arc<dyn WireLane> = Arc::new(
            infraternal_agent::wire::Lane::new(
                GuardedChannel {
                    channel,
                    authority: authority.clone(),
                    retired: retired.clone(),
                },
                canonical,
                infraternal_agent::wire::Side::Requester,
                datagrams,
            )
            .map_err(|_| AgentError::Rejected)?,
        );
        lane.send(opening)
            .await
            .map_err(|()| AgentError::Unavailable)?;
        let mut streams = link.streams();
        if streams.closed {
            lane.retire();
            return Err(AgentError::Unavailable);
        }
        streams.pending.remove(&stream_id);
        streams.native.insert(
            stream_id,
            NativeLease {
                lane: Arc::downgrade(&lane),
                retired,
                capability: canonical.capability,
            },
        );
        Ok(lane)
    }

    #[cfg(feature = "ssh")]
    pub(crate) fn ssh_backed(&self) -> bool {
        matches!(&self.transport, LinkTransport::Ssh { .. })
    }
    pub(crate) fn authorize(mut self, authority: crate::remote_guard::AuthorityGuard) -> Self {
        self.authority = Some(authority);
        self
    }
    pub(crate) async fn admit_operation(&self) -> io::Result<()> {
        match &self.authority {
            Some(authority) => authority.admit_operation().await,
            None => Ok(()),
        }
    }
    pub(crate) fn retire(&self) {
        match &self.transport {
            #[cfg(feature = "ssh")]
            LinkTransport::Ssh { .. } => {}
            LinkTransport::Tcp { channel, .. } => channel.retire(),
            LinkTransport::WebSocket { channel, .. } => channel.retire(),
            LinkTransport::Quic(link) => link.retire(),
        }
    }
    pub(crate) async fn read(
        &self,
        target: &mut BytesMut,
        scratch: &mut [u8],
    ) -> io::Result<usize> {
        let Some(authority) = &self.authority else {
            return self.read_transport(target, scratch).await;
        };
        if !authority.permits() {
            self.retire();
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        tokio::select! {
            biased;
            () = authority.cancelled() => {
                self.retire();
                Err(io::ErrorKind::PermissionDenied.into())
            },
            result = self.read_transport(target, scratch) => result,
        }
    }
    pub(crate) async fn write(
        &self,
        stream: u32,
        frame: &Frame<'_>,
        muxed: &[u8],
    ) -> io::Result<()> {
        let Some(authority) = &self.authority else {
            return self.write_transport(stream, frame, muxed).await;
        };
        if !authority.permits() {
            self.retire();
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let _permit = authority.write_permit().await?;
        tokio::select! {
            biased;
            () = authority.cancelled() => {
                self.retire();
                Err(io::ErrorKind::PermissionDenied.into())
            },
            result = self.write_transport(stream, frame, muxed) => result,
        }
    }

    #[cfg(feature = "ssh")]
    pub(crate) async fn ssh(
        channel: infraternal_plugin_ssh::duplex::Duplex,
        session: Arc<dyn infraternal_plugin_ssh::transport::SshSession>,
    ) -> io::Result<Self> {
        // Publication already carries Hello behind the session receipt in one
        // write. Read that same flight before admitting capabilities, retaining
        // every coalesced byte for the actor's ordinary greeting and replay.
        let mut prefix = BytesMut::with_capacity(256);
        let peer_caps = tokio::time::timeout(Duration::from_secs(5), async {
            let mut scratch = [0; 1024];
            loop {
                match infraternal_protocol::decode_muxed_frame(&prefix) {
                    Ok(decoded) => {
                        if decoded.stream_id != 0 {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        let Frame::Hello {
                            version: 1, caps, ..
                        } = decoded.frame
                        else {
                            return Err(io::ErrorKind::InvalidData.into());
                        };
                        return Ok::<_, io::Error>(caps);
                    }
                    Err(infraternal_protocol::DecodeError::Incomplete) => {}
                    Err(_) => return Err(io::ErrorKind::InvalidData.into()),
                }
                // Two canonical u32 varints add at most ten prefix bytes; keep
                // the wire's existing frame bound, including long client info.
                let remaining =
                    (infraternal_protocol::MAX_FRAME_LEN + 10).saturating_sub(prefix.len());
                if remaining == 0 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let limit = remaining.min(scratch.len());
                let count = channel.read(&mut scratch[..limit]).await?;
                if count == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                prefix.extend_from_slice(&scratch[..count]);
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        Ok(Self {
            path_proof: None,
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            diagnostic_peer: None,
            transport: LinkTransport::Ssh {
                channel,
                _session: session,
                prefix: Mutex::new(Some(prefix.freeze())),
            },
            authority: None,
            renewal: std::sync::atomic::AtomicBool::new(false),
            peer_caps: peer_caps.into(),
            greeting_sent: false,
            priming: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) async fn tcp(channel: TcpTls) -> io::Result<Self> {
        Self::tcp_admitted(channel, None).await
    }
    pub(crate) async fn tcp_admitted(
        channel: TcpTls,
        mut admission: Option<&mut crate::remote_standby::Admission>,
    ) -> io::Result<Self> {
        let mut receive = Receive::default();
        let (prefix, greeting_sent) =
            greeting(&channel, &mut receive, admission.as_deref_mut()).await?;
        let peer_caps = peer_caps(&prefix);
        // TLS losers in the outgoing dial race send no application greeting;
        // they must never supersede the winning host transport in the registry.
        Ok(Self {
            path_proof: None,
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            diagnostic_peer: None,
            transport: LinkTransport::Tcp {
                channel,
                receive: Mutex::new(receive),
                prefix: Mutex::new(Some(Bytes::from(prefix))),
            },
            authority: None,
            renewal: std::sync::atomic::AtomicBool::new(false),
            peer_caps: AtomicU64::new(peer_caps),
            greeting_sent,
            priming: Arc::new(std::sync::Mutex::new(
                admission.and_then(|admission| admission.priming.take()),
            )),
        })
    }
    /// Admit a key-proved app-listener socket using the existing mux and actor greeting.
    pub(crate) async fn websocket(socket: WebSocket) -> io::Result<Self> {
        let channel = WebSocketChannel::new(socket);
        let mut receive = Receive::default();
        let (prefix, greeting_sent) = greeting(&channel, &mut receive, None).await?;
        let peer_caps = peer_caps(&prefix);
        Ok(Self {
            path_proof: None,
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            diagnostic_peer: None,
            transport: LinkTransport::WebSocket {
                channel,
                receive: Mutex::new(receive),
                prefix: Mutex::new(Some(Bytes::from(prefix))),
            },
            authority: None,
            renewal: std::sync::atomic::AtomicBool::new(false),
            peer_caps: AtomicU64::new(peer_caps),
            greeting_sent,
            priming: Arc::new(std::sync::Mutex::new(None)),
        })
    }
    #[cfg(test)]
    pub(crate) async fn quic(connection: quinn::Connection) -> io::Result<Self> {
        Self::quic_admitted(connection, None).await
    }
    pub(crate) async fn quic_admitted(
        connection: quinn::Connection,
        mut admission: Option<&mut crate::remote_standby::Admission>,
    ) -> io::Result<Self> {
        let (send, receive) = tokio::time::timeout(Duration::from_secs(5), connection.accept_bi())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::other)?;
        let control = Arc::new(NativeChannel::control(send, receive)?);
        let mut receive = Receive::default();
        let (prefix, greeting_sent) =
            greeting(control.as_ref(), &mut receive, admission.as_deref_mut()).await?;
        let peer_caps = peer_caps(&prefix);
        let hello = infraternal_protocol::decode_muxed_frame(&prefix).map_err(io::Error::other)?;
        remote_quic::negotiate_binding(&connection, &hello.frame)?;
        let (output, bulk) = mpsc::channel(32);
        let (control_output, control_input) = mpsc::channel(8);
        control_output
            .try_send(Packet {
                bytes: Bytes::from(prefix),
                source: control.clone(),
            })
            .map_err(io::Error::other)?;
        let incoming = Incoming {
            control: control_input,
            bulk,
            pending: None,
            held_control: None,
        };
        let mut pumps = JoinSet::new();
        pumps.spawn(pump(
            control.clone(),
            control_output.clone(),
            connection.clone(),
            receive,
        ));
        Ok(Self {
            path_proof: None,
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            diagnostic_peer: None,
            transport: LinkTransport::Quic(QuicLink {
                #[cfg(any(test, feature = "native-streams"))]
                datagrams: NativeDatagrams::new(connection.clone()),
                connection,
                binding: StdMutex::new(None),
                #[cfg(not(any(test, feature = "native-streams")))]
                terminal_open: Mutex::new(()),
                #[cfg(not(any(test, feature = "native-streams")))]
                streams: StdMutex::new(Streams {
                    terminal: HashMap::from([(0, control)]),
                    ..Streams::default()
                }),
                #[cfg(any(test, feature = "native-streams"))]
                streams: Arc::new(StdMutex::new(Streams {
                    terminal: HashMap::from([(0, control)]),
                    #[cfg(any(test, feature = "native-streams"))]
                    native: HashMap::new(),
                    pending: HashMap::new(),
                    closed: false,
                })),
                incoming: Mutex::new(incoming),
                _control: control_output,
                output,
                pumps: Mutex::new(pumps),
                control_reads: std::sync::atomic::AtomicBool::new(true),
                #[cfg(test)]
                delivery_validation: Mutex::new(()),
            }),
            authority: None,
            renewal: std::sync::atomic::AtomicBool::new(false),
            peer_caps: AtomicU64::new(peer_caps),
            greeting_sent,
            priming: Arc::new(std::sync::Mutex::new(
                admission.and_then(|admission| admission.priming.take()),
            )),
        })
    }

    /// Keep physical proof service with the admitted transport, including queue
    /// cancellation and link replacement; the durable host actor outlives both.
    pub(crate) fn prove_paths(
        &mut self,
        bindings: &Arc<infraternal_plugin_remote::remote_bindings::Bindings>,
    ) -> io::Result<()> {
        if let LinkTransport::Quic(link) = &self.transport {
            self.path_proof = Some(bindings.connection_proof(&link.connection)?);
        }
        Ok(())
    }

    /// Public TCP coordinates label authenticated observations, never authority
    /// or packet provenance for unrestricted terminal bytes.
    #[cfg(all(test, feature = "mesh-transport-proof"))]
    pub(crate) fn with_diagnostic_peer(mut self, peer: std::net::SocketAddr) -> Self {
        self.diagnostic_peer = Some(peer);
        self
    }

    async fn read_transport(
        &self,
        target: &mut BytesMut,
        #[allow(unused_variables)] scratch: &mut [u8],
    ) -> io::Result<usize> {
        match &self.transport {
            #[cfg(feature = "ssh")]
            LinkTransport::Ssh {
                channel, prefix, ..
            } => read_ssh_transport(channel, prefix, target, scratch).await,
            LinkTransport::Tcp {
                channel,
                receive,
                prefix,
            } => {
                #[cfg(all(test, feature = "mesh-transport-proof"))]
                {
                    let diagnostic_peer = self.diagnostic_peer;
                    read_mux_transport(channel, receive, prefix, target, |stream_id, frame| {
                        if matches!(frame, Frame::Output { bytes, .. } if !bytes.is_empty())
                            && let Some(peer) = diagnostic_peer
                        {
                            // Reuse the authenticated decoder at the pre-actor boundary.
                            crate::remote_autoswitch_probe::record(
                                crate::remote_autoswitch_probe::Kind::TerminalByte,
                                peer,
                                stream_id,
                            );
                        }
                    })
                    .await
                }
                #[cfg(not(all(test, feature = "mesh-transport-proof")))]
                {
                    read_mux_transport(channel, receive, prefix, target, |_, _| {}).await
                }
            }
            LinkTransport::WebSocket {
                channel,
                receive,
                prefix,
            } => read_mux_transport(channel, receive, prefix, target, |_, _| {}).await,
            LinkTransport::Quic(link) => loop {
                let mut incoming = link.incoming.lock().await;
                let read_control = link
                    .control_reads
                    .load(std::sync::atomic::Ordering::Relaxed);
                if !read_control
                    && incoming
                        .pending
                        .as_ref()
                        .is_some_and(|message| message.source.native_stream_id() == Some(0))
                {
                    if incoming.held_control.is_some() {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    incoming.held_control = incoming.pending.take();
                }
                if incoming.pending.is_none() {
                    incoming.pending = if read_control {
                        incoming.held_control.take()
                    } else {
                        None
                    };
                }
                if incoming.pending.is_none() {
                    incoming.pending = tokio::select! {
                        biased;
                        _ = link.connection.closed() => return Ok(0),
                        message = async {
                            let Incoming { control, bulk, .. } = &mut *incoming;
                            tokio::select! { biased; message = control.recv(), if read_control => message, message = bulk.recv() => message }
                        } => message,
                    };
                }
                let Some(message) = incoming.pending.as_ref() else {
                    return Ok(0);
                };
                let stream = message.source.native_stream_id().unwrap_or(0);
                #[cfg(test)]
                let _validation = link.delivery_validation.lock().await;
                let mut streams = link.streams();
                if !streams
                    .terminal
                    .get(&stream)
                    .is_some_and(|current| Arc::ptr_eq(current, &message.source))
                {
                    incoming.pending = None;
                    continue;
                }
                if stream != 0
                    && matches!(infraternal_protocol::decode_muxed_frame(&message.bytes), Ok(decoded) if matches!(decoded.frame, Frame::Close { .. }))
                    && let Some(channel) = streams.terminal.remove(&stream)
                {
                    channel.retire();
                }
                drop(streams);
                // No await may follow taking pending ownership until the frame
                // is appended to the actor buffer; cancellation cannot lose it.
                let Some(message) = incoming.pending.take() else {
                    return Err(io::ErrorKind::InvalidData.into());
                };
                target.extend_from_slice(&message.bytes);
                return Ok(message.bytes.len());
            },
        }
    }

    /// Backpressure belongs to the control lane, not healthy terminal streams.
    pub(crate) fn control_read_ready(&self, ready: bool) {
        if let LinkTransport::Quic(link) = &self.transport {
            link.control_reads
                .store(ready, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub(crate) async fn hold_writer_map(
        &self,
        ready: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        if let LinkTransport::Quic(link) = &self.transport {
            let _guard = link.delivery_validation.lock().await;
            let _ = ready.send(());
            let _ = release.await;
        }
    }
    #[cfg(test)]
    pub(crate) async fn control_packet_ready(&self) -> bool {
        match &self.transport {
            LinkTransport::Quic(link) => !link.incoming.lock().await.control.is_empty(),
            LinkTransport::Tcp { .. } => false,
            LinkTransport::WebSocket { .. } => false,
            #[cfg(feature = "ssh")]
            LinkTransport::Ssh { .. } => false,
        }
    }
    /// Observe bounded native ownership without waiting on an actor-held lock.
    /// Counts are streams, reader tasks, control queue, bulk queue and pending frame.
    #[cfg(test)]
    pub(crate) fn native_delivery_counts(&self) -> Option<[Option<usize>; 5]> {
        let LinkTransport::Quic(link) = &self.transport else {
            return None;
        };
        let incoming = link.incoming.try_lock().ok();
        Some([
            link.streams
                .try_lock()
                .ok()
                .map(|streams| streams.terminal.len()),
            link.pumps.try_lock().ok().map(|pumps| pumps.len()),
            incoming.as_ref().map(|incoming| incoming.control.len()),
            incoming.as_ref().map(|incoming| incoming.bulk.len()),
            incoming.as_ref().map(|incoming| {
                usize::from(incoming.pending.is_some())
                    + usize::from(incoming.held_control.is_some())
            }),
        ])
    }
    #[cfg(test)]
    pub(crate) fn register_test_probe(link: &Arc<Self>) {
        if let LinkTransport::Quic(native) = &link.transport {
            let mut probes = TEST_LINKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            probes.retain(|_, link| link.strong_count() != 0);
            probes.insert(native.connection.remote_address(), Arc::downgrade(link));
        }
    }
    #[cfg(test)]
    pub(crate) fn native_counts_for_peer(peer: std::net::SocketAddr) -> Option<[Option<usize>; 5]> {
        let link = TEST_LINKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&peer)
            .and_then(std::sync::Weak::upgrade)?;
        link.native_delivery_counts()
    }
    /// Fixture-only control backpressure; weak lookup adds no transport owner.
    #[cfg(test)]
    pub(crate) fn test_limit_send_window_for_peer(peer: std::net::SocketAddr, bytes: u64) -> bool {
        let link = TEST_LINKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&peer)
            .and_then(std::sync::Weak::upgrade);
        let Some(link) = link else {
            return false;
        };
        link.limit_send_window(bytes);
        true
    }
    #[cfg(test)]
    pub(crate) fn test_native_peer_address(&self) -> Option<std::net::SocketAddr> {
        match &self.transport {
            LinkTransport::Quic(link) => Some(link.connection.remote_address()),
            LinkTransport::Tcp { .. } => None,
            LinkTransport::WebSocket { .. } => None,
            #[cfg(feature = "ssh")]
            LinkTransport::Ssh { .. } => None,
        }
    }

    /// Observe authenticated `STOP_SENDING` before testing a late detach.
    #[cfg(test)]
    pub(crate) fn test_received_stop_sending(&self) -> Option<u64> {
        match &self.transport {
            LinkTransport::Quic(link) => Some(link.connection.stats().frame_rx.stop_sending),
            LinkTransport::Tcp { .. } => None,
            LinkTransport::WebSocket { .. } => None,
            #[cfg(feature = "ssh")]
            LinkTransport::Ssh { .. } => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn limit_send_window(&self, bytes: u64) {
        if let LinkTransport::Quic(link) = &self.transport {
            link.connection.set_send_window(bytes);
        }
    }

    pub(crate) fn priming_admission(&self) -> PrimingAdmission {
        PrimingAdmission {
            state: self.priming.clone(),
            connection: match &self.transport {
                LinkTransport::Quic(link) => Some(link.connection.clone()),
                LinkTransport::Tcp { .. } => None,
                LinkTransport::WebSocket { .. } => None,
                #[cfg(feature = "ssh")]
                LinkTransport::Ssh { .. } => None,
            },
            admitted: false,
        }
    }
    pub(crate) fn native(&self) -> bool {
        matches!(self.transport, LinkTransport::Quic(_))
    }
    pub(crate) fn primed(&self) -> bool {
        self.priming
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
    pub(crate) fn activation(&self, signal: tokio::sync::oneshot::Sender<()>) -> io::Result<()> {
        *self
            .priming
            .lock()
            .map_err(|_| io::ErrorKind::Other)?
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?
            .activation
            .lock()
            .map_err(|_| io::ErrorKind::Other)? = Some(signal);
        Ok(())
    }
    /// The actor never waits for plugin joins while publishing promotion.
    pub(crate) async fn promote(&self) -> io::Result<()> {
        self.admit_operation().await?;
        let priming = self
            .priming
            .lock()
            .map_err(|_| io::ErrorKind::Other)?
            .take()
            .ok_or(io::ErrorKind::InvalidInput)?;
        priming
            .activation
            .lock()
            .map_err(|_| io::ErrorKind::Other)?
            .take()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .send(())
            .map_err(|()| io::ErrorKind::BrokenPipe)?;
        // Dropping priming releases the parking slot after actor queue admission.
        Ok(())
    }

    /// Owns a bounded flight; an exact Attach may recreate a retired binding.
    /// Binding stays inside the flight so the actor and sibling readers keep progressing.
    pub(crate) async fn write_encoded_terminal(
        &self,
        stream: u32,
        encoded: &[u8],
    ) -> io::Result<()> {
        let LinkTransport::Quic(link) = &self.transport else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        let channel = link.streams().terminal.get(&stream).cloned();
        let write = async {
            if let Some(channel) = channel {
                return channel.write(encoded).await;
            }
            let decoded = infraternal_protocol::decode_frame(encoded)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            if decoded.wire_len != encoded.len() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if !matches!(decoded.frame, Frame::AttachTerm { .. }) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            // Promotion removed incomplete shadow owners. Only Attach may
            // establish their replacement; data cannot invent a writer binding.
            self.write_transport(stream, &decoded.frame, encoded).await
        };
        let Some(authority) = &self.authority else {
            return write.await;
        };
        let _permit = authority.write_permit().await?;
        tokio::select! {
            biased;
            () = authority.cancelled() => Err(io::ErrorKind::PermissionDenied.into()),
            result = write => result,
        }
    }

    /// Cancellation may happen before binding, so this never creates a stream.
    pub(crate) fn retire_writer(&self, stream: u32) -> std::future::Ready<()> {
        if let LinkTransport::Quic(link) = &self.transport
            && let Some(channel) = link.streams().terminal.remove(&stream)
        {
            channel.retire();
        }
        std::future::ready(())
    }

    /// Promotion joins setup first, then removes bindings no cached-ready writer owns.
    pub(crate) fn retain_writers(&self, writers: &[u32]) -> std::future::Ready<()> {
        if let LinkTransport::Quic(link) = &self.transport {
            link.streams().terminal.retain(|stream, channel| {
                let keep = *stream == 0 || writers.contains(stream);
                if !keep {
                    channel.retire();
                }
                keep
            });
        }
        std::future::ready(())
    }

    pub(crate) fn peer_capabilities(&self) -> u64 {
        self.peer_caps.load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(crate) fn supports_server_paths(&self) -> bool {
        self.peer_capabilities() & infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS != 0
    }

    pub(crate) fn supports_renewal(&self) -> bool {
        self.renewal.load(std::sync::atomic::Ordering::Acquire)
    }
    /// Whether the agent's Hello offered live host identity rotation.
    pub(crate) fn supports_identity_rotation(&self) -> bool {
        self.peer_capabilities() & infraternal_plugin_api::channel::LIVE_IDENTITY_ROTATION != 0
    }
    pub(crate) fn hello(&self, frame: &Frame<'_>) -> io::Result<()> {
        if let Frame::Hello { caps, .. } = frame {
            self.peer_caps.store(*caps, Ordering::Release);
            self.renewal.store(
                caps & infraternal_agent::remote_renewal::LIVE_RENEWAL != 0,
                std::sync::atomic::Ordering::Release,
            );
        }
        if let LinkTransport::Quic(link) = &self.transport {
            *link
                .binding
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(
                remote_quic::negotiate_binding(&link.connection, frame)?,
            ));
        }
        Ok(())
    }

    async fn write_transport(
        &self,
        stream: u32,
        frame: &Frame<'_>,
        muxed: &[u8],
    ) -> io::Result<()> {
        if self.greeting_sent && stream == 0 && matches!(frame, Frame::Hello { version: 1, .. }) {
            return Ok(());
        }
        match &self.transport {
            #[cfg(feature = "ssh")]
            LinkTransport::Ssh { channel, .. } => channel.write(muxed).await,
            LinkTransport::Tcp { channel, .. } => channel.write(muxed).await,
            LinkTransport::WebSocket { channel, .. } => channel.write(muxed).await,
            LinkTransport::Quic(link) => {
                let terminal_close = stream != 0 && matches!(frame, Frame::Close { .. });
                let existing = link.streams().terminal.get(&stream).cloned();
                let channel = if let Some(channel) = existing {
                    channel
                } else {
                    // Peer retirement may win the race with the consumer's
                    // detach. Cleanup is idempotent; other frames still need
                    // a live binding, and odd/control ids cannot invent one.
                    if terminal_close && stream & 1 == 0 {
                        #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
                        if std::env::var_os("ACCEPTANCE_STANDING_STAGES").is_some() {
                            crate::remote_autoswitch_probe::record(
                                crate::remote_autoswitch_probe::Kind::TerminalDetachAlreadyRetired,
                                link.connection.remote_address(),
                                stream,
                            );
                        }
                        return Ok(());
                    }
                    link.terminal_channel(stream, frame, self.primed()).await?
                };
                let result = Transmit::default()
                    .send(channel.as_ref(), stream, frame)
                    .await;
                if terminal_close {
                    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
                    if result.is_err() && std::env::var_os("ACCEPTANCE_STANDING_STAGES").is_some() {
                        crate::remote_autoswitch_probe::record(
                            crate::remote_autoswitch_probe::Kind::TerminalDetachWriteError,
                            link.connection.remote_address(),
                            stream,
                        );
                    }
                    // A peer can stop receiving before local detach is sent.
                    // Retire this channel even after a partial/failed Close:
                    // no later frame may follow it, and its writer-local error
                    // must not make the actor discard the host connection.
                    drop(result);
                    link.streams().terminal.remove(&stream);
                    channel.retire();
                    Ok(())
                } else {
                    result
                }
            }
        }
    }
}

fn peer_caps(prefix: &[u8]) -> u64 {
    match infraternal_protocol::decode_muxed_frame(prefix) {
        Ok(infraternal_protocol::DecodedMuxedFrame {
            frame: Frame::Hello {
                version: 1, caps, ..
            },
            ..
        }) => caps,
        _ => 0,
    }
}

/// A ledger-admitted candidate may prove liveness without replacing the host.
/// Path proof remains bounded; only an admitted optional standby wait outlives it.
async fn greeting<C: Channel>(
    channel: &C,
    receive: &mut Receive,
    admission: Option<&mut crate::remote_standby::Admission>,
) -> io::Result<(Vec<u8>, bool)> {
    let prefix = tokio::time::timeout(Duration::from_secs(5), async {
        let first = receive.next(channel).await?;
        let probe = if first.stream_id == 0 {
            match first.frame {
                Frame::Ping { nonce, sent_us } => Some((nonce, sent_us)),
                _ => None,
            }
        } else {
            None
        };
        let mut prefix = Vec::new();
        if let Some((nonce, sent_us)) = probe {
            Transmit::default()
                .send(channel, 0, &Frame::Pong { nonce, sent_us })
                .await?;
            let next = receive.next(channel).await?;
            if next.stream_id != 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            match next.frame {
                Frame::Hello { version: 1, .. } => {
                    encode_muxed_frame_into(0, &next.frame, &mut prefix)
                        .map_err(io::Error::other)?;
                }
                Frame::Call {
                    call_id: 0,
                    action_id: "transport.standby",
                    input_json,
                } => {
                    return Ok::<Option<(Vec<u8>, bool)>, io::Error>(Some((
                        Vec::new(),
                        crate::remote_standby::wants_prime(input_json)?,
                    )));
                }
                _ => return Err(io::ErrorKind::InvalidData.into()),
            }
        } else {
            if first.stream_id != 0 || !matches!(first.frame, Frame::Hello { version: 1, .. }) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            encode_muxed_frame_into(0, &first.frame, &mut prefix).map_err(io::Error::other)?;
        }
        Ok::<Option<(Vec<u8>, bool)>, io::Error>(Some((prefix, false)))
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let (prefix, prime) = prefix.ok_or(io::ErrorKind::InvalidData)?;
    if !prefix.is_empty() {
        return Ok((prefix, false));
    }
    let admission = admission.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    Ok((admission.hello(channel, receive, prime).await?, true))
}

/// Advertise only validated compiled routes; packet-supplied capability bits
/// cannot install a provider on either side of the host connection.
#[cfg(not(any(test, feature = "native-streams")))]
pub(crate) fn compiled_wire_capabilities() -> u64 {
    0
}
#[cfg(any(test, feature = "native-streams"))]
pub(crate) fn compiled_wire_capabilities() -> u64 {
    compiled_wire_definitions()
        .filter(|wire| wire.validate().is_ok())
        .fold(0, |caps, wire| caps | wire.capability)
}
#[cfg(any(test, feature = "native-streams"))]
fn compiled_wire_definitions() -> impl Iterator<Item = &'static WireStreamDef> {
    crate::compiled_plugins()
        .iter()
        .flat_map(|descriptor| descriptor.streams)
        .filter_map(|stream| stream.wire.as_ref())
}
#[cfg(any(test, feature = "native-streams"))]
fn same_definition(left: &WireStreamDef, right: &WireStreamDef) -> bool {
    left.capability == right.capability
        && left.browser_capability == right.browser_capability
        && left.opening_tag == right.opening_tag
        && left.requests == right.requests
        && left.replies == right.replies
        && left.max_streams == right.max_streams
        && left.datagram_tag == right.datagram_tag
        && same_decoder(left.opening_identity, right.opening_identity)
        && same_decoder(left.datagram_identity, right.datagram_identity)
}
#[cfg(any(test, feature = "native-streams"))]
fn same_decoder(
    left: Option<infraternal_plugin_api::streams::DatagramIdentity>,
    right: Option<infraternal_plugin_api::streams::DatagramIdentity>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => std::ptr::fn_addr_eq(left, right),
        _ => false,
    }
}

// Authority remains attached to actual reads/writes after the actor transfers
// lane ownership. A writer permit participates in durable revocation draining.
#[cfg(any(test, feature = "native-streams"))]
struct GuardedChannel {
    channel: NativeChannel,
    authority: AuthorityGuard,
    retired: Arc<AtomicBool>,
}
#[cfg(any(test, feature = "native-streams"))]
impl Channel for GuardedChannel {
    fn native_stream_id(&self) -> Option<u32> {
        self.channel.native_stream_id()
    }
    fn frame_timeout(&self) -> Option<Duration> {
        self.channel.frame_timeout()
    }
    fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.channel.retire();
    }
    async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        if !self.authority.permits() {
            self.retire();
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        tokio::select! { biased;
            () = self.authority.cancelled() => { self.retire(); Err(io::ErrorKind::PermissionDenied.into()) },
            result = self.channel.read(bytes) => {
                if self.authority.permits() { result } else { self.retire(); Err(io::ErrorKind::PermissionDenied.into()) }
            },
        }
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let _permit = self.authority.write_permit().await?;
        tokio::select! { biased;
            () = self.authority.cancelled() => { self.retire(); Err(io::ErrorKind::PermissionDenied.into()) },
            result = self.channel.write(bytes) => result,
        }
    }
}
#[cfg(any(test, feature = "native-streams"))]
struct GuardedDatagrams {
    inner: Arc<dyn DatagramLane>,
    authority: AuthorityGuard,
}
#[cfg(any(test, feature = "native-streams"))]
impl DatagramLane for GuardedDatagrams {
    fn retire(&self) {
        self.inner.retire();
    }
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>> {
        Box::pin(async {
            if !self.authority.permits() {
                return Err(());
            }
            tokio::select! { biased;
                () = self.authority.cancelled() => Err(()),
                result = self.inner.receive() => if self.authority.permits() { result } else { Err(()) },
            }
        })
    }
    fn send<'a>(&'a self, packet: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            let _permit = self.authority.write_permit().await.map_err(|_| ())?;
            tokio::select! { biased;
                () = self.authority.cancelled() => Err(()),
                result = self.inner.send(packet) => result,
            }
        })
    }
    fn max_payload(&self) -> Option<usize> {
        if self.authority.permits() {
            self.inner.max_payload()
        } else {
            None
        }
    }
}

async fn pump(
    channel: Arc<NativeChannel>,
    output: mpsc::Sender<Packet>,
    connection: quinn::Connection,
    mut receive: Receive,
) {
    let stream = channel.native_stream_id().unwrap_or(0);
    loop {
        let Ok(decoded) = receive.next(channel.as_ref()).await else {
            if stream == 0 {
                channel.retire();
                connection.close(0u32.into(), b"");
            } else {
                let mut bytes = Vec::new();
                if encode_muxed_frame_into(
                    stream,
                    &Frame::Close {
                        code: 1013,
                        reason: "remote stream unavailable",
                    },
                    &mut bytes,
                )
                .is_ok()
                {
                    let _ = output.try_send(Packet {
                        bytes: Bytes::from(bytes),
                        source: channel.clone(),
                    });
                }
            }
            return;
        };
        #[cfg(all(test, feature = "mesh-transport-proof"))]
        if matches!(decoded.frame, Frame::Output { bytes, .. } if !bytes.is_empty()) {
            crate::remote_autoswitch_probe::record(
                crate::remote_autoswitch_probe::Kind::TerminalByte,
                connection.remote_address(),
                stream,
            );
        }
        let mut bytes = Vec::new();
        if encode_muxed_frame_into(stream, &decoded.frame, &mut bytes).is_err() {
            return;
        }
        // One bounded queue for the actor; no unbounded per-host output buffer.
        if output
            .send(Packet {
                bytes: Bytes::from(bytes),
                source: channel.clone(),
            })
            .await
            .is_err()
        {
            return;
        }
    }
}

#[cfg(all(test, feature = "desktop"))]
#[path = "remote_wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
impl RemoteLink {
    /// Observe the actual authenticated connection close in measurement fixtures.
    #[cfg(test)]
    pub(crate) fn test_connection_for_peer(
        peer: std::net::SocketAddr,
    ) -> Option<quinn::Connection> {
        let link = TEST_LINKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&peer)
            .and_then(std::sync::Weak::upgrade)?;
        match &link.transport {
            LinkTransport::Quic(native) => Some(native.connection.clone()),
            LinkTransport::Tcp { .. } => None,
            LinkTransport::WebSocket { .. } => None,
            #[cfg(feature = "ssh")]
            LinkTransport::Ssh { .. } => None,
        }
    }
}
