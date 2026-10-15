//! Adapts authenticated remote transports to the existing server terminal actor, retaining durable writer ids and raw native frames [64][130], #78.

use bytes::{Bytes, BytesMut};
use infraternal_agent::{
    channel::Channel,
    remote_native::NativeChannel,
    remote_quic::{self, BindingConnection},
    remote_tls::TcpTls,
    transport::{Receive, Transmit},
};
use infraternal_protocol::{Frame, encode_muxed_frame_into};
use std::{collections::HashMap, io, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
};

// Tests observe existing ownership without extending a transport's lifetime.
#[cfg(test)]
static TEST_LINKS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<std::net::SocketAddr, std::sync::Weak<RemoteLink>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Remote TCP keeps the existing mux; native QUIC fans raw streams into bounded actor delivery.
enum LinkTransport {
    Tcp {
        channel: TcpTls,
        receive: Mutex<Receive>,
        prefix: Mutex<Option<Bytes>>,
    },
    Quic(QuicLink),
}

/// Authority is attached only after durable mTLS admission and guards both
/// transport directions; direct actor tests may still construct an unguarded link.
pub(crate) struct RemoteLink {
    // TCP has no Quinn peer accessor. Retain only its public authenticated tuple
    // in opt-in tests; this field is absent from every shipping build.
    #[cfg(all(test, feature = "mesh-transport-proof"))]
    diagnostic_peer: Option<std::net::SocketAddr>,
    transport: LinkTransport,
    authority: Option<crate::remote_guard::AuthorityGuard>,
    renewal: std::sync::atomic::AtomicBool,
    peer_caps: u64,
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
    binding: Mutex<Option<BindingConnection>>,
    streams: Mutex<HashMap<u32, Arc<NativeChannel>>>,
    incoming: Mutex<Incoming>,
    _control: mpsc::Sender<Packet>,
    output: mpsc::Sender<Packet>,
    pumps: Mutex<JoinSet<()>>,
    control_reads: std::sync::atomic::AtomicBool,
}

// Native delivery retains channel identity so queued old frames cannot affect
// a rebound durable writer. The two existing queues remain bounded.
struct Packet {
    bytes: Bytes,
    source: Arc<NativeChannel>,
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
        self.connection.close(0u32.into(), b"");
        // JoinSet aborts every reader; no child task retains an orphaned transport.
    }
}

impl RemoteLink {
    /// The admitted logical QUIC tuple; TCP cannot move below its transport.
    pub(crate) fn peer_address(&self) -> Option<std::net::SocketAddr> {
        match &self.transport {
            LinkTransport::Quic(link) => Some(link.connection.remote_address()),
            LinkTransport::Tcp { .. } => None,
        }
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
    fn retire(&self) {
        match &self.transport {
            LinkTransport::Tcp { channel, .. } => channel.retire(),
            LinkTransport::Quic(link) => link.connection.close(0u32.into(), b""),
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
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            diagnostic_peer: None,
            transport: LinkTransport::Tcp {
                channel,
                receive: Mutex::new(receive),
                prefix: Mutex::new(Some(Bytes::from(prefix))),
            },
            authority: None,
            renewal: std::sync::atomic::AtomicBool::new(false),
            peer_caps,
            greeting_sent,
            priming: Arc::new(std::sync::Mutex::new(
                admission.and_then(|admission| admission.priming.take()),
            )),
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
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            diagnostic_peer: None,
            transport: LinkTransport::Quic(QuicLink {
                connection,
                binding: Mutex::new(None),
                streams: Mutex::new(HashMap::from([(0, control)])),
                incoming: Mutex::new(incoming),
                _control: control_output,
                output,
                pumps: Mutex::new(pumps),
                control_reads: std::sync::atomic::AtomicBool::new(true),
            }),
            authority: None,
            renewal: std::sync::atomic::AtomicBool::new(false),
            peer_caps,
            greeting_sent,
            priming: Arc::new(std::sync::Mutex::new(
                admission.and_then(|admission| admission.priming.take()),
            )),
        })
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
        _scratch: &mut [u8],
    ) -> io::Result<usize> {
        match &self.transport {
            LinkTransport::Tcp {
                channel,
                receive,
                prefix,
            } => {
                if let Some(prefix) = prefix.lock().await.take() {
                    target.extend_from_slice(&prefix);
                    return Ok(prefix.len());
                }
                let mut receive = receive.lock().await;
                let decoded = receive.next(channel).await?;
                #[cfg(all(test, feature = "mesh-transport-proof"))]
                if matches!(decoded.frame, Frame::Output {bytes,..} if !bytes.is_empty())
                    && let Some(peer) = self.diagnostic_peer
                {
                    // Reuse the existing authenticated decoder. This is the same
                    // pre-actor boundary as QUIC's pump, not a second parser.
                    crate::remote_autoswitch_probe::record(
                        crate::remote_autoswitch_probe::Kind::TerminalByte,
                        peer,
                        decoded.stream_id,
                    );
                }
                let mut bytes = Vec::new();
                encode_muxed_frame_into(decoded.stream_id, &decoded.frame, &mut bytes)
                    .map_err(io::Error::other)?;
                let count = bytes.len();
                target.extend_from_slice(&bytes);
                Ok(count)
            }
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
                let mut streams = link.streams.lock().await;
                if !streams
                    .get(&stream)
                    .is_some_and(|current| Arc::ptr_eq(current, &message.source))
                {
                    incoming.pending = None;
                    continue;
                }
                if stream != 0
                    && matches!(infraternal_protocol::decode_muxed_frame(&message.bytes), Ok(decoded) if matches!(decoded.frame, Frame::Close { .. }))
                    && let Some(channel) = streams.remove(&stream)
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
            let _guard = link.streams.lock().await;
            let _ = ready.send(());
            let _ = release.await;
        }
    }
    #[cfg(test)]
    pub(crate) async fn control_packet_ready(&self) -> bool {
        match &self.transport {
            LinkTransport::Quic(link) => !link.incoming.lock().await.control.is_empty(),
            LinkTransport::Tcp { .. } => false,
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
            link.streams.try_lock().ok().map(|streams| streams.len()),
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
        }
    }

    /// Observe authenticated `STOP_SENDING` before testing a late detach.
    #[cfg(test)]
    pub(crate) fn test_received_stop_sending(&self) -> Option<u64> {
        match &self.transport {
            LinkTransport::Quic(link) => Some(link.connection.stats().frame_rx.stop_sending),
            LinkTransport::Tcp { .. } => None,
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
        let channel = link.streams.lock().await.get(&stream).cloned();
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
    pub(crate) async fn retire_writer(&self, stream: u32) {
        if let LinkTransport::Quic(link) = &self.transport
            && let Some(channel) = link.streams.lock().await.remove(&stream)
        {
            channel.retire();
        }
    }

    /// Promotion joins setup first, then removes bindings no cached-ready writer owns.
    pub(crate) async fn retain_writers(&self, writers: &[u32]) {
        if let LinkTransport::Quic(link) = &self.transport {
            link.streams.lock().await.retain(|stream, channel| {
                let keep = *stream == 0 || writers.contains(stream);
                if !keep {
                    channel.retire();
                }
                keep
            });
        }
    }

    pub(crate) fn peer_capabilities(&self) -> u64 {
        self.peer_caps
    }
    #[cfg(test)]
    pub(crate) fn supports_server_paths(&self) -> bool {
        self.peer_caps & infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS != 0
    }

    pub(crate) fn supports_renewal(&self) -> bool {
        self.renewal.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) async fn hello(&self, frame: &Frame<'_>) -> io::Result<()> {
        if let Frame::Hello { caps, .. } = frame {
            self.renewal.store(
                caps & infraternal_agent::remote_renewal::LIVE_RENEWAL != 0,
                std::sync::atomic::Ordering::Release,
            );
        }
        if let LinkTransport::Quic(link) = &self.transport {
            *link.binding.lock().await =
                Some(remote_quic::negotiate_binding(&link.connection, frame)?);
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
            LinkTransport::Tcp { channel, .. } => channel.write(muxed).await,
            LinkTransport::Quic(link) => {
                let terminal_close = stream != 0 && matches!(frame, Frame::Close { .. });
                let existing = link.streams.lock().await.get(&stream).cloned();
                let channel = if let Some(channel) = existing {
                    channel
                } else {
                    // Peer retirement may win the race with the consumer's
                    // detach. Cleanup is idempotent; other frames still need
                    // a live binding, and odd/control ids cannot invent one.
                    if terminal_close && stream & 1 == 0 {
                        return Ok(());
                    }
                    if !matches!(frame, Frame::AttachTerm { .. }) {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    // Binding serializes channel creation, but never owns the
                    // delivery map while QUIC flow control can suspend setup.
                    let binding = link.binding.lock().await;
                    let existing = link.streams.lock().await.get(&stream).cloned();
                    if let Some(channel) = existing {
                        channel
                    } else {
                        let bound = remote_quic::open_bound(
                            binding.as_ref().ok_or(io::ErrorKind::PermissionDenied)?,
                            stream,
                        )
                        .await?;
                        let channel = Arc::new(NativeChannel::terminal(bound)?);
                        if self.primed() {
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
                        let mut pumps = link.pumps.lock().await;
                        while pumps.try_join_next().is_some() {}
                        if pumps.len() >= 129 {
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                        // Publish identity before its reader can deliver an Ack.
                        let mut streams = link.streams.lock().await;
                        streams.insert(stream, channel.clone());
                        pumps.spawn(pump(
                            channel.clone(),
                            link.output.clone(),
                            link.connection.clone(),
                            Receive::default(),
                        ));
                        channel
                    }
                };
                let result = Transmit::default()
                    .send(channel.as_ref(), stream, frame)
                    .await;
                if terminal_close {
                    // A peer can stop receiving before local detach is sent.
                    // Retire this channel even after a partial/failed Close:
                    // no later frame may follow it, and its writer-local error
                    // must not make the actor discard the host connection.
                    link.streams.lock().await.remove(&stream);
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
