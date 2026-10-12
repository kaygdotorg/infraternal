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
    transport: LinkTransport,
    authority: Option<crate::remote_guard::AuthorityGuard>,
    renewal: std::sync::atomic::AtomicBool,
    server_paths: bool,
    greeting_sent: bool,
}

pub(crate) struct QuicLink {
    connection: quinn::Connection,
    binding: Mutex<Option<BindingConnection>>,
    streams: Mutex<HashMap<u32, Arc<NativeChannel>>>,
    incoming: Mutex<Incoming>,
    _control: mpsc::Sender<Packet>,
    output: mpsc::Sender<Packet>,
    pumps: Mutex<JoinSet<()>>,
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
}

impl Drop for QuicLink {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"");
        // JoinSet aborts every reader; no child task retains an orphaned transport.
    }
}

impl RemoteLink {
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
        admission: Option<&mut crate::remote_standby::Admission>,
    ) -> io::Result<Self> {
        let mut receive = Receive::default();
        let (prefix, greeting_sent) = greeting(&channel, &mut receive, admission).await?;
        let server_paths = supports_server_paths(&prefix);
        // TLS losers in the outgoing dial race send no application greeting;
        // they must never supersede the winning host transport in the registry.
        Ok(Self {
            transport: LinkTransport::Tcp {
                channel,
                receive: Mutex::new(receive),
                prefix: Mutex::new(Some(Bytes::from(prefix))),
            },
            authority: None,
            renewal: std::sync::atomic::AtomicBool::new(false),
            server_paths,
            greeting_sent,
        })
    }
    #[cfg(test)]
    pub(crate) async fn quic(connection: quinn::Connection) -> io::Result<Self> {
        Self::quic_admitted(connection, None).await
    }
    pub(crate) async fn quic_admitted(
        connection: quinn::Connection,
        admission: Option<&mut crate::remote_standby::Admission>,
    ) -> io::Result<Self> {
        let (send, receive) = tokio::time::timeout(Duration::from_secs(5), connection.accept_bi())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::other)?;
        let control = Arc::new(NativeChannel::control(send, receive)?);
        let mut receive = Receive::default();
        let (prefix, greeting_sent) = greeting(control.as_ref(), &mut receive, admission).await?;
        let server_paths = supports_server_paths(&prefix);
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
        };
        let mut pumps = JoinSet::new();
        pumps.spawn(pump(
            control.clone(),
            control_output.clone(),
            connection.clone(),
            receive,
        ));
        Ok(Self {
            transport: LinkTransport::Quic(QuicLink {
                connection,
                binding: Mutex::new(None),
                streams: Mutex::new(HashMap::from([(0, control)])),
                incoming: Mutex::new(incoming),
                _control: control_output,
                output,
                pumps: Mutex::new(pumps),
            }),
            authority: None,
            renewal: std::sync::atomic::AtomicBool::new(false),
            server_paths,
            greeting_sent,
        })
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
                let mut bytes = Vec::new();
                encode_muxed_frame_into(decoded.stream_id, &decoded.frame, &mut bytes)
                    .map_err(io::Error::other)?;
                let count = bytes.len();
                target.extend_from_slice(&bytes);
                Ok(count)
            }
            LinkTransport::Quic(link) => loop {
                let mut incoming = link.incoming.lock().await;
                if incoming.pending.is_none() {
                    incoming.pending = tokio::select! {
                        biased;
                        _ = link.connection.closed() => return Ok(0),
                        message = async {
                            let Incoming { control, bulk, .. } = &mut *incoming;
                            tokio::select! { biased; message = control.recv() => message, message = bulk.recv() => message }
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

    pub(crate) fn supports_server_paths(&self) -> bool {
        self.server_paths
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
                let existing = link.streams.lock().await.get(&stream).cloned();
                let channel = if let Some(channel) = existing {
                    channel
                } else {
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
                Transmit::default()
                    .send(channel.as_ref(), stream, frame)
                    .await?;
                if stream != 0 && matches!(frame, Frame::Close { .. }) {
                    link.streams.lock().await.remove(&stream);
                    channel.retire();
                }
                Ok(())
            }
        }
    }
}

fn supports_server_paths(prefix: &[u8]) -> bool {
    matches!(infraternal_protocol::decode_muxed_frame(prefix), Ok(infraternal_protocol::DecodedMuxedFrame { frame: Frame::Hello { caps, .. }, .. })
        if caps & infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS != 0)
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
                } if crate::remote_standby_request::wants_prime(input_json)
                    .is_ok_and(|prime| !prime) =>
                {
                    return Ok::<Option<Vec<u8>>, io::Error>(None);
                }
                _ => return Err(io::ErrorKind::InvalidData.into()),
            }
        } else {
            if first.stream_id != 0 || !matches!(first.frame, Frame::Hello { version: 1, .. }) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            encode_muxed_frame_into(0, &first.frame, &mut prefix).map_err(io::Error::other)?;
        }
        Ok::<Option<Vec<u8>>, io::Error>(Some(prefix))
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if let Some(prefix) = prefix {
        return Ok((prefix, false));
    }
    let admission = admission.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    Ok((admission.hello(channel, receive).await?, true))
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
