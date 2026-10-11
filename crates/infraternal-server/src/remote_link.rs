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
    _control: mpsc::Sender<Bytes>,
    output: mpsc::Sender<Bytes>,
    pumps: Mutex<JoinSet<()>>,
}

struct Incoming {
    control: mpsc::Receiver<Bytes>,
    bulk: mpsc::Receiver<Bytes>,
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
            .try_send(Bytes::from(prefix))
            .map_err(io::Error::other)?;
        let incoming = Incoming {
            control: control_input,
            bulk,
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
            LinkTransport::Quic(link) => {
                tokio::select! {
                    biased;
                    _ = link.connection.closed() => Ok(0),
                    message = async {
                        let mut incoming = link.incoming.lock().await;
                        let Incoming { control, bulk } = &mut *incoming;
                        tokio::select! { biased; message = control.recv() => message, message = bulk.recv() => message }
                    } => {
                        let Some(message) = message else { return Ok(0); };
                        if let Ok(decoded) = infraternal_protocol::decode_muxed_frame(&message)
                            && decoded.stream_id != 0 && matches!(decoded.frame, Frame::Close { .. })
                            && let Some(channel) = link.streams.lock().await.remove(&decoded.stream_id) { channel.retire(); }
                        target.extend_from_slice(&message);
                        Ok(message.len())
                    }
                }
            }
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
                let mut streams = link.streams.lock().await;
                if let std::collections::hash_map::Entry::Vacant(entry) = streams.entry(stream) {
                    if !matches!(frame, Frame::AttachTerm { .. }) {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    let binding = link.binding.lock().await;
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
                    pumps.spawn(pump(
                        channel.clone(),
                        link.output.clone(),
                        link.connection.clone(),
                        Receive::default(),
                    ));
                    entry.insert(channel);
                }
                let channel = streams
                    .get(&stream)
                    .cloned()
                    .ok_or(io::ErrorKind::BrokenPipe)?;
                drop(streams);
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
                    input_json: b"{}",
                } => return Ok::<Option<Vec<u8>>, io::Error>(None),
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
    output: mpsc::Sender<Bytes>,
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
                    let _ = output.try_send(Bytes::from(bytes));
                }
            }
            return;
        };
        let mut bytes = Vec::new();
        if encode_muxed_frame_into(stream, &decoded.frame, &mut bytes).is_err() {
            return;
        }
        // One bounded queue for the actor; no unbounded per-host output buffer.
        if output.send(Bytes::from(bytes)).await.is_err() {
            return;
        }
    }
}
