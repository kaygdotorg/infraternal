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
pub(crate) enum RemoteLink {
    Tcp {
        channel: TcpTls,
        receive: Mutex<Receive>,
        prefix: Mutex<Option<Bytes>>,
    },
    Quic(QuicLink),
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
    pub(crate) async fn tcp(channel: TcpTls) -> io::Result<Self> {
        let mut receive = Receive::default();
        let hello = tokio::time::timeout(Duration::from_secs(5), receive.next(&channel))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if hello.stream_id != 0 || !matches!(hello.frame, Frame::Hello { version: 1, .. }) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut prefix = Vec::new();
        encode_muxed_frame_into(0, &hello.frame, &mut prefix).map_err(io::Error::other)?;
        // TLS losers in the outgoing dial race send no application greeting;
        // they must never supersede the winning host transport in the registry.
        Ok(Self::Tcp {
            channel,
            receive: Mutex::new(receive),
            prefix: Mutex::new(Some(Bytes::from(prefix))),
        })
    }
    pub(crate) async fn quic(connection: quinn::Connection) -> io::Result<Self> {
        let (send, receive) = tokio::time::timeout(Duration::from_secs(5), connection.accept_bi())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::other)?;
        let control = Arc::new(NativeChannel::control(send, receive)?);
        let (output, bulk) = mpsc::channel(32);
        let (control_output, control_input) = mpsc::channel(8);
        let incoming = Incoming {
            control: control_input,
            bulk,
        };
        let mut pumps = JoinSet::new();
        pumps.spawn(pump(
            control.clone(),
            control_output.clone(),
            connection.clone(),
        ));
        Ok(Self::Quic(QuicLink {
            connection,
            binding: Mutex::new(None),
            streams: Mutex::new(HashMap::from([(0, control)])),
            incoming: Mutex::new(incoming),
            _control: control_output,
            output,
            pumps: Mutex::new(pumps),
        }))
    }

    pub(crate) async fn read(
        &self,
        target: &mut BytesMut,
        _scratch: &mut [u8],
    ) -> io::Result<usize> {
        match self {
            Self::Tcp {
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
            Self::Quic(link) => {
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

    pub(crate) async fn hello(&self, frame: &Frame<'_>) -> io::Result<()> {
        if let Self::Quic(link) = self {
            *link.binding.lock().await =
                Some(remote_quic::negotiate_binding(&link.connection, frame)?);
        }
        Ok(())
    }

    pub(crate) async fn write(
        &self,
        stream: u32,
        frame: &Frame<'_>,
        muxed: &[u8],
    ) -> io::Result<()> {
        match self {
            Self::Tcp { channel, .. } => channel.write(muxed).await,
            Self::Quic(link) => {
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

async fn pump(
    channel: Arc<NativeChannel>,
    output: mpsc::Sender<Bytes>,
    connection: quinn::Connection,
) {
    let stream = channel.native_stream_id().unwrap_or(0);
    let mut receive = Receive::default();
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
