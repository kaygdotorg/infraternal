//! Carries the leg-B mutual TLS link through the public HTTPS listener [168,196], #291, #559.
//!
//! When QUIC and TCP/TLS to the server's own port are blocked, the
//! infraternal agent opens `wss://<public origin>/remote/agent` and runs the
//! very same leg-B TLS session it would run over TCP *inside* that WebSocket:
//! TLS 1.3, our CA only, ALPN `infraternal/1`, its host certificate, the
//! enrolled server name and the [`ServerLeafFloor`]. The outer HTTPS session
//! is plain transport. Whoever terminates it (the server itself, a reverse
//! proxy, or a relay holding a publicly trusted certificate for the name) only
//! forwards leg-B ciphertext it cannot read, change or answer for the server.
//!
//! The WebSocket carries the inner TLS bytes in binary messages
//! ([`WebSocketCarrier`]); the server's `/remote/agent` route uses the same
//! adapter on its side.

use crate::remote_tls::{self, Carrier, Identity, TcpTls};
use bytes::Bytes;
use futures_util::{Sink, Stream};
use infraternal_plugin_remote::server_leaf_floor::ServerLeafFloor;
use openssl::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{Instant, Interval, MissedTickBehavior},
};
use tokio_openssl::SslStream;
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{self, Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
use url::Url;

const HANDSHAKE: Duration = Duration::from_secs(5);
/// How often an idle link sends a WebSocket ping, so proxies that close idle
/// upgraded connections (often after 60 s) keep it open. This is the link's
/// only timer, as before #559.
const KEEPALIVE: Duration = Duration::from_secs(25);
const WS_PATH: &str = "/remote/agent";
/// Largest WebSocket message either end of the link sends or accepts.
///
/// Each message carries at most one write of the inner TLS stream, which
/// OpenSSL makes one record (at most 16 KiB of plaintext plus 256 bytes), so
/// honest peers stay far below this. Keeping it small also bounds what an
/// unauthenticated peer can make the other side buffer for one message.
pub const CARRIER_MESSAGE_MAX: usize = 64 * 1024;

/// The WebSocket settings both ends of the link use.
#[must_use]
pub fn carrier_config() -> WebSocketConfig {
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(CARRIER_MESSAGE_MAX);
    config.max_frame_size = Some(CARRIER_MESSAGE_MAX);
    config
}

/// Public-origin preflight failures the enrolling command can explain without exposing IO details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightFailure {
    /// The invitation did not name a bare HTTPS origin.
    InvalidOrigin,
    /// DNS did not resolve the public origin.
    Dns,
    /// TCP 443 could not be reached.
    Connect,
    /// The public HTTPS certificate could not be verified.
    Tls,
    /// The app listener or its proxy did not complete a WebSocket upgrade.
    Upgrade,
    /// The upgraded route did not answer the infraternal agent link: no leg-B
    /// TLS listener behind it.
    Link,
}

/// A WebSocket used as an ordered byte stream: every write becomes one binary
/// message, and reads return the bytes of the binary messages in order.
///
/// It is the [`Carrier`] the inner leg-B TLS session runs on, on both ends of
/// the HTTPS link. While a read waits it also sends a ping every
/// [`KEEPALIVE`]; pings from the peer are answered by the WebSocket layer
/// itself. A text message is a protocol error, and a close ends the stream.
/// Writes are buffered until `poll_flush`, which the TLS channel calls after
/// every frame, so one frame can share a TCP segment.
pub struct WebSocketCarrier<T> {
    /// The upgraded WebSocket.
    socket: WebSocketStream<T>,
    /// The unread rest of the last binary message.
    pending: Bytes,
    /// Ticks every [`KEEPALIVE`] while reads wait.
    keepalive: Interval,
    /// A keepalive ping is due but the socket could not take it yet.
    ping_due: bool,
    /// A ping was queued from the read side and still has to be flushed.
    ping_unflushed: bool,
    /// The peer closed the WebSocket: reads return end of stream.
    finished: bool,
}

impl<T> WebSocketCarrier<T> {
    /// Use an upgraded WebSocket as a byte carrier.
    ///
    /// Must be created inside the Tokio runtime (it holds the keepalive timer).
    pub fn new(socket: WebSocketStream<T>) -> Self {
        let mut keepalive = tokio::time::interval_at(Instant::now() + KEEPALIVE, KEEPALIVE);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            socket,
            pending: Bytes::new(),
            keepalive,
            ping_due: false,
            ping_unflushed: false,
            finished: false,
        }
    }

    /// The WebSocket this carrier wraps, for its owner's bookkeeping.
    pub fn get_mut(&mut self) -> &mut WebSocketStream<T> {
        &mut self.socket
    }
}

/// Map a WebSocket error to the IO error the TLS layer above understands.
fn carrier_error(error: tungstenite::Error) -> io::Error {
    match error {
        tungstenite::Error::Io(error) => error,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            io::ErrorKind::BrokenPipe.into()
        }
        _ => io::ErrorKind::InvalidData.into(),
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> WebSocketCarrier<T> {
    /// Queue and flush a keepalive ping when its timer is due. Never blocks
    /// the read: a socket that cannot take the ping yet keeps it due.
    fn poll_keepalive(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.keepalive.poll_tick(cx).is_ready() {
            self.ping_due = true;
        }
        let mut socket = Pin::new(&mut self.socket);
        if self.ping_due
            && let Poll::Ready(ready) = socket.as_mut().poll_ready(cx)
        {
            ready.map_err(carrier_error)?;
            socket
                .as_mut()
                .start_send(Message::Ping(Bytes::new()))
                .map_err(carrier_error)?;
            self.ping_due = false;
            self.ping_unflushed = true;
        }
        if self.ping_unflushed
            && let Poll::Ready(flushed) = socket.poll_flush(cx)
        {
            flushed.map_err(carrier_error)?;
            self.ping_unflushed = false;
        }
        Ok(())
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketCarrier<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let count = buf.remaining().min(this.pending.len());
                buf.put_slice(&this.pending.split_to(count));
                return Poll::Ready(Ok(()));
            }
            if this.finished || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            this.poll_keepalive(cx)?;
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.pending = data,
                // Answered (pings) or expected (pongs) by the WebSocket layer.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => this.finished = true,
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                Some(Err(error)) => return Poll::Ready(Err(carrier_error(error))),
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketCarrier<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut socket = Pin::new(&mut self.get_mut().socket);
        ready!(socket.as_mut().poll_ready(cx)).map_err(carrier_error)?;
        let count = data.len().min(CARRIER_MESSAGE_MAX);
        socket
            .start_send(Message::Binary(Bytes::copy_from_slice(&data[..count])))
            .map_err(carrier_error)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_flush(cx)
            .map_err(carrier_error)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_close(cx)
            .map_err(carrier_error)
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> WebSocketCarrier<T> {
    /// Box this carrier for [`remote_tls::dial_over`] or
    /// [`remote_tls::accept_over`].
    pub fn into_carrier(self) -> Carrier {
        Carrier::Tunnel(Box::new(self))
    }
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "remote HTTPS agent link refused",
    )
}

/// The TLS client for the outer HTTPS session: either the enrolled server's pinned certificate, or the
/// first trusted fixed system bundle from [`tls_roots`]. It only has to reach the right listener; the
/// inner leg-B session authenticates the server.
///
/// [`tls_roots`]: infraternal_plugin_api::tls_roots
fn https_connector(root: Option<&X509>, system_roots: bool) -> io::Result<SslConnector> {
    let mut config = SslConnector::builder(SslMethod::tls_client()).map_err(|_| refused())?;
    // The app route uses RFC 6455's HTTP/1.1 Upgrade; it does not implement RFC 8441 extended CONNECT.
    config
        .set_alpn_protos(b"\x08http/1.1")
        .map_err(|_| refused())?;
    config.set_verify(SslVerifyMode::PEER);
    if system_roots {
        // Replace OpenSSL's initial environment-derived store with only the approved bundle.
        config.set_cert_store(
            infraternal_plugin_api::tls_roots::public_root_store().map_err(|_| refused())?,
        );
    } else {
        let mut trust = X509StoreBuilder::new().map_err(|_| refused())?;
        trust
            .add_cert(root.ok_or_else(refused)?.clone())
            .map_err(|_| refused())?;
        trust
            .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
            .map_err(|_| refused())?;
        config.set_cert_store(trust.build());
    }
    Ok(config.build())
}

fn origin(value: &str) -> io::Result<(Url, String, u16)> {
    let parsed = Url::parse(value).map_err(|_| refused())?;
    let host = parsed.host_str().ok_or_else(refused)?.to_owned();
    let port = parsed.port_or_known_default().ok_or_else(refused)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(refused());
    }
    Ok((parsed, host, port))
}

/// How the infraternal agent judges the server on the HTTPS link: exactly
/// the trust of its direct leg-B dials.
pub struct ServerTrust<'a> {
    /// The enrolled CA roots.
    pub roots: &'a [X509],
    /// The server name its leaf must carry.
    pub server_name: &'a str,
    /// The newest server leaf this enrollment accepted; refuses older ones.
    pub floor: &'a ServerLeafFloor,
}

/// Dial the public app origin and run the leg-B mutual TLS session inside
/// its WebSocket, presenting `identity` and checking the server against
/// `server`.
///
/// The returned channel is the same type the direct TCP fallback returns,
/// and nothing has been sent on it yet. Round trips after the WebSocket
/// upgrade: one (the inner TLS 1.3 handshake); the first protocol frame
/// leaves with the agent's TLS Finished.
/// # Errors
/// Returns an error if outer TLS, the upgrade, the inner handshake (chain,
/// name, ALPN, client certificate) or the floor refuses. A server leaf the
/// floor refuses is `InvalidData`, as on the direct dials.
pub async fn connect(
    public_origin: &str,
    identity: &Identity,
    https_root: Option<&X509>,
    https_system_roots: bool,
    server: &ServerTrust<'_>,
) -> io::Result<TcpTls> {
    let socket = upgraded(public_origin, https_root, https_system_roots)
        .await
        .map_err(preflight_io)?;
    let config = remote_tls::client_config(identity, server.roots)?;
    let connection = remote_tls::dial_over(
        WebSocketCarrier::new(socket).into_carrier(),
        server.server_name,
        &config,
    )
    .await?;
    // Dropping a refused connection closes it before any frame is sent.
    let leaf = connection
        .peer_leaf
        .as_ref()
        .and_then(|leaf| leaf.to_der().ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    server.floor.admit(&leaf)?;
    Ok(connection.channel)
}

/// Prove that the target can complete the app's WebSocket route and that a
/// leg-B TLS listener answers inside it.
///
/// No identity is sent and nothing is trusted during preflight (see
/// [`remote_tls::probe_over`]); the real link checks the server fully.
/// # Errors
/// Returns a classified error when DNS, TCP, TLS, upgrade, or the inner
/// listener check fails.
pub async fn preflight(
    public_origin: &str,
    https_root: Option<&X509>,
    https_system_roots: bool,
) -> Result<(), PreflightFailure> {
    let socket = upgraded(public_origin, https_root, https_system_roots).await?;
    let host = origin(public_origin)
        .map(|(_, host, _)| host)
        .map_err(|_| PreflightFailure::InvalidOrigin)?;
    remote_tls::probe_over(WebSocketCarrier::new(socket).into_carrier(), &host)
        .await
        .map_err(|_| PreflightFailure::Link)
}

/// The IO error a link attempt reports for a preflight-stage failure.
fn preflight_io(error: PreflightFailure) -> io::Error {
    let kind = match error {
        PreflightFailure::InvalidOrigin => io::ErrorKind::InvalidInput,
        PreflightFailure::Dns => io::ErrorKind::AddrNotAvailable,
        PreflightFailure::Connect => io::ErrorKind::NotConnected,
        PreflightFailure::Tls => io::ErrorKind::PermissionDenied,
        PreflightFailure::Upgrade | PreflightFailure::Link => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, "remote HTTPS agent link refused")
}

/// Dial the origin, complete the outer TLS session and the WebSocket upgrade.
async fn upgraded(
    public_origin: &str,
    root: Option<&X509>,
    system_roots: bool,
) -> Result<WebSocketStream<SslStream<TcpStream>>, PreflightFailure> {
    let (mut url, host, port) =
        origin(public_origin).map_err(|_| PreflightFailure::InvalidOrigin)?;
    let connector = https_connector(root, system_roots).map_err(|_| PreflightFailure::Tls)?;
    let addresses = tokio::time::timeout(HANDSHAKE, tokio::net::lookup_host((host.as_str(), port)))
        .await
        .map_err(|_| PreflightFailure::Dns)?
        .map_err(|_| PreflightFailure::Dns)?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(PreflightFailure::Dns);
    }
    let stream = tokio::time::timeout(HANDSHAKE, TcpStream::connect(addresses.as_slice()))
        .await
        .map_err(|_| PreflightFailure::Connect)?
        .map_err(|_| PreflightFailure::Connect)?;
    stream
        .set_nodelay(true)
        .map_err(|_| PreflightFailure::Connect)?;
    let ssl = connector
        .configure()
        .map_err(|_| PreflightFailure::Tls)?
        .into_ssl(&host)
        .map_err(|_| PreflightFailure::Tls)?;
    let mut tls = SslStream::new(ssl, stream).map_err(|_| PreflightFailure::Tls)?;
    tokio::time::timeout(HANDSHAKE, Pin::new(&mut tls).connect())
        .await
        .map_err(|_| PreflightFailure::Tls)?
        .map_err(|_| PreflightFailure::Tls)?;
    url.set_scheme("wss")
        .map_err(|()| PreflightFailure::InvalidOrigin)?;
    url.set_path(WS_PATH);
    url.set_query(None);
    let request = url
        .as_str()
        .into_client_request()
        .map_err(|_| PreflightFailure::InvalidOrigin)?;
    let (socket, _) = tokio::time::timeout(
        HANDSHAKE,
        client_async_with_config(request, tls, Some(carrier_config())),
    )
    .await
    .map_err(|_| PreflightFailure::Upgrade)?
    .map_err(|_| PreflightFailure::Upgrade)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    //! The byte carrier over a real in-memory WebSocket pair.
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    /// A connected client/server WebSocket pair over an in-memory pipe.
    async fn pair() -> (
        WebSocketStream<tokio::io::DuplexStream>,
        WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (client, server) = tokio::io::duplex(1 << 20);
        (
            WebSocketStream::from_raw_socket(client, Role::Client, Some(carrier_config())).await,
            WebSocketStream::from_raw_socket(server, Role::Server, Some(carrier_config())).await,
        )
    }

    /// Bytes cross in order in both directions, a large write is split into
    /// messages no larger than [`CARRIER_MESSAGE_MAX`], and small reads take
    /// a message in pieces without losing any byte.
    #[tokio::test]
    async fn bytes_cross_in_order_and_large_writes_are_split() {
        let (client, server) = pair().await;
        let mut client = WebSocketCarrier::new(client);
        let mut server = WebSocketCarrier::new(server);
        let large: Vec<u8> = (0..200_000u32)
            .map(|value| value.to_le_bytes()[0])
            .collect();
        let writer = {
            let large = large.clone();
            tokio::spawn(async move {
                client.write_all(&large).await.unwrap();
                client.flush().await.unwrap();
                client
            })
        };
        let mut received = vec![0; large.len()];
        let mut small = [0; 7];
        let first = server.read(&mut small).await.unwrap();
        received[..first].copy_from_slice(&small[..first]);
        server.read_exact(&mut received[first..]).await.unwrap();
        assert_eq!(received, large);
        let mut client = writer.await.unwrap();
        server.write_all(b"back").await.unwrap();
        server.flush().await.unwrap();
        let mut back = [0; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"back");
    }

    /// The raw messages a carrier writes are binary and bounded.
    #[tokio::test]
    async fn messages_are_binary_and_bounded() {
        let (client, mut server) = pair().await;
        let mut client = WebSocketCarrier::new(client);
        client
            .write_all(&vec![1; 3 * CARRIER_MESSAGE_MAX])
            .await
            .unwrap();
        client.flush().await.unwrap();
        for _ in 0..3 {
            let Some(Ok(Message::Binary(data))) = server.next().await else {
                panic!("expected a binary message");
            };
            assert_eq!(data.len(), CARRIER_MESSAGE_MAX);
        }
    }

    /// A close ends the stream; a text message is a protocol error.
    #[tokio::test]
    async fn close_is_end_of_stream_and_text_is_refused() {
        let (client, mut server) = pair().await;
        let mut client = WebSocketCarrier::new(client);
        server.send(Message::Close(None)).await.unwrap();
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);

        let (client, mut server) = pair().await;
        let mut client = WebSocketCarrier::new(client);
        server.send(Message::Text("x".into())).await.unwrap();
        assert_eq!(
            client.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// An idle read sends a ping every [`KEEPALIVE`] and nothing before it.
    #[tokio::test(start_paused = true)]
    async fn idle_reads_send_keepalive_pings() {
        let (client, mut server) = pair().await;
        let mut client = WebSocketCarrier::new(client);
        let reader = tokio::spawn(async move {
            let mut byte = [0; 1];
            client.read(&mut byte).await.map(|_| byte[0])
        });
        let early = tokio::time::timeout(
            KEEPALIVE.saturating_sub(Duration::from_secs(1)),
            server.next(),
        )
        .await;
        assert!(early.is_err(), "no ping before the keepalive interval");
        let Some(Ok(Message::Ping(_))) = server.next().await else {
            panic!("expected a keepalive ping");
        };
        server.send(Message::Binary(vec![7].into())).await.unwrap();
        assert_eq!(reader.await.unwrap().unwrap(), 7);
    }
}
