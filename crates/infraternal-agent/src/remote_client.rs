//! Supervises a locally enrolled dial-out identity over QUIC first and verified TCP fallback, preserving rootless shims through connection loss [64][133], #78.

use crate::{
    channel::Channel,
    daemon,
    remote_native::NativeChannel,
    remote_quic,
    remote_tls::{self, Identity},
    transport::Receive,
};
use infraternal_protocol::encode_frame_into;
use openssl::x509::X509;
use std::{io, net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{sync::Mutex, task::JoinSet};

/// Local enrolled host credentials; no private material leaves the host.
pub struct RemoteIdentity {
    /// Locally generated host key and committed client certificate.
    pub identity: Identity,
    /// Pinned public issuers, including overlap generations.
    pub roots: Vec<X509>,
    /// Trusted server transport address.
    pub endpoint: SocketAddr,
    /// Server SAN, verified on both transports.
    pub server_name: String,
    /// Bound uid, checked against the running rootless infraternal agent.
    pub execution_uid: u32,
}

/// Run until cancelled. Fallback retries sleep; proven alternative paths own a freshness guard.
/// # Errors
/// Refuses local uid mismatch or invalid credentials before contacting the server.
pub async fn run(identity: &RemoteIdentity, state: Option<PathBuf>) -> io::Result<()> {
    run_inner(identity, state, None).await
}

/// Keep atomic publication and reconnect identity in sync throughout live renewal.
/// # Errors
/// Refuses unsafe local identity, expired credentials or failed transport configuration.
pub async fn run_with_publisher(
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
    publisher: std::sync::Arc<dyn crate::remote_renewal::CertificatePublisher>,
) -> io::Result<()> {
    let renewal =
        crate::remote_renewal::RenewalIdentity::new(&identity.identity, &identity.roots, publisher);
    run_inner(identity, state, Some(&renewal)).await
}

async fn run_inner(
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
) -> io::Result<()> {
    if identity.execution_uid != nix::unistd::Uid::effective().as_raw() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let state = crate::sessions::state(state)?;
    // The host control surface remains available while the authenticated server is offline.
    let service =
        crate::plugin_control::Service::start(&state, crate::plugins::ExecutionMode::Remote)
            .await?;
    server_path::run(identity, state, renewal, service.registry.clone()).await
}

// Keep the race in its own future. Its losing socket is dropped when this
// returns, rather than retained throughout the winning control dispatch.
async fn dial_preferred(
    endpoint: &quinn::Endpoint,
    identity: &RemoteIdentity,
    tls: &openssl::ssl::SslConnector,
) -> io::Result<Connected> {
    let quic = quic_connect(endpoint, identity);
    let fallback = async {
        // Start QUIC first, then race TCP after a short grace period. A
        // silent UDP path cannot add its full handshake timeout to TCP.
        tokio::time::sleep(Duration::from_millis(100)).await;
        remote_tls::dial(identity.endpoint, &identity.server_name, tls).await
    };
    tokio::pin!(quic, fallback);
    tokio::select! {
        biased;
        result = &mut quic => match result {
            Ok(connection) => Ok(Connected::Quic(connection)),
            Err(_) => fallback.await.map(Connected::Tcp),
        },
        result = &mut fallback => match result {
            Ok(connection) => Ok(Connected::Tcp(connection)),
            Err(_) => quic.await.map(Connected::Quic),
        },
    }
}

// Dropping the losing handshake releases its transport before dispatch begins.
enum Connected {
    Quic(quinn::Connection),
    Tcp(remote_tls::Connection),
}

// A proven TCP decoder and a native QUIC decoder retain their buffered frames.
enum ControlChannel<'a> {
    Quic(NativeChannel),
    Tcp(&'a crate::remote_tls::TcpTls),
}
impl Channel for ControlChannel<'_> {
    fn native_stream_id(&self) -> Option<u32> {
        match self {
            Self::Quic(channel) => channel.native_stream_id(),
            Self::Tcp(channel) => channel.native_stream_id(),
        }
    }
    fn frame_timeout(&self) -> Option<Duration> {
        match self {
            Self::Quic(channel) => channel.frame_timeout(),
            Self::Tcp(channel) => channel.frame_timeout(),
        }
    }
    fn retire(&self) {
        match self {
            Self::Quic(channel) => channel.retire(),
            Self::Tcp(channel) => channel.retire(),
        }
    }
    async fn read(&self, target: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Quic(channel) => channel.read(target).await,
            Self::Tcp(channel) => channel.read(target).await,
        }
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Quic(channel) => channel.write(bytes).await,
            Self::Tcp(channel) => channel.write(bytes).await,
        }
    }
}

// Replay the negotiated Hello into common dispatch while retaining the same
// decoder: its first read may also contain the following control frame.
struct PrefixedControl<'a> {
    channel: ControlChannel<'a>,
    prefix: Mutex<Vec<u8>>,
    sent_greeting: Mutex<Option<Vec<u8>>>,
    receive: Mutex<Receive>,
}
impl Channel for PrefixedControl<'_> {
    fn native_stream_id(&self) -> Option<u32> {
        self.channel.native_stream_id()
    }
    fn frame_timeout(&self) -> Option<Duration> {
        self.channel.frame_timeout()
    }
    fn retire(&self) {
        self.channel.retire();
    }
    async fn read(&self, target: &mut [u8]) -> io::Result<usize> {
        let mut prefix = self.prefix.lock().await;
        if prefix.is_empty() {
            let mut receive = self.receive.lock().await;
            let frame = receive.next(&self.channel).await?;
            if self.channel.native_stream_id().is_some() {
                encode_frame_into(&frame.frame, &mut prefix).map_err(io::Error::other)?;
            } else {
                infraternal_protocol::encode_muxed_frame_into(
                    frame.stream_id,
                    &frame.frame,
                    &mut prefix,
                )
                .map_err(io::Error::other)?;
            }
        }
        let count = target.len().min(prefix.len());
        target[..count].copy_from_slice(&prefix[..count]);
        prefix.drain(..count);
        Ok(count)
    }

    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if let Some(greeting) = self.sent_greeting.lock().await.take() {
            if greeting != bytes {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Ok(());
        }
        self.channel.write(bytes).await
    }
}

async fn quic_connect(
    endpoint: &quinn::Endpoint,
    identity: &RemoteIdentity,
) -> io::Result<quinn::Connection> {
    tokio::time::timeout(
        Duration::from_secs(5),
        endpoint
            .connect(identity.endpoint, &identity.server_name)
            .map_err(io::Error::other)?,
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    .map_err(io::Error::other)
}

/// A proved stream retains its decoder and an optional parked server greeting.
struct ProvedControl {
    control: NativeChannel,
    receive: Receive,
    greeting: Option<Vec<u8>>,
}

async fn quic_session_on(
    connection: quinn::Connection,
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    plugins: crate::plugin_control::Registry,
    proof: Option<ProvedControl>,
    standby: &tokio::sync::watch::Sender<bool>,
) -> io::Result<()> {
    let result = async {
        let ProvedControl { control, receive: mut rx, greeting: cached } = if let Some(proof) = proof { proof } else {
            let (send, receive) = connection.open_bi().await.map_err(io::Error::other)?;
            ProvedControl { control: NativeChannel::control(send, receive)?, receive: Receive::default(), greeting: None }
        };
        // Opening a QUIC stream emits no packet until there is data. Send the
        // greeting once, then let common dispatch consume the server's greeting.
        let mut tx = crate::transport::Transmit::default();
        let greeting = infraternal_protocol::Frame::Hello { version:1, caps:remote_quic::REMOTE_WRITER_BINDING | infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS | if renewal.is_some() { crate::remote_renewal::LIVE_RENEWAL } else { 0 }, client_info:"infraternal agent" };
        tx.send(&control, 0, &greeting).await?;
        let mut sent_greeting = Vec::new();
        encode_frame_into(&greeting, &mut sent_greeting).map_err(io::Error::other)?;
        let prefix = if let Some(cached) = cached { cached } else {
            let hello = tokio::time::timeout(Duration::from_secs(5), rx.next(&control)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            let mut encoded = Vec::new();
            encode_frame_into(&hello.frame, &mut encoded).map_err(io::Error::other)?;
            encoded
        };
        let hello = infraternal_protocol::decode_frame(&prefix).map_err(io::Error::other)?;
        let binding = remote_quic::negotiate_binding(&connection, &hello.frame)?;
        standby.send_replace(matches!(hello.frame, infraternal_protocol::Frame::Hello { caps, .. } if caps & infraternal_plugin_api::channel::REMOTE_STANDBY != 0));
        let control = PrefixedControl { channel:ControlChannel::Quic(control), prefix:Mutex::new(prefix), sent_greeting:Mutex::new(Some(sent_greeting)), receive:Mutex::new(rx) };
        let mut terminals = JoinSet::new();
        let dispatch = daemon::run_authenticated_with_plugins(&control, state.clone(), identity.execution_uid, renewal,plugins);
        tokio::pin!(dispatch);
        loop {
            // Keep partial binding progress across completed terminal jobs.
            // Cancelling this accept on each completion would lose consumed bytes.
            let next = remote_quic::accept_bound(&binding);
            tokio::pin!(next);
            loop {
            tokio::select! {
                result = &mut dispatch => return result,
                _ = connection.closed() => return Err(io::ErrorKind::BrokenPipe.into()),
                terminal = &mut next => {
                    let channel = NativeChannel::terminal(terminal?)?;
                    if terminals.len() >= crate::sessions::MAX_SESSIONS { channel.retire(); break; }
                    let state = state.clone();
                    terminals.spawn(async move { let _ = daemon::run_bound_terminal(&channel,Some(state)).await; });
                    break;
                }
                _ = terminals.join_next(), if !terminals.is_empty() => {}
            }
            }
        }
    }.await;
    connection.close(0u32.into(), b"");
    result
}

#[cfg(test)]
#[path = "remote_client_tests.rs"]
mod tests;

#[path = "remote_dial_runtime.rs"]
mod dial_runtime;

#[path = "remote_server_path.rs"]
mod server_path;
