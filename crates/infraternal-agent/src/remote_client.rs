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

/// Run until cancelled. Healthy idle connections have no retry/heartbeat timer.
/// # Errors
/// Refuses local uid mismatch or invalid credentials before contacting the server.
pub async fn run(identity: &RemoteIdentity, state: Option<PathBuf>) -> io::Result<()> {
    if identity.execution_uid != nix::unistd::Uid::effective().as_raw() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let tls = remote_tls::client_config(&identity.identity, &identity.roots)?;
    let mut backoff = Duration::from_millis(200);
    loop {
        let started = tokio::time::Instant::now();
        let quic = dial_runtime::DialRuntime::new();
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std::net::UdpSocket::bind(if identity.endpoint.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            })?,
            quic.runtime(),
        )?;
        endpoint.set_default_client_config(remote_quic::client_config(
            &identity.identity,
            &identity.roots,
        )?);
        let connected = dial_preferred(&endpoint, identity, &tls).await;
        match connected {
            Ok(Connected::Quic(connection)) => {
                let _ = quic_session(connection, identity, state.clone()).await;
            }
            Ok(Connected::Tcp(connection)) => {
                // The losing handshake otherwise retains Quinn drain timers after
                // Connecting is dropped. Cancel only this attempt's UDP drivers;
                // the authenticated TCP channel and rootless shims are independent.
                drop(endpoint);
                drop(quic);
                let _ = daemon::run_authenticated(
                    &connection.channel,
                    state.clone(),
                    identity.execution_uid,
                )
                .await;
            }
            Err(_) => {}
        }
        if started.elapsed() > Duration::from_secs(10) {
            backoff = Duration::from_millis(200);
        }
        let jitter = Duration::from_millis(u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 100);
        tokio::time::sleep(backoff + jitter).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
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

// Replay the negotiated Hello into common dispatch while retaining the same
// decoder: its first read may also contain the following control frame.
struct PrefixedControl {
    channel: NativeChannel,
    prefix: Mutex<Vec<u8>>,
    sent_greeting: Mutex<Option<Vec<u8>>>,
    receive: Mutex<Receive>,
}
impl Channel for PrefixedControl {
    fn native_stream_id(&self) -> Option<u32> {
        Some(0)
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
            encode_frame_into(&frame.frame, &mut prefix).map_err(io::Error::other)?;
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

async fn quic_session(
    connection: quinn::Connection,
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
) -> io::Result<()> {
    let result = async {
        let (send, receive) = connection.open_bi().await.map_err(io::Error::other)?;
        let control = NativeChannel::control(send, receive)?;
        // Opening a QUIC stream emits no packet until there is data. Send the
        // greeting once, then let common dispatch consume the server's greeting.
        let mut tx = crate::transport::Transmit::default();
        let greeting = infraternal_protocol::Frame::Hello { version:1, caps:remote_quic::REMOTE_WRITER_BINDING, client_info:"infraternal agent" };
        tx.send(&control, 0, &greeting).await?;
        let mut sent_greeting = Vec::new();
        encode_frame_into(&greeting, &mut sent_greeting).map_err(io::Error::other)?;
        let mut rx = Receive::default();
        let hello = tokio::time::timeout(Duration::from_secs(5), rx.next(&control)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let binding = remote_quic::negotiate_binding(&connection, &hello.frame)?;
        let mut prefix = Vec::new();
        encode_frame_into(&hello.frame, &mut prefix).map_err(io::Error::other)?;
        let control = PrefixedControl { channel:control, prefix:Mutex::new(prefix), sent_greeting:Mutex::new(Some(sent_greeting)), receive:Mutex::new(rx) };
        let mut terminals = JoinSet::new();
        let dispatch = daemon::run_authenticated(&control, state.clone(), identity.execution_uid);
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
                    terminals.spawn(async move { let _ = daemon::run_bound_terminal(&channel,state).await; });
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
