//! Carries the authenticated remote control channel through the public HTTPS listener [168,196], #291.
//!
//! The link speaks agent link v2 (see `infraternal_plugin_remote::agent_link`):
//! the infraternal agent proves its D168 key over a transcript bound to the
//! TLS session it sees, and the server must answer with its current leg-B
//! leaf and a signature over the same transcript. The leaf passes the same
//! chain, name and [`ServerLeafFloor`] checks as on a direct leg-B dial
//! before any protocol frame is sent, so an outer HTTPS certificate alone
//! (pinned, publicly trusted or copied) never makes a peer the server (#559).

use crate::{channel::Channel, remote_tls::Identity};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use bytes::Bytes;
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use infraternal_plugin_remote::{
    agent_link::{
        AgentLinkChallenge, AgentLinkProofV2, AgentLinkReadyV2, AgentTranscript, NONCE_LEN,
        PROOF_V2, READY_V2, ServerProofPolicy, agent_proof_bytes_v2, message_type, server_unproved,
        tls_channel_binding, verify_ready_v2,
    },
    server_leaf_floor::ServerLeafFloor,
};
use infraternal_protocol::MAX_FRAME_LEN;
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    sign::Signer,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use std::io;
use std::time::Duration;
use tokio::{
    net::TcpStream,
    sync::{Mutex, watch},
    time::Instant,
};
use tokio_openssl::SslStream;
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
use url::Url;
use uuid::Uuid;

const HANDSHAKE: Duration = Duration::from_secs(5);
const KEEPALIVE: Duration = Duration::from_secs(25);
const WS_PATH: &str = "/remote/agent";
const MAX_WS_MESSAGE: usize = MAX_FRAME_LEN + 64;
/// Largest `ready-v2` the agent reads: a leaf of at most 4 KiB, base64, plus
/// a signature and field names.
const MAX_READY_MESSAGE: usize = 8192;

type Socket = WebSocketStream<SslStream<TcpStream>>;

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
    /// The upgraded route did not return a valid app-level challenge.
    Challenge,
}

/// A verified HTTPS WebSocket carrying muxed infraternal protocol frames.
pub struct AgentWebSocket {
    writer: Mutex<SplitSink<Socket, Message>>,
    reader: Mutex<SplitStream<Socket>>,
    pending: Mutex<Bytes>,
    retired: watch::Sender<bool>,
}

struct RetireOnDrop<'a> {
    retired: &'a watch::Sender<bool>,
    complete: bool,
}
impl Drop for RetireOnDrop<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.retired.send_replace(true);
        }
    }
}

fn closed() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "remote HTTPS agent link refused",
    )
}

fn trace_client_phase<T>(phase: &'static str, result: io::Result<T>) -> io::Result<T> {
    if std::env::var_os("INFRATERNAL_REMOTE_LINK_TRACE").is_some() {
        match &result {
            Ok(_) => eprintln!("remote agent HTTPS client phase={phase} complete"),
            Err(error) => eprintln!(
                "remote agent HTTPS client phase={phase} kind={:?}",
                error.kind()
            ),
        }
    }
    result
}

/// The TLS client for the agent's server link: either the enrolled server's pinned root, or the
/// first trusted fixed system bundle from [`tls_roots`].
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

fn sign_challenge(key: &PKey<Private>, message: &[u8]) -> io::Result<Vec<u8>> {
    let mut signer = match key.id() {
        Id::ED25519 => Signer::new_without_digest(key),
        Id::EC => Signer::new(MessageDigest::sha256(), key),
        _ => return Err(refused()),
    }
    .map_err(|_| refused())?;
    signer.sign_oneshot_to_vec(message).map_err(|_| refused())
}

/// How the infraternal agent judges the server on the HTTPS link: the same
/// trust as its leg-B dials.
pub struct ServerTrust<'a> {
    /// The enrolled CA roots.
    pub roots: &'a [X509],
    /// The server name its leaf must carry.
    pub server_name: &'a str,
    /// The newest server leaf this enrollment accepted; refuses older ones.
    pub floor: &'a ServerLeafFloor,
    /// Refuse a server that did not check this TLS session's binding. True
    /// when the enrollment pins the server's own HTTPS certificate, which the
    /// server then serves itself (see [`binding_required`]).
    pub require_binding: bool,
}

/// Whether an enrollment must insist on a TLS-bound answer: it pins an HTTPS
/// certificate of its own (`https_der`, the certificate `config.tls`
/// serves), so the server terminates this TLS session itself and can always
/// check the binding.
///
/// Not with system roots (a reverse proxy terminates TLS), and not when the
/// pin is the CA root itself (older enrollments): a TLS proxy holding a
/// CA-issued certificate may sit in front of such a server. In both cases
/// the server still checks the binding whenever it terminates TLS itself.
#[must_use]
pub fn binding_required(
    https_root: Option<&X509>,
    https_system_roots: bool,
    roots: &[X509],
) -> bool {
    let Some(pin) = https_root.filter(|_| !https_system_roots) else {
        return false;
    };
    let Ok(pin) = pin.to_der() else {
        // An unreadable pin cannot have completed TLS; be strict.
        return true;
    };
    !roots
        .iter()
        .any(|root| root.to_der().is_ok_and(|root| root == pin))
}

/// Dial the public app origin, prove possession of the enrolled D168 key and
/// require the server to prove its current leg-B leaf (agent link v2).
/// # Errors
/// Returns an error if TLS trust, the WebSocket upgrade, the challenge, the
/// key proof or the server's proof fails. A server that does not prove its
/// leaf (or answers v1) is refused with `InvalidData`, never
/// `PermissionDenied`, so it cannot start certificate recovery.
pub async fn connect(
    public_origin: &str,
    host_id: Uuid,
    identity: &Identity,
    https_root: Option<&X509>,
    https_system_roots: bool,
    server: &ServerTrust<'_>,
) -> io::Result<AgentWebSocket> {
    let (mut socket, challenge, binding) = trace_client_phase(
        "challenge",
        socket_with_challenge(public_origin, https_root, https_system_roots)
            .await
            .map_err(preflight_io),
    )?;
    let server_nonce: [u8; NONCE_LEN] = trace_client_phase(
        "nonce",
        B64.decode(&challenge.nonce)
            .ok()
            .and_then(|nonce| nonce.try_into().ok())
            .ok_or_else(refused),
    )?;
    let mut client_nonce = [0; NONCE_LEN];
    openssl::rand::rand_bytes(&mut client_nonce).map_err(|_| refused())?;
    let message = agent_proof_bytes_v2(host_id, &server_nonce, &client_nonce, binding.as_ref());
    let certificate_der = trace_client_phase(
        "certificate-encode",
        identity.certificate.to_der().map_err(|_| refused()),
    )?;
    let signature = trace_client_phase("proof-sign", sign_challenge(&identity.key, &message))?;
    let proof = AgentLinkProofV2 {
        message_type: PROOF_V2.to_owned(),
        host_id,
        certificate_der: B64.encode(&certificate_der),
        client_nonce: B64.encode(client_nonce),
        channel_binding: binding.map(|binding| B64.encode(binding)),
        signature: B64.encode(signature),
    };
    let encoded = trace_client_phase(
        "proof-encode",
        serde_json::to_string(&proof).map_err(|_| refused()),
    )?;
    let sent = tokio::time::timeout(HANDSHAKE, socket.send(Message::Text(encoded.into())))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
        .and_then(|result| result.map_err(|_| refused()));
    trace_client_phase("proof-send", sent)?;
    let ready = tokio::time::timeout(HANDSHAKE, socket.next())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
        .and_then(|message| {
            message
                .ok_or_else(closed)
                .and_then(|message| message.map_err(|_| refused()))
        });
    let ready = trace_client_phase("ready-receive", ready)?;
    let transcript = AgentTranscript {
        host_id,
        server_nonce: &server_nonce,
        client_nonce: &client_nonce,
        agent_certificate_der: &certificate_der,
        binding: binding.as_ref(),
    };
    trace_client_phase("server-proof", server_proof(&ready, server, &transcript))?;
    let (writer, reader) = socket.split();
    Ok(AgentWebSocket {
        writer: Mutex::new(writer),
        reader: Mutex::new(reader),
        pending: Mutex::new(Bytes::new()),
        retired: watch::channel(false).0,
    })
}

/// Check the server's answer to the proof: a `ready-v2` whose leaf and
/// signature pass [`verify_ready_v2`] and whose leaf the floor admits. A v1
/// `ready` (a server built before #559) proves nothing and is refused.
fn server_proof(
    ready: &Message,
    server: &ServerTrust<'_>,
    transcript: &AgentTranscript<'_>,
) -> io::Result<()> {
    let Message::Text(ready) = ready else {
        return Err(server_unproved());
    };
    if ready.len() > MAX_READY_MESSAGE || message_type(ready.as_str()).as_deref() != Some(READY_V2)
    {
        return Err(server_unproved());
    }
    let ready: AgentLinkReadyV2 =
        serde_json::from_str(ready.as_str()).map_err(|_| server_unproved())?;
    let leaf_der = canonical(&ready.server_certificate_der)?;
    let signature = canonical(&ready.signature)?;
    verify_ready_v2(
        &ServerProofPolicy {
            roots: server.roots,
            server_name: server.server_name,
            require_binding: server.require_binding,
        },
        transcript,
        &leaf_der,
        ready.channel_bound,
        &signature,
    )?;
    // `verify_ready_v2` checked that this DER is exactly the leaf it verified;
    // the floor reads the DER itself (#580).
    server.floor.admit(&leaf_der)
}

/// Decode canonical base64url from the server, or refuse it as unproved.
fn canonical(value: &str) -> io::Result<Vec<u8>> {
    let bytes = B64.decode(value).map_err(|_| server_unproved())?;
    if B64.encode(&bytes) != value {
        return Err(server_unproved());
    }
    Ok(bytes)
}

/// Prove that the target can complete the app's WebSocket route and receive its challenge.
/// No identity is sent during preflight; the certificate proof follows only after enrollment.
/// # Errors
/// Returns a classified error when DNS, TCP, TLS, upgrade, or challenge setup fails.
pub async fn preflight(
    public_origin: &str,
    https_root: Option<&X509>,
    https_system_roots: bool,
) -> Result<(), PreflightFailure> {
    let (socket, _, _) =
        socket_with_challenge(public_origin, https_root, https_system_roots).await?;
    drop(socket);
    Ok(())
}

fn preflight_io(error: PreflightFailure) -> io::Error {
    let kind = match error {
        PreflightFailure::InvalidOrigin => io::ErrorKind::InvalidInput,
        PreflightFailure::Dns => io::ErrorKind::AddrNotAvailable,
        PreflightFailure::Connect => io::ErrorKind::NotConnected,
        PreflightFailure::Tls => io::ErrorKind::PermissionDenied,
        PreflightFailure::Upgrade | PreflightFailure::Challenge => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, "remote HTTPS agent link refused")
}

/// Dial the origin, complete TLS and the WebSocket upgrade, and read the
/// server's challenge. Also returns the TLS session's channel binding (see
/// [`tls_channel_binding`]), taken before any application byte.
async fn socket_with_challenge(
    public_origin: &str,
    root: Option<&X509>,
    system_roots: bool,
) -> Result<(Socket, AgentLinkChallenge, Option<[u8; 32]>), PreflightFailure> {
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
    tokio::time::timeout(HANDSHAKE, std::pin::Pin::new(&mut tls).connect())
        .await
        .map_err(|_| PreflightFailure::Tls)?
        .map_err(|_| PreflightFailure::Tls)?;
    let binding = tls_channel_binding(tls.ssl());
    url.set_scheme("wss")
        .map_err(|()| PreflightFailure::InvalidOrigin)?;
    url.set_path(WS_PATH);
    url.set_query(None);
    let request = url
        .as_str()
        .into_client_request()
        .map_err(|_| PreflightFailure::InvalidOrigin)?;
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_WS_MESSAGE);
    config.max_frame_size = Some(MAX_WS_MESSAGE);
    let (mut socket, _) = tokio::time::timeout(
        HANDSHAKE,
        client_async_with_config(request, tls, Some(config)),
    )
    .await
    .map_err(|_| PreflightFailure::Upgrade)?
    .map_err(|_| PreflightFailure::Upgrade)?;
    let message = tokio::time::timeout(HANDSHAKE, socket.next())
        .await
        .map_err(|_| PreflightFailure::Upgrade)?
        .ok_or(PreflightFailure::Upgrade)?
        .map_err(|_| PreflightFailure::Upgrade)?;
    let Message::Text(message) = message else {
        return Err(PreflightFailure::Challenge);
    };
    let challenge: AgentLinkChallenge =
        serde_json::from_str(message.as_str()).map_err(|_| PreflightFailure::Challenge)?;
    let nonce = B64
        .decode(&challenge.nonce)
        .map_err(|_| PreflightFailure::Challenge)?;
    if challenge.message_type != "challenge"
        || nonce.len() != 32
        || B64.encode(nonce) != challenge.nonce
    {
        return Err(PreflightFailure::Challenge);
    }
    Ok((socket, challenge, binding))
}

impl AgentWebSocket {
    async fn send_control(&self, message: Message) -> io::Result<()> {
        let mut writer = self.writer.lock().await;
        tokio::time::timeout(HANDSHAKE, writer.send(message))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(|_| closed())
    }
}

impl Channel for AgentWebSocket {
    fn frame_timeout(&self) -> Option<Duration> {
        Some(HANDSHAKE)
    }
    fn retire(&self) {
        self.retired.send_replace(true);
    }
    async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut retired = self.retired.subscribe();
        if *retired.borrow() {
            return Err(closed());
        }
        let mut pending = self.pending.lock().await;
        if !pending.is_empty() {
            let count = bytes.len().min(pending.len());
            bytes[..count].copy_from_slice(&pending[..count]);
            *pending = pending.slice(count..);
            return Ok(count);
        }
        drop(pending);
        let mut reader = self.reader.lock().await;
        let mut keepalive = tokio::time::interval_at(Instant::now() + KEEPALIVE, KEEPALIVE);
        loop {
            tokio::select! {
                biased;
                _ = retired.changed() => return Err(closed()),
                _ = keepalive.tick() => self.send_control(Message::Ping(Vec::new().into())).await?,
                message = reader.next() => match message {
                    Some(Ok(Message::Binary(data))) => {
                        if data.is_empty() { continue; }
                        let count = bytes.len().min(data.len());
                        bytes[..count].copy_from_slice(&data[..count]);
                        *self.pending.lock().await = data.slice(count..);
                        return Ok(count);
                    }
                    Some(Ok(Message::Ping(data))) => self.send_control(Message::Pong(data)).await?,
                    Some(Ok(Message::Pong(_))) => {},
                    Some(Ok(Message::Close(_)) | Err(_)) | None => return Err(closed()),
                    Some(Ok(_)) => return Err(io::ErrorKind::InvalidData.into()),
                }
            }
        }
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_WS_MESSAGE {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut retired = self.retired.subscribe();
        if *retired.borrow() {
            return Err(closed());
        }
        let mut writer = tokio::select! {
            biased;
            _ = retired.changed() => return Err(closed()),
            writer = self.writer.lock() => writer,
        };
        let mut guard = RetireOnDrop {
            retired: &self.retired,
            complete: false,
        };
        let result = tokio::select! {
            biased;
            _ = retired.changed() => Err(closed()),
            result = tokio::time::timeout(
                HANDSHAKE,
                writer.send(Message::Binary(Bytes::copy_from_slice(bytes))),
            ) => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(closed()),
                Err(_) => Err(io::ErrorKind::TimedOut.into()),
            },
        };
        guard.complete = result.is_ok();
        result
    }
}
