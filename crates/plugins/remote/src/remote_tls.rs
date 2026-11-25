//! Authenticates dial-out TCP/TLS fallback before dispatching unchanged leg-B framing; callers recheck durable host admission [64][130], #78.
//!
//! The same mutual TLS also runs inside the HTTPS WebSocket fallback (#559):
//! a TLS session sits on a [`Carrier`], which is either the direct TCP socket
//! or a byte tunnel through another protocol. Whatever carries the bytes, the
//! handshake, the trust (our CA only), the ALPN and the checks are the same,
//! so a carrier that terminates its own TLS (a reverse proxy) only ever sees
//! leg-B ciphertext.

use crate::channel::Channel;
use openssl::{
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslConnector},
    x509::X509,
};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// An ordered, reliable byte stream that is not a TCP socket, such as the
/// HTTPS WebSocket adapter, boxed so one [`TcpTls`] type serves every path.
pub trait Tunnel: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Tunnel for T {}

/// What a leg-B TLS session runs on.
///
/// The TCP fallback keeps static dispatch (one `match` per read or write);
/// only a tunnel pays a virtual call, which is small next to the TLS record
/// work and the tunnel's own framing.
pub enum Carrier {
    /// The direct TCP/TLS fallback socket.
    Tcp(tokio::net::TcpStream),
    /// A byte tunnel through another protocol (#559).
    Tunnel(Box<dyn Tunnel>),
}

impl AsyncRead for Carrier {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(socket) => Pin::new(socket).poll_read(cx, buf),
            Self::Tunnel(tunnel) => Pin::new(tunnel.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Carrier {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(socket) => Pin::new(socket).poll_write(cx, data),
            Self::Tunnel(tunnel) => Pin::new(tunnel.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(socket) => Pin::new(socket).poll_flush(cx),
            Self::Tunnel(tunnel) => Pin::new(tunnel.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(socket) => Pin::new(socket).poll_shutdown(cx),
            Self::Tunnel(tunnel) => Pin::new(tunnel.as_mut()).poll_shutdown(cx),
        }
    }
}

/// The TLS stream every leg-B fallback channel holds.
type Stream = tokio_openssl::SslStream<Carrier>;

/// Configured public identity plus process-local private key; no Debug or serialization.
pub struct Identity {
    /// Public endpoint certificate, with the appropriate client/server EKU.
    pub certificate: X509,
    /// Locally supplied private key, never sent to the peer.
    pub key: PKey<Private>,
}

/// Verified peer fingerprint is still subject to durable host revocation admission.
pub struct Connection {
    /// Authenticated full-duplex framing channel.
    pub channel: TcpTls,
    /// SHA256 of the exact leaf DER, for the server authority ledger.
    pub peer_fingerprint: [u8; 32],
    /// The server's verified leaf on a dialed connection, which the
    /// infraternal agent checks against its
    /// [`crate::server_leaf_floor::ServerLeafFloor`] before using the channel.
    /// `None` on accepted connections: the server keeps one `Connection` per
    /// TCP host link and needs only the fingerprint, so it does not retain a
    /// parsed certificate per host.
    pub peer_leaf: Option<X509>,
}

/// A TLS exchange that cannot enter ordinary host admission or control dispatch.
pub struct RecoveryConnection {
    /// Restricted raw channel used only by the recovery request parser.
    pub channel: TcpTls,
    /// The server's verified leaf on a dialed recovery connection (`None` on
    /// the accepting side, where the peer sends no certificate).
    pub server_leaf: Option<X509>,
}

/// The selected ALPN determines which single purpose may use an accepted TLS socket.
pub enum AcceptedConnection {
    /// Ordinary mTLS host transport with its verified leaf fingerprint.
    Host(Connection),
    /// Server-authenticated recovery exchange without a client certificate.
    Recovery(RecoveryConnection),
}

/// Full-duplex TLS channel over a [`Carrier`]. Reader and writer retain TLS state across readiness waits.
/// Cancelling a partial frame write requires retiring the entire connection.
pub struct TcpTls {
    retired: tokio::sync::watch::Sender<bool>,
    reader: tokio::sync::Mutex<tokio::io::ReadHalf<Stream>>,
    writer: tokio::sync::Mutex<tokio::io::WriteHalf<Stream>>,
}
// A TLS frame may be partially accepted before a caller cancels its future.
// The guard makes such cancellation terminal; no suffix can be replaced by
// another frame. Waiting for the serialized writer alone has no such effect.
struct RetireOnDrop<'a> {
    retired: &'a tokio::sync::watch::Sender<bool>,
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
impl Channel for TcpTls {
    fn frame_timeout(&self) -> Option<std::time::Duration> {
        Some(HANDSHAKE)
    }
    fn retire(&self) {
        self.retired.send_replace(true);
    }
    async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        use tokio::io::AsyncReadExt;
        let mut retired = self.retired.subscribe();
        if *retired.borrow() {
            return Err(closed());
        }
        // Retirement wakes both directions. Healthy idle reads have no timer.
        tokio::select! {
            biased;
            _ = retired.changed() => Err(closed()),
            result = async { self.reader.lock().await.read(bytes).await } => result,
        }
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
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
            // The flush is free on TCP; a tunnel may buffer until it, so
            // every frame leaves before the write reports success.
            result = tokio::time::timeout(HANDSHAKE, async {
                writer.write_all(bytes).await?;
                writer.flush().await
            }) => {
                result.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
            }
        };
        guard.complete = result.is_ok();
        result
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "remote infraternal agent transport refused",
    )
}

const ALPN: &[u8] = b"\x0dinfraternal/1";
const PROTOCOL: &[u8] = b"infraternal/1";
/// The ALPN wire form of the recovery protocol.
const RECOVERY_ALPN: &[u8] = b"\x1dinfraternal/remote-recovery/1";
/// The certificate-free recovery protocol (#285). It may only ever reach the recovery service.
const RECOVERY_PROTOCOL: &[u8] = b"infraternal/remote-recovery/1";
/// What a recovery-aware listener offers: the normal protocol first, then recovery.
const ALPN_WITH_RECOVERY: &[u8] = b"\x0dinfraternal/1\x1dinfraternal/remote-recovery/1";
const HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(5);

fn configure(
    context: &mut openssl::ssl::SslContextBuilder,
    identity: &Identity,
    roots: &[X509],
) -> io::Result<()> {
    use openssl::{ssl::SslVersion, x509::store::X509StoreBuilder};
    if roots.is_empty() || roots.len() > 16 {
        return Err(denied());
    }
    context
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| denied())?;
    context
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| denied())?;
    context
        .set_certificate(&identity.certificate)
        .map_err(|_| denied())?;
    context
        .set_private_key(&identity.key)
        .map_err(|_| denied())?;
    context.check_private_key().map_err(|_| denied())?;
    let mut trust = X509StoreBuilder::new().map_err(|_| denied())?;
    for root in roots {
        trust.add_cert(root.clone()).map_err(|_| denied())?;
    }
    context.set_cert_store(trust.build());
    // Limit certificate-chain work independently of wire-frame admission.
    context.set_verify_depth(2);
    Ok(())
}

/// Build the existing OpenSSL fallback stack with mutual certificate verification.
/// # Errors
/// Refuses inconsistent identity, empty trust or unsupported TLS configuration.
pub fn server_config(identity: &Identity, roots: &[X509]) -> io::Result<SslAcceptor> {
    use openssl::ssl::{AlpnError, SslMethod, SslVerifyMode, select_next_proto};
    let mut config =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).map_err(|_| denied())?;
    configure(&mut config, identity, roots)?;
    config.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    config.set_alpn_select_callback(|_, offered| {
        select_next_proto(ALPN, offered).ok_or(AlpnError::ALERT_FATAL)
    });
    Ok(config.build())
}

/// Build the same TLS listener with one isolated recovery ALPN that permits no client leaf.
/// # Errors
/// Refuses inconsistent identity, empty trust or unsupported TLS configuration.
pub fn recovery_server_config(identity: &Identity, roots: &[X509]) -> io::Result<SslAcceptor> {
    use openssl::ssl::{AlpnError, SslMethod, SslVerifyMode, select_next_proto};
    let mut config =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).map_err(|_| denied())?;
    configure(&mut config, identity, roots)?;
    // Optional certificate exchange is safe only because accept_recovery_aware
    // requires a verified leaf before it returns the ordinary-host variant.
    config.set_verify(SslVerifyMode::PEER);
    config.set_alpn_select_callback(|_, offered| {
        select_next_proto(ALPN_WITH_RECOVERY, offered).ok_or(AlpnError::ALERT_FATAL)
    });
    Ok(config.build())
}
/// Build pinned trust and the local host identity for an outgoing connection.
/// # Errors
/// Refuses inconsistent identity, empty trust or unsupported TLS configuration.
pub fn client_config(identity: &Identity, roots: &[X509]) -> io::Result<SslConnector> {
    use openssl::ssl::{SslMethod, SslVerifyMode};
    let mut config = SslConnector::builder(SslMethod::tls_client()).map_err(|_| denied())?;
    configure(&mut config, identity, roots)?;
    config.set_verify(SslVerifyMode::PEER);
    config.set_alpn_protos(ALPN).map_err(|_| denied())?;
    Ok(config.build())
}

/// Build server-only trust for the one recovery ALPN; this connector sends no client certificate.
/// # Errors
/// Refuses empty trust or unsupported TLS configuration.
pub fn recovery_client_config(roots: &[X509]) -> io::Result<SslConnector> {
    use openssl::{
        ssl::{SslMethod, SslVerifyMode, SslVersion},
        x509::store::X509StoreBuilder,
    };
    if roots.is_empty() || roots.len() > 16 {
        return Err(denied());
    }
    let mut config = SslConnector::builder(SslMethod::tls_client()).map_err(|_| denied())?;
    config
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| denied())?;
    config
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| denied())?;
    let mut trust = X509StoreBuilder::new().map_err(|_| denied())?;
    for root in roots {
        trust.add_cert(root.clone()).map_err(|_| denied())?;
    }
    config.set_cert_store(trust.build());
    config.set_verify_depth(2);
    config.set_verify(SslVerifyMode::PEER);
    config
        .set_alpn_protos(RECOVERY_ALPN)
        .map_err(|_| denied())?;
    Ok(config.build())
}
/// Dial only an outgoing connection and verify the server name before exposing bytes.
/// # Errors
/// Refuses network/deadline errors or failed mutual certificate/name verification.
pub async fn dial(
    address: SocketAddr,
    name: &str,
    config: &SslConnector,
) -> io::Result<Connection> {
    dial_over(Carrier::Tcp(dial_socket(address).await?), name, config).await
}

/// Run the outgoing mutual TLS handshake over an existing carrier and verify
/// the server name, exactly as [`dial`] does on a fresh TCP socket. The
/// HTTPS fallback uses it inside its WebSocket (#559).
/// # Errors
/// Refuses a deadline or failed mutual certificate/name verification.
pub async fn dial_over(
    carrier: Carrier,
    name: &str,
    config: &SslConnector,
) -> io::Result<Connection> {
    let ssl = config
        .configure()
        .map_err(|_| denied())?
        .into_ssl(name)
        .map_err(|_| denied())?;
    let mut stream = tokio_openssl::SslStream::new(ssl, carrier).map_err(|_| denied())?;
    tokio::time::timeout(HANDSHAKE, std::pin::Pin::new(&mut stream).connect())
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
    finish(stream, true)
}

/// Check that `carrier` reaches a leg-B TLS listener, without sending a
/// certificate and without trusting the answer.
///
/// Enrollment preflight uses this inside the HTTPS WebSocket before the host
/// has a certificate (and, for SSH joins, before it knows the CA). It proves
/// only that something answers TLS 1.3 with the `infraternal/1` ALPN; it
/// proves nothing about who answers, which is why it trusts nothing and the
/// real link ([`dial_over`]) checks everything again. The server refuses the
/// session after its first flight, because no client certificate is sent.
/// # Errors
/// Returns `InvalidData` when the peer does not complete a TLS 1.3 server
/// flight with that ALPN within the handshake deadline.
pub async fn probe_over(carrier: Carrier, name: &str) -> io::Result<()> {
    use openssl::ssl::{SslMethod, SslVerifyMode, SslVersion};
    let unexpected = || io::Error::from(io::ErrorKind::InvalidData);
    let mut config = SslConnector::builder(SslMethod::tls_client()).map_err(|_| unexpected())?;
    config
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| unexpected())?;
    config.set_verify(SslVerifyMode::NONE);
    config.set_alpn_protos(ALPN).map_err(|_| unexpected())?;
    let ssl = config
        .build()
        .configure()
        .map_err(|_| unexpected())?
        .verify_hostname(false)
        .into_ssl(name)
        .map_err(|_| unexpected())?;
    let mut stream = tokio_openssl::SslStream::new(ssl, carrier).map_err(|_| unexpected())?;
    tokio::time::timeout(HANDSHAKE, std::pin::Pin::new(&mut stream).connect())
        .await
        .map_err(|_| unexpected())?
        .map_err(|_| unexpected())?;
    if stream.ssl().selected_alpn_protocol() != Some(PROTOCOL) {
        return Err(unexpected());
    }
    Ok(())
}

/// Dial the server-authenticated recovery ALPN without offering an expired client certificate.
/// # Errors
/// Refuses server name, root, ALPN, handshake, deadline or network failures.
pub async fn dial_recovery(
    address: SocketAddr,
    name: &str,
    config: &SslConnector,
) -> io::Result<RecoveryConnection> {
    use openssl::x509::X509VerifyResult;

    let socket = Carrier::Tcp(dial_socket(address).await?);
    let ssl = config
        .configure()
        .map_err(|_| denied())?
        .into_ssl(name)
        .map_err(|_| denied())?;
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).map_err(|_| denied())?;
    tokio::time::timeout(HANDSHAKE, std::pin::Pin::new(&mut stream).connect())
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
    if stream.ssl().verify_result() != X509VerifyResult::OK
        || stream.ssl().selected_alpn_protocol() != Some(RECOVERY_PROTOCOL)
    {
        return Err(denied());
    }
    // This connector is built without a local identity; its peer certificate is
    // the verified server leaf and cannot prove which client certificate was sent.
    let server_leaf = stream.ssl().peer_certificate().ok_or_else(denied)?;
    Ok(RecoveryConnection {
        channel: channel(stream),
        server_leaf: Some(server_leaf),
    })
}
/// Keep connection construction separate so OS liveness can be verified on the
/// actual outgoing socket before the encrypted channel owns its split halves.
async fn dial_socket(address: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let socket = tokio::time::timeout(HANDSHAKE, tokio::net::TcpStream::connect(address))
        .await
        .map_err(|_| denied())??;
    socket.set_nodelay(true)?;
    #[cfg(feature = "agent")]
    {
        use nix::sys::socket::{setsockopt, sockopt};
        // A silent server outage otherwise leaves an idle fallback established
        // indefinitely. Kernel probes need no daemon heartbeat or idle wakeups.
        setsockopt(&socket, sockopt::KeepAlive, &true)?;
        #[cfg(target_os = "linux")]
        {
            setsockopt(&socket, sockopt::TcpKeepIdle, &30)?;
            // Also bound outstanding writes: keepalive alone only covers idle
            // sockets, and a queued write can otherwise use the long TCP retry limit.
            setsockopt(&socket, sockopt::TcpUserTimeout, &60_000)?;
        }
        #[cfg(target_os = "macos")]
        setsockopt(&socket, sockopt::TcpKeepAlive, &30)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            setsockopt(&socket, sockopt::TcpKeepInterval, &10)?;
            setsockopt(&socket, sockopt::TcpKeepCount, &3)?;
        }
    }
    Ok(socket)
}

/// Authenticate a server-side accepted socket before handing it to host admission.
/// # Errors
/// Refuses failed mutual verification or a handshake deadline.
pub async fn accept(socket: tokio::net::TcpStream, config: &SslAcceptor) -> io::Result<Connection> {
    socket.set_nodelay(true)?;
    accept_over(Carrier::Tcp(socket), config).await
}

/// Run the server side of the mutual TLS handshake over an existing carrier,
/// with the same checks as [`accept`]. The HTTPS fallback uses it inside its
/// WebSocket (#559).
///
/// The production acceptor ([`recovery_server_config`]) does offer the
/// recovery ALPN, so a recovery peer can complete this handshake. It is still
/// refused here: `finish` requires the ordinary `infraternal/1` ALPN and never
/// hands the socket to the recovery exchange, which only the TCP/TLS listener
/// runs. The test `recovery_aware_acceptor_admits_only_a_valid_host_over_the_websocket`
/// pins this.
/// # Errors
/// Refuses failed mutual verification or a handshake deadline.
pub async fn accept_over(socket: Carrier, config: &SslAcceptor) -> io::Result<Connection> {
    let ssl = openssl::ssl::Ssl::new(config.context()).map_err(|_| denied())?;
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).map_err(|_| denied())?;
    tokio::time::timeout(HANDSHAKE, std::pin::Pin::new(&mut stream).accept())
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
    finish(stream, false)
}

/// Accept either unchanged mTLS host transport or the certificate-free recovery ALPN.
/// # Errors
/// Refuses missing/invalid ALPN, invalid certificate, non-recovery certificate omission or timeout.
pub async fn accept_recovery_aware(
    socket: tokio::net::TcpStream,
    config: &SslAcceptor,
) -> io::Result<AcceptedConnection> {
    use openssl::{hash::MessageDigest, x509::X509VerifyResult};

    socket.set_nodelay(true)?;
    let ssl = openssl::ssl::Ssl::new(config.context()).map_err(|_| denied())?;
    let mut stream =
        tokio_openssl::SslStream::new(ssl, Carrier::Tcp(socket)).map_err(|_| denied())?;
    tokio::time::timeout(HANDSHAKE, std::pin::Pin::new(&mut stream).accept())
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
    if stream.ssl().verify_result() != X509VerifyResult::OK {
        return Err(denied());
    }
    match stream.ssl().selected_alpn_protocol() {
        Some(PROTOCOL) => {
            let peer = stream.ssl().peer_certificate().ok_or_else(denied)?;
            let peer_fingerprint = peer
                .digest(MessageDigest::sha256())
                .map_err(|_| denied())?
                .as_ref()
                .try_into()
                .map_err(|_| denied())?;
            Ok(AcceptedConnection::Host(Connection {
                channel: channel(stream),
                peer_fingerprint,
                peer_leaf: None,
            }))
        }
        Some(RECOVERY_PROTOCOL) if stream.ssl().peer_certificate().is_none() => {
            Ok(AcceptedConnection::Recovery(RecoveryConnection {
                channel: channel(stream),
                server_leaf: None,
            }))
        }
        _ => Err(denied()),
    }
}

/// Finish an accepted TLS connection: require the negotiated ALPN and a verified client certificate.
/// `dialed` keeps the verified peer leaf (the server's) for the caller's
/// server-leaf check; an accepted connection keeps only its fingerprint.
fn finish(stream: Stream, dialed: bool) -> io::Result<Connection> {
    use openssl::{hash::MessageDigest, x509::X509VerifyResult};
    // Missing ALPN and missing client certificates cannot silently downgrade
    // this endpoint to another protocol. No application bytes escape this check.
    if stream.ssl().verify_result() != X509VerifyResult::OK
        || stream.ssl().selected_alpn_protocol() != Some(PROTOCOL)
    {
        return Err(denied());
    }
    let peer = stream.ssl().peer_certificate().ok_or_else(denied)?;
    let peer_fingerprint = peer
        .digest(MessageDigest::sha256())
        .map_err(|_| denied())?
        .as_ref()
        .try_into()
        .map_err(|_| denied())?;
    Ok(Connection {
        channel: channel(stream),
        peer_fingerprint,
        peer_leaf: dialed.then_some(peer),
    })
}

/// Wrap an accepted TLS stream as a channel that can be retired.
fn channel(stream: Stream) -> TcpTls {
    let (reader, writer) = tokio::io::split(stream);
    TcpTls {
        retired: tokio::sync::watch::channel(false).0,
        reader: tokio::sync::Mutex::new(reader),
        writer: tokio::sync::Mutex::new(writer),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod tests {
    #[cfg(test)]
    use super::*;
    #[cfg(not(test))]
    use super::{Identity, PKey, X509};
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        x509::{
            X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        },
    };
    #[cfg(test)]
    use tokio::net::TcpListener;

    /// Construct a disposable certificate fixture for real transport tests.
    /// # Panics
    /// Panics if the test certificate or its key cannot be constructed.
    #[must_use]
    pub fn root() -> Identity {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test CA").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(8).unwrap())
            .unwrap();
        cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::null()).unwrap();
        Identity {
            certificate: cert.build(),
            key,
        }
    }
    /// Construct a disposable certificate fixture for real transport tests.
    /// # Panics
    /// Panics if the test certificate or its key cannot be constructed.
    #[must_use]
    pub fn leaf(ca: &Identity, server: bool) -> Identity {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test leaf").unwrap();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(
            &BigNum::from_u32(if server { 2 } else { 3 })
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
        cert.set_subject_name(&name.build()).unwrap();
        cert.set_issuer_name(ca.certificate.subject_name()).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(7).unwrap())
            .unwrap();
        cert.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
        let mut eku = ExtendedKeyUsage::new();
        if server {
            eku.server_auth();
        } else {
            eku.client_auth();
        }
        cert.append_extension(eku.build().unwrap()).unwrap();
        cert.append_extension(
            SubjectAlternativeName::new()
                .dns("localhost")
                .build(&cert.x509v3_context(Some(&ca.certificate), None))
                .unwrap(),
        )
        .unwrap();
        cert.sign(&ca.key, MessageDigest::null()).unwrap();
        Identity {
            certificate: cert.build(),
            key,
        }
    }
    /// No application traffic is required for the kernel to retire a vanished
    /// server. Exercise the real socket, rather than transport configuration data.
    #[cfg(all(feature = "agent", target_os = "linux"))]
    #[tokio::test]
    async fn outgoing_tcp_detects_a_vanished_peer_without_application_traffic() {
        use nix::sys::socket::{getsockopt, sockopt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = dial_socket(listener.local_addr().unwrap()).await.unwrap();
        let _peer = listener.accept().await.unwrap();
        assert!(getsockopt(&socket, sockopt::KeepAlive).unwrap());
        assert_eq!(getsockopt(&socket, sockopt::TcpKeepIdle).unwrap(), 30);
        assert_eq!(getsockopt(&socket, sockopt::TcpKeepInterval).unwrap(), 10);
        assert_eq!(getsockopt(&socket, sockopt::TcpKeepCount).unwrap(), 3);
        assert_eq!(
            getsockopt(&socket, sockopt::TcpUserTimeout).unwrap(),
            60_000
        );
    }

    #[tokio::test]
    async fn mutual_tls_delivers_exact_bytes_and_verified_leaf_fingerprints() {
        let ca = root();
        let server = leaf(&ca, true);
        let client = leaf(&ca, false);
        let server_fingerprint: [u8; 32] = server
            .certificate
            .digest(MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let client_fingerprint: [u8; 32] = client
            .certificate
            .digest(MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let server = server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap();
        let client = client_config(&client, &[ca.certificate]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let peer = accept(listener.accept().await.unwrap().0, &server)
                .await
                .unwrap();
            assert_eq!(peer.peer_fingerprint, client_fingerprint);
            let mut received = Vec::new();
            let mut buffer = [0; 16];
            while received.len() < 9 {
                let n = peer.channel.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                received.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(received, b"unchanged");
            peer.channel.write(b"framing").await.unwrap();
        });
        let peer = dial(address, "localhost", &client).await.unwrap();
        assert_eq!(peer.peer_fingerprint, server_fingerprint);
        peer.channel.write(b"unchanged").await.unwrap();
        let mut bytes = [0; 7];
        let mut n = 0;
        while n < bytes.len() {
            let read = peer.channel.read(&mut bytes[n..]).await.unwrap();
            assert!(read > 0);
            n += read;
        }
        assert_eq!(&bytes, b"framing");
        server.await.unwrap();
    }
    // Real TLS/TCP backpressure, not a synthetic future: authenticated peer
    // keeps the connection alive but deliberately supplies no application reads.
    #[tokio::test]
    async fn stalled_write_retires_both_directions_without_idle_polling() {
        let ca = root();
        let server =
            server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap();
        let client = client_config(&leaf(&ca, false), &[ca.certificate]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            accept(listener.accept().await.unwrap().0, &server)
                .await
                .unwrap()
        });
        let peer = dial(address, "localhost", &client).await.unwrap();
        let server_peer = task.await.unwrap();
        let bytes = vec![0; 16 * 1024 * 1024];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(7),
            peer.channel.write(&bytes),
        )
        .await
        .expect("stalled TLS write must have a progress deadline");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let mut byte = [0];
        assert!(peer.channel.read(&mut byte).await.is_err());
        assert!(
            peer.channel
                .write(b"cannot continue a partial frame")
                .await
                .is_err()
        );
        drop(server_peer);
    }

    #[tokio::test]
    async fn cancelled_partial_write_cannot_reuse_the_channel() {
        let ca = root();
        let server =
            server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap();
        let client = client_config(&leaf(&ca, false), &[ca.certificate]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            accept(listener.accept().await.unwrap().0, &server)
                .await
                .unwrap()
        });
        let peer = dial(address, "localhost", &client).await.unwrap();
        let server_peer = task.await.unwrap();
        let bytes = vec![0; 16 * 1024 * 1024];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                peer.channel.write(&bytes)
            )
            .await
            .is_err()
        );
        let mut byte = [0];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                peer.channel.read(&mut byte)
            )
            .await
            .expect("cancelled writes must retire the reader too")
            .is_err()
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                peer.channel
                    .write(b"cancelled frame suffix must not be replaced")
            )
            .await
            .expect("cancelled writes must immediately retire TLS")
            .is_err()
        );
        drop(server_peer);
    }

    #[tokio::test]
    async fn untrusted_server_or_wrong_server_name_is_refused_before_bytes() {
        for wrong_name in [false, true] {
            let ca = root();
            let other = root();
            let server = leaf(&ca, true);
            let client = leaf(&ca, false);
            let server = server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap();
            let client = client_config(
                &client,
                &[if wrong_name {
                    ca.certificate
                } else {
                    other.certificate
                }],
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task =
                tokio::spawn(
                    async move { accept(listener.accept().await.unwrap().0, &server).await },
                );
            assert!(
                dial(
                    address,
                    if wrong_name {
                        "wrong.example"
                    } else {
                        "localhost"
                    },
                    &client
                )
                .await
                .is_err()
            );
            assert!(task.await.unwrap().is_err());
        }
    }
    #[tokio::test]
    async fn untrusted_client_never_reaches_server_admission() {
        let ca = root();
        let other = root();
        let server = leaf(&ca, true);
        let client = leaf(&other, false);
        let server = server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap();
        let client = client_config(&client, &[ca.certificate]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task =
            tokio::spawn(async move { accept(listener.accept().await.unwrap().0, &server).await });
        let connection = dial(address, "localhost", &client).await;
        // TLS1.3 clients can finish before receiving a server's client-auth alert.
        // The server must refuse, regardless of when that alert reaches the dialer.
        assert!(task.await.unwrap().is_err());
        drop(connection);
    }
}
