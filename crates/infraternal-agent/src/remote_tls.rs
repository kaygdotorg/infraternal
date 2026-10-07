//! Authenticates dial-out TCP/TLS fallback before dispatching unchanged leg-B framing; callers recheck durable host admission [64][130], #78.

use crate::channel::Channel;
use openssl::{
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslConnector},
    x509::X509,
};
use std::{io, net::SocketAddr};

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
}

/// Full-duplex TLS channel. Reader and writer retain TLS state across readiness waits.
/// Cancelling a partial frame write requires retiring the entire connection.
pub struct TcpTls {
    retired: tokio::sync::watch::Sender<bool>,
    reader:
        tokio::sync::Mutex<tokio::io::ReadHalf<tokio_openssl::SslStream<tokio::net::TcpStream>>>,
    writer:
        tokio::sync::Mutex<tokio::io::WriteHalf<tokio_openssl::SslStream<tokio::net::TcpStream>>>,
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
            result = tokio::time::timeout(HANDSHAKE, writer.write_all(bytes)) => {
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
/// Dial only an outgoing connection and verify the server name before exposing bytes.
/// # Errors
/// Refuses network/deadline errors or failed mutual certificate/name verification.
pub async fn dial(
    address: SocketAddr,
    name: &str,
    config: &SslConnector,
) -> io::Result<Connection> {
    let socket = tokio::time::timeout(HANDSHAKE, tokio::net::TcpStream::connect(address))
        .await
        .map_err(|_| denied())??;
    socket.set_nodelay(true)?;
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
    finish(stream)
}
/// Authenticate a server-side accepted socket before handing it to host admission.
/// # Errors
/// Refuses failed mutual verification or a handshake deadline.
pub async fn accept(socket: tokio::net::TcpStream, config: &SslAcceptor) -> io::Result<Connection> {
    socket.set_nodelay(true)?;
    let ssl = openssl::ssl::Ssl::new(config.context()).map_err(|_| denied())?;
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).map_err(|_| denied())?;
    tokio::time::timeout(HANDSHAKE, std::pin::Pin::new(&mut stream).accept())
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
    finish(stream)
}
fn finish(stream: tokio_openssl::SslStream<tokio::net::TcpStream>) -> io::Result<Connection> {
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
    let (reader, writer) = tokio::io::split(stream);
    Ok(Connection {
        channel: TcpTls {
            retired: tokio::sync::watch::channel(false).0,
            reader: tokio::sync::Mutex::new(reader),
            writer: tokio::sync::Mutex::new(writer),
        },
        peer_fingerprint,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        x509::{
            X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        },
    };
    use tokio::net::TcpListener;

    pub(crate) fn root() -> Identity {
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
    pub(crate) fn leaf(ca: &Identity, server: bool) -> Identity {
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
