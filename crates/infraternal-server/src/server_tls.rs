//! Configures standalone HTTPS socket admission for interactive terminal traffic [41][130], #78.
//!
//! The acceptor also records each TLS connection's channel binding
//! ([`TlsChannelBinding`]) in the extensions of every request on it, so
//! `/remote/agent` can refuse an infraternal agent proof that was made over a
//! different TLS session, which is what a relay in the middle produces (#559).

use crate::send_queue::SocketAdmission;
use axum_server::{
    accept::Accept,
    tls_openssl::{OpenSSLAcceptor, OpenSSLConfig},
};
#[cfg(feature = "remote")]
use std::{future::Future, io, pin::Pin};
use tokio::net::TcpStream;
#[cfg(feature = "remote")]
use tower_http::add_extension::AddExtension;

/// The TLS acceptor [`HttpsAcceptor`] wraps.
type Tls = OpenSSLAcceptor<SocketAdmission>;

/// The TLS channel binding of the connection a request arrived on, present
/// only when this process terminated that TLS session itself.
///
/// Its value is the RFC 9266 `tls-exporter` binding, or `None` when the
/// session has none (not TLS 1.3, or an export failure). A request with no
/// `TlsChannelBinding` extension came over plain HTTP from a reverse proxy.
/// Only builds with the remote feature (which have `/remote/agent`) take it.
#[cfg(feature = "remote")]
#[derive(Clone, Copy)]
pub(crate) struct TlsChannelBinding(pub(crate) Option<[u8; 32]>);

/// The standalone HTTPS acceptor: TLS over the socket admission (`TCP_NODELAY` and the unsent-data bound), plus (with the
/// remote feature) the connection's [`TlsChannelBinding`] on every request.
///
/// Export costs one TLS key derivation per connection, taken once after the
/// handshake; requests on the connection share the copied 32 bytes.
#[derive(Clone)]
pub(crate) struct HttpsAcceptor(Tls);

impl<S: Send + 'static> Accept<TcpStream, S> for HttpsAcceptor {
    /// The TLS stream (`tokio_openssl::SslStream<TcpStream>`).
    type Stream = <Tls as Accept<TcpStream, S>>::Stream;
    /// The per-connection service, which adds the binding to each request.
    #[cfg(feature = "remote")]
    type Service = AddExtension<<Tls as Accept<TcpStream, S>>::Service, TlsChannelBinding>;
    /// The TLS acceptor's own service: nothing reads a binding here.
    #[cfg(not(feature = "remote"))]
    type Service = <Tls as Accept<TcpStream, S>>::Service;
    /// Boxed once per connection, never per request.
    #[cfg(feature = "remote")]
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;
    /// The TLS acceptor's own future.
    #[cfg(not(feature = "remote"))]
    type Future = <Tls as Accept<TcpStream, S>>::Future;

    /// Complete TLS, then attach the session's binding to its service.
    #[cfg(feature = "remote")]
    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let accepting = self.0.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = accepting.await?;
            let binding = TlsChannelBinding(
                infraternal_plugin_remote::agent_link::tls_channel_binding(stream.ssl()),
            );
            Ok((stream, AddExtension::new(service, binding)))
        })
    }

    /// Complete TLS.
    #[cfg(not(feature = "remote"))]
    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        self.0.accept(stream, service)
    }
}

/// Keep the standalone listener and memory-only integration fixtures on the same acceptor.
pub(crate) fn acceptor(config: OpenSSLConfig) -> HttpsAcceptor {
    // Ack and Output are separate small writes. Nagle would couple a glyph
    // to the browser TCP delayed-Ack timer even on a local connection. The
    // unsent-data bound keeps video and floods out of the kernel's buffer.
    HttpsAcceptor(OpenSSLAcceptor::new(config).acceptor(SocketAdmission))
}

#[cfg(test)]
pub(crate) mod tests {
    //! Tests `TCP_NODELAY` on a real accepted TLS socket, before any HTTP application bytes.
    use super::*;
    use axum_server::accept::Accept;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        ssl::{SslConnector, SslMethod, SslVerifyMode},
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
            store::X509StoreBuilder,
        },
    };
    use tokio::net::TcpStream;

    /// Check the production TLS acceptor before sending any HTTP request.
    #[tokio::test]
    async fn standalone_https_disables_nagle_before_application_bytes() {
        assert_nodelay_with(acceptor).await;
    }

    /// Reuse the same real socket assertion for provisioning fixtures.
    pub(crate) async fn assert_nodelay_with<F, A>(build: F)
    where
        F: FnOnce(OpenSSLConfig) -> A,
        A: Accept<TcpStream, (), Stream = tokio_openssl::SslStream<TcpStream>>,
    {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
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
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
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
        cert.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        cert.append_extension(
            SubjectAlternativeName::new()
                .dns("localhost")
                .build(&cert.x509v3_context(None, None))
                .unwrap(),
        )
        .unwrap();
        cert.sign(&key, MessageDigest::null()).unwrap();
        let cert = cert.build();
        let config =
            OpenSSLConfig::from_der(&cert.to_der().unwrap(), &key.private_key_to_der().unwrap())
                .unwrap();
        let mut client = SslConnector::builder(SslMethod::tls_client()).unwrap();
        let mut trust = X509StoreBuilder::new().unwrap();
        trust.add_cert(cert).unwrap();
        client.set_cert_store(trust.build());
        client.set_verify(SslVerifyMode::PEER);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let ssl = client
                .build()
                .configure()
                .unwrap()
                .into_ssl("localhost")
                .unwrap();
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut stream = tokio_openssl::SslStream::new(ssl, socket).unwrap();
            std::pin::Pin::new(&mut stream).connect().await.unwrap();
            stream
        });
        let (socket, _) = listener.accept().await.unwrap();
        let (stream, _) = build(config).accept(socket, ()).await.unwrap();
        assert!(
            stream.get_ref().nodelay().unwrap(),
            "standalone HTTPS retains Nagle on terminal traffic"
        );
        peer.await.unwrap();
    }
}
