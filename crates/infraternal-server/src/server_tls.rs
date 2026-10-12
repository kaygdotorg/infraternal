//! Configures standalone HTTPS socket admission for interactive terminal traffic [41][130], #78.

use axum_server::{
    accept::NoDelayAcceptor,
    tls_openssl::{OpenSSLAcceptor, OpenSSLConfig},
};

/// Keep the standalone listener and memory-only integration fixtures on the same acceptor.
pub(crate) fn acceptor(config: OpenSSLConfig) -> OpenSSLAcceptor<NoDelayAcceptor> {
    // Ack and Output are separate small writes. Nagle would couple a glyph
    // to the browser TCP delayed-Ack timer even on a local connection.
    OpenSSLAcceptor::new(config).acceptor(NoDelayAcceptor::new())
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

    #[tokio::test]
    async fn standalone_https_disables_nagle_before_application_bytes() {
        assert_nodelay_with(acceptor).await;
    }

    /// Reuse the same real socket assertion for provisioning fixtures.
    pub(crate) async fn assert_nodelay_with<F, A>(build: F)
    where
        F: FnOnce(OpenSSLConfig) -> A,
        A: Accept<TcpStream, (), Stream = tokio_openssl::SslStream<TcpStream>, Service = ()>,
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
        let (stream, ()) = build(config).accept(socket, ()).await.unwrap();
        assert!(
            stream.get_ref().nodelay().unwrap(),
            "standalone HTTPS retains Nagle on terminal traffic"
        );
        peer.await.unwrap();
    }
}
