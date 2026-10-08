//! Role: Builds comparable minimal baseline and candidate stack binaries for size accounting.
//! SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;

#[cfg(all(feature = "size-quinn", feature = "size-openssl-native"))]
compile_error!("build the Quinn and native OpenSSL size probes separately");

#[cfg(not(feature = "size-baseline"))]
compile_error!("build with size-baseline, size-quinn, or size-openssl-native");

fn main() -> Result<(), Box<dyn Error>> {
    touch_existing_tls()?;
    #[cfg(feature = "size-quinn")]
    touch_quinn()?;
    #[cfg(feature = "size-openssl-native")]
    touch_native_quic()?;
    Ok(())
}

fn touch_existing_tls() -> Result<(), Box<dyn Error>> {
    // SAFETY: the context is created and freed through the matching OpenSSL API.
    let context = unsafe { openssl_sys::SSL_CTX_new(openssl_sys::TLS_method()) };
    if context.is_null() {
        return Err("baseline TLS context allocation failed".into());
    }
    // SAFETY: context is a valid object returned by SSL_CTX_new.
    unsafe { openssl_sys::SSL_CTX_free(context) };
    Ok(())
}

#[cfg(feature = "size-quinn")]
fn touch_quinn() -> Result<(), Box<dyn Error>> {
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::{RootCertStore, server::ResolvesServerCert};
    use std::sync::Arc;

    #[derive(Debug)]
    struct EmptyResolver;
    impl ResolvesServerCert for EmptyResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_roots = RootCertStore::empty();
    let server_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(RootCertStore::empty()),
        provider.clone(),
    )
    .build()?;
    let server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(server_verifier)
        .with_cert_resolver(Arc::new(EmptyResolver));
    let server_crypto = QuicServerConfig::try_from(server_tls)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

    let client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(client_roots)
        .with_no_client_auth();
    let client_crypto = QuicClientConfig::try_from(client_tls)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    let transport = Arc::new(transport);
    server_config.transport_config(transport.clone());
    client_config.transport_config(transport);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        let server_addr = server.local_addr()?;
        let server_task_endpoint = server.clone();
        let server_task = tokio::spawn(async move {
            if let Some(incoming) = server_task_endpoint.accept().await {
                let _ = incoming.await;
            }
        });
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        client.set_default_client_config(client_config);
        let connecting = client.connect(server_addr, "localhost")?;
        let _ = tokio::time::timeout(std::time::Duration::from_millis(25), connecting).await;
        client.close(0u32.into(), b"size probe complete");
        server.close(0u32.into(), b"size probe complete");
        let _ = server_task.await;
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}

#[cfg(feature = "size-openssl-native")]
fn touch_native_quic() -> Result<(), Box<dyn Error>> {
    unsafe extern "C" {
        fn OSSL_QUIC_server_method() -> *const openssl_sys::SSL_METHOD;
        fn OSSL_QUIC_client_method() -> *const openssl_sys::SSL_METHOD;
        fn SSL_new_listener(ctx: *mut openssl_sys::SSL_CTX, flags: u64) -> *mut openssl_sys::SSL;
    }

    // SAFETY: each context uses its matching method and is freed after the listener.
    let server_context = unsafe { openssl_sys::SSL_CTX_new(OSSL_QUIC_server_method()) };
    let client_context = unsafe { openssl_sys::SSL_CTX_new(OSSL_QUIC_client_method()) };
    if server_context.is_null() || client_context.is_null() {
        unsafe {
            if !server_context.is_null() {
                openssl_sys::SSL_CTX_free(server_context);
            }
            if !client_context.is_null() {
                openssl_sys::SSL_CTX_free(client_context);
            }
        }
        return Err("native QUIC context allocation failed".into());
    }
    let listener = unsafe { SSL_new_listener(server_context, 0) };
    if listener.is_null() {
        unsafe {
            openssl_sys::SSL_CTX_free(server_context);
            openssl_sys::SSL_CTX_free(client_context);
        }
        return Err("native QUIC listener allocation failed".into());
    }
    // SAFETY: the listener is a valid object returned by SSL_new_listener.
    unsafe {
        openssl_sys::SSL_free(listener);
        openssl_sys::SSL_CTX_free(server_context);
        openssl_sys::SSL_CTX_free(client_context);
    }
    Ok(())
}
