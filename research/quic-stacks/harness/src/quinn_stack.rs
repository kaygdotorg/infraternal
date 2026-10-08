//! Role: Exercises the Quinn async client, server, and stream APIs with rustls and ring.
//! SPDX-License-Identifier: AGPL-3.0-only

use crate::test_identity;
use quinn::{
    Endpoint,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use std::{error::Error, net::SocketAddr, sync::Arc};

const ALPN: &[u8] = b"quicbench";

pub(crate) fn make_configs(
    identity: &test_identity::TestIdentity,
) -> Result<(quinn::ServerConfig, quinn::ClientConfig), Box<dyn Error>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(identity.ca_der.clone()))?;
    let roots = Arc::new(roots);
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.clone()));

    let verifier =
        WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone()).build()?;
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert.clone()], key.clone_key())?;
    server_tls.alpn_protocols = vec![ALPN.to_vec()];
    server_tls.max_early_data_size = u32::MAX;
    let server_crypto = QuicServerConfig::try_from(server_tls)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![cert], key)?;
    client_tls.alpn_protocols = vec![ALPN.to_vec()];
    client_tls.enable_early_data = true;
    let client_crypto = QuicClientConfig::try_from(client_tls)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window((512 * 1024u32).into());
    transport.receive_window((768 * 1024u32).into());
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    let transport = Arc::new(transport);
    server_config.transport_config(transport.clone());
    client_config.transport_config(transport);
    Ok((server_config, client_config))
}

/// Runs a mutually authenticated client/server handshake, opens one bidirectional stream, and echoes it.
pub fn smoke() -> Result<(), Box<dyn Error>> {
    let identity = test_identity::generate()?;
    let (server_config, client_config) = make_configs(&identity)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let server_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let server_endpoint = Endpoint::server(server_config, server_addr)?;
        let server_addr = server_endpoint.local_addr()?;
        let server_endpoint_task = server_endpoint.clone();
        let server = tokio::spawn(async move {
            let incoming = server_endpoint_task
                .accept()
                .await
                .ok_or_else(|| "server endpoint closed before a connection arrived".to_owned())?;
            let connection = incoming.await.map_err(|e| e.to_string())?;
            let (mut send, mut recv) = connection.accept_bi().await.map_err(|e| e.to_string())?;
            let request = recv
                .read_to_end(16 * 1024)
                .await
                .map_err(|e| e.to_string())?;
            send.write_all(&request).await.map_err(|e| e.to_string())?;
            send.finish().map_err(|e| e.to_string())?;
            connection.closed().await;
            Ok::<(), String>(())
        });

        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        client_endpoint.set_default_client_config(client_config);
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        let payload = b"quinn-vs-openssl-native";
        send.write_all(payload).await?;
        send.finish()?;
        let response = recv.read_to_end(16 * 1024).await?;
        if response != payload {
            return Err("Quinn stream echo differed from its payload".into());
        }
        connection.close(0u32.into(), b"smoke complete");
        server
            .await
            .map_err(|e| format!("Quinn server task: {e}"))??;
        client_endpoint.close(0u32.into(), b"smoke complete");
        server_endpoint.close(0u32.into(), b"smoke complete");
        Ok::<(), Box<dyn Error>>(())
    })?;
    println!("quinn_smoke=ok alpn=quicbench mutual_tls=true bidirectional_stream=true");
    Ok(())
}

#[cfg(feature = "measure")]
pub fn bench_handshake(count: u32) -> Result<(), Box<dyn Error>> {
    use std::time::Instant;

    let identity = test_identity::generate()?;
    let (server_config, client_config) = make_configs(&identity)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (samples_us, cpu_us) = runtime.block_on(async move {
        let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        let server_addr = server_endpoint.local_addr()?;
        let (handshakes_done, client_finished) = tokio::sync::oneshot::channel();
        let (handshakes_accepted, server_accepts) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connections = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let incoming = server_endpoint
                    .accept()
                    .await
                    .ok_or_else(|| "server endpoint closed".to_owned())?;
                connections.push(incoming.await.map_err(|e| e.to_string())?);
            }
            handshakes_accepted.send(()).map_err(|_| {
                "client stopped before the server accepted every handshake".to_owned()
            })?;
            // Keep the server endpoint and accepted connections alive until the client
            // has observed server-side completion for every measured handshake.
            client_finished
                .await
                .map_err(|_| "client stopped before all handshakes completed".to_owned())?;
            drop(connections);
            Ok::<(), String>(())
        });
        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        client_endpoint.set_default_client_config(client_config);
        let cpu_before = crate::measure::cpu_us()?;
        let mut samples = Vec::with_capacity(count as usize);
        let mut connections = Vec::with_capacity(count as usize);
        for index in 0..count {
            // A distinct wildcard subdomain prevents an earlier ticket from turning a
            // nominal full handshake into an unintentional resumed handshake.
            let server_name = format!("bench-{index}.quicbench.test");
            let start = Instant::now();
            let connection = client_endpoint.connect(server_addr, &server_name)?.await?;
            samples.push(start.elapsed().as_micros().min(u64::MAX as u128) as u64);
            connections.push(connection);
        }
        server_accepts
            .await
            .map_err(|_| "server stopped before accepting every measured handshake")?;
        handshakes_done
            .send(())
            .map_err(|_| "server stopped before the handshake sample finished")?;
        drop(connections);
        server
            .await
            .map_err(|e| format!("Quinn server task: {e}"))??;
        let cpu_after = crate::measure::cpu_us()?;
        client_endpoint.close(0u32.into(), b"benchmark complete");
        Ok::<_, Box<dyn Error>>((samples, cpu_after.saturating_sub(cpu_before)))
    })?;
    crate::measure::emit(crate::measure::Run {
        stack: "quinn-rustls-ring",
        workload: "handshake-1rtt",
        scenario: "fresh-mtls",
        units: count as u64,
        samples_us,
        cpu_us,
        bytes: 0,
    });
    Ok(())
}

#[cfg(feature = "measure")]
pub fn bench_throughput(stream_count: usize, bytes_total: u64) -> Result<(), Box<dyn Error>> {
    use std::time::Instant;

    let identity = test_identity::generate()?;
    let (server_config, client_config) = make_configs(&identity)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let bytes_per_stream = bytes_total / stream_count as u64;
    let (elapsed_us, cpu_us) = runtime.block_on(async move {
        let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        let server_addr = server_endpoint.local_addr()?;
        let (client_finished, server_wait) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .ok_or_else(|| "server endpoint closed".to_owned())?;
            let connection = incoming.await.map_err(|e| e.to_string())?;
            let mut readers = tokio::task::JoinSet::new();
            for _ in 0..stream_count {
                let (mut send, mut recv) =
                    connection.accept_bi().await.map_err(|e| e.to_string())?;
                readers.spawn(async move {
                    let mut buffer = [0u8; 64 * 1024];
                    let mut remaining = bytes_per_stream;
                    while remaining > 0 {
                        let size = buffer.len().min(remaining as usize);
                        match recv
                            .read(&mut buffer[..size])
                            .await
                            .map_err(|e| e.to_string())?
                        {
                            Some(0) | None => {
                                return Err("stream ended before the byte target".to_owned());
                            }
                            Some(read) => remaining -= read as u64,
                        }
                    }
                    send.write_all(b"\x01").await.map_err(|e| e.to_string())?;
                    Ok::<(), String>(())
                });
            }
            while let Some(result) = readers.join_next().await {
                result.map_err(|e| e.to_string())??;
            }
            // Keep the connection open until the client has received every ACK.
            server_wait
                .await
                .map_err(|_| "client stopped before stream acknowledgments arrived".to_owned())?;
            drop(connection);
            Ok::<(), String>(())
        });
        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        client_endpoint.set_default_client_config(client_config);
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        let cpu_before = crate::measure::cpu_us()?;
        let start = Instant::now();
        let mut streams = Vec::with_capacity(stream_count);
        for _ in 0..stream_count {
            streams.push(connection.open_bi().await?);
        }
        // Emit one byte on every stream before the server drains any stream so
        // every client-initiated stream becomes visible to the accept loop.
        let opening = [0u8; 1];
        for (send, _) in &mut streams {
            send.write_all(&opening).await.map_err(|e| e.to_string())?;
        }
        let payload = [0u8; 16 * 1024];
        let remaining_per_stream = bytes_per_stream.saturating_sub(1);
        let chunks = remaining_per_stream.div_ceil(payload.len() as u64);
        for index in 0..chunks {
            for (send, _) in &mut streams {
                let size = if index + 1 == chunks {
                    (remaining_per_stream - (chunks - 1) * payload.len() as u64) as usize
                } else {
                    payload.len()
                };
                send.write_all(&payload[..size])
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
        for (_, recv) in &mut streams {
            let mut ack = [0u8; 1];
            recv.read_exact(&mut ack).await?;
            if ack != [1] {
                return Err("stream throughput acknowledgment differed".into());
            }
        }
        let elapsed = start.elapsed().as_micros().min(u64::MAX as u128) as u64;
        client_finished
            .send(())
            .map_err(|_| "server stopped before stream acknowledgment completed")?;
        server
            .await
            .map_err(|e| format!("Quinn server task: {e}"))??;
        connection.close(0u32.into(), b"benchmark complete");
        let cpu_after = crate::measure::cpu_us()?;
        client_endpoint.close(0u32.into(), b"benchmark complete");
        Ok::<_, Box<dyn Error>>((elapsed, cpu_after.saturating_sub(cpu_before)))
    })?;
    crate::measure::emit(crate::measure::Run {
        stack: "quinn-rustls-ring",
        workload: "stream-throughput",
        scenario: if stream_count == 1 {
            "1-bidi-stream"
        } else {
            "4-bidi-streams"
        },
        units: bytes_total,
        samples_us: vec![elapsed_us],
        cpu_us,
        bytes: bytes_total,
    });
    Ok(())
}

#[cfg(feature = "measure")]
pub fn bench_0rtt() -> Result<(), Box<dyn Error>> {
    use std::time::{Duration, Instant};

    let identity = test_identity::generate()?;
    let (server_config, client_config) = make_configs(&identity)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (elapsed_us, cpu_us, accepted) = runtime.block_on(async move {
        let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        let server_addr = server_endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let incoming = server_endpoint
                    .accept()
                    .await
                    .ok_or_else(|| "server endpoint closed".to_owned())?;
                let connection = incoming.await.map_err(|e| e.to_string())?;
                let (mut send, mut recv) =
                    connection.accept_bi().await.map_err(|e| e.to_string())?;
                let request = recv.read_to_end(1024).await.map_err(|e| e.to_string())?;
                send.write_all(&request).await.map_err(|e| e.to_string())?;
                send.finish().map_err(|e| e.to_string())?;
                connection.closed().await;
            }
            Ok::<(), String>(())
        });

        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        client_endpoint.set_default_client_config(client_config);
        let first = client_endpoint.connect(server_addr, "localhost")?.await?;
        let (mut first_send, mut first_recv) = first.open_bi().await?;
        first_send.write_all(b"warmup").await?;
        first_send.finish()?;
        let response = first_recv
            .read_to_end(1024)
            .await
            .map_err(|error| format!("warmup echo read: {error}"))?;
        if response != b"warmup" {
            return Err("resumption warmup echo differed".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        first.close(0u32.into(), b"ticket received");

        let cpu_before = crate::measure::cpu_us()?;
        let start = Instant::now();
        let connecting = client_endpoint.connect(server_addr, "localhost")?;
        let (connection, zero_rtt_accepted) = connecting
            .into_0rtt()
            .map_err(|_| "Quinn did not have a resumable session ticket after warmup")?;
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"idempotent-probe").await?;
        send.finish()?;
        let response = recv
            .read_to_end(1024)
            .await
            .map_err(|error| format!("0-RTT echo read: {error}"))?;
        if response != b"idempotent-probe" {
            return Err("0-RTT echo differed from its request".into());
        }
        let accepted = zero_rtt_accepted.await;
        let elapsed_us = start.elapsed().as_micros().min(u64::MAX as u128) as u64;
        let cpu_us = crate::measure::cpu_us()?.saturating_sub(cpu_before);
        connection.close(0u32.into(), b"0-RTT probe complete");
        server
            .await
            .map_err(|e| format!("Quinn 0-RTT server task: {e}"))??;
        client_endpoint.close(0u32.into(), b"0-RTT probe complete");
        Ok::<_, Box<dyn Error>>((elapsed_us, cpu_us, accepted))
    })?;
    if !accepted {
        return Err("server rejected the resumed 0-RTT application data".into());
    }
    crate::measure::emit(crate::measure::Run {
        stack: "quinn-rustls-ring",
        workload: "resumption-0rtt-echo",
        scenario: "mtls-ticket-accepted",
        units: 1,
        samples_us: vec![elapsed_us],
        cpu_us,
        bytes: 16,
    });
    Ok(())
}
