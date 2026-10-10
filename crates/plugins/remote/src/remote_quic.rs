//! Uses owner-selected quinn/BBR and mTLS, binding native streams to durable server writer ids before terminal frames [11][64][130], #78.

use crate::remote_tls::Identity;
use openssl::x509::X509;
use std::io;

/// Server-authorized writer identity plus its independent native QUIC stream.
pub struct BoundStream {
    /// Stable even leg-B writer id; never derived from the native stream id.
    pub writer_id: u32,
    /// Raw v1 wire frames, without the TCP mux envelope.
    pub send: quinn::SendStream,
    /// Raw v1 wire frames; the binding parser leaves all following bytes here.
    pub receive: quinn::RecvStream,
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "remote infraternal agent QUIC transport refused",
    )
}

/// Additive leg-B capability; leg-A `RESUME_NEXT` bit0 is independent.
pub use infraternal_plugin_api::channel::REMOTE_WRITER_BINDING;

/// Peer Hello has opted into durable writer binding. Raw mTLS alone cannot
/// enable a new protocol action on a peer that only supports legacy v1.
pub struct BindingConnection(quinn::Connection);

/// Require the current peer's decoded control Hello before opening terminal streams.
/// # Errors
/// Refuses missing/wrong Hello version or absent binding capability.
pub fn negotiate_binding(
    connection: &quinn::Connection,
    peer_hello: &infraternal_protocol::Frame<'_>,
) -> io::Result<BindingConnection> {
    if matches!(peer_hello, infraternal_protocol::Frame::Hello {version:1,caps,..} if caps & REMOTE_WRITER_BINDING != 0)
    {
        Ok(BindingConnection(connection.clone()))
    } else {
        Err(denied())
    }
}

const ALPN: &[u8] = b"infraternal/1";
const BINDING_LIMIT: usize = 128;
const BINDING_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

fn roots(certificates: &[X509]) -> io::Result<rustls::RootCertStore> {
    if certificates.is_empty() || certificates.len() > 16 {
        return Err(denied());
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(rustls::pki_types::CertificateDer::from(
                certificate.to_der().map_err(|_| denied())?,
            ))
            .map_err(|_| denied())?;
    }
    Ok(roots)
}
fn identity(
    identity: &Identity,
) -> io::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let certificate = rustls::pki_types::CertificateDer::from(
        identity.certificate.to_der().map_err(|_| denied())?,
    );
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        identity.key.private_key_to_pkcs8().map_err(|_| denied())?,
    );
    Ok((vec![certificate], key.into()))
}
fn transport(incoming_streams: u32) -> std::sync::Arc<quinn::TransportConfig> {
    transport_with_liveness(
        incoming_streams,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    )
}
fn transport_with_liveness(
    incoming_streams: u32,
    keep_alive: std::time::Duration,
    idle: std::time::Duration,
) -> std::sync::Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.congestion_controller_factory(std::sync::Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));
    // A small transport-only probe preserves short NAT mappings. Four missed
    // intervals allow a minute of transient loss before reconnect; healthy ACKs
    // reset idle expiry. These probes never perform database or authority work.
    config
        .max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            u32::try_from(idle.as_millis()).unwrap_or(60_000),
        ))))
        .keep_alive_interval(Some(keep_alive));
    config.max_concurrent_uni_streams(0u32.into());
    // Quinn preallocates slots up to this limit. Hosts initiate only control0;
    // server-opened terminals use the daemon's existing attachment bound, not
    // the deployment-wide viewer count multiplied across every idle host.
    config.max_concurrent_bidi_streams(incoming_streams.into());
    // Credit bounds outstanding bytes across streams, not just stream count.
    // 1MiB per peer is <=1GiB outstanding at the 1000-host admission target.
    config
        .receive_window(1_048_576u32.into())
        .stream_receive_window(262_144u32.into())
        .send_window(1_048_576);
    std::sync::Arc::new(config)
}
/// Configure authenticated server admission and event-driven BBR transport.
/// Callers must bound `Incoming`/`Connecting` and control-Hello negotiation
/// explicitly; the transport idle deadline is separate from application admission.
/// # Errors
/// Refuses invalid identity/trust or unavailable crypto configuration.
pub fn server_config(
    endpoint: &Identity,
    certificates: &[X509],
) -> io::Result<quinn::ServerConfig> {
    use std::sync::Arc;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(certificates)?),
        provider.clone(),
    )
    .build()
    .map_err(|_| denied())?;
    let (chain, key) = identity(endpoint)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| denied())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| denied())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| denied())?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport(1));
    Ok(config)
}
/// Configure outgoing mTLS and retained public server trust.
/// Callers must bound `Connecting` and control-Hello negotiation explicitly;
/// healthy established connections remain live through acknowledged transport probes.
/// # Errors
/// Refuses invalid identity/trust or unavailable crypto configuration.
pub fn client_config(
    endpoint: &Identity,
    certificates: &[X509],
) -> io::Result<quinn::ClientConfig> {
    use std::sync::Arc;
    let (chain, key) = identity(endpoint)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| denied())?
        .with_root_certificates(roots(certificates)?)
        .with_client_auth_cert(chain, key)
        .map_err(|_| denied())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // No replayable 0-RTT: terminal input and enrollment are stateful authority.
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| denied())?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport(
        u32::try_from(infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS)
            .map_err(|_| denied())?,
    ));
    Ok(config)
}
/// Return verified leaf identity for durable server-side revocation admission.
/// # Errors
/// Refuses absent/non-certificate peer identity.
pub fn peer_fingerprint(connection: &quinn::Connection) -> io::Result<[u8; 32]> {
    let identity = connection.peer_identity().ok_or_else(denied)?;
    let chain = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| denied())?;
    Ok(openssl::sha::sha256(
        chain.first().ok_or_else(denied)?.as_ref(),
    ))
}
/// Open a terminal stream and bind its server-assigned writer before any terminal frame.
/// # Errors
/// Refuses reserved/odd ids, connection failure or a bounded binding write deadline.
pub async fn open_bound(connection: &BindingConnection, writer_id: u32) -> io::Result<BoundStream> {
    if writer_id == 0 || writer_id & 1 != 0 {
        return Err(denied());
    }
    tokio::time::timeout(BINDING_DEADLINE, async {
        let (mut send, receive) = connection.0.open_bi().await.map_err(|_| denied())?;
        // Server→host terminal input is interactive; host→server bulk is priority0.
        send.set_priority(100).map_err(|_| denied())?;
        let json = serde_json::to_vec(&serde_json::json!({"writer_id":writer_id}))
            .map_err(|_| denied())?;
        let mut bytes = Vec::new();
        infraternal_protocol::encode_frame_into(
            &infraternal_protocol::Frame::Call {
                call_id: 0,
                action_id: "transport.bind",
                input_json: &json,
            },
            &mut bytes,
        )
        .map_err(|_| denied())?;
        send.write_all(&bytes).await.map_err(|_| denied())?;
        Ok(BoundStream {
            writer_id,
            send,
            receive,
        })
    })
    .await
    .map_err(|_| denied())?
}

/// Validate the first binding frame; public for parser fuzzing, grants no host authority.
/// # Errors
/// Refuses oversized/incomplete/trailing frames, wrong action, unknown JSON fields or reserved ids.
pub fn binding_writer(bytes: &[u8]) -> io::Result<u32> {
    use infraternal_protocol::{Frame, decode_frame};
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Binding {
        writer_id: u32,
    }
    if bytes.len() > BINDING_LIMIT {
        return Err(denied());
    }
    let decoded = decode_frame(bytes).map_err(|_| denied())?;
    if decoded.wire_len != bytes.len() {
        return Err(denied());
    }
    if let Frame::Call {
        call_id: 0,
        action_id: "transport.bind",
        input_json,
    } = decoded.frame
    {
        let binding: Binding = serde_json::from_slice(input_json).map_err(|_| denied())?;
        if binding.writer_id != 0 && binding.writer_id & 1 == 0 {
            return Ok(binding.writer_id);
        }
    }
    Err(denied())
}
/// Admit one bounded first-frame binding without consuming any following frame.
/// # Errors
/// Refuses invalid framing/action/JSON/id, EOF or a binding deadline.
pub async fn accept_bound(connection: &BindingConnection) -> io::Result<BoundStream> {
    // Waiting for an unopened stream is ordinary healthy idle. Only an opened
    // stream gets a first-frame deadline; idle time is not an authority expiry.
    let (send, mut receive) = connection.0.accept_bi().await.map_err(|_| denied())?;
    send.set_priority(0).map_err(|_| denied())?;
    let writer_id = tokio::time::timeout(BINDING_DEADLINE, async {
        let mut bytes = Vec::with_capacity(BINDING_LIMIT);
        loop {
            let mut byte = [0];
            if receive.read(&mut byte).await.map_err(|_| denied())? != Some(1) {
                return Err(denied());
            }
            bytes.push(byte[0]);
            match infraternal_protocol::decode_frame(&bytes) {
                Ok(_) => return binding_writer(&bytes),
                Err(infraternal_protocol::DecodeError::Incomplete)
                    if bytes.len() < BINDING_LIMIT => {}
                Err(_) => return Err(denied()),
            }
        }
    })
    .await
    .map_err(|_| denied())??;
    Ok(BoundStream {
        writer_id,
        send,
        receive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_tls::tests::{leaf, root};
    use openssl::hash::MessageDigest;

    /// Exercise acknowledged idle traffic and a lost NAT path using the same
    /// production configuration helper at accelerated transport-only intervals.
    #[tokio::test]
    async fn acknowledged_idle_survives_and_a_silent_path_times_out() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let ca = root();
        let server_identity = leaf(&ca, true);
        let client_identity = leaf(&ca, false);
        let config = transport_with_liveness(
            1,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(250),
        );
        let mut server_config =
            server_config(&server_identity, std::slice::from_ref(&ca.certificate)).unwrap();
        server_config.transport_config(config.clone());
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_address = server.local_addr().unwrap();
        let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let forwarding = Arc::new(AtomicBool::new(true));
        let state = forwarding.clone();
        let relay = tokio::spawn(async move {
            let mut bytes = vec![0; 65536];
            let mut client = None;
            loop {
                let (count, source) = proxy.recv_from(&mut bytes).await.unwrap();
                let target = if source == server_address {
                    client
                } else {
                    client = Some(source);
                    Some(server_address)
                };
                if state.load(Ordering::Relaxed)
                    && let Some(target) = target
                {
                    proxy.send_to(&bytes[..count], target).await.unwrap();
                }
            }
        });
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client_config = client_config(&client_identity, &[ca.certificate]).unwrap();
        client_config.transport_config(config);
        client.set_default_client_config(client_config);
        let (dial, accept) =
            tokio::join!(client.connect(proxy_address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            });
        let dial = dial.unwrap();
        let accept = accept.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        assert!(dial.close_reason().is_none());
        assert!(accept.close_reason().is_none());
        forwarding.store(false, Ordering::Relaxed);
        let failure = tokio::time::timeout(std::time::Duration::from_secs(2), dial.closed())
            .await
            .unwrap();
        assert!(matches!(failure, quinn::ConnectionError::TimedOut));
        relay.abort();
        client.close(0u32.into(), b"");
        server.close(0u32.into(), b"");
    }

    #[tokio::test]
    async fn repeated_native_id_has_distinct_server_writer_authority_and_preserves_suffix() {
        let ca = root();
        let server = leaf(&ca, true);
        let client = leaf(&ca, false);
        let expected: [u8; 32] = client
            .certificate
            .digest(MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let server = quinn::Endpoint::server(
            server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint
            .set_default_client_config(client_config(&client, &[ca.certificate]).unwrap());
        let mut native_ids = Vec::new();
        for writer_id in [42, 44] {
            let dial = client_endpoint
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap();
            let (remote, local) =
                tokio::join!(dial, async { server.accept().await.unwrap().await });
            let remote = remote.unwrap();
            let local = local.unwrap();
            assert_eq!(peer_fingerprint(&local).unwrap(), expected);
            let mut hello = infraternal_protocol::Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "test peer",
            };
            assert!(negotiate_binding(&local, &hello).is_err());
            if let infraternal_protocol::Frame::Hello { caps, .. } = &mut hello {
                *caps = REMOTE_WRITER_BINDING;
            }
            let local_binding = negotiate_binding(&local, &hello).unwrap();
            let remote_binding = negotiate_binding(&remote, &hello).unwrap();
            let mut outgoing = open_bound(&local_binding, writer_id).await.unwrap();
            outgoing
                .send
                .write_all(b"following raw frames")
                .await
                .unwrap();
            outgoing.send.finish().unwrap();
            let mut bound = accept_bound(&remote_binding).await.unwrap();
            assert_eq!(bound.writer_id, writer_id);
            native_ids.push(bound.receive.id());
            assert_eq!(
                bound.receive.read_to_end(128).await.unwrap(),
                b"following raw frames"
            );
            assert!(open_bound(&local_binding, 0).await.is_err());
            assert!(open_bound(&local_binding, 3).await.is_err());
            local.close(0u32.into(), b"");
            remote.close(0u32.into(), b"");
        }
        assert_eq!(native_ids[0], native_ids[1]);
        server.close(0u32.into(), b"");
        client_endpoint.close(0u32.into(), b"");
    }
    #[tokio::test]
    async fn wrong_server_name_never_yields_authenticated_connection() {
        let ca = root();
        let server = leaf(&ca, true);
        let client = leaf(&ca, false);
        let server = quinn::Endpoint::server(
            server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint
            .set_default_client_config(client_config(&client, &[ca.certificate]).unwrap());
        let connect = client_endpoint
            .connect(server.local_addr().unwrap(), "wrong.example")
            .unwrap();
        let (dial, accepted) =
            tokio::join!(connect, async { server.accept().await.unwrap().await });
        assert!(dial.is_err());
        assert!(accepted.is_err());
        server.close(0u32.into(), b"");
        client_endpoint.close(0u32.into(), b"");
    }
    #[tokio::test]
    async fn host_cannot_open_a_second_server_control_stream() {
        let ca = root();
        let server_identity = leaf(&ca, true);
        let client_identity = leaf(&ca, false);
        let server = quinn::Endpoint::server(
            server_config(&server_identity, std::slice::from_ref(&ca.certificate)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client
            .set_default_client_config(client_config(&client_identity, &[ca.certificate]).unwrap());
        let (dial, accepted) = tokio::join!(
            client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let dial = dial.unwrap();
        let accepted = accepted.unwrap();
        let _control = dial.open_bi().await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), dial.open_bi())
                .await
                .is_err()
        );
        dial.close(0u32.into(), b"");
        accepted.close(0u32.into(), b"");
        server.close(0u32.into(), b"");
        client.close(0u32.into(), b"");
    }
}
