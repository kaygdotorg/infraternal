//! Real TLS/QUIC actor admission and enrolled UID regression fixtures, #78.
use infraternal_agent::remote_native::NativeChannel;

use super::*;
use infraternal_agent::{
    channel::Channel,
    transport::{Receive, Transmit},
};
use infraternal_protocol::Frame;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    x509::{
        X509NameBuilder, X509Req,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use std::time::Duration;

pub(crate) fn identities() -> (Identity, Identity, X509, crate::ca::CaMaterial) {
    identities_for_name("localhost")
}

fn identities_for_name(server_dns: &str) -> (Identity, Identity, X509, crate::ca::CaMaterial) {
    let key = PKey::generate_ed25519().unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "runtime test CA").unwrap();
    let name = name.build();
    let mut issuer = X509::builder().unwrap();
    issuer.set_version(2).unwrap();
    issuer
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    issuer.set_subject_name(&name).unwrap();
    issuer.set_issuer_name(&name).unwrap();
    issuer.set_pubkey(&key).unwrap();
    issuer
        .set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    issuer
        .set_not_after(&Asn1Time::from_unix(2_000_000_000).unwrap())
        .unwrap();
    issuer
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(0)
                .build()
                .unwrap(),
        )
        .unwrap();
    issuer
        .append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
        .unwrap();
    issuer.sign(&key, MessageDigest::null()).unwrap();
    let root = issuer.build();
    // Chromium's TLS signature negotiation does not accept an Ed25519 leaf.
    // Browser-facing TLS remains independently configured by the server owner;
    // this fixture uses its existing P-256 support, with the Ed25519 CA/host unchanged.
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let server_key = PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap();
    let mut server = X509::builder().unwrap();
    server.set_version(2).unwrap();
    server
        .set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    let mut server_name = X509NameBuilder::new().unwrap();
    server_name.append_entry_by_text("CN", server_dns).unwrap();
    server.set_subject_name(&server_name.build()).unwrap();
    server.set_issuer_name(&name).unwrap();
    server.set_pubkey(&server_key).unwrap();
    server
        .set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    server
        .set_not_after(&Asn1Time::from_unix(2_000_000_000).unwrap())
        .unwrap();
    server
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    server
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    server
        .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    server
        .append_extension(
            SubjectAlternativeName::new()
                .dns(server_dns)
                .ip("10.69.69.125")
                .build(&server.x509v3_context(Some(&root), None))
                .unwrap(),
        )
        .unwrap();
    server.sign(&key, MessageDigest::null()).unwrap();
    let host_key = PKey::generate_ed25519().unwrap();
    let mut csr = X509Req::builder().unwrap();
    csr.set_subject_name(&X509NameBuilder::new().unwrap().build())
        .unwrap();
    csr.set_pubkey(&host_key).unwrap();
    csr.sign(&host_key, MessageDigest::null()).unwrap();
    let csr = crate::csr::ValidatedCsr::parse(&csr.build().to_der().unwrap()).unwrap();
    let material = crate::ca::CaMaterial::new(key, root.clone());
    let authority = crate::ca::CertificateAuthority::from_material(material.clone()).unwrap();
    let host = authority
        .sign_host(Uuid::from_u128(42), &csr, now().unwrap())
        .unwrap();
    (
        Identity {
            certificate: server.build(),
            key: server_key,
        },
        Identity {
            certificate: X509::from_der(&host.der).unwrap(),
            key: host_key,
        },
        root,
        material,
    )
}

async fn respond(channel: &impl Channel) -> u64 {
    let mut receive = Receive::default();
    let hello = Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING,
        client_info: "test",
    };
    Transmit::default().send(channel, 0, &hello).await.unwrap();
    let Frame::Hello {
        version: 1, caps, ..
    } = receive.next(channel).await.unwrap().frame
    else {
        panic!("expected hello")
    };
    let request = receive.next(channel).await.unwrap();
    let Frame::Call {
        call_id,
        action_id,
        input_json,
    } = request.frame
    else {
        panic!("expected open")
    };
    assert_eq!(action_id, "terminal.open");
    let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
    assert_eq!(input["uid"], 1002);
    let json = serde_json::json!({"session_id":Uuid::from_u128(7)}).to_string();
    Transmit::default()
        .send(
            channel,
            0,
            &Frame::Result {
                call_id,
                ok: true,
                json: json.as_bytes(),
            },
        )
        .await
        .unwrap();
    caps
}

#[tokio::test]
async fn tcp_actor_uses_enrolled_uid_and_replays_admission_hello() {
    let (server, host, root, _) = identities();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_config = remote_tls::client_config(&host, std::slice::from_ref(&root)).unwrap();
    let server_config = remote_tls::server_config(&server, &[root]).unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let client = remote_tls::dial(address, "localhost", &client_config)
            .await
            .unwrap();
        respond(&client.channel).await;
    });
    let connection = remote_tls::accept(listener.accept().await.unwrap().0, &server_config)
        .await
        .unwrap();
    let link = RemoteLink::tcp(connection.channel).await.unwrap();
    let (actor, accepts) = EmbeddedAgent::remote(1002);
    accepts.send(link).await.unwrap();
    let id = tokio::time::timeout(
        Duration::from_secs(2),
        actor.open(crate::embedded::TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(id, *Uuid::from_u128(7).as_bytes());
    peer.await.unwrap();
}

#[tokio::test]
async fn quic_actor_binds_durable_writer_and_recovery_offsets() {
    use infraternal_agent::remote_native::NativeChannel;
    let (server, host, root, _) = identities();
    let listener = quinn::Endpoint::server(
        remote_quic::server_config(&server, std::slice::from_ref(&root)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(remote_quic::client_config(&host, &[root]).unwrap());
    let address = listener.local_addr().unwrap();
    let (done, keep_open) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let connection = endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, receive) = connection.open_bi().await.unwrap();
        let control = NativeChannel::control(send, receive).unwrap();
        let caps = respond(&control).await;
        let binding = remote_quic::negotiate_binding(
            &connection,
            &Frame::Hello {
                version: 1,
                caps,
                client_info: "test",
            },
        )
        .unwrap();
        let bound = remote_quic::accept_bound(&binding).await.unwrap();
        assert_eq!(bound.writer_id, 42);
        assert_ne!(u64::from(bound.writer_id), u64::from(bound.send.id()));
        let terminal = NativeChannel::terminal(bound).unwrap();
        let mut receive = Receive::default();
        assert!(matches!(
            receive.next(&terminal).await.unwrap().frame,
            Frame::AttachTerm {
                last_out_seq: 1234,
                last_in_seq: 5678,
                ..
            }
        ));
        let _ = keep_open.await;
    });
    let connection = listener.accept().await.unwrap().await.unwrap();
    let link = RemoteLink::quic(connection).await.unwrap();
    let (actor, accepts) = EmbeddedAgent::remote(1002);
    accepts.send(link).await.unwrap();
    let id = tokio::time::timeout(
        Duration::from_secs(2),
        actor.open(crate::embedded::TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let attachment = tokio::time::timeout(Duration::from_secs(2), actor.attach(id, 1234, 5678, 42))
        .await
        .unwrap()
        .unwrap();
    drop(attachment);
    let _ = done.send(());
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
}

/// Shared memory-only fixture signer; not a production unlock adapter.
pub(crate) fn server_material() -> (Identity, crate::ca::CaMaterial) {
    let (server, _, _, material) = identities();
    (server, material)
}

#[path = "remote_revocation_tests.rs"]
pub(crate) mod revocation;

#[path = "remote_review_tests.rs"]
mod independent_review;

#[tokio::test]
async fn ephemeral_listener_pair_retries_real_udp_collision_without_leaking_tcp() {
    let (server, _, root, _) = identities();
    let config = remote_quic::server_config(&server, &[root]).unwrap();
    let mut collision = None;
    let mut attempts = 0;
    let (endpoint, tcp, _bindings) =
        reserve_transports("127.0.0.1:0".parse().unwrap(), &config, |address| {
            attempts += 1;
            if attempts == 1 {
                collision = Some(std::net::UdpSocket::bind(address)?);
            }
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(endpoint.local_addr().unwrap(), tcp.local_addr().unwrap());
    let failed = collision.as_ref().unwrap().local_addr().unwrap();
    assert_ne!(failed, endpoint.local_addr().unwrap());
    let released = std::net::TcpListener::bind(failed).unwrap();
    drop(released);
}

#[tokio::test]
async fn explicit_listener_pair_never_moves_an_occupied_operator_port() {
    let (server, _, root, _) = identities();
    let config = remote_quic::server_config(&server, &[root]).unwrap();
    // Keep the fixture's TCP reservation alive throughout the refused start.
    // An unreserved TCP port chosen from UDP's pool belongs to nobody here.
    let collision = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = collision.local_addr().unwrap();
    let mut reserved = false;
    let error = reserve_transports(address, &config, |_| {
        reserved = true;
        Ok(())
    })
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    assert!(
        !reserved,
        "configured TCP collision cannot choose another port"
    );
    assert_eq!(collision.local_addr().unwrap(), address);
}

#[path = "remote_renewal_checks.rs"]
mod renewal_checks;

/// Retain the real shared TLS builder for a pinned browser-auth origin.
pub(crate) fn server_material_for_name(name: &str) -> (Identity, crate::ca::CaMaterial) {
    let (server, _, _, material) = identities_for_name(name);
    (server, material)
}

/// Pre-authentication handshakes share one 64-slot budget across QUIC and
/// TCP/TLS. Sixty-four anonymous TCP sockets that never send a `ClientHello`
/// must not stop a certificate-holding host from completing its handshake
/// [40][134], #78.
#[tokio::test]
async fn claude_review_idle_anonymous_sockets_cannot_starve_host_handshakes() {
    let (server, host, root, _) = identities();
    let (store, _pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let address = listeners.local_addr().unwrap();
    let mut idle = Vec::new();
    for _ in 0..64 {
        idle.push(tokio::net::TcpStream::connect(address).await.unwrap());
    }
    // Let the accept loop hand every idle socket a handshake permit.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let client = remote_tls::client_config(&host, std::slice::from_ref(&root)).unwrap();
    let dialed = remote_tls::dial(address, "localhost", &client).await;
    drop(idle);
    assert!(
        dialed.is_ok(),
        "64 idle anonymous sockets exhausted every host handshake slot"
    );
}

#[path = "remote_probe_tests.rs"]
mod candidate_proofs;
#[cfg(feature = "ssh")]
#[path = "remote_ssh_tests.rs"]
pub(crate) mod ssh_bridge;

#[path = "remote_standby_tests.rs"]
mod standby;

#[path = "remote_listener_tests.rs"]
mod additional_listeners;

#[cfg(all(feature = "mesh-transport-proof", target_os = "linux"))]
#[path = "remote_mesh_namespace_tests.rs"]
pub(crate) mod mesh_namespace;

// Shared native fixtures prove replacement identity and cancelled delivery.
async fn adapter_connect_control(
    address: SocketAddr,
    identity: &Identity,
    root: &X509,
) -> (quinn::Endpoint, quinn::Connection, NativeChannel) {
    adapter_connect_control_with_window(address, identity, root, false).await
}
async fn adapter_connect_control_with_window(
    address: SocketAddr,
    identity: &Identity,
    root: &X509,
    limited: bool,
) -> (quinn::Endpoint, quinn::Connection, NativeChannel) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut config = remote_quic::client_config(identity, std::slice::from_ref(root)).unwrap();
    if limited {
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(4096u32.into())
            .receive_window(8192u32.into());
        config.transport_config(Arc::new(transport));
    }
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (send, receive) = connection.open_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    (endpoint, connection, channel)
}

fn adapter_hello() -> Frame<'static> {
    Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING,
        client_info: "fixture",
    }
}

/// Generates a fresh native pair for actor cancellation/backpressure regressions.
pub(crate) async fn native_link_pair() -> (
    Arc<RemoteLink>,
    infraternal_agent::remote_native::NativeChannel,
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
) {
    use infraternal_agent::remote_native::NativeChannel;
    let (server, node, root, _) = identities();
    let listener = quinn::Endpoint::server(
        remote_quic::server_config(&server, std::slice::from_ref(&root)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut config = remote_quic::client_config(&node, std::slice::from_ref(&root)).unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(4096u32.into())
        .receive_window(8192u32.into());
    config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(config);
    let outgoing = endpoint
        .connect(listener.local_addr().unwrap(), "localhost")
        .unwrap();
    let (peer, admitted) = tokio::join!(outgoing, async {
        listener.accept().await.unwrap().await.unwrap()
    });
    let peer = peer.unwrap();
    let (send, receive) = peer.open_bi().await.unwrap();
    let control = NativeChannel::control(send, receive).unwrap();
    let hello = Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING,
        client_info: "native cancellation fixture",
    };
    Transmit::default().send(&control, 0, &hello).await.unwrap();
    let link = Arc::new(RemoteLink::quic(admitted).await.unwrap());
    link.hello(&hello).unwrap();
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(0, &hello, &mut wire).unwrap();
    link.write(0, &hello, &wire).await.unwrap();
    assert!(matches!(
        Receive::default().next(&control).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let mut received = bytes::BytesMut::new();
    link.read(&mut received, &mut [0; 4096]).await.unwrap();
    (link, control, listener, endpoint, peer)
}

#[tokio::test]
async fn retired_native_writer_frames_cannot_close_or_ack_its_replacement() {
    let (server, node, root, _) = identities();
    let listener = quinn::Endpoint::server(
        remote_quic::server_config(&server, std::slice::from_ref(&root)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let (old_sent, sent) = tokio::sync::oneshot::channel();
    let (done, keep_open) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (_endpoint, connection, control) = adapter_connect_control(address, &node, &root).await;
        Transmit::default()
            .send(&control, 0, &adapter_hello())
            .await
            .unwrap();
        let mut control_rx = Receive::default();
        let response = control_rx.next(&control).await.unwrap();
        let binding = remote_quic::negotiate_binding(&connection, &response.frame).unwrap();
        let first =
            NativeChannel::terminal(remote_quic::accept_bound(&binding).await.unwrap()).unwrap();
        assert!(matches!(
            Receive::default().next(&first).await.unwrap().frame,
            Frame::AttachTerm { .. }
        ));
        Transmit::default()
            .send(&first, 42, &Frame::Ack { in_seq_acked: 10 })
            .await
            .unwrap();
        old_sent.send(()).unwrap();
        let second =
            NativeChannel::terminal(remote_quic::accept_bound(&binding).await.unwrap()).unwrap();
        assert!(matches!(
            Receive::default().next(&second).await.unwrap().frame,
            Frame::AttachTerm { .. }
        ));
        Transmit::default()
            .send(&second, 42, &Frame::Ack { in_seq_acked: 20 })
            .await
            .unwrap();
        let _ = keep_open.await;
    });
    let connection = listener.accept().await.unwrap().await.unwrap();
    let link = RemoteLink::quic(connection).await.unwrap();
    link.hello(&adapter_hello()).unwrap();
    let mut muxed = Vec::new();
    let greeting = adapter_hello();
    infraternal_protocol::encode_muxed_frame_into(0, &greeting, &mut muxed).unwrap();
    link.write(0, &greeting, &muxed).await.unwrap();
    let mut received = bytes::BytesMut::new();
    let mut scratch = vec![0; 4096];
    link.read(&mut received, &mut scratch).await.unwrap();
    received.clear();
    let attach = Frame::AttachTerm {
        session_id: &[1; 16],
        last_out_seq: 0,
        last_in_seq: 0,
    };
    muxed.clear();
    infraternal_protocol::encode_muxed_frame_into(42, &attach, &mut muxed).unwrap();
    link.write(42, &attach, &muxed).await.unwrap();
    sent.await.unwrap();
    let close = Frame::Close {
        code: 1000,
        reason: "rebind fixture",
    };
    let mut closing = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(42, &close, &mut closing).unwrap();
    link.write(42, &close, &closing).await.unwrap();
    link.write(42, &attach, &muxed).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        link.read(&mut received, &mut scratch),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        infraternal_protocol::decode_muxed_frame(&received)
            .unwrap()
            .frame,
        Frame::Ack { in_seq_acked: 20 }
    );
    received.clear();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            link.read(&mut received, &mut scratch)
        )
        .await
        .is_err()
    );
    done.send(()).unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn cancelled_native_read_retains_dequeued_packet() {
    let (link, control, _listener, _endpoint, _peer) = native_link_pair().await;
    let (ready, held) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    let held_link = link.clone();
    let holder = tokio::spawn(async move {
        held_link.hold_writer_map(ready, release_rx).await;
    });
    held.await.unwrap();
    Transmit::default()
        .send(
            &control,
            0,
            &Frame::Result {
                call_id: 91,
                ok: true,
                json: b"{}",
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !link.control_packet_ready().await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut received = bytes::BytesMut::new();
    let mut scratch = [0; 4096];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            link.read(&mut received, &mut scratch)
        )
        .await
        .is_err()
    );
    release.send(()).unwrap();
    holder.await.unwrap();
    tokio::time::timeout(
        Duration::from_millis(100),
        link.read(&mut received, &mut scratch),
    )
    .await
    .expect("select cancellation must retain the dequeued frame")
    .unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&received)
            .unwrap()
            .frame,
        Frame::Result { call_id: 91, .. }
    ));
    received.clear();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            link.read(&mut received, &mut scratch)
        )
        .await
        .is_err(),
        "frame delivered only once"
    );
}

#[test]
fn remote_peer_routing_capability_does_not_retain_the_host_registry() {
    let hosts = RemoteHosts::default();
    let weak = std::sync::Arc::downgrade(&hosts.0);
    // The registry stores each admitted node channel, including its capability.
    // A strong handle here would form a cycle and retain actors after shutdown.
    let capability = hosts.peer_capability();
    drop(hosts);
    assert!(
        weak.upgrade().is_none(),
        "a node route capability retained its owning host registry"
    );
    drop(capability);
}

#[tokio::test]
async fn late_native_detach_after_peer_close_keeps_the_control_connection() {
    let (link, control, _listener, _endpoint, peer) = native_link_pair().await;
    let binding = remote_quic::negotiate_binding(&peer, &adapter_hello()).unwrap();
    let attach = Frame::AttachTerm {
        session_id: &[1; 16],
        last_out_seq: 0,
        last_in_seq: 0,
    };
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(42, &attach, &mut wire).unwrap();
    link.write(42, &attach, &wire).await.unwrap();
    let terminal =
        NativeChannel::terminal(remote_quic::accept_bound(&binding).await.unwrap()).unwrap();
    assert!(matches!(
        Receive::default().next(&terminal).await.unwrap().frame,
        Frame::AttachTerm { .. }
    ));
    let close = Frame::Close {
        code: 1000,
        reason: "terminal complete",
    };
    Transmit::default()
        .send(&terminal, 42, &close)
        .await
        .unwrap();
    let mut received = bytes::BytesMut::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        link.read(&mut received, &mut [0; 4096]),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&received)
            .unwrap()
            .frame,
        Frame::Close { .. }
    ));
    // The peer's close has already removed this native channel. A consumer
    // dropping its attachment later still produces the ordinary detach Close.
    wire.clear();
    infraternal_protocol::encode_muxed_frame_into(42, &close, &mut wire).unwrap();
    assert!(
        link.write(42, &close, &wire).await.is_ok(),
        "late detach rejected a retired native writer"
    );
    wire.clear();
    infraternal_protocol::encode_muxed_frame_into(1, &close, &mut wire).unwrap();
    assert!(
        link.write(1, &close, &wire).await.is_err(),
        "odd id accepted as native terminal cleanup"
    );
    let input = Frame::Input {
        in_seq: 0,
        bytes: b"retired input",
    };
    wire.clear();
    infraternal_protocol::encode_muxed_frame_into(42, &input, &mut wire).unwrap();
    assert!(
        link.write(42, &input, &wire).await.is_err(),
        "data recreated a retired writer"
    );
    let ping = Frame::Ping {
        nonce: 73,
        sent_us: 0,
    };
    wire.clear();
    infraternal_protocol::encode_muxed_frame_into(0, &ping, &mut wire).unwrap();
    link.write(0, &ping, &wire).await.unwrap();
    assert!(matches!(
        Receive::default().next(&control).await.unwrap().frame,
        Frame::Ping { nonce: 73, .. }
    ));
    let response = Frame::Pong {
        nonce: 73,
        sent_us: 0,
    };
    Transmit::default()
        .send(&control, 0, &response)
        .await
        .unwrap();
    received.clear();
    tokio::time::timeout(
        Duration::from_secs(2),
        link.read(&mut received, &mut [0; 4096]),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&received)
            .unwrap()
            .frame,
        Frame::Pong { nonce: 73, .. }
    ));
    assert!(
        peer.close_reason().is_none(),
        "terminal retirement closed the host transport"
    );
}

#[tokio::test]
async fn late_native_detach_after_peer_stop_keeps_the_control_connection() {
    let (link, control, _listener, _endpoint, peer) = native_link_pair().await;
    let binding = remote_quic::negotiate_binding(&peer, &adapter_hello()).unwrap();
    let attach = Frame::AttachTerm {
        session_id: &[1; 16],
        last_out_seq: 0,
        last_in_seq: 0,
    };
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(42, &attach, &mut wire).unwrap();
    link.write(42, &attach, &wire).await.unwrap();
    let mut terminal = remote_quic::accept_bound(&binding).await.unwrap();
    let mut raw = Vec::new();
    infraternal_protocol::encode_frame_into(&attach, &mut raw).unwrap();
    let mut received_attach = vec![0; raw.len()];
    terminal
        .receive
        .read_exact(&mut received_attach)
        .await
        .unwrap();
    assert_eq!(received_attach, raw);
    let before = link.test_received_stop_sending().unwrap();
    terminal.receive.stop(0u32.into()).unwrap();
    // Synchronize with the authenticated engine counter, rather than guessing
    // when the peer's STOP_SENDING packet reached the server's sender.
    tokio::time::timeout(Duration::from_secs(2), async {
        while link.test_received_stop_sending().unwrap() == before {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let close = Frame::Close {
        code: 1000,
        reason: "detached",
    };
    wire.clear();
    infraternal_protocol::encode_muxed_frame_into(42, &close, &mut wire).unwrap();
    assert!(
        link.write(42, &close, &wire).await.is_ok(),
        "late detach propagated a writer-local STOP_SENDING"
    );
    let ping = Frame::Ping {
        nonce: 89,
        sent_us: 0,
    };
    wire.clear();
    infraternal_protocol::encode_muxed_frame_into(0, &ping, &mut wire).unwrap();
    link.write(0, &ping, &wire).await.unwrap();
    assert!(matches!(
        Receive::default().next(&control).await.unwrap().frame,
        Frame::Ping { nonce: 89, .. }
    ));
    assert!(peer.close_reason().is_none());
}

#[path = "remote_ping_flood_tests.rs"]
mod ping_flood;
