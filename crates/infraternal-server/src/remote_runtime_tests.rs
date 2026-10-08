//! Real TLS/QUIC actor admission and enrolled UID regression fixtures, #78.

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

fn identities() -> (Identity, Identity, X509, crate::ca::CaMaterial) {
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
    server_name.append_entry_by_text("CN", "localhost").unwrap();
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
                .dns("localhost")
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
