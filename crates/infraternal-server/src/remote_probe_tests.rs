//! Proves pre-Hello liveness without admitting a replacement and retains coalesced frames on real mTLS streams [128,215].
use super::*;
use bytes::BytesMut;
use infraternal_agent::remote_native::NativeChannel;
use infraternal_protocol::encode_muxed_frame_into;

#[tokio::test]
async fn quic_candidate_proof_waits_for_hello_and_preserves_its_suffix() {
    let (server_identity, client_identity, root, _) = identities();
    let server = quinn::Endpoint::server(
        remote_quic::server_config(&server_identity, std::slice::from_ref(&root)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client
        .set_default_client_config(remote_quic::client_config(&client_identity, &[root]).unwrap());
    let (dial, admitted) = tokio::join!(
        client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { server.accept().await.unwrap().await.unwrap() }
    );
    let connection = dial.unwrap();
    let constructor = tokio::spawn(async move { RemoteLink::quic(admitted).await });
    let (send, receive) = connection.open_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    let mut tx = Transmit::default();
    tx.send(
        &channel,
        0,
        &Frame::Ping {
            nonce: 17,
            sent_us: 3,
        },
    )
    .await
    .unwrap();
    let mut rx = Receive::default();
    let response = tokio::time::timeout(Duration::from_secs(3), rx.next(&channel))
        .await
        .expect("proof response")
        .unwrap();
    assert_eq!(
        response.frame,
        Frame::Pong {
            nonce: 17,
            sent_us: 3
        }
    );
    assert!(
        !constructor.is_finished(),
        "proof cannot admit a host before Hello"
    );
    let mut combined = Vec::new();
    infraternal_protocol::encode_frame_into(
        &Frame::Hello {
            version: 1,
            caps: remote_quic::REMOTE_WRITER_BINDING
                | infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS
                | infraternal_plugin_api::channel::REMOTE_PATH_BACKUP,
            client_info: "fixture",
        },
        &mut combined,
    )
    .unwrap();
    let mut suffix = Vec::new();
    infraternal_protocol::encode_frame_into(
        &Frame::Ping {
            nonce: 19,
            sent_us: 5,
        },
        &mut suffix,
    )
    .unwrap();
    combined.extend(suffix);
    channel.write(&combined).await.unwrap();
    let link = constructor.await.unwrap().unwrap();
    assert!(link.supports_server_paths());
    assert_ne!(
        link.peer_capabilities() & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP,
        0
    );
    let mut bytes = BytesMut::new();
    let mut scratch = vec![0; 4096];
    link.read(&mut bytes, &mut scratch).await.unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&bytes)
            .unwrap()
            .frame,
        Frame::Hello { version: 1, .. }
    ));
    bytes.clear();
    link.read(&mut bytes, &mut scratch).await.unwrap();
    assert_eq!(
        infraternal_protocol::decode_muxed_frame(&bytes)
            .unwrap()
            .frame,
        Frame::Ping {
            nonce: 19,
            sent_us: 5
        }
    );
}

#[tokio::test]
async fn tls_candidate_proof_waits_for_hello_and_preserves_its_suffix() {
    let (server_identity, client_identity, root, _) = identities();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tls = remote_tls::server_config(&server_identity, std::slice::from_ref(&root)).unwrap();
    let accepting = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let connection = remote_tls::accept(socket, &tls).await.unwrap();
        RemoteLink::tcp(connection.channel).await
    });
    let client = remote_tls::dial(
        address,
        "localhost",
        &remote_tls::client_config(&client_identity, &[root]).unwrap(),
    )
    .await
    .unwrap();
    let mut tx = Transmit::default();
    tx.send(
        &client.channel,
        0,
        &Frame::Ping {
            nonce: 21,
            sent_us: 7,
        },
    )
    .await
    .unwrap();
    let mut rx = Receive::default();
    let response = tokio::time::timeout(Duration::from_secs(3), rx.next(&client.channel))
        .await
        .expect("proof response")
        .unwrap();
    assert_eq!(
        response.frame,
        Frame::Pong {
            nonce: 21,
            sent_us: 7
        }
    );
    assert!(
        !accepting.is_finished(),
        "proof cannot admit a host before Hello"
    );
    let mut combined = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "fixture",
        },
        &mut combined,
    )
    .unwrap();
    let mut suffix = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Ping {
            nonce: 23,
            sent_us: 9,
        },
        &mut suffix,
    )
    .unwrap();
    combined.extend(suffix);
    client.channel.write(&combined).await.unwrap();
    let link = accepting.await.unwrap().unwrap();
    assert!(!link.supports_server_paths(), "old Hello stays compatible");
    assert_eq!(
        link.peer_capabilities() & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP,
        0
    );
    let mut bytes = BytesMut::new();
    let mut scratch = vec![0; 4096];
    link.read(&mut bytes, &mut scratch).await.unwrap();
    assert!(matches!(
        infraternal_protocol::decode_muxed_frame(&bytes)
            .unwrap()
            .frame,
        Frame::Hello { version: 1, .. }
    ));
    bytes.clear();
    link.read(&mut bytes, &mut scratch).await.unwrap();
    assert_eq!(
        infraternal_protocol::decode_muxed_frame(&bytes)
            .unwrap()
            .frame,
        Frame::Ping {
            nonce: 23,
            sent_us: 9
        }
    );
}

#[tokio::test]
async fn candidate_proof_refuses_a_second_probe_and_invalid_hello() {
    for second in [
        Frame::Ping {
            nonce: 29,
            sent_us: 0,
        },
        Frame::Hello {
            version: 2,
            caps: 0,
            client_info: "fixture",
        },
    ] {
        let (server_identity, client_identity, root, _) = identities();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = remote_tls::server_config(&server_identity, std::slice::from_ref(&root)).unwrap();
        let accepting = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let connection = remote_tls::accept(socket, &tls).await.unwrap();
            RemoteLink::tcp(connection.channel).await
        });
        let client = remote_tls::dial(
            address,
            "localhost",
            &remote_tls::client_config(&client_identity, &[root]).unwrap(),
        )
        .await
        .unwrap();
        let mut tx = Transmit::default();
        tx.send(
            &client.channel,
            0,
            &Frame::Ping {
                nonce: 27,
                sent_us: 0,
            },
        )
        .await
        .unwrap();
        let mut rx = Receive::default();
        assert_eq!(
            rx.next(&client.channel).await.unwrap().frame,
            Frame::Pong {
                nonce: 27,
                sent_us: 0
            }
        );
        tx.send(&client.channel, 0, &second).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), accepting)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "invalid input must not enter host admission"
        );
    }
}
