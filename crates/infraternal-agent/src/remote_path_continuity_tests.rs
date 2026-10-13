//! Proves existing mTLS connection and native writer continuity through experimental UDP routing, without claiming mesh, PTY or latency acceptance [164,263].
use super::*;
use infraternal_plugin_remote::remote_path_socket::PeerSocket;
use quinn::{AsyncUdpSocket, Runtime as _};
use std::sync::Arc;

fn socket() -> Arc<dyn AsyncUdpSocket> {
    quinn::TokioRuntime
        .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap()
}

async fn transfer(
    sender: &mut remote_quic::BoundStream,
    peer: &mut remote_quic::BoundStream,
    frame: &Frame<'_>,
) {
    let mut encoded = Vec::new();
    encode_frame_into(frame, &mut encoded).unwrap();
    sender.send.write_all(&encoded).await.unwrap();
    let mut received = vec![0; encoded.len()];
    peer.receive.read_exact(&mut received).await.unwrap();
    assert_eq!(received, encoded);
    assert_eq!(
        infraternal_protocol::decode_frame(&received).unwrap().frame,
        *frame
    );
}

// One bounded fixture owns both endpoints and every previous socket. No worker
// survives the test, and failures cannot hang the repository's functional gate.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn existing_quic_connection_and_bound_writer_survive_route_change_and_return() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let ca = root();
        let server_identity = leaf(&ca, true);
        let client_identity = leaf(&ca, false);
        let original_server = socket();
        let original_client = socket();
        let server_address = original_server.local_addr().unwrap();
        let client_address = original_client.local_addr().unwrap();
        let server = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(
                remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
                    .unwrap(),
            ),
            original_server.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            original_client.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        client.set_default_client_config(
            remote_quic::client_config(&client_identity, std::slice::from_ref(&ca.certificate))
                .unwrap(),
        );
        let (dialed, admitted) = tokio::join!(
            client.connect(server_address, "localhost").unwrap(),
            async { server.accept().await.unwrap().await.unwrap() }
        );
        let dialed = dialed.unwrap();
        let identities = (
            remote_quic::peer_fingerprint(&dialed).unwrap(),
            remote_quic::peer_fingerprint(&admitted).unwrap(),
        );
        let connections = (dialed.stable_id(), admitted.stable_id());
        let hello = Frame::Hello {
            version: 1,
            caps: remote_quic::REMOTE_WRITER_BINDING,
            client_info: "fixture",
        };
        let mut greeting = Vec::new();
        encode_frame_into(&hello, &mut greeting).unwrap();
        let (mut client_send, mut client_receive) = dialed.open_bi().await.unwrap();
        client_send.write_all(&greeting).await.unwrap();
        let (mut server_send, mut server_receive) = admitted.accept_bi().await.unwrap();
        let mut received = vec![0; greeting.len()];
        server_receive.read_exact(&mut received).await.unwrap();
        let server_binding = remote_quic::negotiate_binding(
            &admitted,
            &infraternal_protocol::decode_frame(&received).unwrap().frame,
        )
        .unwrap();
        server_send.write_all(&greeting).await.unwrap();
        client_receive.read_exact(&mut received).await.unwrap();
        let client_binding = remote_quic::negotiate_binding(
            &dialed,
            &infraternal_protocol::decode_frame(&received).unwrap().frame,
        )
        .unwrap();
        let mut writer = remote_quic::open_bound(&server_binding, 2).await.unwrap();
        let mut peer = remote_quic::accept_bound(&client_binding).await.unwrap();
        let streams = (writer.send.id(), peer.send.id());
        transfer(
            &mut writer,
            &mut peer,
            &Frame::Input {
                in_seq: 0,
                bytes: b"before|",
            },
        )
        .await;
        transfer(
            &mut peer,
            &mut writer,
            &Frame::Output {
                out_seq: 0,
                bytes: b"before|",
            },
        )
        .await;

        // Keep the logical peer tuples while changing the physical sockets.
        // These use the same local IP deliberately: server source-IP selection
        // across different IPs still needs a separate experiment.
        let routed_server = socket();
        let routed_client = socket();
        let physical_server = routed_server.local_addr().unwrap();
        let physical_client = routed_client.local_addr().unwrap();
        server
            .rebind_abstract(Arc::new(PeerSocket::new(
                routed_server,
                client_address,
                physical_client,
            )))
            .unwrap();
        client
            .rebind_abstract(Arc::new(PeerSocket::new(
                routed_client,
                server_address,
                physical_server,
            )))
            .unwrap();
        transfer(
            &mut writer,
            &mut peer,
            &Frame::Input {
                in_seq: 7,
                bytes: b"mapped|",
            },
        )
        .await;
        transfer(
            &mut peer,
            &mut writer,
            &Frame::Output {
                out_seq: 7,
                bytes: b"mapped|",
            },
        )
        .await;

        // Restore the exact original owned sockets. Rebind replaces the previous
        // slot too, so no descriptor is polled in both current/previous slots.
        server.rebind_abstract(original_server).unwrap();
        client.rebind_abstract(original_client).unwrap();
        transfer(
            &mut writer,
            &mut peer,
            &Frame::Input {
                in_seq: 14,
                bytes: b"returned|",
            },
        )
        .await;
        transfer(
            &mut peer,
            &mut writer,
            &Frame::Output {
                out_seq: 14,
                bytes: b"returned|",
            },
        )
        .await;
        assert_eq!((writer.writer_id, peer.writer_id), (2, 2));
        assert_eq!((writer.send.id(), peer.send.id()), streams);
        assert_eq!((dialed.stable_id(), admitted.stable_id()), connections);
        assert_eq!(
            (
                remote_quic::peer_fingerprint(&dialed).unwrap(),
                remote_quic::peer_fingerprint(&admitted).unwrap()
            ),
            identities
        );
        assert_eq!(
            (server.open_connections(), client.open_connections()),
            (1, 1)
        );
        assert_eq!(admitted.remote_address(), client_address);
        assert_eq!(dialed.remote_address(), server_address);
        writer.send.finish().unwrap();
        peer.send.finish().unwrap();
        let mut tail = [0; 1];
        assert_eq!(writer.receive.read(&mut tail).await.unwrap(), None);
        assert_eq!(peer.receive.read(&mut tail).await.unwrap(), None);
        server.close(0u32.into(), b"");
        client.close(0u32.into(), b"");
    })
    .await
    .expect("authenticated route continuity failed");
}
