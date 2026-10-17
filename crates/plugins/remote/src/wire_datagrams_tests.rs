//! Real QUIC packet ownership and cancellation checks [D198,D232].
use super::NativeDatagrams;
use crate::{
    remote_quic::{client_config, server_config},
    remote_tls::tests::{leaf, root},
};
use infraternal_plugin_api::{datagrams::AdmissionError, streams::WireStreamDef};
use infraternal_protocol::{Frame, decode_frame, desktop::Message, encode_frame_into};
use std::time::Duration;
fn identity(packet: &[u8]) -> Option<[u8; 16]> {
    let decoded = decode_frame(packet).ok()?;
    if decoded.wire_len != packet.len() {
        return None;
    }
    match decoded.frame {
        Frame::Desktop(Message::Fragment { session_id, .. }) => Some(*session_id),
        _ => None,
    }
}
static DEFINITION: WireStreamDef = WireStreamDef {
    browser_capability: None,
    capability: 256,
    opening_tag: 0x40,
    opening_identity: None,
    requests: &[0x40, 0x42, 0x43, 0x44],
    replies: &[0x41],
    max_streams: 2,
    datagram_tag: Some(0x45),
    datagram_identity: Some(identity),
};
fn packet(id: &[u8; 16]) -> Vec<u8> {
    let mut wire = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Fragment {
            session_id: id,
            sequence: 1,
            capture_ns: 1,
            keyframe: true,
            total: 3,
            offset: 0,
            bytes: b"abc",
        }),
        &mut wire,
    )
    .unwrap();
    wire
}
async fn pair() -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
) {
    let ca = root();
    let server = leaf(&ca, true);
    let client = leaf(&ca, false);
    let server = quinn::Endpoint::server(
        server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config(&client, &[ca.certificate]).unwrap());
    let dial = endpoint
        .connect(server.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client, connection) = tokio::join!(dial, async { server.accept().await.unwrap().await });
    (server, endpoint, connection.unwrap(), client.unwrap())
}

#[tokio::test]
async fn consumers_demultiplex_other_lanes_without_a_reader_task() {
    let (_server, _client, server, client) = pair().await;
    let transport = NativeDatagrams::new(server);
    let a = transport.admit(&DEFINITION, [1; 16]).unwrap();
    let b = transport.admit(&DEFINITION, [2; 16]).unwrap();
    assert!(matches!(
        transport.admit(&DEFINITION, [1; 16]),
        Err(AdmissionError::Duplicate)
    ));
    client.send_datagram(packet(&[9; 16]).into()).unwrap();
    client.send_datagram(packet(&[2; 16]).into()).unwrap();
    client.send_datagram(packet(&[1; 16]).into()).unwrap();
    let (a_packet, b_packet) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(a.receive(), b.receive())
    })
    .await
    .unwrap();
    assert_eq!(a_packet.unwrap().as_ref(), packet(&[1; 16]));
    assert_eq!(b_packet.unwrap().as_ref(), packet(&[2; 16]));
    assert!(a.send(&packet(&[2; 16])).await.is_err());
    assert!(a.send(b"malformed").await.is_err());
}
#[tokio::test]
async fn cancelling_every_idle_consumer_releases_the_read_and_last_route() {
    let (_server, _client, server, client) = pair().await;
    let transport = NativeDatagrams::new(server);
    let a = transport.admit(&DEFINITION, [1; 16]).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), a.receive())
            .await
            .is_err()
    );
    client.send_datagram(packet(&[1; 16]).into()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), a.receive())
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        packet(&[1; 16])
    );
    drop(a);
    let a = transport.admit(&DEFINITION, [1; 16]).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), a.receive())
            .await
            .is_err()
    );
    client.send_datagram(packet(&[1; 16]).into()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), a.receive())
            .await
            .unwrap()
            .is_ok()
    );
}
