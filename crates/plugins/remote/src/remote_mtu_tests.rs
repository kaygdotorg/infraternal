//! Keeps acknowledged native QUIC payload sizes valid for a later mesh move in both directions [215,263], #201.
use super::*;
use crate::remote_tls::tests::{leaf, root};
use std::time::Duration;

#[tokio::test]
async fn both_directions_keep_a_mesh_safe_payload_after_discovery() {
    let ca = root();
    let server = quinn::Endpoint::server(
        server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config(&leaf(&ca, false), &[ca.certificate]).unwrap());
    let (dial, accepted) = tokio::join!(
        client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { server.accept().await.unwrap().await }
    );
    let dial = dial.unwrap();
    let accepted = accepted.unwrap();
    let expected = vec![0xa7; 32 * 1024];
    let ((), received) = tokio::join!(
        async {
            let (mut send, _) = accepted.open_bi().await.unwrap();
            send.write_all(&expected).await.unwrap();
            send.finish().unwrap();
        },
        async {
            let (_, mut receive) = dial.accept_bi().await.unwrap();
            receive.read_to_end(64 * 1024).await.unwrap()
        }
    );
    assert_eq!(received, expected);
    // Observe real acknowledged discovery rather than merely reading back the
    // configuration. Three emitted probes and an enlarged learned MTU exclude
    // the untouched 1200-byte initial state; this timeout is only a hang guard.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let client_path = dial.stats().path;
            let server_path = accepted.stats().path;
            if client_path.sent_plpmtud_probes >= 3
                && server_path.sent_plpmtud_probes >= 3
                && client_path.current_mtu > 1200
                && server_path.current_mtu > 1200
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("both real peers must acknowledge MTU discovery");
    assert!(dial.close_reason().is_none() && accepted.close_reason().is_none());
    let client_mtu = dial.stats().path.current_mtu;
    let server_mtu = accepted.stats().path.current_mtu;
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
    assert!(
        client_mtu <= PATH_SAFE_UDP_PAYLOAD,
        "client payload {client_mtu}"
    );
    assert!(
        server_mtu <= PATH_SAFE_UDP_PAYLOAD,
        "server payload {server_mtu}"
    );
}
