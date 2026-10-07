//! Tests native QUIC framing and cancellation against real quinn streams; mux identities never enter raw bytes [64][130], #78.

use super::*;
use crate::{
    remote_quic,
    remote_tls::tests::{leaf, root},
    transport::{Receive, Transmit},
};
use infraternal_protocol::{Frame, decode_frame, encode_frame_into};

struct Pair {
    server_endpoint: quinn::Endpoint,
    client_endpoint: quinn::Endpoint,
    server: quinn::Connection,
    client: quinn::Connection,
}
impl Pair {
    async fn new() -> Self {
        let ca = root();
        let server = quinn::Endpoint::server(
            remote_quic::server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate))
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            remote_quic::client_config(&leaf(&ca, false), &[ca.certificate]).unwrap(),
        );
        let (local, remote) = tokio::join!(
            client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        Self {
            server_endpoint: server,
            client_endpoint: client,
            server: remote.unwrap(),
            client: local.unwrap(),
        }
    }
    fn binding(&self, server: bool) -> remote_quic::BindingConnection {
        remote_quic::negotiate_binding(
            if server { &self.server } else { &self.client },
            &Frame::Hello {
                version: 1,
                caps: remote_quic::REMOTE_WRITER_BINDING,
                client_info: "test",
            },
        )
        .unwrap()
    }
}

#[tokio::test]
async fn bound_writer_uses_raw_frames_and_rejects_cross_writer_transmit() {
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let server = server.unwrap();
    let mut host = host.unwrap();
    let channel = NativeChannel::terminal(server).unwrap();
    let mut tx = Transmit::default();
    let input = Frame::Input {
        in_seq: 11,
        bytes: b"native-input",
    };
    assert_eq!(
        tx.send(&channel, 44, &input).await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    tx.send(&channel, 42, &input).await.unwrap();
    let mut expected = Vec::new();
    encode_frame_into(&input, &mut expected).unwrap();
    let mut raw = vec![0; expected.len()];
    host.receive.read_exact(&mut raw).await.unwrap();
    let decoded = decode_frame(&raw).unwrap();
    assert_eq!(raw, expected);
    assert_eq!(decoded.frame, input);
    assert_eq!(decoded.wire_len, raw.len());
    let mut raw = Vec::new();
    encode_frame_into(&Frame::Ack { in_seq_acked: 11 }, &mut raw).unwrap();
    let mut suffix = Vec::new();
    encode_frame_into(
        &Frame::Output {
            out_seq: 99,
            bytes: b"raw-output",
        },
        &mut suffix,
    )
    .unwrap();
    raw.extend_from_slice(&suffix);
    host.send.write_all(&raw).await.unwrap();
    let mut rx = Receive::default();
    let decoded = rx.next(&channel).await.unwrap();
    assert_eq!(decoded.stream_id, 42);
    assert_eq!(decoded.frame, Frame::Ack { in_seq_acked: 11 });
    let decoded = rx.next(&channel).await.unwrap();
    assert_eq!(decoded.stream_id, 42);
    assert_eq!(
        decoded.frame,
        Frame::Output {
            out_seq: 99,
            bytes: b"raw-output"
        }
    );
}

#[tokio::test]
async fn partial_native_write_cancellation_retires_both_directions() {
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, _host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let channel = NativeChannel::terminal(server.unwrap()).unwrap();
    // The peer retains its stream without consuming. Outstanding flow credit is
    // 1MiB, so this larger write cannot complete before cancellation.
    let bytes = vec![0; 8 * 1024 * 1024];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), channel.write(&bytes))
            .await
            .is_err()
    );
    assert_eq!(
        channel.write(b"suffix").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        channel.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn control_must_be_host_initiated_stream_zero_and_terminal_halves_cannot_impersonate_it() {
    let pair = Pair::new().await;
    let (mut host_send, host_receive) = pair.client.open_bi().await.unwrap();
    host_send.write_all(&[0]).await.unwrap();
    let (send, receive) = pair.server.accept_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    assert_eq!(channel.native_stream_id(), Some(0));
    drop(host_receive);
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let server = server.unwrap();
    assert!(NativeChannel::control(server.send, server.receive).is_err());
    drop(host.unwrap());
}

#[path = "native_terminal_tests.rs"]
mod terminal;
