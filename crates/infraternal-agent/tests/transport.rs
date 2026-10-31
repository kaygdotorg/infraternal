//! Real socketpair framing and inherited descriptor ownership checks [9][12][40][41].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_agent::transport::{Receive, Socket, Transmit};
use infraternal_protocol::{Frame, encode_muxed_frame_into};
use std::{
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixStream},
};

#[tokio::test(flavor = "current_thread")]
async fn fragmented_headers_coalesced_frames_and_reusable_transmit() {
    let (local, mut server) = UnixStream::pair().unwrap();
    let socket = Socket::inherited(local.as_raw_fd()).unwrap();
    let mut receive = Receive::default();
    let mut packet = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "fake server",
        },
        &mut packet,
    )
    .unwrap();
    let mut input = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Input {
            in_seq: 7,
            bytes: b"hello",
        },
        &mut input,
    )
    .unwrap();
    // Fragment both varint headers, then coalesce the remainder with a second
    // frame. The server remains blocking; MSG_DONTWAIT must govern the local fd.
    server.write_all(&packet[..1]).unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), receive.next(&socket))
            .await
            .is_err()
    );
    // Cancellation after a partial mux prefix must retain the prefix exactly.
    let mut remaining = packet[1..].to_vec();
    remaining.extend_from_slice(&input);
    server.write_all(&remaining).unwrap();
    let hello = receive.next(&socket).await.unwrap();
    assert_eq!(hello.stream_id, 0);
    assert!(matches!(hello.frame, Frame::Hello { version: 1, .. }));
    let input = receive.next(&socket).await.unwrap();
    assert_eq!(input.stream_id, 1);
    assert_eq!(
        input.frame,
        Frame::Input {
            in_seq: 7,
            bytes: b"hello"
        }
    );
    let other = Socket::inherited(server.as_raw_fd()).unwrap();
    let mut transmit = Transmit::default();
    transmit
        .send(
            &socket,
            1,
            &Frame::Output {
                out_seq: 12,
                bytes: b"echo",
            },
        )
        .await
        .unwrap();
    let mut response = Receive::default();
    assert_eq!(
        response.next(&other).await.unwrap().frame,
        Frame::Output {
            out_seq: 12,
            bytes: b"echo"
        }
    );
    transmit
        .send(&socket, 1, &Frame::Ack { in_seq_acked: 12 })
        .await
        .unwrap();
    assert_eq!(
        response.next(&other).await.unwrap().frame,
        Frame::Ack { in_seq_acked: 12 }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_header_and_truncated_frame_are_rejected() {
    let (local, mut server) = UnixStream::pair().unwrap();
    let socket = Socket::inherited(local.as_raw_fd()).unwrap();
    // mux stream zero, length 4 MiB + 1; no body allocation is permitted.
    server.write_all(&[0, 0x81, 0x80, 0x80, 0x02]).unwrap();
    assert_eq!(
        Receive::default().next(&socket).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    drop(server);
    let (local, mut server) = UnixStream::pair().unwrap();
    let socket = Socket::inherited(local.as_raw_fd()).unwrap();
    server.write_all(&[0, 9, 0x13, 1]).unwrap();
    drop(server);
    assert_eq!(
        Receive::default().next(&socket).await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replacing_the_callers_descriptor_cannot_redirect_registered_io() {
    use std::os::fd::OwnedFd;
    use std::time::Duration;

    let (original, mut original_peer) = UnixStream::pair().unwrap();
    let mut caller: OwnedFd = original.into();
    let socket = Socket::inherited(caller.as_raw_fd()).unwrap();
    let (replacement, mut replacement_peer) = UnixStream::pair().unwrap();
    // dup2 safely replaces a caller-owned descriptor without racing another
    // test's allocation. A registration must retain the original description.
    nix::unistd::dup2(&replacement, &mut caller).unwrap();
    replacement_peer.write_all(b"replacement").unwrap();
    original_peer.write_all(b"original").unwrap();
    let mut bytes = [0; 32];
    let count = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut bytes))
        .await
        .expect("original socket readiness must remain reachable")
        .unwrap();
    assert_eq!(&bytes[..count], b"original");
    drop(caller);
    original_peer.write_all(b"still open").unwrap();
    let count = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut bytes))
        .await
        .expect("closing the caller must not close the registration")
        .unwrap();
    assert_eq!(&bytes[..count], b"still open");
}
