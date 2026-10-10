//! Exercises the actual terminal actor's leg-A/leg-B routing in SSH readiness; malformed canary input must not retire a healthy host.
use super::*;
use bytes::{Buf, BytesMut};
use infraternal_protocol::{DecodeError, Frame, decode_muxed_frame, encode_muxed_frame_into};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

async fn terminal_peer(mut socket: UnixStream) {
    let mut pending = BytesMut::new();
    let mut reply = Vec::new();
    loop {
        let frame = loop {
            match decode_muxed_frame(&pending) {
                Ok(frame) => break frame,
                Err(DecodeError::Incomplete) => {
                    if socket.read_buf(&mut pending).await.unwrap() == 0 {
                        return;
                    }
                }
                Err(error) => panic!("invalid fixture frame: {error:?}"),
            }
        };
        let length = frame.wire_len;
        let response = match frame.frame {
            Frame::Hello { .. } => Some(Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "readiness-peer",
            }),
            Frame::Call { call_id, .. } => Some(Frame::Result {
                call_id,
                ok: true,
                json: br#"{"session_id":"11111111111111111111111111111111"}"#,
            }),
            Frame::AttachTerm { .. } => Some(Frame::Ack { in_seq_acked: 0 }),
            _ => None,
        };
        if let Some(response) = response {
            encode_muxed_frame_into(frame.stream_id, &response, &mut reply).unwrap();
            socket.write_all(&reply).await.unwrap();
        }
        if let Frame::Input { bytes, .. } = frame.frame {
            // The controlled peer emits a marker only after the actual actor forwards the input.
            let command = std::str::from_utf8(bytes).unwrap();
            let arguments: Vec<_> = command.split('\'').collect();
            let marker = format!("{}{}", arguments[3], arguments[5]);
            encode_muxed_frame_into(
                frame.stream_id,
                &Frame::Output {
                    out_seq: 0,
                    bytes: marker.as_bytes(),
                },
                &mut reply,
            )
            .unwrap();
            socket.write_all(&reply).await.unwrap();
        }
        pending.advance(length);
    }
}

#[tokio::test]
async fn readiness_input_preserves_the_terminal_actor_and_host_connection() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let task = tokio::spawn(terminal_peer(peer));
    let actor = EmbeddedAgent::from_test_socket(socket);
    tokio::time::timeout(Duration::from_secs(5), canary(&actor))
        .await
        .unwrap()
        .unwrap();
    assert!(
        actor
            .call("host.facts.read".into(), b"{}".to_vec())
            .await
            .is_ok()
    );
    drop(actor);
    task.abort();
    let _ = task.await;
}
