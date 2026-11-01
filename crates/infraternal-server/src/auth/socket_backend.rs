//! Synchronizes real backend fixtures on terminal opens while acknowledging independent login preparation.
use super::*;

/// The background login request is independent of the terminal deadline under test.
pub(super) async fn read_terminal_open(peer: &mut UnixStream, receive: &mut BytesMut) -> Vec<u8> {
    loop {
        let wire = read_leg_b_frame(peer, receive).await.unwrap();
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Call {
                action_id: "terminal.login.prepare",
                call_id,
                ..
            } => {
                leg_b_send(
                    peer,
                    0,
                    &Frame::Result {
                        call_id,
                        ok: true,
                        json: br#"{"prepared":true}"#,
                    },
                )
                .await;
            }
            Frame::Call {
                action_id: "terminal.open",
                ..
            } => return wire.to_vec(),
            frame => panic!("unexpected backend frame before terminal open: {frame:?}"),
        }
    }
}
