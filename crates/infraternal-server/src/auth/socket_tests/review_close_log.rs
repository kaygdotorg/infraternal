//! Break-it review of #227: an authenticated client must not be able to turn
//! single frames into an unbounded stream of server close lines.
use super::*;
use infraternal_protocol::{CLOSE_SESSION_GONE, Frame, decode_muxed_frame};
use std::{
    io::Write,
    sync::{Arc, Mutex as StdMutex},
};

#[derive(Clone, Default)]
struct Capture(Arc<StdMutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

fn closed_lines(capture: &Capture) -> Vec<serde_json::Value> {
    String::from_utf8(capture.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["fields"]["event"] == "terminal_stream_closed")
        .collect()
}

/// One browser stream id is reused for attaches to session ids the account never
/// owned. Each is answered with SESSION_GONE and the socket stays up, so the loop
/// is limited only by SQLite. Every attach writes a fresh first-close line because
/// the rate limiter keys on the client-chosen session id.
#[tokio::test]
async fn attaches_to_unowned_session_ids_cannot_flood_the_close_log() {
    let _serial = SERIAL.lock().await;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_writer(capture.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let f = fixture().await;
    let (f, address, server) = socket_fixture_from_fixture(f, None).await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut browser, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut browser).await;
    client_ws_send(
        &mut browser,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "review-close-flood",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    let attempts = 64_u8;
    for i in 0..attempts {
        let session_id = [i.wrapping_add(1); 16];
        client_ws_send(
            &mut browser,
            1,
            &Frame::AttachTerm {
                session_id: &session_id,
                last_out_seq: 0,
                last_in_seq: 0,
            },
        )
        .await;
        let reply = read_client_frame(&mut browser).await;
        assert!(
            matches!(
                decode_muxed_frame(&reply).unwrap().frame,
                Frame::Close { code, .. } if code == CLOSE_SESSION_GONE
            ),
            "attach {i} for an unowned session id is answered as gone and the socket stays up"
        );
    }
    let lines = closed_lines(&capture);
    server.abort();
    assert!(
        lines.len() <= 8,
        "{} terminal_stream_closed lines for {attempts} attach frames on one socket; \
         first session id logged: {}",
        lines.len(),
        lines
            .first()
            .map_or(String::new(), |l| l["fields"]["session_id"].to_string()),
    );
}
