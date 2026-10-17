//! Break-it review of #227: an authenticated client must not be able to turn
//! single frames into an unbounded stream of server close lines.
use super::*;
use infraternal_protocol::{CLOSE_SESSION_GONE, Frame, decode_muxed_frame};
use std::{
    io::Write,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
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
    crate::stream_close::settled();
    String::from_utf8(capture.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["fields"]["event"] == "terminal_stream_closed")
        .collect()
}

/// One browser stream id is reused for attaches to session ids the account never
/// owned. Each is answered with `SESSION_GONE` and the socket stays up, so the loop
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
    // 64 attaches each run several authority reads; the 25 ms production read bound
    // fails one of them on a loaded build host and ends the socket, so the test uses
    // the 2 s bound other socket tests use. The bound is not what this test checks.
    let (f, address, server) = socket_fixture_from_fixture(f, Some(Duration::from_secs(2))).await;
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
        let decoded = decode_muxed_frame(&reply).unwrap();
        assert!(
            matches!(
                decoded.frame,
                Frame::Close { code, .. } if code == CLOSE_SESSION_GONE
            ),
            "attach {i} for an unowned session id is answered as gone and the socket stays up: stream {} {:?}",
            decoded.stream_id,
            decoded.frame
        );
    }
    let lines = closed_lines(&capture);
    server.abort();
    assert!(
        lines
            .iter()
            .all(|line| line["fields"]["session_id"] == "none"),
        "a line names a session id the account does not own"
    );
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
