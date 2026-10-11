//! Exercises shared daemon admission over real mTLS; rejected requests cannot launch a shim or override enrolled uid [64][128], #78.

use super::*;
use crate::remote_tls::{
    self,
    tests::{leaf, root},
};
use std::time::Duration;

struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/remote-agents")
            .join(format!("daemon-{}", uuid::Uuid::new_v4()));
        Self(path)
    }
}
impl Drop for State {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn channels() -> (remote_tls::TcpTls, remote_tls::TcpTls) {
    let ca = root();
    let server =
        remote_tls::server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap();
    let client = remote_tls::client_config(&leaf(&ca, false), &[ca.certificate]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (host, control) = tokio::join!(
        remote_tls::dial(listener.local_addr().unwrap(), "localhost", &client),
        async { remote_tls::accept(listener.accept().await.unwrap().0, &server).await }
    );
    (host.unwrap().channel, control.unwrap().channel)
}

fn hello() -> Frame<'static> {
    Frame::Hello {
        version: 1,
        caps: 0,
        client_info: "authenticated server test",
    }
}

#[tokio::test]
async fn wrong_enrolled_uid_is_refused_before_state_creation() {
    let state = State::new();
    let (host, _) = channels().await;
    assert!(
        run_authenticated(
            &host,
            Some(state.0.clone()),
            nix::unistd::Uid::effective().as_raw() ^ 1
        )
        .await
        .is_err()
    );
    assert!(!state.0.exists());
}

#[tokio::test]
async fn wrong_open_uid_is_rejected_while_control_remains_usable() {
    let state = State::new();
    let (host, control) = channels().await;
    let path = state.0.clone();
    let uid = nix::unistd::Uid::effective().as_raw();
    let daemon = tokio::spawn(async move { run_authenticated(&host, Some(path), uid).await });
    let mut tx = Transmit::default();
    tx.send(&control, 0, &hello()).await.unwrap();
    let mut rx = Receive::default();
    assert!(matches!(
        rx.next(&control).await.unwrap().frame,
        Frame::Hello { version: 1, .. }
    ));
    let json = serde_json::to_vec(&serde_json::json!({"uid":uid ^ 1,"cols":80,"rows":24})).unwrap();
    tx.send(
        &control,
        0,
        &Frame::Call {
            call_id: 7,
            action_id: "terminal.open",
            input_json: &json,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        rx.next(&control).await.unwrap().frame,
        Frame::Result {
            call_id: 7,
            ok: false,
            ..
        }
    ));
    tx.send(
        &control,
        0,
        &Frame::Ping {
            nonce: 42,
            sent_us: 0,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        rx.next(&control).await.unwrap().frame,
        Frame::Pong { nonce: 42, .. }
    ));
    assert_eq!(
        std::fs::read_dir(state.0.join("sessions")).unwrap().count(),
        0
    );
    control.retire();
    daemon.abort();
    let _ = daemon.await;
}

#[tokio::test]
async fn control_greeting_precedes_actions_and_odd_writers_are_refused() {
    for (stream, frame) in [
        (
            0,
            Frame::Ping {
                nonce: 1,
                sent_us: 0,
            },
        ),
        (2, hello()),
        (
            0,
            Frame::Hello {
                version: 2,
                caps: 0,
                client_info: "test",
            },
        ),
    ] {
        let state = State::new();
        let (host, control) = channels().await;
        Transmit::default()
            .send(&control, stream, &frame)
            .await
            .unwrap();
        assert!(
            run_authenticated(
                &host,
                Some(state.0.clone()),
                nix::unistd::Uid::effective().as_raw()
            )
            .await
            .is_err()
        );
    }
    for (stream, frame) in [
        (0, hello()),
        (
            1,
            Frame::Ping {
                nonce: 1,
                sent_us: 0,
            },
        ),
    ] {
        let state = State::new();
        let (host, control) = channels().await;
        let mut tx = Transmit::default();
        tx.send(&control, 0, &hello()).await.unwrap();
        tx.send(&control, stream, &frame).await.unwrap();
        assert!(
            run_authenticated(
                &host,
                Some(state.0.clone()),
                nix::unistd::Uid::effective().as_raw()
            )
            .await
            .is_err()
        );
    }
}

#[tokio::test]
async fn silent_authenticated_peer_has_a_greeting_deadline() {
    let state = State::new();
    let (host, _control) = channels().await;
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        run_authenticated(
            &host,
            Some(state.0.clone()),
            nix::unistd::Uid::effective().as_raw(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn cancelling_remote_dispatch_retires_the_borrowed_authenticated_channel() {
    let state = State::new();
    let (host, control) = channels().await;
    let host = std::sync::Arc::new(host);
    let spare = host.clone();
    let path = state.0.clone();
    let daemon = tokio::spawn(async move {
        run_authenticated(
            host.as_ref(),
            Some(path),
            nix::unistd::Uid::effective().as_raw(),
        )
        .await
    });
    Transmit::default()
        .send(&control, 0, &hello())
        .await
        .unwrap();
    assert!(matches!(
        Receive::default().next(&control).await.unwrap().frame,
        Frame::Hello { version: 1, .. }
    ));
    daemon.abort();
    let _ = daemon.await;
    assert_eq!(
        spare.write(b"must not reuse").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        spare.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}
