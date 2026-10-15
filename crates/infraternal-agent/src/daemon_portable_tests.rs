//! Verifies that portable nodes publish their honest empty census before solicited replies, so admitted Macs become online [D203,D232,#146].
use super::*;
use crate::transport::Transmit;
use std::{
    os::{fd::AsRawFd, unix::fs::DirBuilderExt},
    path::PathBuf,
    time::Duration,
};

struct State(PathBuf);
impl State {
    fn new() -> Self {
        // Relative runtime names stay within Unix socket limits even when
        // Cargo stores its build artifacts under a long scratch path.
        std::fs::create_dir_all("target").unwrap();
        let name = uuid::Uuid::new_v4().simple().to_string();
        let path = PathBuf::from(format!("target/pc-{}-{}", std::process::id(), &name[..8]));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for State {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn portable_greeting_publishes_empty_inventory_before_pong() {
    let state = State::new();
    let service = crate::plugin_control::Service::start(&state.0, ExecutionMode::Embedded, None)
        .await
        .unwrap();
    let registry = service.registry.clone();
    let (host_stream, control_stream) = std::os::unix::net::UnixStream::pair().unwrap();
    let host = Socket::inherited(host_stream.as_raw_fd()).unwrap();
    let control = Socket::inherited(control_stream.as_raw_fd()).unwrap();
    let daemon = tokio::spawn(async move {
        let _lease = host_stream;
        let _service = service;
        dispatch(&host, registry, true, None, 0).await
    });
    let mut tx = Transmit::default();
    tx.send(
        &control,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "portable census regression",
        },
    )
    .await
    .unwrap();
    tx.send(
        &control,
        0,
        &Frame::Ping {
            nonce: 146,
            sent_us: 0,
        },
    )
    .await
    .unwrap();
    let mut rx = Receive::default();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), rx.next(&control))
            .await
            .unwrap()
            .unwrap()
            .frame,
        Frame::Hello { version: 1, .. }
    ));
    let inventory = tokio::time::timeout(Duration::from_secs(5), rx.next(&control))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inventory.stream_id, 0);
    let Frame::Event {
        sub_id: 0,
        event_json,
    } = inventory.frame
    else {
        daemon.abort();
        let _ = daemon.await;
        panic!("portable nodes must publish their empty census before replying to Ping");
    };
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(event_json).unwrap(),
        serde_json::json!({"type":"terminal.sessions.snapshot","session_ids":[]})
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), rx.next(&control))
            .await
            .unwrap()
            .unwrap()
            .frame,
        Frame::Pong { nonce: 146, .. }
    ));
    daemon.abort();
    let _ = daemon.await;
}
