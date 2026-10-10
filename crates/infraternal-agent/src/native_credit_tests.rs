//! Exercises private native-stream credit backpressure while a real Unix shim handshake is deliberately paused [64][130], #78.
use super::*;

#[tokio::test]
async fn private_credit_burst_waits_for_its_shim_without_retiring_native_stream() {
    let id = uuid::Uuid::new_v4();
    let base =
        PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/codex-scratch/remote-agents");
    let path = sessions::state(Some(
        base.join(format!("c{}", &id.simple().to_string()[..8])),
    ))
    .unwrap();
    let state = State { path, pid: None };
    let socket = state
        .path
        .join("sessions")
        .join(format!("{}.sock", id.simple()));
    let shim = tokio::net::UnixListener::bind(socket).unwrap();
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let host = NativeChannel::terminal(host.unwrap()).unwrap();
    let path = state.path.clone();
    let mut task = tokio::spawn(async move { daemon::run_bound_terminal(&host, Some(path)).await });
    let channel = NativeChannel::terminal(server.unwrap()).unwrap();
    Transmit::default()
        .send(
            &channel,
            42,
            &Frame::AttachTerm {
                session_id: id.as_bytes(),
                last_out_seq: 0,
                last_in_seq: 0,
            },
        )
        .await
        .unwrap();
    // The kernel connection is established, but no shim response is sent yet.
    // The relay cannot drain commands while authenticating this peer.
    let (_paused, _) = tokio::time::timeout(Duration::from_secs(2), shim.accept())
        .await
        .unwrap()
        .unwrap();
    let mut burst = Vec::new();
    let mut frame = Vec::new();
    for _ in 0..32 {
        infraternal_protocol::encode_frame_into(&Frame::Credit { bytes: 4096 }, &mut frame)
            .unwrap();
        burst.extend_from_slice(&frame);
    }
    channel.write(&burst).await.unwrap();
    let completed = tokio::time::timeout(Duration::from_millis(100), &mut task).await;
    if completed.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert!(
        completed.is_err(),
        "a bounded private credit burst retired a live native stream"
    );
    channel.retire();
}
