//! Distinguishes a full native control FIFO from healthy independent terminal delivery, #129.
use super::*;
use crate::embedded::TerminalOutput;

/// The controlled shadow proves readiness only: no retained input or shadow
/// Output can mask whether the ordinary primary delivers its healthy terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_native_control_queue_does_not_hide_primary_terminal_output() {
    verify_saturated_primary(false).await;
}

/// Periodic liveness must retain its request while ordinary control is full;
/// independent terminal traffic remains useful within the probe reply budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scheduled_probe_preserves_primary_at_full_native_control_capacity() {
    verify_saturated_primary(true).await;
}

async fn verify_saturated_primary(wait_for_probe: bool) {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let listener = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let (live_endpoint, live_connection, live) =
        connect_control_with_window(address, &node, &root, true).await;
    Transmit::default().send(&live, 0, &hello()).await.unwrap();
    assert!(matches!(
        Receive::default().next(&live).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let live_binding = remote_quic::negotiate_binding(&live_connection, &hello()).unwrap();
    let actor = hosts.0.lock().await[&host_id].actor.clone();
    let attachment = actor.attach([9; 16], 0, 0, 42).await.unwrap();
    let terminal = NativeChannel::terminal(
        tokio::time::timeout(
            Duration::from_secs(2),
            remote_quic::accept_bound(&live_binding),
        )
        .await
        .unwrap()
        .unwrap(),
    )
    .unwrap();
    let mut terminal_receive = Receive::default();
    assert!(matches!(
        terminal_receive.next(&terminal).await.unwrap().frame,
        Frame::AttachTerm { .. }
    ));
    Transmit::default()
        .send(&terminal, 42, &Frame::Ack { in_seq_acked: 0 })
        .await
        .unwrap();
    let (input, mut output) = attachment.split();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), output.recv())
            .await
            .unwrap()
            .unwrap(),
        TerminalOutput::Ack { in_seq_acked: 0 }
    ));
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(41, &Frame::Credit { bytes: 8 }, &mut wire)
        .unwrap();
    input.send_frame(Bytes::from(wire)).await.unwrap();
    assert!(matches!(
        terminal_receive.next(&terminal).await.unwrap().frame,
        Frame::Credit { bytes: 8 }
    ));

    // A real enrolled secondary enables the production owned-write path.
    // The fixture never sends Input or Output on that terminal.
    let (_warm_endpoint, warm_connection, warm) = connect_control(address, &node, &root).await;
    let mut warm_receive = Receive::default();
    Transmit::default()
        .send(
            &warm,
            0,
            &Frame::Ping {
                nonce: 201,
                sent_us: 0,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        warm_receive.next(&warm).await.unwrap().frame,
        Frame::Pong { nonce: 201, .. }
    ));
    Transmit::default()
        .send(
            &warm,
            0,
            &Frame::Call {
                call_id: 0,
                action_id: "transport.standby",
                input_json: br#"{"prime":true}"#,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        warm_receive.next(&warm).await.unwrap().frame,
        Frame::Result {
            call_id: 0,
            ok: true,
            ..
        }
    ));
    assert!(matches!(
        warm_receive.next(&warm).await.unwrap().frame,
        Frame::Hello { caps, .. } if caps & infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS != 0
    ));
    let warm_hello = Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING
            | infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS,
        client_info: "control saturation fixture",
    };
    Transmit::default()
        .send(&warm, 0, &warm_hello)
        .await
        .unwrap();
    let warm_binding = remote_quic::negotiate_binding(&warm_connection, &warm_hello).unwrap();
    let warm_terminal = NativeChannel::terminal(
        tokio::time::timeout(
            Duration::from_secs(2),
            remote_quic::accept_bound(&warm_binding),
        )
        .await
        .unwrap()
        .unwrap(),
    )
    .unwrap();
    let mut warm_terminal_receive = Receive::default();
    assert!(matches!(
        warm_terminal_receive
            .next(&warm_terminal)
            .await
            .unwrap()
            .frame,
        Frame::Call {
            action_id: "transport.prime",
            ..
        }
    ));
    assert!(matches!(
        warm_terminal_receive
            .next(&warm_terminal)
            .await
            .unwrap()
            .frame,
        Frame::AttachTerm { .. }
    ));
    Transmit::default()
        .send(&warm_terminal, 42, &Frame::Ack { in_seq_acked: 0 })
        .await
        .unwrap();
    let peer = live_endpoint.local_addr().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while crate::embedded::test_control_queue_state(peer).is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owned control lane must be installed before the fault");
    assert!(crate::remote_link::RemoteLink::test_limit_send_window_for_peer(peer, 256));
    let caller = actor.clone();
    let payload = serde_json::to_vec(&serde_json::json!({"padding": "x".repeat(6144)})).unwrap();
    assert!(
        payload.len() > 4096,
        "fault must exceed peer control credit"
    );
    assert!(
        payload.len() <= infraternal_plugin_api::MAX_ACTION_BYTES,
        "fixture Call must reach actor admission"
    );
    let mut control_call = AbortCall(tokio::spawn(async move {
        caller.call("fixture.blocked.control".into(), payload).await
    }));

    // A valid >4KiB Call cannot complete its native write without more peer
    // credit. Observe arrival against the Call result so an admission refusal
    // is reported as a setup error rather than a misleading read timeout.
    let mut first_byte = [0; 1];
    let arrival = tokio::select! {
        bytes = tokio::time::timeout(Duration::from_secs(2), live.read(&mut first_byte)) => bytes,
        completed = &mut control_call.0 => panic!(
            "Call ended before first native byte: {completed:?}; control_state={:?}; primary_close={:?}",
            crate::embedded::test_control_queue_state(peer), live_connection.close_reason()
        ),
    };
    assert!(
        matches!(arrival, Ok(Ok(1))),
        "first native byte not observed: {arrival:?}; control_state={:?}; call_finished={}; primary_close={:?}",
        crate::embedded::test_control_queue_state(peer),
        control_call.0.is_finished(),
        live_connection.close_reason()
    );
    Transmit::default()
        .send(
            &live,
            0,
            &Frame::Ping {
                nonce: 202,
                sent_us: 0,
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(500), async {
        while crate::embedded::test_control_queue_state(peer) != Some((true, 0)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fault must prove one active blocked control flight plus a queued Pong");
    assert!(
        live_connection.close_reason().is_none(),
        "primary closed during saturation: {:?}",
        live_connection.close_reason()
    );
    assert!(!control_call.0.is_finished());
    assert!(warm_connection.close_reason().is_none());
    eprintln!("CONTROL_SATURATION active=true queued=1 native_primary_live=true shadow_output=0");
    if wait_for_probe {
        // Three 25 ms probe turns are shorter than the 250 ms reply allowance and
        // the 1 s active-write deadline. This tests queue admission, not latency.
        tokio::time::sleep(Duration::from_millis(75)).await;
        assert!(
            live_connection.close_reason().is_none(),
            "scheduled probe retired a healthy saturated primary: {:?}",
            live_connection.close_reason()
        );
    }

    Transmit::default()
        .send(
            &terminal,
            42,
            &Frame::Output {
                out_seq: 0,
                bytes: b"healthy!",
            },
        )
        .await
        .unwrap();
    let delivered = tokio::time::timeout(Duration::from_millis(100), async {
        loop {
            match output.recv().await {
                // Priming can publish an ordered route notice before the
                // healthy primary's bytes. It is not terminal delivery and
                // must not restart the original absolute deadline.
                Some(TerminalOutput::Reconnecting) => {}
                next => break next,
            }
        }
    })
    .await;
    let outcome = match &delivered {
        Err(_) => "deadline",
        Ok(None) => "channel ended",
        Ok(Some(TerminalOutput::Output { .. })) => "output",
        Ok(Some(TerminalOutput::Snapshot { .. })) => "snapshot",
        Ok(Some(TerminalOutput::Event { .. })) => "event",
        Ok(Some(TerminalOutput::Ack { .. })) => "ack",
        Ok(Some(TerminalOutput::RouteExpired)) => "route expired",
        Ok(Some(TerminalOutput::Reconnecting)) => "reconnecting",
        Ok(Some(TerminalOutput::LinkDoubt)) => "link doubt",
        Ok(Some(TerminalOutput::Recovered)) => "recovered",
        Ok(Some(TerminalOutput::Closed { .. })) => "closed",
    };
    eprintln!(
        "PRIMARY_DELIVERY outcome={outcome} close={:?}",
        live_connection.close_reason()
    );
    // Abort ownership before asserting, so even an intended red cannot leave a
    // detached pending Call. Endpoints/listener own every other task/stream.
    drop(control_call);
    assert!(
        matches!(delivered, Ok(Some(TerminalOutput::Output { out_seq: 0, bytes })) if bytes.as_ref() == b"healthy!"),
        "full control FIFO prevented healthy primary terminal delivery: {outcome}"
    );
}

struct AbortCall(tokio::task::JoinHandle<Result<Vec<u8>, crate::embedded::AgentError>>);
impl Drop for AbortCall {
    fn drop(&mut self) {
        self.0.abort();
    }
}
