//! A missed primary reply only marks the host link doubtful; the second consecutive miss retires it [D300], #234.
use super::*;
use crate::embedded::TerminalOutput;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The fixture host answers the server's primary probes only while `answer` is set.
/// Silence is the only fault: the QUIC connection, streams and terminal stay intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_missed_primary_reply_shows_reconnecting_and_only_a_second_retires_the_link() {
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
    let (_endpoint, connection, live) = connect_control(address, &node, &root).await;
    Transmit::default().send(&live, 0, &hello()).await.unwrap();
    let mut control = Receive::default();
    assert!(matches!(
        control.next(&live).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let binding = remote_quic::negotiate_binding(&connection, &hello()).unwrap();
    let actor = hosts.0.lock().await[&host_id].actor.clone();
    let attachment = actor.attach([9; 16], 0, 0, 42).await.unwrap();
    let terminal = NativeChannel::terminal(
        tokio::time::timeout(Duration::from_secs(2), remote_quic::accept_bound(&binding))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        Receive::default().next(&terminal).await.unwrap().frame,
        Frame::AttachTerm { .. }
    ));
    Transmit::default()
        .send(&terminal, 42, &Frame::Ack { in_seq_acked: 0 })
        .await
        .unwrap();
    let (_input, mut output) = attachment.split();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), output.recv())
            .await
            .unwrap()
            .unwrap(),
        TerminalOutput::Ack { in_seq_acked: 0 }
    ));

    let answer = Arc::new(AtomicBool::new(true));
    let answering = answer.clone();
    let responder = tokio::spawn(async move {
        let mut transmit = Transmit::default();
        while let Ok(received) = control.next(&live).await {
            if let Frame::Ping { nonce, sent_us } = received.frame
                && answering.load(Ordering::SeqCst)
                && transmit
                    .send(&live, 0, &Frame::Pong { nonce, sent_us })
                    .await
                    .is_err()
            {
                break;
            }
        }
    });
    // Several former per-terminal ticks fit inside this window; only the control stream should probe.
    let mut terminal_rx = Receive::default();
    let terminal_ping = tokio::time::timeout(Duration::from_millis(150), async {
        loop {
            if matches!(
                terminal_rx.next(&terminal).await.unwrap().frame,
                Frame::Ping { .. }
            ) {
                return true;
            }
        }
    })
    .await;
    assert!(
        terminal_ping.is_err(),
        "the terminal stream received its own liveness probe"
    );
    // Train the estimate on the healthy loopback host link: its allowance is the floor.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(connection.close_reason().is_none());

    // First miss: the window is told the host link is doubtful; it stays open.
    answer.store(false, Ordering::SeqCst);
    let silent = std::time::Instant::now();
    let notice = tokio::time::timeout(Duration::from_secs(2), output.recv())
        .await
        .expect("a missed reply must surface reconnecting");
    let doubted_after = silent.elapsed();
    assert!(
        matches!(notice, Some(TerminalOutput::LinkDoubt)),
        "unexpected first notice {notice:?}"
    );
    assert!(
        connection.close_reason().is_none(),
        "one missed reply retired the link after {doubted_after:?}: {:?}",
        connection.close_reason()
    );
    assert!(
        doubted_after >= Duration::from_millis(200),
        "doubt preceded the reply allowance: {doubted_after:?}"
    );

    // A reply inside the second allowance clears doubt on the same host link and
    // confirms the window again without a reattach.
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(connection.close_reason().is_none());
    answer.store(true, Ordering::SeqCst);
    let recovered = tokio::time::timeout(Duration::from_secs(1), output.recv())
        .await
        .expect("a reply must clear doubt");
    assert!(
        matches!(recovered, Some(TerminalOutput::Recovered)),
        "unexpected recovery notice {recovered:?}"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        connection.close_reason().is_none(),
        "a cleared doubt still retired the link: {:?}",
        connection.close_reason()
    );

    // Two consecutive misses retire the link.
    answer.store(false, Ordering::SeqCst);
    let silent = std::time::Instant::now();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), output.recv())
            .await
            .unwrap(),
        Some(TerminalOutput::LinkDoubt)
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), output.recv())
            .await
            .unwrap(),
        Some(TerminalOutput::Reconnecting)
    ));
    tokio::time::timeout(Duration::from_secs(3), connection.closed())
        .await
        .expect("a second consecutive miss must retire the link");
    let retired_after = silent.elapsed();
    eprintln!(
        "LIVENESS_DOUBT doubt_ms={} retire_ms={}",
        doubted_after.as_millis(),
        retired_after.as_millis()
    );
    assert!(
        retired_after >= Duration::from_millis(450),
        "the link retired on its first miss: {retired_after:?}"
    );
    responder.abort();
}

/// One shared control probe serves the maximum attached-terminal set and reports link death to each viewer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_host_probe_serves_128_terminals_without_route_probes() {
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
    let (_endpoint, connection, live) = connect_control(address, &node, &root).await;
    Transmit::default().send(&live, 0, &hello()).await.unwrap();
    let mut control = Receive::default();
    assert!(matches!(
        control.next(&live).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let binding = remote_quic::negotiate_binding(&connection, &hello()).unwrap();
    let actor = hosts.0.lock().await[&host_id].actor.clone();

    let answer = Arc::new(AtomicBool::new(true));
    let control_pings = Arc::new(AtomicUsize::new(0));
    let answering = answer.clone();
    let counted = control_pings.clone();
    let responder = tokio::spawn(async move {
        let mut transmit = Transmit::default();
        while let Ok(received) = control.next(&live).await {
            if let Frame::Ping { nonce, sent_us } = received.frame {
                counted.fetch_add(1, Ordering::SeqCst);
                if answering.load(Ordering::SeqCst)
                    && transmit
                        .send(&live, 0, &Frame::Pong { nonce, sent_us })
                        .await
                        .is_err()
                {
                    break;
                }
            }
        }
    });

    let limit = infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS;
    assert_eq!(limit, 128, "the regression covers the host stream ceiling");
    let mut terminals = Vec::with_capacity(limit);
    let mut outputs = Vec::with_capacity(limit);
    for index in 0..limit {
        let stream_id = 42 + 2 * u32::try_from(index).unwrap();
        let session_id = [u8::try_from(index + 1).unwrap(); 16];
        let attachment = tokio::time::timeout(
            Duration::from_secs(2),
            actor.attach(session_id, 0, 0, stream_id),
        )
        .await
        .expect("host actor should admit each bounded terminal")
        .unwrap();
        let terminal = NativeChannel::terminal(
            tokio::time::timeout(Duration::from_secs(2), remote_quic::accept_bound(&binding))
                .await
                .expect("agent should accept each terminal stream")
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            Receive::default().next(&terminal).await.unwrap().frame,
            Frame::AttachTerm { .. }
        ));
        Transmit::default()
            .send(&terminal, stream_id, &Frame::Ack { in_seq_acked: 0 })
            .await
            .unwrap();
        let (_input, output) = attachment.split();
        let mut output = output;
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), output.recv())
                .await
                .unwrap()
                .unwrap(),
            TerminalOutput::Ack { in_seq_acked: 0 }
        ));
        terminals.push(terminal);
        outputs.push(output);
    }

    // Let every route see several legacy 25 ms ticks while counting the one control-stream lease.
    let mut readers = tokio::task::JoinSet::new();
    for terminal in terminals {
        readers.spawn(async move {
            let mut receive = Receive::default();
            let saw_terminal_ping = tokio::time::timeout(Duration::from_millis(350), async {
                loop {
                    let received = receive.next(&terminal).await.unwrap();
                    if matches!(received.frame, Frame::Ping { .. }) {
                        return true;
                    }
                }
            })
            .await
            .unwrap_or(false);
            (terminal, saw_terminal_ping)
        });
    }
    let mut terminals = Vec::with_capacity(limit);
    while let Some(result) = readers.join_next().await {
        let (terminal, saw_terminal_ping) = result.unwrap();
        assert!(
            !saw_terminal_ping,
            "a terminal stream received a liveness probe"
        );
        terminals.push(terminal);
    }
    assert_eq!(terminals.len(), limit);
    assert!(
        control_pings.load(Ordering::SeqCst) >= 2,
        "the shared host link still probes on its control stream"
    );

    // A single missed host reply must notify every settled viewer; the second retires the link.
    answer.store(false, Ordering::SeqCst);
    let silent = std::time::Instant::now();
    for output in &mut outputs {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), output.recv())
                .await
                .expect("the host-link doubt must reach every terminal")
                .unwrap(),
            TerminalOutput::LinkDoubt
        ));
    }
    let doubted_after = silent.elapsed();
    assert!(
        (Duration::from_millis(200)..=Duration::from_millis(2200)).contains(&doubted_after),
        "first-miss notice fell outside D265's response bound: {doubted_after:?}"
    );
    for output in &mut outputs {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), output.recv())
                .await
                .expect("the second host-link miss must notify every terminal")
                .unwrap(),
            TerminalOutput::Reconnecting
        ));
    }
    tokio::time::timeout(Duration::from_secs(5), connection.closed())
        .await
        .expect("the second consecutive miss must retire the host link");
    let retired_after = silent.elapsed();
    assert!(
        (Duration::from_millis(450)..=Duration::from_millis(4200)).contains(&retired_after),
        "host-link retirement fell outside D300's two-allowance bound: {retired_after:?}"
    );
    eprintln!(
        "HOST_LINK_128 terminals={} control_pings={} doubt_ms={} retire_ms={}",
        limit,
        control_pings.load(Ordering::SeqCst),
        doubted_after.as_millis(),
        retired_after.as_millis()
    );
    drop(terminals);
    responder.abort();
}
