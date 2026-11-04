//! A missed primary reply only marks the host link doubtful; the second consecutive miss retires it [D300], #234.
use super::*;
use crate::embedded::TerminalOutput;
use std::sync::atomic::{AtomicBool, Ordering};

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
    // Train the estimate on a healthy loopback route: its allowance is the floor.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(connection.close_reason().is_none());

    // First miss: the window is told the route is doubtful; the link stays.
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

    // A reply inside the second allowance clears doubt on the same link and
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
