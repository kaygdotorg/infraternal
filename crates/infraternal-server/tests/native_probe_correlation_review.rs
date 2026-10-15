//! Native route correlation and healthy-socket scheduling regressions [D265, #199].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

// Exercise the shipping implementation rather than a second liveness model.
#[path = "../src/liveness.rs"]
mod liveness;

use std::time::Duration;

#[tokio::test(start_paused = true)]
async fn unissued_native_probe_reply_cannot_extend_readiness() {
    let mut route = liveness::Liveness::new();
    let (nonce, stamp) = route.ping();
    tokio::time::advance(Duration::from_millis(1)).await;
    route.pong(nonce, stamp);
    tokio::time::advance(Duration::from_millis(24)).await;
    let (first, _) = route.ping();
    tokio::time::advance(Duration::from_millis(25)).await;
    let (second, _) = route.ping();
    let unissued = first + (second - first) / 2;
    assert!(first < unissued && unissued < second);
    tokio::time::advance(Duration::from_millis(10)).await;
    let deadline = route.response_deadline().unwrap();
    assert!(!route.pong(unissued, unissued));
    assert_eq!(route.response_deadline(), Some(deadline));
    // Unissued replies cannot renew the original outstanding deadline, including
    // its scheduling floor. Paused time checks correlation, never host latency.
    tokio::time::advance(deadline - tokio::time::Instant::now()).await;
    assert!(route.expired(), "an unissued reply retained readiness");
}

/// Real peer I/O continues while the server's scheduling turn is held. Run this
/// same oracle pinned alongside bounded CPU stress on the perf VM as well.
#[tokio::test]
async fn healthy_real_socket_survives_a_150ms_server_stall() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let (mut server, mut peer) = UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let peer = std::thread::spawn(move || {
        for _ in 0..2 {
            let mut proof = [0; 16];
            peer.read_exact(&mut proof).unwrap();
            peer.write_all(&proof).unwrap();
        }
    });
    let mut route = liveness::Liveness::answer_paced();
    for stalled in [false, true] {
        let started = std::time::Instant::now();
        let (nonce, stamp) = route.ping();
        let mut proof = [0; 16];
        proof[..8].copy_from_slice(&nonce.to_le_bytes());
        proof[8..].copy_from_slice(&stamp.to_le_bytes());
        server.write_all(&proof).unwrap();
        if stalled {
            std::thread::sleep(Duration::from_millis(150));
        }
        server.read_exact(&mut proof).unwrap();
        let nonce = u64::from_le_bytes(proof[..8].try_into().unwrap());
        let stamp = u64::from_le_bytes(proof[8..].try_into().unwrap());
        assert!(
            route.pong(nonce, stamp),
            "healthy socket retired after local stall"
        );
        assert!(!route.expired());
        println!(
            "METRIC healthy_socket stalled={stalled} reply_us={}",
            started.elapsed().as_micros()
        );
    }
    peer.join().unwrap();
}
