//! Break-it review round 2 of the D300 host-link doubt fixes (#234). Each test
//! names the claim it checks and drives `report_doubt` and `Liveness` as the
//! actor does on every tick.
use super::*;
use crate::liveness::{Liveness, TICK};
use std::collections::HashMap;

const CEILING: Duration = Duration::from_secs(2);

async fn settle(route: &mut Liveness, rtt: Duration, samples: usize) {
    for _ in 0..samples {
        let (nonce, stamp) = route.ping();
        tokio::time::advance(rtt).await;
        assert!(route.pong(nonce, stamp));
        tokio::time::advance(TICK).await;
    }
}

fn drain(rx: &mut mpsc::Receiver<TerminalOutput>) -> (usize, usize) {
    let (mut doubt, mut recovered) = (0, 0);
    while let Ok(output) = rx.try_recv() {
        match output {
            TerminalOutput::LinkDoubt => doubt += 1,
            TerminalOutput::Recovered => recovered += 1,
            _ => {}
        }
    }
    (doubt, recovered)
}

/// Claim: a browser that reconnects mid-doubt gets the indicator on its new
/// window and its recovery; the window that left is forgotten, not retried.
#[tokio::test(start_paused = true)]
async fn a_window_that_reconnects_mid_doubt_is_told_and_recovered() {
    let (old_tx, mut old_rx) = mpsc::channel(4);
    let mut attachments = HashMap::from([(1, attachment(old_tx))]);
    let mut route = Liveness::host_link();
    settle(&mut route, Duration::from_millis(1), 10).await;
    let (nonce, stamp) = route.ping();
    let mut doubted = Vec::new();
    while !route.doubtful() {
        tokio::time::advance(TICK).await;
        report_doubt(&mut route, &mut doubted, &attachments);
    }
    assert_eq!(drain(&mut old_rx), (1, 0));
    // The browser socket drops and reattaches: a new attachment id, first
    // awaiting its Ack (not settled), then settled.
    attachments.remove(&1);
    let (new_tx, mut new_rx) = mpsc::channel(4);
    let mut fresh = attachment(new_tx);
    fresh.awaiting_ack = true;
    attachments.insert(2, fresh);
    tokio::time::advance(TICK).await;
    report_doubt(&mut route, &mut doubted, &attachments);
    assert_eq!(
        drain(&mut new_rx),
        (0, 0),
        "an unsettled window is not told"
    );
    attachments.get_mut(&2).unwrap().awaiting_ack = false;
    tokio::time::advance(TICK).await;
    report_doubt(&mut route, &mut doubted, &attachments);
    assert_eq!(drain(&mut new_rx), (1, 0));
    assert!(route.pong(nonce, stamp));
    report_doubt(&mut route, &mut doubted, &attachments);
    assert_eq!(drain(&mut new_rx), (0, 1));
    assert_eq!(drain(&mut old_rx), (0, 0));
    assert!(doubted.is_empty(), "the departed window is not retried");
}

/// Claim: the per-tick retry is bounded per episode. Over a whole episode up
/// to retirement (80+ ticks) every window, full or not, gets exactly one
/// `LinkDoubt` and no `Recovered` (the link died).
#[tokio::test(start_paused = true)]
async fn doubt_retry_sends_one_notice_per_window_per_episode() {
    let mut receivers = Vec::new();
    let mut attachments = HashMap::new();
    for id in 1..=8u64 {
        let (tx, rx) = mpsc::channel(1);
        if id % 2 == 0 {
            tx.try_send(TerminalOutput::Ack { in_seq_acked: 0 })
                .unwrap();
        }
        attachments.insert(id, attachment(tx));
        receivers.push(rx);
    }
    let mut route = Liveness::host_link();
    settle(&mut route, Duration::from_millis(400), 40).await;
    route.ping();
    let mut doubted = Vec::new();
    let mut counts = vec![(0, 0); receivers.len()];
    let mut ticks = 0;
    while !route.retired() {
        tokio::time::advance(TICK).await;
        ticks += 1;
        report_doubt(&mut route, &mut doubted, &attachments);
        for (rx, count) in receivers.iter_mut().zip(&mut counts) {
            let (d, r) = drain(rx);
            count.0 += d;
            count.1 += r;
        }
    }
    assert!(ticks > 40, "the episode spans many ticks ({ticks})");
    assert!(counts.iter().all(|&c| c == (1, 0)), "{counts:?}");
}

/// Claim: the ceiling pin never delays retirement of a dead host past
/// 2 × 2 s after its last unanswered probe, and a pinned link raises no doubt.
#[tokio::test(start_paused = true)]
async fn a_pinned_dead_host_retires_within_two_ceilings_without_doubt() {
    let (tx, mut rx) = mpsc::channel(4);
    let attachments = HashMap::from([(1, attachment(tx))]);
    let mut route = Liveness::host_link();
    settle(&mut route, Duration::from_millis(1500), 20).await;
    // Pin: one doubt recovered at the ceiling.
    let (nonce, stamp) = route.ping();
    let mut doubted = Vec::new();
    tokio::time::advance(CEILING + Duration::from_millis(1)).await;
    report_doubt(&mut route, &mut doubted, &attachments);
    tokio::time::advance(Duration::from_millis(500)).await;
    assert!(route.pong(nonce, stamp));
    report_doubt(&mut route, &mut doubted, &attachments);
    assert_eq!(drain(&mut rx), (1, 1));
    // The host dies. The actor keeps probing every tick while one is outstanding.
    let died = tokio::time::Instant::now();
    route.ping();
    while !route.retired() {
        tokio::time::advance(TICK).await;
        route.ping();
        report_doubt(&mut route, &mut doubted, &attachments);
        assert!(died.elapsed() <= CEILING * 2 + TICK, "retired late");
    }
    assert_eq!(
        drain(&mut rx),
        (0, 0),
        "a pinned link reports only retirement"
    );
}
