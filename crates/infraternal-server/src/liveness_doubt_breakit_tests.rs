//! Break-it review of D300 host-link doubt (#234): each test states a claim of
//! the branch and drives the shipped code until the claim fails.
use super::*;
use crate::liveness::Liveness;
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SESSION: [u8; 16] = [9; 16];
const STREAM: u32 = 42;

/// Fixture host on one already-greeted Unix socket. It answers primary Pings
/// while `answer` is set and Acks every `AttachTerm`; it never sends a replay
/// fence on its own, so the test decides when a replacement replay ends.
fn fixture_host(
    peer: UnixStream,
    answer: Arc<AtomicBool>,
) -> (
    mpsc::UnboundedReceiver<u32>,
    tokio::sync::oneshot::Sender<Vec<u8>>,
) {
    let (attach_seen, attach_log) = mpsc::unbounded_channel();
    let (fence, fence_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut reader, mut writer) = peer.into_split();
        let mut fence_rx = Some(fence_rx);
        let mut buffer = BytesMut::new();
        let mut wire = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            tokio::select! {
                read = reader.read(&mut chunk) => {
                    let Ok(count) = read else { return };
                    if count == 0 { return; }
                    buffer.extend_from_slice(&chunk[..count]);
                    while let Ok(decoded) = decode_muxed_frame(&buffer) {
                        let (reply, size) = {
                                let reply = match decoded.frame {
                                    Frame::Ping { nonce, sent_us } if decoded.stream_id == 0 => answer
                                        .load(Ordering::SeqCst)
                                        .then_some((0, Frame::Pong { nonce, sent_us })),
                                    Frame::AttachTerm { .. } => {
                                        let _ = attach_seen.send(decoded.stream_id);
                                        Some((decoded.stream_id, Frame::Ack { in_seq_acked: 0 }))
                                    }
                                    _ => None,
                                };
                                (reply, decoded.wire_len)
                        };
                        let _ = buffer.split_to(size);
                        if let Some((stream, frame)) = reply {
                            encode_muxed_frame_into(stream, &frame, &mut wire).unwrap();
                            if writer.write_all(&wire).await.is_err() { return; }
                        }
                    }
                }
                event = async { fence_rx.as_mut().unwrap().await }, if fence_rx.is_some() => {
                    fence_rx = None;
                    let Ok(event_json) = event else { continue };
                    encode_muxed_frame_into(STREAM, &Frame::Event { sub_id: 0, event_json: &event_json }, &mut wire).unwrap();
                    if writer.write_all(&wire).await.is_err() { return; }
                }
            }
        }
    });
    (attach_log, fence)
}

/// Claim: "a reply → Recovered to exactly those windows" (D300, b01f1e326).
/// The doubted window list outlives the link it was recorded on. After the
/// doubted link retires and a replacement reattaches, the replacement's fresh
/// lease is "not doubtful", so the next tick confirms the stale list on the
/// new link as soon as the reattach Ack lands, while the host is still
/// replaying. The browser treats that as the replay fence: it stops
/// suppressing terminal responses for the rest of the replay (replayed
/// queries are answered again into the shell) and clears "Catching up…" early.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_doubt_never_confirms_a_replacement_link_mid_replay() {
    let (link_a, peer_a) = connection();
    let (link_b, peer_b) = connection();
    let answer_a = Arc::new(AtomicBool::new(true));
    let (mut attaches_a, _fence_a) = fixture_host(peer_a, answer_a.clone());
    let (mut attaches_b, fence_b) = fixture_host(peer_b, Arc::new(AtomicBool::new(true)));

    let (attempts, _attempts) = mpsc::unbounded_channel();
    let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
    #[cfg(feature = "remote")]
    let (cleanup, cleanup_rx) = mpsc::unbounded_channel();
    let (changes, notice) = watch::channel(());
    let (inventory, _snapshot) = watch::channel(SessionInventoryState::Pending);
    tokio::spawn(run_actor(
        Source::Fixture {
            connections: std::collections::VecDeque::from([link_a, link_b]),
            attempts,
        },
        receiver,
        #[cfg(feature = "remote")]
        cleanup_rx,
        changes,
        inventory.clone(),
    ));
    let agent = EmbeddedAgent {
        commands,
        #[cfg(feature = "remote")]
        cleanup,
        changes: notice,
        next_attachment_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        session_inventory: inventory,
    };
    let attachment = agent.attach(SESSION, 0, 0, STREAM).await.unwrap();
    let (_input, mut output) = attachment.split();
    tokio::time::timeout(Duration::from_secs(2), attaches_a.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), output.recv())
            .await
            .unwrap(),
        Some(TerminalOutput::Ack { in_seq_acked: 0 })
    ));
    // Prove the loopback link: its allowance settles at the 250 ms floor.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Silence: first miss → LinkDoubt (link kept), second miss → retire.
    answer_a.store(false, Ordering::SeqCst);
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

    // The replacement reattaches and Acks; its replay is still in progress.
    tokio::time::timeout(Duration::from_secs(3), attaches_b.recv())
        .await
        .expect("the actor reattaches on the replacement link")
        .unwrap();
    let mut seen = Vec::new();
    let replay_window = tokio::time::Instant::now() + Duration::from_millis(300);
    while let Ok(Some(item)) = tokio::time::timeout_at(replay_window, output.recv()).await {
        seen.push(format!("{item:?}"));
        assert!(
            !matches!(item, TerminalOutput::Recovered),
            "a doubt recorded on the retired link confirmed the replacement \
             before its replay fence; notices so far: {seen:?}"
        );
    }
    // The host's own fence still reaches the window.
    let session = uuid::Uuid::from_bytes(SESSION).to_string();
    fence_b
        .send(
            format!(
                r#"{{"type":"terminal.replay_complete","session_id":"{session}","out_seq":"0"}}"#
            )
            .into_bytes(),
        )
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), output.recv())
            .await
            .unwrap(),
        Some(TerminalOutput::Event { .. })
    ));
}

/// Settle `route` on one constant round trip under a paused clock.
async fn settle(route: &mut Liveness, rtt: Duration, samples: usize) -> usize {
    let mut accepted = 0;
    for _ in 0..samples {
        let (nonce, stamp) = route.ping();
        tokio::time::advance(rtt).await;
        if route.pong(nonce, stamp) {
            accepted += 1;
        }
        tokio::time::advance(crate::liveness::TICK).await;
    }
    accepted
}

/// Claim: "second consecutive miss → retire" and a doubt marks a real miss.
/// A proven link whose path queues up gradually (an uplink filling a deep
/// buffer) reaches the 2 s ceiling. From there every reply that takes 2–4 s
/// lands after the first allowance and inside the second: each probe raises
/// a doubt that its own reply clears, forever. Windows flip Reconnecting /
/// Recovered on every probe (input held, terminal responses suppressed) and
/// the link is never retired either; the estimator cannot widen past 2 s.
#[tokio::test(start_paused = true)]
async fn queued_path_at_the_ceiling_does_not_flap_doubt_every_probe() {
    let mut route = Liveness::host_link();
    settle(&mut route, Duration::from_millis(300), 20).await;
    // Ramp the round trip 300 ms -> 2.5 s; every reply is accepted.
    for step in 1..=22_u64 {
        let rtt = Duration::from_millis(300 + step * 100);
        assert_eq!(settle(&mut route, rtt, 1).await, 1, "ramp lost {rtt:?}");
    }
    let rtt = Duration::from_millis(2500);
    let mut episodes = 0;
    for _ in 0..10 {
        let (nonce, stamp) = route.ping();
        let sent = tokio::time::Instant::now();
        // The actor evaluates doubt on each 25 ms tick until the reply lands.
        while sent.elapsed() < rtt {
            tokio::time::advance(crate::liveness::TICK).await;
            if route.doubt_started() {
                episodes += 1;
            }
        }
        assert!(
            route.pong(nonce, stamp),
            "the reply is inside the second allowance"
        );
        tokio::time::advance(crate::liveness::TICK).await;
    }
    assert!(
        episodes <= 1,
        "a steady {rtt:?} host link raised {episodes} doubt episodes in 10 probes and never retired"
    );
}

/// Evidence (passes): a host link settled at the 2 s ceiling still retires a
/// dead host within two ceilings (4 s) of its last proof.
#[tokio::test(start_paused = true)]
async fn inflated_host_link_still_retires_a_dead_host_within_four_seconds() {
    // Dead from here: measure from the last proof to retirement.
    let mut route = Liveness::host_link();
    settle(&mut route, Duration::from_millis(1900), 30).await;
    route.ping();
    let silent = tokio::time::Instant::now();
    while !route.retired() {
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    let detected = silent.elapsed();
    eprintln!("DEAD_HOST_WORST retire_ms={}", detected.as_millis());
    assert!(detected <= Duration::from_millis(4001), "{detected:?}");
}

/// Numbers for the review (passes): when doubt starts and when the link
/// retires on a settled path, per RTT.
#[tokio::test(start_paused = true)]
async fn doubt_and_retire_times_per_rtt() {
    for rtt_ms in [1_u64, 30, 150, 300, 600, 1000] {
        let mut route = Liveness::host_link();
        settle(&mut route, Duration::from_millis(rtt_ms), 100).await;
        route.ping();
        let silent = tokio::time::Instant::now();
        let mut doubt = None;
        while !route.retired() {
            tokio::time::advance(Duration::from_millis(1)).await;
            if doubt.is_none() && route.doubt_started() {
                doubt = Some(silent.elapsed());
            }
        }
        eprintln!(
            "D300_TIMES rtt_ms={rtt_ms} doubt_ms={} retire_ms={}",
            doubt.unwrap_or_default().as_millis(),
            silent.elapsed().as_millis()
        );
    }
}

/// Claim (P3-2): "a full window is told on a later tick". A window whose
/// queue is full when the doubt begins still gets `LinkDoubt` once it has
/// room, and then its recovery; a window never told gets no recovery.
#[tokio::test(start_paused = true)]
async fn a_window_full_at_doubt_start_is_told_on_a_later_tick() {
    let (full_tx, mut full_rx) = mpsc::channel(1);
    full_tx
        .try_send(TerminalOutput::Ack { in_seq_acked: 0 })
        .unwrap();
    let (free_tx, mut free_rx) = mpsc::channel(4);
    let attachments = HashMap::from([(1, attachment(full_tx)), (2, attachment(free_tx))]);
    let mut route = Liveness::host_link();
    settle(&mut route, Duration::from_millis(1), 10).await;
    let (nonce, stamp) = route.ping();
    let mut doubted = Vec::new();
    while !route.doubtful() {
        tokio::time::advance(crate::liveness::TICK).await;
        report_doubt(&mut route, &mut doubted, &attachments);
    }
    assert!(matches!(free_rx.try_recv(), Ok(TerminalOutput::LinkDoubt)));
    assert_eq!(doubted, vec![2], "the full window is not told yet");
    // The full window drains; the next tick of the same episode tells it.
    assert!(matches!(full_rx.try_recv(), Ok(TerminalOutput::Ack { .. })));
    tokio::time::advance(crate::liveness::TICK).await;
    report_doubt(&mut route, &mut doubted, &attachments);
    assert!(matches!(full_rx.try_recv(), Ok(TerminalOutput::LinkDoubt)));
    assert!(free_rx.try_recv().is_err(), "a told window is told once");
    // The reply clears doubt; both told windows get their recovery.
    assert!(route.pong(nonce, stamp));
    report_doubt(&mut route, &mut doubted, &attachments);
    assert!(matches!(full_rx.try_recv(), Ok(TerminalOutput::Recovered)));
    assert!(matches!(free_rx.try_recv(), Ok(TerminalOutput::Recovered)));
    assert_eq!(doubted, Vec::<u64>::new());
}
