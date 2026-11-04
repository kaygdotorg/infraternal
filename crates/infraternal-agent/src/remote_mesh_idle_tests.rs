//! Measures transport timer cost with 1,000 real mutually authenticated idle QUIC connections; this is not a 1,000-daemon proof [215].
use super::*;
use crate::remote_client::dial_runtime::DialRuntime;

/// Bounds diagnostic storage while retaining the authenticated arrival spread.
#[derive(Default)]
struct SampledGaps {
    count: u64,
    total_us: u128,
    squared_us: u128,
    maximum_us: u128,
    histogram_25ms: [u64; 32],
}
impl SampledGaps {
    fn observe(&mut self, gap: Duration) {
        let micros = gap.as_micros();
        self.count += 1;
        self.total_us += micros;
        self.squared_us += micros * micros;
        self.maximum_us = self.maximum_us.max(micros);
        self.histogram_25ms[usize::try_from(gap.as_millis() / 25).unwrap_or(31).min(31)] += 1;
    }
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"count":self.count,"total_us":self.total_us,"squared_us":self.squared_us,"maximum_us":self.maximum_us,"histogram_25ms":self.histogram_25ms})
    }
}

fn usage() -> (u64, u64) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let ticks = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    let resident = std::fs::read_to_string("/proc/self/statm")
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    (ticks, resident)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Release-only perf VM measurement under the shared benchmark lock."]
// Keep setup, sampling and teardown together so driver lifetimes match the measured cohort.
#[allow(clippy::too_many_lines)]
async fn mesh_idle_timer_cost_at_one_thousand_connections() {
    let ca = root();
    let system_unit = |name| {
        std::str::from_utf8(
            &std::process::Command::new("getconf")
                .arg(name)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .parse::<u64>()
        .unwrap()
    };
    let clock_ticks = system_unit("CLK_TCK");
    let page_size = system_unit("PAGESIZE");
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    let server = quinn::Endpoint::server(
        remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let listener = server.clone();
    let accepting = tokio::spawn(async move {
        let mut handshakes = tokio::task::JoinSet::new();
        let mut connections = Vec::new();
        while connections.len() < 1000 {
            tokio::select! {
                incoming = listener.accept(), if handshakes.len() < 64 => {
                    handshakes.spawn(async move { incoming.unwrap().await.unwrap() });
                }
                result = handshakes.join_next(), if !handshakes.is_empty() => { connections.push(result.unwrap().unwrap()); }
            }
        }
        connections
    });
    let interval =
        |name, default| std::env::var(name).map_or(default, |value| value.parse::<u64>().unwrap());
    let keepalive_ms = interval("INFRATERNAL_MESH_KEEPALIVE_MS", 100);
    let idle_ms = interval("INFRATERNAL_MESH_IDLE_MS", 60000);
    let join_concurrency = interval("INFRATERNAL_MESH_JOIN_CONCURRENCY", 8);
    let samples = interval("INFRATERNAL_MESH_IDLE_SAMPLES", 320);
    assert!((40..=1200).contains(&samples));
    let guarded = std::env::var("INFRATERNAL_MESH_GUARDED").ok().as_deref() != Some("0");
    assert!((1..=64).contains(&join_concurrency));
    let config = remote_quic::client_config_with_liveness(
        &client_identity,
        std::slice::from_ref(&ca.certificate),
        Duration::from_millis(keepalive_ms),
        Duration::from_millis(idle_ms),
    )
    .unwrap();
    let (baseline_ticks, baseline_pages) = usage();
    let mut dialing = tokio::task::JoinSet::new();
    let mut connections = Vec::new();
    let mut clients = Vec::new();
    let mut drivers = Vec::new();
    for _ in 0..1000 {
        let driver = DialRuntime::new();
        let mut client = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            driver.runtime(),
        )
        .unwrap();
        client.set_default_client_config(config.clone());
        let pending = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        clients.push(client);
        drivers.push(driver);
        dialing.spawn(async move { pending.await.unwrap() });
        if dialing.len() as u64 >= join_concurrency {
            connections.push(dialing.join_next().await.unwrap().unwrap());
        }
    }
    while let Some(connection) = dialing.join_next().await {
        connections.push(connection.unwrap());
    }
    let accepted = accepting.await.unwrap();
    // Each established path gets the same owned watcher as the supervisor.
    // Bulk observation below additionally bounds silence, so CPU includes that
    // diagnostic overhead rather than understating scheduler work at scale.
    let mut watchers = tokio::task::JoinSet::new();
    for connection in connections.iter().filter(|_| guarded) {
        let connection = connection.clone();
        watchers.spawn(async move {
            let started = tokio::time::Instant::now();
            let initial_ping = connection.stats().frame_tx.ping;
            let mut guard = remote_quic::PeerFreshness::new(&connection);
            let mut watched = std::pin::pin!(guard.interrupted_adaptive(&connection));
            let mut last_poll = tokio::time::Instant::now();
            let mut max_poll_gap = Duration::ZERO;
            let mut sampled_peer = remote_quic::PeerFreshness::new(&connection);
            let mut last_arrival = last_poll;
            let mut sampled_gaps = SampledGaps::default();
            // Observe the real guard rather than replacing it with diagnostic
            // polling: a delayed executor wake must remain distinguishable
            // from a peer that never returned an authenticated packet.
            let result = std::future::poll_fn(|context| {
                let now = tokio::time::Instant::now();
                max_poll_gap = max_poll_gap.max(now.duration_since(last_poll));
                last_poll = now;
                // A separate production observer adds one diagnostic stats
                // snapshot per poll. These are sampled authenticated gaps,
                // not packet timestamps or unauthenticated UDP arrivals.
                if sampled_peer.observe_change(&connection) {
                    sampled_gaps.observe(now.duration_since(last_arrival));
                    last_arrival = now;
                }
                std::future::Future::poll(watched.as_mut(), context)
            })
            .await;
            (
                result,
                connection.stats(),
                max_poll_gap,
                started.elapsed(),
                initial_ping,
                sampled_gaps,
            )
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (before_ticks, resident_pages) = usage();
    let before_packets = connections
        .iter()
        .map(|connection| connection.stats().udp_tx.datagrams)
        .sum::<u64>();
    let before_wire_bytes = connections
        .iter()
        .map(|connection| connection.stats().udp_tx.bytes)
        .sum::<u64>();
    let load_before = std::fs::read_to_string("/proc/loadavg").unwrap();
    let start = tokio::time::Instant::now();
    let mut freshness: Vec<_> = connections
        .iter()
        .map(remote_quic::PeerFreshness::new)
        .collect();
    let mut max_silence = Duration::ZERO;
    let mut previous_observation = tokio::time::Instant::now();
    let mut max_observation_gap = Duration::ZERO;
    for _ in 0..samples {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let observed = tokio::time::Instant::now();
        max_observation_gap =
            max_observation_gap.max(observed.duration_since(previous_observation));
        previous_observation = observed;
        for (connection, guard) in connections.iter().zip(&mut freshness) {
            max_silence = max_silence.max(guard.silence(connection));
        }
    }
    let (after_ticks, _) = usage();
    let after_packets = connections
        .iter()
        .map(|connection| connection.stats().udp_tx.datagrams)
        .sum::<u64>();
    // Preserve every completed guard result before the healthy assertion. A
    // false interruption must retain evidence rather than erase its scale run.
    let (mut false_interruptions, mut timeout_interruptions, mut closed_interruptions) = (0, 0, 0);
    let (mut other_interruptions, mut watcher_join_errors, mut unexpected_completions) = (0, 0, 0);
    let mut timeout_paths = Vec::new();
    while let Some(result) = watchers.try_join_next() {
        false_interruptions += 1;
        match result {
            Ok((Err(error), stats, poll_gap, lifetime, initial_ping, gaps))
                if error.kind() == std::io::ErrorKind::TimedOut =>
            {
                timeout_interruptions += 1;
                timeout_paths.push(serde_json::json!({"rtt_us":stats.path.rtt.as_micros(),"min_rtt_us":stats.path.min_rtt.as_micros(),"lost_packets":stats.path.lost_packets,"guard_max_poll_gap_us":poll_gap.as_micros(),"guard_lifetime_us":lifetime.as_micros(),"tx_ping_initial":initial_ping,"tx_ping":stats.frame_tx.ping,"rx_ping":stats.frame_rx.ping,"rx_acks":stats.frame_rx.acks,"sampled_authenticated_gaps":gaps.json()}));
            }
            Ok((Err(error), _, _, _, _, _)) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                closed_interruptions += 1;
            }
            Ok((Err(_), _, _, _, _, _)) => other_interruptions += 1,
            Ok((Ok(()), _, _, _, _, _)) => unexpected_completions += 1,
            Err(_) => watcher_join_errors += 1,
        }
    }
    let after_wire_bytes = connections
        .iter()
        .map(|connection| connection.stats().udp_tx.bytes)
        .sum::<u64>();
    let alive = connections
        .iter()
        .filter(|connection| connection.close_reason().is_none())
        .count();
    let elapsed_us = start.elapsed().as_micros();
    let mut report = serde_json::json!({"machine":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),"profile":"transport_only","connections":1000,"freshness_watcher_tasks":if guarded { 1000 } else { 0 },"freshness_state_bytes":std::mem::size_of::<remote_quic::PeerFreshness>(),"timer_udp_payload_bytes":after_wire_bytes-before_wire_bytes,"client_endpoints":1000,"join_concurrency":join_concurrency,"live":alive,"window_us":elapsed_us,"max_authenticated_silence_us":max_silence.as_micros(),"cpu_ticks":after_ticks-before_ticks,"clock_ticks_per_second":clock_ticks,"setup_cpu_ticks":before_ticks-baseline_ticks,"resident_delta_bytes":resident_pages.saturating_sub(baseline_pages)*page_size,"timer_datagrams":after_packets-before_packets,"keepalive_ms":keepalive_ms,"idle_ms":idle_ms,"load_before":load_before.trim(),"load":std::fs::read_to_string("/proc/loadavg").unwrap().trim()});
    let healthy = false_interruptions == 0 && alive == 1000;
    report["freshness_profile"] = if guarded {
        "adaptive_current_rtt_plus_200ms"
    } else {
        "unguarded"
    }
    .into();
    report["freshness_observation_interval_ms"] = serde_json::json!(if guarded { 50 } else { 0 });
    report["false_interruptions"] = serde_json::json!(false_interruptions);
    report["max_bulk_observation_gap_us"] = serde_json::json!(max_observation_gap.as_micros());
    report["timeout_paths"] = serde_json::json!(timeout_paths);
    report["diagnostic_extra_authenticated_snapshot_per_guard_poll"] = true.into();
    report["freshness_watcher_tasks_remaining"] = serde_json::json!(watchers.len());
    report["timeout_interruptions"] = serde_json::json!(timeout_interruptions);
    report["closed_interruptions"] = serde_json::json!(closed_interruptions);
    report["other_interruptions"] = serde_json::json!(other_interruptions);
    report["watcher_join_errors"] = serde_json::json!(watcher_join_errors);
    report["unexpected_watcher_completions"] = serde_json::json!(unexpected_completions);
    report["result"] = if healthy { "PASS" } else { "FAIL" }.into();
    let scratch = std::env::var_os("INFRATERNAL_MESH_PROOF_SCRATCH").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/mesh-agent-transport-round2")
        },
        PathBuf::from,
    );
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(
        scratch.join(format!(
            "mesh-idle-guarded-{guarded}-1000-{keepalive_ms}-{idle_ms}.json"
        )),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "METRIC mesh_idle connections=1000 live={alive} false_interruptions={false_interruptions} cpu_ticks={} packets={} window_us={elapsed_us} result={}",
        after_ticks - before_ticks,
        after_packets - before_packets,
        if healthy { "PASS" } else { "FAIL" }
    );
    assert_eq!(
        false_interruptions, 0,
        "healthy authenticated watchers must stay live at scale"
    );
    assert_eq!(alive, 1000, "idle transport must stay live at scale");
    watchers.abort_all();
    while watchers.join_next().await.is_some() {}
    for client in clients {
        client.close(0_u32.into(), b"");
    }
    server.close(0_u32.into(), b"");
    drop((connections, accepted, drivers));
}

#[cfg(target_os = "linux")]
#[path = "remote_mesh_copy_cost_tests.rs"]
mod copy_cost;
