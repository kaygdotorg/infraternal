//! Measures transport timer cost with 1,000 real mutually authenticated idle QUIC connections; this is not a 1,000-daemon proof [215].
use super::*;
use crate::remote_client::dial_runtime::DialRuntime;

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
#[ignore = "Release-only local CPUWeight=10000 timer measurement; run without concurrent builds."]
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
    let idle_ms = interval("INFRATERNAL_MESH_IDLE_MS", 5000);
    let join_concurrency = interval("INFRATERNAL_MESH_JOIN_CONCURRENCY", 8);
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
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (before_ticks, resident_pages) = usage();
    let before_packets = connections
        .iter()
        .map(|connection| connection.stats().udp_tx.datagrams)
        .sum::<u64>();
    let start = tokio::time::Instant::now();
    let mut freshness: Vec<_> = connections
        .iter()
        .map(remote_quic::PeerFreshness::new)
        .collect();
    let mut max_silence = Duration::ZERO;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        for (connection, guard) in connections.iter().zip(&mut freshness) {
            max_silence = max_silence.max(guard.silence(connection));
        }
    }
    let (after_ticks, _) = usage();
    let after_packets = connections
        .iter()
        .map(|connection| connection.stats().udp_tx.datagrams)
        .sum::<u64>();
    let alive = connections
        .iter()
        .filter(|connection| connection.close_reason().is_none())
        .count();
    assert_eq!(alive, 1000, "idle transport must stay live at scale");
    let elapsed_us = start.elapsed().as_micros();
    let report = serde_json::json!({"machine":"infraternal-dev","profile":"transport_only","connections":1000,"client_endpoints":1000,"join_concurrency":join_concurrency,"live":alive,"window_us":elapsed_us,"max_authenticated_silence_us":max_silence.as_micros(),"cpu_ticks":after_ticks-before_ticks,"clock_ticks_per_second":clock_ticks,"setup_cpu_ticks":before_ticks-baseline_ticks,"resident_delta_bytes":resident_pages.saturating_sub(baseline_pages)*page_size,"timer_datagrams":after_packets-before_packets,"keepalive_ms":keepalive_ms,"idle_ms":idle_ms,"load":std::fs::read_to_string("/proc/loadavg").unwrap().trim()});
    let scratch = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".cache/codex-scratch/mesh-agent-transport");
    std::fs::write(
        scratch.join(format!(
            "mesh-idle-authenticated-1000-{keepalive_ms}-{idle_ms}.json"
        )),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "METRIC mesh_idle connections=1000 live={alive} cpu_ticks={} packets={} window_us={elapsed_us} result=PASS",
        after_ticks - before_ticks,
        after_packets - before_packets
    );
    for client in clients {
        client.close(0_u32.into(), b"");
    }
    server.close(0_u32.into(), b"");
    drop((connections, accepted, drivers));
}
