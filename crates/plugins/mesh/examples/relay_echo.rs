//! Key-echo measurement through real relayed pairs, without a `WireGuard` device (#201, J1105).
//!
//! One process is one end of a relayed pair. It runs the real [`RelayPaths`] (relay
//! connections, links, the path rule and its probes) but stands in for the engine with a
//! plain loopback UDP socket, so it needs no root, no interface and no kernel module, and
//! can run on shared hosts as well as inside throwaway namespaces. Relays come from
//! `relay_fixture relay`, certificates from `relay_fixture certs`.
//!
//! Input is one JSON line on stdin:
//! `{"host","peer","cert","key","ca","relays":[{"address","name"}],"role", ...}`.
//! - `"role":"echo"` sends every packet it receives back to its peer until stdin closes.
//! - `"role":"measure"` waits for a link, then sends `keys` keys `interval_ms` apart and prints
//!   one `key` line per echo (`rtt_us`, the relay in use), then `stats`; then stays silent for
//!   `idle_s` seconds and prints `idle` with the probe counters and this process's context
//!   switches over that window, and exits.
//!
//! Like a node, which relays a pair only after its direct-path grace period, each end first
//! waits (at most 10 s) until every relay connection is up, then asks for relaying.
//!
//! Every output line is one JSON object with `t_ms`, milliseconds since the process started.
//! A "key" is a 64-byte packet whose first byte is 4, the `WireGuard` data type, so the shim
//! treats it exactly like ciphertext.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_mesh::model::Addresses;
use infraternal_plugin_mesh::{
    dataplane,
    relay_path::{EndpointUpdater, Event, PairSecret, RelayPaths, RelaySpec, RouteMtuUpdater},
};
use infraternal_plugin_relay::{testing::credentials_from_pem, wire::HostId};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{self, BufRead, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

/// The process start, the zero of every printed `t_ms`.
static STARTED: OnceLock<Instant> = OnceLock::new();

/// Print one JSON line with the process-relative time.
fn say(mut line: Value) {
    let elapsed = STARTED.get_or_init(Instant::now).elapsed();
    line["t_ms"] = json!(elapsed.as_secs_f64() * 1000.0);
    let mut out = io::stdout().lock();
    writeln!(out, "{line}").unwrap();
    out.flush().unwrap();
}

/// The one input line.
#[derive(Deserialize)]
struct Config {
    host: String,
    peer: String,
    cert: String,
    key: String,
    ca: String,
    relays: Vec<RelayConfig>,
    role: String,
    #[serde(default = "default_keys")]
    keys: u64,
    #[serde(default = "default_interval")]
    interval_ms: u64,
    #[serde(default)]
    idle_s: u64,
}

/// One relay of the shared list.
#[derive(Deserialize)]
struct RelayConfig {
    address: SocketAddr,
    name: String,
}

/// Keys sent when the input names none.
fn default_keys() -> u64 {
    200
}

/// Milliseconds between keys when the input names none (10 keys a second).
fn default_interval() -> u64 {
    100
}

/// Stands in for the engine: every callback succeeds and changes nothing.
struct NoEngine;

impl EndpointUpdater for NoEngine {
    fn handshake_preparer(
        &self,
        _peer: &dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() -> io::Result<()> + Send + Sync>> {
        Ok(Arc::new(|| Ok(())))
    }

    fn handshake_starter(
        &self,
        _peer: &dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() + Send + Sync>> {
        Ok(Arc::new(|| {}))
    }

    fn route_mtu_updater(&self, _peer: &dataplane::Peer) -> RouteMtuUpdater {
        Arc::new(|_| Ok(()))
    }
}

/// Voluntary plus involuntary context switches of this whole process, from procfs.
fn context_switches() -> u64 {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return 0;
    };
    tasks
        .flatten()
        .filter_map(|task| std::fs::read_to_string(task.path().join("status")).ok())
        .flat_map(|status| {
            status
                .lines()
                .filter(|line| line.contains("ctxt_switches"))
                .filter_map(|line| line.split_whitespace().last()?.parse::<u64>().ok())
                .collect::<Vec<_>>()
        })
        .sum()
}

/// The path counters this tool reports, as JSON.
fn counters(paths: &RelayPaths, peer: HostId) -> Value {
    let stats = paths.stats();
    // head-only-begin: the probe counters and per-relay medians exist only with RTT ranking.
    let rtt: Vec<Option<f64>> = paths
        .rtt(peer)
        .into_iter()
        .map(|rtt| rtt.map(|rtt| rtt.as_secs_f64() * 1000.0))
        .collect();
    let ranked = json!({
        "probes_sent": stats.probes_sent,
        "probes_answered": stats.probes_answered,
        "probe_answers": stats.probe_answers,
        "switches": stats.switches,
        "rtt_ms": rtt,
    });
    // head-only-end
    json!({
        "sent": stats.sent,
        "received": stats.received,
        "unlinked": stats.unlinked,
        "active": paths.active(peer),
        "ranked": ranked,
    })
}

/// Read the configuration, run one end of the pair in its role, and print what it saw.
///
/// One thread, as a node's mesh component gives the shim (the same as `relay_fixture`).
#[tokio::main(flavor = "current_thread")]
async fn main() {
    STARTED.get_or_init(Instant::now);
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).unwrap();
    let config: Config = serde_json::from_str(&line).unwrap();
    let local = HostId::parse(&config.host).unwrap();
    let peer = HostId::parse(&config.peer).unwrap();

    let engine = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let wg_port = engine.local_addr().unwrap().port();
    let (events, mut event_queue) = tokio::sync::mpsc::channel(256);
    // No engine and no real mesh keys here: each end's pair secret is its host uuid twice,
    // and the peer's key is the public half of the peer's, so both ends derive one token.
    let pair_secret = |host: HostId| {
        let mut key = [0_u8; 32];
        key[..16].copy_from_slice(&host.0);
        key[16..].copy_from_slice(&host.0);
        PairSecret::from_private(&key).unwrap()
    };
    let peer_key = pair_secret(peer).public();
    let paths = RelayPaths::start(
        pair_secret(local),
        wg_port,
        config
            .relays
            .iter()
            .map(|relay| RelaySpec {
                address: relay.address,
                name: relay.name.clone(),
            })
            .collect(),
        credentials_from_pem(&config.cert, &config.key, &config.ca),
        events,
    )
    .unwrap();
    // A node asks for relaying only after a pair's direct-path grace period (seconds), by
    // which time every relay connection is up. Do the same: wait until each relay reported
    // up once (at most 10 s), so the run measures relay choice, not connection races.
    let (all_up, mut relays_up) = tokio::sync::watch::channel(0_usize);
    tokio::spawn(async move {
        let mut seen = std::collections::BTreeSet::new();
        while let Some(event) = event_queue.recv().await {
            if let Event::RelayUp { relay } = event {
                seen.insert(relay);
                let _ = all_up.send(seen.len());
            }
            say(match event {
                Event::RelayUp { relay } => json!({"event": "relay_up", "relay": relay}),
                Event::RelayDown { relay } => json!({"event": "relay_down", "relay": relay}),
                Event::Active { relay, .. } => json!({"event": "active", "relay": relay}),
            });
        }
    });
    let relay_count = config.relays.len();
    let _ = tokio::time::timeout(
        Duration::from_secs(10),
        relays_up.wait_for(|up| *up >= relay_count),
    )
    .await;
    let kernel = dataplane::Peer {
        key: peer_key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: Ipv4Addr::new(10, 254, 0, 2),
            ipv6: Ipv6Addr::LOCALHOST,
        },
        endpoint: None,
        candidates: Vec::new(),
        ipv4_only: false,
        side_port: false,
    };
    let shim = paths
        .relay_with_endpoint(&mut NoEngine, peer, &kernel)
        .await
        .unwrap();
    engine.connect(shim).await.unwrap();
    say(json!({"event": "ready", "role": config.role, "shim": shim}));
    let engine = Arc::new(engine);

    if config.role == "echo" {
        let echo = engine.clone();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1_500];
            while let Ok(length) = echo.recv(&mut buffer).await {
                let _ = echo.send(&buffer[..length]).await;
            }
        });
        // Echo until the driver closes stdin.
        tokio::task::spawn_blocking(|| {
            let mut sink = String::new();
            while io::stdin()
                .lock()
                .read_line(&mut sink)
                .is_ok_and(|read| read > 0)
            {
                sink.clear();
            }
        })
        .await
        .unwrap();
        say(json!({"event": "stats", "counters": counters(&paths, peer)}));
        paths.close().await;
        return;
    }

    // Measure: wait for a link, then time each key's echo.
    let linked = Instant::now();
    while paths.active(peer).is_none() {
        assert!(
            linked.elapsed() < Duration::from_secs(30),
            "no relay link in 30 s"
        );
        // sleep: polling the fixture's own link state; no event carries "linked" for one peer.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    say(json!({"event": "linked", "after_ms": linked.elapsed().as_secs_f64() * 1000.0}));
    let pending: Arc<Mutex<HashMap<u64, Instant>>> = Arc::default();
    let receiver = {
        let engine = engine.clone();
        let pending = pending.clone();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1_500];
            while let Ok(length) = engine.recv(&mut buffer).await {
                if length < 12 {
                    continue;
                }
                let sequence = u64::from_be_bytes(buffer[4..12].try_into().unwrap());
                if let Some(sent) = pending.lock().unwrap().remove(&sequence) {
                    let rtt = sent.elapsed();
                    say(json!({"event": "key", "seq": sequence, "rtt_us": rtt.as_micros()}));
                }
            }
        })
    };
    let mut ticker = tokio::time::interval(Duration::from_millis(config.interval_ms));
    let mut packet = [0_u8; 64];
    packet[0] = 4;
    for sequence in 0..config.keys {
        ticker.tick().await;
        packet[4..12].copy_from_slice(&sequence.to_be_bytes());
        pending.lock().unwrap().insert(sequence, Instant::now());
        engine.send(&packet).await.unwrap();
        if sequence % 50 == 49 {
            say(json!({"event": "progress", "seq": sequence, "relay": paths.active(peer)}));
        }
    }
    // sleep: let the last echoes arrive (2 s covers the slowest emulated path twice).
    tokio::time::sleep(Duration::from_secs(2)).await;
    let lost = pending.lock().unwrap().len();
    say(json!({"event": "stats", "lost": lost, "counters": counters(&paths, peer)}));
    if config.idle_s > 0 {
        let before = paths.stats();
        let switches = context_switches();
        // sleep: the idle window under test; nothing of ours sends during it.
        tokio::time::sleep(Duration::from_secs(config.idle_s)).await;
        let after = paths.stats();
        say(json!({
            "event": "idle",
            "seconds": config.idle_s,
            "context_switches": context_switches() - switches,
            "sent": after.sent - before.sent,
            "counters": counters(&paths, peer),
        }));
    }
    receiver.abort();
    paths.close().await;
}
