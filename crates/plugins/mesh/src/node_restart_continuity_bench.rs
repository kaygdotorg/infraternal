//! Measures how a coordinator restart affects live mesh traffic on one node (#382 P2-c, D166).
//!
//! Every coordinator process announces a fresh authority epoch, so a plain
//! server restart sends each node a complete snapshot under a new epoch, even
//! when nothing in the policy changed. This module times that hand-over with
//! real packets flowing, so the cost of a restart is a number instead of a
//! guess.
//!
//! The harness has two halves, both `#[ignore]`d because they need root and a
//! private network namespace:
//!
//! - [`restart_continuity_same_content_snapshot`] is the measured node. It runs
//!   a [`Node`] with [`PEERS`] peers in its snapshot, one of them live.
//! - [`restart_continuity_peer`] is the live peer. The measured node starts it
//!   inside a sibling network namespace joined by a veth pair. It sends one
//!   numbered UDP datagram every millisecond through the tunnel.
//!
//! In the middle of the stream, the measured node receives the same snapshot
//! under a new epoch, exactly what a restarted coordinator sends. The result
//! line reports:
//! - how long the swap took;
//! - datagrams lost, overall and after the swap began;
//! - the longest gap between arrivals, before and around the swap;
//! - the live peer's handshake time and receive counter before and after.
//!
//! A receive counter that drops, or a new handshake, means the swap removed
//! and recreated the peer, so its WireGuard session was cut.
//!
//! Run one trial per engine, as root, for example:
//! `unshare -n env RESTART_BENCH_ENGINE=kernel <test binary> --exact
//! node::restart_continuity_bench::restart_continuity_same_content_snapshot
//! --ignored --nocapture`. Set `RESTART_BENCH_OUT` to also write the result as
//! one JSON line. The module only reports. It asserts that traffic flowed
//! before the swap, so that a broken setup cannot pass for a clean result. It
//! never asserts on the measured numbers: the same file also runs against the
//! code from before the staged swap as the comparison point.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
use super::*;
use crate::{
    dataplane::{DefaultPolicy, Peer, PeerPolicy},
    policy::model::{Addresses, NodeId, PublicKey},
};
use std::{
    net::UdpSocket,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// The epoch of the coordinator process before the restart.
const EPOCH_BEFORE: &str = "00000000-0000-4000-8000-0000000002c1";
/// The epoch the restarted coordinator announces.
const EPOCH_AFTER: &str = "00000000-0000-4000-8000-0000000002c2";
/// Peers in the measured node's snapshot: one live peer plus idle ones, so the
/// swap handles a realistic peer list, not a single entry.
const PEERS: u32 = 64;
/// The UDP port the measured node listens on for the numbered stream.
const STREAM_PORT: u16 = 5547;
/// How often the live peer sends a datagram. One millisecond gives
/// millisecond resolution for gaps.
const SEND_INTERVAL: Duration = Duration::from_millis(1);
/// How long traffic flows before the swap, so the session is settled.
const WARM_UP: Duration = Duration::from_secs(2);
/// How long traffic keeps flowing after the swap, to catch a late re-handshake.
const COOL_DOWN: Duration = Duration::from_secs(3);
/// The measured node's mesh address. The peer's stream is sent here.
const MEASURED_IPV4: &str = "10.254.0.1";
/// The live peer's mesh address.
const PEER_IPV4: &str = "10.254.0.2";
/// Underlay (veth) addresses of the measured node and the peer.
const UNDERLAY_MEASURED: &str = "10.220.0.1";
/// See [`UNDERLAY_MEASURED`].
const UNDERLAY_PEER: &str = "10.220.0.2";

/// Run a command and require that it succeeds, hiding its output.
fn run(program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "{program} {args:?} failed: {status}");
}

/// Choose the engine from `RESTART_BENCH_ENGINE` (`kernel` or `gotatun`).
fn engine_from_env() -> EngineKind {
    match std::env::var("RESTART_BENCH_ENGINE").as_deref() {
        Ok("gotatun") => EngineKind::GotaTun,
        Ok("kernel") | Err(_) => EngineKind::Kernel,
        Ok(other) => panic!("unknown RESTART_BENCH_ENGINE {other}"),
    }
}

/// A private, mode-0700 directory removed when the trial ends. It holds node
/// state and the files the two halves use to talk to each other.
struct Scratch(PathBuf);
impl Scratch {
    /// Create a fresh directory named for this process, a role and the time.
    fn new(role: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "infraternal-restart-{role}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Wait up to `limit` for `path` to exist, polling every few milliseconds.
fn wait_for_file(path: &Path, limit: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if path.exists() {
            return true;
        }
        // sleep: polling a file the other process writes; there is no event to wait on.
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// A one-peer-at-a-time policy entry that allows all traffic both ways.
fn open_peer(
    key: PublicKey,
    addresses: Addresses,
    endpoint: Option<std::net::SocketAddr>,
) -> PeerPolicy {
    PeerPolicy {
        peer: Peer {
            key,
            previous_key: None,
            previous_active: false,
            addresses,
            endpoint,
        },
        inbound: crate::policy::rules::TrafficPolicy::All,
        outbound: crate::policy::rules::TrafficPolicy::All,
        access_ssh: None,
    }
}

/// Build a snapshot for `node` at `address`, holding `peers`, under `epoch`.
fn snapshot(
    node: NodeId,
    local_key: PublicKey,
    address: Addresses,
    peers: BTreeMap<NodeId, PeerPolicy>,
    epoch: &str,
) -> Config {
    Config {
        authority_epoch: Some(epoch.to_owned()),
        local_key: Some(local_key),
        server: None,
        node,
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: "internal".to_owned(),
        version: 10,
        addresses: address,
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers,
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
    }
}

/// Deliver every chunk of `config` to `node`, stamping each with the
/// snapshot's epoch, and return how many chunks it took.
fn deliver(node: &mut Node, config: &Config) -> usize {
    let chunks = crate::configuration::chunks(None, config).unwrap();
    let count = chunks.len();
    for mut chunk in chunks {
        chunk.authority_epoch.clone_from(&config.authority_epoch);
        node.chunk(chunk).unwrap();
    }
    count
}

/// Start a process that holds a fresh network namespace open, and wait until
/// the kernel shows it in a namespace other than ours.
fn sibling_namespace() -> Child {
    let child = Command::new("unshare")
        .args(["-n", "sleep", "600"])
        .spawn()
        .unwrap();
    let pid = child.id();
    for _ in 0..200 {
        if std::fs::read_link(format!("/proc/{pid}/ns/net")).unwrap()
            != std::fs::read_link("/proc/self/ns/net").unwrap()
        {
            return child;
        }
        // sleep: `unshare` switches namespaces asynchronously after spawn.
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("sibling namespace never appeared");
}

/// Join our namespace and the sibling's with a veth pair on the underlay addresses.
fn underlay(sibling: u32) {
    let pid = sibling.to_string();
    run(
        "ip",
        &[
            "link",
            "add",
            "underlay0",
            "type",
            "veth",
            "peer",
            "name",
            "underlay1",
        ],
    );
    run("ip", &["link", "set", "underlay1", "netns", &pid]);
    run(
        "ip",
        &[
            "addr",
            "add",
            &format!("{UNDERLAY_MEASURED}/24"),
            "dev",
            "underlay0",
        ],
    );
    run("ip", &["link", "set", "underlay0", "up"]);
    let inside = |args: &[&str]| {
        let mut full = vec!["-t", &pid, "-n"];
        full.extend_from_slice(args);
        run("nsenter", &full);
    };
    inside(&[
        "ip",
        "addr",
        "add",
        &format!("{UNDERLAY_PEER}/24"),
        "dev",
        "underlay1",
    ]);
    inside(&["ip", "link", "set", "underlay1", "up"]);
    inside(&["ip", "link", "set", "lo", "up"]);
}

/// One arrival of the numbered stream: its sequence number and when it came in.
type Arrival = (u64, Instant);

/// The live peer: brings up a kernel node, connects it to the measured node and
/// sends one numbered datagram per millisecond until told to stop.
///
/// The measured node starts this in the sibling namespace and passes, through
/// the environment, the scratch directory it shares (`RESTART_BENCH_DIR`) and
/// its own identity (`RESTART_BENCH_MEASURED`, JSON). This half writes its
/// identity to `peer-identity.json`, waits for `start`, sends until `stop`
/// exists, then writes the number of datagrams it sent to `sent`.
#[test]
#[ignore = "child process of restart_continuity_same_content_snapshot"]
fn restart_continuity_peer() {
    let dir = PathBuf::from(std::env::var_os("RESTART_BENCH_DIR").unwrap());
    let measured: Identity =
        serde_json::from_str(&std::env::var("RESTART_BENCH_MEASURED").unwrap()).unwrap();
    let state = Scratch::new("peer");
    let mut node = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let identity = node.up().unwrap();
    let address = Addresses {
        ipv4: PEER_IPV4.parse().unwrap(),
        ipv6: "fd01::2".parse().unwrap(),
    };
    let peers = BTreeMap::from([(
        NodeId(1),
        open_peer(
            measured.public_key,
            Addresses {
                ipv4: MEASURED_IPV4.parse().unwrap(),
                ipv6: "fd01::1".parse().unwrap(),
            },
            Some(
                format!("{UNDERLAY_MEASURED}:{}", measured.port)
                    .parse()
                    .unwrap(),
            ),
        ),
    )]);
    deliver(
        &mut node,
        &snapshot(NodeId(2), identity.public_key, address, peers, EPOCH_BEFORE),
    );
    let written = dir.join("peer-identity.json.tmp");
    std::fs::write(&written, serde_json::to_vec(&identity).unwrap()).unwrap();
    std::fs::rename(&written, dir.join("peer-identity.json")).unwrap();
    assert!(wait_for_file(&dir.join("start"), Duration::from_secs(30)));

    let socket = UdpSocket::bind((PEER_IPV4, 0)).unwrap();
    let target = (MEASURED_IPV4, STREAM_PORT);
    let stop = dir.join("stop");
    let mut sent: u64 = 0;
    let started = Instant::now();
    while !stop.exists() {
        // A send can fail while the measured node has no route back yet; the
        // datagram then counts as sent and lost, which is what we measure.
        let _ = socket.send_to(&sent.to_be_bytes(), target);
        sent += 1;
        // Pace by the schedule, not by "sleep after send", so slow sends do
        // not lower the rate.
        let next = started + SEND_INTERVAL * u32::try_from(sent).unwrap();
        if let Some(wait) = next.checked_duration_since(Instant::now()) {
            // sleep: paces the 1 kHz stream; this is the measurement's clock.
            std::thread::sleep(wait);
        }
    }
    std::fs::write(dir.join("sent"), sent.to_string()).unwrap();
    node.down().unwrap();
}

/// The longest gap between consecutive arrivals in `arrivals`, in milliseconds.
fn longest_gap_ms(arrivals: &[Arrival]) -> f64 {
    arrivals
        .windows(2)
        .map(|pair| pair[1].1.duration_since(pair[0].1).as_secs_f64() * 1e3)
        .fold(0.0, f64::max)
}

/// Measure one same-content coordinator restart on the engine from
/// `RESTART_BENCH_ENGINE`, and print one `RESTART_CONTINUITY` result line.
#[test]
#[ignore = "Run as root inside a dedicated network namespace"]
fn restart_continuity_same_content_snapshot() {
    run("ip", &["link", "set", "lo", "up"]);
    let engine = engine_from_env();
    let shared = Scratch::new("shared");
    let state = Scratch::new("measured");
    let mut node = Node::restore_with_engine(&state.0, engine).unwrap();
    let identity = node.up().unwrap();

    let mut sibling = sibling_namespace();
    underlay(sibling.id());
    let mut peer = Command::new("nsenter")
        .args(["-t", &sibling.id().to_string(), "-n"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "node::restart_continuity_bench::restart_continuity_peer",
            "--ignored",
            "--nocapture",
        ])
        .env("RESTART_BENCH_DIR", &shared.0)
        .env(
            "RESTART_BENCH_MEASURED",
            serde_json::to_string(&identity).unwrap(),
        )
        .spawn()
        .unwrap();
    let identity_file = shared.0.join("peer-identity.json");
    assert!(
        wait_for_file(&identity_file, Duration::from_secs(60)),
        "the live peer never came up"
    );
    let live: Identity = serde_json::from_slice(&std::fs::read(&identity_file).unwrap()).unwrap();

    // One live peer plus idle peers, so the snapshot has a realistic size.
    let mut peers = BTreeMap::from([(
        NodeId(2),
        open_peer(
            live.public_key,
            Addresses {
                ipv4: PEER_IPV4.parse().unwrap(),
                ipv6: "fd01::2".parse().unwrap(),
            },
            Some(format!("{UNDERLAY_PEER}:{}", live.port).parse().unwrap()),
        ),
    )]);
    for index in 3..=PEERS + 1 {
        let host = u8::try_from(index).unwrap();
        peers.insert(
            NodeId(u64::from(index)),
            open_peer(
                Key::generate().unwrap().1,
                Addresses {
                    ipv4: std::net::Ipv4Addr::new(10, 254, 1, host),
                    ipv6: format!("fd01::1:{host:x}").parse().unwrap(),
                },
                None,
            ),
        );
    }
    let address = Addresses {
        ipv4: MEASURED_IPV4.parse().unwrap(),
        ipv6: "fd01::1".parse().unwrap(),
    };
    let before = snapshot(NodeId(1), identity.public_key, address, peers, EPOCH_BEFORE);
    deliver(&mut node, &before);

    let receiver = UdpSocket::bind((MEASURED_IPV4, STREAM_PORT)).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let arrivals: Arc<Mutex<Vec<Arrival>>> = Arc::new(Mutex::new(Vec::with_capacity(16_384)));
    let done = Arc::new(AtomicBool::new(false));
    let listener = {
        let arrivals = Arc::clone(&arrivals);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 16];
            while !done.load(Ordering::Relaxed) {
                if let Ok((8, _)) = receiver.recv_from(&mut buffer) {
                    let sequence = u64::from_be_bytes(buffer[..8].try_into().unwrap());
                    arrivals.lock().unwrap().push((sequence, Instant::now()));
                }
            }
        })
    };
    std::fs::write(shared.0.join("start"), b"go").unwrap();
    let first_seen = Instant::now();
    while arrivals.lock().unwrap().is_empty() {
        assert!(
            first_seen.elapsed() < Duration::from_secs(10),
            "no datagram crossed the tunnel before the swap"
        );
        // sleep: waiting for the first datagram from the other process.
        std::thread::sleep(Duration::from_millis(5));
    }
    // sleep: let the stream settle so the swap lands in steady traffic.
    std::thread::sleep(WARM_UP);

    let counters_before = node.counters().unwrap()[&live.public_key].clone();
    let after = Config {
        authority_epoch: Some(EPOCH_AFTER.to_owned()),
        ..before
    };
    let swap_started = Instant::now();
    let chunks = deliver(&mut node, &after);
    let swap_ended = Instant::now();
    // sleep: keep the stream running to catch a delayed re-handshake or loss.
    std::thread::sleep(COOL_DOWN);
    let counters_after = node.counters().unwrap()[&live.public_key].clone();

    std::fs::write(shared.0.join("stop"), b"stop").unwrap();
    assert!(peer.wait().unwrap().success(), "the live peer failed");
    done.store(true, Ordering::Relaxed);
    listener.join().unwrap();
    let sent: u64 = std::fs::read_to_string(shared.0.join("sent"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    sibling.kill().unwrap();
    sibling.wait().unwrap();
    node.down().unwrap();

    let arrivals = std::mem::take(&mut *arrivals.lock().unwrap());
    let mut seen = std::collections::BTreeSet::new();
    for (sequence, _) in &arrivals {
        seen.insert(*sequence);
    }
    // The newest datagram that arrived before the swap began. Everything the
    // peer sent after it is counted against the swap.
    let last_before_swap = arrivals
        .iter()
        .filter(|(_, at)| *at < swap_started)
        .map(|(sequence, _)| *sequence)
        .max()
        .unwrap_or(0);
    let lost_after_swap = (last_before_swap + 1..sent)
        .filter(|sequence| !seen.contains(sequence))
        .count();
    let steady: Vec<Arrival> = arrivals
        .iter()
        .copied()
        .filter(|(_, at)| *at < swap_started)
        .collect();
    let around: Vec<Arrival> = arrivals
        .iter()
        .copied()
        .filter(|(_, at)| *at + Duration::from_millis(500) >= swap_started)
        .collect();
    let peer_recreated = counters_after.received_bytes < counters_before.received_bytes
        || counters_after.handshake_secs != counters_before.handshake_secs;
    let engine_name = match engine {
        EngineKind::Kernel => "kernel",
        EngineKind::GotaTun => "gotatun",
    };
    let result = serde_json::json!({
        "engine": engine_name,
        "peers": PEERS,
        "chunks": chunks,
        "swap_us": swap_ended.duration_since(swap_started).as_micros(),
        "sent": sent,
        "received": seen.len(),
        "lost": sent.saturating_sub(u64::try_from(seen.len()).unwrap()),
        "lost_after_swap": lost_after_swap,
        "steady_max_gap_ms": longest_gap_ms(&steady),
        "swap_max_gap_ms": longest_gap_ms(&around),
        "handshake_before_s": counters_before.handshake_secs,
        "handshake_after_s": counters_after.handshake_secs,
        "rx_bytes_before": counters_before.received_bytes,
        "rx_bytes_after": counters_after.received_bytes,
        "peer_recreated": peer_recreated,
    });
    println!("RESTART_CONTINUITY {result}");
    if let Some(out) = std::env::var_os("RESTART_BENCH_OUT") {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .unwrap();
        writeln!(file, "{result}").unwrap();
    }
}
