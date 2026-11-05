//! Namespace-only fixture for the `GotaTun` relay proof: a relay, or a real mesh node with relayed pairs [220].
//!
//! Driven by `scripts/mesh-relay-proof.py` over stdin/stdout, one JSON object
//! per line. Certificates and keys arrive on stdin and stay in memory;
//! `WireGuard` private keys never leave the node process. Every line printed
//! carries `t_ms`, monotonic milliseconds since the process started.
//!
//! - `relay_fixture certs`: read `{"hosts":[uuid],"relays":[name]}`, print a
//!   disposable CA and one leaf per host and relay.
//! - `relay_fixture relay`: read `{listen,cert,key,ca}`, run a relay; then
//!   `"stats"` prints its counters and end of input stops it.
//! - `relay_fixture node`: read `{host,cert,key,ca,addresses,relays}`,
//!   start the selected mesh data plane and print its public key; then commands
//!   (see `Command`) until `"quit"` or end of input, which deletes the device.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_mesh::{
    discovery::{Discovery, Observation},
    model::{Addresses, NodeId, PublicKey},
};
use infraternal_plugin_mesh::{
    configuration,
    dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
    node::{EngineKind, Node},
    policy::rules::TrafficPolicy,
    relay_path::{self, Observer, RelayPaths, RelaySpec},
    seam::Seam,
    wireguard::Device,
};
use infraternal_plugin_relay::{
    relay::{Limits, Relay},
    testing::{Authority, Purpose, credentials_from_pem},
    wire::HostId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    io::{BufRead, Write},
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime},
};

static STARTED: OnceLock<Instant> = OnceLock::new();

fn say(mut line: Value) {
    let elapsed = STARTED.get_or_init(Instant::now).elapsed();
    line["t_ms"] = json!(elapsed.as_secs_f64() * 1000.0);
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").unwrap();
    out.flush().unwrap();
}

/// Lines from stdin, read on a plain thread so the runtime stays free.
fn lines() -> tokio::sync::mpsc::Receiver<String> {
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if sender.blocking_send(line).is_err() {
                break;
            }
        }
    });
    receiver
}

fn host(text: &str) -> HostId {
    HostId::parse(text).expect("host uuid")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn key(text: &str) -> PublicKey {
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).expect("hex key");
    }
    PublicKey(out)
}

fn unix_time() -> SystemTime {
    SystemTime::now()
}

fn certs() {
    #[derive(Deserialize)]
    struct Request {
        hosts: Vec<String>,
        relays: Vec<String>,
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    let request: Request = serde_json::from_str(&line).unwrap();
    let mut ca = Authority::new();
    let mut hosts = serde_json::Map::new();
    for text in &request.hosts {
        let (cert, key) = ca.issue_pem(Purpose::Host(host(text)));
        hosts.insert(text.clone(), json!({"cert": cert, "key": key}));
    }
    let mut relays = serde_json::Map::new();
    for name in &request.relays {
        let (cert, key) = ca.issue_pem(Purpose::Relay(name));
        relays.insert(name.clone(), json!({"cert": cert, "key": key}));
    }
    say(json!({"ca": ca.pem(), "hosts": hosts, "relays": relays}));
}

async fn relay() {
    #[derive(Deserialize)]
    struct Config {
        listen: SocketAddr,
        cert: String,
        key: String,
        ca: String,
    }
    let mut input = lines();
    let config: Config = serde_json::from_str(&input.recv().await.unwrap()).unwrap();
    let relay = Relay::start(
        config.listen,
        credentials_from_pem(&config.cert, &config.key, &config.ca),
        Limits::default(),
        Arc::new(|_| true),
    )
    .unwrap();
    say(json!({"event": "ready", "address": relay.local_addr().unwrap()}));
    while let Some(line) = input.recv().await {
        if line.trim() == "stats" {
            let stats = relay.stats();
            say(json!({
                "event": "stats",
                "hosts": stats.hosts,
                "links": stats.links,
                "forwarded": stats.forwarded,
                "dropped": stats.dropped,
                "probes_answered": stats.probes_answered,
                "probes_refused": stats.probes_refused,
            }));
        }
    }
    relay.close().await;
}

#[derive(Deserialize)]
struct NodeConfig {
    host: String,
    cert: String,
    key: String,
    ca: String,
    addresses: Addresses,
    relays: Vec<RelayConfig>,
}

#[derive(Deserialize)]
struct RelayConfig {
    address: SocketAddr,
    name: String,
}

#[derive(Deserialize)]
struct PeerConfig {
    host: String,
    key: String,
    addresses: Addresses,
    endpoint: Option<SocketAddr>,
}

/// Node commands, one JSON object per line.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Command {
    /// Install coordinator peers and their host routes.
    Peers(Vec<PeerConfig>),
    /// Wait `grace_ms`; relay the peer if no direct handshake happened.
    DirectOrRelay {
        host: String,
        grace_ms: u64,
    },
    /// Relay the peer now.
    Relay {
        host: String,
    },
    /// Probe relay `index` from the mesh UDP port; record it in the book.
    Observe {
        relay: usize,
        observer: u64,
    },
    /// Retire every observation (network change).
    Generation(u64),
    Evidence,
    Stats,
}

/// Run one fixture node: read its configuration, start the mesh and follow commands from stdin.
async fn node() {
    let mut input = lines();
    let config: NodeConfig = serde_json::from_str(&input.recv().await.unwrap()).unwrap();
    let mut node = Node::default().with_engine(EngineKind::GotaTun);
    let identity = node.up().unwrap();
    assert!(
        Device::owned_tun().unwrap(),
        "relay fixture must use GotaTun"
    );
    let public = identity.public_key;
    let port = identity.port;
    say(json!({"event": "identity", "public_key": hex(&public.0), "port": port}));

    let (events, mut event_queue) = tokio::sync::mpsc::channel(256);
    let paths = RelayPaths::start(
        host(&config.host),
        port,
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
    let names: Arc<std::sync::Mutex<HashMap<HostId, String>>> = Arc::default();
    let printer = tokio::spawn({
        let names = names.clone();
        async move {
            while let Some(event) = event_queue.recv().await {
                let line = match event {
                    relay_path::Event::RelayUp { relay } => {
                        json!({"event": "relay_up", "relay": relay})
                    }
                    relay_path::Event::RelayDown { relay } => {
                        json!({"event": "relay_down", "relay": relay})
                    }
                    relay_path::Event::Active { peer, relay } => json!({
                        "event": "active",
                        "peer": names.lock().unwrap().get(&peer).cloned().unwrap_or_else(|| peer.to_string()),
                        "relay": relay,
                    }),
                };
                say(line);
            }
        }
    });
    let observer = Observer::new(Seam::open(port).unwrap());
    let mut book = Discovery::new(1);
    let mut generation = 1;
    let mut peers: HashMap<String, (Peer, SystemTime)> = HashMap::new();
    let mut accepted: Option<Config> = None;
    let started = Instant::now();
    let since_start = || started.elapsed();

    while let Some(line) = input.recv().await {
        if line.trim() == "quit" {
            break;
        }
        let command: Command = match serde_json::from_str(&line) {
            Ok(command) => command,
            Err(error) => {
                say(json!({"event": "error", "error": error.to_string()}));
                continue;
            }
        };
        match command {
            Command::Peers(list) => {
                let mut next = Config {
                    local_key: Some(public),
                    server: None,
                    node: NodeId(1),
                    #[cfg(feature = "mesh-dns-spike")]
                    name: None,
                    #[cfg(feature = "mesh-dns-spike")]
                    dns_suffix: infraternal_plugin_mesh::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
                    version: accepted.as_ref().map_or(1, |old| old.version + 1),
                    addresses: config.addresses,
                    default_policy: DefaultPolicy::Allow,
                    exposure: None,
                    peers: BTreeMap::default(),
                    #[cfg(feature = "mesh-dns-spike")]
                    peer_names: Default::default(),
                };
                let installed: Vec<Peer> = list
                    .iter()
                    .map(|peer| Peer {
                        key: key(&peer.key),
                        previous_key: None,
                        previous_active: false,
                        addresses: peer.addresses,
                        endpoint: peer.endpoint,
                    })
                    .collect();
                for (index, peer) in list.iter().zip(&installed).enumerate() {
                    next.peers.insert(
                        NodeId(u64::try_from(index + 2).unwrap()),
                        PeerPolicy {
                            peer: peer.1.clone(),
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                            access_ssh: None,
                        },
                    );
                }
                // GotaTun can complete a direct handshake while applying this snapshot. Record
                // the lower-bound time first so that immediate, valid handshakes are not treated
                // as stale merely because Node::chunk returns after starting its packet workers.
                let installed_at = unix_time();
                for chunk in configuration::chunks(accepted.as_ref(), &next).unwrap() {
                    node.chunk(chunk).unwrap();
                }
                accepted = Some(next);
                for (peer, kernel) in list.iter().zip(&installed) {
                    peers.insert(peer.host.clone(), (kernel.clone(), installed_at));
                    names
                        .lock()
                        .unwrap()
                        .insert(host(&peer.host), peer.host.clone());
                }
                say(json!({"event": "peers", "count": list.len()}));
            }
            Command::DirectOrRelay {
                host: name,
                grace_ms,
            } => {
                let (kernel, since) = peers[&name].clone();
                tokio::time::sleep(Duration::from_millis(grace_ms)).await;
                let counters = node.counters().unwrap();
                let peer_counters = counters.get(&kernel.key);
                let direct_failed = relay_path::direct_failed(peer_counters, since);
                if direct_failed {
                    let shim = paths
                        .relay_with_endpoint(&mut node, host(&name), &kernel)
                        .await
                        .unwrap();
                    say(json!({"event": "relayed", "peer": name, "shim": shim}));
                } else {
                    say(json!({"event": "direct", "peer": name}));
                }
            }
            Command::Relay { host: name } => {
                let (kernel, _) = peers[&name].clone();
                let shim = paths
                    .relay_with_endpoint(&mut node, host(&name), &kernel)
                    .await
                    .unwrap();
                say(json!({"event": "relayed", "peer": name, "shim": shim}));
            }
            Command::Observe {
                relay,
                observer: id,
            } => {
                let sent = Instant::now();
                match paths.observe(&observer, relay).await {
                    Ok(reflexive) => {
                        let rtt = sent.elapsed();
                        let destination = config.relays[relay].address;
                        let recorded = book.observe(
                            generation,
                            Observation {
                                observer: NodeId(id),
                                destination,
                                reflexive,
                            },
                            since_start(),
                            Duration::from_secs(60),
                        );
                        say(json!({
                            "event": "observed",
                            "relay": relay,
                            "reflexive": reflexive,
                            "rtt_us": rtt.as_micros(),
                            "recorded": recorded.is_ok(),
                        }));
                    }
                    Err(error) => say(json!({
                        "event": "observe_failed",
                        "relay": relay,
                        "error": error.to_string(),
                    })),
                }
            }
            Command::Generation(next) => {
                let result = book.restart(next, since_start());
                if result.is_ok() {
                    generation = next;
                }
                say(json!({"event": "generation", "generation": next, "ok": result.is_ok()}));
            }
            Command::Evidence => {
                let evidence = book.evidence(false, since_start()).unwrap();
                let live = book.observations(since_start()).unwrap();
                say(json!({
                    "event": "evidence",
                    "ipv4": format!("{evidence:?}"),
                    "observations": live.iter().map(|o| json!({
                        "observer": o.observer.0,
                        "destination": o.destination,
                        "reflexive": o.reflexive,
                    })).collect::<Vec<_>>(),
                }));
            }
            Command::Stats => {
                let stats = paths.stats();
                let counters = node.counters().unwrap();
                let kernel: Vec<Value> = peers
                    .iter()
                    .map(|(name, (kernel, _))| {
                        let counters = counters.get(&kernel.key).cloned().unwrap_or_default();
                        json!({
                            "peer": name,
                            "endpoint": counters.endpoint,
                            "handshake_secs": counters.handshake_secs,
                            "handshake_nanos": counters.handshake_nanos,
                            "received_bytes": counters.received_bytes,
                            "sent_bytes": counters.sent_bytes,
                            "active_relay": paths.active(host(name)),
                        })
                    })
                    .collect();
                say(json!({
                    "event": "stats",
                    "sent": stats.sent,
                    "received": stats.received,
                    "unlinked": stats.unlinked,
                    "too_large": stats.too_large,
                    "inbound_datagrams": stats.inbound_datagrams,
                    "malformed_datagrams": stats.malformed_datagrams,
                    "unknown_links": stats.unknown_links,
                    "unknown_peers": stats.unknown_peers,
                    "injection_errors": stats.injection_errors,
                    "receive_errors": stats.receive_errors,
                    "tap_delivered": observer.delivered(),
                    "peers": kernel,
                }));
            }
        }
    }
    paths.close().await;
    printer.abort();
    drop(observer);
    node.down().unwrap();
    say(json!({"event": "off"}));
}

fn main() {
    STARTED.get_or_init(Instant::now);
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "certs" {
        certs();
        return;
    }
    // One thread, as a node's mesh component would give the shim.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    match mode.as_str() {
        "relay" => runtime.block_on(relay()),
        "node" => runtime.block_on(node()),
        _ => {
            eprintln!("usage: relay_fixture certs|relay|node");
            std::process::exit(2);
        }
    }
}
