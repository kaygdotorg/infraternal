//! Proves that incremental snapshot apply leaves the kernel exactly as a full apply would (#260,
//! J1240).
//!
//! A snapshot writes only the peer host routes that differ from what this process last wrote,
//! and changes the `GotaTun` guard's address sets element by element. These namespace tests
//! drive a real `GotaTun` [`Node`] through seeded random snapshot sequences (peers join, leave,
//! move, change keys, endpoints and policy, turn IPv4-only, and the underlay MTU changes) and,
//! after every step, compare the kernel state with the state a full rewrite of every route and of
//! the whole guard table produces. A second test kills the process with SIGKILL in the middle of
//! an apply, after the kernel changed and before the snapshot was saved, and checks that the
//! restarted node converges to the next snapshot just as exactly.
//!
//! They need root in a network namespace without an uplink (fake endpoints live on a dummy
//! link there), and refuse to run where a default route exists.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
use super::*;
use crate::{
    dataplane::{DefaultPolicy, Peer, PeerPolicy},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The one authority epoch of every snapshot here, so each apply after the first is an
/// ordinary revision, as from a running coordinator.
const EPOCH: &str = "00000000-0000-4000-8000-000000001240";

/// Run `ip` with `args` and fail the test if it fails.
fn ip(args: &[&str]) {
    let status = Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .status()
        .expect("run ip");
    assert!(status.success(), "ip {args:?}");
}

/// Return `ip`'s standard output for `args`.
fn ip_output(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("run ip");
    assert!(output.status.success(), "ip {args:?}");
    String::from_utf8(output.stdout).expect("ip prints text")
}

/// Refuse to run anywhere a packet could leave: the fake endpoints below must stay inside a
/// namespace with no route off the machine (network hygiene rule, 2026-11-22).
fn require_isolated_namespace() {
    assert!(
        ip_output(&["route", "show", "default"]).trim().is_empty()
            && ip_output(&["-6", "route", "show", "default"])
                .trim()
                .is_empty(),
        "run this test only in a disposable network namespace without a default route"
    );
}

/// A dummy link whose connected /24 holds the fake peer endpoints; packets to it are dropped
/// by the dummy driver. Its MTU is the underlay budget the endpoint routes derive from.
const UNDERLAY: &str = "j1240u0";

/// Create [`UNDERLAY`] with 10.99.0.1/24 and bring it and loopback up.
fn underlay_up() {
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", UNDERLAY, "type", "dummy"]);
    ip(&["addr", "add", "10.99.0.1/24", "dev", UNDERLAY]);
    ip(&["link", "set", UNDERLAY, "mtu", "1500", "up"]);
}

/// A private, mode-0700 state directory for one test node, removed when the test ends.
struct StateDir(std::path::PathBuf);
impl StateDir {
    /// Create a fresh directory named for this process and the current time.
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "infraternal-mesh-j1240-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for StateDir {
    /// Remove the directory and everything the node left in it.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A small deterministic generator (xorshift64*), so a failing sequence replays from its seed.
struct Sequence(u64);
impl Sequence {
    /// The next 64 random bits.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// A number below `bound`.
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }
}

/// What a snapshot says about one peer, in the small vocabulary the random steps change.
#[derive(Clone, Debug)]
struct Facts {
    /// Index into the identity pool.
    key: usize,
    /// Last byte of the mesh addresses (`10.254.1.x` and `fd01::1:x`).
    address: u8,
    /// Last byte of the endpoint `10.99.0.x` on the dummy underlay, or none.
    endpoint: Option<u8>,
    /// Whether the peer's inbound policy is closed (it then has no network access).
    closed: bool,
    /// Whether the peer is IPv4-only, so it gets no IPv6 host route.
    ipv4_only: bool,
}

/// Build the complete snapshot `version` for the node `local_key` from `peers`.
fn snapshot(
    local_key: PublicKey,
    keys: &[PublicKey],
    peers: &BTreeMap<u64, Facts>,
    version: u64,
) -> Config {
    Config {
        authority_epoch: Some(EPOCH.to_owned()),
        rotation_operation: None,
        local_key: Some(local_key),
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: peers
            .iter()
            .map(|(id, facts)| {
                let policy = PeerPolicy {
                    peer: Peer {
                        key: keys[facts.key],
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: std::net::Ipv4Addr::new(10, 254, 1, facts.address),
                            ipv6: format!("fd01::1:{:x}", facts.address).parse().unwrap(),
                        },
                        endpoint: facts
                            .endpoint
                            .map(|last| std::net::SocketAddr::from(([10, 99, 0, last], 51820))),
                        candidates: Vec::new(),
                        ipv4_only: facts.ipv4_only,
                        side_port: false,
                    },
                    inbound: if facts.closed {
                        TrafficPolicy::None
                    } else {
                        TrafficPolicy::All
                    },
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                    networks: crate::dataplane::PeerNetworks::default(),
                };
                (NodeId(*id), policy)
            })
            .collect(),
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
    }
}

/// Deliver `config` as a complete snapshot, the way the coordinator sends one.
fn deliver(node: &mut Node, config: &Config) {
    for chunk in crate::configuration::chunks(None, config).unwrap() {
        node.chunk(chunk).unwrap();
    }
    assert_eq!(
        node.config().map(|config| config.version),
        Some(config.version)
    );
}

/// What the kernel holds for the mesh: every route on the mesh link, and the guard table with
/// its handles removed and its set elements sorted (a hash set lists in no stable order).
#[derive(Debug, PartialEq, Eq)]
struct KernelState {
    /// `ip route` lines for both families on the mesh link, sorted.
    routes: BTreeSet<String>,
    /// The guard table's objects as normalised JSON text, sorted.
    guard: BTreeSet<String>,
}

/// Read [`KernelState`] now.
fn kernel_state() -> KernelState {
    let mut routes = BTreeSet::new();
    for family in ["-4", "-6"] {
        for line in
            ip_output(&[family, "route", "show", "dev", crate::wireguard::INTERFACE]).lines()
        {
            routes.insert(format!("{family} {}", line.trim()));
        }
    }
    let output = Command::new(crate::firewall::nft().expect("nft at its fixed path"))
        .args(["-j", "list", "table", "inet", "infraternal_mesh"])
        .output()
        .expect("run nft");
    assert!(output.status.success(), "the guard table exists");
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let guard = listing["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item.get("metainfo").is_none())
        .map(|item| {
            let mut item = item.clone();
            for object in item.as_object_mut().unwrap().values_mut() {
                if let Some(object) = object.as_object_mut() {
                    object.remove("handle");
                    if let Some(serde_json::Value::Array(elements)) = object.get_mut("elem") {
                        elements.sort_by_key(ToString::to_string);
                    }
                }
            }
            item.to_string()
        })
        .collect();
    KernelState { routes, guard }
}

/// The host route destinations `config` asks for: both addresses of every peer, IPv4 only for
/// an IPv4-only peer.
fn wanted_destinations(config: &Config) -> BTreeSet<String> {
    config
        .peers
        .values()
        .flat_map(|policy| policy.peer.routed_addresses())
        .map(|address| address.to_string())
        .collect()
}

/// The destinations of the peer host routes (mesh route protocol) in `state`.
fn route_destinations(state: &KernelState) -> BTreeSet<String> {
    state
        .routes
        .iter()
        .filter(|line| line.contains(" proto 250 "))
        .filter_map(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .collect()
}

/// Check that what the incremental apply left equals a full apply of the same snapshot: the
/// routes are exactly the wanted ones, and rewriting every route and the whole guard table
/// changes nothing.
fn assert_matches_full_apply(node: &mut Node, context: &str) {
    let config = node.config().cloned().expect("an accepted snapshot");
    let incremental = kernel_state();
    assert_eq!(
        route_destinations(&incremental),
        wanted_destinations(&config),
        "{context}: route destinations"
    );
    lock_route_state(&node.peer_route_state).forget_written();
    let peers: Vec<_> = config
        .peers
        .values()
        .map(|policy| policy.peer.clone())
        .collect();
    node.install_peer_routes(&peers, false)
        .expect("full route rewrite");
    node.firewall.forget_installed_guard();
    node.firewall
        .install_pending(&config)
        .expect("full guard rewrite");
    assert_eq!(
        incremental,
        kernel_state(),
        "{context}: against a full apply"
    );
}

/// Wait until the route monitor has read the underlay change just made, so the next snapshot
/// sees a new generation. The watch is asynchronous by design; a snapshot that races it is put
/// right by the next live-endpoint refresh, which this test does not wait for.
fn wait_for_underlay_change(node: &Node, before: Option<u64>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = lock_route_state(&node.peer_route_state)
            .underlay
            .as_ref()
            .and_then(|underlay| underlay.generation());
        if now != before {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the underlay watch saw the change"
        );
        // sleep: the route monitor thread reads the link notification on its own schedule.
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Apply one random change to `peers` (or to the underlay) and describe it.
fn random_step(
    random: &mut Sequence,
    node: &Node,
    peers: &mut BTreeMap<u64, Facts>,
    pool: usize,
    next_id: &mut u64,
) -> String {
    let used_keys: BTreeSet<_> = peers.values().map(|facts| facts.key).collect();
    let used_addresses: BTreeSet<_> = peers.values().map(|facts| facts.address).collect();
    let free_key = (0..pool).find(|key| !used_keys.contains(key));
    let free_address = (2..=60_u8).find(|address| !used_addresses.contains(address));
    let ids: Vec<_> = peers.keys().copied().collect();
    let pick = (!ids.is_empty()).then(|| ids[random.below(ids.len())]);
    let endpoint = |random: &mut Sequence| [None, Some(2), Some(3), Some(4)][random.below(4)];
    match (random.below(9), pick) {
        (0 | 1, _) if free_key.is_some() && free_address.is_some() => {
            let id = *next_id;
            *next_id += 1;
            let facts = Facts {
                key: free_key.unwrap(),
                address: free_address.unwrap(),
                endpoint: endpoint(random),
                closed: random.below(4) == 0,
                ipv4_only: random.below(4) == 0,
            };
            let text = format!("add {id} {facts:?}");
            peers.insert(id, facts);
            text
        }
        (2, Some(id)) => {
            peers.remove(&id);
            format!("remove {id}")
        }
        (3, Some(id)) => {
            let facts = peers.get_mut(&id).unwrap();
            facts.closed = !facts.closed;
            format!("{id} closed={}", facts.closed)
        }
        (4, Some(id)) => {
            let facts = peers.get_mut(&id).unwrap();
            facts.endpoint = endpoint(random);
            format!("{id} endpoint={:?}", facts.endpoint)
        }
        (5, Some(id)) => {
            let facts = peers.get_mut(&id).unwrap();
            facts.ipv4_only = !facts.ipv4_only;
            format!("{id} ipv4_only={}", facts.ipv4_only)
        }
        (6, Some(id)) if free_address.is_some() => {
            peers.get_mut(&id).unwrap().address = free_address.unwrap();
            format!("{id} moves to {}", free_address.unwrap())
        }
        (7, Some(id)) if free_key.is_some() => {
            peers.get_mut(&id).unwrap().key = free_key.unwrap();
            format!("{id} new key {}", free_key.unwrap())
        }
        (8, _) => {
            let before = lock_route_state(&node.peer_route_state)
                .underlay
                .as_ref()
                .and_then(|underlay| underlay.generation());
            let mtu = ["1500", "1400", "1360"][random.below(3)];
            // An unchanged MTU announces nothing; only wait when it really moves.
            let moves = !ip_output(&["link", "show", UNDERLAY]).contains(&format!(" mtu {mtu} "));
            ip(&["link", "set", UNDERLAY, "mtu", mtu]);
            if moves {
                wait_for_underlay_change(node, before);
            }
            format!("underlay mtu {mtu}")
        }
        _ => "no change".to_owned(),
    }
}

/// Seeded random snapshot sequences converge to the kernel state of a full apply, step by step
/// (#260 J1240). `INFRATERNAL_J1240_SEEDS` overrides the seeds as a comma-separated list.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn random_snapshot_sequences_converge_to_a_full_apply() {
    require_isolated_namespace();
    underlay_up();
    let seeds: Vec<u64> = std::env::var("INFRATERNAL_J1240_SEEDS").map_or_else(
        |_| vec![1240, 7, 260],
        |text| text.split(',').map(|seed| seed.parse().unwrap()).collect(),
    );
    let keys: Vec<_> = (0..24)
        .map(|_| crate::wireguard::Key::generate().unwrap().1)
        .collect();
    for seed in seeds {
        let state = StateDir::new();
        let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
        let identity = node.up().unwrap();
        let mut random = Sequence(seed | 1);
        let mut peers = BTreeMap::new();
        let mut next_id = 2;
        for _ in 0..6 {
            random_step(&mut random, &node, &mut peers, keys.len(), &mut next_id);
        }
        let mut version = 1;
        for step in 0..60 {
            let change = if step == 0 {
                "first snapshot".to_owned()
            } else {
                (0..=random.below(3))
                    .map(|_| random_step(&mut random, &node, &mut peers, keys.len(), &mut next_id))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            version += 1;
            deliver(
                &mut node,
                &snapshot(identity.public_key, &keys, &peers, version),
            );
            let installed: BTreeSet<_> = node.installed_peer_keys().unwrap().into_iter().collect();
            assert_eq!(
                installed,
                node.counters().unwrap().into_keys().collect(),
                "key inventory at seed {seed} step {step}: {change}"
            );
            assert_matches_full_apply(&mut node, &format!("seed {seed} step {step}: {change}"));
        }
        node.down().unwrap();
    }
}

/// A new peer must pass cached prefixes and mesh-wide uniqueness, and live route changes must
/// still be checked against peers that keep their addresses.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn incremental_validation_refuses_new_and_unchanged_address_conflicts() {
    require_isolated_namespace();
    underlay_up();
    let state = StateDir::new();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let identity = node.up().unwrap();
    let keys: Vec<_> = (0..2)
        .map(|_| crate::wireguard::Key::generate().unwrap().1)
        .collect();
    let old_peer = Facts {
        key: 0,
        address: 10,
        endpoint: None,
        closed: false,
        ipv4_only: false,
    };
    let mut peers = BTreeMap::from([(2, old_peer.clone())]);
    let cached_prefix = [
        "route",
        "add",
        "10.254.1.20/32",
        "dev",
        UNDERLAY,
        "table",
        "100",
    ];
    ip(&cached_prefix);
    deliver(&mut node, &snapshot(identity.public_key, &keys, &peers, 2));
    peers.insert(
        3,
        Facts {
            key: 1,
            address: 20,
            ..old_peer
        },
    );
    let next = snapshot(identity.public_key, &keys, &peers, 3);
    assert_eq!(
        node.apply(next.clone()).unwrap_err().kind(),
        io::ErrorKind::AddrInUse
    );
    let mut del = cached_prefix;
    del[1] = "del";
    ip(&del);

    // Each address family independently refuses a new peer colliding with an unchanged peer.
    let old = next.peers[&NodeId(2)].peer.addresses;
    for ipv6 in [false, true] {
        let mut duplicate = next.clone();
        let address = &mut duplicate.peers.get_mut(&NodeId(3)).unwrap().peer.addresses;
        if ipv6 {
            address.ipv6 = old.ipv6;
        } else {
            address.ipv4 = old.ipv4;
        }
        assert_eq!(
            node.apply(duplicate).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    // The proposed revision changes only the new peer. This new IPv6 route covers the old one.
    let mut live_prefix = [
        "-6",
        "route",
        "add",
        "fd01::1:a/128",
        "dev",
        UNDERLAY,
        "table",
        "100",
    ];
    ip(&live_prefix);
    assert_eq!(
        node.apply(next.clone()).unwrap_err().kind(),
        io::ErrorKind::AddrInUse
    );
    assert_eq!(node.config().unwrap().version, 2);
    live_prefix[2] = "del";
    ip(&live_prefix);
    deliver(&mut node, &next);
    node.down().unwrap();
}

/// The child side of [`a_restart_after_a_kill_mid_apply_converges`]: apply the first snapshot,
/// then stop for good inside the second one, after its routes and guard are in the kernel and
/// before it is saved, so the parent can kill this process there.
#[test]
#[ignore = "launched by the J1240 mid-apply SIGKILL proof"]
fn incremental_apply_crash_child() {
    let state = std::path::PathBuf::from(
        std::env::var_os("INFRATERNAL_J1240_STATE")
            .expect("the parent supplies the state directory"),
    );
    let ready = std::env::var_os("INFRATERNAL_J1240_READY").expect("the parent supplies a path");
    let keys = crash_keys();
    let mut node = Node::restore_with_engine(&state, EngineKind::GotaTun).unwrap();
    let identity = node.up().unwrap();
    deliver(
        &mut node,
        &snapshot(identity.public_key, &keys, &crash_peers(1), 2),
    );
    *BEFORE_TRANSACTION_SAVE.lock().unwrap() = Some(Box::new(move || -> io::Result<()> {
        std::fs::write(&ready, b"applied").expect("tell the parent");
        loop {
            std::thread::park();
        }
    }));
    deliver(
        &mut node,
        &snapshot(identity.public_key, &keys, &crash_peers(2), 3),
    );
    panic!("the save seam never ran");
}

/// The fixed peer keys of the SIGKILL proof, shared by the child and the parent.
fn crash_keys() -> Vec<PublicKey> {
    (1..=12_u8).map(|byte| PublicKey([byte; 32])).collect()
}

/// The peer set of stage `stage` of the SIGKILL proof: stage 2 adds, removes, moves and
/// re-endpoints peers relative to stage 1, so its apply takes the full path; stage 3 drops the
/// peer stage 2 added and changes more of the others.
fn crash_peers(stage: u8) -> BTreeMap<u64, Facts> {
    let mut peers = BTreeMap::new();
    for id in 0..8_u8 {
        let facts = Facts {
            key: usize::from(id),
            address: 10 + id,
            endpoint: (id % 2 == 0).then_some(2 + id % 3),
            closed: id == 3,
            ipv4_only: id == 5,
        };
        peers.insert(u64::from(id) + 2, facts);
    }
    if stage >= 2 {
        peers.remove(&4);
        peers.insert(
            20,
            Facts {
                key: 9,
                address: 40,
                endpoint: Some(3),
                closed: false,
                ipv4_only: false,
            },
        );
        let moved = peers.get_mut(&6).unwrap();
        moved.address = 41;
        moved.endpoint = None;
    }
    if stage >= 3 {
        peers.remove(&2);
        peers.remove(&20);
        peers.get_mut(&3).unwrap().closed = false;
        peers.get_mut(&7).unwrap().ipv4_only = true;
        peers.get_mut(&8).unwrap().endpoint = Some(4);
    }
    peers
}

/// A restart after SIGKILL in the middle of an apply converges exactly (#260 J1240): the new
/// process starts with no record of written routes or guard content, so its first apply writes
/// everything, and the routes the killed apply added but never saved are retired.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn a_restart_after_a_kill_mid_apply_converges() {
    use std::os::unix::process::ExitStatusExt;
    require_isolated_namespace();
    underlay_up();
    let state = StateDir::new();
    let ready = state.0.join("j1240-ready");
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--ignored",
            "--exact",
            "node::incremental_apply_tests::incremental_apply_crash_child",
        ])
        .env("INFRATERNAL_J1240_STATE", &state.0)
        .env("INFRATERNAL_J1240_READY", &ready)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the child");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "child exited early: {status}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(Instant::now() < deadline, "the child reached the save seam");
        // sleep: poll for the child's readiness file without busy waiting.
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(nix::libc::SIGKILL));
    let killed = kernel_state();
    assert!(
        route_destinations(&killed).contains("10.254.1.40"),
        "the killed apply had written its routes"
    );

    let keys = crash_keys();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let identity = node.up().unwrap();
    deliver(
        &mut node,
        &snapshot(identity.public_key, &keys, &crash_peers(3), 4),
    );
    assert_matches_full_apply(&mut node, "after the restart");
    assert!(
        !route_destinations(&kernel_state()).contains("10.254.1.40"),
        "a route only the killed apply wanted is gone"
    );
    node.down().unwrap();
}
