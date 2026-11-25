//! Checks that the Mac adapter maps authenticated peers to `WireGuard` host routes.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Mac node unit tests panic on unexpected setup or assertion failures."
)]

/// Real-Mac authority refresh proofs with encrypted traffic and kernel MTU checks.
mod authority_mtu;
/// The Mac UDP listener: socket reuse and the handshake admission guard.
mod listener;
/// An enrolled restore binds the folder to this Mac and refuses another Mac's (#221).
mod machine_binding;
use machine_binding::bind_this_mac;
/// A failed retirement save leaves a peer-free deny snapshot, written before the worker fence.
mod retirement;
/// Real-Mac proof that a roamed peer's confirmed endpoint reaches the admission guard.
mod roamed_peer;
/// Startup and journal writes sweep crash-left rotation journal temporaries.
mod rotation_journal;
/// Real-Mac proof that an approved network behind a router peer is routed into the utun and
/// reached through the tunnel, and that revoking it takes the route away (#580).
mod subnet_routes;
/// Root mode's utun MTU and up state through ioctls, checked on a real Mac (#221).
mod utun_ioctl;
/// Idle sessions across snapshots, re-addressed handshakes and candidate walks (#515).
mod walks;

use super::{
    Enrolment, Node, PUBLIC_STATE, RuntimeInfo, SavedState, Worker, WorkerCommand,
    macos_snapshot_binding_is_authorized, mpsc, parse_utun_payload, peers_for_config,
    read_public_state, reconcile, rotation_crash_checkpoint, route_addresses,
    route_mtus_to_refresh, stage_chunk, utun_family, valid_utun_name, validate_config,
    validate_underlay_routes, write_public_state, write_public_state_full_snapshot,
};
use crate::{
    dataplane::{Config, DefaultPolicy, Identity, Peer, PeerPolicy},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::{
        fs::{PermissionsExt, symlink},
        process::ExitStatusExt,
    },
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// Stable process epochs used to distinguish authenticated server authorities in regressions.
const AUTHORITY_EPOCH_A: &str = "00000000-0000-4000-8000-000000000001";
/// A second process epoch for restored-server cases.
const AUTHORITY_EPOCH_B: &str = "00000000-0000-4000-8000-000000000002";

/// The worker's send handle keeps the mesh port while the factory is gone. Dropping that last
/// handle lets a new worker bind the same port, including with connected sends enabled.
#[tokio::test]
async fn worker_send_handle_releases_the_port_on_drop() {
    let key = || super::StaticSecret::from([42; 32]);
    let (factory, port) = super::bind_udp(
        crate::listen_port::Request {
            port: 0,
            allow_fallback: false,
        },
        key(),
    )
    .await
    .expect("bind a mesh port");
    let exact = crate::listen_port::Request {
        port,
        allow_fallback: false,
    };
    let worker_send = factory.send.clone();
    drop(factory);

    assert!(matches!(
        super::bind_udp(exact, key()).await,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse
    ));
    drop(worker_send);

    let (_replacement, rebound_port) = super::bind_udp(exact, key())
        .await
        .expect("rebind the released mesh port");
    assert_eq!(rebound_port, port);
}

/// The Mac mesh port answers a direct-path probe from a known peer endpoint (#220, J1206): the
/// pong leaves the mesh port with the ping's token, and a ping from an unknown source gets
/// silence. This is what a Linux peer needs to measure its direct path to a Mac.
#[tokio::test]
async fn the_mesh_port_answers_a_ping_from_a_known_endpoint_only() {
    use crate::direct_probe::{PING, PONG, frame, parse};
    use gotatun::udp::{UdpRecv, UdpTransportFactory, UdpTransportFactoryParams};
    let (mut factory, port) = super::bind_udp(
        crate::listen_port::Request {
            port: 0,
            allow_fallback: false,
        },
        super::StaticSecret::from([7; 32]),
    )
    .await
    .expect("bind a mesh port");
    let known = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("known");
    let stranger = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("stranger");
    factory
        .admission
        .write()
        .await
        .set_configured_endpoints([known.local_addr().expect("address")]);
    let (_send, mut receiver) = factory
        .bind(&UdpTransportFactoryParams { addr: None, port })
        .await
        .expect("device sockets");
    // The device's receive loop: it must see no probe, only the guard answers.
    let forwarded = std::sync::Arc::new(AtomicU64::new(0));
    let counter = std::sync::Arc::clone(&forwarded);
    let task = tokio::spawn(async move {
        let mut buffer =
            <crate::handshake_admission::PeerAdmissionUdpReceiver as UdpRecv>::RecvManyBuf::default(
            );
        let mut pool = gotatun::packet::PacketBufPool::new(8);
        let mut packets = Vec::new();
        while receiver
            .recv_many_from(&mut buffer, &mut pool, &mut packets)
            .await
            .is_ok()
        {
            counter.fetch_add(packets.len() as u64, Ordering::Relaxed);
            packets.clear();
        }
    });
    let target = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    known
        .send_to(&frame(PING, 0xABCD), target)
        .await
        .expect("ping");
    let mut reply = [0_u8; 64];
    let (length, from) = tokio::time::timeout(Duration::from_secs(2), known.recv_from(&mut reply))
        .await
        .expect("a pong arrives")
        .expect("receive");
    assert_eq!(from.port(), port, "the pong leaves the mesh port");
    assert_eq!(parse(&reply[..length]), Some((PONG, 0xABCD)));
    stranger
        .send_to(&frame(PING, 1), target)
        .await
        .expect("ping");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), stranger.recv_from(&mut reply))
            .await
            .is_err(),
        "a stranger gets silence"
    );
    assert_eq!(
        forwarded.load(Ordering::Relaxed),
        0,
        "no probe reaches GotaTun"
    );
    task.abort();
}

/// Encode a complete snapshot with one epoch repeated across every chunk.
fn chunks_with_epoch(
    old: Option<&Config>,
    new: &Config,
    authority_epoch: &str,
) -> Vec<crate::dataplane::Chunk> {
    crate::configuration::chunks(old, new)
        .expect("full snapshot")
        .into_iter()
        .map(|mut chunk| {
            chunk.authority_epoch = Some(authority_epoch.to_owned());
            chunk
        })
        .collect()
}

/// A one-peer configuration for the macOS node tests (the underlay proofs build their
/// packet filter from it too).
pub(super) fn config() -> Config {
    Config {
        authority_epoch: Some(AUTHORITY_EPOCH_A.to_owned()),
        rotation_operation: None,
        local_key: Some(PublicKey([1; 32])),
        server: Some(NodeId(1)),
        node: NodeId(2),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 3,
        addresses: Addresses {
            ipv4: Ipv4Addr::new(10, 254, 0, 1),
            ipv6: "fd01::1".parse().expect("local IPv6"),
        },
        default_policy: DefaultPolicy::Allow,
        exposure: None,
        peers: BTreeMap::from([(
            NodeId(4),
            PeerPolicy {
                peer: Peer {
                    key: PublicKey([2; 32]),
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: Ipv4Addr::new(10, 254, 0, 4),
                        ipv6: "fd01::4".parse().expect("peer IPv6"),
                    },
                    endpoint: Some("192.0.2.4:51820".parse::<SocketAddr>().expect("endpoint")),
                    candidates: Vec::new(),
                    ipv4_only: false,
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
                access_ssh: None,
                networks: crate::dataplane::PeerNetworks::default(),
            },
        )]),
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
    }
}

/// Verifies that a normal active peer gets host routes, an endpoint and a keepalive.
#[test]
fn peer_conversion_uses_host_routes_and_keepalive() {
    let config = config();
    let peers = peers_for_config(&config).expect("convert peers");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].public_key.as_bytes(), &[2; 32]);
    assert_eq!(peers[0].endpoint, config.peers[&NodeId(4)].peer.endpoint);
    assert_eq!(peers[0].keepalive, Some(25));
    assert_eq!(
        peers[0]
            .allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.254.0.4/32", "fd01::4/128"]
    );
}

/// Install both keys during overlap and leave routes only on the active key.
#[test]
fn peer_conversion_keeps_the_inactive_rotation_key_without_routes_or_endpoint() {
    let endpoint: SocketAddr = "192.0.2.4:51820".parse().expect("endpoint");
    let mut config = config();
    let policy = config.peers.get_mut(&NodeId(4)).expect("configured peer");
    policy.peer.previous_key = Some(PublicKey([7; 32]));
    policy.peer.previous_active = true;
    policy.peer.endpoint = Some(endpoint);
    let peers = peers_for_config(&config).expect("convert both rotation keys");

    assert_eq!(peers.len(), 2, "the peer accepts both overlap identities");
    let candidate = peers
        .iter()
        .find(|peer| peer.public_key.as_bytes() == &[2; 32])
        .expect("candidate identity");
    let previous = peers
        .iter()
        .find(|peer| peer.public_key.as_bytes() == &[7; 32])
        .expect("previous identity");
    assert_eq!(candidate.allowed_ips.as_slice(), &[]);
    assert_eq!(candidate.endpoint, None);
    assert!(
        previous
            .allowed_ips
            .iter()
            .any(|ip| ip.to_string() == "10.254.0.4/32")
    );
    assert_eq!(previous.endpoint, Some(endpoint));
}

/// A test peer `id` with the given inbound policy.
fn peer_policy(id: u8, inbound: TrafficPolicy) -> PeerPolicy {
    PeerPolicy {
        peer: Peer {
            key: PublicKey([id; 32]),
            previous_key: None,
            previous_active: false,
            addresses: Addresses {
                ipv4: Ipv4Addr::new(10, 254, 0, id),
                ipv6: format!("fd01::{id}").parse().expect("peer IPv6"),
            },
            endpoint: None,
            candidates: Vec::new(),
            ipv4_only: false,
        },
        inbound,
        outbound: TrafficPolicy::All,
        access_ssh: None,
        networks: crate::dataplane::PeerNetworks::default(),
    }
}

/// The device keys the Mac would install for `config`, as raw bytes for easy comparison.
fn installed_keys(config: &Config) -> BTreeSet<[u8; 32]> {
    peers_for_config(config)
        .expect("convert peers")
        .iter()
        .map(|peer| *peer.public_key.as_bytes())
        .collect()
}

/// Provide a worker that records complete configs without opening a Mac utun.
fn recording_worker(applied: Arc<Mutex<Vec<Config>>>) -> Worker {
    recording_worker_with_replace_hook(applied, |_| {})
}

/// Provide a recording worker that observes durable state when an authority replacement arrives.
fn recording_worker_with_replace_hook(
    applied: Arc<Mutex<Vec<Config>>>,
    on_replace: impl Fn(&Config) + Send + 'static,
) -> Worker {
    let (commands, mut receiver) = mpsc::unbounded_channel();
    let join = thread::spawn(move || {
        while let Some(command) = receiver.blocking_recv() {
            match command {
                WorkerCommand::Apply { config, reply, .. } => {
                    if let Ok(mut configs) = applied.lock() {
                        configs.push(config.as_ref().clone());
                    }
                    let _ = reply.send(Ok(RuntimeInfo {
                        interface: "utun-test".to_owned(),
                        port: 51820,
                        routes: route_addresses(&config),
                    }));
                }
                WorkerCommand::ReplaceAuthority { config, reply, .. } => {
                    if let Ok(mut configs) = applied.lock() {
                        configs.push(config.as_ref().clone());
                    }
                    on_replace(&config);
                    let _ = reply.send(Ok(RuntimeInfo {
                        interface: "utun-test".to_owned(),
                        port: 51820,
                        routes: route_addresses(&config),
                    }));
                }
                WorkerCommand::SetPrivateKey { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                WorkerCommand::Counters(reply) => {
                    let _ = reply.send(super::CounterMap::new());
                }
                WorkerCommand::Stop(reply) => {
                    let _ = reply.send(Ok(()));
                    break;
                }
                // A recording worker has no guard; dropping the reply tells the asker so.
                WorkerCommand::Admission(_) => {}
            }
        }
    });
    Worker {
        commands,
        join: Some(join),
    }
}

/// `GotaTun` installs granted peers even when the grant is one-way or port-narrowed.
#[test]
fn peers_with_one_way_and_port_narrowed_access_are_installed() {
    let mut config = config();
    config.peers = BTreeMap::from([
        // The coordinator is reachable by every node, whatever its inbound grant.
        (NodeId(1), peer_policy(11, TrafficPolicy::None)),
        (NodeId(4), peer_policy(4, TrafficPolicy::All)),
        // Only this Mac → 5 is granted; 5 must not reach the Mac.
        (NodeId(5), peer_policy(5, TrafficPolicy::None)),
        // 6 → Mac is narrowed to one port, which this node cannot enforce.
        (
            NodeId(6),
            peer_policy(
                6,
                TrafficPolicy::Ports(BTreeSet::from([crate::policy::rules::Port {
                    protocol: crate::policy::rules::Protocol::Tcp,
                    number: 22,
                }])),
            ),
        ),
    ]);

    assert_eq!(
        installed_keys(&config),
        BTreeSet::from([[11; 32], [4; 32], [5; 32], [6; 32]])
    );
    let routes = route_addresses(&config);
    for installed in [4, 5, 6, 11] {
        assert!(routes.contains(&IpAddr::V4(Ipv4Addr::new(10, 254, 0, installed))));
    }
    assert_eq!(super::ENFORCEMENT, "userspace");
}

/// Revoking a peer's arrow removes it from the installed peer set.
#[test]
fn revoking_an_arrow_removes_the_installed_peer() {
    let old = config();
    let identity = Identity {
        public_key: old.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: true,
    };
    assert_eq!(installed_keys(&old), BTreeSet::from([[2; 32]]));

    // The coordinator keeps the peer because Mac → 4 is still granted.
    let mut revoked = old.clone();
    revoked.version += 1;
    revoked.peers.get_mut(&NodeId(4)).expect("peer 4").inbound = TrafficPolicy::None;
    let mut pending = None;
    let mut applied = None;
    for chunk in crate::configuration::chunks(Some(&old), &revoked).expect("delta") {
        applied =
            stage_chunk(&mut pending, Some(&old), &identity, false, chunk).expect("stage delta");
    }
    let applied = applied.expect("complete revision");

    assert!(applied.peers.contains_key(&NodeId(4)));
    assert_eq!(installed_keys(&applied), BTreeSet::from([[2; 32]]));
    assert_eq!(
        route_addresses(&applied),
        BTreeSet::from([
            IpAddr::V4(Ipv4Addr::new(10, 254, 0, 4)),
            IpAddr::V6("fd01::4".parse().expect("peer IPv6")),
        ])
    );
}

/// A restored lower-revision snapshot replaces peers from the later state.
#[test]
fn restored_snapshot_replaces_stale_peers() {
    let mut current = config();
    current.version = 11;
    let directory = test_directory();
    let state_path = directory.join(PUBLIC_STATE);
    let store = crate::node_state::Store::open_for_macos(&directory.0)
        .expect("open persisted replacement store");
    write_public_state(
        &state_path,
        &SavedState {
            enabled: true,
            config: Some(current.clone()),
            routes: route_addresses(&current),
            interface: Some("utun-test".to_owned()),
            port: 51820,
            ..SavedState::default()
        },
    )
    .expect("persist the exact base for the lower-revision transaction");
    let mut restored = current.clone();
    restored.version = 2;
    restored.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    restored.peers.clear();
    let identity = Identity {
        public_key: current.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: true,
    };
    let applied_configs = Arc::new(Mutex::new(Vec::new()));
    let mut node = Node {
        enabled: true,
        worker: Some(recording_worker(Arc::clone(&applied_configs))),
        store: Some(store),
        identity: Some(identity),
        config: Some(current.clone()),
        authority_reset_pending: false,
        pending: None,
        routes: route_addresses(&current),
        interface: Some("utun-test".to_owned()),
        port: 51820,
        path: Some(state_path),
        binding: None,
        network_status: super::subnet::NetworkStatus::default(),
    };
    for chunk in chunks_with_epoch(None, &current, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).expect("initial epoch snapshot");
    }
    applied_configs.lock().expect("recorded configs").clear();
    let mut applied = false;
    for chunk in chunks_with_epoch(None, &restored, AUTHORITY_EPOCH_A) {
        applied = node
            .chunk(chunk)
            .expect("same-authority lower revision should replace the snapshot");
    }

    assert!(applied, "the full restored snapshot was not committed");
    let installed = node.config().expect("accepted configuration");
    assert_eq!(installed.version, 2);
    assert!(installed.peers.is_empty());
    assert!(installed_keys(installed).is_empty());
    let applied_configs = applied_configs.lock().expect("recorded configs");
    assert_eq!(applied_configs.len(), 1, "one ordinary replacement apply");
    assert!(applied_configs[0].peers.is_empty());
}

/// A same-authority full snapshot cannot change accepted contents at an equal revision.
#[test]
fn same_authority_equal_revision_conflict_is_refused() {
    let mut current = config();
    current.version = 11;
    let mut conflicting = current.clone();
    conflicting.peers.clear();
    let identity = Identity {
        public_key: current.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: true,
    };
    let applied_configs = Arc::new(Mutex::new(Vec::new()));
    let mut node = Node {
        enabled: true,
        worker: Some(recording_worker(Arc::clone(&applied_configs))),
        store: None,
        identity: Some(identity),
        config: Some(current.clone()),
        authority_reset_pending: false,
        pending: None,
        routes: route_addresses(&current),
        interface: Some("utun-test".to_owned()),
        port: 51820,
        path: None,
        binding: None,
        network_status: super::subnet::NetworkStatus::default(),
    };
    let result = chunks_with_epoch(None, &conflicting, AUTHORITY_EPOCH_A)
        .into_iter()
        .try_for_each(|chunk| node.chunk(chunk).map(|_| ()));
    let retained = node.config().cloned();
    let applied_configs = applied_configs.lock().expect("recorded configs").clone();
    node.down().expect("stop test worker");

    assert!(
        result.is_err(),
        "same-authority equal-revision conflict was accepted"
    );
    assert_eq!(retained, Some(current));
    assert!(
        applied_configs.is_empty(),
        "the conflicting config reached the worker"
    );
}

/// A same-revision restore from another authority must retire the previous peer set.
#[test]
fn equal_revision_restore_retires_stale_peers() {
    let mut current = config();
    current.version = 11;
    let mut restored = current.clone();
    restored.peers.clear();
    restored.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    let identity = Identity {
        public_key: current.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: true,
    };
    let applied_configs = Arc::new(Mutex::new(Vec::new()));
    let mut node = Node {
        enabled: true,
        worker: Some(recording_worker(Arc::clone(&applied_configs))),
        store: None,
        identity: Some(identity),
        config: Some(current.clone()),
        authority_reset_pending: false,
        pending: None,
        routes: route_addresses(&current),
        interface: Some("utun-test".to_owned()),
        port: 51820,
        path: None,
        binding: None,
        network_status: super::subnet::NetworkStatus::default(),
    };
    for chunk in chunks_with_epoch(None, &current, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).expect("current epoch snapshot");
    }
    applied_configs.lock().expect("recorded configs").clear();
    let result = chunks_with_epoch(None, &restored, AUTHORITY_EPOCH_B)
        .into_iter()
        .try_for_each(|chunk| node.chunk(chunk).map(|_| ()));
    let retained = node.config().cloned();
    let applied_configs = applied_configs.lock().expect("recorded configs").clone();
    node.down().expect("stop test worker");

    assert!(
        result.is_ok(),
        "equal-revision restore was refused: {result:?}"
    );
    assert_eq!(retained, Some(restored));
    assert_eq!(
        applied_configs.len(),
        1,
        "install the complete replacement once"
    );
    assert!(applied_configs[0].peers.is_empty());
}

/// Keep current Mac peers live while a new authority snapshot is incomplete, then replace them once.
#[test]
fn authority_replacement_waits_for_complete_snapshot_before_worker_replacement() {
    let current = config();
    let mut replacement = current.clone();
    replacement.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    let identity = Identity {
        public_key: current.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: true,
    };
    let applied_configs = Arc::new(Mutex::new(vec![current.clone()]));
    let mut node = Node {
        enabled: true,
        worker: Some(recording_worker(Arc::clone(&applied_configs))),
        store: None,
        identity: Some(identity),
        config: Some(current.clone()),
        authority_reset_pending: false,
        pending: None,
        routes: route_addresses(&current),
        interface: Some("utun-test".to_owned()),
        port: 51820,
        path: None,
        binding: None,
        network_status: super::subnet::NetworkStatus::default(),
    };
    let mut complete = chunks_with_epoch(None, &replacement, AUTHORITY_EPOCH_B)
        .pop()
        .expect("one full snapshot");
    let mut first = complete.clone();
    first.last = false;
    complete.index = 1;
    complete.last = true;
    complete.upserted.clear();
    complete.merged.clear();
    complete.removed.clear();
    #[cfg(feature = "mesh-dns")]
    {
        complete.peer_names.clear();
        complete.removed_peer_names.clear();
    }

    let staged = node.chunk(first);
    let config_while_staged = node.config().cloned();
    let runtime_while_staged = applied_configs.lock().expect("runtime log").clone();
    let applied = node.chunk(complete);
    let accepted = node.config().cloned();
    let runtime = applied_configs.lock().expect("runtime log").clone();
    node.down().expect("stop test worker");

    assert!(
        matches!(staged, Ok(false)),
        "the first part should remain staged: {staged:?}"
    );
    assert_eq!(config_while_staged, Some(current.clone()));
    assert_eq!(runtime_while_staged, vec![current.clone()]);
    assert!(
        matches!(applied, Ok(true)),
        "the full snapshot should be applied: {applied:?}"
    );
    assert_eq!(accepted, Some(replacement.clone()));
    assert_eq!(runtime, vec![current, replacement]);
}

/// Two peers with the same key and addresses make the whole snapshot invalid.
#[test]
fn accepted_configuration_rejects_duplicate_peer_identity_and_addresses() {
    let mut config = config();
    let peer = config.peers[&NodeId(4)].clone();
    config.peers.insert(NodeId(5), peer);

    assert_eq!(
        validate_config(&config, PublicKey([1; 32]))
            .expect_err("duplicate peer data must be rejected")
            .kind(),
        std::io::ErrorKind::InvalidData
    );
}

/// A staged configuration is accepted only with its last chunk.
#[test]
fn staged_configuration_is_not_accepted_until_its_last_chunk() {
    let config = config();
    let identity = Identity {
        public_key: config.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: true,
    };
    let mut chunks = crate::configuration::chunks(None, &config).expect("full snapshot");
    assert_eq!(chunks.len(), 1);
    let mut first = chunks.pop().expect("first part");
    first.last = false;
    let mut last = first.clone();
    last.index = 1;
    last.last = true;
    last.upserted.clear();
    last.merged.clear();
    last.removed.clear();
    last.access_updates.clear();
    #[cfg(feature = "mesh-dns")]
    {
        last.peer_names.clear();
        last.removed_peer_names.clear();
    }

    let mut pending = None;
    assert!(
        stage_chunk(&mut pending, None, &identity, false, first)
            .expect("stage first part")
            .is_none()
    );
    assert_eq!(
        stage_chunk(&mut pending, None, &identity, false, last).expect("finish snapshot"),
        Some(config)
    );
}

/// A lower same-authority revision needs a persisted exact-base replacement transaction.
#[test]
fn lower_same_epoch_snapshot_requires_persisted_replacement_path() {
    let mut accepted = config();
    accepted.version = 11;
    let mut replacement = accepted.clone();
    replacement.version = 2;
    replacement.peers.clear();
    let identity = Identity {
        public_key: accepted.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: true,
    };

    let mut pending = None;
    let refused = stage_chunk(
        &mut pending,
        Some(&accepted),
        &identity,
        false,
        chunks_with_epoch(None, &replacement, AUTHORITY_EPOCH_A).remove(0),
    )
    .expect_err("an in-memory snapshot cannot authorize a revision rewind");
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);

    assert_eq!(
        stage_chunk(
            &mut pending,
            Some(&accepted),
            &identity,
            true,
            chunks_with_epoch(None, &replacement, AUTHORITY_EPOCH_A).remove(0),
        )
        .expect("stage the Store-backed transaction"),
        Some(replacement)
    );
}

/// The persisted rollback transaction must compare the exact accepted base before writing.
#[test]
fn lower_revision_public_snapshot_requires_exact_stored_base() {
    let directory =
        std::env::temp_dir().join(format!("j287-mac-lower-revision-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).expect("create state directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("protect state directory");
    let path = directory.join(PUBLIC_STATE);
    let mut accepted = config();
    accepted.version = 11;
    let initial = SavedState {
        config: Some(accepted.clone()),
        routes: route_addresses(&accepted),
        ..SavedState::default()
    };
    write_public_state(&path, &initial).expect("save accepted base");

    let mut replacement = accepted.clone();
    replacement.version = 2;
    replacement.peers.clear();
    let next = SavedState {
        config: Some(replacement.clone()),
        routes: route_addresses(&replacement),
        ..SavedState::default()
    };
    let mut stale_base = accepted.clone();
    stale_base.version = 10;
    assert_eq!(
        write_public_state_full_snapshot(&path, &next, &stale_base)
            .expect_err("a stale base must not authorize replacement")
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        read_public_state(&path)
            .expect("read unchanged base")
            .and_then(|state| state.config),
        Some(accepted.clone())
    );

    write_public_state_full_snapshot(&path, &next, &accepted)
        .expect("replace the exact durable base");
    assert_eq!(
        read_public_state(&path)
            .expect("read replacement")
            .and_then(|state| state.config),
        Some(replacement)
    );
    fs::remove_dir_all(directory).expect("remove state directory");
}

/// The Mac utun parser follows the current peer route budget, including a larger normal path.
#[test]
fn utun_frame_uses_kernel_family_prefix_and_checks_ip_version() {
    let ipv4 = [0, 0, 0, 2, 0x45];
    let ipv6 = [0, 0, 0, 30, 0x60];

    assert_eq!(utun_family(&ipv4[4..]).expect("IPv4 family"), 2);
    assert_eq!(utun_family(&ipv6[4..]).expect("IPv6 family"), 30);
    assert_eq!(
        parse_utun_payload(&ipv4, crate::mesh_mtu::IPV6_MINIMUM_MTU).expect("IPv4 payload"),
        &ipv4[4..]
    );
    assert_eq!(
        parse_utun_payload(&ipv6, crate::mesh_mtu::IPV6_MINIMUM_MTU).expect("IPv6 payload"),
        &ipv6[4..]
    );
    let mut normal_path = vec![0, 0, 0, 2];
    normal_path.resize(4 + 1420, 0);
    normal_path[4] = 0x45;
    assert!(parse_utun_payload(&normal_path, 1420).is_ok());
}

/// Rejects malformed utun family prefixes and packets above the current route budget.
#[test]
fn utun_frame_rejects_truncation_unknown_family_and_mismatch() {
    assert!(parse_utun_payload(&[0, 0, 0], 1280).is_err());
    assert!(parse_utun_payload(&[0, 0, 0, 99, 0x45], 1280).is_err());
    assert!(parse_utun_payload(&[0, 0, 0, 2, 0x60], 1280).is_err());
    assert!(utun_family(&[]).is_err());
    assert!(utun_family(&[0x75]).is_err());
    let mut oversized = vec![0, 0, 0, 2];
    oversized.resize(4 + 1281, 0);
    oversized[4] = 0x45;
    assert!(parse_utun_payload(&oversized, 1280).is_err());
}

/// The saved public snapshot restores without carrying any private key material.
#[test]
fn saved_public_config_restores_without_private_key_material() {
    let directory = test_directory();
    let path = directory.join(PUBLIC_STATE);
    let state = SavedState {
        enabled: true,
        config: Some(config()),
        authority_reset_pending: false,
        routes: route_addresses(&config()),
        interface: Some("utun7".to_owned()),
        port: 51831,
        backend: None,
        binding: None,
    };

    write_public_state(&path, &state).expect("persist public config");
    let restored = read_public_state(&path)
        .expect("read public config")
        .expect("saved config");
    assert_eq!(restored.config, state.config);
    assert_eq!(restored.routes, state.routes);
    assert_eq!(restored.interface, state.interface);
    assert_eq!(restored.port, state.port);
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    let body = fs::read_to_string(path).expect("read public bytes");
    assert!(!body.contains("private_key"));
    assert!(!body.contains("secret"));
}

/// A Mac with no saved state starts enabled, with no snapshot, port, utun or routes.
#[test]
fn absent_state_defaults_to_enabled_without_a_saved_config() {
    let state = SavedState::default();
    assert!(state.enabled);
    assert!(state.config.is_none());
    assert_eq!(state.port, 0);
    assert!(state.interface.is_none());
    assert!(state.routes.is_empty());
}

/// Restore public state from the agent directory owned by the macOS service.
#[test]
fn restore_uses_the_agent_state_directory() {
    let directory = test_directory();
    let state = SavedState {
        enabled: false,
        config: None,
        authority_reset_pending: false,
        routes: BTreeSet::new(),
        interface: None,
        port: 0,
        backend: None,
        binding: None,
    };
    write_public_state(&directory.join(PUBLIC_STATE), &state).expect("write public state");

    let restored = Node::restore(&directory.0, None).expect("restore from agent state directory");

    assert!(!restored.enabled());
    assert!(directory.join(PUBLIC_STATE).is_file());
}

/// A committed Mac journal authorizes only its candidate binding at the same policy revision.
#[test]
fn macos_store_accepts_a_journal_proven_same_revision_binding_advance() {
    let directory = test_directory();
    let previous = [0x11; 32];
    let candidate = [0x22; 32];
    let previous_secret = gotatun::x25519::StaticSecret::from(previous);
    let candidate_secret = gotatun::x25519::StaticSecret::from(candidate);
    let previous_public = PublicKey(*gotatun::x25519::PublicKey::from(&previous_secret).as_bytes());
    let candidate_public =
        PublicKey(*gotatun::x25519::PublicKey::from(&candidate_secret).as_bytes());
    let mut accepted = config();
    accepted.local_key = Some(previous_public);
    accepted.version = 7;
    let mut state = crate::node_state::State {
        enabled: true,
        config: Some(accepted),
        authority_reset_pending: false,
    };
    let (store, _) = crate::node_state::Store::open(&directory.0).expect("open node state");
    store
        .save(&state)
        .expect("save accepted predecessor binding");
    store
        .save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
            sequence: 1,
            previous,
            candidate,
            commit_requested: true,
            completed: false,
        })
        .expect("save commit intent");
    store
        .record_interface(&candidate_public)
        .expect("record candidate interface identity");
    store
        .write_private_key(&candidate)
        .expect("save candidate private key");
    state.config.as_mut().expect("accepted config").local_key = Some(candidate_public);

    store
        .save(&state)
        .expect("advance only the journal-proven binding");
    let (_, restored) =
        crate::node_state::Store::open(&directory.0).expect("restore candidate binding");
    assert_eq!(
        restored.config.and_then(|config| config.local_key),
        Some(candidate_public)
    );
}

/// A finished Mac marker authorizes only its predecessor or candidate snapshot key.
#[test]
fn macos_completed_snapshot_binding_rejects_an_unrelated_key() {
    let directory = test_directory();
    let previous = [0x11; 32];
    let candidate = [0x22; 32];
    let unrelated = [0x33; 32];
    let public = |private| {
        let secret = gotatun::x25519::StaticSecret::from(private);
        PublicKey(*gotatun::x25519::PublicKey::from(&secret).as_bytes())
    };
    let previous_public = public(previous);
    let candidate_public = public(candidate);
    let unrelated_public = public(unrelated);
    let store = crate::node_state::Store::open_for_macos(&directory.0).expect("open Mac store");
    store
        .record_interface(&candidate_public)
        .expect("candidate interface record");
    store
        .write_private_key(&candidate)
        .expect("candidate key file");
    store
        .save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
            sequence: 1,
            previous,
            candidate,
            commit_requested: true,
            completed: false,
        })
        .expect("commit intent");
    store
        .complete_rotation_secret("00000000-0000-4000-8000-000000000367", 1)
        .expect("finish rotation");

    assert!(macos_snapshot_binding_is_authorized(&store, previous_public).expect("old"));
    assert!(macos_snapshot_binding_is_authorized(&store, candidate_public).expect("new"));
    assert!(
        !macos_snapshot_binding_is_authorized(&store, unrelated_public).expect("unrelated"),
        "a completed marker does not authorize an unrelated saved binding"
    );
}

/// The macOS `GotaTun` node advertises and completes the durable key-rotation protocol.
#[test]
#[ignore = "Run on the macOS VM with system service privileges."]
fn macos_gotatun_node_supports_key_rotation() {
    let directory = test_directory();
    let mut node = Node::restore(&directory.0, None).expect("restore Mac node");
    let previous = node.up().expect("start GotaTun");
    assert!(previous.key_rotation, "macOS offers durable rotation");

    let operation = "00000000-0000-4000-8000-000000000051";
    let candidate = node
        .prepare_rotation(operation, 1)
        .expect("prepare rotation");
    assert_ne!(candidate, previous.public_key);
    assert_eq!(
        node.prepare_rotation(operation, 1)
            .expect("retry prepare rotation"),
        candidate,
        "a retry returns the journaled candidate"
    );
    assert_eq!(
        node.finish_rotation(operation, 1)
            .expect_err("an uncommitted candidate cannot finish")
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        node.commit_rotation(operation, 2)
            .expect_err("a stale sequence cannot commit")
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    let committed = node.commit_rotation(operation, 1).expect("commit rotation");
    assert_eq!(committed.public_key, candidate);
    assert_eq!(
        node.commit_rotation(operation, 1)
            .expect("retry commit rotation")
            .public_key,
        candidate,
        "a retry leaves the committed identity stable"
    );
    let (_, persisted) = crate::macos_key::load_or_create(&directory.0).expect("read key file");
    assert_eq!(persisted, candidate);
    node.finish_rotation(operation, 1).expect("finish rotation");
    node.finish_rotation(operation, 1)
        .expect("retry finish rotation");
    node.down().expect("stop GotaTun");
}

/// Preparing the same Mac rotation twice returns its original journaled candidate.
#[test]
#[ignore = "Run on the macOS VM with system service privileges."]
fn macos_gotatun_rotation_prepare_is_retryable() {
    let directory = test_directory();
    let mut node = Node::restore(&directory.0, None).expect("restore Mac node");
    node.up().expect("start GotaTun");

    let operation = "00000000-0000-4000-8000-000000000052";
    let first = node.prepare_rotation(operation, 1);
    let second = first
        .as_ref()
        .ok()
        .map(|_| node.prepare_rotation(operation, 1));
    node.down().expect("stop GotaTun");

    let candidate = first.expect("prepare rotation");
    assert_eq!(
        second
            .expect("retry was attempted")
            .expect("retry prepare rotation"),
        candidate
    );
}

/// Exercise the child side of [`macos_rotation_recovers_after_sigkill_at_each_durable_step`].
#[test]
#[ignore = "launched by the macOS GotaTun SIGKILL recovery proof"]
fn macos_rotation_crash_child() {
    let state = std::env::var_os("INFRATERNAL_MAC_ROTATION_STATE")
        .expect("the parent supplies an isolated Mac state directory");
    let state = PathBuf::from(state);
    let mut node = Node::restore(&state, None).expect("restore Mac rotation child");
    let previous = node.up().expect("start the Mac GotaTun node");
    assert!(previous.key_rotation, "macOS offers durable rotation");
    fs::write(
        state.join("rotation-crash-previous-public"),
        previous.public_key.0,
    )
    .expect("save the public predecessor for the parent proof");
    let operation = "00000000-0000-4000-8000-000000000367";
    node.prepare_rotation(operation, 1)
        .expect("prepare Mac key rotation");
    rotation_crash_checkpoint("rotation_prepared");
    node.commit_rotation(operation, 1)
        .expect("commit Mac key rotation");
    node.finish_rotation(operation, 1)
        .expect("finish Mac key rotation");
    rotation_crash_checkpoint("rotation_finished");
    panic!("the requested Mac crash boundary was never reached");
}

/// Exercise the child side of [`macos_authority_replacement_recovers_after_sigkill`].
#[test]
#[ignore = "launched by the Mac authority replacement SIGKILL proof"]
fn macos_authority_replacement_crash_child() {
    let state = std::env::var_os("INFRATERNAL_MAC_AUTHORITY_STATE")
        .expect("the parent supplies an isolated Mac state directory");
    let state = PathBuf::from(state);
    let mut node = Node::restore(&state, None).expect("restore Mac authority child");
    let identity = node.up().expect("start the Mac mesh node");
    let mut current = config();
    current.local_key = Some(identity.public_key);
    for chunk in crate::configuration::chunks(None, &current).expect("authority A snapshot") {
        node.chunk(chunk).expect("install authority A");
    }
    let mut replacement = current;
    replacement.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    for chunk in crate::configuration::chunks(None, &replacement).expect("authority B snapshot") {
        node.chunk(chunk).expect("stage authority B");
    }
    panic!("the requested Mac authority crash boundary was never reached");
}

/// SIGKILL at every Mac rotation write leaves a journal that restarts on an authorized key.
#[test]
#[ignore = "Run on the macOS VM with system service privileges."]
fn macos_rotation_recovers_after_sigkill_at_each_durable_step() {
    let stages = [
        "rotation_prepared",
        "rotation_commit_requested",
        "rotation_device_key_changed",
        "rotation_interface_recorded",
        "rotation_private_key_saved",
        "rotation_finished",
    ];
    for stage in stages {
        let directory = test_directory();
        let ready = directory.join("rotation-crash-ready");
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            .args(["--ignored", "macos_rotation_crash_child", "--nocapture"])
            .env("INFRATERNAL_MAC_ROTATION_STATE", &directory.0)
            .env("INFRATERNAL_MAC_ROTATION_CRASH_POINT", stage)
            .env("INFRATERNAL_MAC_ROTATION_CRASH_READY", &ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the Mac rotation child");
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ready.exists() {
            if let Some(status) = child.try_wait().expect("check the Mac rotation child") {
                let output = child
                    .wait_with_output()
                    .expect("collect the Mac child's failure");
                panic!(
                    "Mac child exited before {stage}: {status}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert!(Instant::now() < deadline, "Mac child did not reach {stage}");
            // sleep: let the child publish its next durable rotation boundary.
            thread::sleep(Duration::from_millis(10));
        }
        child.kill().expect("send SIGKILL at the Mac boundary");
        let status = child.wait().expect("reap the killed Mac child");
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL), "stage {stage}");

        let previous: [u8; 32] = fs::read(directory.join("rotation-crash-previous-public"))
            .expect("child recorded the predecessor")
            .try_into()
            .expect("public key length");
        let journal = zeroize::Zeroizing::new(
            fs::read(directory.join("mesh-key-rotation.bin"))
                .expect("prepared Mac journal survives SIGKILL"),
        );
        assert_eq!(journal.len(), 117, "stage {stage}");
        assert_eq!(&journal[..8], b"IMKEYV1\0", "stage {stage}");
        assert_eq!(
            u64::from_le_bytes(journal[9..17].try_into().expect("sequence bytes")),
            1,
            "stage {stage}"
        );
        assert_eq!(
            &journal[17..53],
            b"00000000-0000-4000-8000-000000000367",
            "stage {stage}"
        );
        let completed = stage == "rotation_finished";
        assert_eq!(
            journal[8],
            match stage {
                "rotation_finished" => 2,
                "rotation_prepared" => 0,
                _ => 1,
            }
        );
        if completed {
            assert_eq!(
                &journal[53..85],
                &previous,
                "finish keeps only the predecessor's public key"
            );
        }
        let previous_public = if completed {
            PublicKey(
                journal[53..85]
                    .try_into()
                    .expect("predecessor public bytes"),
            )
        } else {
            mac_private_public(&journal[53..85])
        };
        let candidate_public = mac_private_public(&journal[85..117]);
        assert_eq!(previous_public.0, previous, "stage {stage}");

        let key_file = zeroize::Zeroizing::new(
            fs::read(directory.join(crate::macos_key::KEY_FILE))
                .expect("Mac key file survives SIGKILL"),
        );
        let expected_file = if matches!(stage, "rotation_private_key_saved" | "rotation_finished") {
            candidate_public
        } else {
            previous_public
        };
        assert_eq!(
            mac_private_public(&key_file),
            expected_file,
            "key file at {stage}"
        );
        let recorded: PublicKey = serde_json::from_slice(
            &fs::read(directory.join("mesh-interface.json")).expect("recorded Mac identity"),
        )
        .expect("valid recorded Mac identity");
        let expected_record = if matches!(
            stage,
            "rotation_interface_recorded" | "rotation_private_key_saved" | "rotation_finished"
        ) {
            candidate_public
        } else {
            previous_public
        };
        assert_eq!(recorded, expected_record, "interface record at {stage}");

        let expected_live = if stage == "rotation_prepared" {
            previous_public
        } else {
            candidate_public
        };
        let mut restored = Node::restore(&directory.0, None).expect("restore after Mac SIGKILL");
        let identity = restored.up().expect("restart the Mac GotaTun node");
        assert!(
            identity.key_rotation,
            "Mac rotation support survives restart"
        );
        assert_eq!(
            identity.public_key, expected_live,
            "recovered key at {stage}"
        );
        restored
            .commit_rotation("00000000-0000-4000-8000-000000000367", 1)
            .expect("retry Mac commit after restart");
        restored
            .finish_rotation("00000000-0000-4000-8000-000000000367", 1)
            .expect("retry Mac finish after restart");
        restored.down().expect("stop restored Mac node");
    }
}

/// SIGKILL after the new epoch is saved but before worker replacement cannot restore A's peers.
#[test]
#[ignore = "Run on the macOS VM with system service privileges."]
fn macos_authority_replacement_recovers_after_sigkill() {
    let directory = test_directory();
    // Reuse the isolated key-file path so this crash proof never retires a host System keychain item.
    write_key(&directory);
    let ready = directory.join("authority-replacement-ready");
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--ignored",
            "macos_authority_replacement_crash_child",
            "--nocapture",
        ])
        .env("INFRATERNAL_MAC_AUTHORITY_STATE", &directory.0)
        .env("INFRATERNAL_MAC_AUTHORITY_REPLACEMENT_READY", &ready)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the Mac authority child");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready.exists() {
        if let Some(status) = child.try_wait().expect("check the Mac authority child") {
            let output = child
                .wait_with_output()
                .expect("collect the Mac authority child failure");
            panic!(
                "Mac child exited before replacement persistence: {status}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "Mac child did not reach replacement persistence"
        );
        // sleep: let the child publish the durable replacement boundary.
        thread::sleep(Duration::from_millis(10));
    }
    child
        .kill()
        .expect("send SIGKILL at the Mac authority boundary");
    let status = child.wait().expect("reap the killed Mac authority child");
    assert_eq!(status.signal(), Some(nix::libc::SIGKILL));

    let saved = read_public_state(&directory.join(PUBLIC_STATE))
        .expect("read replacement state")
        .expect("replacement state survived SIGKILL");
    let denied = saved.config.expect("peer-free replacement state");
    assert_eq!(denied.authority_epoch.as_deref(), Some(AUTHORITY_EPOCH_B));
    assert!(
        denied.peers.is_empty(),
        "authority A peers survived SIGKILL"
    );
    assert_eq!(denied.default_policy, DefaultPolicy::Deny);
    assert!(saved.authority_reset_pending);

    let mut restored = Node::restore(&directory.0, None).expect("restore Mac node");
    restored.up().expect("start from peer-free saved state");
    assert!(
        restored.counters().expect("read restored peers").is_empty(),
        "authority A peers were reinstalled after SIGKILL"
    );
    restored.down().expect("stop restored Mac node");
}

/// Derive a public identity from a private crash-fixture key without formatting its bytes.
fn mac_private_public(bytes: &[u8]) -> PublicKey {
    let raw: [u8; 32] = bytes.try_into().expect("32-byte private key");
    let secret = gotatun::x25519::StaticSecret::from(raw);
    PublicKey(*gotatun::x25519::PublicKey::from(&secret).as_bytes())
}

/// An enrolment binding for `coordinator` with a fixed host id and agent key.
fn enrolment(coordinator: &[u8]) -> Enrolment {
    Enrolment::new(coordinator, "8c1f0d2e-host", b"agent public key")
}

/// Build saved state with the requested enrollment binding for restore tests.
fn bound_state(binding: Option<Enrolment>) -> SavedState {
    SavedState {
        enabled: false,
        config: Some(config()),
        authority_reset_pending: false,
        routes: route_addresses(&config()),
        interface: Some("utun7".to_owned()),
        port: 51831,
        backend: None,
        binding,
    }
}

/// Write a fixed mesh key file with the 0600 mode the node requires.
fn write_key(directory: &TestDirectory) {
    let path = directory.join(crate::macos_key::KEY_FILE);
    fs::write(&path, [9_u8; 32]).expect("write key");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("key mode");
}

/// #265 P2-1 / #325: another coordinator's peers must never be restored.
#[test]
fn state_from_another_enrolment_is_discarded_and_the_key_rotates() {
    let old = enrolment(b"coordinator A");
    let new = enrolment(b"coordinator B");
    let (state, rotate) = reconcile(bound_state(Some(old.clone())), Some(&new));
    assert!(rotate);
    assert!(state.config.is_none());
    assert!(state.routes.is_empty());
    assert!(state.interface.is_none());
    assert_eq!(state.binding, Some(new.clone()));

    for changed in [
        Enrolment::new(b"coordinator A", "another-host", b"agent public key"),
        Enrolment::new(b"coordinator A", "8c1f0d2e-host", b"new agent key"),
    ] {
        assert!(reconcile(bound_state(Some(old.clone())), Some(&changed)).1);
    }

    let (same, rotate) = reconcile(bound_state(Some(old.clone())), Some(&old));
    assert!(!rotate);
    assert_eq!(same.config, Some(config()));
}

/// J162 F3: unbound (slice-1) state may hold another coordinator's peers.
#[test]
fn unbound_state_is_discarded_like_another_enrolment() {
    let current = enrolment(b"coordinator B");
    let (state, rotate) = reconcile(bound_state(None), Some(&current));
    assert!(rotate);
    assert!(state.config.is_none());
    assert!(state.routes.is_empty());
    assert!(state.interface.is_none());
    assert_eq!(state.binding, Some(current));
    // Without identity.json there is nothing to compare against.
    let (state, rotate) = reconcile(bound_state(None), None);
    assert!(!rotate);
    assert!(state.binding.is_none());
}

/// The `reason=` field of every line in the key-rotation log, in order (empty without a log).
fn rotation_reasons(directory: &TestDirectory) -> Vec<String> {
    fs::read_to_string(directory.join(crate::macos_key::ROTATION_LOG))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            line.split(' ')
                .find_map(|field| field.strip_prefix("reason="))
        })
        .map(str::to_owned)
        .collect()
}

/// State from an unbound (slice-1) node loses its key and peers once, then keeps everything.
#[test]
fn restoring_unbound_state_removes_the_key_and_logs_why() {
    let directory = test_directory();
    // Bind while empty: state with no record is refused.
    bind_this_mac(&directory);
    let current = enrolment(b"coordinator B");
    write_public_state(&directory.join(PUBLIC_STATE), &bound_state(None))
        .expect("write slice-1 state");
    write_key(&directory);

    Node::restore(&directory.0, Some(&current)).expect("restore unbound state");
    assert!(!directory.join(crate::macos_key::KEY_FILE).exists());
    assert_eq!(rotation_reasons(&directory), ["enrolment_changed"]);
    let persisted = read_public_state(&directory.join(PUBLIC_STATE))
        .expect("read state")
        .expect("state persisted");
    assert!(persisted.config.is_none());
    assert_eq!(persisted.binding, Some(current.clone()));

    // Once bound, a restart keeps everything and logs nothing more.
    write_key(&directory);
    Node::restore(&directory.0, Some(&current)).expect("restore bound state");
    assert!(directory.join(crate::macos_key::KEY_FILE).is_file());
    assert_eq!(rotation_reasons(&directory), ["enrolment_changed"]);
}

/// Restoring under a new enrolment retires the old key and records the new binding.
#[test]
fn restore_under_a_new_enrolment_removes_the_old_key_and_records_the_binding() {
    let directory = test_directory();
    // Bind while empty: state with no record is refused.
    bind_this_mac(&directory);
    let old = enrolment(b"coordinator A");
    let new = enrolment(b"coordinator B");
    write_public_state(
        &directory.join(PUBLIC_STATE),
        &bound_state(Some(old.clone())),
    )
    .expect("write old state");
    write_key(&directory);

    Node::restore(&directory.0, Some(&old)).expect("restore same enrolment");
    assert!(directory.join(crate::macos_key::KEY_FILE).is_file());

    Node::restore(&directory.0, Some(&new)).expect("restore new enrolment");
    assert!(!directory.join(crate::macos_key::KEY_FILE).exists());
    assert_eq!(rotation_reasons(&directory), ["enrolment_changed"]);
    let persisted = read_public_state(&directory.join(PUBLIC_STATE))
        .expect("read state")
        .expect("state persisted");
    assert_eq!(persisted.binding, Some(new));
    assert!(persisted.config.is_none());
}

/// Forgetting removes the public state and the key, logs one rotation, and is idempotent.
#[test]
fn forgetting_removes_the_public_state_and_the_key() {
    let directory = test_directory();
    write_public_state(&directory.join(PUBLIC_STATE), &bound_state(None)).expect("state");
    write_key(&directory);
    super::forget(&directory.0).expect("forget");
    assert!(!directory.join(PUBLIC_STATE).exists());
    assert!(!directory.join(crate::macos_key::KEY_FILE).exists());
    // J162 F4: the coordinator must learn the new key, so the rotation is logged once.
    assert_eq!(rotation_reasons(&directory), ["enrolment_changed"]);
    super::forget(&directory.0).expect("forgetting twice succeeds");
    super::forget(&directory.join("absent")).expect("an absent directory is fine");
}

/// The public-state reader never follows a symlink planted at the state path.
#[test]
fn public_config_reader_refuses_a_symlink() {
    let directory = test_directory();
    let target = directory.join("target");
    fs::write(&target, b"{}").expect("target");
    let path = directory.join(PUBLIC_STATE);
    symlink(&target, &path).expect("state symlink");

    assert!(read_public_state(&path).is_err());
}

/// Root mode's host-route inventory is exactly the peers' mesh host addresses.
#[test]
fn route_inventory_contains_only_peer_host_addresses() {
    let routes = route_addresses(&config());
    assert_eq!(
        routes,
        [
            IpAddr::V4(Ipv4Addr::new(10, 254, 0, 4)),
            IpAddr::V6("fd01::4".parse().expect("peer IPv6")),
        ]
        .into_iter()
        .collect()
    );
}

/// A full update must refresh a retained peer when its route-derived MTU changes.
#[test]
fn full_peer_update_refreshes_existing_peer_route_mtu() {
    let old_routes: BTreeSet<IpAddr> = [
        IpAddr::V4(Ipv4Addr::new(10, 254, 0, 4)),
        IpAddr::V6("fd01::4".parse().expect("peer IPv6")),
    ]
    .into_iter()
    .collect();
    let new_routes: BTreeSet<IpAddr> = [
        IpAddr::V4(Ipv4Addr::new(10, 254, 0, 4)),
        IpAddr::V6("fd01::4".parse().expect("peer IPv6")),
        IpAddr::V4(Ipv4Addr::new(10, 254, 0, 5)),
        IpAddr::V6("fd01::5".parse().expect("new peer IPv6")),
    ]
    .into_iter()
    .collect();
    let old_mtus = old_routes
        .iter()
        .copied()
        .map(|route| (route, 1420))
        .collect();
    let new_mtus = new_routes
        .iter()
        .copied()
        .map(|route| (route, 1200))
        .collect();

    let refreshed = route_mtus_to_refresh(&old_routes, &new_routes, &old_mtus, &new_mtus);

    assert_eq!(refreshed, old_routes);
}

/// Only `utun` plus digits counts as a utun name, so saved state cannot aim cleanup elsewhere.
#[test]
fn stale_route_cleanup_accepts_only_kernel_assigned_utun_names() {
    assert!(valid_utun_name("utun0"));
    assert!(valid_utun_name("utun42"));
    assert!(!valid_utun_name("utun"));
    assert!(!valid_utun_name("utun1;rm"));
    assert!(!valid_utun_name("en0"));
}

/// Invalid saved utun names never authorize deleting routes from another interface.
#[test]
fn restore_does_not_delete_routes_using_a_released_utun_name() {
    let directory = test_directory();
    let state = SavedState {
        enabled: false,
        config: None,
        authority_reset_pending: false,
        routes: ["192.0.2.1".parse().expect("stale route")].into(),
        interface: Some("utun99999".to_owned()),
        port: 0,
        backend: None,
        binding: None,
    };
    write_public_state(&directory.join(PUBLIC_STATE), &state).expect("save old intent");

    let restored = Node::restore(&directory.0, None).expect("restore after utun release");

    assert!(!restored.enabled());
    let persisted = read_public_state(&directory.join(PUBLIC_STATE))
        .expect("read state")
        .expect("persist disabled state");
    assert!(persisted.routes.is_empty());
    assert!(persisted.interface.is_none());
}

/// A peer endpoint inside a mesh host route is refused: the tunnel would route into itself.
#[test]
fn wireguard_underlay_endpoints_never_recurse_through_mesh_host_routes() {
    let mut config = config();
    let routes = route_addresses(&config);
    assert!(validate_underlay_routes(&config, &routes).is_ok());
    config
        .peers
        .get_mut(&NodeId(4))
        .expect("server peer")
        .peer
        .endpoint = Some("10.254.0.4:51820".parse().expect("mesh endpoint"));
    assert!(validate_underlay_routes(&config, &routes).is_err());
}

/// A private 0700 scratch folder for one test, removed when dropped.
struct TestDirectory(PathBuf);
/// Sequence number that keeps parallel tests' scratch folders apart.
static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);
impl TestDirectory {
    /// A path inside the scratch folder.
    fn join(&self, path: &str) -> PathBuf {
        self.0.join(path)
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Create a fresh scratch folder under the temp dir, unique per process, time and sequence.
fn test_directory() -> TestDirectory {
    let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "infraternal-mac-mesh-test-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
        sequence
    ));
    fs::create_dir(&path).expect("test directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("test mode");
    TestDirectory(path)
}

/// Thirty-two tests starting at once still get thirty-two distinct folders.
#[test]
fn parallel_test_directories_have_unique_paths() {
    let barrier = Arc::new(Barrier::new(32));
    let workers = (0..32)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                test_directory()
            })
        })
        .collect::<Vec<_>>();
    let directories = workers
        .into_iter()
        .map(|worker| worker.join().expect("create fixture without collision"))
        .collect::<Vec<_>>();
    let paths = directories
        .iter()
        .map(|directory| directory.0.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(paths.len(), directories.len());
}

/// Decode a 64-character hex `WireGuard` key from the bench environment.
fn bench_key(name: &str) -> [u8; 32] {
    let hex = std::env::var(name).expect("bench key variable");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex key"))
        .collect();
    bytes.try_into().expect("32-byte key")
}

/// J461 bench harness (#260): the exact Mac data path (this module's `MacUtun` reader and
/// writer, the bound UDP factory, the pinned `GotaTun` device on a current-thread runtime, as
/// `Node` builds it) with one static peer and no coordinator, so the macOS send and receive
/// cells can be measured against other engines on the same link.
///
/// Root only (utun). Environment: `J461_PRIVATE_HEX`, `J461_PEER_PUBLIC_HEX`,
/// `J461_ENDPOINT` (peer `ip:port`), `J461_PORT`, `J461_ADDR` and `J461_PEER_ADDR` (tunnel
/// IPv4 addresses), `J461_IFNAME_FILE` (the utun name is written there once up) and `J461_STOP` (the
/// device stops when that file appears). Run with
/// `cargo test --release --features agent --lib mac_bench_device -- --ignored`.
#[test]
#[ignore = "bench harness: root, a live peer and the J461_* environment"]
fn mac_bench_device() {
    use gotatun::{
        device::{DeviceBuilder, Peer as WireGuardPeer},
        x25519::{PublicKey as WgPublicKey, StaticSecret},
    };
    let var = |name: &str| std::env::var(name).expect("bench variable");
    let port: u16 = var("J461_PORT").parse().expect("port");
    let endpoint: std::net::SocketAddr = var("J461_ENDPOINT").parse().expect("endpoint");
    let peer_addr: IpAddr = var("J461_PEER_ADDR").parse().expect("peer address");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    // The worker's packet filter, compiled from a one-peer snapshot that grants the bench
    // peer every port both ways, so the filter's per-packet cost is part of the measurement
    // and nothing is dropped. An empty filter would deny all traffic.
    let mut snapshot = config();
    snapshot.addresses.ipv4 = var("J461_ADDR").parse().expect("tunnel IPv4");
    let peer_key = bench_key("J461_PEER_PUBLIC_HEX");
    for policy in snapshot.peers.values_mut() {
        policy.peer.key = PublicKey(peer_key);
        policy.peer.addresses.ipv4 = var("J461_PEER_ADDR").parse().expect("peer IPv4");
        policy.peer.endpoint = Some(endpoint);
    }
    let filter = std::sync::Arc::new(
        crate::packet_filter::PacketFilter::new(
            &snapshot,
            infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
        )
        .expect("compile filter"),
    );
    runtime.block_on(async {
        let utun = super::MacUtun::from_open(super::OpenUtun::open().expect("utun"), filter)
            .expect("register utun");
        // The worker's socket, with its handshake guard admitting the one bench peer.
        let private_key = StaticSecret::from(bench_key("J461_PRIVATE_HEX"));
        let (factory, port) = super::bind_udp(
            crate::listen_port::Request {
                port,
                allow_fallback: false,
            },
            private_key.clone(),
        )
        .await
        .expect("bind");
        {
            let mut admission = factory.admission.write().await;
            admission.set_peers([PublicKey(peer_key)]);
            admission.set_configured_endpoints([endpoint]);
        }
        let mut peer = WireGuardPeer::new(WgPublicKey::from(peer_key))
            .with_allowed_ips(vec![ipnetwork::IpNetwork::new(peer_addr, 32).expect("net")]);
        peer.endpoint = Some(endpoint);
        peer.keepalive = Some(25);
        let device = DeviceBuilder::new()
            .with_udp(factory)
            .with_private_key(private_key)
            .with_listen_port(port)
            .with_ip_pair(utun.sender(), utun.receiver())
            .with_peers(vec![peer])
            .build()
            .await
            .expect("device");
        utun.set_mtu(1280);
        let status = std::process::Command::new("/sbin/ifconfig")
            .args([
                utun.name(),
                "inet",
                &var("J461_ADDR"),
                &peer_addr.to_string(),
            ])
            .args(["mtu", "1280", "up"])
            .status()
            .expect("ifconfig");
        assert!(status.success(), "ifconfig failed");
        fs::write(var("J461_IFNAME_FILE"), utun.name()).expect("publish the utun name");
        let stop = PathBuf::from(var("J461_STOP"));
        while !stop.exists() {
            // sleep: poll the stop file
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        device.stop().await;
    });
}
