//! Node lifecycle, retirement, rotation and kernel snapshot tests.

#![allow(clippy::expect_used)]
use super::*;
/// The default `GotaTun` node treats its kernel-only guard as optional and reports its state.
#[test]
fn default_gotatun_node_treats_kernel_guard_as_optional() {
    assert!(
        Node::default().firewall.kernel_guard_status().is_some(),
        "GotaTun must expose the optional kernel guard state"
    );
}

/// Choosing kernel `WireGuard` keeps D346's required nft frontend selected.
#[test]
fn kernel_wireguard_node_selects_required_nft_frontend() {
    let node = Node::default().with_engine(EngineKind::Kernel);
    assert_eq!(node.firewall.backend(), Some(crate::firewall::Backend::Nft));
}

/// Retirement removes the `GotaTun` private key file itself (#260 J143 P3-3).
#[test]
fn retirement_removes_the_private_key_file() {
    let directory = crate::node_state::tests::Directory::new();
    let (store, _) = crate::node_state::Store::open(&directory.0).expect("store");
    store.write_private_key(&[5; 32]).expect("key");
    let key = directory.0.join("mesh-private-key");
    assert!(key.exists());
    let retirement = Retirement {
        interface: false,
        interface_index: None,
        filter: None,
        left: Vec::new(),
        store: Some(store),
    };
    assert_eq!(retirement.execute().expect("retire"), Vec::<&str>::new());
    assert!(!key.exists(), "retirement leaves no private key behind");
}

/// A completed journal must not recreate the key after host-uninstall retirement (#367).
#[test]
fn j356_retirement_after_rotation_leaves_no_private_key() {
    let directory = crate::node_state::tests::Directory::new();
    let (store, _) = crate::node_state::Store::open(&directory.0).expect("store");
    let (candidate_key, candidate_public) = Key::generate().expect("candidate");
    let candidate: [u8; 32] = candidate_key.private_bytes().try_into().expect("32 bytes");
    store.record_engine(EngineKind::GotaTun).expect("engine");
    store
        .record_interface(&candidate_public)
        .expect("interface");
    store.write_private_key(&candidate).expect("key");
    store
        .save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: "00000000-0000-4000-8000-000000000356".to_owned(),
            sequence: 1,
            previous: [0; 32],
            candidate,
            commit_requested: true,
            completed: true,
        })
        .expect("completed marker");
    let retirement = Retirement {
        interface: false,
        interface_index: None,
        filter: None,
        left: Vec::new(),
        store: Some(store),
    };
    retirement.execute().expect("retire");
    assert!(!directory.0.join("mesh-private-key").exists());
    let (store, _) = crate::node_state::Store::open(&directory.0).expect("reopen");
    let residue = store.rotation_secret().expect("read journal");
    let interface = store.recorded_interface().expect("read interface record");
    let key_before_recovery = store.read_private_key().expect("read key");
    eprintln!(
        "J356 R1: retirement leaves journal={} interface={} private_key={}",
        residue.is_some(),
        interface.is_some(),
        key_before_recovery.is_some()
    );
    recover_gotatun_private_key_from_journal(&store).expect("recover");
    let resurrected = store.read_private_key().expect("read key");
    eprintln!(
        "J356 R1: key file recreated after retirement={}",
        resurrected
            .as_ref()
            .is_some_and(|k| k.as_slice() == candidate)
    );
    assert!(
        residue.is_none() && interface.is_none() && key_before_recovery.is_none(),
        "retirement left identity state: journal={}, interface={}, private_key={}",
        residue.is_some(),
        interface.is_some(),
        key_before_recovery.is_some()
    );
    assert!(resurrected.is_none(), "recovery recreated a retired key");
}

/// Both Linux engines require a live identity and owned link before rotation can start.
#[test]
fn inactive_engines_refuse_rotation_without_reading_or_mutating_state() {
    let operation = "00000000-0000-4000-8000-000000000005";
    let mut gotatun = Node::default().with_engine(EngineKind::GotaTun);
    for result in [
        gotatun.prepare_rotation(operation, 1).map(|_| ()),
        gotatun.commit_rotation(operation, 1).map(|_| ()),
        gotatun.finish_rotation(operation, 1),
    ] {
        assert_eq!(
            result.expect_err("inactive GotaTun refuses").kind(),
            io::ErrorKind::NotConnected
        );
    }
    let mut kernel = Node::default().with_engine(EngineKind::Kernel);
    assert_eq!(
        kernel
            .prepare_rotation(operation, 1)
            .expect_err("inactive kernel refuses")
            .kind(),
        io::ErrorKind::NotConnected
    );
}

/// A committed D166 key must be accepted as the binding of the next config delta.
#[test]
fn config_delta_can_advance_the_local_key_after_rotation_commit() {
    use crate::policy::model::{Addresses, NodeId};
    let previous_key = Key::generate().expect("previous key").1;
    let candidate_key = Key::generate().expect("candidate key").1;
    let previous = Config {
        authority_epoch: None,
        rotation_operation: None,
        local_key: Some(previous_key),
        server: Some(NodeId(1)),
        node: NodeId(2),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 4,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("IPv4"),
            ipv6: "fd01::2".parse().expect("IPv6"),
        },
        default_policy: crate::dataplane::DefaultPolicy::Allow,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: std::collections::BTreeMap::new(),
    };
    let mut next = previous.clone();
    next.local_key = Some(candidate_key);
    next.version = 5;
    let mut chunk = crate::configuration::chunks(Some(&previous), &next)
        .expect("coordinator delta")
        .remove(0);
    // Stop after the binding stage so this unit test does not configure a real interface.
    chunk.last = false;
    let mut node = Node {
        identity: Some(Identity {
            compact_access: true,
            #[cfg(feature = "mesh-dns")]
            dns_names: cfg!(target_os = "linux"),
            key_rotation: true,
            authority_epoch: true,
            rotation_continuity: true,
            public_key: candidate_key,
            port: 44000,
        }),
        config: Some(previous),
        ..Node::default()
    };

    assert!(!node.stage(chunk).expect("stage committed key binding"));
    assert_eq!(
        node.pending
            .as_ref()
            .expect("complete staged config")
            .config
            .local_key,
        Some(candidate_key)
    );
}

/// A staged snapshot cannot change the server's identity.
#[test]
fn server_identity_cannot_change_inside_a_staged_snapshot() {
    use crate::policy::model::{Addresses, NodeId, PublicKey};
    let mut node = Node {
        identity: Some(Identity {
            compact_access: true,
            #[cfg(feature = "mesh-dns")]
            dns_names: cfg!(target_os = "linux"),
            key_rotation: true,
            authority_epoch: true,
            rotation_continuity: true,
            public_key: PublicKey([1; 32]),
            port: 44000,
        }),
        ..Node::default()
    };
    let config = Config {
        authority_epoch: None,
        rotation_operation: None,
        server: Some(NodeId(1)),
        local_key: None,
        node: NodeId(2),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("IPv4"),
            ipv6: "fd01::2".parse().expect("IPv6"),
        },
        default_policy: crate::dataplane::DefaultPolicy::default(),
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: std::collections::BTreeMap::new(),
    };
    let mut chunk = crate::configuration::chunks(None, &config)
        .expect("snapshot")
        .remove(0);
    chunk.last = false;
    assert!(!node.chunk(chunk.clone()).expect("staged header"));
    chunk.index = 1;
    chunk.server = Some(NodeId(3));
    assert!(node.chunk(chunk).is_err());
    assert!(node.config().is_none());
}

/// Explicit up recovers a disabled node with its saved mesh identity.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn explicit_up_recovers_disabled_intent_before_reusing_identity() {
    let mut node = Node::default();
    node.up().expect("start");
    // Down publishes disabled intent before kernel cleanup. Model an
    // interrupted cleanup at that exact boundary with a still-live identity.
    node.enabled = false;
    node.up().expect("explicit restart");
    assert!(node.enabled());
    assert!(Device::owned().expect("owned interface"));
    node.down().expect("cleanup");
}
/// Down clears the node state when another process already removed the interface.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn externally_removed_interface_does_not_block_down() {
    let mut node = Node::default();
    node.up().expect("start");
    Device::delete().expect("external removal");
    node.down().expect("already absent owned interface");
    assert!(!node.active());
    assert!(!node.enabled());
}
/// A 1000-peer snapshot applied in chunks is accepted all at once, with every peer in the kernel.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN; use release for timing."]
fn chunked_snapshot_is_atomic_and_applies_1000_kernel_peers() {
    use crate::{
        dataplane::{DefaultPolicy, Peer, PeerPolicy},
        policy::{
            model::{Addresses, NodeId},
            rules::TrafficPolicy,
        },
    };
    let mut node = Node::default().with_engine(EngineKind::Kernel);
    node.up().expect("start");
    let addresses = |id: u32| Addresses {
        ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
        ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
    };
    let config = Config {
        authority_epoch: None,
        rotation_operation: None,
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 1,
        addresses: addresses(1),
        default_policy: DefaultPolicy::Allow,
        exposure: None,
        peers: (2..=1001)
            .map(|id| {
                let (_, key) = Key::generate().expect("public peer fixture");
                (
                    NodeId(u64::from(id)),
                    PeerPolicy {
                        peer: Peer {
                            key,
                            previous_key: None,
                            previous_active: false,
                            addresses: addresses(id),
                            endpoint: Some("192.0.2.1:44000".parse().expect("public endpoint")),
                            candidates: Vec::new(),
                            ipv4_only: false,
                            side_port: false,
                        },
                        inbound: TrafficPolicy::All,
                        outbound: TrafficPolicy::All,
                        access_ssh: None,
                        networks: crate::dataplane::PeerNetworks::default(),
                    },
                )
            })
            .collect(),
        #[cfg(feature = "mesh-dns")]
        peer_names: std::collections::BTreeMap::new(),
    };
    let chunks = crate::configuration::chunks(None, &config).expect("bounded chunks");
    let count = chunks.len();
    assert!(count > 1);
    // An interrupted or out-of-order snapshot cannot mutate the live view.
    node.chunk(chunks[0].clone()).expect("first staged");
    assert!(node.chunk(chunks[count - 1].clone()).is_err());
    assert!(node.config().is_none());
    assert_eq!(Device::counters().expect("empty kernel").len(), 0);
    let started = std::time::Instant::now();
    for chunk in chunks {
        let last = chunk.last;
        assert_eq!(node.chunk(chunk).expect("stage/apply"), last);
        if !last {
            assert!(node.config().is_none());
        }
    }
    let initial = started.elapsed().as_micros();
    assert_eq!(Device::counters().expect("kernel peers").len(), 1000);
    let mut next = config.clone();
    next.version += 1;
    next.peers
        .get_mut(&NodeId(500))
        .expect("member")
        .peer
        .endpoint = Some("192.0.2.2:44000".parse().expect("public endpoint"));
    let delta = crate::configuration::chunks(Some(&config), &next).expect("delta");
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].upserted.len(), 1);
    let started = std::time::Instant::now();
    node.chunk(delta[0].clone()).expect("endpoint delta");
    println!(
        "METRIC mesh_node machine=infraternal-dev peers=1000 chunks={count} apply_us={initial} single_endpoint_us={} load={}",
        started.elapsed().as_micros(),
        std::fs::read_to_string("/proc/loadavg")
            .expect("load")
            .trim()
    );
    assert_eq!(node.config().expect("applied").version, 2);
    node.down().expect("off");
    assert!(!Device::owned().expect("absent owned interface"));
}
