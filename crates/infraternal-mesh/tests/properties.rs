//! Seeded property checks compare incremental delivery against an independent reference compiler.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_mesh::{
    address::{AddressAllocator, Route, conflicts},
    backend::{Backend, MemoryBackend, PathKind, PeerStats},
    coordinator::{Change, Coordinator, KEY_OVERLAP_SECS},
    model::{LocalPrivateKey, MeshError, MeshSettings, Node, NodeId, PublicKey},
    rules::{Arrow, Endpoint, Port, Protocol, RuleId, TrafficPolicy},
    view::PeerView,
};
use std::collections::{BTreeMap, BTreeSet};

/// A synthetic public key whose first 8 bytes are `value`, so keys are unique.
fn key(value: u64) -> PublicKey {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    PublicKey(bytes)
}
/// A synthetic node numbered `value`, named `host-<value>`, in tag `tag-0`,
/// `tag-1` or `tag-2`.
fn node(value: u64) -> Node {
    Node {
        id: NodeId(value),
        public_key: key(value),
        host: format!("host-{value}"),
        tags: BTreeSet::from([format!("tag-{}", value % 3)]),
    }
}
/// A new coordinator whose server is node 0, with default settings.
fn coordinator() -> Coordinator {
    Coordinator::new(MeshSettings::new([1, 2, 3, 4, 5]), &[], node(0)).unwrap()
}
/// An arrow granting only TCP port 5432.
fn arrow(id: u64, from: Endpoint, to: Endpoint, both_ways: bool) -> Arrow {
    Arrow {
        id: RuleId(id),
        from,
        to,
        both_ways,
        ports: TrafficPolicy::Ports(BTreeSet::from([Port {
            protocol: Protocol::Tcp,
            number: 5432,
        }])),
    }
}
/// Plays the part of the network: applies `change` to each node's in-memory
/// backend, then checks that every node's view equals what a full recompile of
/// the coordinator state gives. This is the property the tests rely on:
/// incremental delivery must equal a from-scratch compile.
fn deliver(state: &Coordinator, clients: &mut BTreeMap<NodeId, MemoryBackend>, change: &Change) {
    for (id, diff) in &change.peers {
        clients
            .entry(*id)
            .or_insert_with(|| MemoryBackend::new(PeerView::empty(*id)))
            .apply(diff)
            .unwrap();
    }
    clients.retain(|id, _| state.view(*id).is_some());
    // A node with no peers (the server before first join) still has an empty snapshot.
    for (id, view) in state.views() {
        clients
            .entry(*id)
            .or_insert_with(|| MemoryBackend::new(view.clone()));
    }
    let applied: BTreeMap<_, _> = clients
        .iter()
        .map(|(id, client)| (*id, client.view().clone()))
        .collect();
    assert_eq!(applied, state.full_compile());
    assert_eq!(state.views(), &state.full_compile());
}

#[test]
fn addresses_are_unique_stable_and_not_recycled() {
    let mut allocation = AddressAllocator::new(MeshSettings::new([1, 2, 3, 4, 5]), &[]).unwrap();
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for id in 0..20_000 {
        let addresses = allocation.allocate(NodeId(id)).unwrap();
        assert_eq!(allocation.allocate(NodeId(id)).unwrap(), addresses);
        assert!(v4.insert(addresses.ipv4));
        assert!(v6.insert(addresses.ipv6));
        if id % 2 == 0 {
            allocation.remove(NodeId(id));
        }
    }
    for id in (0..20_000).step_by(2) {
        let addresses = allocation.allocate(NodeId(id)).unwrap();
        assert!(v4.insert(addresses.ipv4));
        assert!(v6.insert(addresses.ipv6));
    }
}

#[test]
fn overlaps_are_reported_without_silent_range_changes() {
    let settings = MeshSettings::new([1, 2, 3, 4, 5]);
    let routes = [
        Route {
            network: "10.254.2.0".parse().unwrap(),
            prefix: 24,
        },
        Route {
            network: "fd01:203:405::".parse().unwrap(),
            prefix: 48,
        },
        Route {
            network: "10.69.69.0".parse().unwrap(),
            prefix: 24,
        },
    ];
    assert_eq!(conflicts(&settings, &routes).unwrap(), routes[..2]);
    assert!(matches!(
        AddressAllocator::new(settings.clone(), &routes),
        Err(MeshError::RouteOverlap)
    ));
    assert_eq!(settings.ipv4.network.to_string(), "10.254.0.0");
    assert!(
        conflicts(
            &settings,
            &[Route {
                network: "10.1.2.3".parse().unwrap(),
                prefix: 16
            }]
        )
        .is_err()
    );
    assert_eq!(
        conflicts(
            &settings,
            &[Route {
                network: "0.0.0.0".parse().unwrap(),
                prefix: 0
            }]
        )
        .unwrap()
        .len(),
        1
    );
    let mut small = settings;
    small.ipv4.prefix = 30;
    let mut allocation = AddressAllocator::new(small, &[]).unwrap();
    allocation.allocate(NodeId(1)).unwrap();
    allocation.allocate(NodeId(2)).unwrap();
    assert_eq!(
        allocation.allocate(NodeId(3)),
        Err(MeshError::AddressExhausted)
    );
}

#[test]
fn private_material_never_enters_debug_or_coordination_serialization() {
    let local = LocalPrivateKey::new([165; 32]);
    assert_eq!(format!("{local:?}"), "LocalPrivateKey([REDACTED])");
    assert_eq!(local.expose(|bytes| bytes[0]), 165);
    let mut state = coordinator();
    let change = state.join(node(1)).unwrap();
    let message = serde_json::to_string(&change).unwrap();
    assert!(!message.contains("private"));
    assert!(!message.contains("165"));
    assert_eq!(serde_json::from_str::<Change>(&message).unwrap(), change);
}

#[test]
fn directional_grants_union_and_minimal_updates() {
    let mut state = coordinator();
    for id in 1..5 {
        state.join(node(id)).unwrap();
    }
    let first = state
        .add_arrow(arrow(
            1,
            Endpoint::Node(NodeId(1)),
            Endpoint::Node(NodeId(2)),
            false,
        ))
        .unwrap();
    assert_eq!(
        first.peers.keys().copied().collect::<Vec<_>>(),
        [NodeId(1), NodeId(2)]
    );
    let peer = &state.view(NodeId(1)).unwrap().peers[&NodeId(2)];
    assert_eq!(peer.inbound, TrafficPolicy::None);
    assert!(peer.outbound.allows(Port {
        protocol: Protocol::Tcp,
        number: 5432
    }));
    assert!(!peer.outbound.allows(Port {
        protocol: Protocol::Udp,
        number: 5432
    }));
    assert_eq!(first.peers[&NodeId(1)].upserted.len(), 1);
    assert!(
        state
            .add_arrow(arrow(
                2,
                Endpoint::Node(NodeId(1)),
                Endpoint::Node(NodeId(2)),
                false
            ))
            .unwrap()
            .peers
            .is_empty()
    );
    assert!(state.remove_arrow(RuleId(1)).unwrap().peers.is_empty());
    assert_eq!(state.remove_arrow(RuleId(2)).unwrap().peers.len(), 2);
    assert!(
        !state
            .view(NodeId(1))
            .unwrap()
            .peers
            .contains_key(&NodeId(2))
    );
    let invalid = arrow(3, Endpoint::User(1), Endpoint::Node(NodeId(2)), false);
    assert_eq!(state.add_arrow(invalid), Err(MeshError::UserEndpoint));
}

#[test]
fn join_to_same_tag_grants_both_initiation_directions() {
    let mut state = coordinator();
    state.join(node(3)).unwrap();
    state
        .add_arrow(arrow(
            1,
            Endpoint::Tag("tag-0".into()),
            Endpoint::Tag("tag-0".into()),
            false,
        ))
        .unwrap();
    state.join(node(6)).unwrap();
    assert_eq!(state.views(), &state.full_compile());
}

#[test]
fn rotation_waits_for_overlap_and_delivery_and_removal_drops_every_key() {
    let mut state = coordinator();
    let mut clients = BTreeMap::new();
    for id in 1..4 {
        let change = state.join(node(id)).unwrap();
        deliver(&state, &mut clients, &change);
    }
    let change = state
        .add_arrow(arrow(
            1,
            Endpoint::Node(NodeId(1)),
            Endpoint::Node(NodeId(2)),
            true,
        ))
        .unwrap();
    deliver(&state, &mut clients, &change);
    let before = clients[&NodeId(2)].view().clone();
    let change = state.rotate_key(NodeId(1), key(99), 100).unwrap();
    assert_eq!(change.peers.len(), 2);
    assert!(
        state
            .finish_rotation(NodeId(1), u64::MAX)
            .unwrap()
            .peers
            .is_empty()
    );
    // An unreachable coordinator has no timer in the backend; even an arbitrarily long outage keeps the view.
    assert_eq!(clients[&NodeId(2)].view(), &before);
    deliver(&state, &mut clients, &change);
    for peer in [NodeId(0), NodeId(2)] {
        let keys = &clients[&peer].view().peers[&NodeId(1)].keys;
        assert_eq!(keys.current, key(99));
        assert_eq!(keys.previous, Some(key(1)));
        state
            .acknowledge(peer, clients[&peer].view().rule_version)
            .unwrap();
    }
    assert!(
        state
            .finish_rotation(NodeId(1), 100 + KEY_OVERLAP_SECS - 1)
            .unwrap()
            .peers
            .is_empty()
    );
    let change = state
        .finish_rotation(NodeId(1), 100 + KEY_OVERLAP_SECS)
        .unwrap();
    deliver(&state, &mut clients, &change);
    for peer in [NodeId(0), NodeId(2)] {
        assert_eq!(clients[&peer].view().peers[&NodeId(1)].keys.previous, None);
    }
    let change = state.rotate_key(NodeId(1), key(100), 300).unwrap();
    deliver(&state, &mut clients, &change);
    let change = state.remove_node(NodeId(1)).unwrap();
    deliver(&state, &mut clients, &change);
    for view in state.views().values() {
        assert!(!view.peers.contains_key(&NodeId(1)));
        assert!(
            view.peers
                .values()
                .all(|p| p.keys.current != key(100) && p.keys.previous != Some(key(99)))
        );
    }
}

#[test]
fn names_versions_and_backend_status() {
    let mut state = coordinator();
    let change = state.join(node(1)).unwrap();
    let mut backend = MemoryBackend::new(PeerView::empty(NodeId(1)));
    backend.apply(&change.peers[&NodeId(1)]).unwrap();
    assert_eq!(
        backend.apply(&change.peers[&NodeId(1)]),
        Err(MeshError::StaleDiff)
    );
    assert_eq!(state.is_behind(NodeId(1)), Some(true));
    state
        .acknowledge(NodeId(1), backend.view().rule_version)
        .unwrap();
    assert_eq!(state.is_behind(NodeId(1)), Some(false));
    assert!(state.acknowledge(NodeId(1), u64::MAX).is_err());
    backend
        .set_stats(PeerStats {
            node: NodeId(0),
            path: PathKind::Relayed { relay: NodeId(0) },
            last_handshake_unix_secs: Some(123),
            received_bytes: 4,
            sent_bytes: 5,
        })
        .unwrap();
    let status = backend.status(Some(backend.view().rule_version));
    assert_eq!(
        serde_json::from_str::<infraternal_mesh::backend::MeshStatus>(
            &serde_json::to_string(&status).unwrap()
        )
        .unwrap(),
        status
    );
    assert!(state.names().lookup("example.org").is_none());
    let address = state.names().lookup("host-1.internal").unwrap();
    assert_eq!(
        state.rename(NodeId(1), "host-0".into()),
        Err(MeshError::DuplicateName)
    );
    let change = state.rename(NodeId(1), "db".into()).unwrap();
    assert_eq!(change.names.removed, ["host-1.internal"]);
    assert_eq!(state.names().lookup("db.internal"), Some(address));
    let change = state.set_suffix("vpn.example.org".into()).unwrap();
    assert_eq!(change.names.upserted.len(), 2);
    assert_eq!(state.names().lookup("db.vpn.example.org"), Some(address));
    assert!(state.names().lookup("db.internal").is_none());
    assert!(state.set_suffix("INVALID".into()).is_err());
}

/// Whether `endpoint` names `node`, by id or by tag. An independent reference
/// for the coordinator's own matching.
fn matches(endpoint: &Endpoint, node: &Node) -> bool {
    match endpoint {
        Endpoint::Node(id) => *id == node.id,
        Endpoint::Tag(tag) => node.tags.contains(tag),
        Endpoint::User(_) => false,
    }
}
/// A small deterministic pseudo-random generator: advances `seed` and returns
/// 32 random bits, so a failing sequence can be replayed from its seed.
fn random(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed >> 32
}

#[test]
fn seeded_random_sequences_equal_full_compile_and_deny_without_grants() {
    for seed in 0..100 {
        let mut rng = seed;
        let mut state = coordinator();
        let mut clients = BTreeMap::new();
        let mut nodes = BTreeMap::from([(NodeId(0), node(0))]);
        let mut rules = BTreeMap::<RuleId, Arrow>::new();
        for id in 1..12 {
            let member = node(id);
            nodes.insert(member.id, member.clone());
            let change = state.join(member).unwrap();
            deliver(&state, &mut clients, &change);
        }
        for step in 1..101 {
            let id = NodeId(1 + random(&mut rng) % 11);
            let change = match random(&mut rng) % 6 {
                0 | 1 => {
                    let endpoint = |rng: &mut u64| {
                        if random(rng).is_multiple_of(2) {
                            Endpoint::Node(NodeId(random(rng) % 12))
                        } else {
                            Endpoint::Tag(format!("tag-{}", random(rng) % 3))
                        }
                    };
                    let mut grant = arrow(
                        step,
                        endpoint(&mut rng),
                        endpoint(&mut rng),
                        random(&mut rng).is_multiple_of(2),
                    );
                    if random(&mut rng).is_multiple_of(3) {
                        grant.ports = TrafficPolicy::All;
                    }
                    if let Ok(change) = state.add_arrow(grant.clone()) {
                        rules.insert(grant.id, grant);
                        change
                    } else {
                        Change::default()
                    }
                }
                2 => {
                    if let Some(rule) = rules.keys().next().copied() {
                        rules.remove(&rule);
                        state.remove_arrow(rule).unwrap()
                    } else {
                        Change::default()
                    }
                }
                3 => {
                    if nodes.remove(&id).is_some() {
                        state.remove_node(id).unwrap()
                    } else {
                        nodes.insert(id, node(id.0));
                        state.join(node(id.0)).unwrap()
                    }
                }
                4 => {
                    if let Some(member) = nodes.get_mut(&id) {
                        member.tags = BTreeSet::from([format!("tag-{}", random(&mut rng) % 3)]);
                        state.set_tags(id, member.tags.clone()).unwrap()
                    } else {
                        Change::default()
                    }
                }
                _ => {
                    if nodes.contains_key(&id) {
                        state
                            .rotate_key(id, key(1000 + step), step)
                            .unwrap_or_default()
                    } else {
                        Change::default()
                    }
                }
            };
            deliver(&state, &mut clients, &change);
            for (owner, view) in state.views() {
                for (peer, entry) in &view.peers {
                    let granted = |a: NodeId, b: NodeId| {
                        b == NodeId(0)
                            || rules.values().any(|rule| {
                                (matches(&rule.from, &nodes[&a]) && matches(&rule.to, &nodes[&b]))
                                    || (rule.both_ways
                                        && matches(&rule.to, &nodes[&a])
                                        && matches(&rule.from, &nodes[&b]))
                            })
                    };
                    assert!(granted(*owner, *peer) || granted(*peer, *owner));
                    if !granted(*owner, *peer) {
                        assert_eq!(entry.outbound, TrafficPolicy::None);
                    }
                    if !granted(*peer, *owner) {
                        assert_eq!(entry.inbound, TrafficPolicy::None);
                    }
                }
            }
        }
    }
}

#[test]
fn public_checkpoint_preserves_addresses_rules_versions_and_overlap() {
    let mut state = coordinator();
    for id in 1..8 {
        state.join(node(id)).unwrap();
    }
    state
        .add_arrow(arrow(
            1,
            Endpoint::Node(NodeId(1)),
            Endpoint::Tag("tag-2".into()),
            true,
        ))
        .unwrap();
    state.rotate_key(NodeId(1), key(99), 100).unwrap();
    state.remove_node(NodeId(2)).unwrap();
    let json = serde_json::to_vec(&state.checkpoint()).unwrap();
    let restored = Coordinator::restore(serde_json::from_slice(&json).unwrap(), &[]).unwrap();
    assert_eq!(state.views(), restored.views());
    assert_eq!(state.names().records(), restored.names().records());
    let mut restored = restored;
    let old_addresses = state.names().lookup("host-3.internal").unwrap();
    assert_eq!(
        restored.names().lookup("host-3.internal"),
        Some(old_addresses)
    );
    restored.join(node(8)).unwrap();
    state.join(node(8)).unwrap();
    assert_eq!(state.views(), restored.views());
    let mut malformed = state.checkpoint();
    malformed.settings.ula_global_id = [9; 5];
    assert!(matches!(
        Coordinator::restore(malformed, &[]),
        Err(MeshError::InvalidCheckpoint)
    ));
    let mut malformed = serde_json::to_value(state.checkpoint()).unwrap();
    malformed["allocation"]["next"] = serde_json::json!(1);
    assert!(
        serde_json::from_value::<infraternal_mesh::coordinator::CoordinatorCheckpoint>(malformed)
            .is_err()
    );
}

#[test]
fn exhausted_versions_reject_mutations_without_changing_state() {
    let mut checkpoint = coordinator().checkpoint();
    checkpoint.generation = u64::MAX;
    let mut state = Coordinator::restore(checkpoint, &[]).unwrap();
    let before = serde_json::to_value(state.checkpoint()).unwrap();
    assert!(state.join(node(1)).is_err());
    assert_eq!(serde_json::to_value(state.checkpoint()).unwrap(), before);
}

#[test]
fn arrow_replacement_is_atomic_and_unrelated_nodes_keep_their_versions() {
    let mut state = coordinator();
    for id in 1..5 {
        state.join(node(id)).unwrap();
    }
    let versions: Vec<_> = state
        .views()
        .iter()
        .map(|(id, view)| (*id, view.rule_version))
        .collect();
    for (id, version) in versions {
        state.acknowledge(id, version).unwrap();
    }
    let grant = arrow(
        1,
        Endpoint::Node(NodeId(1)),
        Endpoint::Node(NodeId(2)),
        false,
    );
    state.add_arrow(grant.clone()).unwrap();
    assert_eq!(state.is_behind(NodeId(1)), Some(true));
    assert_eq!(state.is_behind(NodeId(2)), Some(true));
    assert_eq!(state.is_behind(NodeId(3)), Some(false));
    let mut replacement = grant;
    replacement.to = Endpoint::Node(NodeId(3));
    replacement.both_ways = true;
    let change = state.replace_arrow(replacement).unwrap();
    assert_eq!(change.peers.len(), 3);
    assert_eq!(change.peers[&NodeId(1)].removed, [NodeId(2)]);
    assert_eq!(change.peers[&NodeId(1)].upserted.len(), 1);
    assert_eq!(state.views(), &state.full_compile());
    let mut invalid = arrow(1, Endpoint::Node(NodeId(1)), Endpoint::User(3), false);
    let before = serde_json::to_value(state.checkpoint()).unwrap();
    assert!(state.replace_arrow(invalid.clone()).is_err());
    invalid.to = Endpoint::Node(NodeId(99));
    assert!(state.replace_arrow(invalid).is_err());
    assert_eq!(serde_json::to_value(state.checkpoint()).unwrap(), before);
}

#[test]
fn protocol_port_unions_never_grant_an_unlisted_service() {
    let mut state = coordinator();
    state.join(node(1)).unwrap();
    state.join(node(2)).unwrap();
    let first = arrow(
        1,
        Endpoint::Node(NodeId(1)),
        Endpoint::Node(NodeId(2)),
        false,
    );
    state.add_arrow(first).unwrap();
    let mut second = arrow(
        2,
        Endpoint::Node(NodeId(1)),
        Endpoint::Node(NodeId(2)),
        false,
    );
    second.ports = TrafficPolicy::Ports(BTreeSet::from([Port {
        protocol: Protocol::Udp,
        number: 53,
    }]));
    state.add_arrow(second).unwrap();
    let policy = &state.view(NodeId(2)).unwrap().peers[&NodeId(1)].inbound;
    for number in 1..=u16::MAX {
        assert_eq!(
            policy.allows(Port {
                protocol: Protocol::Tcp,
                number
            }),
            number == 5432
        );
        assert_eq!(
            policy.allows(Port {
                protocol: Protocol::Udp,
                number
            }),
            number == 53
        );
    }
    state.remove_arrow(RuleId(1)).unwrap();
    assert!(
        !state.view(NodeId(2)).unwrap().peers[&NodeId(1)]
            .inbound
            .allows(Port {
                protocol: Protocol::Tcp,
                number: 5432
            })
    );
    assert_eq!(state.views(), &state.full_compile());
}

#[test]
fn checkpoint_after_suffix_change_restores_without_reallocating_addresses() {
    let mut state = coordinator();
    state.join(node(1)).unwrap();
    let address = state.names().lookup("host-1.internal").unwrap();
    state.rename(NodeId(1), "db".into()).unwrap();
    state.set_suffix("vpn.example.org".into()).unwrap();
    let checkpoint =
        serde_json::from_slice(&serde_json::to_vec(&state.checkpoint()).unwrap()).unwrap();
    let restored = Coordinator::restore(checkpoint, &[]).unwrap();
    assert_eq!(restored.settings().dns_suffix, "vpn.example.org");
    assert_eq!(restored.names().lookup("db.vpn.example.org"), Some(address));
    assert_eq!(state.views(), restored.views());
}

#[test]
fn server_rotation_has_continuous_keys_for_every_node_during_delivery() {
    let mut state = coordinator();
    let mut clients = BTreeMap::new();
    for id in 1..6 {
        let change = state.join(node(id)).unwrap();
        deliver(&state, &mut clients, &change);
    }
    let change = state.rotate_key(NodeId(0), key(255), 0).unwrap();
    assert_eq!(change.peers.len(), 5);
    let local = &change.local_keys[&NodeId(0)];
    assert_eq!(local.previous, Some(key(0)));
    for (id, diff) in &change.peers {
        let before = &clients[id].view().peers[&NodeId(0)].keys;
        assert!(before.current == local.current || Some(before.current) == local.previous);
        clients.get_mut(id).unwrap().apply(diff).unwrap();
        let after = &clients[id].view().peers[&NodeId(0)].keys;
        assert_eq!(after, local);
        state
            .acknowledge(*id, clients[id].view().rule_version)
            .unwrap();
    }
    let retired = state.finish_rotation(NodeId(0), KEY_OVERLAP_SECS).unwrap();
    assert_eq!(retired.local_keys[&NodeId(0)].previous, None);
    deliver(&state, &mut clients, &retired);
    for client in clients
        .values()
        .filter(|client| client.view().node != NodeId(0))
    {
        let accepted = &client.view().peers[&NodeId(0)].keys;
        assert_eq!(accepted.current, key(255));
        assert_eq!(accepted.previous, None);
    }
    assert_eq!(state.views(), &state.full_compile());
}
