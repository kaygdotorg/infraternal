//! Reject an unrepresentable grace deadline before changing key state.
#![allow(clippy::unwrap_used)]
use infraternal_mesh::{
    coordinator::Coordinator,
    model::{MeshSettings, Node, NodeId, PublicKey},
    rules::{Arrow, Endpoint, RuleId, TrafficPolicy},
};
use std::collections::BTreeSet;
fn node(id: u8) -> Node {
    Node {
        id: NodeId(u64::from(id)),
        public_key: PublicKey([id; 32]),
        host: format!("host-{id}"),
        tags: BTreeSet::new(),
    }
}
#[test]
fn unrepresentable_rotation_overlap_rejects_before_mutation() {
    let mut state = Coordinator::new(MeshSettings::new([1; 5]), &[], node(0)).unwrap();
    state.join(node(1)).unwrap();
    let before = state.full_compile();
    assert!(
        state
            .rotate_key(NodeId(1), PublicKey([99; 32]), u64::MAX)
            .is_err()
    );
    assert_eq!(state.full_compile(), before);
}

/// Rotation retires after the 120 s overlap and waits only for acknowledgments from reachable peers.
#[test]
fn rotation_retires_after_120_seconds_and_only_waits_for_reachable_acknowledgements() {
    let mut state = Coordinator::new(MeshSettings::new([1; 5]), &[], node(0)).unwrap();
    for id in 1..=3 {
        state.join(node(id)).unwrap();
    }
    for peer in [0_u8, 2, 3] {
        state
            .add_arrow(Arrow {
                id: RuleId(u64::from(peer) + 1),
                from: Endpoint::Node(NodeId(1)),
                to: Endpoint::Node(NodeId(u64::from(peer))),
                both_ways: true,
                ports: TrafficPolicy::All,
            })
            .unwrap();
    }
    let old = PublicKey([1; 32]);
    let new = PublicKey([99; 32]);
    state.rotate_key(NodeId(1), new, 100).unwrap();
    for peer in [2_u8, 3] {
        let keys = &state.full_compile()[&NodeId(u64::from(peer))].peers[&NodeId(1)].keys;
        assert_eq!(keys.current, new);
        assert_eq!(keys.previous, Some(old));
    }
    for id in [0_u8, 2] {
        let version = state.view(NodeId(u64::from(id))).unwrap().rule_version;
        state.acknowledge(NodeId(u64::from(id)), version).unwrap();
    }
    let reachable = BTreeSet::from([NodeId(0), NodeId(2)]);

    assert!(
        state
            .finish_rotation_reachable(NodeId(1), 219, &reachable)
            .unwrap()
            .peers
            .is_empty()
    );
    assert!(
        !state
            .finish_rotation_reachable(NodeId(1), 220, &reachable)
            .unwrap()
            .peers
            .is_empty()
    );
    for peer in [2_u8, 3] {
        let keys = &state.full_compile()[&NodeId(u64::from(peer))].peers[&NodeId(1)].keys;
        assert_eq!(keys.current, new);
        assert_eq!(keys.previous, None);
    }
}

/// A compromise replacement drops the old key at once and has no overlap deadline.
#[test]
fn compromise_replacement_does_not_keep_the_old_key_or_the_overlap_deadline() {
    let mut state = Coordinator::new(MeshSettings::new([1; 5]), &[], node(0)).unwrap();
    state.join(node(1)).unwrap();
    state
        .rotate_key(NodeId(1), PublicKey([99; 32]), 100)
        .unwrap();
    let replacement = PublicKey([101; 32]);
    state.compromise_key(NodeId(1), replacement).unwrap();

    let keys = &state.full_compile()[&NodeId(0)].peers[&NodeId(1)].keys;
    assert_eq!(keys.current, replacement);
    assert_eq!(keys.previous, None);
}
