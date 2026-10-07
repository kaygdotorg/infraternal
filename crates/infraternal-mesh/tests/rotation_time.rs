//! Reject an unrepresentable grace deadline before changing key state.
#![allow(clippy::unwrap_used)]
use infraternal_mesh::{
    coordinator::Coordinator,
    model::{MeshSettings, Node, NodeId, PublicKey},
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
