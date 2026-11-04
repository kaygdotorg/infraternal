//! Fuzz structured-input validation and lifecycle invariants; no transport parser is introduced here.
#![no_main]
#![forbid(unsafe_code)]
use infraternal_mesh::{
    address::{AddressAllocator, Route, conflicts},
    coordinator::{Coordinator, CoordinatorCheckpoint},
    model::{MeshSettings, Node, NodeId, PublicKey},
    rules::{Arrow, Endpoint, RuleId, TrafficPolicy},
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

/// A valid node numbered `id`, with a key, a host name and one of four tags,
/// used as building material for the fuzzed operations.
fn node(id: u8) -> Node {
    Node {
        id: NodeId(u64::from(id)),
        public_key: PublicKey([id; 32]),
        host: format!("host-{id}"),
        tags: BTreeSet::from([format!("tag-{}", id % 4)]),
    }
}
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    if let Ok(settings) = serde_json::from_slice::<MeshSettings>(data) {
        let _ = AddressAllocator::new(settings, &[]);
    }
    if let Ok(routes) = serde_json::from_slice::<Vec<Route>>(data) {
        let _ = conflicts(&MeshSettings::new([1; 5]), &routes);
    }
    if let Ok(checkpoint) = serde_json::from_slice::<CoordinatorCheckpoint>(data) {
        let _ = Coordinator::restore(checkpoint, &[]);
    }
    if let Ok(arrow) = serde_json::from_slice::<Arrow>(data) {
        let _ = arrow.validate();
    }
    if let Ok(diff) = serde_json::from_slice::<infraternal_mesh::view::PeerDiff>(data) {
        let mut view = infraternal_mesh::view::PeerView::empty(diff.node);
        let _ = view.apply(&diff);
    }
    let Ok(mut state) = Coordinator::new(MeshSettings::new([1; 5]), &[], node(0)) else {
        return;
    };
    for (step, instruction) in data.as_chunks::<4>().0.iter().take(64).enumerate() {
        let id = instruction[1] % 16;
        match instruction[0] % 6 {
            0 => {
                let _ = state.join(node(id));
            }
            1 => {
                let _ = state.remove_node(NodeId(u64::from(id)));
            }
            2 => {
                let endpoint = |byte: u8| {
                    if byte.is_multiple_of(2) {
                        Endpoint::Node(NodeId(u64::from(byte % 16)))
                    } else {
                        Endpoint::Tag(format!("tag-{}", byte % 4))
                    }
                };
                let _ = state.add_arrow(Arrow {
                    id: RuleId(u64::try_from(step).unwrap_or(0)),
                    from: endpoint(instruction[1]),
                    to: endpoint(instruction[2]),
                    both_ways: instruction[3].is_multiple_of(2),
                    ports: TrafficPolicy::All,
                });
            }
            3 => {
                let _ = state.remove_arrow(RuleId(u64::from(instruction[2])));
            }
            4 => {
                let _ = state.set_tags(
                    NodeId(u64::from(id)),
                    BTreeSet::from([format!("tag-{}", instruction[2] % 4)]),
                );
            }
            _ => {
                let _ = state.rotate_key(
                    NodeId(u64::from(id)),
                    PublicKey([instruction[2]; 32]),
                    u64::from(instruction[3]),
                );
            }
        }
        assert_eq!(state.views(), &state.full_compile());
    }
});
