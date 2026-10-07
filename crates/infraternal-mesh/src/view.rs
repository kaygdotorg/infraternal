//! Serializable snapshots and version-checked minimal peer updates for unreliable delivery.
use crate::{
    model::{Addresses, MeshError, NodeId, PublicKey},
    rules::TrafficPolicy,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Brief node-side rotation overlap. No local timeout removes keys during a server outage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerKeys {
    pub current: PublicKey,
    pub previous: Option<PublicKey>,
}

/// Backend installs /32 and /128 allowed IPs for these addresses, never a subnet route.
/// Incoming/outgoing apply to NEW connections; authenticated established replies must pass.
/// A backend must enforce both directions: an incoming grant is not permission to initiate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub node: NodeId,
    pub keys: PeerKeys,
    pub allowed_ips: Addresses,
    pub inbound: TrafficPolicy,
    pub outbound: TrafficPolicy,
}

/// Target version is per node. Unchanged nodes are not marked behind by unrelated rule edits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerView {
    pub node: NodeId,
    pub rule_version: u64,
    pub peers: BTreeMap<NodeId, Peer>,
}
impl PeerView {
    #[must_use]
    pub fn empty(node: NodeId) -> Self {
        Self {
            node,
            rule_version: 0,
            peers: BTreeMap::new(),
        }
    }
    /// # Errors
    /// Rejects a wrong target or noncontiguous version before changing any peer.
    pub fn apply(&mut self, diff: &PeerDiff) -> Result<(), MeshError> {
        if self.node != diff.node
            || self.rule_version != diff.from_version
            || diff.to_version <= diff.from_version
        {
            return Err(MeshError::StaleDiff);
        }
        for peer in &diff.removed {
            self.peers.remove(peer);
        }
        self.peers.extend(
            diff.upserted
                .iter()
                .map(|(node, peer)| (*node, peer.clone())),
        );
        self.rule_version = diff.to_version;
        Ok(())
    }
}

/// Omitted peers are unchanged; missed/out-of-order diffs require a fresh snapshot on reconnect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDiff {
    pub node: NodeId,
    pub from_version: u64,
    pub to_version: u64,
    pub removed: Vec<NodeId>,
    pub upserted: BTreeMap<NodeId, Peer>,
}
