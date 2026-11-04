//! What one node needs to know about its peers, and how to update it.
//!
//! A [`PeerView`] is a snapshot of a node's peers. A [`PeerDiff`] is a small,
//! version-checked change to it. Diffs may be lost or arrive out of order, so
//! a receiver that cannot apply one asks for a fresh snapshot.
use crate::{
    model::{Addresses, MeshError, NodeId, PublicKey},
    rules::TrafficPolicy,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The public keys accepted for one peer. During a key rotation both keys are
/// valid for a short overlap. A node never drops the old key on its own timer,
/// so a server outage cannot lock a peer out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerKeys {
    /// The peer's current key.
    pub current: PublicKey,
    /// The key being replaced, while the rotation overlap lasts.
    pub previous: Option<PublicKey>,
}

/// One peer as seen from one node.
///
/// The backend installs `/32` and `/128` allowed IPs for the peer's addresses,
/// never a subnet route. `inbound` and `outbound` apply to NEW connections;
/// authenticated replies on established connections always pass. A backend must
/// enforce both directions: permission to receive connections is not permission
/// to start them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    /// The peer's identity.
    pub node: NodeId,
    /// The keys accepted for the peer.
    pub keys: PeerKeys,
    /// The peer's addresses, installed as the only allowed IPs.
    pub allowed_ips: Addresses,
    /// What the peer may start toward this node.
    pub inbound: TrafficPolicy,
    /// What this node may start toward the peer.
    pub outbound: TrafficPolicy,
}

/// All peers of one node at one policy version.
///
/// The version is tracked per node, so a rule edit that does not affect a node
/// does not make that node look behind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerView {
    /// The node that owns this view.
    pub node: NodeId,
    /// The policy version this view reflects.
    pub rule_version: u64,
    /// The peers, by identity.
    pub peers: BTreeMap<NodeId, Peer>,
}
impl PeerView {
    /// A view with no peers, at version 0.
    #[must_use]
    pub fn empty(node: NodeId) -> Self {
        Self {
            node,
            rule_version: 0,
            peers: BTreeMap::new(),
        }
    }
    /// Applies `diff`: removes the peers it lists, then adds or overwrites the
    /// peers it carries, and moves to its target version.
    ///
    /// # Errors
    /// Returns `StaleDiff` if the diff is for another node, does not start at
    /// this view's version, or does not move the version forward. Nothing is
    /// changed in that case.
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

/// A change from one version of a [`PeerView`] to a later one.
///
/// Peers it does not mention are unchanged. A receiver that missed an earlier
/// diff, or got them out of order, cannot apply this one and must request a
/// fresh snapshot on reconnect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDiff {
    /// The node this change is for.
    pub node: NodeId,
    /// The version the receiver must be at to apply it.
    pub from_version: u64,
    /// The version the receiver will be at afterwards. Must be higher.
    pub to_version: u64,
    /// Peers to remove.
    pub removed: Vec<NodeId>,
    /// Peers to add, or to replace with the version given here.
    pub upserted: BTreeMap<NodeId, Peer>,
}
