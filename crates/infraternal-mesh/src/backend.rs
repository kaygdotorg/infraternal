//! The boundary between the coordinator and whatever moves packets.
//!
//! [`Backend`] is the trait a real data plane implements: it applies peer
//! updates and reports per-peer statistics. [`MemoryBackend`] is a
//! deterministic stand-in for tests. This crate selects no device library or
//! transport.
use crate::{
    model::{MeshError, NodeId},
    view::{PeerDiff, PeerView},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How traffic currently reaches a peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathKind {
    /// No path has been observed yet, for example before the first handshake.
    Unknown,
    /// Packets flow straight between the two nodes.
    Direct,
    /// Packets are forwarded through another node, `relay`.
    Relayed { relay: NodeId },
}

/// What the data plane reports about one peer.
///
/// Counters are cumulative bytes since the backend started counting. While a
/// peer has two keys during a rotation, the backend adds both keys' numbers
/// together under the one logical node, and keeps the totals when the old key
/// retires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStats {
    /// The peer these numbers belong to.
    pub node: NodeId,
    /// How traffic currently reaches the peer.
    pub path: PathKind,
    /// When the last handshake finished, in seconds since the Unix epoch.
    /// `None` if there has not been one.
    pub last_handshake_unix_secs: Option<u64>,
    /// Bytes received from the peer.
    pub received_bytes: u64,
    /// Bytes sent to the peer.
    pub sent_bytes: u64,
}

/// A node's view of itself, ready to show to a person.
///
/// It carries only what users should see, none of the coordinator's internal
/// state, so the CLI, API and MCP surfaces can all render it as is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshStatus {
    /// The node this status describes.
    pub node: NodeId,
    /// The policy version the node has applied.
    pub rule_version: u64,
    /// The version the server wants the node to reach, when known. A value
    /// above `rule_version` means the node is behind.
    pub desired_rule_version: Option<u64>,
    /// One entry per peer in the node's current view.
    pub peers: Vec<PeerStats>,
}

/// A data plane that can carry the mesh's peer configuration.
///
/// What an implementation must guarantee:
///
/// - **Atomic updates.** [`apply`](Backend::apply) either installs the whole
///   diff or leaves the old view untouched. A half-applied grant is never safe.
/// - **Host routes only.** Peers get `/32` and `/128` routes, never subnets.
/// - **Both directions are filtered.** New connections are checked against the
///   sender's outbound policy and the receiver's inbound policy. Replies on
///   established connections are allowed.
/// - **Key rotation.** During an overlap both public keys of a peer are
///   accepted.
/// - **Server loss.** If the server is unreachable, keep the last state
///   indefinitely instead of timing anything out.
/// - A real backend must show that the old and new keys can overlap without
///   conflicting allowed-IP routes.
pub trait Backend {
    /// The error type of the concrete data plane.
    type Error;
    /// Applies one version-checked peer update.
    ///
    /// # Errors
    /// Returns the backend error on failed atomic application; old state must remain intact.
    fn apply(&mut self, diff: &PeerDiff) -> Result<(), Self::Error>;
    /// Reads the current per-peer statistics.
    ///
    /// # Errors
    /// Returns the backend error if device counters cannot be read.
    fn stats(&self) -> Result<Vec<PeerStats>, Self::Error>;
}

/// An in-memory [`Backend`] for tests.
///
/// It only tracks which peers are configured and the statistics a test sets.
/// It does not process packets or perform handshakes.
#[derive(Clone, Debug)]
pub struct MemoryBackend {
    view: PeerView,
    stats: BTreeMap<NodeId, PeerStats>,
}
impl MemoryBackend {
    /// Starts from `view`, with no statistics recorded yet.
    #[must_use]
    pub fn new(view: PeerView) -> Self {
        Self {
            view,
            stats: BTreeMap::new(),
        }
    }
    /// The peers configured right now.
    #[must_use]
    pub fn view(&self) -> &PeerView {
        &self.view
    }
    /// Records the statistics to report for `stats.node`, replacing earlier ones.
    ///
    /// # Errors
    /// Returns `UnknownNode` if the peer is absent from the current view.
    pub fn set_stats(&mut self, stats: PeerStats) -> Result<(), MeshError> {
        if !self.view.peers.contains_key(&stats.node) {
            return Err(MeshError::UnknownNode);
        }
        self.stats.insert(stats.node, stats);
        Ok(())
    }
    /// Builds the [`MeshStatus`] for this node. `desired_rule_version` is the
    /// version the server wants, if the caller knows it.
    #[must_use]
    pub fn status(&self, desired_rule_version: Option<u64>) -> MeshStatus {
        MeshStatus {
            node: self.view.node,
            rule_version: self.view.rule_version,
            desired_rule_version,
            peers: self.read_stats(),
        }
    }
    /// Statistics for every peer in the view, in node order. A peer nobody
    /// has set statistics for reports an unknown path and zero counters.
    fn read_stats(&self) -> Vec<PeerStats> {
        self.view
            .peers
            .keys()
            .map(|node| {
                self.stats.get(node).cloned().unwrap_or(PeerStats {
                    node: *node,
                    path: PathKind::Unknown,
                    last_handshake_unix_secs: None,
                    received_bytes: 0,
                    sent_bytes: 0,
                })
            })
            .collect()
    }
}
impl Backend for MemoryBackend {
    type Error = MeshError;
    /// Applies the diff to the view, then drops statistics of peers that are
    /// gone.
    ///
    /// # Errors
    /// Returns `StaleDiff` if the diff does not continue the current version.
    /// The view is unchanged in that case.
    fn apply(&mut self, diff: &PeerDiff) -> Result<(), Self::Error> {
        self.view.apply(diff)?;
        self.stats
            .retain(|node, _| self.view.peers.contains_key(node));
        Ok(())
    }
    /// Returns the statistics of every peer in the view. Never fails.
    fn stats(&self) -> Result<Vec<PeerStats>, Self::Error> {
        Ok(self.read_stats())
    }
}
