//! Data-plane boundary and deterministic test backend; no device library or transport is selected.
use crate::{
    model::{MeshError, NodeId},
    view::{PeerDiff, PeerView},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathKind {
    Unknown,
    Direct,
    Relayed { relay: NodeId },
}

/// Seconds since Unix epoch for reporting; counters are cumulative bytes from the real backend.
/// Aggregate overlapping keys by logical node and preserve totals when the old key retires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStats {
    pub node: NodeId,
    pub path: PathKind,
    pub last_handshake_unix_secs: Option<u64>,
    pub received_bytes: u64,
    pub sent_bytes: u64,
}

/// Slice 2 renders this type through CLI/API/MCP without exposing coordinator internals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshStatus {
    pub node: NodeId,
    pub rule_version: u64,
    pub desired_rule_version: Option<u64>,
    pub peers: Vec<PeerStats>,
}

/// Apply policy and keys atomically. On failure retain the old view; no partial grant is safe.
/// Enforce /32+/128 routes, new-connection filters in BOTH directions and established replies.
/// Accept both public keys during rotation and retain last state indefinitely on server loss.
/// Real backends must prove overlap without conflicting allowed-IP routes before slice 2 wiring.
pub trait Backend {
    type Error;
    /// # Errors
    /// Returns the backend error on failed atomic application; old state must remain intact.
    fn apply(&mut self, diff: &PeerDiff) -> Result<(), Self::Error>;
    /// # Errors
    /// Returns the backend error if device counters cannot be read.
    fn stats(&self) -> Result<Vec<PeerStats>, Self::Error>;
}

/// Test-only data plane state. It models messages, not kernel packet processing or handshakes.
#[derive(Clone, Debug)]
pub struct MemoryBackend {
    view: PeerView,
    stats: BTreeMap<NodeId, PeerStats>,
}
impl MemoryBackend {
    #[must_use]
    pub fn new(view: PeerView) -> Self {
        Self {
            view,
            stats: BTreeMap::new(),
        }
    }
    #[must_use]
    pub fn view(&self) -> &PeerView {
        &self.view
    }
    /// # Errors
    /// Returns `UnknownNode` if the peer is absent from the current view.
    pub fn set_stats(&mut self, stats: PeerStats) -> Result<(), MeshError> {
        if !self.view.peers.contains_key(&stats.node) {
            return Err(MeshError::UnknownNode);
        }
        self.stats.insert(stats.node, stats);
        Ok(())
    }
    #[must_use]
    pub fn status(&self, desired_rule_version: Option<u64>) -> MeshStatus {
        MeshStatus {
            node: self.view.node,
            rule_version: self.view.rule_version,
            desired_rule_version,
            peers: self.read_stats(),
        }
    }
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
    /// # Errors
    /// Returns the backend error on failed atomic application; old state must remain intact.
    fn apply(&mut self, diff: &PeerDiff) -> Result<(), Self::Error> {
        self.view.apply(diff)?;
        self.stats
            .retain(|node, _| self.view.peers.contains_key(node));
        Ok(())
    }
    /// # Errors
    /// Returns the backend error if device counters cannot be read.
    fn stats(&self) -> Result<Vec<PeerStats>, Self::Error> {
        Ok(self.read_stats())
    }
}
