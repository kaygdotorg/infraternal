//! This node's applied mesh configuration, reduced to what mesh-only services need [D235, D252], #221.
//!
//! The mesh plugin produces it from each accepted configuration; services
//! such as mesh SSH consume it without depending on the mesh plugin, so
//! either can be compiled out on its own. Its policy facts are the ones the
//! kernel firewall enforces, never a second policy.

use std::{collections::BTreeMap, net::IpAddr};

/// One mesh peer as this node's applied configuration sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshPeer {
    /// The peer's mesh addresses: a source address maps to this peer only through them.
    pub addresses: Vec<IpAddr>,
    /// The peer's inbound policy on this node admits TCP/22.
    pub ssh_allowed: bool,
}

/// This node's mesh identity, addresses and peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshView {
    /// This node's mesh ID.
    pub node: u64,
    /// This node's own mesh addresses: the only addresses mesh services bind.
    pub addresses: Vec<IpAddr>,
    /// The mesh network interface those addresses live on.
    pub interface: String,
    /// Every peer in the applied configuration, by mesh ID.
    pub peers: BTreeMap<u64, MeshPeer>,
}
