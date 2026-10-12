//! Public-only direct-path configuration and D216 fallback policy, shared by node and coordinator [165,166,216].
use crate::policy::{
    model::{Addresses, NodeId, PublicKey},
    rules::TrafficPolicy,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr};

/// Public node identity and actual UDP socket coordinates; private material has no field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub public_key: PublicKey,
    pub port: u16,
}

/// Explicit pair rules replace this fallback, so port grants also narrow an open mesh.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultPolicy {
    Allow,
    Deny,
}
impl Default for DefaultPolicy {
    fn default() -> Self {
        if cfg!(feature = "ee") {
            Self::Deny
        } else {
            Self::Allow
        }
    }
}
/// Public kernel peer; only host routes are supported in this slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub key: PublicKey,
    pub addresses: Addresses,
    pub endpoint: Option<SocketAddr>,
}
/// New connection policies. Established authenticated replies pass independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPolicy {
    pub peer: Peer,
    pub inbound: TrafficPolicy,
    pub outbound: TrafficPolicy,
}
/// All fields are public. Private key material has no representation on this boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Authenticated coordinator binding to the enabled local kernel key.
    /// Legacy snapshots lack it and cannot replace an accepted node identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_key: Option<PublicKey>,
    /// Explicit server identity; older persisted snapshots cannot propose a route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<NodeId>,
    pub node: NodeId,
    pub version: u64,
    pub addresses: Addresses,
    pub default_policy: DefaultPolicy,
    pub peers: BTreeMap<NodeId, PeerPolicy>,
}
/// Transport selector seam: a mesh destination never replaces the enrolled TLS server name [215].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPath {
    pub mesh: SocketAddr,
    pub enrolled_fallback: SocketAddr,
}

/// One transport chunk is bounded by the existing plugin action frame resource budget.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    /// Repeated in every part so a split snapshot cannot change its binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_key: Option<PublicKey>,
    /// Repeated on every chunk and checked before applying the complete policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<NodeId>,
    pub node: NodeId,
    pub from_version: Option<u64>,
    pub version: u64,
    pub index: u32,
    pub last: bool,
    pub addresses: crate::policy::model::Addresses,
    pub default_policy: crate::dataplane::DefaultPolicy,
    pub upserted: BTreeMap<NodeId, PeerPolicy>,
    /// Continuations union port grants into a staged peer; they never apply a partial policy.
    #[serde(default)]
    pub merged: BTreeMap<NodeId, PeerPolicy>,
    pub removed: Vec<NodeId>,
}
