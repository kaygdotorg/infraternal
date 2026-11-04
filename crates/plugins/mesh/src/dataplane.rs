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
    /// New coordinators use ranges only after the enabled receiver advertises support.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compact_access: bool,
    /// Resolver support is negotiated separately from compact access snapshots [#266].
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dns_names: bool,
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
/// Directional network access for initiating tuples and their authenticated replies [242].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPolicy {
    pub peer: Peer,
    pub inbound: TrafficPolicy,
    pub outbound: TrafficPolicy,
}

/// Coordinator-owned DNS identity used by mesh-only listeners and names [#266, #281].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureIdentity {
    /// Stable machine label assigned by the coordinator.
    pub machine_name: String,
    /// Coordinator-selected suffix for proxy naming; `.internal` is the compatibility default.
    /// The optional DNS resolver remains a separate feature and does not follow from this field.
    pub dns_suffix: String,
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
    /// The coordinator's canonical single-label name for this node; absent on legacy snapshots.
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Mesh DNS zone; default omission preserves receivers that have not negotiated DNS names.
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(
        default = "default_dns_suffix",
        skip_serializing_if = "is_default_dns_suffix"
    )]
    pub dns_suffix: String,
    pub version: u64,
    pub addresses: Addresses,
    pub default_policy: DefaultPolicy,
    /// Optional so nodes without proxy support retain the legacy wire shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<ExposureIdentity>,
    pub peers: BTreeMap<NodeId, PeerPolicy>,
    /// Names for peers in the same policy snapshot, keyed by their stable node identity.
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_names: BTreeMap<NodeId, String>,
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
    /// Repeated on every chunk so a rename commits with the complete accepted revision.
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Repeated on every chunk so a zone change commits with the complete accepted revision.
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(
        default = "default_dns_suffix",
        skip_serializing_if = "is_default_dns_suffix"
    )]
    pub dns_suffix: String,
    pub from_version: Option<u64>,
    pub version: u64,
    pub index: u32,
    pub last: bool,
    pub addresses: crate::policy::model::Addresses,
    pub default_policy: crate::dataplane::DefaultPolicy,
    /// Repeated in every chunk so name/address and grants commit atomically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<ExposureIdentity>,
    pub upserted: BTreeMap<NodeId, PeerPolicy>,
    /// Continuations union port grants into a staged peer; they never apply a partial policy.
    #[serde(default)]
    pub merged: BTreeMap<NodeId, PeerPolicy>,
    pub removed: Vec<NodeId>,
    /// Name updates are staged with peer changes and published only on the final chunk.
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_names: BTreeMap<NodeId, String>,
    /// Access revocation removes a name without retiring its peer key or policy entry.
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_peer_names: Vec<NodeId>,
    /// Negotiated, final access-only delta; snapshots retain ordinary peer chunks.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_access_updates"
    )]
    pub access_updates: Vec<AccessUpdate>,
}

pub(crate) const DEFAULT_DNS_SUFFIX: &str = "internal";

#[cfg(feature = "mesh-dns-spike")]
fn default_dns_suffix() -> String {
    DEFAULT_DNS_SUFFIX.to_owned()
}

#[cfg(feature = "mesh-dns-spike")]
#[allow(clippy::ptr_arg)]
fn is_default_dns_suffix(suffix: &String) -> bool {
    suffix == DEFAULT_DNS_SUFFIX
}

/// Ordered existing-node range whose directional rules change without peer identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessUpdate {
    pub first: NodeId,
    pub last: NodeId,
    /// Null keeps this direction; a concrete rule replaces it.
    pub inbound: Option<TrafficPolicy>,
    pub outbound: Option<TrafficPolicy>,
}

// Deriving a struct decoder also accepts positional arrays. Range entries are
// objects on this boundary; forwarding MapAccess preserves duplicate-field refusal.
fn deserialize_access_updates<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<AccessUpdate>, D::Error> {
    struct Object(AccessUpdate);
    impl<'de> Deserialize<'de> for Object {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Object;
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("an access update object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    map: A,
                ) -> Result<Object, A::Error> {
                    AccessUpdate::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                        .map(Object)
                }
            }
            deserializer.deserialize_map(Visitor)
        }
    }
    Vec::<Object>::deserialize(deserializer)
        .map(|objects| objects.into_iter().map(|object| object.0).collect())
}
