//! Public-only direct-path configuration and D216 fallback policy, shared by node and coordinator [165,166,216].
use crate::policy::{
    model::{Addresses, NodeId, PublicKey},
    rules::TrafficPolicy,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr};

/// Accept only the canonical UUID text used to identify one durable server deployment authority.
#[must_use]
pub fn valid_authority_epoch(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

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
    #[cfg(feature = "mesh-dns")]
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dns_names: bool,
    /// This node supports durable automatic key rotation actions.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub key_rotation: bool,
    /// This node accepts authenticated authority epochs on configuration chunks.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authority_epoch: bool,
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
    /// Other identity accepted during the coordinator's overlap window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_key: Option<PublicKey>,
    /// Keep outgoing host routes on `previous_key` until the new local key is active.
    /// This avoids sending to a candidate identity before its `WireGuard` interface switches.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub previous_active: bool,
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
    /// Whether the Access policy lets this peer start TCP/22 toward this
    /// node, sent only where `inbound` is wider than the policy: on the
    /// server's own node, whose inbound adds the infraternal control-plane
    /// ports for every member (D215, D352). Mesh SSH enforces Access itself
    /// and reads this (D235 "two checks", #221); see
    /// [`Config::admits_ssh`]. Absent everywhere else, so strict parsers in
    /// older infraternal agents never see it (only the server's embedded
    /// infraternal agent, the same binary, receives a server-node snapshot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_ssh: Option<bool>,
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
    /// Authenticated server deployment authority retained beside this peer snapshot.
    /// Missing values are legacy snapshots; once an epoch is present, an epoch-less replacement
    /// must retire the old peers and be refused instead of silently downgrading authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_epoch: Option<String>,
    pub node: NodeId,
    /// The coordinator's canonical single-label name for this node; absent on legacy snapshots.
    #[cfg(feature = "mesh-dns")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Mesh DNS zone; default omission preserves receivers that have not negotiated DNS names.
    #[cfg(feature = "mesh-dns")]
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
    #[cfg(feature = "mesh-dns")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_names: BTreeMap<NodeId, String>,
}
impl Config {
    /// Whether the Access policy lets `peer` start a TCP/22 connection to
    /// this node: the check mesh SSH makes on every connection (#221).
    ///
    /// On the server's own node only `access_ssh` answers (its inbound also
    /// carries the control plane); a server-node snapshot without it
    /// (written before #221) refuses. A saved configuration without the
    /// `server` field refuses too, since it cannot say whether it is the
    /// server's node. On every other node the installed inbound is the policy.
    #[must_use]
    pub fn admits_ssh(&self, peer: &PeerPolicy) -> bool {
        let ssh = crate::policy::rules::Port {
            protocol: crate::policy::rules::Protocol::Tcp,
            number: 22,
        };
        match (peer.access_ssh, self.server) {
            (Some(admitted), _) => admitted,
            // Another node's configuration: its installed inbound is the policy.
            (None, Some(server)) if server != self.node => peer.inbound.allows(ssh),
            // The server's node without the answer (written before #221), or
            // a saved configuration that predates the `server` field and so
            // cannot say which node it is (J236 P3-4): refuse.
            (None, _) => false,
        }
    }
}

/// Whether two snapshots describe the same installed mesh while ignoring authority and revision metadata.
///
/// A coordinator restart can advance its authenticated authority epoch while returning the same
/// policy. Nodes use this check to update that metadata without rebuilding peers or losing their
/// existing handshakes.
#[must_use]
pub(crate) fn same_runtime_content(left: &Config, right: &Config) -> bool {
    let mut normalized = left.clone();
    normalized.authority_epoch = right.authority_epoch.clone();
    normalized.version = right.version;
    normalized == *right
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
    /// Repeated in every part so a changed authenticated deployment epoch retires old peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_epoch: Option<String>,
    /// Repeated on every chunk and checked before applying the complete policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<NodeId>,
    pub node: NodeId,
    /// Repeated on every chunk so a rename commits with the complete accepted revision.
    #[cfg(feature = "mesh-dns")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Repeated on every chunk so a zone change commits with the complete accepted revision.
    #[cfg(feature = "mesh-dns")]
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
    #[cfg(feature = "mesh-dns")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_names: BTreeMap<NodeId, String>,
    /// Access revocation removes a name without retiring its peer key or policy entry.
    #[cfg(feature = "mesh-dns")]
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

/// The mesh DNS suffix every node answers under (D165, D197): `<host>.internal`.
/// Public so examples and fixtures build configs with the same value the product uses.
pub const DEFAULT_DNS_SUFFIX: &str = "internal";

#[cfg(feature = "mesh-dns")]
fn default_dns_suffix() -> String {
    DEFAULT_DNS_SUFFIX.to_owned()
}

#[cfg(feature = "mesh-dns")]
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

#[cfg(test)]
mod compatibility_tests {
    //! Keep non-rotating peer snapshots readable by strict pre-rotation nodes.
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The peer shape understood by nodes built before rotation fields were added.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PreRotationPeer {
        key: PublicKey,
        addresses: Addresses,
        endpoint: Option<SocketAddr>,
    }

    /// Authority and revision changes alone do not require a peer reconfiguration.
    #[test]
    fn same_runtime_content_ignores_authority_and_revision() {
        let current = Config {
            local_key: Some(PublicKey([1; 32])),
            server: Some(NodeId(3)),
            authority_epoch: Some("00000000-0000-4000-8000-000000000001".to_owned()),
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: DEFAULT_DNS_SUFFIX.to_owned(),
            version: 10,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().unwrap(),
                ipv6: "fd01::1".parse().unwrap(),
            },
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            peers: BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
            peer_names: BTreeMap::new(),
        };
        let mut restarted = current.clone();
        restarted.authority_epoch = Some("00000000-0000-4000-8000-000000000002".to_owned());
        restarted.version = 2;
        assert!(same_runtime_content(&current, &restarted));

        restarted.default_policy = DefaultPolicy::Allow;
        assert!(!same_runtime_content(&current, &restarted));
    }

    /// A non-rotating peer keeps the old wire shape so an upgraded server can still configure it.
    #[test]
    fn nonrotating_peer_uses_pre_rotation_wire_shape() {
        let peer = Peer {
            key: PublicKey([1; 32]),
            previous_key: None,
            previous_active: false,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().unwrap(),
                ipv6: "fd01::2".parse().unwrap(),
            },
            endpoint: None,
        };
        let encoded = serde_json::to_vec(&peer).unwrap();
        let legacy: PreRotationPeer = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(legacy.key, peer.key);
        assert_eq!(legacy.addresses, peer.addresses);
        assert_eq!(legacy.endpoint, peer.endpoint);
    }
}
