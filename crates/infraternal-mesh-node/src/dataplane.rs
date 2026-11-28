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
// These capability flags are independent additive fields in the authenticated identity wire shape.
#[allow(clippy::struct_excessive_bools)]
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
    /// This node accepts operation-bound rotation continuity across authority epochs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rotation_continuity: bool,
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
    /// The first underlay address to send to; `None` waits for the peer to reach this node first.
    pub endpoint: Option<SocketAddr>,
    /// Further addresses to try, in order, while `endpoint` has not carried a packet back (#515,
    /// D391): the peer's LAN address when both nodes share a public address, its server-reflexive
    /// address, and the coordinator's older guess. The coordinator sends them only to nodes whose
    /// identity reply said they accept them, because this struct refuses unknown fields: an older
    /// node gets `endpoint` alone. Empty is omitted, so a snapshot without candidates is unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<SocketAddr>,
    /// The peer runs IPv4-only because IPv6 is off on its mesh link (#578, J1142). Its IPv6 mesh
    /// address stays reserved in `addresses`, but this node installs no IPv6 route or allowed IP
    /// for it and mesh DNS answers no `AAAA` for its name, so a client that asks for IPv6 first
    /// gets "no such record" at once instead of waiting out a connect timeout. The coordinator
    /// sets it only for a peer that reported IPv6 off, and only in snapshots for nodes that said
    /// they understand it, because this struct refuses unknown fields. Omitted while false, so a
    /// dual-stack mesh's snapshots are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ipv4_only: bool,
    /// The peer advertised that it understands the side mark (the receive rule: a marked data
    /// packet never moves its view of our endpoint) and listens on a second UDP socket, so this
    /// node may send it small data datagrams from its own second socket (#260, J1211). The
    /// coordinator sets it only for a peer that said so, and only in snapshots for nodes that
    /// understand the field, because this struct refuses unknown fields. Kernel `WireGuard` and
    /// plain `GotaTun` drop marked packets, so it is never guessed: no mark means no second
    /// socket for that peer. Omitted while false, so a snapshot without capable peers is
    /// unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub side_port: bool,
}

impl Peer {
    /// The mesh addresses this node should route to the peer: always the IPv4 one, and the IPv6
    /// one unless the peer is [`ipv4_only`](Self::ipv4_only). Every place that installs a peer
    /// route or allowed IP uses this one list, so IPv4-only peers are skipped everywhere alike.
    pub fn routed_addresses(&self) -> impl Iterator<Item = std::net::IpAddr> {
        std::iter::once(std::net::IpAddr::V4(self.addresses.ipv4))
            .chain((!self.ipv4_only).then_some(std::net::IpAddr::V6(self.addresses.ipv6)))
    }
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
    /// Subnet routes between this node and the peer (D197 M3). Sent only to a node that said it
    /// understands them (the `{"routes":true}` identity probe), because this struct refuses
    /// unknown fields; omitted while empty, so a mesh without routes keeps its wire shape.
    #[serde(default, skip_serializing_if = "PeerNetworks::is_empty")]
    pub networks: PeerNetworks,
}

/// The approved networks that involve one peer, from the receiving node's side (D197 M3).
///
/// Both lists hold only networks an administrator approved and that the Access policy lets
/// someone reach; an entry's policy is never `None`. A network is in `through` when the peer is
/// its router, and in `served` when this node is the router and the peer may start into it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerNetworks {
    /// Networks behind this peer that this node may start connections into: the node routes
    /// them to the peer and adds them to the peer's allowed IPs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub through: Vec<ReachableNetwork>,
    /// This node's own routed networks that the peer may start connections into: the node
    /// forwards the peer's packets there and, unless told to keep the source, masquerades them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub served: Vec<ServedNetwork>,
}
impl PeerNetworks {
    /// Whether neither list has an entry, which is how the field is left off the wire.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.through.is_empty() && self.served.is_empty()
    }
}

/// A network behind a peer, and what this node may start into it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachableNetwork {
    /// The approved network.
    pub network: infraternal_mesh::networks::Network,
    /// The new connections this node may start into it, from arrows or the mesh default.
    pub outbound: TrafficPolicy,
}

/// One of this node's routed networks, and what a peer may start into it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedNetwork {
    /// The approved network this node routes.
    pub network: infraternal_mesh::networks::Network,
    /// The new connections the peer may start into it.
    pub inbound: TrafficPolicy,
    /// The administrator chose to keep the peer's real mesh address instead of masquerading
    /// (D197 M3: masquerade is the default). Omitted while false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep_source: bool,
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
/// Public proof that the authenticated coordinator still owns this exact rotation operation.
/// A fresh database has no matching random operation UUID, even if its sequence restarts at one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationContinuation {
    /// Random operation identity retained in the coordinator database across process restarts.
    pub operation_id: String,
    /// Monotonic sequence within that database's node rotation history.
    pub sequence: u64,
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
    /// Missing values identify legacy snapshots. An authenticated full snapshot bound to the
    /// current local key may replace an epoch-bearing authority with an epoch-less one, allowing
    /// coordinator rollback. The transition durably retires the old authority before applying
    /// changed peers; unchanged peers retain their sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_epoch: Option<String>,
    /// The open coordinator operation; an exact match may retain its local journal on epoch change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_operation: Option<RotationContinuation>,
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
impl PeerPolicy {
    /// Whether `self`, a port continuation from a later chunk, may be merged into `base`, the
    /// peer staged by an earlier chunk of the same snapshot.
    ///
    /// A continuation only adds ports: it names the same peer identity, never grants `All` (that
    /// fits in the base part), and never carries subnet routes, which always travel in the base
    /// part (D197 M3). Linux and Mac staging both refuse a chunk that breaks this.
    #[must_use]
    pub fn continues(&self, base: &Self) -> bool {
        self.peer == base.peer
            && self.networks.is_empty()
            && !matches!(self.inbound, TrafficPolicy::All)
            && !matches!(self.outbound, TrafficPolicy::All)
    }

    /// Whether this peer's grants allow at least one network packet in either direction.
    ///
    /// The `GotaTun` node workers (Linux and macOS) install, and let through the handshake
    /// admission guard, only peers for which this is true. A peer with no access gets no device
    /// entry, so the node neither answers its handshakes nor keeps a session alive toward it
    /// (#93478, J781, #483). The kernel engine keeps its complete inventory instead.
    ///
    /// A peer without access still stays in snapshots, so a later grant changes only policy, and
    /// it learns no more of the node's coordinates than an older node would: no private
    /// candidates, and no candidate walk toward it (#515).
    #[must_use]
    pub fn has_network_access(&self) -> bool {
        /// Whether one direction's rule allows at least one packet tuple.
        fn allows_any(policy: &TrafficPolicy) -> bool {
            match policy {
                TrafficPolicy::All => true,
                TrafficPolicy::Ports(ports) => !ports.is_empty(),
                TrafficPolicy::None => false,
            }
        }
        allows_any(&self.inbound)
            || allows_any(&self.outbound)
            || self
                .networks
                .through
                .iter()
                .any(|network| allows_any(&network.outbound))
            || self
                .networks
                .served
                .iter()
                .any(|network| allows_any(&network.inbound))
    }
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
pub fn same_runtime_content(left: &Config, right: &Config) -> bool {
    let mut normalized = left.clone();
    normalized
        .rotation_operation
        .clone_from(&right.rotation_operation);
    normalized
        .authority_epoch
        .clone_from(&right.authority_epoch);
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
    /// The open coordinator operation; an exact match may retain its local journal on epoch change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_operation: Option<RotationContinuation>,
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

/// Supply the default suffix when the coordinator omits its DNS setting.
#[cfg(feature = "mesh-dns")]
fn default_dns_suffix() -> String {
    DEFAULT_DNS_SUFFIX.to_owned()
}

/// Keep the default suffix out of snapshots for older readers.
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
/// Read access updates while enforcing the action payload bound.
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
            rotation_operation: None,
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
            candidates: Vec::new(),
            ipv4_only: false,
            side_port: false,
        };
        let encoded = serde_json::to_vec(&peer).unwrap();
        let legacy: PreRotationPeer = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(legacy.key, peer.key);
        assert_eq!(legacy.addresses, peer.addresses);
        assert_eq!(legacy.endpoint, peer.endpoint);
    }
}
