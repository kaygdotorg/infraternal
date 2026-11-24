//! Subnet routes (D197 M3): networks a node routes for the mesh, and the checks they must pass.
//!
//! A node *advertises* networks it can reach (a LAN behind it, for example). Nothing happens
//! until an administrator *approves* one: only then does the coordinator hand it to peers, and
//! only to peers that an arrow (or the mesh default, D216) lets reach it. An approved network is
//! the target of arrows ([`crate::rules::Endpoint::Network`]); it is never their source, because
//! machines on that network are not mesh members and cannot be identified.
//!
//! This module owns the [`Network`] type (one canonical CIDR) and [`check_routable`], which
//! refuses, with a sentence a person can act on, every network that must never be routed:
//! the default route (that is an exit node, D197 M2), loopback, link-local, multicast and
//! reserved space, anything overlapping the mesh's own range, and (in this slice) IPv6.
//! Overlaps between approved networks are refused by the coordinator, which knows them all.
use crate::model::{MeshError, MeshSettings, NodeId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

/// The identity of one approved network. The server's route table hands these out and never
/// reuses one, so an arrow that pointed at a revoked approval can never come back to life when
/// the same network is approved again later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub u64);

/// One canonical IP network, such as `192.168.1.0/24`.
///
/// "Canonical" means no address bits are set below the prefix: `192.168.1.0/24` is accepted,
/// `192.168.1.7/24` is refused (with a hint naming the canonical form), so two spellings of one
/// network can never be approved side by side. The fields are private so every value went
/// through [`Network::new`]; it serializes as its text form (`"192.168.1.0/24"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Network {
    /// First address of the network.
    address: IpAddr,
    /// Prefix length: 0 to 32 for IPv4, 0 to 128 for IPv6.
    prefix: u8,
}

impl Network {
    /// Builds a network from its first address and prefix length.
    ///
    /// # Errors
    /// Returns `InvalidNetwork` when the prefix is too long for the address family or when the
    /// address has bits set below the prefix.
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, MeshError> {
        let network = Self { address, prefix };
        if u32::from(prefix) > network.width() || network.bounds().0 != network.number() {
            return Err(MeshError::InvalidNetwork);
        }
        Ok(network)
    }
    /// The network's first address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }
    /// The prefix length in bits.
    #[must_use]
    pub const fn prefix(self) -> u8 {
        self.prefix
    }
    /// Whether this is an IPv4 network.
    #[must_use]
    pub const fn is_ipv4(self) -> bool {
        self.address.is_ipv4()
    }
    /// Whether `address` lies inside this network. Addresses of the other family never do.
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        if address.is_ipv4() != self.is_ipv4() {
            return false;
        }
        let (first, last) = self.bounds();
        let number = match address {
            IpAddr::V4(ip) => u128::from(u32::from(ip)),
            IpAddr::V6(ip) => u128::from(ip),
        };
        first <= number && number <= last
    }
    /// Whether the two networks share at least one address. Networks of different families
    /// never overlap.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        if self.is_ipv4() != other.is_ipv4() {
            return false;
        }
        let (a, b) = (self.bounds(), other.bounds());
        a.0 <= b.1 && b.0 <= a.1
    }
    /// The address width of the family: 32 or 128.
    const fn width(self) -> u32 {
        if self.address.is_ipv4() { 32 } else { 128 }
    }
    /// The first address as an integer.
    fn number(self) -> u128 {
        match self.address {
            IpAddr::V4(ip) => u128::from(u32::from(ip)),
            IpAddr::V6(ip) => u128::from(ip),
        }
    }
    /// First and last address as integers, both inclusive, with host bits cleared from the
    /// first. [`Network::new`] uses the first to prove the input was canonical.
    fn bounds(self) -> (u128, u128) {
        let host_bits = self.width().saturating_sub(u32::from(self.prefix));
        let host_mask = if host_bits == 0 {
            0
        } else {
            u128::MAX >> (128 - host_bits)
        };
        let first = self.number() & !host_mask;
        (first, first | host_mask)
    }
    /// The canonical form of `address/prefix`: the same prefix with host bits cleared. Used to
    /// tell a person which network they probably meant.
    fn canonical_of(address: IpAddr, prefix: u8) -> Option<Self> {
        let probe = Self { address, prefix };
        if u32::from(prefix) > probe.width() {
            return None;
        }
        let first = probe.bounds().0;
        let address = match address {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(u32::try_from(first).ok()?)),
            IpAddr::V6(_) => IpAddr::V6(first.into()),
        };
        Some(Self { address, prefix })
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// Why a piece of text is not a network, in words a person can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseNetworkError(pub String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseNetworkError {}

impl FromStr for Network {
    type Err = ParseNetworkError;
    /// Parses `address/prefix`. The prefix is required, so `192.168.1.5` is never silently
    /// read as one host; a value with host bits set is refused with its canonical form.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let Some((address, prefix)) = text.split_once('/') else {
            return Err(ParseNetworkError(format!(
                "{text} has no prefix length: write it as a network, such as 192.168.1.0/24"
            )));
        };
        let address: IpAddr = address
            .parse()
            .map_err(|_| ParseNetworkError(format!("{text} is not an IP network")))?;
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|prefix| u32::from(*prefix) <= if address.is_ipv4() { 32 } else { 128 })
            .ok_or_else(|| ParseNetworkError(format!("{text} has an impossible prefix length")))?;
        Self::new(address, prefix).map_err(|_| {
            let hint = Self::canonical_of(address, prefix).map_or_else(String::new, |canonical| {
                format!("; did you mean {canonical}?")
            });
            ParseNetworkError(format!(
                "{text} has host bits set below the /{prefix} prefix{hint}"
            ))
        })
    }
}

impl Serialize for Network {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Network {
    /// Every decoded network passes the same canonical check as typed input.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// An approved network: who routes it, and whether its traffic is masqueraded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedNetwork {
    /// The approval's stable identity, the target arrows name.
    pub id: NetworkId,
    /// The node that advertised the network and forwards traffic into it.
    pub router: NodeId,
    /// The network itself.
    pub network: Network,
    /// `true` (the default, D197 M3): the router rewrites the source of forwarded packets to its
    /// own address on that network, so hosts there need no route back to the mesh. `false`
    /// keeps the peer's real mesh address; the network then needs a route to the mesh range
    /// through the router.
    pub masquerade: bool,
}

/// Why a network may not be routed, as a sentence for the CLI, the API and the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkRefusal {
    /// IPv6 networks wait for a later slice: turning on IPv6 forwarding changes how every
    /// interface of the router handles router advertisements.
    Ipv6(Network),
    /// A prefix of zero is every address, which is an exit node (D197 M2), not a subnet route.
    DefaultRoute(Network),
    /// Loopback, link-local, multicast, "this network" or reserved space.
    Special(Network, &'static str),
    /// The network overlaps the mesh's own address range.
    MeshRange(Network, Network),
    /// The network overlaps one that is already approved.
    Overlap {
        /// The refused network.
        network: Network,
        /// The approved network it overlaps.
        approved: ApprovedNetwork,
    },
}

impl fmt::Display for NetworkRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv6(network) => write!(
                f,
                "{network} is an IPv6 network; subnet routes carry IPv4 networks for now"
            ),
            Self::DefaultRoute(network) => write!(
                f,
                "{network} is every address: that would make the machine an exit node, which a subnet route is not"
            ),
            Self::Special(network, kind) => {
                write!(
                    f,
                    "{network} is {kind} and is never routed through the mesh"
                )
            }
            Self::MeshRange(network, mesh) => write!(
                f,
                "{network} overlaps the mesh's own range {mesh}; pick a network outside it"
            ),
            Self::Overlap { network, approved } => write!(
                f,
                "{network} overlaps {}, which is already approved (route {}); revoke that one first or pick a network that does not overlap",
                approved.network, approved.id.0
            ),
        }
    }
}

/// The IPv4 blocks that are never routed, with the words used to explain why.
const SPECIAL_IPV4: [(Ipv4Addr, u8, &str); 5] = [
    (Ipv4Addr::UNSPECIFIED, 8, "the \"this network\" block"),
    (Ipv4Addr::new(127, 0, 0, 0), 8, "loopback"),
    (Ipv4Addr::new(169, 254, 0, 0), 16, "link-local"),
    (Ipv4Addr::new(224, 0, 0, 0), 4, "multicast"),
    (Ipv4Addr::new(240, 0, 0, 0), 4, "reserved"),
];

/// Checks that `network` may be routed in a mesh with `settings`, before any overlap with other
/// approved networks is considered (the coordinator adds that check).
///
/// # Errors
/// Returns the [`NetworkRefusal`] that explains the first rule `network` breaks.
pub fn check_routable(network: Network, settings: &MeshSettings) -> Result<(), NetworkRefusal> {
    if network.prefix == 0 {
        return Err(NetworkRefusal::DefaultRoute(network));
    }
    if !network.is_ipv4() {
        return Err(NetworkRefusal::Ipv6(network));
    }
    for (address, prefix, kind) in SPECIAL_IPV4 {
        // The table's entries are canonical constants.
        if let Ok(special) = Network::new(IpAddr::V4(address), prefix)
            && special.overlaps(network)
        {
            return Err(NetworkRefusal::Special(network, kind));
        }
    }
    if let Ok(mesh) = Network::new(IpAddr::V4(settings.ipv4.network), settings.ipv4.prefix)
        && mesh.overlaps(network)
    {
        return Err(NetworkRefusal::MeshRange(network, mesh));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The canonical form, parsing hints and the routability rules.
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Parse a network that the test knows is valid.
    fn net(text: &str) -> Network {
        text.parse().unwrap()
    }

    /// A prefix is required, host bits are refused with the canonical form as a hint, and bad text is refused.
    #[test]
    fn parsing_requires_a_prefix_and_a_canonical_network() {
        assert_eq!(net("192.168.1.0/24").to_string(), "192.168.1.0/24");
        assert_eq!(net("10.0.0.1/32").prefix(), 32);
        let missing = "192.168.1.5".parse::<Network>().unwrap_err().0;
        assert!(missing.contains("no prefix length"), "{missing}");
        let host_bits = "192.168.1.7/24".parse::<Network>().unwrap_err().0;
        assert!(
            host_bits.contains("did you mean 192.168.1.0/24?"),
            "{host_bits}"
        );
        assert!("10.0.0.0/33".parse::<Network>().is_err());
        assert!("not-an-ip/8".parse::<Network>().is_err());
        assert_eq!(net("fd00::/64").to_string(), "fd00::/64");
    }

    /// Networks travel as their text, and decoding applies the same canonical check as typed input.
    #[test]
    fn serde_uses_the_text_form_and_refuses_noncanonical_input() {
        let encoded = serde_json::to_string(&net("10.1.0.0/16")).unwrap();
        assert_eq!(encoded, "\"10.1.0.0/16\"");
        assert_eq!(
            serde_json::from_str::<Network>(&encoded).unwrap(),
            net("10.1.0.0/16")
        );
        assert!(serde_json::from_str::<Network>("\"10.1.2.3/16\"").is_err());
    }

    /// Overlap and containment compare address ranges, never across address families.
    #[test]
    fn overlap_and_containment_follow_the_address_ranges() {
        assert!(net("10.0.0.0/8").overlaps(net("10.20.0.0/16")));
        assert!(net("10.20.0.0/16").overlaps(net("10.0.0.0/8")));
        assert!(!net("10.0.0.0/24").overlaps(net("10.0.1.0/24")));
        assert!(!net("10.0.0.0/8").overlaps(net("fd00::/8")));
        assert!(net("192.168.1.0/24").contains("192.168.1.200".parse().unwrap()));
        assert!(!net("192.168.1.0/24").contains("192.168.2.1".parse().unwrap()));
        assert!(!net("192.168.1.0/24").contains("::1".parse().unwrap()));
    }

    /// Every never-routed block, the mesh range and IPv6 are refused with a sentence that says why.
    #[test]
    fn unroutable_networks_are_refused_with_a_reason() {
        let settings = MeshSettings::new([1, 2, 3, 4, 5]);
        assert!(check_routable(net("192.168.1.0/24"), &settings).is_ok());
        let refused = |text: &str| {
            check_routable(net(text), &settings)
                .unwrap_err()
                .to_string()
        };
        assert!(refused("0.0.0.0/0").contains("exit node"));
        assert!(refused("127.0.0.0/8").contains("loopback"));
        assert!(refused("169.254.0.0/16").contains("link-local"));
        assert!(refused("224.0.0.0/4").contains("multicast"));
        assert!(refused("10.254.3.0/24").contains("mesh's own range 10.254.0.0/16"));
        assert!(refused("10.0.0.0/8").contains("mesh's own range"));
        assert!(refused("fd00::/64").contains("IPv6"));
    }
}
