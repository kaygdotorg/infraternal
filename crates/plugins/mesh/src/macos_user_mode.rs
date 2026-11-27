//! Pure rules for macOS user mode (#146, D203 C2 as amended 2026-11-20).
//!
//! In user mode the infraternal agent runs as the logged-in person, from a
//! `LaunchAgent`, with its files under `~/Library` (D395). Only three things on
//! a Mac need root for the mesh: creating the utun, routing the mesh prefix
//! into it, and pointing the system resolver at the mesh resolver address. A
//! small root helper ([`crate::macos_helper`]) does exactly those, on request,
//! and exits. Everything here is the part of that design that needs no
//! operating system: the wire format between agent and helper, the checks the
//! helper applies to every request, the routing-table reader behind the
//! overlap check, and the two launchd property lists. Keeping it free of side
//! effects lets the Linux gate run its tests.
//!
//! **Wire format.** One request and one reply per connection. Each is a
//! 2-byte big-endian length and that many bytes of JSON, at most
//! [`MAX_MESSAGE_BYTES`]. Unknown fields and versions other than
//! [`PROTOCOL_VERSION`] are refused. The utun travels as one `SCM_RIGHTS`
//! descriptor beside the frame: in the reply to [`Request::Open`], and in
//! every request that changes an existing utun ([`Request::needs_utun`]), so a
//! caller can only configure a utun it already holds.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// The one reverse-DNS root every identifier infraternal gives macOS starts with (#580).
///
/// Apple wants a unique reverse-DNS-style string, not a domain we own, so the owner chose
/// `kayg.infraternal` (2026-11-24). The iOS app uses the same root (its tunnel extension is
/// `kayg.infraternal.tunnel`). Builds before this change used `org.infraternal`; [`legacy`]
/// keeps those names so an existing Mac is moved over, never stranded.
pub const IDENTIFIER_ROOT: &str = "kayg.infraternal";
/// The bundle identifier embedded in the macOS binary's `Info.plist` section (#576), and so its
/// code-signing identifier; the user-mode `LaunchAgent` names it in `AssociatedBundleIdentifiers`,
/// as TN3179 asks of agents not installed through `SMAppService`, to tie the agent's Local Network
/// use to that identity. Must equal `crates/infraternal/macos/Info.plist` (a test checks it).
pub const BUNDLE_IDENTIFIER: &str = "kayg.infraternal";
/// The launchd label of the root-mode system service (the `LaunchDaemon`).
pub const DAEMON_LABEL: &str = "kayg.infraternal.mesh";
/// The root-mode service's launchd property list, root-owned.
pub const DAEMON_PLIST: &str = "/Library/LaunchDaemons/kayg.infraternal.mesh.plist";
/// The launchd label of the on-demand root helper.
pub const HELPER_LABEL: &str = "kayg.infraternal.mesh-helper";
/// The helper's launchd property list, root-owned.
pub const HELPER_PLIST: &str = "/Library/LaunchDaemons/kayg.infraternal.mesh-helper.plist";
/// The root-owned copy of the binary that launchd runs as the helper.
///
/// It is never the person's own copy: anything that person (or code running
/// as them) can write must not run as root.
pub const HELPER_BINARY: &str = "/Library/PrivilegedHelperTools/kayg.infraternal.mesh-helper";
/// The folder Apple reserves for privileged helper tools.
pub const HELPER_DIRECTORY: &str = "/Library/PrivilegedHelperTools";
/// The socket launchd listens on for the helper; owned by the registered user, mode 0600.
pub const HELPER_SOCKET: &str = "/var/run/kayg.infraternal.mesh-helper.sock";
/// The hidden first argument that turns the binary into the helper.
pub const HELPER_ENTRY: &str = "__mesh-helper";
/// The launchd label of the user-mode agent.
pub const AGENT_LABEL: &str = "kayg.infraternal.agent";
/// The receipt in a user-mode install's base folder that names the host it belongs to.
pub const USER_RECEIPT: &str = ".user-owner";
/// The hidden entry a user-mode agent starts, in its own process group, to remove its install
/// after the server's authenticated uninstall reply is written (J1087, J1027).
///
/// The child waits for one armed byte on standard input, so a reply the transport drops
/// (stdin closes unread) removes nothing.
pub const USER_REMOVE_HANDOFF: &str = "--macos-user-remove-after-reply";

/// A user-mode install's base folder for the account whose home is `home` (D395).
#[must_use]
pub fn user_install_base(home: &Path) -> PathBuf {
    home.join("Library/Application Support/infraternal")
}

/// The binary a user-mode `LaunchAgent` runs, under [`user_install_base`].
#[must_use]
pub fn user_install_binary(home: &Path) -> PathBuf {
    user_install_base(home).join("bin/infraternal")
}

/// The receipt naming the install's host, under [`user_install_base`].
#[must_use]
pub fn user_install_receipt(home: &Path) -> PathBuf {
    user_install_base(home).join(USER_RECEIPT)
}

/// Whether a user-mode receipt's `contents` name exactly `host`.
///
/// `host` must be the 32-digit lowercase form the receipt is written in, so a removal request
/// for any other text never matches a receipt by accident.
#[must_use]
pub fn receipt_names_host(contents: &str, host: &str) -> bool {
    host.len() == 32
        && host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && contents.trim_end_matches('\n') == host
}

/// List only resolver entries carrying the root-owned infraternal marker.
///
/// # Errors
/// Reports an unreadable resolver directory or entry.
#[cfg(all(feature = "agent", feature = "mesh-dns", target_os = "macos"))]
pub fn managed_resolvers() -> std::io::Result<Vec<PathBuf>> {
    crate::dns_integration::managed_macos_paths()
}

/// The version both sides must speak; a mismatch is refused, never guessed.
pub const PROTOCOL_VERSION: u32 = 2;
/// Largest request or reply body accepted, in bytes.
///
/// 16 KiB: a [`Request::Networks`] reply names up to 64 networks, each left-out one with its
/// reason (about 175 bytes), which no longer fits the earlier 4 KiB. Every other message is far
/// smaller, and an older peer never sends or receives one this large.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Smallest MTU the helper sets: IPv6's link minimum, so the interface keeps its IPv6 address.
pub const MIN_MTU: u16 = 1280;
/// Largest MTU the helper sets: an Ethernet underlay's packet size.
pub const MAX_MTU: u16 = 1500;
/// The widest IPv4 route the helper adds, so one request cannot capture a whole private block
/// wider than any mesh range the coordinator can hand out by default.
pub const MIN_IPV4_PREFIX: u8 = 8;
/// The narrowest IPv4 route: the coordinator's own limit for a range (two usable hosts).
pub const MAX_IPV4_PREFIX: u8 = 30;
/// The widest IPv4 prefix the agent asks for before its peers force a wider one.
///
/// The node is never told the deployment's range (only its own and its peers' addresses), so
/// the agent asks for the smallest prefix covering them, but no narrower than this. It equals
/// the coordinator's default range, `10.254.0.0/16`, so the default deployment is routed
/// exactly.
pub const DEFAULT_IPV4_PREFIX: u8 = 16;
/// Every mesh node's IPv6 address shares the deployment's unique-local `/48`.
pub const IPV6_PREFIX: u8 = 48;

/// One thing the agent asks the helper to do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    /// Create a fresh utun at [`MIN_MTU`], bring it up, and return it.
    Open,
    /// Give the attached utun the node's addresses and MTU, and route the mesh prefixes to it.
    Address {
        /// The node's own mesh IPv4 address.
        ipv4: Ipv4Addr,
        /// Length of the IPv4 prefix to route, from [`covering_ipv4_prefix`].
        ipv4_prefix: u8,
        /// The node's own mesh IPv6 address; its `/48` is routed.
        ipv6: Ipv6Addr,
        /// Interface MTU, [`MIN_MTU`] to [`MAX_MTU`].
        mtu: u16,
    },
    /// Change only the attached utun's MTU.
    Mtu {
        /// Interface MTU, [`MIN_MTU`] to [`MAX_MTU`].
        mtu: u16,
    },
    /// Point the system resolver for `suffixes` at the mesh resolver address, which the agent
    /// answers from the attached utun (#146, J1027 F2). The helper derives the address from the
    /// utun's own mesh IPv6 address and checks the mesh route sends it into that utun, so the
    /// request carries no address at all.
    Resolver {
        /// DNS suffixes; only those [`allowed_suffix`] accepts are written.
        suffixes: Vec<String>,
    },
    /// Make the approved networks routed into the attached utun exactly `networks` (D197 M3,
    /// #580). Declarative, so a lost reply is repaired by the next request. Each network is
    /// checked by [`crate::macos_subnet_routes::check_requested`] (private IPv4 only, at most 64,
    /// none overlapping another) and planned by [`crate::macos_subnet_routes::plan_networks`]
    /// against the Mac's routes and interfaces before anything changes; the reply says what
    /// happened to each one.
    Networks {
        /// The networks to route, from the agent's applied snapshot.
        networks: Vec<infraternal_mesh::networks::Network>,
    },
    /// Remove every resolver file the helper wrote.
    ClearResolver,
    /// Uninstall: remove resolver files and the helper's own registration and binary.
    Remove,
}

impl Request {
    /// Whether the request must carry the utun it acts on.
    #[must_use]
    pub const fn needs_utun(&self) -> bool {
        matches!(
            self,
            Self::Address { .. } | Self::Mtu { .. } | Self::Resolver { .. } | Self::Networks { .. }
        )
    }
}

/// The request frame: a version and one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Always [`PROTOCOL_VERSION`].
    pub version: u32,
    /// What to do.
    pub request: Request,
}

/// The helper's reply. `error` is a sentence for the person, never private input.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    /// Whether the request was carried out completely.
    pub ok: bool,
    /// The utun's name, for [`Request::Open`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Suffixes the helper refused to point at the agent (see [`allowed_suffix`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_suffixes: Vec<String>,
    /// What happened to each network of a [`Request::Networks`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<NetworkOutcome>,
    /// Why the request failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One network of a [`Request::Networks`] reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkOutcome {
    /// The network, as asked.
    pub network: infraternal_mesh::networks::Network,
    /// Whether it is now routed into the caller's utun.
    pub installed: bool,
    /// Why not, as a sentence for `mesh routes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Reply {
    /// A refusal carrying a reason the person can act on.
    #[must_use]
    pub fn refused(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
            ..Self::default()
        }
    }
}

/// Why a frame or request was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The frame was empty, too long, or not valid JSON for this protocol.
    #[error("the request is malformed")]
    Malformed,
    /// The other side speaks another protocol version.
    #[error("the helper and the agent are different versions; run infraternal up again")]
    Version,
    /// A value is outside what the helper may set; the text says which.
    #[error("{0}")]
    Invalid(String),
}

/// Frame one body: 2-byte big-endian length, then the bytes.
///
/// # Errors
/// Refuses an empty body or one above [`MAX_MESSAGE_BYTES`].
pub fn frame(body: &[u8]) -> Result<Vec<u8>, Refusal> {
    if body.is_empty() || body.len() > MAX_MESSAGE_BYTES {
        return Err(Refusal::Malformed);
    }
    let length = u16::try_from(body.len()).map_err(|_| Refusal::Malformed)?;
    let mut framed = Vec::with_capacity(body.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(body);
    Ok(framed)
}

/// Read the declared body length from a frame's first two bytes.
///
/// # Errors
/// Refuses a zero length or one above [`MAX_MESSAGE_BYTES`], before any body is read.
pub fn frame_length(header: [u8; 2]) -> Result<usize, Refusal> {
    let length = usize::from(u16::from_be_bytes(header));
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err(Refusal::Malformed);
    }
    Ok(length)
}

/// Encode one request at the current version.
///
/// # Errors
/// Only if serialization fails or the body would exceed the frame limit.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, Refusal> {
    let body = serde_json::to_vec(&Envelope {
        version: PROTOCOL_VERSION,
        request: request.clone(),
    })
    .map_err(|_| Refusal::Malformed)?;
    frame(&body)
}

/// Only the version of a request body, read before its request so that a body from another
/// version is reported as a version mismatch even when its request no longer parses.
#[derive(Deserialize)]
struct VersionOnly {
    /// The sender's [`PROTOCOL_VERSION`].
    version: u32,
}

/// Decode and check one request body (without its length header).
///
/// The version is checked first: a body from another version is refused with
/// [`Refusal::Version`], whose sentence tells the person to run `infraternal up` again, which
/// refreshes the helper. The one exception is [`Request::Remove`]: its wire form, the bare
/// string `"remove"`, is frozen, so any version's agent can uninstall any version's helper
/// without an administrator (J1087 on L3).
///
/// # Errors
/// Refuses malformed JSON, unknown fields, another version, and any value
/// [`validate`] refuses.
pub fn decode_request(body: &[u8]) -> Result<Request, Refusal> {
    let VersionOnly { version } = serde_json::from_slice(body).map_err(|_| Refusal::Malformed)?;
    if version != PROTOCOL_VERSION {
        let removal = serde_json::from_slice::<Envelope>(body)
            .is_ok_and(|envelope| envelope.request == Request::Remove);
        return if removal {
            Ok(Request::Remove)
        } else {
            Err(Refusal::Version)
        };
    }
    let envelope: Envelope = serde_json::from_slice(body).map_err(|_| Refusal::Malformed)?;
    validate(&envelope.request)?;
    Ok(envelope.request)
}

/// Check every value in a request against what the helper may set.
///
/// # Errors
/// Names the first value outside its allowed range.
pub fn validate(request: &Request) -> Result<(), Refusal> {
    match request {
        Request::Open | Request::ClearResolver | Request::Remove => Ok(()),
        Request::Mtu { mtu } => validate_mtu(*mtu),
        Request::Address {
            ipv4,
            ipv4_prefix,
            ipv6,
            mtu,
        } => {
            validate_mtu(*mtu)?;
            ipv4_route(*ipv4, *ipv4_prefix)?;
            ipv6_route(*ipv6)?;
            Ok(())
        }
        Request::Resolver { suffixes } => {
            if suffixes.is_empty() || suffixes.len() > 8 {
                return Err(Refusal::Invalid(
                    "a resolver request names one to eight DNS suffixes".to_owned(),
                ));
            }
            for suffix in suffixes {
                crate::policy::model::validate_dns(suffix, false)
                    .map_err(|_| Refusal::Invalid("a DNS suffix is not valid".to_owned()))?;
            }
            Ok(())
        }
        Request::Networks { networks } => crate::macos_subnet_routes::check_requested(networks),
    }
}

/// Refuse an MTU outside [`MIN_MTU`]..=[`MAX_MTU`].
fn validate_mtu(mtu: u16) -> Result<(), Refusal> {
    if (MIN_MTU..=MAX_MTU).contains(&mtu) {
        Ok(())
    } else {
        Err(Refusal::Invalid(format!(
            "an MTU of {mtu} is outside {MIN_MTU}–{MAX_MTU}"
        )))
    }
}

/// The private IPv4 blocks a mesh may use: RFC 1918 and the shared CGNAT space.
const PRIVATE_IPV4: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
];

/// The private block that holds `address`, if any.
pub(crate) fn private_ipv4_block(address: Ipv4Addr) -> Option<Network> {
    PRIVATE_IPV4
        .iter()
        .map(|&(network, prefix)| Network::v4(network, prefix))
        .find(|block| block.contains(IpAddr::V4(address)))
}

/// The IPv4 route for a node address and prefix length.
///
/// The route must hold the node's own address and stay inside one private block, so a request
/// can never route public addresses, or a whole private block wider than `/8`, away from the
/// rest of the Mac.
///
/// # Errors
/// Refuses a prefix length outside [`MIN_IPV4_PREFIX`]..=[`MAX_IPV4_PREFIX`], a public
/// address, or a prefix wider than the address's private block.
pub fn ipv4_route(address: Ipv4Addr, prefix: u8) -> Result<Network, Refusal> {
    if !(MIN_IPV4_PREFIX..=MAX_IPV4_PREFIX).contains(&prefix) {
        return Err(Refusal::Invalid(format!(
            "an IPv4 prefix of /{prefix} is outside /{MIN_IPV4_PREFIX}–/{MAX_IPV4_PREFIX}"
        )));
    }
    let block = private_ipv4_block(address)
        .ok_or_else(|| Refusal::Invalid(format!("{address} is not a private IPv4 address")))?;
    if prefix < block.prefix {
        return Err(Refusal::Invalid(format!(
            "/{prefix} is wider than the private block {block}"
        )));
    }
    Ok(Network::v4(address, prefix))
}

/// The IPv6 route for a node address: its unique-local `/48`.
///
/// # Errors
/// Refuses an address outside `fd00::/8`, the locally assigned unique-local range the
/// coordinator uses.
pub fn ipv6_route(address: Ipv6Addr) -> Result<Network, Refusal> {
    if address.octets()[0] != 0xfd {
        return Err(Refusal::Invalid(format!(
            "{address} is not a unique-local mesh address"
        )));
    }
    Ok(Network::v6(address, IPV6_PREFIX))
}

/// The prefix length the agent asks for: the longest prefix that holds the node and every
/// peer, but never narrower than [`DEFAULT_IPV4_PREFIX`].
///
/// Peers outside the node's private block cannot share one route and are left out; the
/// helper refuses to widen a route past that block anyway.
#[must_use]
pub fn covering_ipv4_prefix(own: Ipv4Addr, peers: impl IntoIterator<Item = Ipv4Addr>) -> u8 {
    let block = private_ipv4_block(own);
    let mut prefix = DEFAULT_IPV4_PREFIX;
    for peer in peers {
        if block.is_some_and(|block| !block.contains(IpAddr::V4(peer))) {
            continue;
        }
        let common = (u32::from(own) ^ u32::from(peer)).leading_zeros();
        let common = u8::try_from(common).unwrap_or(32);
        prefix = prefix.min(common);
    }
    let floor = block.map_or(MIN_IPV4_PREFIX, |block| block.prefix);
    prefix.max(floor).max(MIN_IPV4_PREFIX)
}

/// Whether the helper may point the system resolver for `suffix` at a user-mode agent.
///
/// A suffix chosen by a process that runs as one person would otherwise let that person
/// redirect system-wide DNS for any domain, for every account on the Mac. Only names under
/// the reserved private-use suffixes `internal` and `home.arpa` are accepted, so no real
/// public domain can be taken over. The coordinator's default suffix is `internal`.
#[must_use]
pub fn allowed_suffix(suffix: &str) -> bool {
    let suffix = suffix.to_ascii_lowercase();
    ["internal", "home.arpa"].iter().any(|reserved| {
        suffix == *reserved
            || suffix
                .strip_suffix(reserved)
                .is_some_and(|label| label.ends_with('.') && label.len() > 1)
    })
}

/// One IP network: an address with its host bits cleared and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    /// The first address of the network.
    pub address: IpAddr,
    /// Prefix length in bits.
    pub prefix: u8,
}

impl Network {
    /// The IPv4 network of `address` at `prefix` bits (clamped to 32).
    #[must_use]
    pub fn v4(address: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
        Self {
            address: IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask)),
            prefix,
        }
    }

    /// The IPv6 network of `address` at `prefix` bits (clamped to 128).
    #[must_use]
    pub fn v6(address: Ipv6Addr, prefix: u8) -> Self {
        let prefix = prefix.min(128);
        let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
        Self {
            address: IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask)),
            prefix,
        }
    }

    /// Whether `address` lies inside this network (never across address families).
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(_), IpAddr::V4(address)) => {
                Self::v4(address, self.prefix).address == self.address
            }
            (IpAddr::V6(_), IpAddr::V6(address)) => {
                Self::v6(address, self.prefix).address == self.address
            }
            _ => false,
        }
    }

    /// Whether the two networks share any address.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.contains(other.address) || other.contains(self.address)
    }

    /// Whether this is IPv4.
    #[must_use]
    pub const fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }
}

impl std::fmt::Display for Network {
    /// Show the network as `address/prefix`, the form `route` and people read.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix)
    }
}

/// One routing-table row: where it goes and through which interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The destination network (a host route has a full-length prefix).
    pub network: Network,
    /// The interface name, such as `en0` or `utun4`.
    pub interface: String,
}

impl Route {
    /// Whether the row is IPv4.
    #[must_use]
    pub const fn is_ipv4(&self) -> bool {
        self.network.is_ipv4()
    }
}

/// Read the rows of `netstat -rn` output for one address family.
///
/// macOS prints IPv4 destinations shortened: `10.69.69/24`, `192.168.64` (a /24), `127`
/// (a /8), and host routes as four octets or with the `H` flag. IPv6 destinations may carry a
/// `%scope`. `default` rows are skipped: a default route is the fallback for everything and
/// never overlaps a more specific mesh route. Rows whose destination is not an address
/// (`link#7`) are skipped.
///
/// # Errors
/// Refuses a row whose destination looks like an address but cannot be read, so the overlap
/// check fails closed rather than missing a network.
pub fn parse_routes(output: &str, ipv4: bool) -> Result<Vec<Route>, Refusal> {
    let mut routes = Vec::new();
    let mut in_family = false;
    for line in output.lines() {
        let trimmed = line.trim();
        match trimmed {
            "Internet:" => {
                in_family = ipv4;
                continue;
            }
            "Internet6:" => {
                in_family = !ipv4;
                continue;
            }
            _ => {}
        }
        if !in_family || trimmed.is_empty() || trimmed.starts_with("Destination") {
            continue;
        }
        let columns: Vec<&str> = trimmed.split_whitespace().collect();
        let (Some(&destination), Some(&flags), Some(&interface)) =
            (columns.first(), columns.get(2), columns.get(3))
        else {
            return Err(Refusal::Invalid(format!(
                "a routing table row could not be read: {trimmed}"
            )));
        };
        if destination == "default" {
            continue;
        }
        let network = if ipv4 {
            parse_ipv4_destination(destination, flags.contains('H'))
        } else {
            parse_ipv6_destination(destination)
        };
        match network {
            Some(network) => routes.push(Route {
                network,
                interface: interface.to_owned(),
            }),
            None if destination.starts_with("link#") => {}
            None => {
                return Err(Refusal::Invalid(format!(
                    "a routing table destination could not be read: {destination}"
                )));
            }
        }
    }
    Ok(routes)
}

/// Read one shortened IPv4 destination from `netstat -rn`.
fn parse_ipv4_destination(destination: &str, host: bool) -> Option<Network> {
    let (address, prefix) = match destination.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
        None => (destination, None),
    };
    let octets: Vec<u8> = address
        .split('.')
        .map(|octet| octet.parse::<u8>().ok())
        .collect::<Option<_>>()?;
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    let given = u8::try_from(octets.len()).ok()?;
    let mut full = [0_u8; 4];
    full[..octets.len()].copy_from_slice(&octets);
    let prefix = match prefix {
        Some(prefix) if prefix <= 32 => prefix,
        Some(_) => return None,
        None if host || given == 4 => 32,
        None => given * 8,
    };
    Some(Network::v4(Ipv4Addr::from(full), prefix))
}

/// Read one IPv6 destination from `netstat -rn`, dropping any `%scope`.
fn parse_ipv6_destination(destination: &str) -> Option<Network> {
    let (address, prefix) = match destination.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
        None => (destination, None),
    };
    let address = address.split('%').next()?;
    let address: Ipv6Addr = address.parse().ok()?;
    let prefix = prefix.unwrap_or(128);
    if prefix > 128 {
        return None;
    }
    Some(Network::v6(address, prefix))
}

/// What adding a mesh route needs first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePlan {
    /// Exact copies of the mesh route on our own earlier utuns, to delete before adding ours.
    pub replace: Vec<String>,
}

/// The other utuns that already carry exactly `wanted`, in table order and without repeats.
///
/// Each one is either an earlier utun of this person's agent or another VPN with the same
/// range. The helper finds out which by asking the kernel who holds it
/// ([`crate::macos_utun_holder`]) and passes the answer to [`plan_route`]. An empty list means
/// that lookup is not needed at all.
#[must_use]
pub fn same_prefix_utuns(wanted: Network, interface: &str, routes: &[Route]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for row in routes {
        if row.network == wanted
            && row.interface != interface
            && row.interface.starts_with("utun")
            && !found.contains(&row.interface)
        {
            found.push(row.interface.clone());
        }
    }
    found
}

/// Check that nothing on the Mac overlaps `wanted` before it is routed to `interface`.
///
/// `local` holds the networks of every interface address (from `getifaddrs`) with their
/// interface names; `routes` holds the routing table. Rows on `interface` itself are ours.
/// `ours` names the utuns the helper has proved belong to this person's agent (held by a
/// process of the registered uid that runs the installed infraternal binary). A utun in `ours`
/// that carries an exact copy of `wanted` is an earlier mesh utun (an agent that restarted, or a
/// worker being replaced while the old one still runs): its copy is replaced and its own address
/// rows are not conflicts. A same-prefix utun that is *not* in `ours` is another VPN and is
/// refused like any other overlap (review J1027 F1): the route alone cannot prove ownership,
/// because a caller or coordinator can ask for any prefix. Host routes on `lo0` are skipped:
/// macOS adds one for every local address (including this utun's own IPv6 address), and the
/// address itself is already checked on its real interface through `local`. Anything else that
/// overlaps, in either direction, is a conflict: routing the mesh there would take traffic from
/// a network the Mac already uses.
///
/// # Errors
/// Names the first overlapping network and its interface, in words the person can act on.
pub fn plan_route(
    wanted: Network,
    interface: &str,
    routes: &[Route],
    local: &[Route],
    ours: &[String],
) -> Result<RoutePlan, Refusal> {
    let plan = RoutePlan {
        replace: same_prefix_utuns(wanted, interface, routes)
            .into_iter()
            .filter(|utun| ours.contains(utun))
            .collect(),
    };
    for row in local.iter().chain(routes) {
        let loopback_host = row.interface == "lo0"
            && row.network.prefix == if row.is_ipv4() { 32 } else { 128 }
            && routes.contains(row);
        if row.interface == interface
            || plan.replace.contains(&row.interface)
            || loopback_host
            || !row.network.overlaps(&wanted)
        {
            continue;
        }
        return Err(Refusal::Invalid(format!(
            "the mesh network {wanted} overlaps {} on {}; the mesh route was not added. \
             Disconnect that network or VPN, or ask the server's owner to move the mesh range",
            row.network, row.interface
        )));
    }
    Ok(plan)
}

/// Escape text for an XML property list.
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The helper's `LaunchDaemon`: socket-activated, one process per connection.
///
/// launchd owns the socket at [`HELPER_SOCKET`], created for `uid` with mode 0600, so only
/// that person (and root) can connect. With `inetdCompatibility` and `Wait = false`, launchd
/// accepts each connection and starts the helper with it as standard input; nothing runs
/// between requests. Standard output and error go to `/dev/null` so nothing but a reply can
/// reach the socket. The registered uid is in the arguments so the helper can re-check the
/// kernel's peer credentials against it.
#[must_use]
pub fn helper_plist(uid: u32) -> String {
    render_helper_plist(HELPER_LABEL, HELPER_BINARY, HELPER_SOCKET, uid)
}

/// Render a helper property list for the given names; the current and the [`legacy`] names
/// differ only in these three strings.
fn render_helper_plist(label: &str, binary: &str, socket: &str, uid: u32) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>{label}</string>\n\
         <key>ProgramArguments</key><array>\n\
         <string>{binary}</string><string>{HELPER_ENTRY}</string><string>{uid}</string>\n\
         </array>\n\
         <key>inetdCompatibility</key><dict><key>Wait</key><false/></dict>\n\
         <key>Sockets</key><dict><key>Listeners</key><dict>\n\
         <key>SockPathName</key><string>{socket}</string>\n\
         <key>SockPathMode</key><integer>384</integer>\n\
         <key>SockPathOwner</key><integer>{uid}</integer>\n\
         <key>SockPathGroup</key><integer>0</integer>\n\
         </dict></dict>\n\
         <key>StandardOutPath</key><string>/dev/null</string>\n\
         <key>StandardErrorPath</key><string>/dev/null</string>\n\
         </dict></plist>\n"
    )
}

/// Read the registered uid back from a helper property list this module wrote.
///
/// Returns `None` for any other text, so a foreign or edited file is never treated as ours.
#[must_use]
pub fn helper_plist_uid(contents: &str) -> Option<u32> {
    helper_plist_uid_with(contents, helper_plist)
}

/// [`helper_plist_uid`] for a renderer: the uid is read out, then the text must equal what the
/// renderer writes for that uid.
fn helper_plist_uid_with(contents: &str, render: impl Fn(u32) -> String) -> Option<u32> {
    let start = contents.find(&format!("<string>{HELPER_ENTRY}</string><string>"))?;
    let rest = &contents[start + HELPER_ENTRY.len() + "<string></string><string>".len()..];
    let uid: u32 = rest.split('<').next()?.parse().ok()?;
    (render(uid) == contents).then_some(uid)
}

/// The identifiers of builds before the move to [`IDENTIFIER_ROOT`] (#580), and the plan that
/// retires them.
///
/// Macs that joined with an older build have these names in launchd and on disk. `infraternal
/// up` removes them and installs the new ones; uninstall removes both sets. Nothing else is
/// renamed on disk: the install folders, the enrolment and the mesh key file keep their
/// paths, so the node keeps its identity and its mesh public key through the move. The
/// slice-1 keychain item (`macos_key`) is not here: no build has written it since #265, and
/// it is only ever deleted, under the name it was created with.
pub mod legacy {
    use super::render_helper_plist;

    /// The old `LaunchAgent` label of user mode.
    pub const AGENT_LABEL: &str = "org.infraternal.agent";
    /// The old label of the root-mode system service.
    pub const DAEMON_LABEL: &str = "org.infraternal.mesh";
    /// The old root-mode property list.
    pub const DAEMON_PLIST: &str = "/Library/LaunchDaemons/org.infraternal.mesh.plist";
    /// The old helper label.
    pub const HELPER_LABEL: &str = "org.infraternal.mesh-helper";
    /// The old helper property list.
    pub const HELPER_PLIST: &str = "/Library/LaunchDaemons/org.infraternal.mesh-helper.plist";
    /// The old helper binary.
    pub const HELPER_BINARY: &str = "/Library/PrivilegedHelperTools/org.infraternal.mesh-helper";
    /// The old helper socket.
    pub const HELPER_SOCKET: &str = "/var/run/org.infraternal.mesh-helper.sock";

    /// The old helper property list for `uid`, byte for byte what those builds wrote.
    #[must_use]
    pub fn helper_plist(uid: u32) -> String {
        render_helper_plist(HELPER_LABEL, HELPER_BINARY, HELPER_SOCKET, uid)
    }

    /// The uid an old helper property list serves, or `None` for any other text.
    #[must_use]
    pub fn helper_plist_uid(contents: &str) -> Option<u32> {
        super::helper_plist_uid_with(contents, helper_plist)
    }

    /// Which of the old helper's three files exist.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct HelperFiles {
        /// The old helper's property list exists.
        pub plist: bool,
        /// The old helper's binary exists.
        pub binary: bool,
        /// The old helper's socket path exists.
        pub socket: bool,
    }

    /// What exists on this Mac from the old names, as the caller found it.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Found {
        /// `~/Library/LaunchAgents/org.infraternal.agent.plist` exists.
        pub agent_plist: bool,
        /// The old helper's files.
        pub helper: HelperFiles,
    }

    /// One removal the move makes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Step {
        /// Unload the old `LaunchAgent` from the person's session (stops the old agent).
        UnloadAgent,
        /// Delete the old `LaunchAgent` property list.
        RemoveAgentPlist,
        /// Unload the old helper job from the system domain (root).
        UnloadHelper,
        /// Delete the old helper's socket path (root).
        RemoveHelperSocket,
        /// Delete the old helper's property list (root).
        RemoveHelperPlist,
        /// Delete the old helper's binary (root).
        RemoveHelperBinary,
    }

    impl Step {
        /// Whether the step needs root (the helper lives under `/Library` and `/var/run`).
        #[must_use]
        pub fn needs_root(self) -> bool {
            !matches!(self, Self::UnloadAgent | Self::RemoveAgentPlist)
        }
    }

    /// The removals for what was found, in the order they are safe to run.
    ///
    /// The job is unloaded before its files go, so launchd cannot start it from a file that
    /// is half removed, and the property list goes before the binary it names, so a stop
    /// halfway never leaves a plist that points at nothing. Nothing is planned for names that
    /// are not there, so a Mac that never had the old names gets an empty plan.
    #[must_use]
    pub fn plan(found: Found) -> Vec<Step> {
        let mut steps = Vec::new();
        if found.agent_plist {
            steps.extend([Step::UnloadAgent, Step::RemoveAgentPlist]);
        }
        let helper = found.helper;
        if helper.plist || helper.binary || helper.socket {
            steps.push(Step::UnloadHelper);
        }
        if helper.socket {
            steps.push(Step::RemoveHelperSocket);
        }
        if helper.plist {
            steps.push(Step::RemoveHelperPlist);
        }
        if helper.binary {
            steps.push(Step::RemoveHelperBinary);
        }
        steps
    }
}

/// The user-mode agent's `LaunchAgent`.
///
/// It runs `executable agent run --data <data> --state <state>` in the person's login
/// session, starts at login, restarts after a crash (throttled to every 5 s), and sends its
/// output to `log` so the person can read why it stopped. `AssociatedBundleIdentifiers` names
/// [`BUNDLE_IDENTIFIER`], which TN3179 asks of a launchd agent not installed through
/// `SMAppService`, so Local Network privacy finds the responsible code (#576).
#[must_use]
pub fn agent_plist(executable: &str, data: &str, state: &str, log: &str) -> String {
    let executable = xml_escape(executable);
    let data = xml_escape(data);
    let state = xml_escape(state);
    let log = xml_escape(log);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>{AGENT_LABEL}</string>\n\
         <key>ProgramArguments</key><array>\n\
         <string>{executable}</string><string>agent</string><string>run</string>\n\
         <string>--data</string><string>{data}</string>\n\
         <string>--state</string><string>{state}</string>\n\
         </array>\n\
         <key>RunAtLoad</key><true/>\n\
         <key>KeepAlive</key><true/>\n\
         <key>ThrottleInterval</key><integer>5</integer>\n\
         <key>ProcessType</key><string>Interactive</string>\n\
         <key>AssociatedBundleIdentifiers</key><array><string>{BUNDLE_IDENTIFIER}</string></array>\n\
         <key>StandardOutPath</key><string>{log}</string>\n\
         <key>StandardErrorPath</key><string>{log}</string>\n\
         </dict></plist>\n"
    )
}

/// Wire format, validation, route reading and property list checks.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A request survives a round trip, and an unknown field or version is refused.
    #[test]
    fn requests_round_trip_and_unknown_input_is_refused() {
        let request = Request::Address {
            ipv4: Ipv4Addr::new(10, 254, 0, 7),
            ipv4_prefix: 16,
            ipv6: "fd12:3456:789a::7".parse().unwrap(),
            mtu: 1280,
        };
        let framed = encode_request(&request).unwrap();
        let length = frame_length([framed[0], framed[1]]).unwrap();
        assert_eq!(length, framed.len() - 2);
        assert_eq!(decode_request(&framed[2..]).unwrap(), request);
        assert_eq!(
            decode_request(br#"{"version":2,"request":"open","extra":1}"#),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            decode_request(br#"{"version":2,"request":{"mtu":{"mtu":1300,"x":1}}}"#),
            Err(Refusal::Malformed)
        );
        // Version 1 (J998) still sent an address with its resolver request; it is refused as a
        // version mismatch, which `infraternal up` repairs by refreshing the helper.
        for old in [
            &br#"{"version":1,"request":"open"}"#[..],
            br#"{"version":3,"request":"open"}"#,
        ] {
            assert_eq!(decode_request(old), Err(Refusal::Version));
        }
        let resolver = Request::Resolver {
            suffixes: vec!["internal".to_owned()],
        };
        assert!(resolver.needs_utun());
        let framed = encode_request(&resolver).unwrap();
        assert_eq!(decode_request(&framed[2..]).unwrap(), resolver);
        assert_eq!(
            decode_request(
                br#"{"version":2,"request":{"resolver":{"address":"10.254.0.7","suffixes":["internal"]}}}"#
            ),
            Err(Refusal::Malformed)
        );
        // J998's own resolver request is a version mismatch, not "malformed", so the agent's log
        // says what to do.
        assert_eq!(
            decode_request(
                br#"{"version":1,"request":{"resolver":{"address":"10.254.0.7","suffixes":["internal"]}}}"#
            ),
            Err(Refusal::Version)
        );
        // Removal works across versions; nothing else does.
        assert_eq!(
            decode_request(br#"{"version":1,"request":"remove"}"#),
            Ok(Request::Remove)
        );
        assert_eq!(
            decode_request(br#"{"version":1,"request":"clear-resolver"}"#),
            Err(Refusal::Version)
        );
        assert_eq!(
            decode_request(br#"{"request":"open"}"#),
            Err(Refusal::Malformed)
        );
        assert_eq!(frame_length([0, 0]), Err(Refusal::Malformed));
        assert_eq!(frame_length([0x40, 0x01]), Err(Refusal::Malformed));
        assert!(frame(&vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
    }

    /// Only requests that change a held utun must carry it.
    #[test]
    fn utun_changes_carry_the_utun() {
        assert!(!Request::Open.needs_utun());
        assert!(Request::Mtu { mtu: 1280 }.needs_utun());
        assert!(!Request::ClearResolver.needs_utun());
        assert!(!Request::Remove.needs_utun());
    }

    /// The helper never routes public space, a block wider than its private range, or odd MTUs.
    #[test]
    fn routes_stay_private_and_mtus_bounded() {
        let mesh = Ipv4Addr::new(10, 254, 3, 9);
        assert_eq!(ipv4_route(mesh, 16).unwrap().to_string(), "10.254.0.0/16");
        assert!(ipv4_route(mesh, 7).is_err());
        assert!(ipv4_route(mesh, 31).is_err());
        assert!(ipv4_route(Ipv4Addr::new(8, 8, 8, 8), 16).is_err());
        assert!(ipv4_route(Ipv4Addr::new(172, 20, 0, 1), 11).is_err());
        assert!(ipv4_route(Ipv4Addr::new(172, 20, 0, 1), 12).is_ok());
        assert!(ipv4_route(Ipv4Addr::new(100, 64, 0, 1), 9).is_err());
        assert_eq!(
            ipv6_route("fd12:3456:789a::7".parse().unwrap())
                .unwrap()
                .to_string(),
            "fd12:3456:789a::/48"
        );
        assert!(ipv6_route("2001:db8::1".parse().unwrap()).is_err());
        assert!(validate(&Request::Mtu { mtu: 1279 }).is_err());
        assert!(validate(&Request::Mtu { mtu: 1501 }).is_err());
        assert!(validate(&Request::Mtu { mtu: 1420 }).is_ok());
    }

    /// The agent asks for /16 unless a peer in the same private block needs a wider route.
    #[test]
    fn the_covering_prefix_starts_at_the_default_range() {
        let own = Ipv4Addr::new(10, 254, 0, 7);
        assert_eq!(covering_ipv4_prefix(own, []), 16);
        assert_eq!(
            covering_ipv4_prefix(own, [Ipv4Addr::new(10, 254, 9, 1)]),
            16
        );
        assert_eq!(
            covering_ipv4_prefix(own, [Ipv4Addr::new(10, 255, 0, 1)]),
            15
        );
        assert_eq!(covering_ipv4_prefix(own, [Ipv4Addr::new(10, 1, 0, 1)]), 8);
        // A peer outside the node's private block cannot share the route and is left out.
        assert_eq!(
            covering_ipv4_prefix(own, [Ipv4Addr::new(192, 168, 1, 1)]),
            16
        );
        let cgnat = Ipv4Addr::new(100, 100, 0, 1);
        assert_eq!(
            covering_ipv4_prefix(cgnat, [Ipv4Addr::new(100, 64, 0, 1)]),
            10
        );
    }

    /// Only reserved private-use suffixes may be pointed at a user-mode agent.
    #[test]
    fn only_private_use_suffixes_are_written() {
        for suffix in ["internal", "mesh.internal", "HOME.ARPA", "lab.home.arpa"] {
            assert!(allowed_suffix(suffix), "{suffix}");
        }
        for suffix in [
            "apple.com",
            "xinternal",
            "com",
            ".internal",
            "internal.com",
            "arpa",
        ] {
            assert!(!allowed_suffix(suffix), "{suffix}");
        }
    }

    /// The table reader handles macOS's shortened destinations and fails closed on garbage.
    #[test]
    fn netstat_rows_are_read_with_their_real_prefixes() {
        let output = "Routing tables\n\nInternet:\n\
            Destination        Gateway            Flags               Netif Expire\n\
            default            192.168.64.1       UGScg                 en0       \n\
            10.69.69/24        utun100            USc               utun100       \n\
            10.69.69.58        10.69.69.58        UH                utun100       \n\
            127                127.0.0.1          UCS                   lo0       \n\
            169.254            link#7             UCS                   en0      !\n\
            192.168.64         link#7             UCS                   en0      !\n\
            224.0.0/4          link#7             UmCS                  en0      !\n\
            \nInternet6:\n\
            Destination                             Gateway                                 Flags               Netif Expire\n\
            default                                 fe80::%utun0                            UGcIg               utun0       \n\
            ::1                                     ::1                                     UHL                   lo0       \n\
            fd12:3456:789a::/48                     utun5                                   USc                 utun5       \n\
            fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0       \n";
        let v4 = parse_routes(output, true).unwrap();
        let shown: Vec<String> = v4.iter().map(|route| route.network.to_string()).collect();
        assert_eq!(
            shown,
            [
                "10.69.69.0/24",
                "10.69.69.58/32",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "192.168.64.0/24",
                "224.0.0.0/4"
            ]
        );
        let v6 = parse_routes(output, false).unwrap();
        let shown: Vec<String> = v6.iter().map(|route| route.network.to_string()).collect();
        assert_eq!(shown, ["::1/128", "fd12:3456:789a::/48", "fe80::/64"]);
        assert!(parse_routes("Internet:\n10.x.1 a UH en0\n", true).is_err());
    }

    /// An overlapping network is refused by name, ours is ignored, and an older mesh utun is replaced.
    #[test]
    fn overlapping_networks_refuse_the_mesh_route() {
        let wanted = Network::v4(Ipv4Addr::new(10, 254, 0, 0), 16);
        let route = |network: Network, interface: &str| Route {
            network,
            interface: interface.to_owned(),
        };
        let netbird = route(Network::v4(Ipv4Addr::new(10, 69, 69, 0), 24), "utun100");
        let lan = route(Network::v4(Ipv4Addr::new(192, 168, 64, 0), 24), "en0");
        assert_eq!(
            plan_route(wanted, "utun7", &[netbird.clone(), lan.clone()], &[], &[]),
            Ok(RoutePlan::default())
        );
        let wide_vpn = route(Network::v4(Ipv4Addr::new(10, 0, 0, 0), 8), "utun100");
        let error = plan_route(wanted, "utun7", &[wide_vpn], &[], &[]).unwrap_err();
        assert!(
            error.to_string().contains("10.0.0.0/8 on utun100"),
            "{error}"
        );
        let inside = route(Network::v4(Ipv4Addr::new(10, 254, 3, 0), 24), "en1");
        assert!(plan_route(wanted, "utun7", &[], &[inside], &[]).is_err());
        let ours = route(Network::v4(Ipv4Addr::new(10, 254, 0, 7), 32), "utun7");
        assert!(plan_route(wanted, "utun7", &[ours], &[], &[]).is_ok());
        let earlier = route(wanted, "utun6");
        assert_eq!(
            plan_route(
                wanted,
                "utun7",
                std::slice::from_ref(&earlier),
                &[],
                &["utun6".to_owned()]
            )
            .unwrap()
            .replace,
            ["utun6"]
        );
        // The same network on a non-utun interface is a real conflict.
        let ethernet = route(wanted, "en5");
        assert!(plan_route(wanted, "utun7", &[ethernet], &[], &["en5".to_owned()]).is_err());
    }

    /// Found on the Mac VM: re-sending an address request on the same utun must not trip over
    /// the `lo0` host route macOS adds for that utun's own IPv6 address.
    #[test]
    fn a_repeated_request_ignores_the_loopback_route_for_our_own_address() {
        let wanted = Network::v6("fd77:7777:7777::".parse().unwrap(), 48);
        let own = "fd77:7777:7777::7".parse::<Ipv6Addr>().unwrap();
        let rows = [
            Route {
                network: wanted,
                interface: "utun5".to_owned(),
            },
            Route {
                network: Network::v6(own, 128),
                interface: "lo0".to_owned(),
            },
        ];
        let local = [Route {
            network: Network::v6(own, 128),
            interface: "utun5".to_owned(),
        }];
        assert_eq!(
            plan_route(wanted, "utun5", &rows, &local, &[]),
            Ok(RoutePlan::default())
        );
        // A local address inside the mesh on another interface is still a conflict.
        let alias = [Route {
            network: Network::v6("fd77:7777:7777::9".parse().unwrap(), 128),
            interface: "lo0".to_owned(),
        }];
        assert!(plan_route(wanted, "utun5", &rows, &alias, &[]).is_err());
    }

    /// Found on the Mac VM: a new utun takes over the mesh route while the old one still
    /// exists, without the old utun's own address route counting as a conflict, once the helper
    /// has proved the old utun is this agent's own (J1027 F1).
    #[test]
    fn a_new_utun_takes_over_while_the_old_one_still_exists() {
        let wanted = Network::v4(Ipv4Addr::new(10, 254, 0, 0), 16);
        let old_address = Network::v4(Ipv4Addr::new(10, 254, 77, 7), 32);
        let rows = [
            Route {
                network: wanted,
                interface: "utun5".to_owned(),
            },
            Route {
                network: old_address,
                interface: "utun5".to_owned(),
            },
        ];
        let local = [Route {
            network: old_address,
            interface: "utun5".to_owned(),
        }];
        assert_eq!(
            plan_route(wanted, "utun6", &rows, &local, &["utun5".to_owned()])
                .unwrap()
                .replace,
            ["utun5"]
        );
    }

    /// Review J1027 F1 (#146): another VPN's utun that carries exactly the prefix asked for is
    /// not an earlier mesh utun. Red on 9467b9aa4, where any utun with an exact copy of the route
    /// counted as ours, so the helper deleted that VPN's route and took its traffic. Example: a
    /// CGNAT VPN routes `100.64.0.0/10` (and owns `100.101.102.103`) on `utun3`; a node at
    /// `100.64.0.5` whose peers span the block asks for `/10`. Unless the helper has proved that
    /// `utun3` is held by this person's agent, it is refused like any other overlap.
    #[test]
    fn another_vpn_with_the_same_prefix_is_a_conflict_not_an_earlier_mesh_utun() {
        let wanted = ipv4_route(Ipv4Addr::new(100, 64, 0, 5), 10).unwrap();
        let vpn_route = Route {
            network: Network::v4(Ipv4Addr::new(100, 64, 0, 0), 10),
            interface: "utun3".to_owned(),
        };
        let vpn_address = Route {
            network: Network::v4(Ipv4Addr::new(100, 101, 102, 103), 32),
            interface: "utun3".to_owned(),
        };
        let rows = [vpn_route, vpn_address.clone()];
        assert_eq!(same_prefix_utuns(wanted, "utun7", &rows), ["utun3"]);
        let plan = plan_route(wanted, "utun7", &rows, &[vpn_address], &[]);
        assert!(
            plan.is_err(),
            "the helper would delete the VPN's route and take its traffic: {plan:?}"
        );
        // The same for IPv6: a unique-local /48 another VPN already routes on its own utun.
        let wanted = ipv6_route("fd7a:115c:a1e0::5".parse().unwrap()).unwrap();
        let vpn_route = Route {
            network: wanted,
            interface: "utun3".to_owned(),
        };
        assert!(plan_route(wanted, "utun7", &[vpn_route], &[], &[]).is_err());
        // A utun proved ours elsewhere does not make this one ours.
        let vpn_route = Route {
            network: wanted,
            interface: "utun3".to_owned(),
        };
        assert!(plan_route(wanted, "utun7", &[vpn_route], &[], &["utun2".to_owned()]).is_err());
    }

    /// A user-mode install's paths sit under the person's own `~/Library` (D395), and a receipt
    /// matches only the exact host it names (J1087 server uninstall).
    #[test]
    fn user_install_paths_and_receipts() {
        let home = Path::new("/Users/a");
        assert_eq!(
            user_install_binary(home),
            Path::new("/Users/a/Library/Application Support/infraternal/bin/infraternal")
        );
        assert_eq!(
            user_install_receipt(home),
            Path::new("/Users/a/Library/Application Support/infraternal/.user-owner")
        );
        let host = "0123456789abcdef0123456789abcdef";
        assert!(receipt_names_host(&format!("{host}\n"), host));
        assert!(!receipt_names_host(
            &format!("{host}\n"),
            "0123456789abcdef0123456789abcdee"
        ));
        assert!(!receipt_names_host("\n", ""));
        assert!(!receipt_names_host(" x\n", " x"));
        let upper = host.to_ascii_uppercase();
        assert!(!receipt_names_host(&upper, &upper));
    }

    /// The helper's property list is socket-activated for one uid and read back exactly.
    #[test]
    fn helper_plist_names_its_uid_and_nothing_else_matches() {
        let plist = helper_plist(501);
        assert!(plist.contains("<key>SockPathOwner</key><integer>501</integer>"));
        assert!(plist.contains("<key>SockPathMode</key><integer>384</integer>"));
        assert!(plist.contains("<key>Wait</key><false/>"));
        assert_eq!(helper_plist_uid(&plist), Some(501));
        assert_eq!(helper_plist_uid(&plist.replace("384", "438")), None);
        assert_eq!(helper_plist_uid("<plist/>"), None);
    }

    /// The agent's property list escapes paths and runs the agent with its own folders.
    #[test]
    fn agent_plist_escapes_paths() {
        let plist = agent_plist(
            "/Users/a&b/Library/Application Support/infraternal/bin/infraternal",
            "/d",
            "/s",
            "/l",
        );
        assert!(plist.contains("a&amp;b"));
        assert!(plist.contains("<string>--state</string><string>/s</string>"));
        // Local Network privacy attributes the agent to the binary's embedded bundle (#576).
        assert!(plist.contains(
            "<key>AssociatedBundleIdentifiers</key><array><string>kayg.infraternal</string></array>"
        ));
    }

    /// The embedded `Info.plist` names the same bundle as the `LaunchAgent`, and carries the
    /// sentence the Local Network alert shows (#576).
    #[test]
    fn the_embedded_info_plist_matches_the_launch_agent() {
        let info = include_str!("../../../infraternal/macos/Info.plist");
        assert!(info.contains(&format!(
            "<key>CFBundleIdentifier</key>\n\t<string>{BUNDLE_IDENTIFIER}</string>"
        )));
        assert!(info.contains("<key>NSLocalNetworkUsageDescription</key>"));
    }

    /// Every identifier infraternal gives macOS starts with the one owner-chosen root (#580).
    #[test]
    fn every_identifier_shares_the_kayg_root() {
        for name in [
            BUNDLE_IDENTIFIER,
            DAEMON_LABEL,
            HELPER_LABEL,
            AGENT_LABEL,
            DAEMON_PLIST,
            HELPER_PLIST,
            HELPER_BINARY,
            HELPER_SOCKET,
        ] {
            assert!(
                name.contains(IDENTIFIER_ROOT) && !name.contains("org.infraternal"),
                "{name}"
            );
        }
        assert_eq!(BUNDLE_IDENTIFIER, IDENTIFIER_ROOT);
        for name in [
            legacy::AGENT_LABEL,
            legacy::DAEMON_LABEL,
            legacy::HELPER_LABEL,
            legacy::HELPER_PLIST,
            legacy::HELPER_BINARY,
            legacy::HELPER_SOCKET,
            legacy::DAEMON_PLIST,
        ] {
            assert!(name.contains("org.infraternal"), "{name}");
        }
    }

    /// The old and new helper property lists name only their own label, binary and socket, so
    /// a file of one generation is never read as the other.
    #[test]
    fn old_and_new_helper_property_lists_are_told_apart() {
        let new = helper_plist(501);
        let old = legacy::helper_plist(501);
        assert_ne!(new, old);
        assert!(!new.contains("org.infraternal") && !old.contains("kayg.infraternal"));
        assert_eq!(helper_plist_uid(&new), Some(501));
        assert_eq!(legacy::helper_plist_uid(&old), Some(501));
        assert_eq!(helper_plist_uid(&old), None);
        assert_eq!(legacy::helper_plist_uid(&new), None);
        // An edited file (the owner no longer matches the argument) is not ours.
        assert_eq!(
            legacy::helper_plist_uid(
                &old.replace("<integer>501</integer>", "<integer>502</integer>")
            ),
            None
        );
    }

    /// A Mac with nothing old gets an empty plan; the plan never names a step for a path that
    /// is not there.
    #[test]
    fn nothing_old_means_nothing_to_remove() {
        assert_eq!(legacy::plan(legacy::Found::default()), []);
    }

    /// A full old install is removed in a safe order: unload before delete, the property list
    /// before the binary it names, and the person's own steps need no root.
    #[test]
    fn a_full_old_install_is_removed_in_order() {
        use legacy::Step::*;
        let steps = legacy::plan(legacy::Found {
            agent_plist: true,
            helper: legacy::HelperFiles {
                plist: true,
                binary: true,
                socket: true,
            },
        });
        assert_eq!(
            steps,
            [
                UnloadAgent,
                RemoveAgentPlist,
                UnloadHelper,
                RemoveHelperSocket,
                RemoveHelperPlist,
                RemoveHelperBinary
            ]
        );
        assert_eq!(
            steps
                .iter()
                .map(|step| step.needs_root())
                .collect::<Vec<_>>(),
            [false, false, true, true, true, true]
        );
    }

    /// Leftovers of an interrupted removal are still cleaned up: a binary alone, or a socket
    /// alone, still unloads the job and removes just what exists.
    #[test]
    fn a_partly_removed_old_install_is_finished() {
        use legacy::Step::*;
        assert_eq!(
            legacy::plan(legacy::Found {
                helper: legacy::HelperFiles {
                    binary: true,
                    ..legacy::HelperFiles::default()
                },
                ..legacy::Found::default()
            }),
            [UnloadHelper, RemoveHelperBinary]
        );
        assert_eq!(
            legacy::plan(legacy::Found {
                helper: legacy::HelperFiles {
                    socket: true,
                    ..legacy::HelperFiles::default()
                },
                ..legacy::Found::default()
            }),
            [UnloadHelper, RemoveHelperSocket]
        );
        assert_eq!(
            legacy::plan(legacy::Found {
                agent_plist: true,
                ..legacy::Found::default()
            }),
            [UnloadAgent, RemoveAgentPlist]
        );
    }

    /// The old helper property list is byte for byte what builds before #580 wrote, so a Mac
    /// they set up is recognised and its helper retired (the text is copied from `2fb0b50d2`).
    #[test]
    fn the_old_helper_property_list_is_what_old_builds_wrote() {
        let golden = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>org.infraternal.mesh-helper</string>\n\
         <key>ProgramArguments</key><array>\n\
         <string>/Library/PrivilegedHelperTools/org.infraternal.mesh-helper</string><string>__mesh-helper</string><string>UID</string>\n\
         </array>\n\
         <key>inetdCompatibility</key><dict><key>Wait</key><false/></dict>\n\
         <key>Sockets</key><dict><key>Listeners</key><dict>\n\
         <key>SockPathName</key><string>/var/run/org.infraternal.mesh-helper.sock</string>\n\
         <key>SockPathMode</key><integer>384</integer>\n\
         <key>SockPathOwner</key><integer>UID</integer>\n\
         <key>SockPathGroup</key><integer>0</integer>\n\
         </dict></dict>\n\
         <key>StandardOutPath</key><string>/dev/null</string>\n\
         <key>StandardErrorPath</key><string>/dev/null</string>\n\
         </dict></plist>\n";
        assert_eq!(legacy::helper_plist(501), golden.replace("UID", "501"));
    }
}
