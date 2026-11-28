//! Renders and applies the host input policy owned by infraternal, D386.
//!
//! Two shapes share the one `inet infraternal_host` table, chosen by role in
//! [`InputMode::for_roles`]:
//! - **Enforce** (a server policy exists): default drop, with the server's
//!   listeners, the administrators' rules, and the mesh input when mesh runs.
//! - **Mesh only** (no server policy: a machine joined with `infraternal up`):
//!   `policy accept`, adding only `infraternal0` and the bound mesh UDP port.
//!   It never drops anything, so it cannot lock an administrator out (J555).
//!
//! An accept in this table cannot override a drop in another table's base
//! chain; tables not named `infraternal_*` are never touched (D386).

/// Compare live nft JSON with the policy built from infraternal's configuration.
#[path = "host_firewall_semantics.rs"]
mod host_firewall_semantics;

/// Learn sshd's ports and check every default-drop table keeps them open (J671).
#[path = "host_firewall_sshd.rs"]
mod host_firewall_sshd;

#[cfg(target_os = "linux")]
pub use host_firewall_sshd::sshd_listening_ports;
pub use host_firewall_sshd::{
    SshdPort, SshdPortSource, SshdPorts, admits_sshd, check_sshd_admission, proc_net_address,
    socket_unit_ports, sshd_config_ports, sshd_ports, uncovered_sshd_ports,
};

#[cfg(any(test, feature = "test-support"))]
/// Provides a checked nft executable for privileged namespace tests.
#[path = "../tests/support/nft_fixture.rs"]
mod nft_fixture;

use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "test-support"))]
use std::cell::RefCell;
use std::{
    collections::HashSet,
    fmt::{self, Write as _},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

/// The only nft executable names this product checks without a configured path.
///
/// Each is a fixed entry point that only root can repoint: distro paths, the
/// Nix system profile, and root's own and the default Nix profiles. A store
/// path is reached only through one of these root-owned links (J589, #483).
const NFT_CANDIDATES: &[&str] = &[
    "/usr/sbin/nft",
    "/usr/bin/nft",
    "/sbin/nft",
    "/bin/nft",
    "/run/current-system/sw/bin/nft",
    "/nix/var/nix/profiles/default/bin/nft",
    "/nix/var/nix/profiles/system/sw/bin/nft",
    "/root/.nix-profile/bin/nft",
    "/root/.local/state/nix/profile/bin/nft",
];
/// The nftables table whose input chain protects server and agent listeners.
pub const HOST_TABLE: &str = "infraternal_host";
/// The standard mesh UDP port (D386), used until a node records its bound port.
pub const MESH_UDP_DEFAULT_PORT: u16 = 10_254;
/// The UDP port `DHCPv6` servers and relays send from (RFC 8415).
pub(crate) const DHCPV6_SERVER_PORT: u16 = 547;
/// The UDP port `DHCPv6` clients listen on (RFC 8415).
pub(crate) const DHCPV6_CLIENT_PORT: u16 = 546;
/// Server-owned listener and proxy settings read by the boot service.
pub const SERVER_POLICY_PATH: &str = "/var/lib/infraternal/host-firewall-server.json";
/// Agent-owned administrator and mesh settings read by the boot service.
pub const AGENT_POLICY_PATH: &str = "/var/lib/infraternal/host-firewall-agent.json";
/// Product-managed systemd unit that applies the combined host policy before networking.
pub const HOST_FIREWALL_UNIT_PATH: &str = "/etc/systemd/system/infraternal-firewall.service";
/// Product-managed network-pre enablement link for the host firewall unit.
pub const HOST_FIREWALL_ENABLED_PATH: &str =
    "/etc/systemd/system/network-pre.target.wants/infraternal-firewall.service";
/// Exact comment used to identify the unit file that infraternal may remove.
pub const HOST_FIREWALL_UNIT_MARKER: &str = "# Managed by infraternal: host-firewall/v1";
/// Exact JSON marker used to identify role policy files that infraternal may remove.
pub const HOST_FIREWALL_POLICY_MARKER: &str = "infraternal-host-firewall-policy-v1";

/// Names one role whose host input policy can be cleared through the product.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRole {
    /// The server listener and trusted-proxy policy.
    Server,
    /// The local infraternal agent's administrator and mesh policy.
    Agent,
}

/// How the host table treats input the policy does not name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputMode {
    /// Default drop: only the policy's rules, loopback, replies and ICMP get in.
    Enforce,
    /// Default accept: the table only names the input the mesh needs.
    MeshOnly,
}

impl InputMode {
    /// Pick the table shape from which roles have a saved policy.
    ///
    /// Only the server role gets the default-drop input policy. Other machines
    /// get the mesh input and nothing else, because a default drop whose only
    /// SSH rule is the installer's address can lock other administrators out
    /// (J555, #483). This is the safe default from 2026-11-14 until the owner
    /// decides; flipping it is this one function.
    #[must_use]
    pub fn for_roles(server: Option<&Policy>) -> Self {
        if server.is_some() {
            Self::Enforce
        } else {
            Self::MeshOnly
        }
    }
}

/// Names the owned role files and loader paths used by host-policy lifecycle operations.
///
/// Production uses [`HostFirewallPaths::system`]. [`HostFirewallPaths::under`] gives
/// privileged namespace tests the same layout below a private root without touching
/// the machine running the test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostFirewallPaths {
    server_policy: PathBuf,
    agent_policy: PathBuf,
    unit: PathBuf,
    enabled: PathBuf,
}

impl HostFirewallPaths {
    /// Return the fixed system paths managed by the infraternal host policy.
    #[must_use]
    pub fn system() -> Self {
        Self {
            server_policy: PathBuf::from(SERVER_POLICY_PATH),
            agent_policy: PathBuf::from(AGENT_POLICY_PATH),
            unit: PathBuf::from(HOST_FIREWALL_UNIT_PATH),
            enabled: PathBuf::from(HOST_FIREWALL_ENABLED_PATH),
        }
    }

    /// Map those fixed paths below an isolated root, as namespace tests do.
    #[must_use]
    pub fn under(root: &Path) -> Self {
        Self {
            server_policy: root.join("var/lib/infraternal/host-firewall-server.json"),
            agent_policy: root.join("var/lib/infraternal/host-firewall-agent.json"),
            unit: root.join("etc/systemd/system/infraternal-firewall.service"),
            enabled: root
                .join("etc/systemd/system/network-pre.target.wants/infraternal-firewall.service"),
        }
    }

    /// Return the product's saved server policy path in this layout.
    #[must_use]
    pub fn server_policy_path(&self) -> &Path {
        &self.server_policy
    }

    /// Return the product's saved agent policy path in this layout.
    #[must_use]
    pub fn agent_policy_path(&self) -> &Path {
        &self.agent_policy
    }

    /// Return the loader unit path in this layout.
    #[must_use]
    pub fn unit_path(&self) -> &Path {
        &self.unit
    }

    /// Return the network-pre enablement link path in this layout.
    #[must_use]
    pub fn enabled_path(&self) -> &Path {
        &self.enabled
    }
}

/// Bound disk reads and writes for each root-owned policy file.
const MAX_POLICY_BYTES: u64 = 64 * 1024;
/// Disambiguate concurrently written temporary policy names in this process.
static POLICY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// Namespace tests use a private nft copy whose owner maps to root in the sandbox.
#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    /// The checked nft fixture active on this test thread, if one was requested.
    static TEST_NFT_PATH: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// A test-only fixed-path nft override shared by host and mesh policy tests.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct NftTestPathOverride {
    /// The previous thread-local path, restored when the guard leaves scope.
    previous: Option<PathBuf>,
    /// The fixture executable kept alive by [`Self::with_fixed_nft_fixture`].
    fixture: Option<nft_fixture::NftFixture>,
}

/// Test-only lifecycle methods for the shared nft fixture.
#[cfg(any(test, feature = "test-support"))]
impl NftTestPathOverride {
    /// Create a private executable from one fixed system or Nix candidate.
    #[doc(hidden)]
    #[must_use]
    pub fn with_fixed_nft_fixture() -> Self {
        let fixture = nft_fixture::NftFixture::new(NFT_CANDIDATES);
        let mut guard = Self::install(fixture.path());
        guard.fixture = Some(fixture);
        guard
    }

    /// Use an existing private fixture for this test thread.
    #[doc(hidden)]
    #[must_use]
    pub fn install(path: &Path) -> Self {
        let previous = TEST_NFT_PATH.with(|current| current.replace(Some(path.to_owned())));
        Self {
            previous,
            fixture: None,
        }
    }
}

/// Restore the previous fixture path without affecting another test thread.
#[cfg(any(test, feature = "test-support"))]
impl Drop for NftTestPathOverride {
    /// Restore an earlier override after this test ends.
    fn drop(&mut self) {
        let previous = self.previous.take();
        TEST_NFT_PATH.with(|current| *current.borrow_mut() = previous);
        let _ = self.fixture.take();
    }
}

// Namespace tests cannot see a real sshd, so they state the one their table must admit.
#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    /// The sshd ports a test on this thread declared, if any.
    static TEST_SSHD_PORTS: RefCell<Option<SshdPorts>> = const { RefCell::new(None) };
}

/// A test-only answer for "which ports does sshd use", replacing [`sshd_ports`] on this thread.
///
/// Privileged namespace tests apply real default-drop tables but have no
/// sshd of their own (and cannot read the host's), so each states the sshd
/// its policy must keep reachable. The check itself still runs.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct SshdPortsTestOverride {
    /// The previous thread-local answer, restored when the guard leaves scope.
    previous: Option<SshdPorts>,
}

/// Test-only constructor for the sshd port override.
#[cfg(any(test, feature = "test-support"))]
impl SshdPortsTestOverride {
    /// Answer with `ports` from one named source until the guard is dropped.
    #[doc(hidden)]
    #[must_use]
    pub fn install(ports: &[SshdPort]) -> Self {
        let answer = SshdPorts::Known(vec![SshdPortSource {
            source: "test fixture".to_owned(),
            ports: ports.to_vec(),
        }]);
        let previous = TEST_SSHD_PORTS.with(|current| current.replace(Some(answer)));
        Self { previous }
    }
}

/// Restore the previous answer without affecting another test thread.
#[cfg(any(test, feature = "test-support"))]
impl Drop for SshdPortsTestOverride {
    /// Put back an earlier override after this test ends.
    fn drop(&mut self) {
        let previous = self.previous.take();
        TEST_SSHD_PORTS.with(|current| *current.borrow_mut() = previous);
    }
}

/// sshd's ports for an apply: a test's declared answer, else the host's ([`sshd_ports`]).
fn current_sshd_ports() -> SshdPorts {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(ports) = TEST_SSHD_PORTS.with(|current| current.borrow().clone()) {
        return ports;
    }
    sshd_ports()
}

/// One layer of the host input policy supplied by server or host configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Explicit paths that must remain available to host administrators.
    pub admin_rules: Vec<AllowRule>,
    /// Interfaces with an intentional unrestricted input exception.
    pub accept_interfaces: Vec<String>,
    /// Application listeners and their configured ingress sources.
    pub listeners: Vec<Listener>,
    /// Whether the local mesh node needs TUN and UDP ingress.
    pub mesh_enabled: bool,
    /// The UDP port the running mesh node actually bound, recorded by the node.
    ///
    /// This is the only source for the mesh UDP rule: the node reports the
    /// port its socket holds (after any automatic fallback), and the policy
    /// admits exactly that port. `None` comes from policy files written
    /// before the field existed, and from hosts whose node has not bound a
    /// socket yet; it renders the standard port, [`MESH_UDP_DEFAULT_PORT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_udp_port: Option<u16>,
}

impl Policy {
    /// The UDP port the mesh rule admits when [`Policy::mesh_enabled`] is set.
    #[must_use]
    pub fn mesh_udp_port(&self) -> u16 {
        self.mesh_udp_port.unwrap_or(MESH_UDP_DEFAULT_PORT)
    }
}

/// Wrap a role policy with the marker required before the product may remove it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredPolicy {
    /// Identifies role configuration files written by infraternal.
    marker: String,
    /// The validated settings used to render the host input table.
    policy: Policy,
}

/// Combine server and agent settings into the one host input policy.
///
/// Rules keep their first-seen order and duplicates from the shared server
/// and agent configuration are included only once.
#[must_use]
pub fn combine(server: Option<Policy>, agent: Option<Policy>) -> Policy {
    let mut combined = Policy::default();
    for policy in [server, agent].into_iter().flatten() {
        for rule in policy.admin_rules {
            if !combined.admin_rules.contains(&rule) {
                combined.admin_rules.push(rule);
            }
        }
        for interface in policy.accept_interfaces {
            if !combined.accept_interfaces.contains(&interface) {
                combined.accept_interfaces.push(interface);
            }
        }
        for listener in policy.listeners {
            if !combined.listeners.contains(&listener) {
                combined.listeners.push(listener);
            }
        }
        combined.mesh_enabled |= policy.mesh_enabled;
        // Only the agent role runs a mesh node, so at most one layer records a
        // port; a later layer's recorded port wins over an absent one.
        combined.mesh_udp_port = policy.mesh_udp_port.or(combined.mesh_udp_port);
    }
    combined
}

/// A typed allow rule that cannot contain nft syntax or command fragments.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AllowRule {
    /// Network interface on which this traffic may arrive, or `None` for any.
    pub interface: Option<String>,
    /// Allowed peer source, or `None` for any source.
    pub source: Option<IpPrefix>,
    /// Transport protocol accepted by this rule.
    pub protocol: Protocol,
    /// Destination port accepted by this rule.
    pub port: u16,
}

/// One application listener and the network sources configured to reach it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Listener {
    /// Network interface on which this listener is allowed, or `None` for any.
    pub interface: Option<String>,
    /// Address and port passed to the application listener.
    pub address: SocketAddr,
    /// Transport protocol used by the listener.
    pub protocol: Protocol,
    /// Trusted or explicitly configured remote source networks.
    pub sources: Vec<IpPrefix>,
}

/// A supported transport protocol for an input allow rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl fmt::Display for Protocol {
    /// Write the protocol keyword accepted by nft.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// An IPv4 or IPv6 address prefix accepted as an input source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpPrefix {
    /// The canonical network address.
    address: IpAddr,
    /// The number of significant network bits.
    prefix: u8,
}

impl IpPrefix {
    /// Return the canonical network address.
    #[must_use]
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// Return the prefix length in bits.
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Validate fields loaded from a persisted configuration file.
    fn is_valid(&self) -> bool {
        match self.address {
            IpAddr::V4(_) => self.prefix <= 32,
            IpAddr::V6(_) => self.prefix <= 128,
        }
    }

    /// Check whether an address belongs to this canonical prefix.
    fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) if self.prefix <= 32 => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) if self.prefix <= 128 => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) == (u128::from(candidate) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpPrefix {
    /// Write the network in nft-compatible CIDR form.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let full_prefix = match self.address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if self.prefix == full_prefix {
            write!(formatter, "{}", self.address)
        } else {
            write!(formatter, "{}/{}", self.address, self.prefix)
        }
    }
}

impl FromStr for IpPrefix {
    type Err = PolicyError;

    /// Parse and canonicalize a single IP address or CIDR prefix.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address_text, prefix_text) = value
            .split_once('/')
            .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
        let address = address_text
            .parse::<IpAddr>()
            .map_err(|_| PolicyError::InvalidRule)?;
        let prefix = prefix_text
            .map(str::parse::<u8>)
            .transpose()
            .map_err(|_| PolicyError::InvalidRule)?
            .unwrap_or(match address {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            });
        let network = match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
            _ => return Err(PolicyError::InvalidRule),
        };
        Ok(Self {
            address: network,
            prefix,
        })
    }
}

impl FromStr for AllowRule {
    type Err = PolicyError;

    /// Parse `INTERFACE,SOURCE,PROTOCOL,PORT` without accepting nft syntax.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let fields = value.split(',').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(PolicyError::InvalidRule);
        }
        let interface = parse_optional_interface(fields[0])?;
        let source = parse_optional_prefix(fields[1])?;
        let protocol = parse_protocol(fields[2])?;
        let port = fields[3]
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(PolicyError::InvalidRule)?;
        Ok(Self {
            interface,
            source,
            protocol,
            port,
        })
    }
}

impl fmt::Display for AllowRule {
    /// Write the same narrow four-field form accepted by the CLI.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{},{},{},{}",
            self.interface.as_deref().unwrap_or("*"),
            self.source
                .as_ref()
                .map_or_else(|| "*".to_owned(), ToString::to_string),
            self.protocol,
            self.port
        )
    }
}

/// Errors returned while validating, locating nft, or applying a policy.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A policy entry contains invalid network or interface data.
    #[error("host firewall rule is invalid")]
    InvalidRule,
    /// The default-drop policy has no explicit TCP administrator (SSH) rule.
    #[error("host firewall policy needs an explicit TCP admin rule for sshd's port")]
    MissingAdminPath,
    /// Applying a candidate policy would remove the SSH connection running this command.
    #[error("host firewall policy would drop the current SSH admin path")]
    AdminPathWouldBeLost,
    /// Replacing the current table would remove a configured TCP/22 path.
    ///
    /// Only port 22 is recognised in a live table, because nothing there says
    /// which other TCP accept is sshd's. A non-22 session is protected by
    /// [`PolicyError::AdminPathWouldBeLost`] instead.
    #[error("host firewall policy would remove an existing TCP/22 allow rule")]
    ExistingAdminPathWouldBeLost,
    /// The admin rules leave a port sshd uses now, or after a restart, without a path in.
    ///
    /// See [`check_sshd_admission`]. Nothing was saved or applied.
    #[error(
        "no admin rule admits sshd's port {missing}; sshd uses {uses}; each needs a rule such as \
         '*,*,tcp,<port>' (a rule limited to lo, to one source address, to a loopback network \
         or to an address family sshd does not accept on that port does not count), so the \
         default-drop host table keeps an SSH path now and after sshd restarts"
    )]
    SshdNotAdmitted {
        /// The ports no rule admits, for example `2222, 2201 (IPv6 only)`.
        missing: String,
        /// Every source and the ports it named.
        uses: String,
    },
    /// Some source of sshd's ports could not be read, so no default-drop table is saved or applied.
    #[error(
        "sshd's ports could not be determined ({failed}); ports seen so far: {seen}; no \
         default-drop host table is saved or applied while one of sshd's ports may be unknown: \
         fix what is named above (or run as root), then allow every port sshd uses"
    )]
    SshdPortsUnknown {
        /// Each source that failed and why.
        failed: String,
        /// The ports the other sources named, or `none`.
        seen: String,
    },
    /// The boot loader refused to enforce a table that would drop sshd and left input open instead.
    #[error(
        "host firewall NOT enforced, host input left open so sshd stays reachable: {reason}; \
         {opened}; fix the saved policy or sshd, then run `systemctl restart \
         infraternal-firewall.service`"
    )]
    FailedOpen {
        /// Why the default-drop table was not applied.
        reason: Box<PolicyError>,
        /// What the loader did instead.
        opened: String,
    },
    /// A host policy file is not a root-owned, non-writable regular file.
    #[error("host firewall policy file at {0} is not a safe root-owned file")]
    UnsafePolicy(PathBuf),
    /// A saved role policy exists but does not carry infraternal's ownership marker.
    #[error("host firewall policy at {0} is not marked as infraternal-owned")]
    UnownedPolicy(PathBuf),
    /// A host policy file is too large or contains invalid serialized settings.
    #[error("host firewall policy file at {0} is invalid")]
    BadPolicy(PathBuf),
    /// A validated role policy could not be serialized for durable storage.
    #[error("host firewall policy could not be encoded: {0}")]
    EncodePolicy(#[source] serde_json::Error),
    /// A loader item is not a protected regular file and cannot be safely inspected.
    #[error("host firewall item at {0} is not a safe root-owned regular file")]
    UnsafeManagedItem(PathBuf),
    /// A named product-owned file could not be removed.
    #[error("could not remove host firewall item {item}: {source}")]
    RemovalFailed {
        /// The exact item whose removal failed.
        item: PathBuf,
        /// The filesystem error from the attempted removal.
        #[source]
        source: io::Error,
    },
    /// The named host table could not be inspected or removed with nft.
    #[error("could not remove nft table {item} using {nft}: {source}")]
    TableRemovalFailed {
        /// The exact nft table that the product was asked to remove.
        item: String,
        /// The selected nft path, or the fixed candidates checked during discovery.
        nft: String,
        /// The inspection or transaction failure that stopped removal.
        #[source]
        source: Box<PolicyError>,
    },
    /// A marker or tool could not be checked while cleaning one named file.
    #[error("could not finish removing host firewall item {item}: {source}")]
    ManagedItemRemovalFailed {
        /// The exact marked policy or loader path involved in cleanup.
        item: PathBuf,
        /// The inspection or service-manager failure that stopped cleanup.
        #[source]
        source: Box<PolicyError>,
    },
    /// No safe nft executable was available at the listed fixed paths.
    #[error("nft executable was not found; checked: {checked}")]
    NftMissing {
        /// Every absolute candidate inspected, in order.
        checked: String,
    },
    /// The nft executable is not a root-owned, non-group-writable regular file.
    #[error("nft executable at {0} is not a safe root-owned file")]
    UnsafeNft(PathBuf),
    /// A filesystem operation failed while inspecting or executing nft.
    #[error("host firewall I/O failed: {0}")]
    Io(#[source] io::Error),
    /// nft rejected an inventory query or transaction.
    #[error("nft at {path} failed: {message}")]
    NftRejected {
        /// The exact root-owned executable selected for this operation.
        path: PathBuf,
        /// nft's stderr, or a bounded fallback description.
        message: String,
    },
    /// nft returned invalid JSON for a table inventory.
    #[error("nft at {path} returned invalid table inventory")]
    BadInventory {
        /// The exact root-owned executable selected for this operation.
        path: PathBuf,
    },
    /// No safe fixed-path systemctl executable was available for loader cleanup.
    #[error("systemctl executable was not found; checked: {checked}")]
    SystemctlMissing {
        /// Every absolute candidate inspected.
        checked: String,
    },
    /// The selected systemctl path is not a safe root-owned executable.
    #[error("systemctl at {0} is not a safe root-owned executable")]
    UnsafeSystemctl(PathBuf),
    /// The selected systemctl could not be started after the loader was removed.
    #[error(
        "could not reload units after removing host firewall item {item} with {path}: {source}"
    )]
    SystemctlExecutionFailed {
        /// The exact root-owned systemctl executable selected for this operation.
        path: PathBuf,
        /// The loader item removed before systemctl failed to start.
        item: PathBuf,
        /// The process creation error.
        #[source]
        source: io::Error,
    },
    /// systemd could not reload after the product-owned loader was removed.
    #[error("systemctl at {path} failed to reload units after removing {item}: {message}")]
    SystemctlRejected {
        /// The exact root-owned systemctl executable selected for this operation.
        path: PathBuf,
        /// The loader or enablement item removed before reload failed.
        item: PathBuf,
        /// systemctl's stderr or a bounded fallback description.
        message: String,
    },
}

/// Ensure that all rule fields are safe and keep an explicit SSH path.
///
/// Any explicit TCP admin rule counts, whatever its port: sshd may listen on
/// a port other than 22 (J555). When the command runs over SSH,
/// [`validate_ssh_connection`] additionally checks that the rules admit the
/// live session's exact port, source and interface. Rejected: reading the
/// port from `sshd_config` (Include, Match blocks and socket activation make
/// it unreliable) or from listening sockets (a root-only /proc scan, and it
/// cannot run at boot before sshd starts).
///
/// # Errors
/// Returns [`PolicyError::InvalidRule`] for malformed fields or
/// [`PolicyError::MissingAdminPath`] when no TCP admin rule is configured.
pub fn validate(policy: &Policy) -> Result<(), PolicyError> {
    validate_fields(policy)?;
    if !policy
        .admin_rules
        .iter()
        .any(|rule| rule.protocol == Protocol::Tcp)
    {
        return Err(PolicyError::MissingAdminPath);
    }
    Ok(())
}

/// Validate an agent role policy, which needs no admin rule of its own.
///
/// An agent policy alone renders [`InputMode::MeshOnly`], which drops nothing.
/// Its admin rules, if any, only take effect under a server policy, and
/// [`validate`] checks the combined policy then.
///
/// # Errors
/// Returns [`PolicyError::InvalidRule`] for malformed fields.
pub fn validate_agent(policy: &Policy) -> Result<(), PolicyError> {
    validate_fields(policy)
}

/// Validate stored rule fields before their role-specific policies are merged.
fn validate_fields(policy: &Policy) -> Result<(), PolicyError> {
    if policy.mesh_udp_port == Some(0) {
        return Err(PolicyError::InvalidRule);
    }
    for interface in &policy.accept_interfaces {
        validate_interface(Some(interface))?;
    }
    for rule in &policy.admin_rules {
        validate_interface(rule.interface.as_deref())?;
        if rule
            .source
            .as_ref()
            .is_some_and(|source| !source.is_valid())
            || rule.port == 0
        {
            return Err(PolicyError::InvalidRule);
        }
    }
    for listener in &policy.listeners {
        validate_interface(listener.interface.as_deref())?;
        if listener.address.port() == 0
            || listener.sources.iter().any(|source| {
                !source.is_valid() || source.address().is_ipv4() != listener.address.is_ipv4()
            })
        {
            return Err(PolicyError::InvalidRule);
        }
    }
    Ok(())
}

/// Refuse an apply that would remove the admin path in `SSH_CONNECTION`.
///
/// Systemd boot applies have no SSH connection environment and rely on the
/// persisted explicit TCP admin rule validated by [`validate`]. Interactive
/// invocations additionally match the active remote address, port, and local
/// interface before nft is called.
///
/// # Errors
/// Returns an error when the policy is invalid or does not preserve the current SSH connection.
pub fn validate_ssh_connection(
    policy: &Policy,
    ssh_connection: Option<&str>,
) -> Result<(), PolicyError> {
    validate(policy)?;
    let Some(connection) = ssh_connection else {
        return Ok(());
    };
    let Some((_remote, _port, local)) = parse_ssh_connection(connection) else {
        return Err(PolicyError::AdminPathWouldBeLost);
    };
    let interface = interface_for_address(local);
    validate_ssh_connection_on(policy, connection, interface.as_deref())
}

/// Match a parsed SSH connection against configured admin rules.
///
/// This variant lets tests provide the interface found for the local address,
/// while normal applies discover that interface from the host's address list.
///
/// # Errors
/// Returns an error when the policy is invalid or excludes the supplied connection.
pub fn validate_ssh_connection_on(
    policy: &Policy,
    ssh_connection: &str,
    interface: Option<&str>,
) -> Result<(), PolicyError> {
    validate(policy)?;
    let Some((remote, port, _local)) = parse_ssh_connection(ssh_connection) else {
        return Err(PolicyError::AdminPathWouldBeLost);
    };
    let allowed = policy.admin_rules.iter().any(|rule| {
        rule.protocol == Protocol::Tcp
            && rule.port == port
            && rule
                .source
                .as_ref()
                .is_none_or(|source| source.contains(remote))
            && rule
                .interface
                .as_deref()
                .is_none_or(|expected| Some(expected) == interface)
    });
    if allowed {
        Ok(())
    } else {
        Err(PolicyError::AdminPathWouldBeLost)
    }
}

/// Render a complete default-drop host table from structured policy.
///
/// # Errors
/// Returns an error when the policy is invalid or has no explicit TCP admin rule.
pub fn render(policy: &Policy) -> Result<String, PolicyError> {
    validate(policy)?;
    let mut rules = String::from(
        "table inet infraternal_host {\n    chain input {\n        type filter hook input priority filter - 10; policy drop;\n",
    );
    for interface in &policy.accept_interfaces {
        let _ = writeln!(rules, "        iifname \"{interface}\" accept");
    }
    rules.push_str(
        "        iifname \"lo\" accept\n        ct state invalid drop\n        ct state established,related accept\n        ip protocol icmp accept\n        meta l4proto ipv6-icmp accept\n",
    );
    // DHCPv6 clients solicit the ff02::1:2 multicast group, so conntrack never
    // sees the server's unicast link-local reply as established. Without this
    // rule a DHCPv6 host loses its address at lease renewal (J555). Neighbour
    // discovery and router advertisements are untracked ICMPv6, which the
    // line above already admits.
    let _ = writeln!(
        rules,
        "        ip6 saddr fe80::/10 udp sport {DHCPV6_SERVER_PORT} udp dport {DHCPV6_CLIENT_PORT} accept"
    );
    for rule in &policy.admin_rules {
        render_rule(
            &mut rules,
            rule.interface.as_deref(),
            rule.source.as_ref(),
            None,
            rule.protocol,
            rule.port,
        );
    }
    for listener in &policy.listeners {
        if listener.sources.is_empty() {
            render_rule(
                &mut rules,
                listener.interface.as_deref(),
                None,
                Some(listener.address.ip()),
                listener.protocol,
                listener.address.port(),
            );
        } else {
            for source in &listener.sources {
                render_rule(
                    &mut rules,
                    listener.interface.as_deref(),
                    Some(source),
                    Some(listener.address.ip()),
                    listener.protocol,
                    listener.address.port(),
                );
            }
        }
    }
    if policy.mesh_enabled {
        let _ = write!(
            rules,
            "        iifname \"infraternal0\" accept\n        udp dport {} accept\n",
            policy.mesh_udp_port()
        );
    }
    rules.push_str("    }\n}\n");
    let mut unique = String::with_capacity(rules.len());
    let mut seen = HashSet::new();
    for line in rules.lines() {
        if line.starts_with("        ") && !seen.insert(line) {
            continue;
        }
        unique.push_str(line);
        unique.push('\n');
    }
    Ok(unique)
}

/// Render the accept-policy table that only names the mesh's input.
///
/// # Errors
/// Returns [`PolicyError::InvalidRule`] for malformed fields.
pub fn render_mesh_only(policy: &Policy) -> Result<String, PolicyError> {
    validate_fields(policy)?;
    let mut rules = String::from(
        "table inet infraternal_host {\n    chain input {\n        type filter hook input priority filter - 10; policy accept;\n",
    );
    if policy.mesh_enabled {
        let _ = write!(
            rules,
            "        iifname \"infraternal0\" accept\n        udp dport {} accept\n",
            policy.mesh_udp_port()
        );
    }
    rules.push_str("    }\n}\n");
    Ok(rules)
}

/// Render the table for `mode`.
///
/// # Errors
/// Returns an error when the policy is invalid for that mode.
pub fn render_for(policy: &Policy, mode: InputMode) -> Result<String, PolicyError> {
    match mode {
        InputMode::Enforce => render(policy),
        InputMode::MeshOnly => render_mesh_only(policy),
    }
}

/// Return the fixed paths nft discovery checks when no path is configured.
#[must_use]
pub fn nft_candidates() -> &'static [&'static str] {
    NFT_CANDIDATES
}

/// Validate and apply a policy in one nft transaction, returning its migration report.
///
/// `nft_path` is optional; when present, it must resolve to a root-owned executable.
/// The configured path is useful for immutable package paths recorded by installers.
///
/// # Errors
/// Returns an error for invalid policy, missing or unsafe nft, or a rejected batch.
pub fn apply(policy: &Policy, nft_path: Option<&Path>) -> Result<String, PolicyError> {
    apply_with_ssh_connection(policy, nft_path, ssh_connection_from_env()?.as_deref())
}

/// Read `SSH_CONNECTION`; a value that is not UTF-8 cannot be checked, so it refuses.
fn ssh_connection_from_env() -> Result<Option<String>, PolicyError> {
    match std::env::var("SSH_CONNECTION") {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(PolicyError::AdminPathWouldBeLost),
    }
}

/// Apply a policy after checking a caller-supplied SSH connection.
///
/// The normal [`apply`] entry reads `SSH_CONNECTION` itself. The explicit
/// argument keeps isolated namespace tests independent of their SSH runner.
///
/// # Errors
/// Returns an error when policy validation, SSH preservation, nft discovery, or the batch fails.
pub fn apply_with_ssh_connection(
    policy: &Policy,
    nft_path: Option<&Path>,
    ssh_connection: Option<&str>,
) -> Result<String, PolicyError> {
    apply_mode_with_ssh_connection(policy, InputMode::Enforce, nft_path, ssh_connection)
}

/// Apply a policy in the given table shape after checking the SSH connection.
///
/// [`InputMode::Enforce`] first checks the live SSH session and then the
/// invariant in [`check_sshd_admission`]: every port sshd uses now or after
/// a restart is admitted. [`InputMode::MeshOnly`] drops nothing, so it skips
/// the admin-path checks; switching from an enforcing table to it only opens
/// input.
///
/// # Errors
/// Returns an error when validation, SSH preservation, nft discovery, or the batch fails.
pub fn apply_mode_with_ssh_connection(
    policy: &Policy,
    mode: InputMode,
    nft_path: Option<&Path>,
    ssh_connection: Option<&str>,
) -> Result<String, PolicyError> {
    if mode == InputMode::Enforce {
        validate_ssh_connection(policy, ssh_connection)?;
        // J671: every default-drop apply (install restart, boot, mesh
        // listener, role clear) keeps every port sshd uses, now and after a
        // restart, not only the session's.
        check_sshd_admission(&policy.admin_rules, &current_sshd_ports())?;
    }
    let desired = render_for(policy, mode)?;
    let nft = discover_nft(nft_path)?;
    let inventory = run_nft(&nft, &["-j", "list", "tables"], None)?;
    let tables: serde_json::Value = serde_json::from_slice(&inventory.stdout)
        .map_err(|_| PolicyError::BadInventory { path: nft.clone() })?;
    let exists = tables["nftables"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["table"]["family"] == "inet" && item["table"]["name"] == HOST_TABLE)
    });
    let current = if exists {
        let output = run_nft(&nft, &["-j", "list", "table", "inet", HOST_TABLE], None)?;
        let current: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| PolicyError::BadInventory { path: nft.clone() })?;
        Some(host_firewall_semantics::from_nft_json(&current, &nft)?)
    } else {
        None
    };
    let desired_semantics = match mode {
        InputMode::Enforce => host_firewall_semantics::from_policy(policy),
        InputMode::MeshOnly => host_firewall_semantics::from_mesh_only_policy(policy),
    };
    if mode == InputMode::Enforce {
        ensure_existing_admin_rules_are_preserved(current.as_ref(), &desired_semantics)?;
    }
    let report = host_firewall_semantics::report(current.as_ref(), Some(&desired_semantics));
    if report == "host firewall migration: no rule differences\n" {
        return Ok(report);
    }
    run_nft(
        &nft,
        &["-f", "-"],
        Some(replace_table_transaction(&desired).as_bytes()),
    )?;
    Ok(report)
}

/// Build the one nft batch that swaps the live host table for the rendered one.
///
/// The rendered table goes into the batch verbatim, so every rule
/// [`render`] writes is installed, whatever selector it starts with. (An
/// earlier version re-filtered rendered lines by prefix and silently dropped
/// rules starting with `ip saddr` or `ip6 saddr`, J573.) The delete and the
/// add share one transaction, so the kernel never runs without the table.
///
/// The batch starts with `add table` (a no-op when the table exists) and
/// then `delete table`, so it is correct whether or not the table is there
/// when the kernel runs it. Choosing `delete` from an earlier `list tables`
/// left a window: a table removed or created in between made the batch fail
/// (J589 P3). Rejected: `destroy table`, which needs nft 1.0.8 or newer.
fn replace_table_transaction(rendered: &str) -> String {
    let mut transaction = String::with_capacity(rendered.len() + 80);
    let _ = writeln!(transaction, "add table inet {HOST_TABLE}");
    let _ = writeln!(transaction, "delete table inet {HOST_TABLE}");
    transaction.push_str(rendered);
    transaction
}

/// Apply the saved role policies in the shape [`InputMode::for_roles`] picks.
fn apply_roles(
    server: Option<Policy>,
    agent: Option<Policy>,
    nft_path: Option<&Path>,
) -> Result<String, PolicyError> {
    let mode = InputMode::for_roles(server.as_ref());
    let ssh_connection = ssh_connection_from_env()?;
    apply_mode_with_ssh_connection(
        &combine(server, agent),
        mode,
        nft_path,
        ssh_connection.as_deref(),
    )
}

/// Load and apply the merged policy stored by the server and agent installers.
///
/// Both files are opened without following symlinks and must be root-owned,
/// non-writable regular files. A missing role file is normal; a missing pair
/// means the product has not configured host firewall ownership yet.
///
/// # Errors
/// Returns an error for an unsafe or malformed role file, missing nft, or a rejected transaction.
pub fn apply_from_config() -> Result<String, PolicyError> {
    apply_from_config_at(&HostFirewallPaths::system(), None, None)
}

/// Apply stored role policies, or remove stale product-owned state when both are cleared.
///
/// The optional executable paths are used by isolated namespace tests. Normal
/// boot and installer paths pass `None` and use the fixed root-owned candidates.
///
/// # Errors
/// Returns an error for unsafe role files, missing tools, or failed nft/systemd operations.
pub fn apply_from_config_at(
    paths: &HostFirewallPaths,
    nft_path: Option<&Path>,
    systemctl_path: Option<&Path>,
) -> Result<String, PolicyError> {
    let server = read_policy_file(paths.server_policy_path())?;
    let agent = read_policy_file(paths.agent_policy_path())?;
    if server.is_none() && agent.is_none() {
        let mut report = remove_host_table(nft_path)?;
        report.push_str(&remove_owned_loader(paths, systemctl_path)?);
        return Ok(report);
    }
    apply_roles(server, agent, nft_path)
}

/// What `infraternal-firewall.service` runs at boot: apply the saved policy, or fail open.
///
/// When the saved default-drop table would drop a port sshd uses on this
/// host now (its configuration, service or socket changed since the policy
/// was saved, or a source cannot be read), the table is **not** enforced:
/// the mesh-only accept shape is applied instead, which replaces any
/// enforcing table and keeps the mesh port, and a loud
/// [`PolicyError::FailedOpen`] is returned so the unit fails and the
/// journal says why. An open host is recoverable from anywhere; a host that
/// drops sshd is not (J671, #483).
///
/// # Errors
/// [`PolicyError::FailedOpen`] after failing open; otherwise as [`apply_from_config_at`].
pub fn boot_apply_from_config() -> Result<String, PolicyError> {
    boot_apply_from_config_at(&HostFirewallPaths::system(), None, None)
}

/// [`boot_apply_from_config`] below the supplied layout, for namespace tests.
///
/// # Errors
/// As [`boot_apply_from_config`].
pub fn boot_apply_from_config_at(
    paths: &HostFirewallPaths,
    nft_path: Option<&Path>,
    systemctl_path: Option<&Path>,
) -> Result<String, PolicyError> {
    match apply_from_config_at(paths, nft_path, systemctl_path) {
        Err(
            reason @ (PolicyError::SshdNotAdmitted { .. } | PolicyError::SshdPortsUnknown { .. }),
        ) => {
            let opened = read_policy_file(paths.server_policy_path())
                .and_then(|server| {
                    let agent = read_policy_file(paths.agent_policy_path())?;
                    apply_mode_with_ssh_connection(
                        &combine(server, agent),
                        InputMode::MeshOnly,
                        nft_path,
                        None,
                    )
                })
                .map_or_else(
                    |error| {
                        format!(
                            "replacing the table with the open mesh-only one also failed: {error}"
                        )
                    },
                    |_| "the open mesh-only table is live instead".to_owned(),
                );
            Err(PolicyError::FailedOpen {
                reason: Box::new(reason),
                opened,
            })
        }
        other => other,
    }
}

/// Clear one role's policy and reconcile the remaining host input configuration.
///
/// Removing the last default-drop table only opens input. When another role
/// still owns policy, its candidate is validated against the active SSH path
/// before the nft transaction runs.
///
/// # Errors
/// Returns an error for unmarked files, unsafe policies, missing tools, or failed removals.
pub fn clear_role_from_config(role: PolicyRole) -> Result<String, PolicyError> {
    clear_role_from_config_at(role, &HostFirewallPaths::system(), None, None)
}

/// Clear a role below the supplied layout and use the requested fixed executables.
///
/// This is the same lifecycle used by [`clear_role_from_config`], with explicit
/// paths so privileged namespace tests can prove removal without touching `/etc`
/// or `/var/lib` on the build host.
///
/// # Errors
/// Returns an error for unmarked files, unsafe policies, missing tools, or failed removals.
pub fn clear_role_from_config_at(
    role: PolicyRole,
    paths: &HostFirewallPaths,
    nft_path: Option<&Path>,
    systemctl_path: Option<&Path>,
) -> Result<String, PolicyError> {
    clear_role(role, paths, nft_path, systemctl_path, true)
}

/// Retire an agent's input rules and policy. The installer journal owns the
/// separate decision about the shared systemd loader and its enablement link.
///
/// # Errors
/// Refuses an unsafe policy or a firewall change that cannot finish safely.
pub fn clear_installed_agent_rules_at(
    paths: &HostFirewallPaths,
    nft_path: Option<&Path>,
) -> Result<String, PolicyError> {
    clear_role(PolicyRole::Agent, paths, nft_path, None, false)
}

/// Reconcile the selected role and optionally reconcile its shared loader.
fn clear_role(
    role: PolicyRole,
    paths: &HostFirewallPaths,
    nft_path: Option<&Path>,
    systemctl_path: Option<&Path>,
    manage_loader: bool,
) -> Result<String, PolicyError> {
    let server = read_policy_file(paths.server_policy_path())?;
    let agent = read_policy_file(paths.agent_policy_path())?;
    let (cleared, remaining_server, remaining_agent) = match role {
        PolicyRole::Server => (server, None, agent),
        PolicyRole::Agent => (agent, server, None),
    };
    if cleared.is_none() {
        return if manage_loader {
            apply_from_config_at(paths, nft_path, systemctl_path)
        } else {
            Ok(String::new())
        };
    }

    let no_remaining_policy = remaining_server.is_none() && remaining_agent.is_none();
    let mut report = if no_remaining_policy {
        remove_host_table(nft_path)?
    } else {
        apply_roles(remaining_server, remaining_agent, nft_path)?
    };
    let policy_path = match role {
        PolicyRole::Server => paths.server_policy_path(),
        PolicyRole::Agent => paths.agent_policy_path(),
    };
    remove_policy_file(policy_path)?;
    let role_name = match role {
        PolicyRole::Server => "server",
        PolicyRole::Agent => "agent",
    };
    let _ = writeln!(
        report,
        "host firewall removal: removed {role_name} policy file {}",
        policy_path.display()
    );

    if no_remaining_policy && manage_loader {
        report.push_str(&remove_owned_loader(paths, systemctl_path)?);
    }
    Ok(report)
}

/// Withdraw an uncommitted agent install's policy without changing its loader files.
///
/// Reapply the saved server policy, or remove the product table if the agent
/// was its only owner. When the installer is restoring its prior hand-written
/// loader, let that loader restore the previous table instead. The caller
/// holds the install journal and has already stopped the agent.
///
/// # Errors
/// Returns an error if the saved role files or their live rules cannot be reconciled.
#[cfg(target_os = "linux")]
pub fn rollback_agent_policy(
    paths: &HostFirewallPaths,
    restore_saved_policy: bool,
    nft_path: Option<&Path>,
) -> Result<(), PolicyError> {
    let agent = paths.agent_policy_path();
    if read_policy_file(agent)?.is_none() {
        return Ok(());
    }
    if restore_saved_policy {
        if let Some(server) = read_policy_file(paths.server_policy_path())? {
            apply_roles(Some(server), None, nft_path)?;
        } else {
            match remove_host_table(nft_path) {
                Ok(_) => {}
                // No loader can apply a new table without nft. Keep unwinding the install.
                Err(PolicyError::TableRemovalFailed { source, .. })
                    if matches!(*source, PolicyError::NftMissing { .. }) => {}
                Err(error) => return Err(error),
            }
        }
    }
    remove_policy_file(agent)
}

/// Read one validated role policy from its root-owned configuration file.
///
/// # Errors
/// Returns an error when the file is unsafe, oversized, unreadable, or malformed.
pub fn read_policy_file(path: &Path) -> Result<Option<Policy>, PolicyError> {
    read_policy_file_for_owner(path, 0)
}

/// Read the marked policy for the owner of a checked installation namespace.
///
/// # Errors
/// Rejects unsafe file metadata, oversized input or a foreign policy marker.
pub fn read_policy_file_for_owner(path: &Path, owner: u32) -> Result<Option<Policy>, PolicyError> {
    #[cfg(any(test, feature = "test-support"))]
    refuse_live_test_policy(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PolicyError::Io(error)),
    };
    let metadata = file.metadata().map_err(PolicyError::Io)?;
    #[cfg(unix)]
    let approved_owner = metadata.uid() == owner && metadata.mode() & 0o022 == 0;
    #[cfg(not(unix))]
    let approved_owner = metadata.is_file();
    if !metadata.is_file() || !approved_owner || metadata.len() > MAX_POLICY_BYTES {
        return Err(PolicyError::UnsafePolicy(path.to_owned()));
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| PolicyError::BadPolicy(path.to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(PolicyError::Io)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(PolicyError::BadPolicy(path.to_owned()));
    }
    let stored: StoredPolicy =
        serde_json::from_slice(&bytes).map_err(|_| PolicyError::BadPolicy(path.to_owned()))?;
    if stored.marker != HOST_FIREWALL_POLICY_MARKER {
        return Err(PolicyError::UnownedPolicy(path.to_owned()));
    }
    validate_fields(&stored.policy).map_err(|_| PolicyError::BadPolicy(path.to_owned()))?;
    Ok(Some(stored.policy))
}

/// Encode a validated role policy with the ownership marker used by startup and cleanup.
///
/// Installer journals call this before publishing bytes so cleanup can recognize
/// only files the product created.
///
/// # Errors
/// Returns an error when policy fields are invalid or JSON encoding fails.
pub fn serialize_policy_file(policy: &Policy) -> Result<Vec<u8>, PolicyError> {
    validate_fields(policy)?;
    serde_json::to_vec_pretty(&StoredPolicy {
        marker: HOST_FIREWALL_POLICY_MARKER.to_owned(),
        policy: policy.clone(),
    })
    .map_err(PolicyError::EncodePolicy)
}

/// Replace one role policy atomically with root-only permissions.
///
/// The temporary file is created beside the destination with mode 0600, then
/// synced before rename. The parent directory is synced after publication so
/// boot sees either the complete previous policy or the complete new one.
///
/// # Errors
/// Returns an error for invalid settings, unsafe paths, or failed file operations.
pub fn write_policy_file(path: &Path, policy: &Policy) -> Result<(), PolicyError> {
    #[cfg(any(test, feature = "test-support"))]
    refuse_live_test_policy(path)?;
    validate_fields(policy)?;
    let Some(parent) = path.parent() else {
        return Err(PolicyError::UnsafePolicy(path.to_owned()));
    };
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(PolicyError::UnsafePolicy(path.to_owned()));
    }
    // A missing policy folder is created private (0700), never with the
    // default 0755: on a host where `infraternal up` saves the agent policy
    // before `server init --system`, this creates `/var/lib/infraternal`, the
    // D395 data folder, and the server install keeps an existing folder's
    // mode (J755). Folders that already exist keep theirs.
    #[cfg(unix)]
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(PolicyError::Io)?;
    #[cfg(not(unix))]
    fs::create_dir_all(parent).map_err(PolicyError::Io)?;
    validate_policy_directories(parent, path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || !safe_policy_owner(&metadata) => {
            return Err(PolicyError::UnsafePolicy(path.to_owned()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(PolicyError::Io(error)),
    }
    // Fixed role paths do not make a file ours. Updates may replace only a valid marked policy.
    let _existing_policy = read_policy_file(path)?;
    let bytes = serialize_policy_file(policy)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(PolicyError::BadPolicy(path.to_owned()));
    }
    let sequence = POLICY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.{}.{}.pending",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("policy"),
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        let mut file = options.open(&temporary).map_err(PolicyError::Io)?;
        file.write_all(&bytes).map_err(PolicyError::Io)?;
        file.sync_all().map_err(PolicyError::Io)?;
        fs::rename(&temporary, path).map_err(PolicyError::Io)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(PolicyError::Io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Remove one validated product-owned role file after its replacement is active.
fn remove_policy_file(path: &Path) -> Result<(), PolicyError> {
    if read_policy_file(path)
        .map_err(|source| managed_item_removal_failure(path, source))?
        .is_none()
    {
        return Ok(());
    }
    match fs::remove_file(path) {
        Ok(()) => sync_parent_after_removal(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PolicyError::RemovalFailed {
            item: path.to_owned(),
            source,
        }),
    }
}

/// Remove only the named product host table in one nft transaction and report its rules.
fn remove_host_table(nft_path: Option<&Path>) -> Result<String, PolicyError> {
    let nft =
        discover_nft(nft_path).map_err(|source| host_table_removal_failure(nft_path, source))?;
    let inventory = run_nft(&nft, &["-j", "list", "tables"], None)
        .map_err(|source| host_table_removal_failure(Some(&nft), source))?;
    let tables: serde_json::Value = serde_json::from_slice(&inventory.stdout)
        .map_err(|_| PolicyError::BadInventory { path: nft.clone() })
        .map_err(|source| host_table_removal_failure(Some(&nft), source))?;
    let entries = tables["nftables"]
        .as_array()
        .ok_or_else(|| PolicyError::BadInventory { path: nft.clone() })
        .map_err(|source| host_table_removal_failure(Some(&nft), source))?;
    let exists = entries.iter().any(|item| {
        item.get("table")
            .is_some_and(|table| table["family"] == "inet" && table["name"] == HOST_TABLE)
    });
    if !exists {
        return Ok("host firewall migration: no rule differences\nhost firewall removal: inet infraternal_host was already absent\n".to_owned());
    }

    let output = run_nft(&nft, &["-j", "list", "table", "inet", HOST_TABLE], None)
        .map_err(|source| host_table_removal_failure(Some(&nft), source))?;
    let current: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| PolicyError::BadInventory { path: nft.clone() })
        .map_err(|source| host_table_removal_failure(Some(&nft), source))?;
    let current = host_firewall_semantics::from_nft_json(&current, &nft)
        .map_err(|source| host_table_removal_failure(Some(&nft), source))?;
    let mut report = host_firewall_semantics::report(Some(&current), None);
    // `add` first keeps the delete valid if the table vanished since the listing.
    run_nft(
        &nft,
        &["-f", "-"],
        Some(format!("add table inet {HOST_TABLE}\ndelete table inet {HOST_TABLE}\n").as_bytes()),
    )
    .map_err(|source| host_table_removal_failure(Some(&nft), source))?;
    let _ = writeln!(report, "host firewall removal: removed inet {HOST_TABLE}");
    Ok(report)
}

/// Name the product-owned host table when any removal step fails.
fn host_table_removal_failure(nft_path: Option<&Path>, source: PolicyError) -> PolicyError {
    let nft = nft_path.map_or_else(
        || "the fixed system and Nix paths".to_owned(),
        |path| format!("nft at {}", path.display()),
    );
    PolicyError::TableRemovalFailed {
        item: format!("inet {HOST_TABLE}"),
        nft,
        source: Box::new(source),
    }
}

/// Name the managed path when an inspection step prevents its safe removal.
fn managed_item_removal_failure(path: &Path, source: PolicyError) -> PolicyError {
    PolicyError::ManagedItemRemovalFailed {
        item: path.to_owned(),
        source: Box::new(source),
    }
}

/// Remove the marked loader files and reload systemd after the table has been removed.
fn remove_owned_loader(
    paths: &HostFirewallPaths,
    systemctl_path: Option<&Path>,
) -> Result<String, PolicyError> {
    let unit_owned = has_unit_marker(paths.unit_path())
        .map_err(|source| managed_item_removal_failure(paths.unit_path(), source))?;
    let unit_present = path_exists(paths.unit_path())
        .map_err(|source| managed_item_removal_failure(paths.unit_path(), source))?;
    let link_present = path_exists(paths.enabled_path())
        .map_err(|source| managed_item_removal_failure(paths.enabled_path(), source))?;
    let link_owned = if unit_owned {
        is_product_enablement_link(paths)
            .map_err(|source| managed_item_removal_failure(paths.enabled_path(), source))?
    } else {
        false
    };
    if !unit_owned && !unit_present && !link_present {
        return Ok("host firewall removal: loader was already absent\n".to_owned());
    }

    let systemctl = if unit_owned {
        Some(
            discover_systemctl(systemctl_path)
                .map_err(|source| managed_item_removal_failure(paths.unit_path(), source))?,
        )
    } else {
        None
    };
    let mut report = String::new();
    if link_owned {
        remove_named_item(paths.enabled_path())?;
        let _ = writeln!(
            report,
            "host firewall removal: removed enablement link {}",
            paths.enabled_path().display()
        );
    } else if link_present {
        let _ = writeln!(
            report,
            "host firewall removal: kept unmarked enablement link {}",
            paths.enabled_path().display()
        );
    }

    if unit_owned {
        remove_named_item(paths.unit_path())?;
        let _ = writeln!(
            report,
            "host firewall removal: removed loader unit {}",
            paths.unit_path().display()
        );
        if let Some(systemctl) = systemctl {
            reload_systemd(&systemctl, paths.unit_path())?;
        }
    } else if unit_present {
        let _ = writeln!(
            report,
            "host firewall removal: kept unmarked loader unit {}",
            paths.unit_path().display()
        );
    }
    Ok(report)
}

/// Recognize only the production hand loader that reads the documented nft file.
///
/// Before the product owned the host firewall (D386), prod's
/// `infraternal-firewall.service` was written by hand to load
/// `/etc/nftables/infraternal-host.nft` (#274). `infraternal up` and
/// `server init` may replace exactly that unit, or one carrying
/// [`HOST_FIREWALL_UNIT_MARKER`]; any other unit at that path is someone
/// else's and is never overwritten.
#[must_use]
pub fn known_hand_firewall_unit(bytes: &[u8]) -> bool {
    let Ok(unit) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut starts = Vec::new();
    let mut pres = Vec::new();
    for line in unit.lines() {
        if let Some(command) = line.strip_prefix("ExecStart=") {
            starts.push(command);
        } else if let Some(command) = line.strip_prefix("ExecStartPre=") {
            pres.push(command);
        } else if [
            "ExecStartPost=",
            "ExecStop=",
            "ExecStopPost=",
            "ExecCondition=",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix))
        {
            return false;
        }
    }
    if starts.len() != 1 || pres.len() > 1 {
        return false;
    }
    let command_matches = |command: &str, expected_args: &str| {
        let command = command.strip_prefix('-').unwrap_or(command);
        let Some((executable, arguments)) = command.split_once(' ') else {
            return false;
        };
        Path::new(executable).is_absolute()
            && Path::new(executable)
                .file_name()
                .is_some_and(|name| name == "nft")
            && arguments == expected_args
    };
    command_matches(starts[0], "-f /etc/nftables/infraternal-host.nft")
        && pres
            .first()
            .is_none_or(|command| command_matches(command, "delete table inet infraternal_host"))
}

/// Check whether the root-owned loader file carries its exact product marker.
fn has_unit_marker(path: &Path) -> Result<bool, PolicyError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(PolicyError::Io(error)),
    };
    if !metadata.is_file() || !safe_policy_owner(&metadata) {
        return Err(PolicyError::UnsafeManagedItem(path.to_owned()));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PolicyError::Io(error)
        } else {
            PolicyError::UnsafeManagedItem(path.to_owned())
        }
    })?;
    let opened = file.metadata().map_err(PolicyError::Io)?;
    if !opened.is_file() || !safe_policy_owner(&opened) {
        return Err(PolicyError::UnsafeManagedItem(path.to_owned()));
    }
    #[cfg(unix)]
    if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
        return Err(PolicyError::UnsafeManagedItem(path.to_owned()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(PolicyError::Io)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(PolicyError::UnsafeManagedItem(path.to_owned()));
    }
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .any(|line| line == HOST_FIREWALL_UNIT_MARKER))
}

/// Check whether the enablement symlink resolves to this layout's loader unit.
fn is_product_enablement_link(paths: &HostFirewallPaths) -> Result<bool, PolicyError> {
    let metadata = match fs::symlink_metadata(paths.enabled_path()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(PolicyError::Io(error)),
    };
    if !metadata.file_type().is_symlink() {
        return Ok(false);
    }
    #[cfg(unix)]
    if metadata.uid() != 0 {
        return Ok(false);
    }
    let target = fs::read_link(paths.enabled_path()).map_err(PolicyError::Io)?;
    Ok(target == Path::new("../infraternal-firewall.service"))
}

/// Check for any object at a managed path without following a possible symlink.
fn path_exists(path: &Path) -> Result<bool, PolicyError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(PolicyError::Io(error)),
    }
}

/// Remove one already-validated product path and name it if the unlink fails.
fn remove_named_item(path: &Path) -> Result<(), PolicyError> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent_after_removal(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PolicyError::RemovalFailed {
            item: path.to_owned(),
            source,
        }),
    }
}

/// Persist a successful unlink before reporting the policy clear as complete.
fn sync_parent_after_removal(path: &Path) -> Result<(), PolicyError> {
    let parent = path.parent().ok_or_else(|| PolicyError::RemovalFailed {
        item: path.to_owned(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "managed path has no parent"),
    })?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| PolicyError::RemovalFailed {
            item: path.to_owned(),
            source,
        })
}

/// Find systemctl from fixed system and Nix profile paths, never through `PATH`.
///
/// `configured` replaces the search list (a test hook); `None` searches the
/// fixed, root-owned locations, and every hop of a symlink chain must be
/// root-controlled (the same rule as nft, D384/D386).
///
/// # Errors
/// Returns [`PolicyError::UnsafeSystemctl`] for a candidate that is not
/// root-controlled and [`PolicyError::SystemctlMissing`] when none exists.
pub fn discover_systemctl(configured: Option<&Path>) -> Result<PathBuf, PolicyError> {
    const CANDIDATES: &[&str] = &[
        "/usr/bin/systemctl",
        "/bin/systemctl",
        "/run/current-system/sw/bin/systemctl",
        "/nix/var/nix/profiles/default/bin/systemctl",
        "/nix/var/nix/profiles/system/sw/bin/systemctl",
        "/root/.nix-profile/bin/systemctl",
    ];
    let candidates = configured.map_or_else(
        || CANDIDATES.iter().map(PathBuf::from).collect::<Vec<_>>(),
        |path| vec![path.to_owned()],
    );
    for candidate in &candidates {
        match safe_nft_path(candidate) {
            Ok(Some(path)) => return Ok(path),
            Ok(None) => {}
            Err(PolicyError::UnsafeNft(path)) => return Err(PolicyError::UnsafeSystemctl(path)),
            Err(error) => return Err(error),
        }
    }
    Err(PolicyError::SystemctlMissing {
        checked: candidates
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    })
}

/// Ask the fixed system manager to forget the loader after its files are removed.
fn reload_systemd(systemctl: &Path, removed_unit: &Path) -> Result<(), PolicyError> {
    let output = Command::new(systemctl)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .arg("daemon-reload")
        .stdin(Stdio::null())
        .output()
        .map_err(|source| PolicyError::SystemctlExecutionFailed {
            path: systemctl.to_owned(),
            item: removed_unit.to_owned(),
            source,
        })?;
    if !output.status.success() {
        return Err(PolicyError::SystemctlRejected {
            path: systemctl.to_owned(),
            item: removed_unit.to_owned(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(())
}

/// Record the mesh node's listener in the agent policy and apply the merged host policy.
///
/// Call it with `Some(port)`, the UDP port the node's socket actually bound,
/// when the mesh comes up or rebinds; and with `None` when the mesh stops.
/// The host table then admits `infraternal0` and exactly that UDP port, or
/// neither. A missing pair of role files is normal on hosts without
/// product-managed kernel policy; the mesh userspace filter remains active as
/// D384 requires, and nothing is written.
///
/// # Errors
/// Returns an error when the role files are unsafe or the merged nft update fails.
pub fn set_mesh_listener(udp_port: Option<u16>) -> Result<Option<String>, PolicyError> {
    #[cfg(any(test, feature = "test-support"))]
    {
        if let Some(paths) = TEST_POLICY_PATHS.with(|current| current.borrow().clone()) {
            return set_mesh_listener_at(&paths, None, udp_port);
        }
        if let Some(root) = std::env::var_os(TEST_HOST_FIREWALL_ROOT) {
            let paths = fixture_policy_paths(Path::new(&root))?;
            return set_mesh_listener_at(&paths, None, udp_port);
        }
        // Standalone test builds without configured host policy model an
        // unenrolled host. The privileged runner must provide its fixture root.
        if std::env::var_os("INFRATERNAL_VERIFY_OUTER_NETNS").is_none() {
            return Ok(None);
        }
    }
    // Rootless namespace proofs run whole `infraternal agent` processes, which cannot use the
    // thread-local override above. A build with `test-support` (never shipped) maps the fixed
    // layout below this private root instead, so a machine that has a real install in
    // /var/lib/infraternal does not make the proof's nodes fail with EACCES.
    #[cfg(feature = "test-support")]
    if let Some(root) = std::env::var_os("INFRATERNAL_TEST_HOST_FIREWALL_ROOT") {
        return set_mesh_listener_at(&HostFirewallPaths::under(Path::new(&root)), None, udp_port);
    }
    set_mesh_listener_at(&HostFirewallPaths::system(), None, udp_port)
}

/// The private policy layout shared with fixture subprocesses and worker threads.
#[cfg(any(test, feature = "test-support"))]
const TEST_HOST_FIREWALL_ROOT: &str = "INFRATERNAL_TEST_HOST_FIREWALL_ROOT";

/// Refuse to open or modify the installed policy when the fixture runner is active.
#[cfg(any(test, feature = "test-support"))]
fn refuse_live_test_policy(path: &Path) -> Result<(), PolicyError> {
    if path.starts_with("/var/lib/infraternal")
        && (std::env::var_os("INFRATERNAL_VERIFY_OUTER_NETNS").is_some()
            || std::env::var_os(TEST_HOST_FIREWALL_ROOT).is_some())
    {
        return Err(PolicyError::Io(io::Error::other(format!(
            "privileged test refused to access live state at {}; set {TEST_HOST_FIREWALL_ROOT} to a private fixture directory",
            path.display()
        ))));
    }
    Ok(())
}

/// Resolve a fixture's alternate root before forming any policy paths.
#[cfg(any(test, feature = "test-support"))]
fn fixture_policy_paths(root: &Path) -> Result<HostFirewallPaths, PolicyError> {
    let invalid_root = || {
        PolicyError::Io(io::Error::other(format!(
            "{TEST_HOST_FIREWALL_ROOT} must name an existing private directory: {}",
            root.display()
        )))
    };
    if !root.is_absolute() || root.starts_with("/var/lib/infraternal") {
        return Err(invalid_root());
    }
    let resolved = root.canonicalize().map_err(|_| invalid_root())?;
    if resolved == Path::new("/")
        || resolved.starts_with("/var/lib/infraternal")
        || !resolved.is_dir()
    {
        return Err(invalid_root());
    }
    Ok(HostFirewallPaths::under(&resolved))
}

// Node-level namespace tests drive `set_mesh_listener` through a real mesh node,
// which always asks for the fixed system layout; they point it at a private root.
#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    /// The private policy layout a test on this thread asked the mesh listener to use, if any.
    static TEST_POLICY_PATHS: RefCell<Option<HostFirewallPaths>> = const { RefCell::new(None) };
}

/// A test-only redirect of [`set_mesh_listener`]'s policy files to a private layout.
///
/// A mesh node opens and closes its listener through [`set_mesh_listener`],
/// which reads the fixed `/var/lib/infraternal` role files. A privileged
/// namespace test that brings up a real node installs this guard with
/// [`HostFirewallPaths::under`] a private root, so the node's own calls
/// update the test's host table and never read or write the machine's.
/// Only the current thread is affected, and dropping the guard restores the
/// previous layout. The nft it runs is still found by [`discover_nft`], so a
/// test pairs this with [`NftTestPathOverride`].
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct HostFirewallPathsTestOverride {
    /// The previous thread-local layout, restored when the guard leaves scope.
    previous: Option<HostFirewallPaths>,
}

/// Test-only constructor for the policy layout redirect.
#[cfg(any(test, feature = "test-support"))]
impl HostFirewallPathsTestOverride {
    /// Send this thread's [`set_mesh_listener`] calls to `paths` until the guard is dropped.
    #[doc(hidden)]
    #[must_use]
    pub fn install(paths: &HostFirewallPaths) -> Self {
        let previous = TEST_POLICY_PATHS.with(|current| current.replace(Some(paths.clone())));
        Self { previous }
    }
}

/// Restore the previous layout without affecting another test thread.
#[cfg(any(test, feature = "test-support"))]
impl Drop for HostFirewallPathsTestOverride {
    /// Put back an earlier redirect after this test ends.
    fn drop(&mut self) {
        let previous = self.previous.take();
        TEST_POLICY_PATHS.with(|current| *current.borrow_mut() = previous);
    }
}

/// Record the mesh listener below the supplied layout, using the given nft executable.
///
/// This is the same lifecycle as [`set_mesh_listener`], with explicit paths so
/// privileged namespace tests can prove it without touching `/var/lib`.
///
/// # Errors
/// Returns an error when the role files are unsafe or the merged nft update fails.
pub fn set_mesh_listener_at(
    paths: &HostFirewallPaths,
    nft_path: Option<&Path>,
    udp_port: Option<u16>,
) -> Result<Option<String>, PolicyError> {
    let server = read_policy_file(paths.server_policy_path())?;
    let mut agent = read_policy_file(paths.agent_policy_path())?;
    if server.is_none() && agent.is_none() {
        return Ok(None);
    }
    let changed = update_mesh_listener(&mut agent, udp_port);
    // Apply first: a rejected nft transaction leaves both the live table and
    // the saved file at the previous listener, so a retry starts consistent.
    let report = apply_roles(server, agent.clone(), nft_path)?;
    if changed {
        let Some(policy) = agent else {
            return Err(PolicyError::Io(io::Error::other(
                "mesh policy changed without an agent configuration",
            )));
        };
        write_policy_file(paths.agent_policy_path(), &policy)?;
    }
    Ok(Some(report))
}

/// Change the saved mesh listener only when it differs from the requested one.
///
/// A stopped mesh keeps no port, so the next start records whatever it binds.
fn update_mesh_listener(agent: &mut Option<Policy>, udp_port: Option<u16>) -> bool {
    let enabled = udp_port.is_some();
    match agent {
        Some(policy) if policy.mesh_enabled == enabled && policy.mesh_udp_port == udp_port => false,
        Some(policy) => {
            policy.mesh_enabled = enabled;
            policy.mesh_udp_port = udp_port;
            true
        }
        None if enabled => {
            *agent = Some(Policy {
                mesh_enabled: true,
                mesh_udp_port: udp_port,
                ..Policy::default()
            });
            true
        }
        None => false,
    }
}

/// Reject an adoption that would remove an existing explicit SSH allow rule.
fn ensure_existing_admin_rules_are_preserved(
    current: Option<&host_firewall_semantics::HostTable>,
    desired: &host_firewall_semantics::HostTable,
) -> Result<(), PolicyError> {
    if !host_firewall_semantics::preserves_admin_rules(current, desired) {
        return Err(PolicyError::ExistingAdminPathWouldBeLost);
    }
    Ok(())
}

/// Turn the current OpenSSH session into the rule that keeps sshd reachable: TCP on its port.
///
/// The rule admits any source on any interface (`*,*,tcp,<port>`). Pinning
/// it to the session's remote address would lock out a second
/// administrator, or the same one after their address changes; pinning it to
/// the interface that owns the dialled address would drop every new login to
/// an address held by `lo` or a dummy interface (a VIP), whose packets
/// arrive on the NIC (J589, #483). An operator who wants a narrower rule
/// passes it explicitly. `server init` and `infraternal up` both use this.
///
/// # Errors
/// Returns [`PolicyError::AdminPathWouldBeLost`] when the SSH connection is malformed.
pub fn admin_rule_for_ssh_session(value: &str) -> Result<AllowRule, PolicyError> {
    let Some((_remote, port, _local)) = parse_ssh_connection(value) else {
        return Err(PolicyError::AdminPathWouldBeLost);
    };
    if port == 0 {
        return Err(PolicyError::AdminPathWouldBeLost);
    }
    Ok(AllowRule {
        interface: None,
        source: None,
        protocol: Protocol::Tcp,
        port,
    })
}

/// Check every directory component against root writes up to a fixed safe anchor.
fn validate_policy_directories(parent: &Path, policy: &Path) -> Result<(), PolicyError> {
    for directory in parent.ancestors() {
        let metadata = fs::symlink_metadata(directory).map_err(PolicyError::Io)?;
        #[cfg(unix)]
        let safe = metadata.is_dir() && safe_policy_owner(&metadata);
        #[cfg(not(unix))]
        let safe = metadata.is_dir();
        if !safe {
            return Err(PolicyError::UnsafePolicy(policy.to_owned()));
        }
        // `/run` is a fixed root-owned anchor for private runtime fixtures.
        // Its parent can have an unmapped owner in the privileged test namespace.
        if directory == Path::new("/run") {
            break;
        }
    }
    Ok(())
}

/// True only for a regular file owned by root and not writable by group or others.
fn safe_policy_owner(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

/// Parse the four fields supplied by OpenSSH for an active session.
fn parse_ssh_connection(value: &str) -> Option<(IpAddr, u16, IpAddr)> {
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 4 {
        return None;
    }
    Some((
        fields[0].parse().ok()?,
        fields[3].parse().ok()?,
        fields[2].parse().ok()?,
    ))
}

/// Find the interface that owns the local address of an SSH connection.
/// Find the host interface that owns a local address, when one is assigned.
#[must_use]
pub fn interface_for_address(address: IpAddr) -> Option<String> {
    nix::ifaddrs::getifaddrs().ok()?.find_map(|interface| {
        let address_matches = interface.address.as_ref().is_some_and(|socket_address| {
            socket_address
                .as_sockaddr_in()
                .is_some_and(|value| IpAddr::V4(value.ip()) == address)
                || socket_address
                    .as_sockaddr_in6()
                    .is_some_and(|value| IpAddr::V6(value.ip()) == address)
        });
        address_matches.then_some(interface.interface_name)
    })
}

/// Render one validated rule with optional interface, source and destination selectors.
fn render_rule(
    output: &mut String,
    interface: Option<&str>,
    source: Option<&IpPrefix>,
    destination: Option<IpAddr>,
    protocol: Protocol,
    port: u16,
) {
    output.push_str("        ");
    if let Some(interface) = interface {
        let _ = write!(output, "iifname \"{interface}\" ");
    }
    if let Some(source) = source {
        let family = if source.address().is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        let _ = write!(output, "{family} saddr {source} ");
    }
    // A wildcard bind address describes the socket, not a destination on the wire.
    if let Some(destination) = destination.filter(|address| !address.is_unspecified()) {
        let family = if destination.is_ipv4() { "ip" } else { "ip6" };
        let _ = write!(output, "{family} daddr {destination} ");
    }
    let _ = writeln!(output, "{protocol} dport {port} accept");
}

/// Parse `*` or a network interface while excluding nft metacharacters.
fn parse_optional_interface(value: &str) -> Result<Option<String>, PolicyError> {
    if value == "*" {
        return Ok(None);
    }
    validate_interface(Some(value))?;
    Ok(Some(value.to_owned()))
}

/// Parse `*` or an IP prefix for a source field.
fn parse_optional_prefix(value: &str) -> Result<Option<IpPrefix>, PolicyError> {
    if value == "*" {
        Ok(None)
    } else {
        Ok(Some(value.parse()?))
    }
}

/// Validate interface names before they reach the nft input stream.
fn validate_interface(value: Option<&str>) -> Result<(), PolicyError> {
    if value.is_some_and(|interface| {
        interface.is_empty()
            || interface.len() > 15
            || !interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    }) {
        return Err(PolicyError::InvalidRule);
    }
    Ok(())
}

/// Parse one of the supported transport protocols.
fn parse_protocol(value: &str) -> Result<Protocol, PolicyError> {
    match value {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        _ => Err(PolicyError::InvalidRule),
    }
}

/// Resolve a configured executable or one of the fixed entry points in [`NFT_CANDIDATES`].
///
/// Only fixed paths that root alone can repoint are checked: the distro
/// directories and the Nix system, default and root profiles. The Nix store
/// is never scanned by name. Any local user can add a root-owned, read-only
/// `<hash>-nftables-<version>` path through the Nix daemon, so a store
/// entry's name and owner say nothing about who asked for it (J589, #483).
/// A store path is used only when a root-owned profile link points at it,
/// or when it is the explicitly configured path. Rejected: keeping the scan
/// and checking the store's referrer or registration database (still
/// user-writable through the daemon, and slower).
///
/// # Errors
/// Returns [`PolicyError::UnsafeNft`] when a candidate exists but any hop of
/// its symlink chain is not root-controlled, or [`PolicyError::NftMissing`],
/// listing every place checked, when none exists.
pub fn discover_nft(configured: Option<&Path>) -> Result<PathBuf, PolicyError> {
    #[cfg(any(test, feature = "test-support"))]
    let test_path = configured
        .is_none()
        .then(|| TEST_NFT_PATH.with(|current| current.borrow().clone()))
        .flatten();
    #[cfg(not(any(test, feature = "test-support")))]
    let test_path: Option<PathBuf> = None;
    let configured = configured.or(test_path.as_deref());
    let candidates = nft_search_paths(configured);
    for candidate in &candidates {
        if let Some(resolved) = safe_nft_path(candidate)? {
            return Ok(resolved);
        }
    }
    Err(PolicyError::NftMissing {
        checked: candidates
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    })
}

/// Every path [`discover_nft`] may run, in order: the configured one alone, or the fixed list.
fn nft_search_paths(configured: Option<&Path>) -> Vec<PathBuf> {
    configured.map_or_else(
        || NFT_CANDIDATES.iter().map(PathBuf::from).collect(),
        |configured| vec![configured.to_owned()],
    )
}

/// The most symlinks [`trusted_chain`] follows for one candidate, as the kernel limits it.
#[cfg(unix)]
const MAX_SYMLINK_HOPS: usize = 40;

/// Root-owned directories that may be group- or world-writable because they are sticky.
///
/// In a sticky directory nobody but root can rename or remove root's
/// entries, and [`trusted_chain`] requires every entry it passes to be
/// root-owned, so an entry another user created there is refused. Only these
/// two are exempt: the store (`1775 root:nixbld`) and the per-user profile
/// root, which older Nix installs create as `1777`.
#[cfg(unix)]
const STICKY_TRUSTED_DIRECTORIES: &[&str] = &["/nix/store", "/nix/var/nix/profiles/per-user"];

/// Check a candidate and return its final, root-controlled target.
///
/// A path that does not exist, or that runs through a regular file
/// (`NotADirectory`), is simply absent. Anything else that exists must pass
/// [`trusted_chain`], or the call fails loudly.
fn safe_nft_path(candidate: &Path) -> Result<Option<PathBuf>, PolicyError> {
    if !candidate.is_absolute() {
        return Err(PolicyError::UnsafeNft(candidate.to_owned()));
    }
    match candidate.canonicalize() {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(PolicyError::Io(error)),
    }
    #[cfg(unix)]
    {
        trusted_chain(candidate).map(Some)
    }
    #[cfg(not(unix))]
    {
        let resolved = candidate.canonicalize().map_err(PolicyError::Io)?;
        if !fs::metadata(&resolved).map_err(PolicyError::Io)?.is_file() {
            return Err(PolicyError::UnsafeNft(resolved));
        }
        Ok(Some(resolved))
    }
}

/// Follow `candidate` one component at a time and check every hop of its symlink chain.
///
/// `canonicalize` alone checks only the end of the chain, so a link that a
/// user could repoint in the middle (a profile generation, a per-user
/// directory) would go unnoticed. Here every directory passed through must be
/// root-owned and not group- or world-writable (except the sticky ones in
/// [`STICKY_TRUSTED_DIRECTORIES`]), every symlink must be root-owned, and
/// the target must be a root-owned regular file that is executable and not
/// group- or world-writable. `current` never contains a symlink, so `..`
/// is resolved by dropping its last component.
#[cfg(unix)]
fn trusted_chain(candidate: &Path) -> Result<PathBuf, PolicyError> {
    use std::{collections::VecDeque, ffi::OsString, path::Component};

    /// Queue a path's components, keeping `..` and dropping `.` and the root.
    fn components(path: &Path) -> impl DoubleEndedIterator<Item = OsString> + '_ {
        path.components().filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_owned()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
    }

    let refuse = |path: &Path| PolicyError::UnsafeNft(path.to_owned());
    let mut current = PathBuf::from("/");
    let root = fs::metadata(&current).map_err(PolicyError::Io)?;
    // `/run` is a fixed root-owned anchor for runtime tools and the
    // privileged test sandbox, whose `/` shows host root as an unmapped uid.
    // Below it, as before J591, `/` need only be unwritable by others.
    let root_trusted = if candidate.starts_with("/run") {
        root.is_dir() && root.permissions().mode() & 0o022 == 0
    } else {
        trusted_directory(&current, &root)
    };
    if !root_trusted {
        return Err(refuse(&current));
    }
    let mut pending = components(candidate).collect::<VecDeque<_>>();
    let mut hops = 0;
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            current.pop();
            continue;
        }
        let next = current.join(&name);
        let metadata = fs::symlink_metadata(&next).map_err(PolicyError::Io)?;
        if metadata.uid() != 0 {
            return Err(refuse(&next));
        }
        if metadata.file_type().is_symlink() {
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return Err(refuse(candidate));
            }
            let target = fs::read_link(&next).map_err(PolicyError::Io)?;
            if target.is_absolute() {
                current = PathBuf::from("/");
            }
            for component in components(&target).rev() {
                pending.push_front(component);
            }
            continue;
        }
        if metadata.is_dir() {
            if !trusted_directory(&next, &metadata) {
                return Err(refuse(&next));
            }
            current = next;
            continue;
        }
        let mode = metadata.permissions().mode();
        if pending.is_empty() && metadata.is_file() && mode & 0o022 == 0 && mode & 0o111 != 0 {
            return Ok(next);
        }
        return Err(refuse(&next));
    }
    // The chain ended on a directory, not an executable.
    Err(refuse(candidate))
}

/// True for a root-owned directory that no other user can write into.
#[cfg(unix)]
fn trusted_directory(path: &Path, metadata: &fs::Metadata) -> bool {
    let mode = metadata.permissions().mode();
    metadata.is_dir()
        && metadata.uid() == 0
        && (mode & 0o022 == 0
            || (mode & 0o1000 != 0
                && STICKY_TRUSTED_DIRECTORIES
                    .iter()
                    .any(|sticky| path == Path::new(sticky))))
}

/// Run nft at its resolved absolute path while capturing inventory and error output.
fn run_nft(
    path: &Path,
    arguments: &[&str],
    input: Option<&[u8]>,
) -> Result<std::process::Output, PolicyError> {
    let mut command = Command::new(path);
    command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().map_err(PolicyError::Io)?;
    if let Some(input) = input {
        let Some(mut stdin) = child.stdin.take() else {
            return Err(PolicyError::Io(io::Error::other(
                "nft stdin is unavailable",
            )));
        };
        stdin.write_all(input).map_err(PolicyError::Io)?;
    }
    let output = child.wait_with_output().map_err(PolicyError::Io)?;
    if !output.status.success() {
        return Err(PolicyError::NftRejected {
            path: path.to_owned(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output)
}

/// Host policy state transitions avoid a disk write and nft transaction when unchanged.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "a failed fixture step should name the step that failed"
)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        HOST_TABLE, MESH_UDP_DEFAULT_PORT, Policy, PolicyError, combine,
        host_table_removal_failure, render, update_mesh_listener,
    };

    /// A missing policy folder is created 0700, so an agent-first host's `/var/lib/infraternal` is private (J755 P3-3).
    ///
    /// The scratch folder is not root-owned, so the write itself is refused
    /// by the directory check after the folder exists; only the mode of the
    /// folder it created matters here.
    #[cfg(unix)]
    #[test]
    fn a_missing_policy_folder_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "j771-policy-folder-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        let folder = root.join("var/lib/infraternal");
        let _ =
            super::write_policy_file(&folder.join("host-firewall-agent.json"), &Policy::default());
        let mode = std::fs::metadata(&folder)
            .expect("the policy writer creates its missing folder")
            .permissions()
            .mode();
        std::fs::remove_dir_all(&root).expect("remove the scratch folder");
        assert_eq!(mode & 0o777, 0o700);
    }

    /// Applying the current mesh listener again leaves its policy unchanged and reports no work.
    #[test]
    fn repeated_mesh_listener_does_not_request_an_update() {
        let mut agent = Some(Policy {
            mesh_enabled: true,
            mesh_udp_port: Some(10_254),
            ..Policy::default()
        });

        assert!(!update_mesh_listener(&mut agent, Some(10_254)));
        assert_eq!(agent.as_ref().map(|policy| policy.mesh_enabled), Some(true));
    }

    /// A node that bound another port moves the saved rule to that port; stopping clears it.
    #[test]
    fn mesh_listener_follows_the_bound_port_and_clears_on_stop() {
        let mut agent = Some(Policy {
            mesh_enabled: true,
            mesh_udp_port: Some(10_254),
            ..Policy::default()
        });

        assert!(update_mesh_listener(&mut agent, Some(32_001)));
        assert_eq!(
            agent.as_ref().and_then(|policy| policy.mesh_udp_port),
            Some(32_001)
        );
        assert!(update_mesh_listener(&mut agent, None));
        let stopped = agent.expect("agent policy stays saved");
        assert!(!stopped.mesh_enabled);
        assert_eq!(stopped.mesh_udp_port, None);
    }

    /// The rendered table admits the recorded port, and only the standard port when none is recorded.
    #[test]
    fn rendered_mesh_rule_uses_the_recorded_port() {
        let admin = Policy {
            admin_rules: vec!["wt0,10.69.69.0/24,tcp,22".parse().expect("admin rule")],
            ..Policy::default()
        };
        let agent = Policy {
            mesh_enabled: true,
            mesh_udp_port: Some(32_001),
            ..Policy::default()
        };
        let bound = render(&combine(Some(admin.clone()), Some(agent))).expect("render");
        assert!(bound.contains("udp dport 32001 accept"), "{bound}");
        assert!(!bound.contains("udp dport 10254 accept"), "{bound}");

        let legacy = Policy {
            mesh_enabled: true,
            ..Policy::default()
        };
        let standard = render(&combine(Some(admin), Some(legacy))).expect("render");
        assert!(
            standard.contains(&format!("udp dport {MESH_UDP_DEFAULT_PORT} accept")),
            "{standard}"
        );
    }

    /// Policy files written before the port field existed still load.
    #[test]
    fn policy_without_a_recorded_port_still_deserializes() {
        let policy: Policy = serde_json::from_str(
            r#"{"admin_rules":[],"accept_interfaces":[],"listeners":[],"mesh_enabled":true}"#,
        )
        .expect("legacy policy file");
        assert_eq!(policy.mesh_udp_port(), MESH_UDP_DEFAULT_PORT);
    }

    /// J555 review (P1): a `/nix/store` entry whose name contains `-nftables-` but
    /// is a regular file (a `.drv`, a source tarball, a patch) must be skipped
    /// like a missing candidate. Today `canonicalize` fails with
    /// `NotADirectory`, which is not `NotFound`, so discovery aborts on the
    /// first such entry and a Nix-only host gets no host or mesh nft at all.
    #[test]
    fn review_j555_a_file_shaped_store_entry_does_not_abort_nft_discovery() {
        let regular_file = std::env::current_exe().expect("test binary path");
        let candidate = regular_file.join("bin/nft");
        let result = super::safe_nft_path(&candidate);
        assert!(
            matches!(result, Ok(None)),
            "a candidate below a regular file must be skipped, got {result:?}"
        );
    }

    /// J589 review (P1, security): on a multi-user Nix host any local user can
    /// put a root-owned, read-only `<hash>-nftables-<version>/bin/nft` into
    /// `/nix/store` (`nix-store --add` through the world-writable daemon
    /// socket). It passes every ownership check, so a lookup that lists the
    /// store and picks the highest version hands infraternal an attacker's
    /// program to run as root (prod's shape, #483). Store names and ownership
    /// say nothing about who asked for the path.
    ///
    /// J591 removed the store scan. This checks, without touching the store,
    /// the two things that keep it removed: the search list names only fixed
    /// entry points outside `/nix/store`, and the lookup code never lists a
    /// directory. It used to plant a fake nft with `nix-store --add` and left
    /// it in the real, shared store on every run (J608, #483); a static check
    /// proves the same without writing anything.
    #[test]
    fn review_j589_store_scan_never_offers_a_user_added_nft() {
        let offered = super::nft_search_paths(None);
        assert!(!offered.is_empty(), "the fixed search list is empty");
        for path in &offered {
            let text = path.to_str().expect("candidate paths are UTF-8");
            assert!(
                path.is_absolute() && !path.starts_with("/nix/store"),
                "the search list names a store or relative path: {offered:?}"
            );
            assert!(
                !text.contains(['*', '?', '[']),
                "a candidate looks like a pattern, not a fixed path: {text}"
            );
        }
        // The lookup is everything from `discover_nft` up to `run_nft`
        // (search list, chain check, sticky directories). Listing a
        // directory there would bring back a scan of the store.
        let source = include_str!("host_firewall.rs");
        let lookup_start = source
            .find("pub fn discover_nft(")
            .expect("discover_nft in this module");
        let lookup_end = source.find("fn run_nft(").expect("run_nft in this module");
        let lookup = &source[lookup_start..lookup_end];
        assert!(
            !lookup.contains("read_dir") && !lookup.contains("glob"),
            "nft lookup lists a directory; it must only check the fixed entry points"
        );
    }

    /// A root-owned system chain with relative, absolute and `..` hops resolves to its file.
    ///
    /// The Nix default profile is prod's shape (#483): `default` ->
    /// `per-user/root/profile` -> generation link -> store environment ->
    /// store package, every hop root-owned.
    #[cfg(unix)]
    #[test]
    fn a_root_owned_symlink_chain_resolves() {
        for candidate in [
            "/bin/sh",
            "/usr/bin/../bin/sh",
            "/nix/var/nix/profiles/default/bin/nix-store",
        ] {
            let candidate = Path::new(candidate);
            if !candidate.exists() {
                eprintln!("SKIP: {} is absent", candidate.display());
                continue;
            }
            let resolved = super::safe_nft_path(candidate).expect("trusted system chain");
            assert_eq!(
                resolved.as_deref(),
                Some(candidate.canonicalize().expect("canonical").as_path())
            );
        }
    }

    /// Any hop a non-root user owns is refused loudly, not skipped, even when it ends at a root file.
    #[cfg(unix)]
    #[test]
    fn a_user_owned_hop_in_the_chain_is_refused() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let scratch = std::env::temp_dir().join(format!("j591-chain-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("scratch directory");
        let link = scratch.join("nft");
        symlink("/bin/sh", &link).expect("user-owned link to a root-owned file");
        let owner = std::fs::symlink_metadata(&link)
            .expect("link metadata")
            .uid();
        let result = super::safe_nft_path(&link);
        let _ = std::fs::remove_dir_all(&scratch);
        if owner == 0 {
            eprintln!("SKIP: running as root, the link is root-owned");
            return;
        }
        assert!(
            matches!(result, Err(PolicyError::UnsafeNft(_))),
            "a chain through a user-owned link must be refused, got {result:?}"
        );
    }

    /// Only a server policy makes the host table drop by default (J555, #483).
    #[test]
    fn only_the_server_role_gets_a_default_drop_table() {
        let server = Policy {
            admin_rules: vec!["*,*,tcp,22".parse().expect("admin rule")],
            ..Policy::default()
        };
        assert_eq!(
            super::InputMode::for_roles(Some(&server)),
            super::InputMode::Enforce
        );
        assert_eq!(
            super::InputMode::for_roles(None),
            super::InputMode::MeshOnly
        );
    }

    /// A joined machine's table accepts by default and names only the mesh's input.
    #[test]
    fn mesh_only_table_drops_nothing_and_opens_the_bound_port() {
        let agent = Policy {
            admin_rules: vec!["*,192.0.2.5,tcp,22".parse().expect("admin rule")],
            mesh_enabled: true,
            mesh_udp_port: Some(32_001),
            ..Policy::default()
        };
        super::validate_agent(&Policy::default()).expect("an agent needs no admin rule");
        let rendered = super::render_mesh_only(&agent).expect("render");
        assert_eq!(
            rendered,
            concat!(
                "table inet infraternal_host {\n",
                "    chain input {\n",
                "        type filter hook input priority filter - 10; policy accept;\n",
                "        iifname \"infraternal0\" accept\n",
                "        udp dport 32001 accept\n",
                "    }\n",
                "}\n",
            )
        );
        let stopped = super::render_mesh_only(&Policy::default()).expect("render");
        assert!(!stopped.contains(" drop"), "{stopped}");
        assert!(!stopped.contains("dport"), "{stopped}");
    }

    /// Every rendered rule reaches the nft batch, including ones that start with a source address.
    #[test]
    fn replace_transaction_keeps_source_restricted_rules() {
        let policy = Policy {
            admin_rules: vec!["*,192.0.2.0/24,tcp,22".parse().expect("admin rule")],
            listeners: vec![super::Listener {
                interface: None,
                address: "0.0.0.0:443".parse().expect("listener address"),
                protocol: super::Protocol::Tcp,
                sources: vec!["198.51.100.0/24".parse().expect("source")],
            }],
            ..Policy::default()
        };
        let rendered = render(&policy).expect("render");
        let batch = super::replace_table_transaction(&rendered);
        assert!(
            batch.contains("ip saddr 192.0.2.0/24 tcp dport 22 accept"),
            "{batch}"
        );
        assert!(
            batch.contains("ip saddr 198.51.100.0/24 tcp dport 443 accept"),
            "{batch}"
        );
        // One batch, valid whether or not the table exists when it runs.
        assert!(
            batch.starts_with(
                "add table inet infraternal_host\ndelete table inet infraternal_host\ntable inet infraternal_host {"
            ),
            "{batch}"
        );
    }

    /// J555 review (P2): a host that gets IPv6 addresses by `DHCPv6` must keep
    /// receiving server replies. The client sends to the `ff02::1:2`
    /// multicast group, so conntrack cannot match the unicast reply from the
    /// server's link-local address as established; without an explicit
    /// `udp dport 546` allowance from `fe80::/10` the default-drop chain
    /// drops it and the host loses its leased address at renewal.
    #[test]
    fn review_j555_rendered_policy_admits_dhcpv6_client_replies() {
        let policy = Policy {
            admin_rules: vec!["*,*,tcp,22".parse().expect("admin rule")],
            ..Policy::default()
        };
        let rendered = render(&policy).expect("render");
        assert!(
            rendered
                .lines()
                .any(|line| line.contains("fe80::/10") && line.contains("udp dport 546")),
            "DHCPv6 client replies are dropped by:\n{rendered}"
        );
    }

    /// J555 review (P3): an administrator whose sshd listens on another port,
    /// and who has an explicit allow rule for it, must be able to install the
    /// policy. `validate` insists on a literal TCP/22 rule instead of the
    /// port in `SSH_CONNECTION`, so this host is refused (or must open 22).
    #[test]
    fn review_j555_ssh_on_a_non_default_port_is_a_valid_admin_path() {
        let policy = Policy {
            admin_rules: vec!["*,*,tcp,2222".parse().expect("admin rule")],
            ..Policy::default()
        };
        let result =
            super::validate_ssh_connection_on(&policy, "203.0.113.7 50000 198.51.100.2 2222", None);
        assert!(result.is_ok(), "{result:?}");
    }

    /// A rejected nft delete names the table the user asked infraternal to remove.
    #[test]
    fn table_removal_failure_names_the_product_table() {
        let nft = Path::new("/nix/store/test-nft/bin/nft");
        let error = host_table_removal_failure(
            Some(nft),
            PolicyError::NftRejected {
                path: PathBuf::from(nft),
                message: "permission denied".to_owned(),
            },
        );

        assert!(error.to_string().contains(&format!("inet {HOST_TABLE}")));
        assert!(error.to_string().contains("permission denied"));
    }
}
