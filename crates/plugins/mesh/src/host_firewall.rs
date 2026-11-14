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
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

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
/// [`InputMode::MeshOnly`] drops nothing, so it skips the admin-path checks;
/// switching from an enforcing table to it only opens input.
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
    let server = read_policy_file(paths.server_policy_path())?;
    let agent = read_policy_file(paths.agent_policy_path())?;
    let (cleared, remaining_server, remaining_agent) = match role {
        PolicyRole::Server => (server, None, agent),
        PolicyRole::Agent => (agent, server, None),
    };
    if cleared.is_none() {
        return apply_from_config_at(paths, nft_path, systemctl_path);
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

    if no_remaining_policy {
        report.push_str(&remove_owned_loader(paths, systemctl_path)?);
    }
    Ok(report)
}

/// Read one validated role policy from its root-owned configuration file.
///
/// # Errors
/// Returns an error when the file is unsafe, oversized, unreadable, or malformed.
pub fn read_policy_file(path: &Path) -> Result<Option<Policy>, PolicyError> {
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
    if !metadata.is_file() || !safe_policy_owner(&metadata) || metadata.len() > MAX_POLICY_BYTES {
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
    set_mesh_listener_at(&HostFirewallPaths::system(), None, udp_port)
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

/// Whether `rules` keep an SSH path to every port sshd uses when there is no live session to check.
///
/// A console install has no `SSH_CONNECTION`, so [`validate_ssh_connection`]
/// cannot prove the saved default-drop table keeps sshd reachable, and
/// [`validate`] accepts any TCP rule (sshd may not listen on 22). This
/// requires a counting rule for **every** port in `sshd_ports`, the union
/// [`sshd_ports`] learned: a rule for the configured port alone dropped an
/// sshd running on another one (J658, #483). An empty list never passes:
/// guessing 22 let a console install lock out an sshd on 2222 (J608).
///
/// See [`uncovered_sshd_ports`] for which rules count.
#[must_use]
pub fn admits_sshd(rules: &[AllowRule], sshd_ports: &[u16]) -> bool {
    !sshd_ports.is_empty() && uncovered_sshd_ports(rules, sshd_ports).is_empty()
}

/// The ports in `sshd_ports` that no rule in `rules` admits as an SSH path, in order.
///
/// A rule counts for a port when it is TCP on that port and is not limited
/// to the loopback interface, to a single source address (/32 or /128), or
/// to a loopback source network (`127.0.0.0/8`, `::1/127`, ...): those admit
/// only local logins or one machine, which proves nothing about the
/// administrators' way in (J608, J658). A real interface or a real source
/// network is a deliberate admin path and counts.
#[must_use]
pub fn uncovered_sshd_ports(rules: &[AllowRule], sshd_ports: &[u16]) -> Vec<u16> {
    let counts = |rule: &AllowRule, port: u16| {
        rule.protocol == Protocol::Tcp
            && rule.port == port
            && rule.interface.as_deref() != Some("lo")
            && rule.source.as_ref().is_none_or(|source| {
                source.prefix() < if source.address().is_ipv4() { 32 } else { 128 }
                    && !loopback_only(source)
            })
    };
    sshd_ports
        .iter()
        .copied()
        .filter(|port| !rules.iter().any(|rule| counts(rule, *port)))
        .collect()
}

/// Whether every address in `source` is a loopback address.
///
/// `source` holds its network address (host bits cleared), so `::1/127` is
/// stored as `::/127`: it covers `::` and `::1` and nothing routable. A
/// wider network that merely contains loopback (`64.0.0.0/2`) is not
/// loopback-only.
fn loopback_only(source: &IpPrefix) -> bool {
    match source.address() {
        IpAddr::V4(address) => source.prefix() >= 8 && address.octets()[0] == 127,
        IpAddr::V6(address) => {
            (source.prefix() >= 127 && address.segments()[..7] == [0; 7])
                || (source.prefix() >= 104
                    && address
                        .to_ipv4_mapped()
                        .is_some_and(|mapped| mapped.octets()[0] == 127))
        }
    }
}

/// One place sshd's ports were learned from, for a console install.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshdPortSource {
    /// A short name for the source, for messages ("sshd -G", ...).
    pub source: &'static str,
    /// The TCP ports this source names, sorted and without duplicates; never empty.
    pub ports: Vec<u16>,
}

/// sshd's TCP ports as learned for a console install, or why none could be.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshdPorts {
    /// Every source that named ports; never empty. The saved table must
    /// admit all of their ports ([`SshdPorts::required`]).
    Known(Vec<SshdPortSource>),
    /// No source named a port; the text lists what was tried and why it failed.
    Unknown(String),
}

impl SshdPorts {
    /// Combine what each source answered: every port any source named is required.
    ///
    /// Sources that failed or named nothing add their reason to the text an
    /// [`SshdPorts::Unknown`] carries when no source answered at all.
    #[must_use]
    pub fn combine(answers: Vec<(&'static str, Result<Vec<u16>, String>)>) -> Self {
        let mut known = Vec::new();
        let mut tried = Vec::new();
        for (source, answer) in answers {
            match answer {
                Ok(mut ports) => {
                    ports.retain(|port| *port != 0);
                    ports.sort_unstable();
                    ports.dedup();
                    if ports.is_empty() {
                        tried.push(format!("{source}: no port"));
                    } else {
                        known.push(SshdPortSource { source, ports });
                    }
                }
                Err(reason) => tried.push(format!("{source}: {reason}")),
            }
        }
        if known.is_empty() {
            Self::Unknown(tried.join("; "))
        } else {
            Self::Known(known)
        }
    }

    /// The union of all known ports, sorted and without duplicates; empty when unknown.
    #[must_use]
    pub fn required(&self) -> Vec<u16> {
        let Self::Known(sources) = self else {
            return Vec::new();
        };
        let mut ports = sources
            .iter()
            .flat_map(|source| source.ports.iter().copied())
            .collect::<Vec<_>>();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Each source and its ports, for a refusal: `22 (sshd -G), 2222 (running sshd processes)`.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Known(sources) => sources
                .iter()
                .map(|source| {
                    let ports = source
                        .ports
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("{ports} (from {})", source.source)
                })
                .collect::<Vec<_>>()
                .join("; "),
            Self::Unknown(tried) => tried.clone(),
        }
    }
}

/// The fixed places sshd is looked for, never through `PATH` (the same rule as nft, D386).
#[cfg(target_os = "linux")]
const SSHD_CANDIDATES: &[&str] = &[
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/sbin/sshd",
    "/usr/local/sbin/sshd",
    "/run/current-system/sw/bin/sshd",
    "/nix/var/nix/profiles/default/bin/sshd",
    "/nix/var/nix/profiles/system/sw/bin/sshd",
    "/root/.nix-profile/bin/sshd",
];

/// Learn every TCP port sshd accepts on, or will after a restart, for a console `server init`.
///
/// The saved table must keep both the sshd running now and the one the
/// next boot or restart starts, so every source is asked and the answers
/// are combined ([`SshdPorts::combine`]); none of them wins over another.
/// Taking the first answer let `sshd -G`'s configured 22 hide a running
/// sshd started with `-p 2222` (`SSHD_OPTS`, `OPTIONS`, an `ExecStart`
/// drop-in, or a `Port` edit not yet restarted), and the table dropped it
/// (J658, #483). The sources:
/// 1. An `ssh.socket` or `sshd.socket` unit that is active or enabled: the
///    service manager owns the listener (socket activation, the default on
///    current Ubuntu), and sshd's own `Port` lines are ignored for it.
/// 2. sshd's effective configuration, `sshd -G` (no host keys needed), else
///    `sshd -T` for older releases. Both work when sshd is stopped, but only
///    as root, because the configuration files are root-only.
/// 3. Listening sockets held by running `sshd` processes owned by root or by
///    the ssh service's own account ([`sshd_listening_ports`]).
///
/// systemctl and sshd are run only from fixed, root-owned paths, with a
/// clean environment. When nothing answers the result is
/// [`SshdPorts::Unknown`]; the caller refuses rather than guess 22.
#[cfg(target_os = "linux")]
#[must_use]
pub fn sshd_ports() -> SshdPorts {
    let mut answers = Vec::new();
    let mut owners = vec![0];
    match discover_systemctl(None) {
        Ok(systemctl) => {
            answers.push((
                "sshd's systemd socket unit",
                capture(
                    &systemctl,
                    &[
                        "show",
                        "--property=Listen,ActiveState,UnitFileState",
                        "ssh.socket",
                        "sshd.socket",
                    ],
                )
                .map(|text| socket_unit_ports(&text)),
            ));
            if let Ok(text) = capture(
                &systemctl,
                &["show", "--property=UID", "ssh.service", "sshd.service"],
            ) {
                owners.extend(service_uids(&text));
            }
        }
        Err(error) => answers.push(("systemctl", Err(error.to_string()))),
    }
    answers.push(("sshd's configuration", sshd_config_answer()));
    answers.push(("running sshd processes", Ok(sshd_listening_ports(&owners))));
    SshdPorts::combine(answers)
}

/// Ask sshd at a fixed, root-owned path for its effective ports: `sshd -G`, else `sshd -T`.
#[cfg(target_os = "linux")]
fn sshd_config_answer() -> Result<Vec<u16>, String> {
    let mut tried = Vec::new();
    let mut sshd = None;
    for candidate in SSHD_CANDIDATES {
        match safe_nft_path(Path::new(candidate)) {
            Ok(Some(path)) => {
                sshd = Some(path);
                break;
            }
            Ok(None) => {}
            Err(_) => tried.push(format!("{candidate} is not root-controlled")),
        }
    }
    let Some(sshd) = sshd else {
        tried.push("no sshd at the fixed paths".to_owned());
        return Err(tried.join("; "));
    };
    for (flag, source) in [("-G", "sshd -G"), ("-T", "sshd -T")] {
        match capture(&sshd, &[flag]) {
            Ok(text) => {
                let ports = sshd_config_ports(&text);
                if !ports.is_empty() {
                    return Ok(ports);
                }
                tried.push(format!("{source} printed no port"));
            }
            Err(reason) => tried.push(format!("{source}: {reason}")),
        }
    }
    Err(tried.join("; "))
}

/// The numeric `UID=` values in `systemctl show --property=UID` output.
///
/// A service running as root, or not running, prints `UID=[not set]`, which
/// adds nothing; a service with `User=` or `DynamicUser=` prints its
/// account's uid while it runs.
#[must_use]
pub fn service_uids(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|line| line.strip_prefix("UID="))
        .filter_map(|value| value.trim().parse::<u32>().ok())
        .collect()
}

/// Run a fixed, already trusted program with a clean environment and return its stdout.
///
/// The error is the first line of its stderr (or the spawn error), short
/// enough to quote in a refusal.
#[cfg(target_os = "linux")]
fn capture(program: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(stderr
        .lines()
        .next()
        .map_or_else(|| format!("exit {}", output.status), str::to_owned))
}

/// The ports in `sshd -G`/`-T` output: its `listenaddress` lines, else its `port` lines.
///
/// sshd prints one `listenaddress <addr>:<port>` per socket it will open,
/// with `Port` already applied, so those are exact; `port` lines are the
/// fallback when a release prints none. Sorted, no duplicates, no zero.
#[must_use]
pub fn sshd_config_ports(text: &str) -> Vec<u16> {
    let mut listen = Vec::new();
    let mut port = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(key), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        if key.eq_ignore_ascii_case("listenaddress") {
            listen.extend(
                value
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok()),
            );
        } else if key.eq_ignore_ascii_case("port") {
            port.extend(value.parse::<u16>().ok());
        }
    }
    let mut ports = if listen.is_empty() { port } else { listen };
    ports.retain(|port| *port != 0);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The TCP ports of active or enabled socket units in `systemctl show` output.
///
/// The output has one block per unit, separated by a blank line, holding
/// `Listen=<address> (Stream)` lines plus `ActiveState=` and
/// `UnitFileState=`. A unit that is neither active nor enabled (a stock
/// `ssh.socket` next to a plain `ssh.service`) does not listen and is
/// ignored. Sorted, no duplicates, no zero.
#[must_use]
pub fn socket_unit_ports(text: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for block in text.split("\n\n") {
        let mut listens = Vec::new();
        let mut live = false;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("Listen=") {
                let Some(address) = value.strip_suffix(" (Stream)") else {
                    continue;
                };
                let port = address.rsplit_once(':').map_or(address, |(_, port)| port);
                listens.extend(port.parse::<u16>().ok());
            } else if let Some(state) = line.strip_prefix("ActiveState=") {
                live |= state == "active";
            } else if let Some(state) = line.strip_prefix("UnitFileState=") {
                live |= state.starts_with("enabled");
            }
        }
        if live {
            ports.extend(listens);
        }
    }
    ports.retain(|port| *port != 0);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The TCP ports `sshd` processes owned by one of `owners` listen on, sorted; empty when none.
///
/// Reads `/proc/net/tcp{,6}` for listening sockets and maps their inodes to
/// `sshd` processes through `/proc/<pid>/fd`, which only root can read for
/// root's processes. A process counts only when its real and effective uids
/// (from `/proc/<pid>/status`) are both in `owners`: any user can start a
/// program named `sshd`, and its port must not become "sshd's port"
/// (J658). The owner of `/proc/<pid>` is not used, because a process that
/// marks itself non-dumpable shows as root there.
///
/// Listeners bound only to a loopback address are skipped: the network
/// cannot reach them, so they need no rule.
///
/// Used only by a console `server init`, never at boot (sshd may not have
/// started yet) and never as the only proof: the saved policy still needs
/// an explicit rule ([`admits_sshd`]). A socket-activated sshd's listener
/// belongs to the service manager, so it is not seen here; [`sshd_ports`]
/// asks the socket unit too.
#[cfg(target_os = "linux")]
#[must_use]
pub fn sshd_listening_ports(owners: &[u32]) -> Vec<u16> {
    /// Map listening-socket inodes to their local ports from one `/proc/net` table.
    fn listeners(table: &str, into: &mut std::collections::HashMap<u64, u16>) {
        let Ok(text) = fs::read_to_string(table) else {
            return;
        };
        for line in text.lines().skip(1) {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
            let (Some(local), Some(&"0A"), Some(inode)) =
                (fields.get(1), fields.get(3), fields.get(9))
            else {
                continue;
            };
            let Some((address, port)) = local.rsplit_once(':') else {
                continue;
            };
            if proc_net_address_is_loopback(address) {
                continue;
            }
            if let (Ok(port), Ok(inode)) = (u16::from_str_radix(port, 16), inode.parse::<u64>()) {
                into.insert(inode, port);
            }
        }
    }
    let mut sockets = std::collections::HashMap::new();
    listeners("/proc/net/tcp", &mut sockets);
    listeners("/proc/net/tcp6", &mut sockets);
    let mut ports = Vec::new();
    let Ok(processes) = fs::read_dir("/proc") else {
        return ports;
    };
    for process in processes.filter_map(Result::ok) {
        let path = process.path();
        if fs::read_to_string(path.join("comm")).map_or(true, |name| name.trim_end() != "sshd") {
            continue;
        }
        let owned = fs::read_to_string(path.join("status")).is_ok_and(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .is_some_and(|uids| {
                    let mut uids = uids.split_ascii_whitespace().map(str::parse::<u32>);
                    matches!(
                        (uids.next(), uids.next()),
                        (Some(Ok(real)), Some(Ok(effective)))
                            if owners.contains(&real) && owners.contains(&effective)
                    )
                })
        });
        if !owned {
            continue;
        }
        let Ok(descriptors) = fs::read_dir(path.join("fd")) else {
            continue;
        };
        for descriptor in descriptors.filter_map(Result::ok) {
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            let inode = target
                .to_str()
                .and_then(|text| text.strip_prefix("socket:["))
                .and_then(|text| text.strip_suffix(']'))
                .and_then(|text| text.parse::<u64>().ok());
            if let Some(port) = inode.and_then(|inode| sockets.get(&inode)) {
                ports.push(*port);
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Whether a `/proc/net/tcp{,6}` local address (hex) is a loopback address.
///
/// The kernel prints each 32-bit word of the network-order address as a
/// native-endian hex number, so the bytes come back with `to_ne_bytes`.
/// IPv4-mapped loopback (`::ffff:127.x.y.z`) counts as loopback too. An
/// unparsable address is not loopback, so its listener is kept.
#[must_use]
pub fn proc_net_address_is_loopback(hex: &str) -> bool {
    let words = hex
        .as_bytes()
        .chunks(8)
        .map(|word| {
            std::str::from_utf8(word)
                .ok()
                .and_then(|word| u32::from_str_radix(word, 16).ok())
        })
        .collect::<Option<Vec<_>>>();
    match words.as_deref() {
        Some([word]) if hex.len() == 8 => Ipv4Addr::from(word.to_ne_bytes()).is_loopback(),
        Some(words) if hex.len() == 32 && words.len() == 4 => {
            let mut bytes = [0_u8; 16];
            for (chunk, word) in bytes.chunks_mut(4).zip(words) {
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            let address = Ipv6Addr::from(bytes);
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        _ => false,
    }
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

    /// A console install needs a TCP rule on one of sshd's ports; no port known never passes.
    #[test]
    fn console_install_needs_a_rule_for_sshd() {
        let rules = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.parse().expect("rule"))
                .collect::<Vec<super::AllowRule>>()
        };
        assert!(!super::admits_sshd(&rules(&["*,*,tcp,443"]), &[22]));
        assert!(super::admits_sshd(
            &rules(&["*,*,tcp,443", "*,*,tcp,22"]),
            &[22]
        ));
        assert!(!super::admits_sshd(&rules(&["*,*,udp,22"]), &[22]));
        // J658: every port sshd uses needs a rule, not just one of them.
        assert!(!super::admits_sshd(&rules(&["*,*,tcp,2222"]), &[22, 2222]));
        assert!(super::admits_sshd(
            &rules(&["*,*,tcp,2222", "eth0,*,tcp,22"]),
            &[22, 2222]
        ));
        assert!(!super::admits_sshd(&rules(&["*,*,tcp,22"]), &[2222]));
        // J608 (P2): with no port learned, 22 is not assumed.
        assert!(!super::admits_sshd(&rules(&["*,*,tcp,22"]), &[]));
    }

    /// J608 (P3): from a console, a rule limited to `lo` or to one source address is no SSH path.
    ///
    /// `lo,*,tcp,22` admits only local logins, and `*,10.255.255.1,tcp,22`
    /// only one machine that may not exist; neither proves an administrator
    /// can still get in. A real interface or a source network is a
    /// deliberate admin path (prod's is netbird's `wt0` /24) and counts.
    #[test]
    fn console_admin_path_ignores_loopback_and_single_source_rules() {
        let rules = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.parse().expect("rule"))
                .collect::<Vec<super::AllowRule>>()
        };
        assert!(!super::admits_sshd(&rules(&["lo,*,tcp,22"]), &[22]));
        assert!(!super::admits_sshd(
            &rules(&["*,10.255.255.1/32,tcp,22"]),
            &[22]
        ));
        assert!(!super::admits_sshd(
            &rules(&["eth9,10.255.255.1,tcp,22"]),
            &[22]
        ));
        assert!(!super::admits_sshd(
            &rules(&["*,2001:db8::1/128,tcp,22"]),
            &[22]
        ));
        assert!(super::admits_sshd(
            &rules(&["wt0,10.69.69.0/24,tcp,22"]),
            &[22]
        ));
        assert!(super::admits_sshd(&rules(&["eth0,*,tcp,22"]), &[22]));
        assert!(super::admits_sshd(
            &rules(&["lo,*,tcp,22", "*,*,tcp,22"]),
            &[22]
        ));
    }

    /// J658 (P2): every source's ports are required; the configuration never hides a live listener.
    ///
    /// `sshd_config` says 22 while the running sshd listens on 2222 (started
    /// with `-p 2222`). Taking the first answer kept only 22, and the saved
    /// table dropped the running sshd. Combined, both are required, and a
    /// refusal names each port with its source.
    #[test]
    fn review_j658_sshd_sources_are_combined_not_first_wins() {
        use super::{SshdPortSource, SshdPorts};
        let combined = SshdPorts::combine(vec![
            ("sshd's systemd socket unit", Ok(Vec::new())),
            ("sshd's configuration", Ok(vec![22])),
            ("running sshd processes", Ok(vec![2222, 2222, 0])),
        ]);
        assert_eq!(
            combined,
            SshdPorts::Known(vec![
                SshdPortSource {
                    source: "sshd's configuration",
                    ports: vec![22],
                },
                SshdPortSource {
                    source: "running sshd processes",
                    ports: vec![2222],
                },
            ])
        );
        assert_eq!(combined.required(), vec![22, 2222]);
        assert_eq!(
            combined.describe(),
            "22 (from sshd's configuration); 2222 (from running sshd processes)"
        );
        let rule = |value: &str| vec![value.parse::<super::AllowRule>().expect("rule")];
        assert_eq!(
            super::uncovered_sshd_ports(&rule("*,*,tcp,22"), &combined.required()),
            vec![2222]
        );
        // Nothing answered: unknown, with every reason kept.
        let unknown = SshdPorts::combine(vec![
            (
                "systemctl",
                Err("no systemctl at the fixed paths".to_owned()),
            ),
            (
                "sshd's configuration",
                Err("sshd -G: Permission denied".to_owned()),
            ),
            ("running sshd processes", Ok(Vec::new())),
        ]);
        assert!(unknown.required().is_empty());
        let SshdPorts::Unknown(tried) = unknown else {
            panic!("no port must be unknown");
        };
        assert!(
            tried.contains("Permission denied")
                && tried.contains("running sshd processes: no port")
        );
        assert_eq!(super::service_uids("UID=[not set]\n\nUID=105\n"), vec![105]);
    }

    /// A listener bound only to loopback needs no rule; wildcard and real addresses do.
    #[test]
    fn proc_net_loopback_listeners_are_recognised() {
        let v4 = |address: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(address));
        let v6 = |address: std::net::Ipv6Addr| {
            address
                .octets()
                .chunks(4)
                .map(|word| format!("{:08X}", u32::from_ne_bytes(word.try_into().expect("word"))))
                .collect::<String>()
        };
        assert!(super::proc_net_address_is_loopback(&v4([127, 0, 0, 1])));
        assert!(super::proc_net_address_is_loopback(&v4([127, 9, 9, 9])));
        assert!(!super::proc_net_address_is_loopback(&v4([0, 0, 0, 0])));
        assert!(!super::proc_net_address_is_loopback(&v4([10, 0, 0, 1])));
        assert!(super::proc_net_address_is_loopback(&v6(
            std::net::Ipv6Addr::LOCALHOST
        )));
        assert!(super::proc_net_address_is_loopback(&v6("::ffff:127.0.0.1"
            .parse()
            .expect("mapped"))));
        assert!(!super::proc_net_address_is_loopback(&v6(
            std::net::Ipv6Addr::UNSPECIFIED
        )));
        assert!(!super::proc_net_address_is_loopback("zz"));
    }

    /// J658 (P3): a loopback source network is no SSH path, whatever its prefix length.
    ///
    /// J608 excluded only /32 and /128 sources, so `127.0.0.0/8` and
    /// `::1/127` (stored as its network address `::`) still counted, though
    /// both admit only this machine's own logins. A loopback network inside a
    /// wider one (`64.0.0.0/2` holds `127.0.0.0/8`) is a real network and
    /// still counts.
    #[test]
    fn review_j658_loopback_networks_are_no_ssh_path() {
        let rules = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.parse().expect("rule"))
                .collect::<Vec<super::AllowRule>>()
        };
        for loopback in [
            "*,127.0.0.0/8,tcp,22",
            "*,127.1.0.0/16,tcp,22",
            "*,::1/127,tcp,22",
            "*,::ffff:127.0.0.0/104,tcp,22",
            "eth0,127.0.0.0/8,tcp,22",
        ] {
            assert!(
                !super::admits_sshd(&rules(&[loopback]), &[22]),
                "{loopback} counted as an SSH path"
            );
        }
        assert!(super::admits_sshd(&rules(&["*,64.0.0.0/2,tcp,22"]), &[22]));
        assert!(super::admits_sshd(&rules(&["*,::/0,tcp,22"]), &[22]));
        assert!(super::admits_sshd(&rules(&["*,0.0.0.0/0,tcp,22"]), &[22]));
    }

    /// `sshd -G`/`-T` output: `listenaddress` lines are exact, `port` lines are the fallback.
    #[test]
    fn sshd_config_ports_prefer_listen_addresses() {
        let both = "port 2222\nport 2200\naddressfamily any\n\
                    listenaddress [::]:2222\nlistenaddress 0.0.0.0:2222\n\
                    listenaddress 192.0.2.1:2200\n";
        assert_eq!(super::sshd_config_ports(both), vec![2200, 2222]);
        // A ListenAddress with its own port overrides Port.
        let listen = "port 22\nlistenaddress 0.0.0.0:2022\n";
        assert_eq!(super::sshd_config_ports(listen), vec![2022]);
        assert_eq!(super::sshd_config_ports("Port 2222\n"), vec![2222]);
        assert_eq!(
            super::sshd_config_ports("usedns no\nport 0\n"),
            Vec::<u16>::new()
        );
    }

    /// `systemctl show` output: only an active or enabled socket unit's stream ports count.
    #[test]
    fn socket_unit_ports_come_from_live_units_only() {
        let active = "Listen=0.0.0.0:2222 (Stream)\nListen=[::]:2222 (Stream)\n\
                      ActiveState=active\nUnitFileState=enabled\n\n\
                      ActiveState=inactive\nUnitFileState=\n";
        assert_eq!(super::socket_unit_ports(active), vec![2222]);
        // Enabled but not started yet (before the next boot) still counts.
        let enabled = "Listen=2200 (Stream)\nListen=/run/x.sock (Stream)\n\
                       Listen=[::]:5353 (Datagram)\nActiveState=inactive\n\
                       UnitFileState=enabled\n";
        assert_eq!(super::socket_unit_ports(enabled), vec![2200]);
        // A stock, disabled ssh.socket next to a plain ssh.service is ignored.
        let disabled = "Listen=[::]:22 (Stream)\nActiveState=inactive\n\
                        UnitFileState=disabled\n";
        assert_eq!(super::socket_unit_ports(disabled), Vec::<u16>::new());
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

    /// J658 (P3): a non-root process named `sshd` must not set the console check's port.
    ///
    /// Any local user can start a program named `sshd` that holds a
    /// listener; only one owned by root, or by sshd's own service account,
    /// is the real daemon. The holder here is a copy of the system shell
    /// renamed `sshd`, blocked in `read` on a pipe this test keeps open, with
    /// the listener as its stdout. It must be alive and named `sshd` when
    /// the ports are read: J635's first version copied `sleep`, which under
    /// Nix is a link to multi-call coreutils, so its copy exited at once
    /// ("unknown program") and the test passed without a holder. As root the
    /// holder would be root-owned, so the test reports SKIP.
    #[cfg(target_os = "linux")]
    #[test]
    fn review_j658_a_non_root_process_named_sshd_sets_no_port() {
        use std::os::{fd::OwnedFd, unix::fs::MetadataExt};
        use std::process::{Command, Stdio};
        if std::fs::metadata("/proc/self").expect("proc").uid() == 0 {
            eprintln!("SKIP: running as root; the holder would be root-owned");
            return;
        }
        // A real, single-program binary: a multi-call one exits when renamed.
        let shell = std::fs::canonicalize("/bin/sh").expect("resolve /bin/sh");
        let scratch = std::env::temp_dir().join(format!("j658-sshd-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("scratch");
        let fake = scratch.join("sshd");
        std::fs::copy(&shell, &fake).expect("copy the shell as sshd");
        // Wildcard, not loopback: loopback-only listeners are skipped by design.
        let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("listener");
        let port = listener.local_addr().expect("address").port();
        let mut holder = Command::new(&fake)
            .args(["-c", "read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(OwnedFd::from(listener)))
            .stderr(Stdio::null())
            .spawn()
            .expect("start the fake sshd");
        let comm = format!("/proc/{}/comm", holder.id());
        for _ in 0..100 {
            if std::fs::read_to_string(&comm).is_ok_and(|name| name.trim_end() == "sshd") {
                break;
            }
            // sleep: poll until the child has exec'd and its comm reads `sshd`.
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let alive = holder.try_wait().expect("holder state").is_none();
        let named = std::fs::read_to_string(&comm).unwrap_or_default();
        let own = std::fs::metadata("/proc/self").expect("proc").uid();
        // Control: counted as its own account, the holder's port is seen.
        let as_service_account = super::sshd_listening_ports(&[0, own]);
        let ports = super::sshd_listening_ports(&[0]);
        let _ = holder.kill();
        let _ = holder.wait();
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            alive && named.trim_end() == "sshd",
            "the holder is not a live process named sshd (alive {alive}, comm {named:?}); \
             the check below would prove nothing"
        );
        assert!(
            as_service_account.contains(&port),
            "the holder's port {port} was not seen even for its own account \
             ({as_service_account:?}); the check below would prove nothing"
        );
        assert!(
            !ports.contains(&port),
            "a non-root process named sshd set sshd's port to {port} ({ports:?})"
        );
    }
}
