//! Renders and applies the host input policy owned by infraternal, D386.

use serde::{Deserialize, Serialize};
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
const NFT_CANDIDATES: &[&str] = &[
    "/usr/sbin/nft",
    "/usr/bin/nft",
    "/sbin/nft",
    "/bin/nft",
    "/run/current-system/sw/bin/nft",
    "/nix/var/nix/profiles/default/bin/nft",
    "/nix/var/nix/profiles/system/sw/bin/nft",
    "/root/.nix-profile/bin/nft",
];
/// The nftables table whose input chain protects server and agent listeners.
pub const HOST_TABLE: &str = "infraternal_host";
/// Server-owned listener and proxy settings read by the boot service.
pub const SERVER_POLICY_PATH: &str = "/var/lib/infraternal/host-firewall-server.json";
/// Agent-owned administrator and mesh settings read by the boot service.
pub const AGENT_POLICY_PATH: &str = "/var/lib/infraternal/host-firewall-agent.json";

/// Bound disk reads and writes for each root-owned policy file.
const MAX_POLICY_BYTES: u64 = 64 * 1024;
/// Disambiguate concurrently written temporary policy names in this process.
static POLICY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    /// The default-drop policy does not explicitly preserve TCP/22 administration.
    #[error("host firewall policy needs an explicit TCP/22 admin rule")]
    MissingAdminPath,
    /// Applying a candidate policy would remove the SSH connection running this command.
    #[error("host firewall policy would drop the current SSH admin path")]
    AdminPathWouldBeLost,
    /// Replacing the current table would remove a configured TCP/22 path.
    #[error("host firewall policy would remove an existing TCP/22 allow rule")]
    ExistingAdminPathWouldBeLost,
    /// No product-owned host policy file is installed.
    #[error("host firewall policy is not configured")]
    NoPolicy,
    /// A host policy file is not a root-owned, non-writable regular file.
    #[error("host firewall policy file at {0} is not a safe root-owned file")]
    UnsafePolicy(PathBuf),
    /// A host policy file is too large or contains invalid serialized settings.
    #[error("host firewall policy file at {0} is invalid")]
    BadPolicy(PathBuf),
    /// No safe nft executable was available at the listed fixed paths.
    #[error("nft executable was not found; checked: {checked}")]
    NftMissing {
        /// Every absolute candidate inspected, including the fixed Nix store glob.
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
}

/// Ensure that all rule fields are safe and preserve an explicit SSH path.
///
/// # Errors
/// Returns [`PolicyError::InvalidRule`] for malformed fields or
/// [`PolicyError::MissingAdminPath`] when TCP/22 is not explicitly allowed.
pub fn validate(policy: &Policy) -> Result<(), PolicyError> {
    validate_fields(policy)?;
    if !policy
        .admin_rules
        .iter()
        .any(|rule| rule.protocol == Protocol::Tcp && rule.port == 22)
    {
        return Err(PolicyError::MissingAdminPath);
    }
    Ok(())
}

/// Validate stored rule fields before their role-specific policies are merged.
fn validate_fields(policy: &Policy) -> Result<(), PolicyError> {
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
/// persisted explicit TCP/22 rule validated by [`validate`]. Interactive
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
/// Returns an error when the policy is invalid or has no explicit TCP/22 admin rule.
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
        rules.push_str("        iifname \"infraternal0\" accept\n        udp dport 10254 accept\n");
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

/// Report changed lines between the current table and the desired rendering.
#[must_use]
pub fn diff_report(current: &str, desired: &str) -> String {
    let current_lines = meaningful_lines(current);
    let desired_lines = meaningful_lines(desired);
    if current_lines == desired_lines {
        return "host firewall migration: no rule differences\n".to_owned();
    }
    let mut report = String::from("host firewall migration: current and desired rules differ\n");
    report_ordered_diff(&current_lines, &desired_lines, &mut report);
    report
}

/// Show ordered removals and additions so migration receipts explain chain reordering.
fn report_ordered_diff(current: &[String], desired: &[String], report: &mut String) {
    let mut common = vec![vec![0; desired.len() + 1]; current.len() + 1];
    for current_index in (0..current.len()).rev() {
        for desired_index in (0..desired.len()).rev() {
            common[current_index][desired_index] =
                if current[current_index] == desired[desired_index] {
                    common[current_index + 1][desired_index + 1] + 1
                } else {
                    common[current_index + 1][desired_index]
                        .max(common[current_index][desired_index + 1])
                };
        }
    }

    let mut current_index = 0;
    let mut desired_index = 0;
    while current_index < current.len() || desired_index < desired.len() {
        if current_index < current.len()
            && desired_index < desired.len()
            && current[current_index] == desired[desired_index]
        {
            current_index += 1;
            desired_index += 1;
        } else if desired_index < desired.len()
            && (current_index == current.len()
                || common[current_index][desired_index + 1]
                    >= common[current_index + 1][desired_index])
        {
            let _ = writeln!(report, "+ desired: {}", desired[desired_index]);
            desired_index += 1;
        } else {
            let _ = writeln!(report, "- current: {}", current[current_index]);
            current_index += 1;
        }
    }
}

/// Return the fixed system paths checked before the Nix store.
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
    let ssh_connection = match std::env::var("SSH_CONNECTION") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(PolicyError::AdminPathWouldBeLost);
        }
    };
    apply_with_ssh_connection(policy, nft_path, ssh_connection.as_deref())
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
    validate_ssh_connection(policy, ssh_connection)?;
    let desired = render(policy)?;
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
        let output = run_nft(&nft, &["-n", "list", "table", "inet", HOST_TABLE], None)?;
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else {
        String::new()
    };
    ensure_existing_admin_rules_are_preserved(&current, &desired)?;
    let report = diff_report(&current, &desired);
    if report == "host firewall migration: no rule differences\n" {
        return Ok(report);
    }
    let mut transaction = String::new();
    if exists {
        transaction.push_str("delete table inet infraternal_host\n");
    }
    transaction.push_str("add table inet infraternal_host\n");
    transaction.push_str(
        "add chain inet infraternal_host input { type filter hook input priority filter - 10; policy drop; }\n",
    );
    for line in desired.lines().filter(|line| {
        line.trim_start().starts_with("iifname")
            || line.trim_start().starts_with("ct state")
            || line.trim_start().starts_with("ip protocol")
            || line.trim_start().starts_with("meta l4proto")
            || line.trim_start().starts_with("tcp dport")
            || line.trim_start().starts_with("udp dport")
    }) {
        let rule = line.trim();
        transaction.push_str("add rule inet infraternal_host input ");
        transaction.push_str(rule);
        transaction.push('\n');
    }
    run_nft(&nft, &["-f", "-"], Some(transaction.as_bytes()))?;
    Ok(report)
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
    let server = read_policy_file(Path::new(SERVER_POLICY_PATH))?;
    let agent = read_policy_file(Path::new(AGENT_POLICY_PATH))?;
    if server.is_none() && agent.is_none() {
        return Err(PolicyError::NoPolicy);
    }
    apply(&combine(server, agent), None)
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
    let policy: Policy =
        serde_json::from_slice(&bytes).map_err(|_| PolicyError::BadPolicy(path.to_owned()))?;
    validate_fields(&policy).map_err(|_| PolicyError::BadPolicy(path.to_owned()))?;
    Ok(Some(policy))
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
    let bytes =
        serde_json::to_vec_pretty(policy).map_err(|_| PolicyError::BadPolicy(path.to_owned()))?;
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

/// Change the agent's mesh bit and apply the merged host policy if configured.
///
/// A missing pair of role files is normal on hosts without product-managed
/// kernel policy; the mesh userspace filter remains active as D384 requires.
///
/// # Errors
/// Returns an error when the role files are unsafe or the merged nft update fails.
pub fn set_mesh_enabled(enabled: bool) -> Result<Option<String>, PolicyError> {
    let server = read_policy_file(Path::new(SERVER_POLICY_PATH))?;
    let mut agent = read_policy_file(Path::new(AGENT_POLICY_PATH))?;
    if server.is_none() && agent.is_none() {
        return Ok(None);
    }
    let changed = update_mesh_enabled(&mut agent, enabled);
    let combined = combine(server, agent.clone());
    let report = apply(&combined, None)?;
    if changed {
        let Some(policy) = agent else {
            return Err(PolicyError::Io(io::Error::other(
                "mesh policy changed without an agent configuration",
            )));
        };
        write_policy_file(Path::new(AGENT_POLICY_PATH), &policy)?;
    }
    Ok(Some(report))
}

/// Change the saved mesh bit only when its value differs from the requested state.
fn update_mesh_enabled(agent: &mut Option<Policy>, enabled: bool) -> bool {
    match agent {
        Some(policy) if policy.mesh_enabled == enabled => false,
        Some(policy) => {
            policy.mesh_enabled = enabled;
            true
        }
        None if enabled => {
            *agent = Some(Policy {
                mesh_enabled: true,
                ..Policy::default()
            });
            true
        }
        None => false,
    }
}

/// Reject an adoption that would remove an existing explicit SSH allow rule.
fn ensure_existing_admin_rules_are_preserved(
    current: &str,
    desired: &str,
) -> Result<(), PolicyError> {
    let desired = meaningful_lines(desired);
    let current_admin = meaningful_lines(current)
        .into_iter()
        .filter(|line| line.contains("tcp dport 22") && line.contains("accept"));
    if current_admin.into_iter().any(|line| {
        let normalized = remove_counter_clause(&line);
        !desired
            .iter()
            .any(|desired_line| remove_counter_clause(desired_line) == normalized)
    }) {
        return Err(PolicyError::ExistingAdminPathWouldBeLost);
    }
    Ok(())
}

/// Turn the current OpenSSH session into one explicit source and interface rule.
///
/// `infraternal up` uses this before asking for approval, then passes the
/// resulting typed rule to its root installer so sudo environment filtering
/// cannot lose the active administrator path.
///
/// # Errors
/// Returns an error when the SSH connection is malformed or its addresses cannot be parsed.
pub fn admin_rule_for_ssh_connection(value: &str) -> Result<AllowRule, PolicyError> {
    let Some((remote, port, local)) = parse_ssh_connection(value) else {
        return Err(PolicyError::AdminPathWouldBeLost);
    };
    Ok(AllowRule {
        interface: interface_for_address(local),
        source: Some(remote.to_string().parse()?),
        protocol: Protocol::Tcp,
        port,
    })
}

/// Ignore generated counter text when comparing existing nft rules with policy output.
fn remove_counter_clause(line: &str) -> String {
    let Some((before, after)) = line.split_once(" counter packets") else {
        return line.to_owned();
    };
    after.find(" accept").map_or_else(
        || line.to_owned(),
        |accept| format!("{before}{}", &after[accept..]),
    )
}

/// Check every directory component and existing policy file against root writes.
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

/// Keep rule-bearing lines and normalize nft presentation details for comparison.
fn meaningful_lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && *line != "{"
                && *line != "}"
                && !line.starts_with("table ")
                && !line.starts_with("chain ")
        })
        .map(remove_counter_clause)
        // nft versions may print the invalid conntrack bit as either 0x1 or its name.
        .map(|line| line.replace("ct state 0x1 ", "ct state invalid "))
        .collect()
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

/// Resolve a configured executable or the fixed distro and Nix paths.
///
/// # Errors
/// Returns an error when a candidate is unsafe or no fixed executable path exists.
pub fn discover_nft(configured: Option<&Path>) -> Result<PathBuf, PolicyError> {
    let (candidates, checked) = if let Some(configured) = configured {
        (vec![configured.to_owned()], vec![configured.to_owned()])
    } else {
        let mut candidates = NFT_CANDIDATES.iter().map(PathBuf::from).collect::<Vec<_>>();
        candidates.extend(nix_store_candidates());
        let checked = candidates.clone();
        (candidates, checked)
    };
    for candidate in &candidates {
        if let Some(resolved) = safe_nft_path(candidate)? {
            return Ok(resolved);
        }
    }
    let mut checked = checked
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    if configured.is_none() {
        checked.push("/nix/store/*-nftables-*/bin/nft".to_owned());
    }
    Err(PolicyError::NftMissing {
        checked: checked.join(", "),
    })
}

/// Find package-local nft executables only below the fixed Nix store directory.
fn nix_store_candidates() -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir("/nix/store") else {
        return Vec::new();
    };
    let mut candidates = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            name.to_string_lossy().contains("-nftables-")
        })
        .map(|entry| entry.path().join("bin/nft"))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.reverse();
    candidates
}

/// Resolve and check a candidate without following any path from the environment.
fn safe_nft_path(candidate: &Path) -> Result<Option<PathBuf>, PolicyError> {
    if !candidate.is_absolute() {
        return Err(PolicyError::UnsafeNft(candidate.to_owned()));
    }
    let resolved = match candidate.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PolicyError::Io(error)),
    };
    let metadata = fs::metadata(&resolved).map_err(PolicyError::Io)?;
    #[cfg(unix)]
    {
        if !metadata.is_file()
            || !safe_policy_owner(&metadata)
            || metadata.permissions().mode() & 0o111 == 0
        {
            return Err(PolicyError::UnsafeNft(resolved));
        }
        for directory in resolved.parent().into_iter().flat_map(Path::ancestors) {
            let directory_metadata = fs::metadata(directory).map_err(PolicyError::Io)?;
            if !directory_metadata.is_dir() || !safe_nft_directory(directory, &directory_metadata) {
                return Err(PolicyError::UnsafeNft(resolved));
            }
        }
        let candidate_metadata = fs::symlink_metadata(candidate).map_err(PolicyError::Io)?;
        if candidate_metadata.uid() != 0 {
            return Err(PolicyError::UnsafeNft(resolved));
        }
    }
    #[cfg(not(unix))]
    if !metadata.is_file() {
        return Err(PolicyError::UnsafeNft(resolved));
    }
    Ok(Some(resolved))
}

/// Trust the sticky, root-owned Nix store while rejecting writable executable paths.
#[cfg(unix)]
fn safe_nft_directory(path: &Path, metadata: &fs::Metadata) -> bool {
    let mode = metadata.permissions().mode();
    metadata.uid() == 0
        && (mode & 0o022 == 0 || (path == Path::new("/nix/store") && mode & 0o1000 != 0))
}

/// Run nft at its resolved absolute path and retain useful stderr on failure.
fn run_nft(
    path: &Path,
    arguments: &[&str],
    input: Option<&[u8]>,
) -> Result<std::process::Output, PolicyError> {
    let mut command = Command::new(path);
    command.args(arguments).stderr(Stdio::piped());
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
mod tests {
    use super::{Policy, update_mesh_enabled};

    /// Applying the current mesh state again leaves its policy unchanged and reports no work.
    #[test]
    fn repeated_mesh_state_does_not_request_an_update() {
        let mut agent = Some(Policy {
            mesh_enabled: true,
            ..Policy::default()
        });

        assert!(!update_mesh_enabled(&mut agent, true));
        assert_eq!(agent.as_ref().map(|policy| policy.mesh_enabled), Some(true));
    }
}
