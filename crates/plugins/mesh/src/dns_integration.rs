//! Installs mesh-only DNS routes in the host resolver without replacing unrelated DNS.

use crate::dns::Records;
#[cfg(target_os = "macos")]
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write as _,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
#[cfg(target_os = "linux")]
use std::{
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
use std::{fs, io, net::Ipv4Addr, os::unix::fs::MetadataExt, path::Path};

/// Identifies resolver files owned by the infraternal agent on macOS.
#[cfg(any(target_os = "macos", test))]
const MACOS_MARKER: &str = "# Managed by infraternal agent.";
/// The only directory used for per-suffix resolver files on macOS.
#[cfg(target_os = "macos")]
const MACOS_RESOLVER_DIRECTORY: &str = "/etc/resolver";
/// Fixed systemd-resolved binaries; protected Nix profiles are checked before distro paths.
#[cfg(target_os = "linux")]
const RESOLVECTL_PATHS: &[&str] = &[
    "/nix/var/nix/profiles/default/bin/resolvectl",
    "/nix/var/nix/profiles/system/sw/bin/resolvectl",
    "/nix/var/nix/profiles/per-user/root/profile/bin/resolvectl",
    "/root/.local/state/nix/profiles/profile/bin/resolvectl",
    "/root/.nix-profile/bin/resolvectl",
    "/run/current-system/sw/bin/resolvectl",
    "/usr/bin/resolvectl",
    "/usr/sbin/resolvectl",
    "/bin/resolvectl",
];
/// Fixed `NetworkManager` client binaries; root never looks them up through `PATH`.
#[cfg(target_os = "linux")]
const NMCLI_PATHS: &[&str] = &[
    "/nix/var/nix/profiles/default/bin/nmcli",
    "/nix/var/nix/profiles/system/sw/bin/nmcli",
    "/nix/var/nix/profiles/per-user/root/profile/bin/nmcli",
    "/root/.local/state/nix/profiles/profile/bin/nmcli",
    "/root/.nix-profile/bin/nmcli",
    "/run/current-system/sw/bin/nmcli",
    "/usr/bin/nmcli",
    "/usr/sbin/nmcli",
    "/bin/nmcli",
];
/// Fixed `NetworkManager` daemon binaries used only to inspect its active DNS mode.
#[cfg(target_os = "linux")]
const NETWORKMANAGER_PATHS: &[&str] = &[
    "/nix/var/nix/profiles/default/bin/NetworkManager",
    "/nix/var/nix/profiles/system/sw/bin/NetworkManager",
    "/nix/var/nix/profiles/per-user/root/profile/bin/NetworkManager",
    "/root/.local/state/nix/profiles/profile/bin/NetworkManager",
    "/root/.nix-profile/bin/NetworkManager",
    "/run/current-system/sw/bin/NetworkManager",
    "/usr/sbin/NetworkManager",
    "/usr/bin/NetworkManager",
];
/// The directory where `NetworkManager` reads dnsmasq plugin drop-ins.
#[cfg(target_os = "linux")]
const NETWORKMANAGER_DNSMASQ_DIRECTORY: &str = "/etc/NetworkManager/dnsmasq.d";
/// The one `NetworkManager` dnsmasq drop-in owned by mesh DNS.
#[cfg(target_os = "linux")]
const NETWORKMANAGER_MESH_DNS_FILE: &str = "infraternal-mesh.conf";
/// Identifies the only dnsmasq configuration file this module may replace or remove.
#[cfg(target_os = "linux")]
const NETWORKMANAGER_MESH_DNS_MARKER: &str = "# Managed by infraternal agent.";
/// Gives atomic resolver-file writes distinct temporary names within one process.
#[cfg(any(target_os = "linux", target_os = "macos"))]
static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

/// Owns just the mesh suffix routes installed in the host resolver.
///
/// Linux prefers a per-link systemd-resolved route, then `NetworkManager`'s
/// dnsmasq split-DNS support. Unsupported hosts return a setup error and keep
/// their existing resolver unchanged.
/// macOS writes one managed `/etc/resolver` file per suffix only when root.
#[derive(Default)]
pub(crate) struct DnsIntegration {
    /// The last setup failure, shown by `mesh status` until a later attempt succeeds.
    last_error: Option<String>,
    /// Set when the process lacked the authority to touch system resolver files.
    unprivileged: bool,
    /// Active Linux resolver mechanism and its last accepted route.
    #[cfg(target_os = "linux")]
    linux: Option<LinuxInstall>,
    /// Suffixes and address currently represented by the Mac resolver files.
    #[cfg(target_os = "macos")]
    macos: Option<MacosInstall>,
}

/// The Linux DNS mechanism currently owning the mesh suffix route.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxMode {
    /// systemd-resolved has a per-link DNS server and a routing-only domain.
    Resolved,
    /// Last resort: a marked block in `/etc/hosts` lists the mesh names. It needs no resolver
    /// support, leaves every other tool's `resolv.conf` alone and answers exact names only.
    Hosts,
    /// `NetworkManager`'s dnsmasq plugin forwards mesh suffixes from an owned drop-in.
    NetworkManager,
}

/// Describes the `NetworkManager` capabilities needed for mesh-only DNS forwarding.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct NetworkManagerSupport {
    /// Whether the daemon forwards DNS through its dnsmasq plugin.
    dnsmasq_enabled: bool,
    /// Whether the trusted client can ask `NetworkManager` to reload only DNS state.
    nmcli_available: bool,
}

#[cfg(target_os = "linux")]
impl NetworkManagerSupport {
    /// Reports whether `NetworkManager` can forward DNS through its dnsmasq plugin.
    const fn usable(self) -> bool {
        self.dnsmasq_enabled && self.nmcli_available
    }
}

/// The input needed to reverse one Linux host-resolver installation.
#[cfg(target_os = "linux")]
struct LinuxInstall {
    /// Cleanup ownership survives failures, but only an intact successful install may be reused.
    valid: bool,
    /// The mesh interface used by the per-link systemd-resolved route.
    interface: String,
    /// The index of the owned mesh link that systemd-resolved was told about; `None` outside
    /// `LinuxMode::Resolved`. Cleanup reverts exactly this index, and only while it still holds
    /// the owned mesh link (#584).
    ifindex: Option<u32>,
    /// The split-DNS mechanism installed successfully for this node.
    mode: LinuxMode,
    /// The local mesh DNS server used by the route.
    address: Ipv4Addr,
    /// The default and optional custom suffixes installed for the node.
    suffixes: Vec<String>,
    /// Whether the suffixes were also installed as search domains (off by default).
    search: bool,
    /// The `/etc/hosts` block last written; empty outside `LinuxMode::Hosts`.
    hosts_block: String,
}

/// The input needed to update or remove this node's Mac resolver files.
#[cfg(target_os = "macos")]
struct MacosInstall {
    /// The local mesh DNS server used by each suffix file.
    address: Ipv4Addr,
    /// The default and optional custom suffixes represented by files.
    suffixes: Vec<String>,
}

/// What `mesh status` reports about the host resolver integration.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct DnsState {
    /// `resolved`, `networkmanager`, `hosts`, `resolver-files`, `unprivileged`, `unavailable`
    /// or `off` (nothing attempted yet).
    pub mode: &'static str,
    /// One plain sentence a person can act on.
    pub detail: String,
    /// The suffixes routed to the mesh resolver.
    pub suffixes: Vec<String>,
    /// Whether the suffixes are also search domains.
    pub search: bool,
}

/// Name of the environment switch that also makes the mesh suffix a search domain.
///
/// Off by default: a search domain changes how every bare name on the host resolves, which a
/// routing-only suffix never does. Set it to `1` (or `true`, `yes`, `on`) to opt in.
const SEARCH_ENVIRONMENT: &str = "INFRATERNAL_MESH_DNS_SEARCH";

/// Reads the opt-in for a search domain from the environment.
fn search_domain_requested() -> bool {
    std::env::var(SEARCH_ENVIRONMENT).is_ok_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

impl DnsIntegration {
    /// Reports the host resolver state for `mesh status`.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn state(&self) -> DnsState {
        let search = search_domain_requested();
        let unavailable = |error: &String| DnsState {
            mode: "unavailable",
            detail: error.clone(),
            suffixes: Vec::new(),
            search,
        };
        #[cfg(target_os = "linux")]
        if let Some(install) = &self.linux {
            let (mode, detail) = match install.mode {
                LinuxMode::Resolved => (
                    "resolved",
                    format!(
                        "systemd-resolved routes {} to {}:{} on {} (link {})",
                        install.suffixes.join(", "),
                        install.address,
                        crate::dns::DNS_PORT,
                        install.interface,
                        install.ifindex.unwrap_or_default()
                    ),
                ),
                LinuxMode::NetworkManager => (
                    "networkmanager",
                    format!(
                        "NetworkManager's dnsmasq forwards {} to {}:{}",
                        install.suffixes.join(", "),
                        install.address,
                        crate::dns::DNS_PORT
                    ),
                ),
                LinuxMode::Hosts => (
                    "hosts",
                    format!(
                        "names listed in {HOSTS_PATH} (exact names only; no systemd-resolved or \
                         NetworkManager dnsmasq to route {})",
                        install.suffixes.join(", ")
                    ),
                ),
            };
            return DnsState {
                mode,
                detail,
                suffixes: install.suffixes.clone(),
                search: install.search,
            };
        }
        #[cfg(target_os = "macos")]
        if let Some(install) = &self.macos {
            return DnsState {
                mode: "resolver-files",
                detail: format!(
                    "/etc/resolver files send {} to {}:{}",
                    install.suffixes.join(", "),
                    install.address,
                    crate::dns::DNS_PORT
                ),
                suffixes: install.suffixes.clone(),
                search,
            };
        }
        if let Some(error) = &self.last_error {
            return unavailable(error);
        }
        if self.unprivileged {
            return DnsState {
                mode: "unprivileged",
                detail: "this process is not root, so it serves mesh names to peers but leaves \
                         the host resolver alone"
                    .to_owned(),
                suffixes: Vec::new(),
                search,
            };
        }
        DnsState {
            mode: "off",
            detail: "mesh DNS is not installed in the host resolver".to_owned(),
            suffixes: Vec::new(),
            search,
        }
    }

    /// Applies the current accepted DNS snapshot to this host's resolver.
    ///
    /// A userspace process without root authority keeps the DNS listener for
    /// mesh peers and leaves system resolver files untouched.
    /// # Errors
    /// Returns resolver discovery or setup failures, malformed DNS data, or failed owned-file updates.
    pub(crate) fn configure(
        &mut self,
        interface: &str,
        records: &Records,
        effective_uid: u32,
    ) -> io::Result<()> {
        let result = self.configure_inner(interface, records, effective_uid);
        self.last_error = result.as_ref().err().map(ToString::to_string);
        result
    }

    /// Does the work of [`Self::configure`]; the wrapper keeps the status error current.
    fn configure_inner(
        &mut self,
        interface: &str,
        records: &Records,
        effective_uid: u32,
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if effective_uid != 0 {
            self.unprivileged = true;
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        if !macos_resolver_write_allowed(effective_uid) {
            self.unprivileged = true;
            return Ok(());
        }
        self.unprivileged = false;
        #[cfg(target_os = "macos")]
        let _ = interface;
        #[cfg(target_os = "macos")]
        let address = records.local_address();
        #[cfg(target_os = "macos")]
        let suffixes = records.suffixes();
        #[cfg(target_os = "linux")]
        {
            self.configure_linux(interface, records)
        }
        #[cfg(target_os = "macos")]
        {
            let _ = interface;
            self.configure_macos(address, suffixes)
        }
    }

    /// Removes the routes and files owned by this integration.
    /// # Errors
    /// Reports failed removal of a per-link route or managed resolver file.
    pub(crate) fn remove(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            if let Some(install) = self.linux.as_mut() {
                install.valid = false;
                remove_linux_install(install)?;
                self.linux = None;
            }
            // The stale cleanups edit host-wide files that a node in another network namespace
            // (a test fixture, a container sharing /etc) never wrote, so they run only from the
            // host's own namespace (#584).
            if in_host_network_namespace().is_ok() {
                clear_stale_networkmanager_dns()?;
                clear_stale_hosts_block()?;
            }
        }
        #[cfg(target_os = "macos")]
        if current_process_is_root() {
            let had_install = self.macos.is_some();
            remove_macos_files(had_install)?;
            self.macos = None;
        }
        Ok(())
    }

    /// Updates the Linux host resolver for the accepted mesh suffixes.
    /// `NetworkManager` uses its DNS plugin and never reapplies the mesh interface.
    /// Only a successful install is retained, so the next snapshot retries after a failed attempt.
    #[cfg(target_os = "linux")]
    fn configure_linux(&mut self, interface: &str, records: &Records) -> io::Result<()> {
        // Every Linux mechanism below changes host-wide state (resolved's links, NetworkManager's
        // drop-ins, /etc/hosts). A node whose thread runs in another network namespace shares
        // none of that host's links, so it must leave the host resolver alone (#584).
        in_host_network_namespace()?;
        let address = records.local_address();
        let suffixes = records.suffixes();
        let search = search_domain_requested();
        // Names change with every snapshot, so the hosts block is rewritten whenever it differs.
        if let Some(current) = self.linux.as_mut()
            && current.mode == LinuxMode::Hosts
            && current.valid
        {
            let block = render_hosts_block(records);
            if block != current.hosts_block || current.suffixes != suffixes {
                current.valid = false;
                write_hosts_block(Path::new(HOSTS_PATH), &block, 0)?;
                current.hosts_block = block;
                current.suffixes = suffixes.to_vec();
                current.valid = true;
            }
            return Ok(());
        }
        if let Some(current) = self.linux.as_mut()
            && current.interface == interface
            && current.address == address
            && current.suffixes == suffixes
            && current.search == search
            && current.valid
            && current.mode != LinuxMode::Hosts
        {
            // Invalidate before any fallible inspection: an unsafe or missing file is not success.
            current.valid = false;
            current.valid = linux_install_is_intact(current)?;
            if current.valid {
                return Ok(());
            }
        }

        // A previous process may have left a marked dnsmasq drop-in without an in-memory install.
        // Reconcile it before selecting this process's resolver, including when the mode changed.
        if self.linux.is_none() {
            clear_stale_networkmanager_dns()?;
        }

        if let Some(current) = self.linux.as_mut() {
            // Retain the cleanup recipe on error, never its previous success shortcut.
            current.valid = false;
            remove_linux_install(current)?;
            self.linux = None;
        }

        let mut failures = Vec::new();
        let resolvectl = trusted_program("resolvectl", RESOLVECTL_PATHS);
        let resolved_available = match &resolvectl {
            Ok(program) => match program_succeeds(program, &["status"]) {
                Ok(true) => true,
                Ok(false) => {
                    failures.push(format!(
                        "resolvectl at {} did not report an active resolver; looked in: {}",
                        program.display(),
                        RESOLVECTL_PATHS.join(", ")
                    ));
                    false
                }
                Err(error) => {
                    failures.push(format!(
                        "could not run resolvectl at {}: {error}; looked in: {}",
                        program.display(),
                        RESOLVECTL_PATHS.join(", ")
                    ));
                    false
                }
            },
            Err(error) => {
                failures.push(error.to_string());
                false
            }
        };
        let nmcli = trusted_program("nmcli", NMCLI_PATHS);
        if let Err(error) = &nmcli {
            failures.push(error.to_string());
        }
        let networkmanager = trusted_program("NetworkManager", NETWORKMANAGER_PATHS);
        let nm_dnsmasq = match &networkmanager {
            Ok(program) => match networkmanager_dnsmasq_enabled(program) {
                Ok(true) => true,
                Ok(false) => {
                    failures.push(format!(
                        "NetworkManager at {} does not use its dnsmasq plugin; looked in: {}",
                        program.display(),
                        NETWORKMANAGER_PATHS.join(", ")
                    ));
                    false
                }
                Err(error) => {
                    failures.push(error.to_string());
                    false
                }
            },
            Err(error) => {
                failures.push(error.to_string());
                false
            }
        };
        let nm_support = NetworkManagerSupport {
            dnsmasq_enabled: nm_dnsmasq,
            nmcli_available: nmcli.is_ok(),
        };
        let mode = select_linux_mode(resolved_available, nm_support);

        if mode.is_none() {
            // Neither resolver can route one suffix (for example NetBird owns resolv.conf and
            // systemd-resolved is off). Name the mesh hosts in a marked /etc/hosts block rather
            // than touching another tool's resolver files.
            let block = render_hosts_block(records);
            return match write_hosts_block(Path::new(HOSTS_PATH), &block, 0) {
                Ok(()) => {
                    self.linux = Some(LinuxInstall {
                        valid: true,
                        interface: interface.to_owned(),
                        ifindex: None,
                        mode: LinuxMode::Hosts,
                        address,
                        suffixes: suffixes.to_vec(),
                        search,
                        hosts_block: block,
                    });
                    Ok(())
                }
                Err(error) => {
                    failures.push(format!(
                        "could not list mesh names in {HOSTS_PATH}: {error}"
                    ));
                    Err(resolver_setup_error(&failures))
                }
            };
        }
        // A previous process may have left a hosts block; the chosen resolver supersedes it.
        clear_stale_hosts_block()?;

        if mode == Some(LinuxMode::Resolved)
            && let Ok(resolvectl) = &resolvectl
        {
            // systemd-resolved is running, so it owns this host's DNS. When the mesh link cannot
            // be proven to be ours and visible to it, refuse outright: falling back to
            // NetworkManager or /etc/hosts would change the host's DNS from the wrong place.
            let ifindex = resolved_link(interface)?;
            let commands = resolved_route_commands(ifindex, address, suffixes, search);
            match run_commands(resolvectl, &commands) {
                Ok(()) => {
                    self.linux = Some(LinuxInstall {
                        valid: true,
                        interface: interface.to_owned(),
                        ifindex: Some(ifindex),
                        mode: LinuxMode::Resolved,
                        address,
                        suffixes: suffixes.to_vec(),
                        search,
                        hosts_block: String::new(),
                    });
                    return Ok(());
                }
                Err(error) => {
                    failures.push(format!(
                        "resolvectl at {} could not install mesh DNS: {error}; looked in: {}",
                        resolvectl.display(),
                        RESOLVECTL_PATHS.join(", ")
                    ));
                    if let Err(revert_error) = run_commands(
                        resolvectl,
                        &[vec!["revert".to_owned(), ifindex.to_string()]],
                    ) {
                        failures.push(format!(
                            "resolvectl at {} could not revert the partial mesh DNS update: {revert_error}",
                            resolvectl.display()
                        ));
                    }
                }
            }
        }

        let fallback_mode = select_linux_mode(false, nm_support);
        if matches!(mode, Some(LinuxMode::NetworkManager | LinuxMode::Resolved))
            && fallback_mode == Some(LinuxMode::NetworkManager)
            && let Ok(nmcli) = &nmcli
        {
            match install_networkmanager_dns(nmcli, address, suffixes) {
                Ok(()) => {
                    self.linux = Some(LinuxInstall {
                        valid: true,
                        interface: interface.to_owned(),
                        ifindex: None,
                        mode: LinuxMode::NetworkManager,
                        address,
                        suffixes: suffixes.to_vec(),
                        search,
                        hosts_block: String::new(),
                    });
                    return Ok(());
                }
                Err(error) => {
                    failures.push(format!(
                        "nmcli at {} could not install mesh DNS: {error}; looked in: {}",
                        nmcli.display(),
                        NMCLI_PATHS.join(", ")
                    ));
                    if let Err(cleanup_error) = clear_networkmanager_dns(nmcli) {
                        failures.push(format!(
                            "nmcli at {} could not clean up the failed mesh DNS update: {cleanup_error}",
                            nmcli.display()
                        ));
                    }
                }
            }
        }

        Err(resolver_setup_error(&failures))
    }

    /// Writes each suffix resolver file and removes stale files with our marker.
    #[cfg(target_os = "macos")]
    fn configure_macos(&mut self, address: Ipv4Addr, suffixes: &[String]) -> io::Result<()> {
        let desired = suffixes.to_vec();
        if self
            .macos
            .as_ref()
            .is_some_and(|current| current.address == address && current.suffixes == desired)
        {
            return Ok(());
        }
        write_macos_files(address, &desired)?;
        refresh_macos_resolver()?;
        self.macos = Some(MacosInstall {
            address,
            suffixes: desired,
        });
        Ok(())
    }
}

impl Drop for DnsIntegration {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

/// Builds `resolvectl` arguments that route only mesh names over the mesh link.
///
/// Suffixes become routing-only domains (`~internal`): queries under them go to the mesh
/// resolver and no bare name is ever completed with them. With `search` they are also plain
/// search domains, so `ssh compute01` finds `compute01.internal`.
///
/// The link is named by the index [`resolved_link`] proved, never by name: `resolvectl` would
/// look a name up in its own network namespace and then hand systemd-resolved a bare index,
/// which resolved applies to whichever of its links has that number (#584).
#[cfg(target_os = "linux")]
fn resolved_route_commands(
    ifindex: u32,
    address: Ipv4Addr,
    suffixes: &[String],
    search: bool,
) -> Vec<Vec<String>> {
    let link = ifindex.to_string();
    let mut domains = vec!["domain".to_owned(), link.clone()];
    for suffix in suffixes {
        domains.push(format!("~{suffix}"));
        if search {
            domains.push(suffix.clone());
        }
    }
    vec![
        vec!["default-route".to_owned(), link.clone(), "no".to_owned()],
        vec![
            "dns".to_owned(),
            link,
            format!("{address}:{}", crate::dns::DNS_PORT),
        ],
        domains,
    ]
}

/// Builds the `NetworkManager` command that reloads only the DNS plugin.
#[cfg(target_os = "linux")]
fn networkmanager_route_commands() -> Vec<Vec<String>> {
    networkmanager_dns_reload_commands()
}

/// Builds the `NetworkManager` command that applies a removed dnsmasq drop-in.
#[cfg(target_os = "linux")]
fn networkmanager_clear_commands() -> Vec<Vec<String>> {
    networkmanager_dns_reload_commands()
}

/// Reloads `NetworkManager`'s DNS plugin without reapplying any network device.
#[cfg(target_os = "linux")]
fn networkmanager_dns_reload_commands() -> Vec<Vec<String>> {
    vec![vec![
        "general".to_owned(),
        "reload".to_owned(),
        "dns-full".to_owned(),
    ]]
}

/// Renders `NetworkManager` dnsmasq routes without changing the host's search list.
#[cfg(target_os = "linux")]
fn render_networkmanager_dnsmasq_config(
    address: Ipv4Addr,
    suffixes: &[String],
) -> io::Result<String> {
    // Only suffix servers belong here; NetworkManager keeps its existing search list and upstreams.
    let mut contents = format!("{NETWORKMANAGER_MESH_DNS_MARKER}\n");
    for suffix in suffixes {
        crate::policy::model::validate_dns(suffix, false)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mesh DNS suffix"))?;
        writeln!(
            &mut contents,
            "server=/{suffix}/{address}#{}",
            crate::dns::DNS_PORT
        )
        .map_err(|_| io::Error::other("could not render mesh DNS forwarding rule"))?;
    }
    Ok(contents)
}

/// Writes and applies the one `NetworkManager` dnsmasq file owned by mesh DNS.
#[cfg(target_os = "linux")]
fn install_networkmanager_dns(
    nmcli: &Path,
    address: Ipv4Addr,
    suffixes: &[String],
) -> io::Result<()> {
    let contents = render_networkmanager_dnsmasq_config(address, suffixes)?;
    let directory = Path::new(NETWORKMANAGER_DNSMASQ_DIRECTORY);
    ensure_networkmanager_directory(directory, 0)?;
    let path = directory.join(NETWORKMANAGER_MESH_DNS_FILE);
    write_networkmanager_dns_file(&path, contents.as_bytes(), 0)?;
    run_commands(nmcli, &networkmanager_route_commands())
}

/// Creates the dnsmasq drop-in directory only beneath an already safe parent.
#[cfg(target_os = "linux")]
fn ensure_networkmanager_directory(path: &Path, owner_uid: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_networkmanager_directory(path, owner_uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
            validate_networkmanager_directory(parent, owner_uid)?;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o755).create(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
            validate_networkmanager_directory(path, owner_uid)
        }
        Err(error) => Err(error),
    }
}

/// Verifies a real directory is owned by the service account and cannot be changed by others.
#[cfg(target_os = "linux")]
fn validate_networkmanager_directory(path: &Path, owner_uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && metadata.uid() == owner_uid && metadata.mode() & 0o022 == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "NetworkManager dnsmasq directory is not a safe owned directory",
        ))
    }
}

/// Replaces the owned dnsmasq file atomically, refusing an unmarked file at that path.
#[cfg(target_os = "linux")]
fn write_networkmanager_dns_file(path: &Path, contents: &[u8], owner_uid: u32) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    validate_networkmanager_directory(parent, owner_uid)?;
    let already_managed = networkmanager_dns_file_is_managed(path, owner_uid)?;
    let mode = if already_managed {
        fs::symlink_metadata(path)?.mode() & 0o777
    } else {
        0o644
    };
    atomic_write(path, contents, mode, parent)
}

/// Removes only a regular, owned dnsmasq file carrying this module's marker.
#[cfg(target_os = "linux")]
fn remove_networkmanager_dns_file(path: &Path, owner_uid: u32) -> io::Result<bool> {
    if !networkmanager_dns_file_is_managed(path, owner_uid)? {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

/// Recognizes a mesh DNS file by its owner, safe permissions and first-line marker.
#[cfg(target_os = "linux")]
fn networkmanager_dns_file_is_managed(path: &Path, owner_uid: u32) -> io::Result<bool> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    match fs::symlink_metadata(parent) {
        Ok(_) => validate_networkmanager_directory(parent, owner_uid)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "NetworkManager dnsmasq file is not a safe owned regular file",
        ));
    }
    if fs::read_to_string(path)?.lines().next() == Some(NETWORKMANAGER_MESH_DNS_MARKER) {
        Ok(true)
    } else {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "NetworkManager dnsmasq file is not owned by the infraternal agent",
        ))
    }
}

/// Removes the owned `NetworkManager` file and reloads only its DNS plugin.
/// # Errors
/// Refuses an unsafe or unmarked file and reports a failed DNS-only reload.
#[cfg(target_os = "linux")]
fn clear_networkmanager_dns(nmcli: &Path) -> io::Result<()> {
    let path = Path::new(NETWORKMANAGER_DNSMASQ_DIRECTORY).join(NETWORKMANAGER_MESH_DNS_FILE);
    if networkmanager_dns_file_is_managed(&path, 0)? {
        // Leave an empty, marked file until NetworkManager confirms the DNS-only reload. If the
        // command fails or the process stops, the next cleanup can safely retry the reload.
        let empty = format!("{NETWORKMANAGER_MESH_DNS_MARKER}\n");
        write_networkmanager_dns_file(&path, empty.as_bytes(), 0)?;
        run_commands(nmcli, &networkmanager_clear_commands())?;
        let _ = remove_networkmanager_dns_file(&path, 0)?;
        Ok(())
    } else {
        run_commands(nmcli, &networkmanager_clear_commands())
    }
}

/// Remove a previous process's marked drop-in even when this process has no in-memory install.
/// # Errors
/// Refuses an unsafe or unmarked file, an unavailable trusted `nmcli`, or a failed DNS-only reload.
#[cfg(target_os = "linux")]
fn clear_stale_networkmanager_dns() -> io::Result<()> {
    let path = Path::new(NETWORKMANAGER_DNSMASQ_DIRECTORY).join(NETWORKMANAGER_MESH_DNS_FILE);
    if !networkmanager_dns_file_is_managed(&path, 0)? {
        return Ok(());
    }
    let nmcli = trusted_program("nmcli", NMCLI_PATHS)?;
    clear_networkmanager_dns(&nmcli)
}

/// Renders one macOS resolver file for a suffix.
///
/// `nameserver` is the mesh address in root mode. In user mode (J1157) the one-shot root helper writes
/// the deployment's resolver address (`fd<id>:ffff::53`, port 53), which the agent answers from
/// the packets it reads from its tunnel. The `search` line is only written when the owner opted in: it makes the suffix a
/// search domain for every bare name, while the file name alone already routes the suffix.
#[cfg(any(target_os = "macos", test))]
fn render_macos_resolver(
    nameserver: std::net::IpAddr,
    port: u16,
    suffix: &str,
    search: bool,
) -> String {
    let search_line = if search {
        format!("search {suffix}\n")
    } else {
        String::new()
    };
    format!("{MACOS_MARKER}\nnameserver {nameserver}\nport {port}\n{search_line}")
}

/// Reports whether a process may write system resolver files on macOS.
#[cfg(target_os = "macos")]
fn macos_resolver_write_allowed(effective_uid: u32) -> bool {
    effective_uid == 0
}

/// The system hosts file that the last-resort mode edits.
#[cfg(target_os = "linux")]
const HOSTS_PATH: &str = "/etc/hosts";
/// First line of the block this module owns inside the hosts file.
#[cfg(target_os = "linux")]
const HOSTS_BEGIN: &str =
    "# BEGIN infraternal mesh names (managed by the infraternal agent; do not edit)";
/// Last line of the block this module owns inside the hosts file.
#[cfg(target_os = "linux")]
const HOSTS_END: &str = "# END infraternal mesh names";
/// Fixed `restorecon` locations; the label step is best effort and only runs from these.
#[cfg(target_os = "linux")]
const RESTORECON_PATHS: &[&str] = &[
    "/usr/sbin/restorecon",
    "/usr/bin/restorecon",
    "/sbin/restorecon",
];

/// Renders the managed hosts block: one line per address family and name, with every suffix.
///
/// Empty when there are no names, in which case the block is removed instead of written.
#[cfg(target_os = "linux")]
fn render_hosts_block(records: &Records) -> String {
    let mut lines = String::new();
    for (label, ipv4, ipv6) in records.host_entries() {
        let names = records
            .suffixes()
            .iter()
            .map(|suffix| format!("{label}.{suffix}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(lines, "{ipv4}\t{names}");
        if let Some(ipv6) = ipv6 {
            let _ = writeln!(lines, "{ipv6}\t{names}");
        }
    }
    if lines.is_empty() {
        String::new()
    } else {
        format!("{HOSTS_BEGIN}\n{lines}{HOSTS_END}\n")
    }
}

/// Returns `existing` with the managed block replaced by `block` (or removed when empty).
///
/// Everything outside the markers is preserved byte for byte. A begin marker without its end
/// (or a second block) means someone edited the file by hand, so the function refuses rather
/// than guess which lines are ours.
/// # Errors
/// `InvalidData` when the markers are unbalanced or repeated.
#[cfg(target_os = "linux")]
fn splice_hosts_block(existing: &str, block: &str) -> io::Result<String> {
    let mut kept = String::with_capacity(existing.len() + block.len());
    let mut inside = false;
    let mut blocks = 0;
    for line in existing.split_inclusive('\n') {
        let text = line.trim_end_matches('\n');
        if !inside && text == HOSTS_BEGIN {
            inside = true;
            blocks += 1;
        } else if inside && text == HOSTS_END {
            inside = false;
        } else if !inside {
            kept.push_str(line);
        }
    }
    if inside || blocks > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the infraternal block in the hosts file is damaged; remove its marker lines by hand",
        ));
    }
    if !block.is_empty() {
        if !kept.is_empty() && !kept.ends_with('\n') {
            kept.push('\n');
        }
        kept.push_str(block);
    }
    Ok(kept)
}

/// Installs (or, for an empty `block`, removes) the managed block in a hosts file.
///
/// Refuses a symlink, a non-regular file or one another user can write; replaces the file
/// atomically with the same mode, so a reader never sees half a file. Writes nothing when the
/// result equals the current contents.
/// # Errors
/// Unsafe file, damaged markers, or a failed write (for example a bind-mounted hosts file).
#[cfg(target_os = "linux")]
fn write_hosts_block(path: &Path, block: &str, owner_uid: u32) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound && block.is_empty() => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the hosts file is not a safe, owned regular file",
        ));
    }
    let existing = fs::read_to_string(path)?;
    let updated = splice_hosts_block(&existing, block)?;
    if updated == existing {
        return Ok(());
    }
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    atomic_write(path, updated.as_bytes(), metadata.mode() & 0o777, parent)?;
    // A new inode starts with the directory's default SELinux type; put the file's own back.
    if let Ok(restorecon) = trusted_program("restorecon", RESTORECON_PATHS) {
        let _ = run_commands(&restorecon, &[vec![path.display().to_string()]]);
    }
    Ok(())
}

/// Removes a managed hosts block left by an earlier process or a different resolver mode.
/// # Errors
/// Reports an unsafe hosts file or damaged markers; an absent block is success.
#[cfg(target_os = "linux")]
fn clear_stale_hosts_block() -> io::Result<()> {
    let path = Path::new(HOSTS_PATH);
    match fs::read_to_string(path) {
        Ok(contents) if contents.contains(HOSTS_BEGIN) => write_hosts_block(path, "", 0),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The command name (`/proc/<pid>/comm`, cut to 15 bytes by the kernel) of systemd-resolved.
#[cfg(target_os = "linux")]
const RESOLVED_COMM: &str = "systemd-resolve";

/// Identifies one network namespace by the device and inode of its `nsfs` file.
#[cfg(target_os = "linux")]
fn network_namespace_of(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// The network namespace of the calling thread.
///
/// `thread-self`, not `self`: a node may run on a thread that entered its own namespace while the
/// process's main thread stays elsewhere, and every resolver command is spawned from this thread.
#[cfg(target_os = "linux")]
fn own_network_namespace() -> io::Result<(u64, u64)> {
    network_namespace_of(Path::new("/proc/thread-self/ns/net"))
}

/// Explains a refused host-resolver change in words a person can act on.
#[cfg(target_os = "linux")]
fn foreign_namespace_error(detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("mesh DNS left the host resolver alone: {detail}"),
    )
}

/// Succeeds only when the calling thread shares the network namespace of PID 1, the host's.
///
/// Host resolver state (systemd-resolved's links, `NetworkManager`'s drop-ins, `/etc/hosts`)
/// belongs to the init namespace. A node inside `unshare -n` or `ip netns exec` must not edit it:
/// its links are not the host's links (#584). An unreadable PID 1 namespace counts as foreign.
/// # Errors
/// Reports a foreign or unreadable namespace.
#[cfg(target_os = "linux")]
fn in_host_network_namespace() -> io::Result<()> {
    let own = own_network_namespace().map_err(|error| {
        foreign_namespace_error(&format!(
            "cannot read this thread's network namespace: {error}"
        ))
    })?;
    match network_namespace_of(Path::new("/proc/1/ns/net")) {
        Ok(host) if host == own => Ok(()),
        Ok(_) => Err(foreign_namespace_error(
            "this node runs in a network namespace other than the host's",
        )),
        Err(error) => Err(foreign_namespace_error(&format!(
            "cannot read the host's network namespace: {error}"
        ))),
    }
}

/// Succeeds when a visible systemd-resolved process shares the calling thread's network namespace.
///
/// `resolvectl` reaches resolved over the system D-Bus, which a mount namespace may still expose
/// from another network namespace. resolved then reads every link index we send as one of its
/// own links. Only a resolved that sees our namespace may be told about our link.
/// # Errors
/// Reports when no resolved process is visible, or none shares this namespace.
#[cfg(target_os = "linux")]
fn resolved_shares_network_namespace() -> io::Result<()> {
    let own = own_network_namespace().map_err(|error| {
        foreign_namespace_error(&format!(
            "cannot read this thread's network namespace: {error}"
        ))
    })?;
    let mut seen = false;
    for entry in fs::read_dir("/proc")? {
        let name = entry?.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|pid| pid.bytes().all(|byte| byte.is_ascii_digit()))
        else {
            continue;
        };
        let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        if comm.trim_end() != RESOLVED_COMM {
            continue;
        }
        seen = true;
        if network_namespace_of(Path::new(&format!("/proc/{pid}/ns/net")))
            .is_ok_and(|namespace| namespace == own)
        {
            return Ok(());
        }
    }
    Err(foreign_namespace_error(if seen {
        "systemd-resolved runs in another network namespace, so it cannot see the mesh link"
    } else {
        "no systemd-resolved process is visible from here, so its network namespace is unknown"
    }))
}

/// Proves that `interface` is the mesh link this infraternal agent created, and returns its index.
///
/// The link must carry the mesh name, a kernel `WireGuard` or TUN kind and the infraternal agent's
/// marker, all read in one netlink reply in the calling thread's namespace.
/// # Errors
/// Refuses another name, a missing link, or a link with the mesh name that we did not create.
#[cfg(target_os = "linux")]
fn owned_mesh_link(interface: &str) -> io::Result<u32> {
    if interface != crate::wireguard::INTERFACE {
        return Err(foreign_namespace_error(&format!(
            "{interface} is not the mesh link {}",
            crate::wireguard::INTERFACE
        )));
    }
    match crate::wireguard::Device::active_link() {
        Ok(Some(link)) => Ok(link.ifindex),
        Ok(None) => Err(foreign_namespace_error(&format!(
            "the mesh link {interface} does not exist in this network namespace"
        ))),
        Err(error) => Err(foreign_namespace_error(&format!(
            "{interface} is not a mesh link this infraternal agent created ({error})"
        ))),
    }
}

/// Returns the index systemd-resolved may be told about for the mesh link, after every proof.
///
/// The host namespace, resolved's namespace and the link's ownership are all checked, so the
/// index means the same link to resolved as it does to us (#584).
/// # Errors
/// Reports the first proof that failed; the caller then leaves resolved untouched.
#[cfg(target_os = "linux")]
fn resolved_link(interface: &str) -> io::Result<u32> {
    in_host_network_namespace()?;
    resolved_shares_network_namespace()?;
    owned_mesh_link(interface)
}

/// Chooses a split-DNS mechanism without ever replacing the host's default resolver.
#[cfg(target_os = "linux")]
fn select_linux_mode(
    resolved_available: bool,
    networkmanager: NetworkManagerSupport,
) -> Option<LinuxMode> {
    if resolved_available {
        Some(LinuxMode::Resolved)
    } else if networkmanager.usable() {
        Some(LinuxMode::NetworkManager)
    } else {
        None
    }
}

/// Explains why neither fixed, trusted Linux split-DNS mechanism could be installed.
#[cfg(target_os = "linux")]
fn resolver_setup_error(failures: &[String]) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "mesh DNS setup failed because no supported split-DNS resolver could be installed: {}. \
             Install systemd-resolved (resolvectl) or set NetworkManager's dns=dnsmasq, or make \
             /etc/hosts a regular root-owned file so mesh names can be listed there",
            failures.join("; ")
        ),
    )
}

/// Checks the durable forwarding file before reusing a successful Linux installation.
/// systemd-resolved has no forwarding file; its existing per-link cache behaviour is unchanged.
#[cfg(target_os = "linux")]
fn linux_install_is_intact(install: &LinuxInstall) -> io::Result<bool> {
    if install.mode == LinuxMode::Resolved {
        // A recreated mesh link has a new index that resolved knows nothing about yet. Only the
        // cheap link proof runs here; resolved's namespace was checked when it was installed.
        return Ok(owned_mesh_link(&install.interface).ok() == install.ifindex);
    }
    if install.mode == LinuxMode::Hosts {
        return Ok(
            fs::read_to_string(HOSTS_PATH)?.contains(HOSTS_BEGIN) != install.hosts_block.is_empty()
        );
    }
    let path = Path::new(NETWORKMANAGER_DNSMASQ_DIRECTORY).join(NETWORKMANAGER_MESH_DNS_FILE);
    if !networkmanager_dns_file_is_managed(&path, 0)? {
        return Ok(false);
    }
    Ok(fs::read_to_string(path)?
        == render_networkmanager_dnsmasq_config(install.address, &install.suffixes)?)
}

/// Removes the resolver mechanism recorded for one Linux node.
#[cfg(target_os = "linux")]
fn remove_linux_install(install: &LinuxInstall) -> io::Result<()> {
    match install.mode {
        LinuxMode::Resolved => {
            // Revert only the index we configured, and only while it still holds our link. A
            // vanished link needs nothing (resolved forgets a link's settings when it goes), and
            // any other link at that index is not ours to reset (#584).
            let Some(ifindex) = install.ifindex else {
                return Ok(());
            };
            if resolved_link(&install.interface).ok() != Some(ifindex) {
                return Ok(());
            }
            let resolvectl = trusted_program("resolvectl", RESOLVECTL_PATHS)?;
            run_commands(
                &resolvectl,
                &[vec!["revert".to_owned(), ifindex.to_string()]],
            )?;
        }
        LinuxMode::NetworkManager => {
            let nmcli = trusted_program("nmcli", NMCLI_PATHS)?;
            clear_networkmanager_dns(&nmcli)?;
        }
        LinuxMode::Hosts => write_hosts_block(Path::new(HOSTS_PATH), "", 0)?,
    }
    Ok(())
}

/// Detects whether `NetworkManager` already routes split DNS through dnsmasq.
/// # Errors
/// Reports failures to run the fixed daemon binary and includes its candidate paths.
#[cfg(target_os = "linux")]
fn networkmanager_dnsmasq_enabled(program: &Path) -> io::Result<bool> {
    let output = Command::new(program)
        .arg("--print-config")
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not inspect NetworkManager at {}; looked in: {}: {error}",
                    program.display(),
                    NETWORKMANAGER_PATHS.join(", ")
                ),
            )
        })?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "NetworkManager at {} failed --print-config; looked in: {}",
            program.display(),
            NETWORKMANAGER_PATHS.join(", ")
        )));
    }
    Ok(config_uses_dnsmasq(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Reads `NetworkManager`'s main DNS plugin setting without accepting other plugins.
#[cfg(target_os = "linux")]
fn config_uses_dnsmasq(configuration: &str) -> bool {
    let mut in_main = false;
    let mut dns_plugin = None;
    for line in configuration.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_main = line.eq_ignore_ascii_case("[main]");
        } else if in_main
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("dns")
        {
            dns_plugin = Some(value.trim());
        }
    }
    dns_plugin == Some("dnsmasq")
}

/// Runs one fixed resolver probe and reports spawn errors to its caller.
/// # Errors
/// Returns an operating-system error if the trusted program cannot be run.
#[cfg(target_os = "linux")]
fn program_succeeds(program: &Path, arguments: &[&str]) -> io::Result<bool> {
    Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
}

/// Runs a fixed resolver command list with a clean environment and no shell.
#[cfg(target_os = "linux")]
fn run_commands(program: &Path, commands: &[Vec<String>]) -> io::Result<()> {
    for arguments in commands {
        let status = Command::new(program)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(io::Error::other("mesh resolver command failed"));
        }
    }
    Ok(())
}

/// Finds one fixed root-owned executable and refuses unsafe candidates instead of using `PATH`.
///
/// Both the candidate and canonical target directory chains must be protected. This accepts the
/// sticky, root-owned Nix store while refusing a writable profile or symlink parent.
/// # Errors
/// Names the missing or unsafe tool and every fixed candidate path that was checked.
#[cfg(target_os = "linux")]
fn trusted_program(tool: &str, candidates: &[&str]) -> io::Result<PathBuf> {
    let looked_in = if candidates.is_empty() {
        "(no fixed candidate paths)".to_owned()
    } else {
        candidates.join(", ")
    };
    let mut rejected = Vec::new();
    for candidate in candidates {
        let path = Path::new(candidate);
        let canonical = match fs::canonicalize(path) {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                rejected.push(format!("{candidate}: {error}"));
                continue;
            }
        };
        let directories_are_protected = path
            .parent()
            .into_iter()
            .flat_map(Path::ancestors)
            .chain(canonical.parent().into_iter().flat_map(Path::ancestors))
            .all(|directory| protected_program_directory(directory, 0));
        if regular_executable_of(&canonical, 0) && directories_are_protected {
            return Ok(canonical);
        }
        rejected.push(format!(
            "{candidate}: resolves to a replaceable or non-root-owned file"
        ));
    }
    let rejection_summary = if rejected.is_empty() {
        String::new()
    } else {
        format!("; rejected candidates: {}", rejected.join("; "))
    };
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{tool} was not found at any trusted candidate; looked in: {looked_in}{rejection_summary}"
        ),
    ))
}

/// Confirms the canonical tool is a root-owned executable that other users cannot replace.
#[cfg(target_os = "linux")]
fn regular_executable_of(path: &Path, owner_uid: u32) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        let mode = metadata.mode();
        metadata.is_file() && metadata.uid() == owner_uid && mode & 0o022 == 0 && mode & 0o111 != 0
    })
}

/// Confirms another local user cannot replace a path component such as `/nix/store`.
/// The namespace root is accepted by path identity because it cannot be replaced as a child path.
#[cfg(target_os = "linux")]
fn protected_program_directory(path: &Path, owner_uid: u32) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        let mode = metadata.mode();
        metadata.is_dir()
            // The mount namespace root cannot be replaced by changing a pathname. A user
            // namespace may show its host owner as an unmapped uid, so check its mode instead.
            && (metadata.uid() == owner_uid || path == Path::new("/"))
            && (mode & 0o022 == 0 || mode & 0o1000 != 0)
    })
}

/// Reports whether the current process can clean system resolver files.
#[cfg(target_os = "macos")]
fn current_process_is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

/// Writes the resolver files a user-mode agent asked the root helper for, then refreshes
/// the system resolver (#146).
///
/// The files name the deployment's mesh resolver address and port 53, which the agent answers
/// from the packets it reads from its utun (J1027 F2): no socket is bound, so no other account
/// can answer in its place. The helper has already checked that the address is routed into the
/// caller's utun and that every suffix is a reserved private-use name; the same marker and
/// ownership rules as root mode apply, so a file infraternal did not write is never replaced.
/// # Errors
/// Reports an unsafe resolver directory, a foreign file, or a failed write or refresh.
#[cfg(target_os = "macos")]
pub(crate) fn write_user_mode_resolver(
    resolver: std::net::Ipv6Addr,
    suffixes: &[String],
) -> io::Result<()> {
    write_macos_resolver_files(resolver.into(), crate::tunnel_dns::PORT, suffixes)?;
    refresh_macos_resolver()
}

/// Reports the Mac resolver state by reading the marked files in `/etc/resolver`.
///
/// The Mac integration lives on the worker thread, so `mesh status` reads the durable result
/// instead: it stays right across restarts and never writes anything.
#[cfg(target_os = "macos")]
pub(crate) fn macos_installed_state() -> DnsState {
    let mut suffixes = Vec::new();
    let mut target = String::new();
    let mut search = false;
    if let Ok(entries) = fs::read_dir(MACOS_RESOLVER_DIRECTORY) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_managed_file(&path).unwrap_or(false) {
                continue;
            }
            let (Some(name), Ok(contents)) = (
                path.file_name().and_then(|name| name.to_str()),
                fs::read_to_string(&path),
            ) else {
                continue;
            };
            suffixes.push(name.to_owned());
            let field = |key: &str| {
                contents
                    .lines()
                    .find_map(|line| line.strip_prefix(key))
                    .map(|value| value.trim().to_owned())
            };
            search |= contents.lines().any(|line| line.starts_with("search "));
            if target.is_empty() {
                let server = field("nameserver ").unwrap_or_default();
                let server = if server.contains(':') {
                    format!("[{server}]")
                } else {
                    server
                };
                target = format!(
                    "{server}:{}",
                    field("port ").unwrap_or_else(|| "53".to_owned())
                );
            }
        }
    }
    suffixes.sort();
    if suffixes.is_empty() {
        return DnsState {
            mode: "off",
            detail: "no mesh resolver files in /etc/resolver (a node that is not root serves \
                     mesh names to peers only)"
                .to_owned(),
            suffixes,
            search,
        };
    }
    DnsState {
        mode: "resolver-files",
        detail: format!(
            "/etc/resolver files send {} to {target}",
            suffixes.join(", ")
        ),
        suffixes,
        search,
    }
}

/// Writes one resolver file per suffix, naming the mesh address and [`crate::dns::DNS_PORT`],
/// and removes stale files carrying our marker.
#[cfg(target_os = "macos")]
fn write_macos_files(address: Ipv4Addr, suffixes: &[String]) -> io::Result<()> {
    write_macos_resolver_files(address.into(), crate::dns::DNS_PORT, suffixes)
}

/// Writes one resolver file per suffix for `address`:`port` and removes stale files carrying
/// our marker.
#[cfg(target_os = "macos")]
fn write_macos_resolver_files(
    address: std::net::IpAddr,
    port: u16,
    suffixes: &[String],
) -> io::Result<()> {
    ensure_macos_resolver_directory()?;
    let desired = suffixes.iter().cloned().collect::<BTreeSet<_>>();
    for suffix in &desired {
        validate_suffix(suffix)?;
        let path = Path::new(MACOS_RESOLVER_DIRECTORY).join(suffix);
        validate_managed_file_target(&path)?;
    }
    for suffix in &desired {
        let path = Path::new(MACOS_RESOLVER_DIRECTORY).join(suffix);
        let contents = render_macos_resolver(address, port, suffix, search_domain_requested());
        write_managed_file(&path, contents.as_bytes())?;
    }
    remove_stale_macos_files(&desired)
}

/// Creates or verifies the root-owned directory used for Mac suffix resolvers.
#[cfg(target_os = "macos")]
fn ensure_macos_resolver_directory() -> io::Result<()> {
    let directory = Path::new(MACOS_RESOLVER_DIRECTORY);
    match fs::symlink_metadata(directory) {
        Ok(metadata)
            if metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "macOS resolver directory is not root-owned",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = directory.parent().ok_or(io::ErrorKind::InvalidInput)?;
            let metadata = fs::metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            fs::create_dir(directory)?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Refuses to replace an unowned file at the suffix's resolver path.
#[cfg(target_os = "macos")]
fn validate_managed_file_target(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.uid() == 0 => {
            let contents = fs::read_to_string(path)?;
            if contents.lines().next() == Some(MACOS_MARKER) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "macOS resolver file is not owned by infraternal",
                ))
            }
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "macOS resolver target is not a root-owned regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Atomically writes one file after proving it is absent or already ours.
#[cfg(target_os = "macos")]
fn write_managed_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    validate_managed_file_target(path)?;
    let mode = fs::symlink_metadata(path).map_or(0o644, |metadata| metadata.mode() & 0o777);
    let staging_directory = macos_staging_directory(path)?;
    atomic_write(path, contents, mode, staging_directory)
}

/// Removes only stale resolver files that carry the infraternal marker.
#[cfg(target_os = "macos")]
fn remove_stale_macos_files(desired: &BTreeSet<String>) -> io::Result<()> {
    for entry in fs::read_dir(MACOS_RESOLVER_DIRECTORY)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if desired.contains(name) || !is_managed_file(&path)? {
            continue;
        }
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Removes every resolver file with our ownership marker during stop or uninstall.
#[cfg(target_os = "macos")]
fn remove_macos_files(force_refresh: bool) -> io::Result<()> {
    let directory = Path::new(MACOS_RESOLVER_DIRECTORY);
    match fs::symlink_metadata(directory) {
        Ok(metadata)
            if metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if force_refresh {
                refresh_macos_resolver()?;
            }
            return Ok(());
        }
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "macOS resolver directory is not root-owned",
            ));
        }
    }
    let removed = remove_managed_macos_files(directory, 0)?;
    if force_refresh || removed {
        refresh_macos_resolver()?;
    }
    Ok(())
}

/// List the resolver files this build would remove during macOS uninstall.
#[cfg(target_os = "macos")]
pub(crate) fn managed_macos_paths() -> io::Result<Vec<std::path::PathBuf>> {
    let directory = Path::new(MACOS_RESOLVER_DIRECTORY);
    match fs::symlink_metadata(directory) {
        Ok(metadata)
            if metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
        Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
    }
    let entries = fs::read_dir(directory)?;
    let mut managed = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if is_managed_file(&path)? {
            managed.push(path);
        }
    }
    managed.sort_unstable();
    Ok(managed)
}

/// Identifies a regular root-owned resolver file as ours by its first line.
#[cfg(target_os = "macos")]
fn is_managed_file(path: &Path) -> io::Result<bool> {
    is_managed_file_owned_by(path, 0)
}

/// Removes marked regular files owned by `owner_uid`, preserving other resolver entries.
#[cfg(target_os = "macos")]
fn remove_managed_macos_files(directory: &Path, owner_uid: u32) -> io::Result<bool> {
    let mut removed = false;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if is_managed_file_owned_by(&path, owner_uid)? {
            fs::remove_file(path)?;
            removed = true;
        }
    }
    Ok(removed)
}

/// Identifies a regular resolver file with our marker and the expected owner.
#[cfg(target_os = "macos")]
fn is_managed_file_owned_by(path: &Path, owner_uid: u32) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.uid() != owner_uid {
        return Ok(false);
    }
    Ok(fs::read_to_string(path)?.lines().next() == Some(MACOS_MARKER))
}

/// Rejects suffixes that cannot safely become resolver filenames.
#[cfg(target_os = "macos")]
fn validate_suffix(suffix: &str) -> io::Result<()> {
    crate::policy::model::validate_dns(suffix, false)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mesh DNS suffix"))
}

/// Refreshes macOS's cached resolver configuration after installing or removing routes.
///
/// Atomic file renames are not enough for a newly created `/etc/resolver` entry;
/// a resolver refresh makes the final suffix filename visible to system lookups.
#[cfg(target_os = "macos")]
fn refresh_macos_resolver() -> io::Result<()> {
    let status = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("macOS DNS resolver refresh failed"))
    }
}

/// Chooses a staging directory that macOS does not scan as a resolver directory.
///
/// Every file inside `/etc/resolver` is interpreted as a live route, including
/// hidden temporary files, so resolver updates stage in `/etc` before rename.
#[cfg(target_os = "macos")]
fn macos_staging_directory(path: &Path) -> io::Result<&Path> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    if parent == Path::new(MACOS_RESOLVER_DIRECTORY) {
        parent
            .parent()
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    } else {
        Ok(parent)
    }
}

/// Atomically replaces one owned resolver file while preserving its mode.
/// `staging_directory` stays outside active resolver directories when the OS scans every entry.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn atomic_write(
    path: &Path,
    contents: &[u8],
    mode: u32,
    staging_directory: &Path,
) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let name = path
        .file_name()
        .ok_or(io::ErrorKind::InvalidInput)?
        .to_string_lossy();
    let unique = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = staging_directory.join(format!(
        ".{name}.infraternal-{}-{unique}.tmp",
        std::process::id()
    ));
    // The `.tmp` suffix is ignored by dnsmasq; macOS also stages outside its active resolver directory.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        if staging_directory != parent {
            File::open(staging_directory)?.sync_all()?;
        }
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    //! Check Linux split-DNS forwarding and Mac per-suffix resolver-file contents.
    #![allow(clippy::expect_used)]

    use super::render_macos_resolver;
    #[cfg(target_os = "linux")]
    use super::{
        LinuxMode, NETWORKMANAGER_MESH_DNS_MARKER, NetworkManagerSupport,
        ensure_networkmanager_directory, networkmanager_clear_commands,
        networkmanager_route_commands, remove_networkmanager_dns_file,
        render_networkmanager_dnsmasq_config, resolved_route_commands, select_linux_mode,
        write_networkmanager_dns_file,
    };
    #[cfg(target_os = "macos")]
    use super::{MACOS_RESOLVER_DIRECTORY, macos_resolver_write_allowed, macos_staging_directory};
    use std::net::Ipv4Addr;
    #[cfg(target_os = "linux")]
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    /// Creates a private test directory for `NetworkManager`-owned file operations.
    #[cfg(target_os = "linux")]
    fn temporary_dns_config_directory() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "infraternal-dns-config-{}-{}",
            std::process::id(),
            super::NEXT_TEMP_FILE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("create DNS config test directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("secure DNS config test directory");
        directory
    }

    /// The systemd-resolved route stays on the mesh interface and includes both DNS aliases.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolved_route_is_per_link_and_covers_default_and_custom_suffixes() {
        let commands = resolved_route_commands(
            7,
            Ipv4Addr::new(10, 254, 0, 2),
            &["internal".to_owned(), "mesh.kayg.org".to_owned()],
            false,
        );

        // The link is the proven index, never the name `resolvectl` would look up (#584).
        assert_eq!(
            commands,
            vec![
                vec!["default-route", "7", "no"],
                vec!["dns", "7", "10.254.0.2:1053"],
                vec!["domain", "7", "~internal", "~mesh.kayg.org"],
            ]
            .into_iter()
            .map(|arguments| arguments.into_iter().map(str::to_owned).collect())
            .collect::<Vec<Vec<String>>>()
        );
    }

    /// `NetworkManager` reloads only its DNS plugin for mesh route changes.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_route_update_does_not_reapply_the_mesh_device() {
        let commands = networkmanager_route_commands();

        assert_eq!(
            commands,
            vec![vec!["general", "reload", "dns-full"]]
                .into_iter()
                .map(|arguments| arguments.into_iter().map(str::to_owned).collect())
                .collect::<Vec<Vec<String>>>()
        );
    }

    /// `NetworkManager` DNS cleanup also reloads only the DNS plugin.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_cleanup_does_not_reapply_the_mesh_device() {
        assert_eq!(
            networkmanager_clear_commands(),
            vec![vec!["general", "reload", "dns-full"]]
                .into_iter()
                .map(|arguments| arguments.into_iter().map(str::to_owned).collect())
                .collect::<Vec<Vec<String>>>()
        );
    }

    /// The dnsmasq fallback works without `NetworkManager` managing the mesh link or port 53.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_fallback_does_not_require_a_managed_link_or_system_port() {
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: true,
                    nmcli_available: true,
                },
            ),
            Some(LinuxMode::NetworkManager)
        );
    }

    /// Resolved remains the preferred route even when the standard DNS port is unavailable.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolved_route_does_not_need_the_system_dns_port() {
        assert_eq!(
            select_linux_mode(
                true,
                NetworkManagerSupport {
                    dnsmasq_enabled: true,
                    nmcli_available: true,
                },
            ),
            Some(LinuxMode::Resolved)
        );
    }

    /// `NetworkManager` needs dnsmasq and its trusted reload client for split forwarding.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_fallback_requires_dnsmasq_and_nmcli() {
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: true,
                    nmcli_available: true,
                },
            ),
            Some(LinuxMode::NetworkManager)
        );
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: true,
                    nmcli_available: false,
                },
            ),
            None
        );
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: false,
                    nmcli_available: true,
                },
            ),
            None
        );
    }

    /// Unsupported Linux hosts keep their resolver and receive no per-link mutation.
    #[cfg(target_os = "linux")]
    #[test]
    fn unavailable_split_dns_does_not_select_a_host_wide_fallback() {
        let mode = select_linux_mode(
            false,
            NetworkManagerSupport {
                dnsmasq_enabled: false,
                nmcli_available: false,
            },
        );

        assert_eq!(mode, None);
    }

    /// Each mesh suffix forwards to the node's high-port listener without replacing host search.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_dnsmasq_config_routes_suffixes_to_mesh_listener() {
        assert_eq!(
            render_networkmanager_dnsmasq_config(
                Ipv4Addr::new(10, 254, 0, 2),
                &["internal".to_owned(), "mesh.kayg.org".to_owned()],
            )
            .expect("valid mesh DNS suffixes"),
            format!(
                "{NETWORKMANAGER_MESH_DNS_MARKER}\nserver=/internal/10.254.0.2#1053\nserver=/mesh.kayg.org/10.254.0.2#1053\n"
            )
        );
    }

    /// Invalid suffix text cannot add extra dnsmasq directives to the root-owned file.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_dnsmasq_config_rejects_invalid_suffixes() {
        let error = render_networkmanager_dnsmasq_config(
            Ipv4Addr::new(10, 254, 0, 2),
            &["internal\nlisten-address=0.0.0.0".to_owned()],
        )
        .expect_err("invalid DNS text must not reach the root-owned plugin config");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    /// The `NetworkManager` file lifecycle updates and removes only its marked config.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_dns_file_lifecycle_preserves_unowned_files() {
        let owner_uid = nix::unistd::Uid::effective().as_raw();
        let base = temporary_dns_config_directory();
        let directory = base.join("dnsmasq.d");
        ensure_networkmanager_directory(&directory, owner_uid)
            .expect("create owned dnsmasq directory");
        let path = directory.join("infraternal-mesh.conf");
        let first = format!("{NETWORKMANAGER_MESH_DNS_MARKER}\nserver=/internal/10.254.0.2#1053\n");
        write_networkmanager_dns_file(&path, first.as_bytes(), owner_uid)
            .expect("write the owned dnsmasq file");
        let second =
            format!("{NETWORKMANAGER_MESH_DNS_MARKER}\nserver=/mesh.kayg.org/10.254.0.2#1053\n");
        write_networkmanager_dns_file(&path, second.as_bytes(), owner_uid)
            .expect("replace the owned dnsmasq file");
        assert_eq!(
            fs::read_to_string(&path).expect("read owned dnsmasq file"),
            second
        );
        assert!(remove_networkmanager_dns_file(&path, owner_uid).expect("remove owned file"));
        assert!(!path.exists());

        let unowned = b"# locally managed\nserver=/internal/192.0.2.1\n";
        fs::write(&path, unowned).expect("write an unowned test file");
        assert!(write_networkmanager_dns_file(&path, first.as_bytes(), owner_uid).is_err());
        assert!(remove_networkmanager_dns_file(&path, owner_uid).is_err());
        assert_eq!(
            fs::read(&path).expect("preserved unowned dnsmasq file"),
            unowned
        );
        fs::remove_dir_all(base).expect("remove DNS config test directory");
    }

    /// The macOS resolver file points only at the mesh listener on its unprivileged port, and
    /// is not a search domain unless the owner opted in.
    #[test]
    fn macos_resolver_file_uses_the_mesh_address_and_high_port() {
        assert_eq!(
            render_macos_resolver(
                std::net::IpAddr::from(Ipv4Addr::new(10, 254, 0, 2)),
                1053,
                "internal",
                false
            ),
            "# Managed by infraternal agent.\nnameserver 10.254.0.2\nport 1053\n"
        );
        assert_eq!(
            render_macos_resolver(
                std::net::IpAddr::from(Ipv4Addr::new(10, 254, 0, 2)),
                1053,
                "internal",
                true
            ),
            "# Managed by infraternal agent.\nnameserver 10.254.0.2\nport 1053\nsearch internal\n"
        );
        // User mode names the in-tunnel mesh resolver address on port 53 (#146, J1027 F2).
        assert_eq!(
            render_macos_resolver(
                "fd12:3456:789a:ffff::53".parse().expect("address"),
                53,
                "internal",
                false
            ),
            "# Managed by infraternal agent.\nnameserver fd12:3456:789a:ffff::53\nport 53\n"
        );
    }

    /// User mode (J1157): the helper writes the deployment's resolver address on port 53, which
    /// the agent answers from its tunnel, so no loopback listener exists.
    #[test]
    fn macos_user_mode_resolver_file_names_the_tunnel_resolver() {
        let resolver: std::net::Ipv6Addr = "fd12:3456:789a:ffff::53".parse().expect("address");
        assert_eq!(
            render_macos_resolver(resolver.into(), 53, "internal", false),
            "# Managed by infraternal agent.\nnameserver fd12:3456:789a:ffff::53\nport 53\n"
        );
    }

    /// Keeps staging files outside `/etc/resolver`, where macOS treats every file as a route.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_resolver_staging_stays_outside_the_active_resolver_directory() {
        let destination = std::path::Path::new(MACOS_RESOLVER_DIRECTORY).join("internal");

        let staging = macos_staging_directory(&destination).expect("resolver staging directory");

        assert_eq!(staging, std::path::Path::new("/etc"));
        assert!(!staging.starts_with(std::path::Path::new(MACOS_RESOLVER_DIRECTORY)));
    }

    /// A userspace Mac process leaves system resolver files alone unless it has root authority.
    #[cfg(target_os = "macos")]
    #[test]
    fn rootless_macos_node_does_not_write_system_resolver_files() {
        assert!(!macos_resolver_write_allowed(501));
        assert!(macos_resolver_write_allowed(0));
    }

    /// Resolver cleanup removes only marked files owned by this node.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_cleanup_removes_only_managed_resolver_files() {
        use std::{fs, os::unix::fs::MetadataExt};

        let directory = std::env::temp_dir().join(format!(
            "infraternal-mesh-dns-{}-{}",
            std::process::id(),
            super::NEXT_TEMP_FILE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("temporary resolver directory");
        let managed = directory.join("internal");
        let unrelated = directory.join("example.test");
        fs::write(
            &managed,
            "# Managed by infraternal agent.\nnameserver 10.254.0.2\nport 1053\n",
        )
        .expect("managed resolver file");
        fs::write(&unrelated, "nameserver 192.0.2.1\n").expect("unrelated resolver file");
        let owner = fs::metadata(&managed).expect("managed file metadata").uid();

        assert!(
            super::remove_managed_macos_files(&directory, owner).expect("remove managed resolver")
        );

        assert!(!managed.exists(), "the owned suffix file is removed");
        assert!(unrelated.exists(), "a file without our marker is preserved");
        fs::remove_dir_all(directory).expect("temporary resolver directory cleanup");
    }

    /// Opting in makes each suffix a search domain as well as a routing domain.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolved_search_domain_is_opt_in() {
        let commands = resolved_route_commands(
            7,
            Ipv4Addr::new(10, 254, 0, 2),
            &["internal".to_owned()],
            true,
        );
        assert_eq!(commands[2], ["domain", "7", "~internal", "internal"]);
    }

    /// The hosts block lists every suffix per name, writes IPv6 only when the node has one, and
    /// is empty (so removed) when there are no names.
    #[cfg(target_os = "linux")]
    #[test]
    fn hosts_block_lists_each_name_under_every_suffix() {
        let config: crate::dataplane::Config = serde_json::from_value(serde_json::json!({
            "node": 1, "version": 1, "name": "laptop", "dns_suffix": "mesh.kayg.org",
            "addresses": {"ipv4": "10.254.0.1", "ipv6": "fd01::1"},
            "default_policy": "Deny", "peers": {}
        }))
        .expect("public test configuration");
        let records = crate::dns::Records::from_config(&config).expect("records");
        let block = super::render_hosts_block(&records);
        assert!(block.starts_with(super::HOSTS_BEGIN), "{block}");
        assert!(
            block.ends_with(&format!("{}\n", super::HOSTS_END)),
            "{block}"
        );
        assert!(
            block.contains("10.254.0.1\tlaptop.mesh.kayg.org laptop.internal\n"),
            "{block}"
        );
        assert!(
            block.contains("fd01::1\tlaptop.mesh.kayg.org laptop.internal\n"),
            "{block}"
        );
    }

    /// Splicing keeps every foreign line, replaces only the marked block, removes it on an
    /// empty block, and refuses damaged markers.
    #[cfg(target_os = "linux")]
    #[test]
    fn hosts_splice_preserves_foreign_lines_and_refuses_damage() {
        use super::{HOSTS_BEGIN, HOSTS_END, splice_hosts_block};
        let block = format!("{HOSTS_BEGIN}\n10.254.0.1\tweb.internal\n{HOSTS_END}\n");
        let base = "127.0.0.1 localhost\n::1 localhost";
        let added = splice_hosts_block(base, &block).expect("append");
        assert_eq!(added, format!("{base}\n{block}"));
        let newer = format!("{HOSTS_BEGIN}\n10.254.0.9\tdb.internal\n{HOSTS_END}\n");
        let replaced = splice_hosts_block(&added, &newer).expect("replace");
        assert_eq!(replaced, format!("{base}\n{newer}"));
        let cleared = splice_hosts_block(&replaced, "").expect("remove");
        assert_eq!(cleared, format!("{base}\n"));
        assert!(splice_hosts_block(&format!("{HOSTS_BEGIN}\nx\n"), "").is_err());
        assert!(splice_hosts_block(&format!("{added}{block}"), "").is_err());
    }

    /// The hosts file is rewritten in place only when it is a safe regular file, with its mode
    /// kept, and a second identical write changes nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn hosts_file_lifecycle_is_atomic_and_refuses_unsafe_files() {
        use super::write_hosts_block;
        let directory = temporary_dns_config_directory();
        let path = directory.join("hosts");
        let uid =
            std::os::unix::fs::MetadataExt::uid(&fs::metadata(&directory).expect("directory"));
        fs::write(&path, "127.0.0.1 localhost\n").expect("seed hosts");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
        let block = format!(
            "{}\n10.254.0.1\tweb.internal\n{}\n",
            super::HOSTS_BEGIN,
            super::HOSTS_END
        );
        write_hosts_block(&path, &block, uid).expect("install");
        write_hosts_block(&path, &block, uid).expect("idempotent");
        assert!(
            fs::read_to_string(&path)
                .expect("read")
                .contains("web.internal")
        );
        assert_eq!(
            fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
            0o644
        );
        write_hosts_block(&path, "", uid).expect("remove");
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "127.0.0.1 localhost\n"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("loosen");
        assert!(write_hosts_block(&path, &block, uid).is_err());
        let link = directory.join("link");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(write_hosts_block(&link, &block, uid).is_err());
        fs::remove_dir_all(directory).expect("cleanup");
    }

    /// Status names the mechanism, its suffixes, and the last failure a person can act on.
    #[test]
    fn state_reports_unprivileged_failed_and_idle_integrations() {
        let mut integration = super::DnsIntegration::default();
        assert_eq!(integration.state().mode, "off");
        integration.unprivileged = true;
        assert_eq!(integration.state().mode, "unprivileged");
        integration.last_error = Some("no resolver".to_owned());
        let state = integration.state();
        assert_eq!(state.mode, "unavailable");
        assert_eq!(state.detail, "no resolver");
    }
}

/// Checks that split-DNS route arguments follow the real CLI parser grammar.
#[cfg(all(test, target_os = "linux", feature = "mesh-dns"))]
#[path = "review_j354_integration.rs"]
mod review_j354_integration;

/// Regression probes for restart cleanup and resolver failures found by J519 (#483).
#[cfg(all(test, target_os = "linux", feature = "mesh-dns"))]
#[path = "review_j519_dns.rs"]
mod review_j519_dns;

/// Probes that mesh DNS reaches systemd-resolved only for its own link and namespace (#584, J1208).
#[cfg(all(test, target_os = "linux", feature = "mesh-dns"))]
#[path = "review_j1208_dns.rs"]
mod review_j1208_dns;
