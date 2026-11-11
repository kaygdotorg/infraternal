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
#[cfg(target_os = "macos")]
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
    /// systemd-resolved has a per-link DNS server and search domains.
    Resolved,
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
    /// The mesh interface used by the per-link systemd-resolved route.
    interface: String,
    /// The split-DNS mechanism installed successfully for this node.
    mode: LinuxMode,
    /// The local mesh DNS server used by the route.
    address: Ipv4Addr,
    /// The default and optional custom suffixes installed for the node.
    suffixes: Vec<String>,
}

/// The input needed to update or remove this node's Mac resolver files.
#[cfg(target_os = "macos")]
struct MacosInstall {
    /// The local mesh DNS server used by each suffix file.
    address: Ipv4Addr,
    /// The default and optional custom suffixes represented by files.
    suffixes: Vec<String>,
}

impl DnsIntegration {
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
        #[cfg(target_os = "linux")]
        if effective_uid != 0 {
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        if !macos_resolver_write_allowed(effective_uid) {
            return Ok(());
        }
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
            if let Some(install) = self.linux.as_ref() {
                remove_linux_install(install)?;
                self.linux = None;
            }
            clear_stale_networkmanager_dns()?;
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
        let address = records.local_address();
        let suffixes = records.suffixes();
        if let Some(current) = self.linux.as_mut()
            && current.interface == interface
            && current.address == address
            && current.suffixes == suffixes
        {
            return Ok(());
        }

        // A previous process may have left a marked dnsmasq drop-in without an in-memory install.
        // Reconcile it before selecting this process's resolver, including when the mode changed.
        if self.linux.is_none() {
            clear_stale_networkmanager_dns()?;
        }

        if let Some(current) = self.linux.as_ref() {
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
            return Err(resolver_setup_error(&failures));
        }

        if mode == Some(LinuxMode::Resolved)
            && let Ok(resolvectl) = &resolvectl
        {
            let commands = resolved_route_commands(interface, address, suffixes);
            match run_commands(resolvectl, &commands) {
                Ok(()) => {
                    self.linux = Some(LinuxInstall {
                        interface: interface.to_owned(),
                        mode: LinuxMode::Resolved,
                        address,
                        suffixes: suffixes.to_vec(),
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
                        &[vec!["revert".to_owned(), interface.to_owned()]],
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
                        interface: interface.to_owned(),
                        mode: LinuxMode::NetworkManager,
                        address,
                        suffixes: suffixes.to_vec(),
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
#[cfg(target_os = "linux")]
fn resolved_route_commands(
    interface: &str,
    address: Ipv4Addr,
    suffixes: &[String],
) -> Vec<Vec<String>> {
    let mut domains = vec!["domain".to_owned(), interface.to_owned()];
    domains.extend(suffixes.iter().cloned());
    vec![
        vec![
            "default-route".to_owned(),
            interface.to_owned(),
            "no".to_owned(),
        ],
        vec![
            "dns".to_owned(),
            interface.to_owned(),
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

/// Renders one macOS resolver file for a suffix and the node's high DNS port.
#[cfg(target_os = "macos")]
fn render_macos_resolver(address: Ipv4Addr, port: u16, suffix: &str) -> String {
    format!("{MACOS_MARKER}\nnameserver {address}\nport {port}\nsearch {suffix}\n")
}

/// Reports whether a process may write system resolver files on macOS.
#[cfg(target_os = "macos")]
fn macos_resolver_write_allowed(effective_uid: u32) -> bool {
    effective_uid == 0
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
            "mesh DNS setup failed because no supported split-DNS resolver could be installed: {}",
            failures.join("; ")
        ),
    )
}

/// Removes the resolver mechanism recorded for one Linux node.
#[cfg(target_os = "linux")]
fn remove_linux_install(install: &LinuxInstall) -> io::Result<()> {
    match install.mode {
        LinuxMode::Resolved => {
            let resolvectl = trusted_program("resolvectl", RESOLVECTL_PATHS)?;
            run_commands(
                &resolvectl,
                &[vec!["revert".to_owned(), install.interface.clone()]],
            )?;
        }
        LinuxMode::NetworkManager => {
            let nmcli = trusted_program("nmcli", NMCLI_PATHS)?;
            clear_networkmanager_dns(&nmcli)?;
        }
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

/// Writes one resolver file per suffix and removes stale files carrying our marker.
#[cfg(target_os = "macos")]
fn write_macos_files(address: Ipv4Addr, suffixes: &[String]) -> io::Result<()> {
    ensure_macos_resolver_directory()?;
    let desired = suffixes.iter().cloned().collect::<BTreeSet<_>>();
    for suffix in &desired {
        validate_suffix(suffix)?;
        let path = Path::new(MACOS_RESOLVER_DIRECTORY).join(suffix);
        validate_managed_file_target(&path)?;
    }
    for suffix in &desired {
        let path = Path::new(MACOS_RESOLVER_DIRECTORY).join(suffix);
        let contents = render_macos_resolver(address, crate::dns::DNS_PORT, suffix);
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

    #[cfg(target_os = "linux")]
    use super::{
        LinuxMode, NETWORKMANAGER_MESH_DNS_MARKER, NetworkManagerSupport,
        ensure_networkmanager_directory, networkmanager_clear_commands,
        networkmanager_route_commands, remove_networkmanager_dns_file,
        render_networkmanager_dnsmasq_config, resolved_route_commands, select_linux_mode,
        write_networkmanager_dns_file,
    };
    #[cfg(target_os = "macos")]
    use super::{
        MACOS_RESOLVER_DIRECTORY, macos_resolver_write_allowed, macos_staging_directory,
        render_macos_resolver,
    };
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
            "infraternal0",
            Ipv4Addr::new(10, 254, 0, 2),
            &["internal".to_owned(), "mesh.kayg.org".to_owned()],
        );

        assert_eq!(
            commands,
            vec![
                vec!["default-route", "infraternal0", "no"],
                vec!["dns", "infraternal0", "10.254.0.2:1053"],
                vec!["domain", "infraternal0", "internal", "mesh.kayg.org"],
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

    /// The macOS resolver file points only at the mesh listener on its unprivileged port.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_resolver_file_uses_the_mesh_address_and_high_port() {
        assert_eq!(
            render_macos_resolver(Ipv4Addr::new(10, 254, 0, 2), 1053, "internal"),
            "# Managed by infraternal agent.\nnameserver 10.254.0.2\nport 1053\nsearch internal\n"
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
}

/// Checks that split-DNS route arguments follow the real CLI parser grammar.
#[cfg(all(test, target_os = "linux", feature = "mesh-dns"))]
#[path = "review_j354_integration.rs"]
mod review_j354_integration;

/// Regression probes for restart cleanup and resolver failures found by J519 (#483).
#[cfg(all(test, target_os = "linux", feature = "mesh-dns"))]
#[path = "review_j519_dns.rs"]
mod review_j519_dns;
