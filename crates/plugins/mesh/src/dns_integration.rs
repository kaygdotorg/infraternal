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
use std::{fs, io, net::Ipv4Addr, os::unix::fs::MetadataExt, path::Path};
#[cfg(target_os = "linux")]
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

/// Identifies resolver files owned by the infraternal agent on macOS.
#[cfg(target_os = "macos")]
const MACOS_MARKER: &str = "# Managed by infraternal agent.";
/// The only directory used for per-suffix resolver files on macOS.
#[cfg(target_os = "macos")]
const MACOS_RESOLVER_DIRECTORY: &str = "/etc/resolver";
/// Fixed systemd-resolved binaries; root never looks them up through `PATH`.
#[cfg(target_os = "linux")]
const RESOLVECTL_PATHS: &[&str] = &["/usr/bin/resolvectl", "/bin/resolvectl"];
/// Fixed `NetworkManager` client binaries; root never looks them up through `PATH`.
#[cfg(target_os = "linux")]
const NMCLI_PATHS: &[&str] = &["/usr/bin/nmcli", "/bin/nmcli"];
/// Fixed `NetworkManager` daemon binaries used only to inspect its active DNS mode.
#[cfg(target_os = "linux")]
const NETWORKMANAGER_PATHS: &[&str] = &["/usr/sbin/NetworkManager", "/usr/bin/NetworkManager"];
/// Gives atomic resolver-file writes distinct temporary names within one process.
#[cfg(target_os = "macos")]
static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

/// Owns just the mesh suffix routes installed in the host resolver.
///
/// Linux prefers a per-link systemd-resolved route, then `NetworkManager`'s
/// dnsmasq split-DNS support. Unsupported hosts keep their resolver unchanged.
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
    /// `NetworkManager`'s dnsmasq plugin routes the suffix over one link.
    NetworkManager,
}

/// Describes the `NetworkManager` capabilities needed for mesh-only DNS routing.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct NetworkManagerSupport {
    /// Whether the daemon forwards DNS through its dnsmasq plugin.
    dnsmasq_enabled: bool,
    /// Whether the daemon currently manages the infraternal mesh link.
    manages_link: bool,
    /// Whether the node owns the standard DNS port on its mesh address.
    standard_listener: bool,
}

#[cfg(target_os = "linux")]
impl NetworkManagerSupport {
    /// Reports whether every `NetworkManager` requirement for per-link routing is present.
    const fn usable(self) -> bool {
        self.dnsmasq_enabled && self.manages_link && self.standard_listener
    }
}

/// The input needed to reverse one Linux host-resolver installation.
#[cfg(target_os = "linux")]
struct LinuxInstall {
    /// The mesh-owned interface whose resolver state was changed.
    interface: String,
    /// The split-DNS mechanism configured, or none if this host supports neither one.
    mode: Option<LinuxMode>,
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
    /// Returns errors from malformed resolver data or failed owned-file updates.
    pub(crate) fn configure(
        &mut self,
        interface: &str,
        records: &Records,
        effective_uid: u32,
        standard_listener: bool,
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
        let _ = (interface, standard_listener);
        #[cfg(target_os = "macos")]
        let address = records.local_address();
        #[cfg(target_os = "macos")]
        let suffixes = records.suffixes();
        #[cfg(target_os = "linux")]
        {
            self.configure_linux(interface, records, standard_listener)
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
        if let Some(install) = self.linux.as_ref() {
            remove_linux_install(install)?;
            self.linux = None;
        } else if current_process_is_root() {
            clear_stale_linux_install(crate::wireguard::INTERFACE);
        }
        #[cfg(target_os = "macos")]
        if current_process_is_root() {
            let had_install = self.macos.is_some();
            remove_macos_files(had_install)?;
            self.macos = None;
        }
        Ok(())
    }

    /// Updates only the mesh link's Linux resolver state.
    #[cfg(target_os = "linux")]
    fn configure_linux(
        &mut self,
        interface: &str,
        records: &Records,
        standard_listener: bool,
    ) -> io::Result<()> {
        let address = records.local_address();
        let suffixes = records.suffixes();
        if let Some(current) = self.linux.as_mut()
            && current.interface == interface
            && current.address == address
            && current.suffixes == suffixes
        {
            return Ok(());
        }

        if let Some(current) = self.linux.as_ref() {
            remove_linux_install(current)?;
            self.linux = None;
        } else {
            clear_stale_linux_install(interface);
        }

        let resolvectl = trusted_program(RESOLVECTL_PATHS)
            .filter(|program| program_succeeds(program, &["status"]));
        let nmcli = trusted_program(NMCLI_PATHS);
        let nm_dnsmasq = networkmanager_dnsmasq_enabled();
        let nm_manages_link = nmcli
            .as_deref()
            .is_some_and(|program| networkmanager_device_is_managed(program, interface));
        let nm_support = NetworkManagerSupport {
            dnsmasq_enabled: nm_dnsmasq,
            manages_link: nm_manages_link,
            standard_listener,
        };
        let mode = select_linux_mode(resolvectl.is_some(), nm_support);

        if mode == Some(LinuxMode::Resolved)
            && let Some(resolvectl) = resolvectl.as_ref()
        {
            let commands = resolved_route_commands(interface, address, suffixes);
            if run_commands(resolvectl, &commands).is_ok() {
                self.linux = Some(LinuxInstall {
                    interface: interface.to_owned(),
                    mode: Some(LinuxMode::Resolved),
                    address,
                    suffixes: suffixes.to_vec(),
                });
                return Ok(());
            }
            let _ = run_commands(
                resolvectl,
                &[vec!["revert".to_owned(), interface.to_owned()]],
            );
        }

        let fallback_mode = select_linux_mode(false, nm_support);
        if matches!(mode, Some(LinuxMode::NetworkManager | LinuxMode::Resolved))
            && fallback_mode == Some(LinuxMode::NetworkManager)
            && let Some(nmcli) = nmcli
        {
            let commands = networkmanager_route_commands(interface, address, suffixes);
            if run_commands(&nmcli, &commands).is_ok() {
                self.linux = Some(LinuxInstall {
                    interface: interface.to_owned(),
                    mode: Some(LinuxMode::NetworkManager),
                    address,
                    suffixes: suffixes.to_vec(),
                });
                return Ok(());
            }
            let _ = run_commands(&nmcli, &networkmanager_clear_commands(interface));
        }

        // A host without an available split-DNS mechanism keeps all existing DNS settings.
        self.linux = Some(LinuxInstall {
            interface: interface.to_owned(),
            mode: None,
            address,
            suffixes: suffixes.to_vec(),
        });
        Ok(())
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

/// Builds `nmcli` arguments with search and route-only domains on one mesh link.
#[cfg(target_os = "linux")]
fn networkmanager_route_commands(
    interface: &str,
    address: Ipv4Addr,
    suffixes: &[String],
) -> Vec<Vec<String>> {
    let mut arguments = vec![
        "device".to_owned(),
        "modify".to_owned(),
        interface.to_owned(),
        "ipv4.dns".to_owned(),
        address.to_string(),
        "ipv4.dns-search".to_owned(),
    ];
    for suffix in suffixes {
        arguments.push(suffix.clone());
        arguments.push(format!("~{suffix}"));
    }
    vec![arguments]
}

/// Builds the `nmcli` reset for only the mesh device's temporary DNS properties.
#[cfg(target_os = "linux")]
fn networkmanager_clear_commands(interface: &str) -> Vec<Vec<String>> {
    vec![vec![
        "device".to_owned(),
        "modify".to_owned(),
        interface.to_owned(),
        "ipv4.dns".to_owned(),
        String::new(),
        "ipv4.dns-search".to_owned(),
        String::new(),
    ]]
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

/// Removes the resolver mechanism recorded for one Linux node.
#[cfg(target_os = "linux")]
fn remove_linux_install(install: &LinuxInstall) -> io::Result<()> {
    match install.mode {
        Some(LinuxMode::Resolved) => {
            let resolvectl = trusted_program(RESOLVECTL_PATHS).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "resolvectl is unavailable for cleanup",
                )
            })?;
            run_commands(
                &resolvectl,
                &[vec!["revert".to_owned(), install.interface.clone()]],
            )?;
        }
        Some(LinuxMode::NetworkManager) => {
            let nmcli = trusted_program(NMCLI_PATHS).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "nmcli is unavailable for cleanup")
            })?;
            run_commands(&nmcli, &networkmanager_clear_commands(&install.interface))?;
        }
        None => {}
    }
    Ok(())
}

/// Best-effort removal of stale settings from the mesh link before resolver selection.
#[cfg(target_os = "linux")]
fn clear_stale_linux_install(interface: &str) {
    if let Some(resolvectl) = trusted_program(RESOLVECTL_PATHS) {
        let _ = run_commands(
            &resolvectl,
            &[vec!["revert".to_owned(), interface.to_owned()]],
        );
    }
    if let Some(nmcli) = trusted_program(NMCLI_PATHS) {
        let _ = run_commands(&nmcli, &networkmanager_clear_commands(interface));
    }
}

/// Detects whether `NetworkManager` already routes split DNS through dnsmasq.
#[cfg(target_os = "linux")]
fn networkmanager_dnsmasq_enabled() -> bool {
    let Some(program) = trusted_program(NETWORKMANAGER_PATHS) else {
        return false;
    };
    let Ok(output) = Command::new(program)
        .arg("--print-config")
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    output.status.success() && config_uses_dnsmasq(&String::from_utf8_lossy(&output.stdout))
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

/// Reports whether `NetworkManager` currently manages the mesh interface.
#[cfg(target_os = "linux")]
fn networkmanager_device_is_managed(nmcli: &Path, interface: &str) -> bool {
    let Ok(output) = Command::new(nmcli)
        .args(["-g", "GENERAL.STATE", "device", "show", interface])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    let state = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    output.status.success() && state.contains("connected") && !state.contains("unmanaged")
}

/// Runs one fixed system resolver probe and reports its exit status.
#[cfg(target_os = "linux")]
fn program_succeeds(program: &Path, arguments: &[&str]) -> bool {
    Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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

/// Returns a fixed system binary only when its installed file is root-owned and not writable by others.
#[cfg(target_os = "linux")]
fn trusted_program(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().find_map(|candidate| {
        let path = Path::new(candidate);
        let metadata = fs::metadata(path).ok()?;
        (metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
            .then(|| path.to_path_buf())
    })
}

/// Reports whether the current process can clean system resolver files.
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
    atomic_write(path, contents, mode)
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

/// Atomically replaces one root-owned resolver file while preserving its mode.
/// Its temporary file stays outside `/etc/resolver`, where macOS treats every file as a route.
#[cfg(target_os = "macos")]
fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let staging_directory = macos_staging_directory(path)?;
    let name = path
        .file_name()
        .ok_or(io::ErrorKind::InvalidInput)?
        .to_string_lossy();
    let unique = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = staging_directory.join(format!(
        ".{name}.infraternal-{}-{unique}.tmp",
        std::process::id()
    ));
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
    //! Check Linux split-route selection and Mac per-suffix resolver-file contents.
    #![allow(clippy::expect_used)]

    #[cfg(target_os = "linux")]
    use super::{
        LinuxMode, NetworkManagerSupport, networkmanager_clear_commands,
        networkmanager_route_commands, resolved_route_commands, select_linux_mode,
    };
    #[cfg(target_os = "macos")]
    use super::{
        MACOS_RESOLVER_DIRECTORY, macos_resolver_write_allowed, macos_staging_directory,
        render_macos_resolver,
    };
    use std::net::Ipv4Addr;

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

    /// `NetworkManager` receives search and route-only domains on the mesh link alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_route_is_per_link_and_keeps_bare_names_searchable() {
        let commands = networkmanager_route_commands(
            "infraternal0",
            Ipv4Addr::new(10, 254, 0, 2),
            &["internal".to_owned(), "mesh.kayg.org".to_owned()],
        );

        assert_eq!(
            commands,
            vec![vec![
                "device",
                "modify",
                "infraternal0",
                "ipv4.dns",
                "10.254.0.2",
                "ipv4.dns-search",
                "internal",
                "~internal",
                "mesh.kayg.org",
                "~mesh.kayg.org",
            ]]
            .into_iter()
            .map(|arguments| arguments.into_iter().map(str::to_owned).collect())
            .collect::<Vec<Vec<String>>>()
        );
    }

    /// Clearing `NetworkManager` DNS touches only the mesh interface's DNS properties.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_cleanup_is_scoped_to_the_mesh_link() {
        assert_eq!(
            networkmanager_clear_commands("infraternal0"),
            vec![vec![
                "device".to_owned(),
                "modify".to_owned(),
                "infraternal0".to_owned(),
                "ipv4.dns".to_owned(),
                String::new(),
                "ipv4.dns-search".to_owned(),
                String::new(),
            ]]
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
                    manages_link: true,
                    standard_listener: false,
                },
            ),
            Some(LinuxMode::Resolved)
        );
    }

    /// `NetworkManager` is used only with dnsmasq, a managed mesh link and port 53 bound.
    #[cfg(target_os = "linux")]
    #[test]
    fn networkmanager_fallback_requires_a_split_dns_link_and_standard_listener() {
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: true,
                    manages_link: true,
                    standard_listener: true,
                },
            ),
            Some(LinuxMode::NetworkManager)
        );
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: true,
                    manages_link: true,
                    standard_listener: false,
                },
            ),
            None
        );
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: true,
                    manages_link: false,
                    standard_listener: true,
                },
            ),
            None
        );
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: false,
                    manages_link: true,
                    standard_listener: true,
                },
            ),
            None
        );
    }

    /// Unsupported Linux hosts keep their existing resolver instead of guessing globally.
    #[cfg(target_os = "linux")]
    #[test]
    fn unavailable_split_dns_does_not_select_a_host_wide_fallback() {
        assert_eq!(
            select_linux_mode(
                false,
                NetworkManagerSupport {
                    dnsmasq_enabled: false,
                    manages_link: false,
                    standard_listener: false,
                },
            ),
            None
        );
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
