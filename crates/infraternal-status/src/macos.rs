//! Finds installed launchd jobs and checks the dynamically assigned mesh tunnel.

use crate::{Activity, Kind, Scope, Unit, option};
use std::{fs, path::Path};

/// Read the two installer jobs independently. Older labels remain readable until `up` migrates them.
pub(super) fn units(
    system: &Path,
    user: Option<&Path>,
    arguments: impl Fn(&Path) -> Option<Vec<String>>,
) -> Vec<Unit> {
    [
        (
            Scope::System,
            Some(system),
            ["kayg.infraternal.mesh", "org.infraternal.mesh"],
        ),
        (
            Scope::User,
            user,
            ["kayg.infraternal.agent", "org.infraternal.agent"],
        ),
    ]
    .into_iter()
    .filter_map(|(scope, directory, labels)| {
        let directory = directory?;
        labels.into_iter().find_map(|label| {
            let plist = directory.join(format!("{label}.plist"));
            if !fs::symlink_metadata(&plist).ok()?.is_file() {
                return None;
            }
            let words = arguments(&plist)?;
            if !Path::new(words.first()?).is_absolute() || words.get(1)?.as_str() != "agent" {
                return None;
            }
            Some(Unit {
                scope,
                name: label.to_owned(),
                kind: Kind::Agent,
                data: option(&words, "--data").filter(|path| path.is_absolute()),
                state: option(&words, "--state").filter(|path| path.is_absolute()),
                launchd: true,
                masked: false,
                query_error: None,
            })
        })
    })
    .collect()
}

/// Locate the same plists that `up` writes and ask the system parser for their argument arrays.
#[cfg(target_os = "macos")]
pub(super) fn local_units(roots: &crate::Roots) -> Vec<Unit> {
    let Some(system) = roots.system_units.first() else {
        return Vec::new();
    };
    units(system, roots.user_units.as_deref(), |plist| {
        let mut command = std::process::Command::new("/usr/bin/plutil");
        command
            .args(["-extract", "ProgramArguments", "json", "-o", "-", "--"])
            .arg(plist)
            .env_clear();
        let output = crate::manager_output(&mut command).ok()?;
        if !output.status.success() {
            return None;
        }
        serde_json::from_slice(&output.stdout).ok()
    })
}

/// launchd uses a GUI bootstrap domain for a per-user install and the system domain for root mode.
pub(super) fn target(unit: &Unit) -> String {
    match unit.scope {
        Scope::System => format!("system/{}", unit.name),
        Scope::User => format!("gui/{}/{}", nix::unistd::Uid::effective(), unit.name),
    }
}

/// Query the actual installed launchd job without letting a slow manager stall status.
#[cfg(target_os = "macos")]
pub(super) fn activity(unit: &Unit) -> Result<Activity, &'static str> {
    let mut command = std::process::Command::new("/bin/launchctl");
    command
        .arg("print")
        .arg(target(unit))
        .env_clear()
        .env("LC_ALL", "C");
    let output = crate::manager_output(&mut command)?;
    observed(output.status.success(), &output.stdout, &output.stderr)
}

/// Classify launchd's reply. An unreachable GUI domain does not prove a service is stopped.
pub(super) fn observed(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Activity, &'static str> {
    if success {
        match String::from_utf8_lossy(stdout)
            .lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix("state = "))
        {
            Some("running") => Ok(Activity::Active),
            Some("not running" | "waiting" | "exited" | "spawn scheduled") => {
                Ok(Activity::Inactive)
            }
            _ => Err("service manager did not provide a readable runtime state"),
        }
    } else {
        let stderr = String::from_utf8_lossy(stderr).to_ascii_lowercase();
        if stderr.contains("could not find service") || stderr.contains("service not found") {
            Ok(Activity::Inactive)
        } else {
            Err("service manager query was refused")
        }
    }
}

/// The mesh identity sufficient to distinguish this node's utun from other tunnels.
#[derive(serde::Deserialize)]
struct Snapshot {
    /// The saved utun name, which the kernel can reuse after the service stops.
    interface: Option<String>,
    /// Accepted server configuration with the addresses assigned to this node.
    config: Option<Config>,
}

/// The local address pair from the accepted mesh configuration.
#[derive(serde::Deserialize)]
struct Config {
    /// Addresses installed on the node's tunnel.
    addresses: Addresses,
}

/// The node's addresses inside the mesh.
#[derive(serde::Deserialize)]
struct Addresses {
    /// Assigned IPv4 address.
    ipv4: std::net::Ipv4Addr,
    /// Assigned IPv6 address.
    ipv6: std::net::Ipv6Addr,
}

/// Check the snapshot's exact interface and mesh addresses without checking other VPNs.
pub(super) fn snapshot_link(
    bytes: &[u8],
    has_address: impl Fn(&str, std::net::IpAddr) -> bool,
) -> bool {
    let Ok(Snapshot {
        interface: Some(interface),
        config: Some(Config { addresses }),
    }) = serde_json::from_slice(bytes)
    else {
        return false;
    };
    interface
        .strip_prefix("utun")
        .is_some_and(|index| !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()))
        && (has_address(&interface, addresses.ipv4.into())
            || has_address(&interface, addresses.ipv6.into()))
}

/// Match an address on the live utun using the kernel's local interface list.
#[cfg(all(target_os = "macos", not(test)))]
pub(super) fn link_is_up(_net_class: &Path, bytes: &[u8]) -> bool {
    use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
    snapshot_link(bytes, |name, wanted| {
        getifaddrs().is_ok_and(|mut interfaces| {
            interfaces.any(|interface| {
                if interface.interface_name != name
                    || !interface.flags.contains(InterfaceFlags::IFF_UP)
                {
                    return false;
                }
                interface.address.is_some_and(|address| match wanted {
                    std::net::IpAddr::V4(ip) => address
                        .as_sockaddr_in()
                        .is_some_and(|value| value.ip() == ip),
                    std::net::IpAddr::V6(ip) => address
                        .as_sockaddr_in6()
                        .is_some_and(|value| value.ip() == ip),
                })
            })
        })
    })
}

/// Match the fixture's local interface and address marker without creating a tunnel.
#[cfg(test)]
pub(super) fn link_is_up(net_class: &Path, bytes: &[u8]) -> bool {
    snapshot_link(bytes, |name, address| {
        net_class.join(name).join(address.to_string()).is_file()
    })
}

/// Report current local mesh setup and keep saved peer intent distinct from a live tunnel.
pub(super) fn mesh(unit: &Unit, activity: Activity, net_class: &Path) -> crate::Component {
    use std::{
        io::{self, Read},
        os::unix::fs::OpenOptionsExt,
    };
    const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

    if matches!(
        activity,
        Activity::Inactive | Activity::Failed | Activity::Restarting { .. }
    ) {
        return crate::row("mesh", "Stopped", "infraternal agent is stopped");
    }
    let Some(state) = &unit.state else {
        return crate::row("mesh", "Unknown", "mesh state directory unavailable");
    };
    let snapshot = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(state.join("mesh-public.json"))
        .and_then(|file| {
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > MAX_SNAPSHOT_BYTES {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut bytes = Vec::new();
            file.take(MAX_SNAPSHOT_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(bytes)
        });
    match snapshot {
        Ok(bytes) if crate::waiting_for_server_configuration(&bytes) => crate::mesh_waiting(),
        Ok(bytes) if link_is_up(net_class, &bytes) => {
            let detail = crate::peer_count(&bytes).map_or_else(
                || "peers unknown".to_owned(),
                |count| format!("peers: {count}"),
            );
            crate::row("mesh", "Running", detail)
        }
        Ok(_) => crate::row("mesh", "Stopped", "interface is down"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            crate::row("mesh", "Not set up", "")
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => crate::row(
            "mesh",
            "Unknown",
            "mesh details unavailable to this account",
        ),
        Err(_) => crate::row("mesh", "Unknown", "could not read mesh state"),
    }
}
