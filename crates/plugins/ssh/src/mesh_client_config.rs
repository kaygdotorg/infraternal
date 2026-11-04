//! Writes the one `ssh_config.d` file and known-hosts line that let plain `ssh` use mesh SSH [D235 Q2], #221.
//!
//! The block applies only to mesh names (`*.<suffix>`) and mesh addresses,
//! so every other host keeps the person's own SSH configuration. Inside it:
//! - `IdentityAgent` points at the infraternal key socket ([`crate::mesh_keys`]);
//! - `UserKnownHostsFile` holds one `@cert-authority` line for the mesh CA,
//!   so mesh hosts are trusted through their host certificates with no
//!   prompt, and `StrictHostKeyChecking yes` refuses any host without one.
//!
//! Mesh names need no DNS: each peer gets a `Host <name>.<suffix>` block
//! with its mesh address as `HostName` and its name as `HostKeyAlias`, so
//! plain `ssh <name>.<suffix>` connects to the mesh address and checks the
//! host certificate under the mesh name. The shared block matches on
//! `originalhost`, the name as typed, so it applies to mesh names and to
//! typed mesh addresses alike.
//!
//! Slice 1 limits (#221): bare names (`ssh db-01`) are not mapped, because
//! a short name could shadow a real host the person already reaches; and
//! `-A` forwards this socket, whose forwarded connections never sign
//! (`mesh_keys`), rather than the person's own agent.
//!
//! Every value written here comes from the server's validated mesh settings
//! (a DNS suffix of `[a-z0-9-.]` labels and a canonical IPv4 range) or from
//! fixed paths; [`client_config`] still refuses anything that could break
//! out of a quoted `ssh_config` value or a known-hosts pattern.

use std::{fmt::Write as _, net::Ipv4Addr, path::Path};

/// Where the file goes. OpenSSH's default configuration includes this
/// directory on current Debian, Ubuntu, Fedora and macOS releases. Shared
/// with uninstall, which removes exactly this file.
pub use infraternal_plugin_api::mesh_ssh_files::CONFIG_PATH;

/// The patterns that match mesh hosts: the name suffix and, when the range
/// falls on octet boundaries, an address glob (OpenSSH patterns have no CIDR).
fn patterns(suffix: &str, network: Ipv4Addr, prefix: u8) -> Option<Vec<String>> {
    let suffix_ok = !suffix.is_empty()
        && suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        });
    if !suffix_ok || prefix > 32 {
        return None;
    }
    let mut patterns = vec![format!("*.{suffix}")];
    if prefix.is_multiple_of(8) && (8..=24).contains(&prefix) {
        let octets = network.octets();
        let fixed = usize::from(prefix / 8);
        let mut glob = octets[..fixed]
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".");
        glob.push_str(".*");
        patterns.push(glob);
    }
    Some(patterns)
}

/// An absolute path quoted for `ssh_config`, or `None` if it could break out of the quotes.
fn quoted_path(path: &Path) -> Option<String> {
    let path = path.to_str()?;
    (path.starts_with('/')
        && !path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'"'))
    .then(|| format!("\"{path}\""))
}

/// One mesh peer the file maps by name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeshHost {
    /// The peer's mesh machine name, a single DNS label.
    pub name: String,
    /// The peer's mesh IPv4 address.
    pub address: Ipv4Addr,
}

/// A single lowercase DNS label: safe as an `ssh_config` pattern and value.
fn valid_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The `ssh_config.d` file with no named peers.
#[must_use]
pub fn client_config(
    suffix: &str,
    network: Ipv4Addr,
    prefix: u8,
    socket: &Path,
    known_hosts: &Path,
) -> Option<String> {
    client_config_with_hosts(suffix, network, prefix, socket, known_hosts, &[])
}

/// The `ssh_config.d` file, mapping each peer's `<name>.<suffix>` to its
/// mesh address.
#[must_use]
pub fn client_config_with_hosts(
    suffix: &str,
    network: Ipv4Addr,
    prefix: u8,
    socket: &Path,
    known_hosts: &Path,
    hosts: &[MeshHost],
) -> Option<String> {
    let patterns = patterns(suffix, network, prefix)?.join(",");
    let socket = quoted_path(socket)?;
    let known_hosts = quoted_path(known_hosts)?;
    let mut file = String::new();
    writeln!(
        file,
        "{} for mesh names and addresses only.",
        infraternal_plugin_api::mesh_ssh_files::HEADER
    )
    .ok()?;
    writeln!(
        file,
        "# Other hosts keep their own settings. Remove with `infraternal mesh ssh off`."
    )
    .ok()?;
    for host in hosts {
        if !valid_label(&host.name) {
            return None;
        }
        let name = format!("{}.{suffix}", host.name);
        writeln!(file, "Host {name}").ok()?;
        writeln!(file, "    HostName {}", host.address).ok()?;
        writeln!(file, "    HostKeyAlias {name}").ok()?;
    }
    writeln!(file, "Match originalhost \"{patterns}\"").ok()?;
    writeln!(file, "    IdentityAgent {socket}").ok()?;
    writeln!(file, "    UserKnownHostsFile {known_hosts}").ok()?;
    writeln!(file, "    StrictHostKeyChecking yes").ok()?;
    writeln!(file, "    PasswordAuthentication no").ok()?;
    writeln!(file, "    KbdInteractiveAuthentication no").ok()?;
    Some(file)
}

/// The known-hosts file: one `@cert-authority` line for the mesh CA.
#[must_use]
pub fn known_hosts(suffix: &str, network: Ipv4Addr, prefix: u8, ca: [u8; 32]) -> Option<String> {
    use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData, PublicKey};
    let patterns = patterns(suffix, network, prefix)?.join(",");
    let key = PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(ca)))
        .to_openssh()
        .ok()?;
    Some(format!("@cert-authority {patterns} {key}\n"))
}

#[cfg(test)]
#[path = "mesh_client_config_tests.rs"]
mod tests;
