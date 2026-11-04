//! Writes the one `ssh_config.d` file and known-hosts line that let plain `ssh` use mesh SSH [D235 Q2], #221.
//!
//! The block applies only to mesh names (`*.<suffix>`) and mesh addresses,
//! so every other host keeps the person's own SSH configuration. Inside it:
//! - `IdentityAgent` points at the infraternal key socket ([`crate::mesh_keys`]);
//! - `UserKnownHostsFile` holds one `@cert-authority` line for the mesh CA,
//!   so mesh hosts are trusted through their host certificates with no
//!   prompt, and `StrictHostKeyChecking yes` refuses any host without one.
//!
//! Slice 1 limits (#221 plan): bare names (`ssh db-01`) match only where the
//! resolver adds the suffix before `ssh` sees the name, so the proof uses
//! `<name>.<suffix>` or the address; and `-A` forwards this socket, whose
//! forwarded connections never sign (`mesh_keys`), rather than the
//! person's own agent.
//!
//! Every value written here comes from the server's validated mesh settings
//! (a DNS suffix of `[a-z0-9-.]` labels and a canonical IPv4 range) or from
//! fixed paths; [`client_config`] still refuses anything that could break
//! out of a quoted `ssh_config` value or a known-hosts pattern.

use std::{fmt::Write as _, net::Ipv4Addr, path::Path};

/// Where the file goes. OpenSSH's default configuration includes this
/// directory on current Debian, Ubuntu, Fedora and macOS releases.
pub const CONFIG_PATH: &str = "/etc/ssh/ssh_config.d/50-infraternal-mesh.conf";

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
    if prefix % 8 == 0 && (8..=24).contains(&prefix) {
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

fn quoted_path(path: &Path) -> Option<String> {
    let path = path.to_str()?;
    (path.starts_with('/')
        && !path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'"'))
    .then(|| format!("\"{path}\""))
}

/// The `ssh_config.d` file.
#[must_use]
pub fn client_config(
    suffix: &str,
    network: Ipv4Addr,
    prefix: u8,
    socket: &Path,
    known_hosts: &Path,
) -> Option<String> {
    let patterns = patterns(suffix, network, prefix)?.join(",");
    let socket = quoted_path(socket)?;
    let known_hosts = quoted_path(known_hosts)?;
    let mut file = String::new();
    writeln!(
        file,
        "# Managed by infraternal: mesh SSH for mesh names and addresses only."
    )
    .ok()?;
    writeln!(
        file,
        "# Other hosts keep their own settings. Remove with `infraternal mesh ssh off`."
    )
    .ok()?;
    writeln!(file, "Match host \"{patterns}\"").ok()?;
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
