//! Owns exact-address mesh TCP/22 listeners and reversible nft redirects [D197,D235], #221.
//!
//! The node lifecycle must serialize start/stop/recovery and supply only its
//! applied mesh address/interface. These blocking operations belong outside the
//! async packet path. No protocol server is started by this module. The mesh
//! firewall must enforce original TCP/22 access before this is wired to a node.

use std::{
    fmt::Write as _,
    io::{self, Write},
    net::{IpAddr, SocketAddr, TcpListener},
    process::{Command, Stdio},
};

/// Fixed absolute path of the firewall tool; never looked up through `PATH`.
const NFT: &str = "/usr/sbin/nft";
/// Table comment that marks a table as ours. Tables without it are never touched.
const MARKER: &str = "infraternal.ssh.v1";

/// Observable selection for owner review; no host SSH configuration is changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortMode {
    /// No listener is held.
    Stopped,
    /// Listening on TCP/22 of the mesh address itself.
    Direct,
    /// TCP/22 was taken, so we listen on a random port and redirect mesh TCP/22 to it.
    Redirect,
}

/// A listener and its optional owned redirect. Explicit stop is retryable and
/// reports cleanup failure; Drop is only a best-effort fallback, not evidence.
pub struct MeshPort {
    /// The bound socket; `None` once stopped.
    listener: Option<TcpListener>,
    /// The mesh address; also names the firewall table.
    address: IpAddr,
    /// True while our redirect rules are installed.
    redirected: bool,
}

impl MeshPort {
    /// Bind TCP/22, falling back only when another listener occupies the port.
    /// The caller must recover retained rules before starting a replacement.
    ///
    /// # Errors
    /// Refuses invalid coordinates, foreign/stale tables, missing privileges,
    /// non-address-in-use bind failures and failed atomic rule installation.
    pub fn bind(address: IpAddr, interface: &str) -> io::Result<Self> {
        validate(address, interface)?;
        // Never silently adopt rules that might still belong to a live listener.
        if presence(address)? {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let (listener, redirected) = match TcpListener::bind(SocketAddr::new(address, 22)) {
            Ok(listener) => (listener, false),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                (TcpListener::bind(SocketAddr::new(address, 0))?, true)
            }
            Err(error) => return Err(error),
        };
        if redirected {
            transaction(&render(address, interface, listener.local_addr()?.port()))?;
            // Never run with a partial install: a bare table would let mesh
            // TCP/22 reach the host's own sshd. Remove it and refuse.
            if let Err(error) = verify_installed(address) {
                let _ = Self::recover(address);
                return Err(error);
            }
        }
        Ok(Self {
            listener: Some(listener),
            address,
            redirected,
        })
    }

    /// Whether the port is stopped, direct or redirected.
    #[must_use]
    pub fn mode(&self) -> PortMode {
        if self.listener.is_none() {
            PortMode::Stopped
        } else if self.redirected {
            PortMode::Redirect
        } else {
            PortMode::Direct
        }
    }

    /// Borrow the owned listener without transferring lifecycle responsibility.
    /// A stopped lease has no listener.
    #[must_use]
    pub fn listener(&self) -> Option<&TcpListener> {
        self.listener.as_ref()
    }

    /// Remove the rules before releasing the socket. Failed removal leaves the
    /// lease intact so the component cannot report itself stopped prematurely.
    ///
    /// # Errors
    /// Reports failed ownership validation or kernel cleanup; callers retry.
    pub fn stop(&mut self) -> io::Result<()> {
        if self.redirected {
            Self::recover(self.address)?;
            self.redirected = false;
        }
        self.listener = None;
        Ok(())
    }

    /// Remove retained owned rules during serialized restart recovery/uninstall.
    /// This must not be called while another instance owns a live lease.
    ///
    /// # Errors
    /// Never removes an unmarked table; permission/tool failures stay visible.
    pub fn recover(address: IpAddr) -> io::Result<()> {
        if presence(address)? {
            transaction(&format!("delete table inet {}\n", table(address)))?;
        }
        Ok(())
    }
}

/// Best-effort `stop`; errors are ignored here, so call `stop` explicitly to learn of them.
impl Drop for MeshPort {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Reject addresses that make no sense for a mesh listener (unspecified,
/// loopback, multicast) and interface names that are empty, over 15 bytes or
/// contain anything but letters, digits, `_`, `.` and `-`. The strict character
/// set is what keeps the interface name safe to place in the firewall script.
fn validate(address: IpAddr, interface: &str) -> io::Result<()> {
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

/// Firewall table name derived from the address (hex), so each mesh address has its own table.
fn table(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => format!("infraternal_ssh4_{:08x}", u32::from(address)),
        IpAddr::V6(address) => format!("infraternal_ssh6_{:032x}", u128::from(address)),
    }
}

// Table names and script coordinates contain only typed addresses, integer ports
// and a validated interface. No shell, key material or caller script is accepted.
/// Apply an nft script atomically (`nft -f -`, script on stdin, output discarded).
/// Any tool failure is reported as `PermissionDenied`.
fn transaction(script: &str) -> io::Result<()> {
    let mut child = Command::new(NFT)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let written = child
        .stdin
        .take()
        .ok_or(io::ErrorKind::BrokenPipe)?
        .write_all(script.as_bytes());
    let status = child.wait()?;
    written?;
    if !status.success() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

/// Whether our table for `address` exists. `Ok(true)` only for a table whose
/// comment is exactly the marker. A table with the same name but another (or no)
/// comment is foreign and gives `AlreadyExists`, so we never delete or adopt it.
/// A failing or unparsable `nft` listing is an error, not "absent".
fn presence(address: IpAddr) -> io::Result<bool> {
    let output = Command::new(NFT)
        .args(["-j", "list", "tables"])
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let name = table(address);
    let tables: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
    let entries = tables["nftables"].as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing nftables table inventory",
        )
    })?;
    let Some(entry) = entries
        .iter()
        .map(|entry| &entry["table"])
        .find(|entry| entry["family"] == "inet" && entry["name"] == name)
    else {
        return Ok(false);
    };
    // Ownership must be the exact table comment, never a comment on a rule or a
    // prefix match. Inventory includes table comments on the supported frontend.
    if entry["comment"] != MARKER {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    Ok(true)
}

/// Build the nft script that redirects mesh TCP/22 to the internal `port`.
///
/// One table with three chains: `incoming` redirects traffic arriving on the
/// mesh `interface`; `local` does the same for this node's own traffic; `guard`
/// drops direct connections to the internal port unless the flow was originally
/// addressed to TCP/22.
fn render(address: IpAddr, interface: &str, port: u16) -> String {
    let family = if address.is_ipv4() { "ip" } else { "ip6" };
    let destination = match address {
        IpAddr::V4(address) => format!("{address}:{port}"),
        IpAddr::V6(address) => format!("[{address}]:{port}"),
    };
    let table = table(address);
    // One command per table, chain and rule, all in one atomic `nft -f`
    // transaction. nftables 1.0.9 drops chains nested inside
    // `create table X { … }` silently and still succeeds (#221 comment
    // 78954). `create` keeps refusing an existing table, so we never adopt one.
    let mut script = format!("create table inet {table} {{ comment \"{MARKER}\"; }}\n");
    let _ = writeln!(
        script,
        "add chain inet {table} incoming {{ type nat hook prerouting priority dstnat; policy accept; }}"
    );
    let _ = writeln!(
        script,
        "add rule inet {table} incoming iifname \"{interface}\" {family} daddr {address} tcp dport 22 dnat {family} to {destination}"
    );
    // DNAT back to the same address supports node-local traffic without moving
    // the listener onto loopback or intercepting ordinary host SSH destinations.
    let _ = writeln!(
        script,
        "add chain inet {table} local {{ type nat hook output priority dstnat; policy accept; }}"
    );
    let _ = writeln!(
        script,
        "add rule inet {table} local {family} daddr {address} tcp dport 22 dnat {family} to {destination}"
    );
    // The internal port is not a second externally usable SSH service. Only a
    // conntracked flow originally addressed to this node's TCP/22 may reach it.
    let _ = writeln!(
        script,
        "add chain inet {table} guard {{ type filter hook input priority -11; policy accept; }}"
    );
    let _ = writeln!(
        script,
        "add rule inet {table} guard {family} daddr {address} tcp dport {port} ct original {family} daddr {address} ct original proto-dst 22 return"
    );
    let _ = writeln!(
        script,
        "add rule inet {table} guard {family} daddr {address} tcp dport {port} drop"
    );
    script
}

/// Whether a listed table (`nft -j list table`) holds every chain and rule
/// [`render`] installs: the three chains, with one rule each in `incoming`
/// and `local` and two in `guard`. Anything less is a failed install.
fn installed(listing: &serde_json::Value) -> bool {
    let Some(items) = listing["nftables"].as_array() else {
        return false;
    };
    let chains: Vec<&str> = items
        .iter()
        .filter_map(|item| item["chain"]["name"].as_str())
        .collect();
    let rules = |chain: &str| {
        items
            .iter()
            .filter(|item| item["rule"]["chain"].as_str() == Some(chain))
            .count()
    };
    ["incoming", "local", "guard"]
        .iter()
        .all(|chain| chains.contains(chain))
        && rules("incoming") == 1
        && rules("local") == 1
        && rules("guard") == 2
}

/// Read our table back after installing it.
fn verify_installed(address: IpAddr) -> io::Result<()> {
    let output = Command::new(NFT)
        .args(["-j", "list", "table", "inet", &table(address)])
        .stderr(Stdio::null())
        .output()?;
    let listing: serde_json::Value = if output.status.success() {
        serde_json::from_slice(&output.stdout).map_err(io::Error::other)?
    } else {
        serde_json::Value::Null
    };
    if installed(&listing) {
        Ok(())
    } else {
        Err(io::Error::other("redirect rules incomplete after install"))
    }
}

#[cfg(test)]
#[path = "mesh_port_tests.rs"]
mod tests;
