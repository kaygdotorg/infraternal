//! Owns exact-address mesh TCP/22 listeners and publishes private ports to the userspace filter [D197,D235,D384], #221.
//!
//! The node lifecycle must serialize start/stop/recovery and supply only its
//! applied mesh address/interface. These blocking operations belong outside the
//! async packet path. No protocol server is started by this module. The mesh
//! policy must check the original TCP/22 grant before a private listener port is used.

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
    /// TCP/22 was taken, so we listen on a privileged internal port and
    /// redirect mesh TCP/22 to it.
    Redirect,
    /// TCP/22 was taken, so `GotaTun` rewrites mesh packets to the private listener.
    UserspaceRedirect,
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
    /// True while the `GotaTun` packet filter translates TCP/22 to the private listener.
    userspace_redirected: bool,
    /// The listener port published for the packet filter, if the lease is active.
    filter_port: Option<u16>,
}

impl MeshPort {
    /// Bind TCP/22, falling back only when another listener occupies the port.
    /// The caller must recover retained rules before starting a replacement.
    ///
    /// # Errors
    /// Refuses invalid coordinates, foreign/stale tables, missing privileges,
    /// non-address-in-use bind failures and failed atomic rule installation.
    pub fn bind(address: IpAddr, interface: &str) -> io::Result<Self> {
        Self::bind_mode(address, interface, false)
    }

    /// Bind a listener whose private-port redirect is applied by `GotaTun`.
    ///
    /// The filter checks the original TCP/22 grant before rewriting the destination port. No
    /// nft table is needed for this path; kernel `WireGuard` continues to use [`Self::bind`].
    ///
    /// # Errors
    /// Refuses invalid coordinates, non-address-in-use bind failures, unavailable privileged
    /// ports, or a listener address that cannot be published to the packet filter.
    pub(crate) fn bind_for_userspace_filter(address: IpAddr, interface: &str) -> io::Result<Self> {
        Self::bind_mode(address, interface, true)
    }

    /// Bind one exact address using either `GotaTun`'s packet filter or the kernel redirect.
    fn bind_mode(address: IpAddr, interface: &str, userspace_filter: bool) -> io::Result<Self> {
        validate(address, interface)?;
        // Never silently adopt rules that might still belong to a live listener.
        if !userspace_filter && presence(address)? {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let (listener, needs_redirect) = match TcpListener::bind(SocketAddr::new(address, 22)) {
            Ok(listener) => (listener, false),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                (internal_listener(address)?, true)
            }
            Err(error) => return Err(error),
        };
        let redirected = needs_redirect && !userspace_filter;
        if redirected {
            transaction(&render(address, interface, listener.local_addr()?.port()))?;
            // Never run with a partial install: a bare table would let mesh
            // TCP/22 reach the host's own sshd. Remove it and refuse.
            if let Err(error) = verify_installed(address) {
                let _ = Self::recover(address);
                return Err(error);
            }
        }
        let listener_port = listener.local_addr()?.port();
        let filter_port = userspace_filter.then_some(listener_port);
        let mut binding = Self {
            listener: Some(listener),
            address,
            redirected,
            userspace_redirected: needs_redirect && userspace_filter,
            filter_port,
        };
        if let Some(port) = filter_port
            && let Err(error) = infraternal_mesh::mesh_ssh::publish_listener(address, port)
        {
            let _ = binding.stop();
            return Err(error);
        }
        Ok(binding)
    }

    /// [`Self::bind`] for a component that is starting: a table our marker
    /// owns for this address can only be left from a previous run of this
    /// process's component (the caller holds no lease for it), so it is
    /// recovered first, as the contract requires before admitting sessions.
    /// A same-named table without our marker is still refused.
    ///
    /// # Errors
    /// The same refusals as [`Self::bind`].
    pub fn bind_after_restart(address: IpAddr, interface: &str) -> io::Result<Self> {
        Self::bind_after_restart_with_filter(address, interface, false)
    }

    /// Recover and bind using the packet filter when `GotaTun` owns mesh access enforcement.
    ///
    /// # Errors
    /// The same refusals as [`Self::bind`], plus failures while recovering an old kernel redirect.
    pub(crate) fn bind_after_restart_with_filter(
        address: IpAddr,
        interface: &str,
        userspace_filter: bool,
    ) -> io::Result<Self> {
        validate(address, interface)?;
        if userspace_filter {
            Self::recover_legacy_redirect(address)?;
            Self::bind_for_userspace_filter(address, interface)
        } else {
            Self::recover(address)?;
            Self::bind(address, interface)
        }
    }

    /// Whether the port is stopped, direct or redirected.
    #[must_use]
    pub fn mode(&self) -> PortMode {
        if self.listener.is_none() {
            PortMode::Stopped
        } else if self.userspace_redirected {
            PortMode::UserspaceRedirect
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
        if let Some(port) = self.filter_port.take() {
            infraternal_mesh::mesh_ssh::clear_listener(self.address, port);
        }
        self.userspace_redirected = false;
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

    /// Remove an exact owned legacy redirect when nft is available to `GotaTun` recovery.
    ///
    /// `GotaTun` does not need a firewall executable. A missing fixed path therefore skips only
    /// this optional inspection; the mesh status guard reports the same missing path and its
    /// kernel-only protections. Any present tool refusal or foreign table still stops recovery.
    ///
    /// # Errors
    /// Refuses a foreign same-named table or reports failures from the fixed nft path.
    fn recover_legacy_redirect(address: IpAddr) -> io::Result<()> {
        match Self::recover(address) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

/// Best-effort `stop`; errors are ignored here, so call `stop` explicitly to learn of them.
impl Drop for MeshPort {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The internal ports a redirect may listen on, tried highest first.
///
/// Invariant (J236 P2-2, #221): only root can bind them. After an abrupt exit
/// (SIGKILL, OOM) the owned table stays until restart recovery, and its guard
/// admits any flow originally addressed to :22 whoever owns the internal
/// port. An unprivileged port let any local account take mesh TCP/22 over
/// in that window.
const INTERNAL_PORTS: std::ops::RangeInclusive<u16> = 960..=1022;

/// The kernel's lowest port an unprivileged account may bind. It is one value
/// for both IPv4 and IPv6, despite its name.
const UNPRIVILEGED_PORT_START: &str = "/proc/sys/net/ipv4/ip_unprivileged_port_start";

/// The internal ports usable for `euid` when unprivileged accounts may bind
/// from `unprivileged_start` up.
///
/// # Errors
/// `PermissionDenied` for a rootless infraternal agent (it cannot hold a port
/// only root may take, so it never redirects), and for a host whose bound
/// leaves no port in [`INTERNAL_PORTS`] reserved to root.
pub(crate) fn internal_ports(
    euid: u32,
    unprivileged_start: u16,
) -> io::Result<impl Iterator<Item = u16>> {
    let mut ports = INTERNAL_PORTS
        .rev()
        .filter(move |port| *port < unprivileged_start)
        .peekable();
    if euid != 0 || ports.peek().is_none() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(ports)
}

/// Bind the redirect's internal listener on a free port only root can bind,
/// reading the kernel's bound each time (a host may have lowered it).
fn internal_listener(address: IpAddr) -> io::Result<TcpListener> {
    let start = std::fs::read_to_string(UNPRIVILEGED_PORT_START)?
        .trim()
        .parse::<u16>()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    for port in internal_ports(nix::unistd::Uid::effective().as_raw(), start)? {
        match TcpListener::bind(SocketAddr::new(address, port)) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            bound => return bound,
        }
    }
    Err(io::ErrorKind::AddrInUse.into())
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
/// Name the fixed firewall executable and operation when its spawn or command fails.
fn nft_error(operation: &str, error: &io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("nft at {NFT} could not {operation}: {error}"),
    )
}

/// Apply an nft script atomically (`nft -f -`, script on stdin, output discarded).
/// Failures name the fixed nft path so a missing or unusable tool is diagnosable.
fn transaction(script: &str) -> io::Result<()> {
    let mut child = Command::new(NFT)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| nft_error("start the mesh SSH redirect", &error))?;
    let written = child
        .stdin
        .take()
        .ok_or(io::ErrorKind::BrokenPipe)?
        .write_all(script.as_bytes());
    let status = child
        .wait()
        .map_err(|error| nft_error("finish the mesh SSH redirect", &error))?;
    written.map_err(|error| nft_error("write the mesh SSH redirect", &error))?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("nft at {NFT} refused the mesh SSH redirect ({status})"),
        ));
    }
    Ok(())
}

/// Whether our table for `address` exists. `Ok(true)` only for a table whose
/// comment is exactly the marker. A table with the same name but another (or no)
/// comment is foreign and gives `AlreadyExists`, so we never delete or adopt it.
/// A failing or unparsable `nft` listing is an error, not "absent".
pub(crate) fn presence(address: IpAddr) -> io::Result<bool> {
    let output = Command::new(NFT)
        .args(["-j", "list", "tables"])
        .stderr(Stdio::null())
        .output()
        .map_err(|error| nft_error("inspect mesh SSH redirect ownership", &error))?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "nft at {NFT} could not inspect mesh SSH redirect ownership ({})",
                output.status
            ),
        ));
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
