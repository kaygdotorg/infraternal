//! Asks for, and keeps watching, macOS Local Network access for the user-mode infraternal agent
//! (#576, D203 C2).
//!
//! macOS lets a program reach hosts on the Mac's own local networks (Wi-Fi, Ethernet) only after
//! the person allows it under Privacy & Security › Local Network. Root processes, launchd daemons
//! and tools run from Terminal or SSH are exempt, so root mode never needs this; a launchd
//! *agent*, which is what user mode runs, is not (Apple's TN3179, "macOS considerations"). Until
//! it is allowed, every flow the agent starts to a LAN peer dies with `EHOSTUNREACH` or `EPIPE`,
//! while peers across the internet keep working (measured on the M1, J1108). That is a silent
//! black hole for exactly the peers that should be fastest, so this module:
//!
//! 1. **raises the system alert and learns the answer** with one operation, as soon as the
//!    agent starts and while `infraternal up` is still in front of the person: it connects a UDP
//!    socket to the IPv4 all-hosts group `224.0.0.1`, port 9 (discard), and sends one empty
//!    datagram. macOS has no call that reports the grant (TN3179, FB8711182), so the result of a
//!    real local operation is the only signal;
//! 2. **keeps trying and never exits** on a refusal: macOS may refuse the first operation before
//!    the person answers, and it shows no alert at all to a process that exits right after a
//!    refusal (TN3179, FB16131937). It checks every 15 s while not allowed, so an Allow takes
//!    effect without a restart, and every 10 minutes once allowed, so a later switch-off shows up;
//! 3. **writes the state** to [`STATE_FILE`] in the mesh state folder, one word from
//!    [`LocalNetwork::word`], so `infraternal up` can tell the person what to click and wait for
//!    it, and logs each change to the agent log.
//!
//! **Why that probe** (measured on the M1, macOS 27.2.1, as a launchd agent with no grant, then
//! with a grant; J1157 on #576). Not allowed: an empty send to `224.0.0.1` or to a LAN host fails
//! with `EPIPE` (`sendto` with `EHOSTUNREACH`), and so does IPv6 `ff02::1`. Allowed: the same
//! sends succeed. Two operations that look like local ones are *not* usable: a send to the
//! subnet's broadcast address succeeded without a grant and raised no alert, and the default
//! gateway is always allowed. A plain `connect` is never refused. Link-local multicast names no
//! host, never leaves the link (TTL 1), and reaches only the discard port, so it is the gentlest
//! operation that answers the question; it runs once per check.
//!
//! Whether the Mac has a local network at all is decided from its interfaces: a broadcast-capable
//! interface with a routable IPv4 network ([`broadcast_targets`], pure code the Linux gate tests).
// The watcher is Mac-only, so the Linux test build sees the pure part unused.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

/// The file in the mesh state folder that holds the current state, one word and a newline.
pub const STATE_FILE: &str = "local-network";
/// How often to check while access is not (yet) allowed.
const RETRY_DENIED: Duration = Duration::from_secs(15);
/// How often to check once access is allowed, to notice it being switched off.
const RECHECK_ALLOWED: Duration = Duration::from_secs(600);
/// How often to look again when the Mac has no local network at all.
const RECHECK_NONE: Duration = Duration::from_secs(60);
/// The discard port: an empty datagram there asks nothing of any host.
const DISCARD_PORT: u16 = 9;
/// The IPv4 link-local all-hosts group the probe sends to (see the module notes).
const ALL_HOSTS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

/// What the agent knows about its Local Network access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalNetwork {
    /// A local operation succeeded: LAN peers are reachable.
    Allowed,
    /// macOS refused a local operation: the person has not allowed it (or switched it off).
    Denied,
    /// The Mac has no broadcast-capable network with an IPv4 address right now.
    NoLocalNetwork,
    /// A check failed for another reason; it is tried again.
    Unknown,
}

impl LocalNetwork {
    /// The word written to [`STATE_FILE`]: `allowed`, `denied`, `none` or `unknown`.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::NoLocalNetwork => "none",
            Self::Unknown => "unknown",
        }
    }

    /// Read a state back from [`STATE_FILE`]'s contents; anything else is `None`.
    #[must_use]
    pub fn from_word(text: &str) -> Option<Self> {
        match text.trim() {
            "allowed" => Some(Self::Allowed),
            "denied" => Some(Self::Denied),
            "none" => Some(Self::NoLocalNetwork),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// How long to wait before the next check in this state.
    const fn next_check(self) -> Duration {
        match self {
            Self::Allowed => RECHECK_ALLOWED,
            Self::NoLocalNetwork => RECHECK_NONE,
            Self::Denied | Self::Unknown => RETRY_DENIED,
        }
    }
}

/// The result of one empty datagram: allowed, refused by Local Network privacy, or unclear.
///
/// `EHOSTUNREACH` is what `sendto` returns and `EPIPE` what a connected socket returns once macOS
/// has marked it defunct for this reason (J1108's measurements on the M1).
#[must_use]
pub fn classify(errno: Option<i32>) -> LocalNetwork {
    match errno {
        None => LocalNetwork::Allowed,
        Some(code) if code == nix::libc::EHOSTUNREACH || code == nix::libc::EPIPE => {
            LocalNetwork::Denied
        }
        Some(_) => LocalNetwork::Unknown,
    }
}

/// One interface address as the selection needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceAddress {
    /// The interface name, such as `en0`.
    pub name: String,
    /// The interface is up, running and broadcast-capable, and not loopback.
    pub broadcast_capable: bool,
    /// The interface's IPv4 address.
    pub address: Ipv4Addr,
    /// Its netmask.
    pub netmask: Ipv4Addr,
}

/// The Mac's local IPv4 networks, each named by its broadcast address, in interface order.
///
/// An empty list means the Mac has no local network right now, so there is nothing to ask for.
/// Only broadcast-capable interfaces count, which is also how TN3179 defines a local network,
/// so tunnels (utun, including the mesh's own), loopback and cellular are left out. Self-assigned
/// `169.254/16` addresses and point-to-point `/31` and `/32` networks have no LAN behind them.
#[must_use]
pub fn broadcast_targets(addresses: &[InterfaceAddress]) -> Vec<Ipv4Addr> {
    let mut targets = Vec::new();
    for entry in addresses {
        let prefix = u32::from(entry.netmask).leading_ones();
        if !entry.broadcast_capable
            || entry.address.is_link_local()
            || entry.address.is_loopback()
            || entry.address.is_unspecified()
            || prefix >= 31
            || prefix == 0
        {
            continue;
        }
        let broadcast = Ipv4Addr::from(u32::from(entry.address) | !u32::from(entry.netmask));
        if !targets.contains(&broadcast) {
            targets.push(broadcast);
        }
    }
    targets
}

/// Start watching Local Network access on a background thread for the life of the agent.
///
/// `state` is the mesh state folder, where [`STATE_FILE`] is kept. The thread never ends on a
/// refusal (see the module notes); it ends only with the process.
#[cfg(target_os = "macos")]
pub fn watch(state: &Path) {
    let file = state.join(STATE_FILE);
    let spawned = std::thread::Builder::new()
        .name("mesh-local-network".to_owned())
        .spawn(move || {
            let mut last = None;
            loop {
                let now = check();
                if last != Some(now) {
                    eprintln!("{}", sentence(now));
                    if let Err(error) = write_state(&file, now) {
                        eprintln!(
                            "infraternal: the Local Network state could not be saved ({:?})",
                            error.kind()
                        );
                    }
                    last = Some(now);
                }
                // sleep: there is no notification for a Local Network decision; polling is the
                // only way to see the person's answer (TN3179).
                std::thread::sleep(now.next_check());
            }
        });
    if let Err(error) = spawned {
        eprintln!(
            "infraternal: Local Network access is not watched ({:?})",
            error.kind()
        );
    }
}

/// The agent-log line for a new state.
fn sentence(state: LocalNetwork) -> &'static str {
    match state {
        LocalNetwork::Allowed => "infraternal: Local Network access is allowed; mesh peers on this network are reachable directly",
        LocalNetwork::Denied => "infraternal: Local Network access is not allowed, so mesh peers on this network cannot be reached directly. Allow infraternal under System Settings > Privacy & Security > Local Network",
        LocalNetwork::NoLocalNetwork => "infraternal: no local network right now; Local Network access is checked again when one appears",
        LocalNetwork::Unknown => "infraternal: Local Network access could not be checked; trying again",
    }
}

/// Write `state` to `file` through a temporary file and a rename, so a reader never sees half.
fn write_state(file: &Path, state: LocalNetwork) -> std::io::Result<()> {
    let temporary = file.with_extension("tmp");
    std::fs::write(&temporary, format!("{}\n", state.word()))?;
    std::fs::rename(&temporary, file)
}

/// One check: no local network, or the answer of one multicast probe.
#[cfg(target_os = "macos")]
fn check() -> LocalNetwork {
    let Some(addresses) = interface_addresses() else {
        return LocalNetwork::Unknown;
    };
    if broadcast_targets(&addresses).is_empty() {
        return LocalNetwork::NoLocalNetwork;
    }
    probe()
}

/// This Mac's IPv4 interface addresses with whether each interface is broadcast-capable;
/// `None` when the list cannot be read.
#[cfg(target_os = "macos")]
fn interface_addresses() -> Option<Vec<InterfaceAddress>> {
    use nix::net::if_::InterfaceFlags as F;
    let entries = nix::ifaddrs::getifaddrs().ok()?;
    Some(
        entries
            .filter_map(|entry| {
                let address = entry.address.as_ref()?.as_sockaddr_in()?.ip();
                let netmask = entry.netmask.as_ref()?.as_sockaddr_in()?.ip();
                let flags = entry.flags;
                Some(InterfaceAddress {
                    name: entry.interface_name,
                    broadcast_capable: flags
                        .contains(F::IFF_UP | F::IFF_RUNNING | F::IFF_BROADCAST)
                        && !flags.contains(F::IFF_LOOPBACK),
                    address,
                    netmask,
                })
            })
            .collect(),
    )
}

/// Connect a UDP socket to `224.0.0.1`:9 and send one empty datagram (see the module notes).
#[cfg(target_os = "macos")]
fn probe() -> LocalNetwork {
    match probe_errors() {
        Some((Some(errno), _) | (None, Some(errno))) => classify(Some(errno)),
        Some((None, None)) => LocalNetwork::Allowed,
        None => LocalNetwork::Unknown,
    }
}

/// The raw `errno` of the connect and of the empty send to `224.0.0.1`:9; `None` when no
/// socket could be made. The send is skipped when the connect already failed.
#[cfg(target_os = "macos")]
fn probe_errors() -> Option<(Option<i32>, Option<i32>)> {
    use nix::sys::socket::{
        AddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn, connect, send, socket,
    };
    use std::os::fd::AsRawFd;
    let socket = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .ok()?;
    let [a, b, c, d] = ALL_HOSTS.octets();
    if let Err(errno) = connect(
        socket.as_raw_fd(),
        &SockaddrIn::new(a, b, c, d, DISCARD_PORT),
    ) {
        return Some((Some(errno as i32), None));
    }
    let sent = send(socket.as_raw_fd(), &[], MsgFlags::empty()).err();
    Some((None, sent.map(|errno| errno as i32)))
}

/// Interface selection, error classification and the state words, checked without a Mac.
#[cfg(test)]
mod tests {
    use super::*;

    /// One interface address.
    fn entry(name: &str, broadcast_capable: bool, address: [u8; 4], prefix: u32) -> InterfaceAddress {
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        InterfaceAddress {
            name: name.to_owned(),
            broadcast_capable,
            address: Ipv4Addr::from(address),
            netmask: Ipv4Addr::from(mask),
        }
    }

    /// Wi-Fi and Ethernet give their broadcast addresses once each; the mesh utun, loopback,
    /// self-assigned and point-to-point addresses give none.
    #[test]
    fn only_real_local_networks_are_checked() {
        let addresses = [
            entry("lo0", false, [127, 0, 0, 1], 8),
            entry("en0", true, [192, 168, 1, 23], 24),
            entry("en0", true, [192, 168, 1, 24], 24),
            entry("en1", true, [10, 69, 0, 204], 22),
            entry("utun4", false, [10, 254, 0, 7], 32),
            entry("en2", true, [169, 254, 3, 4], 16),
            entry("en3", true, [192, 0, 2, 1], 31),
        ];
        assert_eq!(
            broadcast_targets(&addresses),
            [Ipv4Addr::new(192, 168, 1, 255), Ipv4Addr::new(10, 69, 3, 255)]
        );
        assert_eq!(broadcast_targets(&[]), Vec::<Ipv4Addr>::new());
    }

    /// Success is allowed, the two refusal codes macOS uses are denied, anything else unknown.
    #[test]
    fn errors_are_classified() {
        assert_eq!(classify(None), LocalNetwork::Allowed);
        assert_eq!(classify(Some(nix::libc::EHOSTUNREACH)), LocalNetwork::Denied);
        assert_eq!(classify(Some(nix::libc::EPIPE)), LocalNetwork::Denied);
        assert_eq!(classify(Some(nix::libc::ENOBUFS)), LocalNetwork::Unknown);
    }

    /// Live measurement for a real Mac (#576): run this test binary as a launchd agent in a
    /// person's login session and watch what each check returns while they answer the alert.
    /// Prints one line per check for `J1157_LN_SECONDS` (default 300) seconds.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "Run on a real Mac as a launchd agent in a login session."]
    fn live_local_network_checks() {
        let seconds: u64 = std::env::var("J1157_LN_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(300);
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < seconds {
            let addresses = interface_addresses().unwrap_or_default();
            let state = check();
            let networks = broadcast_targets(&addresses);
            println!(
                "t={:>4}s state={} probe={:?} networks={networks:?} interfaces={:?}",
                start.elapsed().as_secs(),
                state.word(),
                probe_errors(),
                addresses
                    .iter()
                    .map(|entry| format!("{}={}", entry.name, entry.address))
                    .collect::<Vec<_>>()
            );
            // sleep: the measurement samples the person's answer over time.
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    /// Every state survives the state file, and nothing else is read as a state.
    #[test]
    fn state_words_round_trip() {
        for state in [
            LocalNetwork::Allowed,
            LocalNetwork::Denied,
            LocalNetwork::NoLocalNetwork,
            LocalNetwork::Unknown,
        ] {
            assert_eq!(LocalNetwork::from_word(&format!("{}\n", state.word())), Some(state));
        }
        assert_eq!(LocalNetwork::from_word("maybe"), None);
        assert!(LocalNetwork::Denied.next_check() < LocalNetwork::Allowed.next_check());
    }
}
