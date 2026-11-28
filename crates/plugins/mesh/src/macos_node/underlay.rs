//! The macOS node's underlay listener: one `PF_ROUTE` routing socket that tells the worker when
//! the host's addresses, routes or links changed in a way that can move our own endpoint, so
//! live sessions announce it at once (#483 J707 P2-3).
//!
//! A peer learns our endpoint only from an authenticated packet. A Mac that is only receiving
//! sends nothing until its 25 s keepalive (D392), so after its address changes the peer keeps
//! sending to the old one for that long. The Linux node hears the change on its route-netlink
//! subscription; this is the macOS equivalent, feeding the same coalesced
//! [`UnderlayAnnounce`](crate::underlay_announce::UnderlayAnnounce).
//!
//! **Why a routing socket (D81).** The kernel pushes every address, route and interface change
//! to each `PF_ROUTE` socket as it happens, so an idle host costs no wakeup and nothing polls.
//! The platform's configuration notifications were rejected: they arrive later (configd reads
//! the same kernel events first), they need a run-loop thread of their own, and they miss
//! routes nobody publishes to the dynamic store.
//!
//! **What counts.** Every routing socket sees every process's route requests and lookups, so
//! the listener drops most messages cheaply: lookups (`RTM_GET`), misses and failed requests,
//! anything on our own utun (our peer host routes, its address and MTU), ARP and neighbour
//! entries and per-destination clones. What is left is reduced to the parts that can move our
//! endpoint and compared with what was last seen ([`ChangeBook`]), so a repeat of a known fact
//! (a lifetime refresh, a DHCP renewal re-applying the same address) is not a change.
//!
//! **What it cannot see.** xnu sends no routing message when an address is added to or removed
//! from an interface inside a prefix that is already routed there (a second IPv4 address in the
//! same subnet; J710 measured it on macOS 26). Joining or leaving a network, a new or lost default
//! route and a link going down all send messages, so the moves that strand a peer are seen; an
//! extra address inside the current subnet is not, and the 25 s keepalive still covers it.
//!
//! **Lost messages.** macOS drops a routing message silently when the socket's buffer is full;
//! there is no `ENOBUFS` to read. The buffer is sized for a large apply's own route echoes, and
//! the worker calls [`UnderlayMonitor::resync`] after each apply, when the burst it caused may
//! have pushed a real change out: the address and link books are rebuilt and any difference in
//! them is announced. The resync does not compare routes and drops the route book, so a default
//! route or gateway change lost to a full buffer during an apply is not announced; the 25 s
//! keepalive still covers it, and it takes more than about 6,500 messages in one apply.
//!
//! **Peer-to-peer Wi-Fi links never count.** A Wi-Fi Mac has `awdl0` and `llw0`, the links
//! macOS uses for nearby-device discovery and transfers. They carry only `fe80::` addresses, so
//! no peer can reach our endpoint through them, but the kernel adds and deletes host routes for
//! nearby devices on them all the time. On an idle M1 on Wi-Fi, 48 `awdl0` route deletes in
//! 5,400 s (one per 112 s) were each judged a change (J1028 on #260); a later raw capture on the
//! same Mac had 52 adds and 51 deletes in 24 minutes, and the adds count too (J1108). Each one
//! asked every live session for a keepalive and, with connected sends, marked every pool socket
//! stale. So their
//! routes, addresses and link flags are dropped like our own utun's: by interface name (`awdl*`,
//! `llw*`), and for routes also by a link gateway on such an interface, since the kernel sends
//! the `RTM_ADD` for a nearby device's route unscoped (interface index 0) with the link only in
//! the gateway ([`PeerToPeerLinks`]).

use crate::underlay_announce::{AnnouncementWaiter, ChangeBook, UnderlayAnnounce};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    libc,
    sys::socket::{AddressFamily, SockFlag, SockType, setsockopt, socket, sockopt},
};
use std::{
    io,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::OwnedFd,
    sync::Arc,
};
use tokio::io::unix::AsyncFd;

/// The routing socket's receive buffer. Each route message is about 160 bytes, so 1 MiB holds the
/// echoes of about 6,500 route writes: a 1,000-peer apply installs 2,000 host routes while the
/// worker is busy and not reading (D393).
const RECEIVE_BUFFER_BYTES: usize = 1 << 20;

/// The largest routing message we read; the kernel caps one message well below this.
const MESSAGE_BYTES: usize = 2048;

/// Interface flags that say whether a link can carry our endpoint. Others (promiscuous mode,
/// multicast membership, the `SMART` bit) change without moving anything.
const LINK_FLAGS: i32 = libc::IFF_UP | libc::IFF_RUNNING;

/// Route flags that change where a route sends packets. The rest are bookkeeping the kernel
/// updates on its own (`RTF_DONE` on replies, use counts, protocol bits).
const ROUTE_FLAGS: i32 = libc::RTF_UP
    | libc::RTF_GATEWAY
    | libc::RTF_HOST
    | libc::RTF_REJECT
    | libc::RTF_BLACKHOLE
    | libc::RTF_IFSCOPE;

/// Routes that never move our endpoint: ARP and neighbour entries, and the per-destination
/// clones the kernel makes from a parent route (the parent is what counts).
const IGNORED_ROUTE_FLAGS: i32 = libc::RTF_LLINFO | libc::RTF_WASCLONED;

/// An interface address as the kernel identifies it: interface index, the address, and its
/// prefix length. The broadcast or point-to-point peer address is left out; it cannot move our
/// own source address.
type AddressKey = (u16, IpAddr, u8);

/// A route as the kernel identifies it: destination, prefix length, and the interface it is
/// scoped to (zero for an unscoped route).
type RouteKey = (IpAddr, u8, u16);

/// Where a route sends packets: its gateway, interface, preferred source address and the flags
/// in [`ROUTE_FLAGS`]. Its lifetime and metrics are left out, so a refresh is not a change.
type RouteValue = (Option<Gateway>, u16, Option<IpAddr>, i32);

/// A route's gateway: a next-hop address, or a link for a route straight onto an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Gateway {
    /// A next-hop router.
    Address(IpAddr),
    /// The interface index of a directly connected route.
    Link(u16),
}

/// The interface-name prefixes of macOS's peer-to-peer Wi-Fi links (see the module docs).
const PEER_TO_PEER_PREFIXES: [&str; 2] = ["awdl", "llw"];

/// Whether `name` is one of macOS's peer-to-peer Wi-Fi links, whose changes never move our
/// endpoint.
fn is_peer_to_peer(name: &str) -> bool {
    PEER_TO_PEER_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Which interface indices are peer-to-peer Wi-Fi links ([`is_peer_to_peer`]), learned from
/// interface names.
///
/// The answer for every interface that existed is filled in when the books are built. An index
/// first seen in a later message (a link created after the listener opened) is looked up then,
/// once, by listing the interfaces again. An index that is in no list (an interface already
/// gone) is not peer-to-peer and is not remembered, so its messages count, which errs on the
/// side of announcing.
#[derive(Debug)]
struct PeerToPeerLinks {
    /// Each known index and whether it is peer-to-peer.
    known: std::collections::BTreeMap<u16, bool>,
    /// Lists the host's interfaces as `(index, name)`: `getifaddrs` in the product, a fixed list
    /// in tests so synthetic indices never meet the test Mac's real interfaces.
    list: fn() -> Vec<(u16, String)>,
}

impl Default for PeerToPeerLinks {
    fn default() -> Self {
        Self {
            known: std::collections::BTreeMap::new(),
            list: host_interfaces,
        }
    }
}

impl PeerToPeerLinks {
    /// Record that `index` is called `name`.
    fn learn(&mut self, index: u16, name: &str) {
        self.known.insert(index, is_peer_to_peer(name));
    }

    /// Whether interface `index` is a peer-to-peer Wi-Fi link. Index 0 (an unscoped route) never
    /// is.
    fn contains(&mut self, index: u16) -> bool {
        if index == 0 {
            return false;
        }
        if let Some(known) = self.known.get(&index) {
            return *known;
        }
        for (listed, name) in (self.list)() {
            self.learn(listed, &name);
        }
        self.known.get(&index).copied().unwrap_or(false)
    }
}

/// The host's interfaces as `(index, name)`, one entry per interface; empty if they cannot be
/// listed.
fn host_interfaces() -> Vec<(u16, String)> {
    let Ok(interfaces) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let mut seen = std::collections::BTreeMap::new();
    for interface in interfaces {
        if let Some(index) = nix::net::if_::if_nametoindex(interface.interface_name.as_str())
            .ok()
            .and_then(|index| u16::try_from(index).ok())
        {
            seen.entry(index).or_insert(interface.interface_name);
        }
    }
    seen.into_iter().collect()
}

/// The host's addresses, links and routes outside our utun and the peer-to-peer Wi-Fi links, as
/// last seen, so each routing message can be judged a change or a repeat.
#[derive(Debug, Default)]
struct UnderlayBooks {
    /// Every address outside the utun. The value is empty: an address is there or it is not.
    addresses: ChangeBook<AddressKey, ()>,
    /// Each interface's [`LINK_FLAGS`], by index.
    links: ChangeBook<u16, i32>,
    /// Routes seen since the listener opened. It starts empty (macOS has no safe route dump
    /// without `unsafe` sysctl calls), so the first message about an existing route counts
    /// once; routes on an idle Mac are not re-announced, so that costs at most one extra
    /// announcement per route, never a missed change.
    routes: ChangeBook<RouteKey, RouteValue>,
    /// Which interfaces are peer-to-peer Wi-Fi links; nothing on them counts.
    peer_to_peer: PeerToPeerLinks,
}

impl UnderlayBooks {
    /// Read the host's current addresses and links (outside `utun_index` and the peer-to-peer
    /// Wi-Fi links), so a later repeat of one of them is recognised as a repeat.
    /// # Errors
    /// Returns the `getifaddrs` error.
    fn current(utun_index: u16) -> io::Result<Self> {
        let mut books = Self::default();
        for interface in nix::ifaddrs::getifaddrs()? {
            let Ok(index) = nix::net::if_::if_nametoindex(interface.interface_name.as_str()) else {
                continue;
            };
            let Ok(index) = u16::try_from(index) else {
                continue;
            };
            books
                .peer_to_peer
                .learn(index, interface.interface_name.as_str());
            if index == utun_index || is_peer_to_peer(interface.interface_name.as_str()) {
                continue;
            }
            let flags = interface.flags.bits() & LINK_FLAGS;
            books.links.present(index, flags);
            let Some(address) = interface.address.as_ref().and_then(storage_ip) else {
                continue;
            };
            let prefix = interface
                .netmask
                .as_ref()
                .and_then(storage_ip)
                .map_or(full_prefix(address), prefix_length);
            books.addresses.present((index, address, prefix), ());
        }
        Ok(books)
    }

    /// Judge one routing message: whether it changed something that can move our endpoint.
    /// Malformed or truncated messages are ignored, never trusted as a change.
    fn observe(&mut self, message: &[u8], utun_index: u16) -> bool {
        // The kernel states each message's length; a read shorter than that was cut off.
        let Some(length) = u16_at(message, 0).map(usize::from) else {
            return false;
        };
        let Some(message) = message.get(..length) else {
            return false;
        };
        let Some(kind) = message.get(3).map(|kind| i32::from(*kind)) else {
            return false;
        };
        if message.get(2).map(|version| i32::from(*version)) != Some(libc::RTM_VERSION) {
            return false;
        }
        match kind {
            libc::RTM_ADD | libc::RTM_CHANGE | libc::RTM_DELETE => {
                self.observe_route(kind, message, utun_index)
            }
            libc::RTM_NEWADDR | libc::RTM_DELADDR => {
                self.observe_address(kind, message, utun_index)
            }
            libc::RTM_IFINFO => self.observe_link(message, utun_index),
            // Lookups, misses, redirects of no route, multicast memberships and the rest.
            _ => false,
        }
    }

    /// An added, changed or deleted route (`rt_msghdr`).
    fn observe_route(&mut self, kind: i32, message: &[u8], utun_index: u16) -> bool {
        let header = size_of::<libc::rt_msghdr>();
        let (Some(index), Some(flags), Some(present), Some(errno)) = (
            u16_at(message, offset_of!(libc::rt_msghdr, rtm_index)),
            i32_at(message, offset_of!(libc::rt_msghdr, rtm_flags)),
            i32_at(message, offset_of!(libc::rt_msghdr, rtm_addrs)),
            i32_at(message, offset_of!(libc::rt_msghdr, rtm_errno)),
        ) else {
            return false;
        };
        // A failed request changed nothing; our own utun's routes are results, not inputs, and
        // the peer-to-peer links' routes lead to nearby devices, never to a peer.
        if errno != 0
            || index == utun_index
            || flags & IGNORED_ROUTE_FLAGS != 0
            || self.peer_to_peer.contains(index)
        {
            return false;
        }
        let Some(addresses) = message
            .get(header..)
            .and_then(|tail| sockaddrs(tail, present))
        else {
            return false;
        };
        let Some(destination) = addresses[RTAX_DST].and_then(sockaddr_ip) else {
            return false;
        };
        let prefix = if flags & libc::RTF_HOST != 0 {
            full_prefix(destination)
        } else {
            addresses[RTAX_NETMASK]
                .map(|mask| netmask_ip(mask, destination))
                .map_or(0, prefix_length)
        };
        let gateway = addresses[RTAX_GATEWAY].and_then(gateway);
        if let Some(Gateway::Link(link)) = gateway {
            // An unscoped route (index 0) names its interface only here.
            if link == utun_index || self.peer_to_peer.contains(link) {
                return false;
            }
        }
        let scope = if flags & libc::RTF_IFSCOPE != 0 {
            index
        } else {
            0
        };
        let key = (destination, prefix, scope);
        if kind == libc::RTM_DELETE {
            return self.routes.absent(&key);
        }
        let source = addresses[RTAX_IFA].and_then(sockaddr_ip);
        self.routes
            .present(key, (gateway, index, source, flags & ROUTE_FLAGS))
    }

    /// A new or removed interface address (`ifa_msghdr`).
    fn observe_address(&mut self, kind: i32, message: &[u8], utun_index: u16) -> bool {
        let header = size_of::<libc::ifa_msghdr>();
        let (Some(index), Some(present)) = (
            u16_at(message, offset_of!(libc::ifa_msghdr, ifam_index)),
            i32_at(message, offset_of!(libc::ifa_msghdr, ifam_addrs)),
        ) else {
            return false;
        };
        if index == utun_index || self.peer_to_peer.contains(index) {
            return false;
        }
        let Some(addresses) = message
            .get(header..)
            .and_then(|tail| sockaddrs(tail, present))
        else {
            return false;
        };
        let Some(address) = addresses[RTAX_IFA].and_then(sockaddr_ip) else {
            return false;
        };
        let prefix = addresses[RTAX_NETMASK]
            .map(|mask| netmask_ip(mask, address))
            .map_or(full_prefix(address), prefix_length);
        let key = (index, address, prefix);
        if kind == libc::RTM_DELADDR {
            self.addresses.absent(&key)
        } else {
            self.addresses.present(key, ())
        }
    }

    /// An interface's flags or link state (`if_msghdr`).
    fn observe_link(&mut self, message: &[u8], utun_index: u16) -> bool {
        let (Some(index), Some(flags)) = (
            u16_at(message, offset_of!(libc::if_msghdr, ifm_index)),
            i32_at(message, offset_of!(libc::if_msghdr, ifm_flags)),
        ) else {
            return false;
        };
        index != utun_index
            && !self.peer_to_peer.contains(index)
            && self.links.present(index, flags & LINK_FLAGS)
    }
}

/// The macOS node's one routing-socket subscription (see the module docs).
pub(super) struct UnderlayMonitor {
    /// The nonblocking `PF_ROUTE` socket, registered with the worker's runtime for reading.
    socket: AsyncFd<OwnedFd>,
    /// Our utun's interface index; nothing on it counts.
    utun_index: u16,
    /// Reused storage for one routing message; they carry no secrets.
    buffer: Vec<u8>,
    /// What the host's underlay looked like at the last message.
    books: UnderlayBooks,
    /// Woken for every change that can move our endpoint.
    announce: Arc<UnderlayAnnounce>,
}

impl UnderlayMonitor {
    /// Subscribe to routing messages for the node whose utun is `utun`, waking `announce` for
    /// every change that can move our endpoint. Must run inside the worker's Tokio runtime.
    ///
    /// Opening wakes `announce` once: nothing reported what changed while no listener ran. The
    /// host's addresses and links are read after the socket exists, so a change between the two
    /// is either in that read or delivered after it.
    /// # Errors
    /// Returns socket, socket-option, interface lookup or runtime registration errors.
    pub(super) fn open(utun: &str, announce: Arc<UnderlayAnnounce>) -> io::Result<Self> {
        let utun_index = u16::try_from(nix::net::if_::if_nametoindex(utun)?)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let fd = socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)?;
        fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        fcntl(&fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
        // A smaller buffer still works; resync covers what it drops.
        if let Err(error) = setsockopt(&fd, sockopt::RcvBuf, &RECEIVE_BUFFER_BYTES) {
            tracing::debug!(%error, "routing socket kept its default receive buffer");
        }
        // Tokio deprecates its safe constructors because a borrowed descriptor could be closed
        // under the registration; this one is an `OwnedFd` the registration owns outright, and
        // the crate forbids the `unsafe` replacement (the utun registration does the same).
        #[allow(deprecated)]
        let socket = AsyncFd::with_interest(fd, tokio::io::Interest::READABLE)?;
        let books = UnderlayBooks::current(utun_index)?;
        announce.changed();
        Ok(Self {
            socket,
            utun_index,
            buffer: vec![0; MESSAGE_BYTES],
            books,
            announce,
        })
    }

    /// Wait for routing messages and read every one that is queued, waking the announce if any
    /// of them changed something. Returns after each batch. Idle, it sleeps in the runtime's
    /// kqueue with no timer (D81).
    ///
    /// Cancel-safe for a `select!`: readiness is awaited first and the reads that follow do not
    /// wait, so a dropped call loses no message.
    /// # Errors
    /// Returns a read error other than "no more messages"; the socket is then unusable.
    pub(super) async fn next_batch(&mut self) -> io::Result<()> {
        let mut guard = self.socket.readable().await?;
        let mut changed = false;
        loop {
            match nix::unistd::read(guard.get_inner(), &mut self.buffer) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(length) => {
                    changed |= self.books.observe(&self.buffer[..length], self.utun_index);
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    guard.clear_ready();
                    break;
                }
                Err(nix::errno::Errno::EINTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if changed {
            self.announce.changed();
        }
        Ok(())
    }

    /// Re-read the host's addresses and links after a burst that may have overflowed the socket
    /// (our own route writes during an apply), and announce if they differ from the books.
    /// Routes are forgotten too, so each one counts once more when next reported.
    pub(super) fn resync(&mut self) {
        let Ok(current) = UnderlayBooks::current(self.utun_index) else {
            // Without a fresh view, treat everything as possibly moved.
            self.books = UnderlayBooks::default();
            self.announce.changed();
            return;
        };
        if current.addresses != self.books.addresses || current.links != self.books.links {
            self.announce.changed();
        }
        self.books = current;
    }
}

/// The worker's whole announce path on macOS: the routing-socket listener (when it could open)
/// and the shared coalescing. [`Self::due`] yields when live sessions should announce our
/// endpoint; the caller then calls `request_keepalives` on its `GotaTun` device.
pub struct UnderlayAnnouncer {
    /// The listener, or `None` when it could not open or has failed.
    monitor: Option<UnderlayMonitor>,
    /// The shared 25 ms / 250 ms coalescing over the listener's wakeups.
    waiter: AnnouncementWaiter,
}

impl UnderlayAnnouncer {
    /// Start listening for the node whose utun is `utun`. If the routing socket cannot open,
    /// the node still runs, without announcements (the keepalive still recovers in 25 s).
    pub(super) fn start(utun: &str) -> Self {
        let announce = Arc::new(UnderlayAnnounce::default());
        let monitor = match UnderlayMonitor::open(utun, Arc::clone(&announce)) {
            Ok(monitor) => Some(monitor),
            Err(error) => {
                tracing::warn!(%error, "mesh underlay listener could not start; peers follow an address change only on the next keepalive");
                None
            }
        };
        Self {
            monitor,
            waiter: AnnouncementWaiter::new(announce),
        }
    }

    /// Wait until an announcement is due. Cancel-safe, so the worker can `select!` on it next
    /// to its commands. A listener that fails is dropped with a warning; announcements already
    /// requested still go out.
    pub(super) async fn due(&mut self) {
        loop {
            tokio::select! {
                () = self.waiter.next() => return,
                result = next_batch(self.monitor.as_mut()) => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "mesh underlay listener stopped; peers follow an address change only on the next keepalive");
                        self.monitor = None;
                    }
                }
            }
        }
    }

    /// See [`UnderlayMonitor::resync`]; call it after the worker wrote routes.
    pub(super) fn resync(&mut self) {
        if let Some(monitor) = self.monitor.as_mut() {
            monitor.resync();
        }
    }

    /// Whether the routing-socket listener is running.
    #[cfg(test)]
    pub(super) fn is_listening(&self) -> bool {
        self.monitor.is_some()
    }
}

/// The next batch of `monitor`, or never when there is no listener.
async fn next_batch(monitor: Option<&mut UnderlayMonitor>) -> io::Result<()> {
    match monitor {
        Some(monitor) => monitor.next_batch().await,
        None => std::future::pending().await,
    }
}

/// Sockaddr slot of a route's destination (`RTAX_DST`).
const RTAX_DST: usize = 0;
/// Sockaddr slot of a route's gateway (`RTAX_GATEWAY`).
const RTAX_GATEWAY: usize = 1;
/// Sockaddr slot of a route's or address's netmask (`RTAX_NETMASK`).
const RTAX_NETMASK: usize = 2;
/// Sockaddr slot of an interface address, or a route's preferred source (`RTAX_IFA`).
const RTAX_IFA: usize = 5;
/// How many sockaddr slots a routing message can carry (`RTAX_MAX`).
const RTAX_COUNT: usize = 8;

/// Split the sockaddrs after a routing message header: slot `i` is present when bit `i` of
/// `present` is set. Each sockaddr starts with its length and is padded to 4 bytes; a zero length
/// takes 4 bytes. A list cut short is `None`: a message missing a netmask or gateway it claims
/// must not be read as a different route.
fn sockaddrs(mut bytes: &[u8], present: i32) -> Option<[Option<&[u8]>; RTAX_COUNT]> {
    let mut slots = [None; RTAX_COUNT];
    for (slot, entry) in slots.iter_mut().enumerate() {
        if present & (1 << slot) == 0 {
            continue;
        }
        let length = usize::from(*bytes.first()?);
        *entry = Some(bytes.get(..length)?);
        let padded = if length == 0 { 4 } else { (length + 3) & !3 };
        bytes = bytes.get(padded..).unwrap_or_default();
    }
    Some(slots)
}

/// The IP address in an `AF_INET` or `AF_INET6` sockaddr.
fn sockaddr_ip(sockaddr: &[u8]) -> Option<IpAddr> {
    match i32::from(*sockaddr.get(1)?) {
        libc::AF_INET => <[u8; 4]>::try_from(sockaddr.get(4..8)?)
            .ok()
            .map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
        libc::AF_INET6 => <[u8; 16]>::try_from(sockaddr.get(8..24)?)
            .ok()
            .map(|octets| IpAddr::V6(Ipv6Addr::from(octets))),
        _ => None,
    }
}

/// A netmask sockaddr for `address`'s family. The kernel trims trailing zero bytes from masks
/// (and may leave the family unset), so the mask is read zero-filled at the family's offset.
fn netmask_ip(sockaddr: &[u8], address: IpAddr) -> IpAddr {
    let tail = |offset: usize, out: &mut [u8]| {
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = sockaddr.get(offset + index).copied().unwrap_or(0);
        }
    };
    match address {
        IpAddr::V4(_) => {
            let mut octets = [0; 4];
            tail(4, &mut octets);
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        IpAddr::V6(_) => {
            let mut octets = [0; 16];
            tail(8, &mut octets);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// A route's gateway sockaddr: a next-hop address, or the interface of an `AF_LINK` gateway
/// (`sockaddr_dl`, whose index follows its length and family bytes).
fn gateway(sockaddr: &[u8]) -> Option<Gateway> {
    if i32::from(*sockaddr.get(1)?) == libc::AF_LINK {
        return u16_at(sockaddr, 2).map(Gateway::Link);
    }
    sockaddr_ip(sockaddr).map(Gateway::Address)
}

/// The IP of a `getifaddrs` entry, when it is an IPv4 or IPv6 address.
fn storage_ip(storage: &nix::sys::socket::SockaddrStorage) -> Option<IpAddr> {
    if let Some(v4) = storage.as_sockaddr_in() {
        return Some(IpAddr::V4(v4.ip()));
    }
    storage.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip()))
}

/// The prefix length of a contiguous netmask (the leading one bits).
fn prefix_length(mask: IpAddr) -> u8 {
    let ones = match mask {
        IpAddr::V4(mask) => u32::from(mask).leading_ones(),
        IpAddr::V6(mask) => u128::from(mask).leading_ones(),
    };
    u8::try_from(ones).unwrap_or(u8::MAX)
}

/// The host prefix length for `address`'s family.
fn full_prefix(address: IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}

/// A native-endian `u16` at `offset`, if the message is long enough.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let field = bytes.get(offset..offset + 2)?;
    Some(u16::from_ne_bytes([field[0], field[1]]))
}

/// A native-endian `i32` at `offset`, if the message is long enough.
fn i32_at(bytes: &[u8], offset: usize) -> Option<i32> {
    <[u8; 4]>::try_from(bytes.get(offset..offset + 4)?)
        .ok()
        .map(i32::from_ne_bytes)
}

/// Which routing messages count as an endpoint change, built byte for byte from the `libc`
/// layouts, plus root tests against the real kernel and the real-change proof harness.
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
