//! Tests of the macOS underlay listener: which routing messages count as an endpoint change
//! (built byte for byte from the `libc` layouts), and, with root, the real kernel's messages
//! and the real-change proof harness.

use super::{UnderlayAnnouncer, UnderlayBooks, UnderlayMonitor};
use crate::underlay_announce::UnderlayAnnounce;
use nix::libc;
use std::{
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

/// Our utun's index in the synthetic messages.
const UTUN: u16 = 9;
/// The Ethernet underlay's index in the synthetic messages.
const EN0: u16 = 4;

/// Pad a sockaddr to the routing socket's 4-byte alignment.
fn padded(mut sockaddr: Vec<u8>) -> Vec<u8> {
    while !sockaddr.len().is_multiple_of(4) {
        sockaddr.push(0);
    }
    sockaddr
}

/// A `sockaddr_in` for `ip`.
fn v4(ip: [u8; 4]) -> Vec<u8> {
    let mut sockaddr = vec![16, u8::try_from(libc::AF_INET).expect("family"), 0, 0];
    sockaddr.extend(ip);
    sockaddr.extend([0; 8]);
    sockaddr
}

/// A `sockaddr_in6` for `ip`.
fn v6(ip: Ipv6Addr) -> Vec<u8> {
    let mut sockaddr = vec![28, u8::try_from(libc::AF_INET6).expect("family")];
    sockaddr.extend([0; 6]);
    sockaddr.extend(ip.octets());
    sockaddr.extend([0; 4]);
    sockaddr
}

/// A netmask the way the kernel sends it: trailing zero bytes trimmed, family unset.
fn mask(offset: usize, octets: &[u8]) -> Vec<u8> {
    let used = octets
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    let mut sockaddr = vec![0; offset];
    sockaddr.extend(&octets[..used]);
    sockaddr[0] = u8::try_from(sockaddr.len()).expect("mask length");
    sockaddr
}

/// A `sockaddr_dl` naming interface `index`, as a directly connected route's gateway.
fn link(index: u16) -> Vec<u8> {
    let mut sockaddr = vec![20, u8::try_from(libc::AF_LINK).expect("family")];
    sockaddr.extend(index.to_ne_bytes());
    sockaddr.extend([0; 16]);
    sockaddr
}

/// Put `value` at `offset` of `message`.
fn put(message: &mut [u8], offset: usize, value: &[u8]) {
    message[offset..offset + value.len()].copy_from_slice(value);
}

/// A routing message: a zeroed header of `header` bytes with the common prefix filled in, then
/// the sockaddrs in slot order. Returns the message and its `addrs` bitmask.
fn message(kind: i32, header: usize, sockaddrs: &[(usize, Vec<u8>)]) -> (Vec<u8>, i32) {
    let mut message = vec![0; header];
    message[2] = u8::try_from(libc::RTM_VERSION).expect("version");
    message[3] = u8::try_from(kind).expect("type");
    let mut present = 0;
    let mut sorted = sockaddrs.to_vec();
    sorted.sort_by_key(|(slot, _)| *slot);
    for (slot, sockaddr) in sorted {
        present |= 1 << slot;
        message.extend(padded(sockaddr));
    }
    let length = u16::try_from(message.len()).expect("length");
    put(&mut message, 0, &length.to_ne_bytes());
    (message, present)
}

/// An `rt_msghdr` route message.
fn route(kind: i32, index: u16, flags: i32, errno: i32, sockaddrs: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let (mut bytes, present) = message(kind, size_of::<libc::rt_msghdr>(), sockaddrs);
    put(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_index),
        &index.to_ne_bytes(),
    );
    put(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_flags),
        &flags.to_ne_bytes(),
    );
    put(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        &present.to_ne_bytes(),
    );
    put(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_errno),
        &errno.to_ne_bytes(),
    );
    bytes
}

/// An `ifa_msghdr` address message.
fn address(kind: i32, index: u16, sockaddrs: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let (mut bytes, present) = message(kind, size_of::<libc::ifa_msghdr>(), sockaddrs);
    put(
        &mut bytes,
        offset_of!(libc::ifa_msghdr, ifam_index),
        &index.to_ne_bytes(),
    );
    put(
        &mut bytes,
        offset_of!(libc::ifa_msghdr, ifam_addrs),
        &present.to_ne_bytes(),
    );
    bytes
}

/// An `if_msghdr` interface message.
fn interface(index: u16, flags: i32) -> Vec<u8> {
    let (mut bytes, _) = message(libc::RTM_IFINFO, size_of::<libc::if_msghdr>(), &[]);
    put(
        &mut bytes,
        offset_of!(libc::if_msghdr, ifm_index),
        &index.to_ne_bytes(),
    );
    put(
        &mut bytes,
        offset_of!(libc::if_msghdr, ifm_flags),
        &flags.to_ne_bytes(),
    );
    bytes
}

/// The default route through `gateway` on en0.
fn default_route(kind: i32, gateway: [u8; 4]) -> Vec<u8> {
    route(
        kind,
        EN0,
        libc::RTF_UP | libc::RTF_GATEWAY | libc::RTF_STATIC,
        0,
        &[(0, v4([0; 4])), (1, v4(gateway)), (2, mask(4, &[0; 4]))],
    )
}

/// en0's IPv4 address `ip`/24.
fn en0_address(kind: i32, ip: [u8; 4]) -> Vec<u8> {
    address(kind, EN0, &[(2, mask(4, &[255, 255, 255, 0])), (5, v4(ip))])
}

/// Our own utun's results never count: its peer host routes (by index, or by a link gateway
/// naming it while the index is unset), its address and its MTU or flag changes. Counting them
/// would make every apply announce to every live session.
#[test]
fn our_own_utun_never_counts() {
    let mut books = UnderlayBooks::default();
    let host = libc::RTF_UP | libc::RTF_HOST | libc::RTF_STATIC;
    let peer = [(0, v4([100, 64, 0, 7])), (1, link(UTUN))];
    for kind in [libc::RTM_ADD, libc::RTM_CHANGE, libc::RTM_DELETE] {
        assert!(!books.observe(&route(kind, UTUN, host, 0, &peer), UTUN));
        assert!(!books.observe(&route(kind, 0, host, 0, &peer), UTUN));
    }
    let own = [(2, mask(4, &[255; 4])), (5, v4([100, 64, 0, 1]))];
    assert!(!books.observe(&address(libc::RTM_NEWADDR, UTUN, &own), UTUN));
    assert!(!books.observe(&address(libc::RTM_DELADDR, UTUN, &own), UTUN));
    assert!(!books.observe(&interface(UTUN, libc::IFF_UP), UTUN));
}

/// ARP and neighbour entries and per-destination clones come and go with ordinary traffic, and
/// lookups, misses and failed requests change nothing; none of them may wake the announce, or
/// an idle Mac on a busy LAN would announce all day (D81).
#[test]
fn traffic_lookups_and_failed_requests_never_count() {
    let mut books = UnderlayBooks::default();
    let neighbour = [(0, v4([192, 168, 64, 7])), (1, link(EN0))];
    for flags in [libc::RTF_LLINFO, libc::RTF_WASCLONED] {
        let flags = flags | libc::RTF_UP | libc::RTF_HOST;
        assert!(!books.observe(&route(libc::RTM_ADD, EN0, flags, 0, &neighbour), UTUN));
        assert!(!books.observe(&route(libc::RTM_DELETE, EN0, flags, 0, &neighbour), UTUN));
    }
    for kind in [
        libc::RTM_GET,
        libc::RTM_MISS,
        libc::RTM_LOSING,
        libc::RTM_RESOLVE,
    ] {
        assert!(!books.observe(&route(kind, EN0, libc::RTF_UP, 0, &neighbour), UTUN));
    }
    let failed = route(
        libc::RTM_ADD,
        EN0,
        libc::RTF_UP | libc::RTF_GATEWAY,
        libc::EEXIST,
        &[
            (0, v4([0; 4])),
            (1, v4([192, 168, 64, 1])),
            (2, mask(4, &[0; 4])),
        ],
    );
    assert!(!books.observe(&failed, UTUN));
}

/// A new address counts; the same address reported again (a DHCP renewal re-applying it, a
/// lifetime refresh) does not; its removal does.
#[test]
fn a_new_address_counts_and_its_refresh_does_not() {
    let mut books = UnderlayBooks::default();
    assert!(books.observe(&en0_address(libc::RTM_NEWADDR, [192, 168, 64, 51]), UTUN));
    assert!(!books.observe(&en0_address(libc::RTM_NEWADDR, [192, 168, 64, 51]), UTUN));
    assert!(books.observe(&en0_address(libc::RTM_NEWADDR, [192, 168, 64, 52]), UTUN));
    assert!(books.observe(&en0_address(libc::RTM_DELADDR, [192, 168, 64, 51]), UTUN));
}

/// IPv6 addresses are keyed by their full address and prefix, read from the kernel's trimmed
/// netmask, so a refresh of a SLAAC address is recognised.
#[test]
fn an_ipv6_address_refresh_does_not_count() {
    let mut books = UnderlayBooks::default();
    let ip: Ipv6Addr = "2001:db8:64::51".parse().expect("address");
    let message = address(
        libc::RTM_NEWADDR,
        EN0,
        &[(2, mask(8, &[255; 8])), (5, v6(ip))],
    );
    assert!(books.observe(&message, UTUN));
    assert!(!books.observe(&message, UTUN));
    let key = (EN0, IpAddr::V6(ip), 64);
    assert!(!books.addresses.present(key, ()), "the mask is read as /64");
}

/// A route change that can move our source address or next hop counts; the same route again
/// does not, nor does a change only to its lifetime; its removal does.
#[test]
fn a_route_change_counts_and_its_repeat_does_not() {
    let mut books = UnderlayBooks::default();
    assert!(books.observe(&default_route(libc::RTM_ADD, [192, 168, 64, 1]), UTUN));
    assert!(!books.observe(&default_route(libc::RTM_CHANGE, [192, 168, 64, 1]), UTUN));
    let mut refreshed = default_route(libc::RTM_CHANGE, [192, 168, 64, 1]);
    let expire = offset_of!(libc::rt_msghdr, rtm_rmx) + offset_of!(libc::rt_metrics, rmx_expire);
    put(&mut refreshed, expire, &1_800_i32.to_ne_bytes());
    assert!(
        !books.observe(&refreshed, UTUN),
        "a lifetime is not a change"
    );
    assert!(books.observe(&default_route(libc::RTM_CHANGE, [192, 168, 64, 254]), UTUN));
    assert!(books.observe(&default_route(libc::RTM_DELETE, [192, 168, 64, 254]), UTUN));
}

/// A route that keeps its gateway but picks another source address (`-ifa`) moves our endpoint
/// as peers see it, so it counts.
#[test]
fn a_new_source_address_on_a_route_counts() {
    let mut books = UnderlayBooks::default();
    let host = libc::RTF_UP | libc::RTF_HOST | libc::RTF_STATIC;
    let via = |source: [u8; 4]| {
        route(
            libc::RTM_CHANGE,
            EN0,
            host,
            0,
            &[(0, v4([192, 168, 64, 7])), (1, link(EN0)), (5, v4(source))],
        )
    };
    assert!(books.observe(&via([192, 168, 64, 50]), UTUN));
    assert!(!books.observe(&via([192, 168, 64, 50]), UTUN));
    assert!(books.observe(&via([192, 168, 64, 51]), UTUN));
}

/// A link going down or up counts; a flag change that cannot move traffic (promiscuous mode)
/// and an unchanged report do not.
#[test]
fn a_link_state_change_counts_and_a_repeat_does_not() {
    let mut books = UnderlayBooks::default();
    let up = libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_BROADCAST;
    assert!(books.observe(&interface(EN0, up), UTUN));
    assert!(!books.observe(&interface(EN0, up), UTUN));
    assert!(!books.observe(&interface(EN0, up | libc::IFF_PROMISC), UTUN));
    assert!(
        books.observe(&interface(EN0, libc::IFF_UP), UTUN),
        "carrier lost"
    );
}

/// Truncated or foreign-version messages are ignored, never read past their end.
#[test]
fn malformed_messages_never_count() {
    let mut books = UnderlayBooks::default();
    let whole = default_route(libc::RTM_ADD, [192, 168, 64, 1]);
    for length in 0..whole.len() {
        assert!(!books.observe(&whole[..length], UTUN), "{length} bytes");
    }
    let mut future = whole.clone();
    future[2] = 99;
    assert!(!books.observe(&future, UTUN));
}

/// The host's current addresses seed the book, so a refresh of one that existed before the
/// listener opened is not a change (here loopback's 127.0.0.1/8, present on every Mac).
#[test]
fn addresses_present_at_open_are_known() {
    let lo0 = u16::try_from(nix::net::if_::if_nametoindex("lo0").expect("lo0")).expect("index");
    let mut books = UnderlayBooks::current(UTUN).expect("read the host's addresses");
    let refresh = address(
        libc::RTM_NEWADDR,
        lo0,
        &[(2, mask(4, &[255, 0, 0, 0])), (5, v4([127, 0, 0, 1]))],
    );
    assert!(!books.observe(&refresh, UTUN));
}

/// D81: a node whose listener could not open never announces and arms no timer (an hour on the
/// paused clock).
#[tokio::test(start_paused = true)]
async fn a_node_without_a_listener_never_announces() {
    let mut announcer = UnderlayAnnouncer::start("utun-no-such-interface");
    assert!(!announcer.is_listening());
    let quiet = tokio::time::timeout(Duration::from_secs(3_600), announcer.due()).await;
    assert!(quiet.is_err(), "nothing changed, so nothing is announced");
}

/// Run `command` and fail the test if it does not succeed.
fn run(command: &str, arguments: &[&str]) {
    let status = std::process::Command::new(command)
        .args(arguments)
        .status()
        .expect("start the network utility");
    assert!(status.success(), "{command} {arguments:?} failed");
}

/// Read every routing message the kernel sends within `window`, and say whether any of them
/// woke the announce.
async fn announced_within(
    monitor: &mut UnderlayMonitor,
    announce: &UnderlayAnnounce,
    window: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(result) = tokio::time::timeout_at(deadline, monitor.next_batch()).await {
        result.expect("read routing messages");
    }
    announce.take_for_test()
}

/// The real kernel's messages (root: it changes loopback addresses and routes, and opens a
/// utun). A new address, its removal and a route change on another interface announce; the
/// same alias applied again, a host route through our own utun, and an idle second announce
/// nothing. Run with `sudo -E cargo test --features agent --lib underlay -- --ignored`.
#[tokio::test(flavor = "current_thread")]
#[ignore = "root: changes loopback addresses and routes on this Mac"]
async fn the_kernel_reports_real_changes_only() {
    // The utun's packet filter; this test sends no tunnel traffic, so its policy doesn't matter.
    let filter = Arc::new(
        crate::packet_filter::PacketFilter::new(
            &crate::macos_node::tests::config(),
            infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
        )
        .expect("compile filter"),
    );
    let utun = crate::macos_node::MacUtun::from_open(
        crate::macos_node::OpenUtun::open().expect("open a utun (root)"),
        filter,
    )
    .expect("register the utun");
    let name = utun.name().to_owned();
    let announce = Arc::new(UnderlayAnnounce::default());
    let mut monitor = UnderlayMonitor::open(&name, Arc::clone(&announce)).expect("open");
    assert!(announce.take_for_test(), "opening announces once");
    let window = Duration::from_millis(500);
    assert!(
        !announced_within(&mut monitor, &announce, window).await,
        "idle"
    );

    run(
        "/sbin/ifconfig",
        &["lo0", "alias", "127.0.0.77", "255.255.255.255"],
    );
    let added = announced_within(&mut monitor, &announce, window).await;
    run(
        "/sbin/ifconfig",
        &["lo0", "alias", "127.0.0.77", "255.255.255.255"],
    );
    let reapplied = announced_within(&mut monitor, &announce, window).await;
    run("/sbin/ifconfig", &["lo0", "-alias", "127.0.0.77"]);
    let removed = announced_within(&mut monitor, &announce, window).await;

    run(
        "/sbin/ifconfig",
        &[&name, "inet", "100.64.71.1", "100.64.71.1", "up"],
    );
    run(
        "/sbin/route",
        &["-qn", "add", "-host", "100.64.71.7", "-interface", &name],
    );
    let own_route = announced_within(&mut monitor, &announce, window).await;
    run(
        "/sbin/route",
        &["-qn", "delete", "-host", "100.64.71.7", "-interface", &name],
    );
    let own_delete = announced_within(&mut monitor, &announce, window).await;

    run(
        "/sbin/route",
        &["-qn", "add", "-net", "198.18.71.0/24", "127.0.0.1"],
    );
    let route_added = announced_within(&mut monitor, &announce, window).await;
    run("/sbin/route", &["-qn", "get", "198.18.71.9"]);
    let lookup = announced_within(&mut monitor, &announce, window).await;
    run(
        "/sbin/route",
        &["-qn", "delete", "-net", "198.18.71.0/24", "127.0.0.1"],
    );
    let route_removed = announced_within(&mut monitor, &announce, window).await;
    let idle = announced_within(&mut monitor, &announce, Duration::from_secs(2)).await;

    assert!(added, "a new address announces");
    assert!(!reapplied, "re-applying the same address is a refresh");
    assert!(removed, "a removed address announces");
    assert!(
        !own_route && !own_delete,
        "our own utun's routes never announce"
    );
    assert!(
        route_added && route_removed,
        "another interface's routes announce"
    );
    assert!(!lookup, "a route lookup is not a change");
    assert!(!idle, "nothing changed, so nothing is announced");
}

/// Decode a 64-character hex `WireGuard` key from the harness environment.
fn harness_key(name: &str) -> [u8; 32] {
    let hex = std::env::var(name).expect("harness key variable");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex key"))
        .collect();
    bytes.try_into().expect("32-byte key")
}

/// The real-change proof's Mac side (#483 J710): this module's utun, the bound UDP factory and
/// the pinned `GotaTun` device on a current-thread runtime, as the worker builds them, with one
/// static peer (keepalive 25 s, D392) and the worker's own announce path
/// ([`UnderlayAnnouncer`] plus `request_keepalives`). `J710_WATCH=off` leaves the announce path
/// out, which is the node before this change; nothing else differs.
///
/// Root only (utun). Environment: `J710_PRIVATE_HEX`, `J710_PEER_PUBLIC_HEX`, `J710_ENDPOINT`
/// (peer `ip:port`), `J710_PORT`, `J710_ADDR` and `J710_PEER_ADDR` (tunnel IPv4 addresses),
/// `J710_IFNAME_FILE` (the utun name is written there once up). It runs until SIGTERM, so an
/// idle run adds no wakeup of its own. Run with
/// `cargo test --release --features agent --lib mac_underlay_announce_device -- --ignored`.
#[test]
#[ignore = "proof harness: root, a live peer and the J710_* environment"]
fn mac_underlay_announce_device() {
    use crate::macos_node::{MacUtun, OpenUtun};
    use gotatun::{
        device::{DeviceBuilder, Peer as WireGuardPeer},
        x25519::{PublicKey, StaticSecret},
    };
    let var = |name: &str| std::env::var(name).expect("harness variable");
    let port: u16 = var("J710_PORT").parse().expect("port");
    let endpoint: std::net::SocketAddr = var("J710_ENDPOINT").parse().expect("endpoint");
    let peer_addr: IpAddr = var("J710_PEER_ADDR").parse().expect("peer address");
    let watch = std::env::var("J710_WATCH").as_deref() != Ok("off");
    let peer_key = harness_key("J710_PEER_PUBLIC_HEX");
    // The worker's packet filter, from a one-peer snapshot that grants the harness peer every
    // port both ways (an empty filter would deny all tunnel traffic).
    let mut snapshot = crate::macos_node::tests::config();
    snapshot.addresses.ipv4 = var("J710_ADDR").parse().expect("tunnel IPv4");
    for policy in snapshot.peers.values_mut() {
        policy.peer.key = crate::policy::model::PublicKey(peer_key);
        policy.peer.addresses.ipv4 = var("J710_PEER_ADDR").parse().expect("peer IPv4");
        policy.peer.endpoint = Some(endpoint);
    }
    let filter = Arc::new(
        crate::packet_filter::PacketFilter::new(
            &snapshot,
            infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
        )
        .expect("compile filter"),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut stop = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        let utun =
            MacUtun::from_open(OpenUtun::open().expect("utun"), filter).expect("register utun");
        // The worker's socket, with its handshake guard admitting the one harness peer.
        let private_key = StaticSecret::from(harness_key("J710_PRIVATE_HEX"));
        let (factory, port) = crate::macos_node::bind_udp(
            crate::listen_port::Request {
                port,
                allow_fallback: false,
            },
            private_key.clone(),
        )
        .await
        .expect("bind");
        {
            let mut admission = factory.admission.write().await;
            admission.set_peers([crate::policy::model::PublicKey(peer_key)]);
            admission.set_configured_endpoints([endpoint]);
        }
        let mut peer = WireGuardPeer::new(PublicKey::from(peer_key))
            .with_allowed_ips(vec![ipnetwork::IpNetwork::new(peer_addr, 32).expect("net")]);
        peer.endpoint = Some(endpoint);
        peer.keepalive = Some(25);
        let device = DeviceBuilder::new()
            .with_udp(factory)
            .with_private_key(private_key)
            .with_listen_port(port)
            .with_ip_pair(utun.sender(), utun.receiver())
            .with_peers(vec![peer])
            .build()
            .await
            .expect("device");
        utun.set_mtu(1280);
        run("/sbin/ifconfig", &[
            utun.name(),
            "inet",
            &var("J710_ADDR"),
            &peer_addr.to_string(),
            "mtu",
            "1280",
            "up",
        ]);
        std::fs::write(var("J710_IFNAME_FILE"), utun.name()).expect("publish the utun name");
        let mut announcer = watch.then(|| UnderlayAnnouncer::start(utun.name()));
        eprintln!("J710 harness up: watch={watch}");
        loop {
            tokio::select! {
                _ = stop.recv() => break,
                () = super::super::announcement_due(announcer.as_mut()) => {
                    let sessions = device.request_keepalives().await;
                    eprintln!("J710 announce {:?} sessions={sessions}", std::time::SystemTime::now());
                }
            }
        }
        device.stop().await;
    });
}
