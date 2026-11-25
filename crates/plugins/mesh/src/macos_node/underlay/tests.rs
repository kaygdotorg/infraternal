//! Tests of the macOS underlay listener: which routing messages count as an endpoint change
//! (built byte for byte from the `libc` layouts), and, with root, the real kernel's messages
//! and the real-change proof harness.

use super::{PeerToPeerLinks, UnderlayAnnouncer, UnderlayBooks, UnderlayMonitor};
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

/// `awdl0`'s index in the synthetic messages; 13 is its index on the M1 Air J1028 captured.
const AWDL0: u16 = 13;
/// `llw0`'s index in the synthetic messages.
const LLW0: u16 = 14;
/// A peer-to-peer link that appears only after the books were built.
const AWDL1: u16 = 21;

/// The interfaces the synthetic messages name, so they never meet the test Mac's real ones.
fn synthetic_interfaces() -> Vec<(u16, String)> {
    [
        (EN0, "en0"),
        (UTUN, "utun9"),
        (AWDL0, "awdl0"),
        (LLW0, "llw0"),
        (AWDL1, "awdl1"),
    ]
    .into_iter()
    .map(|(index, name)| (index, name.to_owned()))
    .collect()
}

/// Empty books whose interface names come from [`synthetic_interfaces`].
fn books() -> UnderlayBooks {
    UnderlayBooks {
        peer_to_peer: PeerToPeerLinks {
            known: std::collections::BTreeMap::new(),
            list: synthetic_interfaces,
        },
        ..UnderlayBooks::default()
    }
}

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
    let mut books = books();
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

/// The messages macOS sends for nearby devices on its peer-to-peer Wi-Fi links never count.
/// They are the ones J1028 captured on an idle M1 Air on Wi-Fi (#260, `observe.txt` and
/// `observe-flap.txt`): an `fe80::` host route to a nearby device is added unscoped (index 0,
/// the link only in its gateway, `HOST|DONE|STATIC`) and deleted scoped to `awdl0`
/// (`0x3000844`, which adds `IFSCOPE` and the kernel's condemned bit), about once per 112 s; a
/// Wi-Fi flap adds `llw0` deletes, `fe80::` address churn and link flag changes. Before J1108
/// every delete was a change, so an idle Mac asked every session for a keepalive and restaled
/// every connected send each time.
#[test]
fn peer_to_peer_wifi_links_never_count() {
    let mut books = books();
    let nearby: Ipv6Addr = "fe80::a0f9:4cff:fe7c:36b5".parse().expect("address");
    let captured_add = libc::RTF_HOST | libc::RTF_DONE | libc::RTF_STATIC;
    assert_eq!(captured_add, 0x844, "the flags J1028 captured on the add");
    let captured_delete = 0x300_0844;
    let route_to =
        |kind, index, flags| route(kind, index, flags, 0, &[(0, v6(nearby)), (1, link(AWDL0))]);
    for _ in 0..48 {
        assert!(!books.observe(&route_to(libc::RTM_ADD, 0, captured_add), UTUN));
        assert!(!books.observe(&route_to(libc::RTM_DELETE, AWDL0, captured_delete), UTUN));
    }
    // A Wi-Fi flap: llw0's route delete, the links' fe80:: addresses and flags.
    let llw_route = route(
        libc::RTM_DELETE,
        LLW0,
        0x320_0004,
        0,
        &[(0, v6(nearby)), (1, link(LLW0))],
    );
    assert!(!books.observe(&llw_route, UTUN));
    let own: Ipv6Addr = "fe80::1c4d:2eff:fe11:9a01".parse().expect("address");
    for index in [AWDL0, LLW0] {
        let fe80 = [(2, mask(8, &[255; 8])), (5, v6(own))];
        assert!(!books.observe(&address(libc::RTM_DELADDR, index, &fe80), UTUN));
        assert!(!books.observe(&address(libc::RTM_NEWADDR, index, &fe80), UTUN));
        assert!(!books.observe(&interface(index, libc::IFF_UP), UTUN));
        assert!(!books.observe(&interface(index, libc::IFF_UP | libc::IFF_RUNNING), UTUN));
    }
    // A peer-to-peer link created after the books were built is recognised by its name too.
    assert!(!books.observe(&interface(AWDL1, libc::IFF_UP), UTUN));

    // The same messages on the Wi-Fi underlay still count: only the peer-to-peer links are
    // dropped.
    let en0_route = route(
        libc::RTM_DELETE,
        EN0,
        captured_delete,
        0,
        &[(0, v6(nearby)), (1, link(EN0))],
    );
    assert!(books.observe(&en0_route, UTUN));
    assert!(books.observe(&interface(EN0, libc::IFF_UP), UTUN));
}

/// Two routing messages exactly as the kernel sent them on an idle M1 Air on Wi-Fi (macOS
/// 27.2.1, J1108 capture on #260: 52 adds and 51 deletes like these in 24 minutes, awdl0 is
/// index 13 there). The add is unscoped (index 0) and names awdl0 only in its gateway's
/// `sockaddr_dl`; both carry the destination's scope embedded in the address (`fe80:d::`).
/// Neither counts; the same add with the gateway on en0 does.
#[test]
fn captured_awdl0_messages_never_count() {
    let add: &[u8] = &[
        0x8c, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x44, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x49, 0x01, 0x00, 0x00, 0x89, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x1c, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x0d, 0x00,
        0x00, 0x00, 0x00, 0xa4, 0x3d, 0x58, 0xff, 0xfe, 0x9f, 0x55, 0xe0, 0x0d, 0x00, 0x00, 0x00,
        0x14, 0x12, 0x0d, 0x00, 0x06, 0x00, 0x06, 0x00, 0xa6, 0x3d, 0x58, 0x9f, 0x55, 0xe0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let delete: &[u8] = &[
        0x8c, 0x00, 0x05, 0x02, 0x0d, 0x00, 0x00, 0x00, 0x44, 0x08, 0x00, 0x03, 0x03, 0x00, 0x00,
        0x00, 0x49, 0x01, 0x00, 0x00, 0x8a, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x1c, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x0d, 0x00,
        0x00, 0x00, 0x00, 0xf0, 0xa8, 0xbf, 0xff, 0xfe, 0x48, 0xc8, 0x53, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x12, 0x0d, 0x00, 0x06, 0x00, 0x06, 0x00, 0xf2, 0xa8, 0xbf, 0x48, 0xc8, 0x53, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let utun = 21;
    let mut books = books();
    assert!(!books.observe(add, utun), "the unscoped add");
    assert!(!books.observe(delete, utun), "the awdl0 delete");
    // The gateway's interface index sits after the header, the 28-byte destination and the
    // gateway's length and family bytes.
    let gateway_index = size_of::<libc::rt_msghdr>() + 28 + 2;
    assert_eq!(add[gateway_index..gateway_index + 2], AWDL0.to_ne_bytes());
    let mut on_en0 = add.to_vec();
    put(&mut on_en0, gateway_index, &EN0.to_ne_bytes());
    assert!(books.observe(&on_en0, utun), "the same route on en0 counts");
}

/// An index no interface has (a link already gone) is not peer-to-peer: its messages count, so
/// a doubt announces instead of hiding a change.
#[test]
fn an_unknown_interface_still_counts() {
    let mut books = books();
    assert!(books.observe(&interface(77, libc::IFF_UP), UTUN));
    assert!(
        !books.peer_to_peer.known.contains_key(&77),
        "not remembered"
    );
}

/// ARP and neighbour entries and per-destination clones come and go with ordinary traffic, and
/// lookups, misses and failed requests change nothing; none of them may wake the announce, or
/// an idle Mac on a busy LAN would announce all day (D81).
#[test]
fn traffic_lookups_and_failed_requests_never_count() {
    let mut books = books();
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
    let mut books = books();
    assert!(books.observe(&en0_address(libc::RTM_NEWADDR, [192, 168, 64, 51]), UTUN));
    assert!(!books.observe(&en0_address(libc::RTM_NEWADDR, [192, 168, 64, 51]), UTUN));
    assert!(books.observe(&en0_address(libc::RTM_NEWADDR, [192, 168, 64, 52]), UTUN));
    assert!(books.observe(&en0_address(libc::RTM_DELADDR, [192, 168, 64, 51]), UTUN));
}

/// IPv6 addresses are keyed by their full address and prefix, read from the kernel's trimmed
/// netmask, so a refresh of a SLAAC address is recognised.
#[test]
fn an_ipv6_address_refresh_does_not_count() {
    let mut books = books();
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
    let mut books = books();
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
    let mut books = books();
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
    let mut books = books();
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
    let mut books = books();
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
/// static peer (keepalive 25 s, D392). It runs the production worker loop so the probe
/// covers route-socket wakeups alongside candidate-walk scheduling. `J710_WATCH=off`
/// runs the same device without the worker as the control.
///
/// Root only (utun). Environment: `J710_PRIVATE_HEX`, `J710_PEER_PUBLIC_HEX`, `J710_ENDPOINT`
/// (peer `ip:port`), `J710_PORT`, `J710_ADDR` and `J710_PEER_ADDR` (tunnel IPv4 addresses),
/// `J710_IFNAME_FILE` (the utun name is written there once up). It runs until SIGTERM, so an
/// idle run adds no wakeup of its own. Run with
/// `cargo test --release --features agent --lib mac_underlay_announce_device -- --ignored`.
#[test]
#[ignore = "proof harness: root, a live peer and the J710_* environment"]
fn mac_underlay_announce_device() {
    use crate::macos_node::{MacUtun, OpenUtun, RuntimeState, walks};
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
        let admission = Arc::clone(&factory.admission);
        {
            let mut admission = factory.admission.write().await;
            admission.set_peers([crate::policy::model::PublicKey(peer_key)]);
            admission.set_configured_endpoints([endpoint]);
        }
        let udp = factory.send.clone();
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
        run(
            "/sbin/ifconfig",
            &[
                utun.name(),
                "inet",
                &var("J710_ADDR"),
                &peer_addr.to_string(),
                "mtu",
                "1280",
                "up",
            ],
        );
        std::fs::write(var("J710_IFNAME_FILE"), utun.name()).expect("publish the utun name");
        eprintln!("J710 harness up: watch={watch}");
        if !watch {
            stop.recv().await;
            device.stop().await;
            return;
        }
        let state = RuntimeState {
            udp,
            utun: Some(utun),
            device: Some(Arc::new(device)),
            handshakes: tokio::task::JoinSet::new(),
            walks: crate::candidate_walks::Walks::default(),
            config: Some(snapshot),
            // The harness's point-to-point address installs the route with the utun.
            routes: std::collections::BTreeSet::default(),
            route_mtus: std::collections::BTreeMap::default(),
            networks: std::collections::BTreeMap::default(),
            network_status: crate::macos_node::subnet::NetworkStatus::default(),
            interface_mtu: 1280,
            port,
            admission,
            confirmed_feed: crate::handshake_admission::ConfirmedEndpointFeed::default(),
            #[cfg(feature = "mesh-dns")]
            dns_resolver: None,
            #[cfg(feature = "mesh-dns")]
            dns_integration: crate::dns_integration::DnsIntegration::default(),
        };
        let (commands, receiver) = tokio::sync::mpsc::unbounded_channel();
        let worker = tokio::spawn(walks::run_worker(receiver, state));
        stop.recv().await;
        drop(commands);
        worker.await.expect("stop Mac worker");
    });
}
