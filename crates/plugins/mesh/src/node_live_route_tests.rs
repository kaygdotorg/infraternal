//! Live-endpoint route refresh tests for the node's peer host routes (#489).
//!
//! They cover the budgets derived from authenticated endpoints `GotaTun` learns: writes go only to
//! the proven link, only changed budgets are rewritten, a relay's shim never chooses a direct
//! budget, and a steady refresh probes the underlay only after it changed. Most need root inside
//! a disposable network namespace, so they are `#[ignore]`d and run under `unshare -Urnm`.
//! They live outside `node.rs` to keep that file under the repository's size limit.

#![expect(
    clippy::expect_used,
    reason = "namespace fixtures identify setup failures precisely"
)]

use super::*;

/// Run one namespace-local route command for the foreign-interface review proof.
fn review_route_command(args: &[&str]) -> String {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .expect("ip command");
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("ip output")
}

/// Retained peer inventory must not authorize writes after a foreign link replaces our TUN.
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn review_live_endpoint_refresh_refuses_foreign_interface() {
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    review_route_command(&["link", "add", "infraternal0", "type", "dummy"]);
    review_route_command(&["link", "set", "infraternal0", "up"]);
    review_route_command(&["address", "add", "10.254.0.1/32", "dev", "infraternal0"]);
    review_route_command(&[
        "-6",
        "address",
        "add",
        "fd01::1/128",
        "dev",
        "infraternal0",
        "nodad",
    ]);
    review_route_command(&[
        "route",
        "add",
        "10.254.0.2/32",
        "dev",
        "infraternal0",
        "mtu",
        "1400",
    ]);
    review_route_command(&[
        "-6",
        "route",
        "add",
        "fd01::2/128",
        "dev",
        "infraternal0",
        "mtu",
        "1400",
    ]);
    let key = PublicKey([7; 32]);
    let peer = crate::dataplane::Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("IPv4"),
            ipv6: "fd01::2".parse().expect("IPv6"),
        },
        endpoint: Some("192.0.2.2:51820".parse().expect("configured endpoint")),
    };
    // This inventory can survive a person's deletion/replacement of the live TUN. The
    // replacement has no ownership alias, so its routes are outside this node's authority.
    let learned = review_learned_underlay(9000);
    let state = Mutex::new(PeerRouteState::default());
    lock_route_state(&state).set_peers(&[peer]);
    let before = review_route_command(&["route", "show", "exact", "10.254.0.2/32"]);
    let before_v6 = review_route_command(&["-6", "route", "show", "exact", "fd01::2/128"]);
    let result = update_live_peer_endpoints(&state, &[(key, Some(learned))]);
    let after = review_route_command(&["route", "show", "exact", "10.254.0.2/32"]);
    let after_v6 = review_route_command(&["-6", "route", "show", "exact", "fd01::2/128"]);
    eprintln!(
        "REVIEW foreign link result={result:?} IPv4 before={before:?} after={after:?} IPv6 before={before_v6:?} after={after_v6:?}"
    );
    assert_eq!(
        after, before,
        "endpoint callback must leave a foreign interface's IPv4 route alone"
    );
    assert_eq!(
        after_v6, before_v6,
        "endpoint callback must leave a foreign interface's IPv6 route alone"
    );
}

/// Create a persistent TUN under the shared name, mark it as `owner`'s, and give both peer
/// host routes a 1400-byte budget; return the link identity the kernel reports for it.
fn review_marked_tun(owner: crate::policy::model::PublicKey) -> crate::wireguard::ActiveLink {
    review_route_command(&["tuntap", "add", "dev", "infraternal0", "mode", "tun"]);
    Device::mark_tun(owner).expect("mark the TUN as this node's");
    review_route_command(&["link", "set", "infraternal0", "up"]);
    review_route_command(&[
        "route",
        "add",
        "10.254.0.2/32",
        "dev",
        "infraternal0",
        "mtu",
        "1400",
    ]);
    review_route_command(&[
        "-6",
        "route",
        "add",
        "fd01::2/128",
        "dev",
        "infraternal0",
        "mtu",
        "1400",
    ]);
    Device::active_link()
        .expect("read the mesh link")
        .expect("the marked TUN holds the shared name")
}

/// Add a dummy underlay `under0` at `mtu` that carries the learned endpoint
/// `198.51.100.2`, and return that endpoint.
///
/// Learned endpoints must be remote addresses: a loopback one never chooses a route budget
/// (#489 J552 P2-1), so tests change this link's MTU to change the derived budget.
fn review_learned_underlay(mtu: u32) -> std::net::SocketAddr {
    review_route_command(&["link", "add", "under0", "type", "dummy"]);
    review_route_command(&["link", "set", "under0", "mtu", &mtu.to_string(), "up"]);
    review_route_command(&["address", "add", "198.51.100.1/24", "dev", "under0"]);
    "198.51.100.2:51820".parse().expect("learned endpoint")
}

/// Read both peer host routes, IPv4 then IPv6, as `ip` prints them.
fn review_peer_routes() -> (String, String) {
    (
        review_route_command(&["route", "show", "exact", "10.254.0.2/32"]),
        review_route_command(&["-6", "route", "show", "exact", "fd01::2/128"]),
    )
}

/// A live-endpoint refresh writes only to the link the route-repair worker proved, never to a
/// replacement that took the shared name with this node's own marker (#489 J549 P2).
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn live_endpoint_refresh_stays_on_the_proven_link() {
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    let owner = PublicKey([9; 32]);
    let proven = review_marked_tun(owner);
    let key = PublicKey([7; 32]);
    let peer = crate::dataplane::Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("IPv4"),
            ipv6: "fd01::2".parse().expect("IPv6"),
        },
        endpoint: Some("192.0.2.2:51820".parse().expect("configured endpoint")),
    };
    let state = Mutex::new(PeerRouteState::default());
    {
        let mut route_state = lock_route_state(&state);
        route_state.set_peers(std::slice::from_ref(&peer));
        route_state.link = Some(proven);
    }

    // Control: the proven link takes the learned endpoint's much larger budget.
    let learned = review_learned_underlay(9000);
    update_live_peer_endpoints(&state, &[(key, Some(learned))]).expect("refresh the proven link");
    let (proven_v4, proven_v6) = review_peer_routes();
    assert!(
        proven_v4.contains("proto 250") && !proven_v4.contains("mtu 1400"),
        "{proven_v4}"
    );
    assert!(
        proven_v6.contains("proto 250") && !proven_v6.contains("mtu 1400"),
        "{proven_v6}"
    );

    // Replace the link: same name, same owner marker, a new interface index.
    review_route_command(&["link", "del", "infraternal0"]);
    let replacement = review_marked_tun(owner);
    assert_ne!(replacement.ifindex, proven.ifindex);
    assert_eq!(replacement.owner, proven.owner);
    // Change the budget too, so the refresh has something to write and must refuse it.
    review_route_command(&["link", "set", "under0", "mtu", "4000"]);
    let before = review_peer_routes();
    let result = update_live_peer_endpoints(&state, &[(key, Some(learned))]);
    let after = review_peer_routes();
    eprintln!(
        "REVIEW marked replacement proven={} replacement={} result={result:?} before={before:?} after={after:?}",
        proven.ifindex, replacement.ifindex
    );
    assert!(
        result.is_err(),
        "a refresh bound to a replaced link must refuse"
    );
    assert_eq!(
        after, before,
        "a marked replacement link's routes must stay untouched"
    );
}

/// Repeated refreshes at an unchanged budget write nothing; a budget change writes once
/// (#489 J549 P2). The returned count is the number of peers whose two routes were replaced.
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn live_endpoint_refresh_writes_only_changed_budgets() {
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    let proven = review_marked_tun(PublicKey([9; 32]));
    let endpoint = review_learned_underlay(1500);
    let peers: Vec<_> = (2_u8..6)
        .map(|id| crate::dataplane::Peer {
            key: PublicKey([id; 32]),
            previous_key: None,
            previous_active: false,
            addresses: Addresses {
                ipv4: std::net::Ipv4Addr::new(10, 254, 0, id),
                ipv6: format!("fd01::{id}").parse().expect("IPv6"),
            },
            endpoint: Some("192.0.2.2:51820".parse().expect("configured endpoint")),
        })
        .collect();
    let state = Mutex::new(PeerRouteState::default());
    {
        let mut route_state = lock_route_state(&state);
        route_state.set_peers(&peers);
        route_state.link = Some(proven);
    }
    let learned: Vec<_> = peers
        .iter()
        .map(|peer| (peer.key, Some(endpoint)))
        .collect();
    let mut writes = Vec::new();
    for _ in 0..4 {
        writes.push(update_live_peer_endpoints(&state, &learned).expect("steady refresh"));
    }
    // A larger underlay MTU changes every peer's budget at the same endpoint.
    review_route_command(&["link", "set", "under0", "mtu", "9000"]);
    for _ in 0..4 {
        writes.push(update_live_peer_endpoints(&state, &learned).expect("refresh after change"));
    }
    let (route_v4, route_v6) = review_peer_routes();
    eprintln!("REVIEW peer writes per refresh={writes:?} routes={route_v4:?} {route_v6:?}");
    assert_eq!(
        writes,
        [4, 0, 0, 0, 4, 0, 0, 0],
        "only the first refresh and the one after the budget change may write"
    );
    assert!(route_v4.contains("mtu 8912"), "{route_v4}");
    assert!(route_v6.contains("mtu 8912"), "{route_v6}");
}

/// A relay keeps its budget through live refreshes, and endpoints confirmed while it carries
/// the peer are not recorded: they are the relay shim's, never a direct path (#489 J552 P2-1).
/// A direct endpoint confirmed after the relay ends is used again.
#[test]
fn live_endpoint_refresh_preserves_relay_budget_for_direct_fallback() {
    use crate::policy::model::Addresses;

    let key = crate::policy::model::PublicKey([7; 32]);
    let configured: std::net::SocketAddr = "192.0.2.2:51820".parse().expect("configured endpoint");
    let learned: std::net::SocketAddr = "198.51.100.2:51820".parse().expect("learned endpoint");
    let peer = crate::dataplane::Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("mesh IPv4"),
            ipv6: "fd01::2".parse().expect("mesh IPv6"),
        },
        endpoint: Some(configured),
    };
    let state = Mutex::new(PeerRouteState::default());
    {
        let mut route_state = lock_route_state(&state);
        route_state.set_peers(std::slice::from_ref(&peer));
        route_state.overrides.insert(key, 1392);
    }

    update_live_peer_endpoints(&state, &[(key, Some(learned))])
        .expect("relay owns the route, so nothing is written");
    {
        let route_state = lock_route_state(&state);
        assert_eq!(route_state.overrides.get(&key), Some(&1392));
        assert!(route_state.live_endpoints.is_empty());
        assert_eq!(route_state.route_peer(&peer).endpoint, Some(configured));
    }

    // Once the relay is gone, a confirmed direct endpoint chooses the budget again. A
    // loopback one, such as the shim GotaTun may still report, never does.
    lock_route_state(&state).overrides.remove(&key);
    let shim: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("relay shim");
    let mapped_shim: std::net::SocketAddr = "[::ffff:127.0.0.1]:40000"
        .parse()
        .expect("mapped relay shim");
    for local in [shim, mapped_shim] {
        let mut route_state = lock_route_state(&state);
        route_state.live_endpoints.insert(key, local);
        assert_eq!(route_state.route_peer(&peer).endpoint, Some(configured));
        route_state.live_endpoints.clear();
    }
    let mut route_state = lock_route_state(&state);
    route_state.live_endpoints.insert(key, learned);
    assert_eq!(route_state.route_peer(&peer).endpoint, Some(learned));
}

/// J552 review (#489): when a relay ends, the direct-path budget must come from a direct
/// endpoint, never from the relay shim's address.
///
/// While a relay carries a peer, the relay shim delivers its datagrams to `GotaTun` from a
/// loopback socket (`relay_path`, bound to `127.0.0.1:0`). That traffic is authenticated, so
/// the fork's `confirmed_endpoint` becomes the shim's loopback address and the live refresh
/// records it in `live_endpoints`. When the relay is lost, `update_relay_route_mtu(None)`
/// derives the direct budget from `route_peer`, which is that loopback address, so the
/// route budget is the loopback MTU (65456) instead of the configured endpoint's (1408 on a
/// 1500-byte underlay). The next live refresh keeps writing 65456 until a direct data packet
/// moves the confirmed endpoint. Before J502, the fallback used the configured endpoint.
#[cfg(feature = "relay")]
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn review_j552_relay_fallback_does_not_derive_budget_from_relay_shim() {
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    // The direct underlay toward the configured endpoint: 1500 bytes, so a 1408 budget.
    review_route_command(&["link", "add", "under0", "type", "dummy"]);
    review_route_command(&["link", "set", "under0", "mtu", "1500", "up"]);
    review_route_command(&["address", "add", "192.0.2.1/24", "dev", "under0"]);
    let proven = review_marked_tun(PublicKey([9; 32]));
    let key = PublicKey([7; 32]);
    let peer = crate::dataplane::Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("IPv4"),
            ipv6: "fd01::2".parse().expect("IPv6"),
        },
        endpoint: Some("192.0.2.2:51820".parse().expect("configured endpoint")),
    };
    let state = Mutex::new(PeerRouteState::default());
    {
        let mut route_state = lock_route_state(&state);
        route_state.set_peers(std::slice::from_ref(&peer));
        route_state.link = Some(proven);
    }
    // A relay takes the peer: its budget overrides the direct one.
    update_relay_route_mtu(&state, key, Some(1392)).expect("install the relay budget");
    // Relayed data reaches GotaTun from the shim's loopback socket, so that is the
    // confirmed endpoint the worker reports while the relay carries traffic.
    let shim: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("relay shim source");
    update_live_peer_endpoints(&state, &[(key, Some(shim))]).expect("relayed refresh");

    // The relay is lost: fall back to the direct budget.
    update_relay_route_mtu(&state, key, None).expect("direct-path fallback");
    let (fallback_v4, fallback_v6) = review_peer_routes();
    // GotaTun still reports the shim until a direct data packet arrives.
    let refresh = update_live_peer_endpoints(&state, &[(key, Some(shim))]);
    let (refresh_v4, refresh_v6) = review_peer_routes();
    eprintln!(
        "REVIEW J552 relay fallback: fallback v4={fallback_v4:?} v6={fallback_v6:?}; \
         refresh={refresh:?} v4={refresh_v4:?} v6={refresh_v6:?}"
    );
    for route in [&fallback_v4, &fallback_v6, &refresh_v4, &refresh_v6] {
        assert!(
            route.contains("mtu 1408"),
            "the direct fallback must use the configured endpoint's 1408 budget, not the \
             relay shim's loopback budget: {route}"
        );
    }
}

/// J552 review (#489): the cost of one steady live refresh at mesh scale, as a receipt.
///
/// Under any continuous traffic, the `GotaTun` worker refreshes up to four times a second
/// and each refresh probes every installed peer's underlay route (one route and one link
/// netlink request, each on a fresh socket) while holding the shared route-state mutex
/// that relay callbacks, route repair and configuration also take. This prints the time
/// of steady refreshes (no route writes) for 4,096 peers with distinct endpoints, or for
/// `J552_PEERS` peers when that is set. It asserts only the write count, never speed
/// (ENGINEERING P3); the numbers are the receipt.
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn review_j552_steady_refresh_cost_at_4096_peers() {
    use crate::policy::model::{Addresses, PublicKey};
    let peer_count: u16 = std::env::var("J552_PEERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4096);
    review_route_command(&["link", "set", "lo", "up"]);
    review_route_command(&["link", "add", "under0", "type", "dummy"]);
    review_route_command(&["link", "set", "under0", "mtu", "1500", "up"]);
    review_route_command(&["address", "add", "100.64.0.1/10", "dev", "under0"]);
    review_marked_tun(PublicKey([0xee; 32]));
    let mut peers = Vec::new();
    let mut learned = Vec::new();
    for index in 0..peer_count {
        let [high, low] = index.to_be_bytes();
        let mut key = [0_u8; 32];
        key[..2].copy_from_slice(&index.to_be_bytes());
        key[31] = 1;
        let key = PublicKey(key);
        peers.push(crate::dataplane::Peer {
            key,
            previous_key: None,
            previous_active: false,
            addresses: Addresses {
                ipv4: std::net::Ipv4Addr::new(10, 200, high, low),
                ipv6: format!("fd02::{:x}", index + 2).parse().expect("IPv6"),
            },
            endpoint: Some(std::net::SocketAddr::from(([192, 0, 2, 2], 51820))),
        });
        learned.push((
            key,
            Some(std::net::SocketAddr::from(([100, 65, high, low], 51820))),
        ));
    }
    let state = Arc::new(Mutex::new(PeerRouteState::default()));
    lock_route_state(&state).set_peers(&peers);
    // Run the route-repair worker as a node does: it proves and publishes the link, and its
    // route listener is the one a running node has while refreshes happen (J571).
    let mut worker = RouteRepairWorker::start(Arc::clone(&state)).expect("start route repair");
    let first = std::time::Instant::now();
    let written = update_live_peer_endpoints(&state, &learned).expect("first refresh");
    let first = first.elapsed();
    assert_eq!(written, usize::from(peer_count));
    let mut steady = Vec::new();
    for _ in 0..8 {
        let started = std::time::Instant::now();
        let written = update_live_peer_endpoints(&state, &learned).expect("steady refresh");
        steady.push(started.elapsed());
        assert_eq!(written, 0, "a steady refresh writes nothing");
    }
    steady.sort();
    let median = steady[steady.len() / 2];
    eprintln!(
        "METRIC j552_live_refresh peers={peer_count} first_ms={:.1} steady_median_ms={:.1} \
         steady_max_ms={:.1} lock_held_per_second_at_4hz_ms={:.1}",
        first.as_secs_f64() * 1e3,
        median.as_secs_f64() * 1e3,
        steady[steady.len() - 1].as_secs_f64() * 1e3,
        median.as_secs_f64() * 4e3,
    );
    worker.stop();
}
