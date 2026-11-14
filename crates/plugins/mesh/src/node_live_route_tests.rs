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

/// A steady refresh looks no underlay route up; an underlay MTU change, announced by the
/// kernel to the route-repair worker's listener, makes the next refresh re-derive and rewrite
/// every peer (#489 J552 P2-2). Lookups are counted, never timed (ENGINEERING P3).
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn live_endpoint_refresh_probes_only_after_underlay_changes() {
    use crate::mesh_mtu::ROUTE_LOOKUPS;
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    review_marked_tun(PublicKey([9; 32]));
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
    let learned: Vec<_> = peers
        .iter()
        .map(|peer| (peer.key, Some(endpoint)))
        .collect();
    let state = Arc::new(Mutex::new(PeerRouteState::default()));
    lock_route_state(&state).set_peers(&peers);
    let mut worker = RouteRepairWorker::start(Arc::clone(&state)).expect("start route repair");
    // Count lookups and writes of one refresh.
    let refresh = || {
        ROUTE_LOOKUPS.with(|lookups| lookups.set(0));
        let written = update_live_peer_endpoints(&state, &learned).expect("refresh");
        (ROUTE_LOOKUPS.with(std::cell::Cell::get), written)
    };
    let first = refresh();
    // Our own peer-route writes must not count as underlay changes.
    let steady: Vec<_> = (0..4).map(|_| refresh()).collect();

    review_route_command(&["link", "set", "under0", "mtu", "9000"]);
    // The listener sees the kernel's announcement asynchronously: refresh until a refresh
    // re-derives (an event, not a clock). The deadline only bounds a broken listener.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut idle_refreshes = 0;
    let after_change = loop {
        let result = refresh();
        if result != (0, 0) || std::time::Instant::now() > deadline {
            break result;
        }
        idle_refreshes += 1;
        std::thread::yield_now();
    };
    let after_steady = refresh();
    let (route_v4, route_v6) = review_peer_routes();
    worker.stop();
    eprintln!(
        "REVIEW underlay watch first={first:?} steady={steady:?} after_change={after_change:?} \
         (after {idle_refreshes} idle refreshes) after_steady={after_steady:?} \
         routes={route_v4:?} {route_v6:?}"
    );
    // One endpoint shared by four peers: one lookup, four writes.
    assert_eq!(first, (1, 4));
    assert_eq!(
        steady,
        [(0, 0); 4],
        "a steady refresh must not probe the underlay"
    );
    assert_eq!(
        after_change,
        (1, 4),
        "an underlay change must re-derive every peer"
    );
    assert_eq!(after_steady, (0, 0));
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

/// J609 review (#489): a policy-routing rule change moves a peer endpoint's underlay path, and
/// the kernel announces it on the rule groups, not on the link or route groups the underlay
/// watch subscribes to (#489 J552 P2-2).
///
/// Order matters and is the common one: a VPN or interface manager first adds its routes to a
/// separate table (announced, so the watch moves and one refresh re-derives every peer while
/// the main table still carries the endpoint), then adds the rule that sends the endpoint into
/// that table (not announced). Every later refresh trusts the stale budget until the 30 s
/// inventory check bumps the watch, so for up to 30 s the peer routes advertise a budget the
/// new path cannot carry, the #489 failure itself. IPv4 and IPv6 both.
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn review_j609_policy_rule_change_rederives_route_budgets() {
    use crate::mesh_mtu::ROUTE_LOOKUPS;
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    review_marked_tun(PublicKey([9; 32]));
    review_route_command(&["route", "add", "10.254.0.3/32", "dev", "infraternal0"]);
    review_route_command(&["-6", "route", "add", "fd01::3/128", "dev", "infraternal0"]);
    // The main-table underlay: 1500 bytes, so a 1408 budget for both families.
    let endpoint_v4 = review_learned_underlay(1500);
    review_route_command(&[
        "-6",
        "address",
        "add",
        "2001:db8:1::1/64",
        "dev",
        "under0",
        "nodad",
    ]);
    let endpoint_v6: std::net::SocketAddr = "[2001:db8:1::2]:51820".parse().expect("IPv6 endpoint");
    let peer = |id: u8| crate::dataplane::Peer {
        key: PublicKey([id; 32]),
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: std::net::Ipv4Addr::new(10, 254, 0, id),
            ipv6: format!("fd01::{id}").parse().expect("IPv6"),
        },
        endpoint: Some("192.0.2.2:51820".parse().expect("configured endpoint")),
    };
    let peers = [peer(2), peer(3)];
    let learned = [
        (peers[0].key, Some(endpoint_v4)),
        (peers[1].key, Some(endpoint_v6)),
    ];
    let state = Arc::new(Mutex::new(PeerRouteState::default()));
    lock_route_state(&state).set_peers(&peers);
    let mut worker = RouteRepairWorker::start(Arc::clone(&state)).expect("start route repair");
    let refresh = || {
        ROUTE_LOOKUPS.with(|lookups| lookups.set(0));
        let written = update_live_peer_endpoints(&state, &learned).expect("refresh");
        (ROUTE_LOOKUPS.with(std::cell::Cell::get), written)
    };
    // Refresh until one re-derives (the listener is asynchronous); the deadline only bounds it.
    let refresh_until = |done: &dyn Fn((usize, usize)) -> bool| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let result = refresh();
            if done(result) || std::time::Instant::now() > deadline {
                break result;
            }
            // The kernel announcement reaches the listener thread asynchronously, and the test
            // can observe it only through a refresh.
            // sleep: paces the polling refreshes; there is no event to wait on.
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    };
    let routes = || {
        [
            review_route_command(&["route", "show", "exact", "10.254.0.2/32"]),
            review_route_command(&["-6", "route", "show", "exact", "fd01::2/128"]),
            review_route_command(&["route", "show", "exact", "10.254.0.3/32"]),
            review_route_command(&["-6", "route", "show", "exact", "fd01::3/128"]),
        ]
    };
    let first = refresh();
    let before = routes();

    // A second, smaller underlay in its own table: 1300 bytes, so a 1216 budget.
    review_route_command(&["link", "add", "under1", "type", "dummy"]);
    review_route_command(&["link", "set", "under1", "mtu", "1300", "up"]);
    review_route_command(&[
        "route",
        "add",
        "198.51.100.0/24",
        "dev",
        "under1",
        "table",
        "100",
    ]);
    review_route_command(&[
        "-6",
        "route",
        "add",
        "2001:db8:1::/64",
        "dev",
        "under1",
        "table",
        "100",
    ]);
    // Those announcements move the watch: one refresh re-derives, still through the main table.
    let table_added = refresh_until(&|(lookups, _)| lookups > 0);

    // Now the rules send both endpoints into table 100. No link or route changes.
    review_route_command(&[
        "rule",
        "add",
        "to",
        "198.51.100.2",
        "lookup",
        "100",
        "pref",
        "100",
    ]);
    review_route_command(&[
        "-6",
        "rule",
        "add",
        "to",
        "2001:db8:1::2",
        "lookup",
        "100",
        "pref",
        "100",
    ]);
    let path_v4 = review_route_command(&["route", "get", "198.51.100.2"]);
    let path_v6 = review_route_command(&["-6", "route", "get", "2001:db8:1::2"]);
    let rule_added = refresh_until(&|(lookups, _)| lookups > 0);
    let after = routes();
    worker.stop();
    eprintln!(
        "REVIEW J609 policy rule: first={first:?} before={before:?} table_added={table_added:?} \
         path_v4={path_v4:?} path_v6={path_v6:?} rule_added={rule_added:?} after={after:?}"
    );
    assert!(
        before.iter().all(|route| route.contains("mtu 1408")),
        "{before:?}"
    );
    assert!(path_v4.contains("dev under1") && path_v6.contains("dev under1"));
    for route in &after {
        assert!(
            route.contains("mtu 1216"),
            "a rule that moves the endpoint onto the 1300-byte underlay must re-derive the \
             budget (1216) at the next refresh, not after the 30 s inventory check: {route}"
        );
    }
}

/// Replacing a nexthop object re-points every route that refers to it. With
/// `net.ipv4.nexthop_compat_mode` off, the kernel announces only the nexthop, not the routes,
/// so the watch must listen to nexthop changes too (#489 J609 note). IPv4 only: the nexthop
/// group and its compat switch are shared by both families.
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn live_endpoint_refresh_rederives_after_nexthop_replace() {
    use crate::mesh_mtu::ROUTE_LOOKUPS;
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    review_marked_tun(PublicKey([9; 32]));
    let endpoint = review_learned_underlay(1500);
    review_route_command(&["link", "add", "under1", "type", "dummy"]);
    review_route_command(&["link", "set", "under1", "mtu", "1300", "up"]);
    // The endpoint's host route goes through nexthop object 1, first on the 1500-byte underlay.
    review_route_command(&["nexthop", "add", "id", "1", "dev", "under0"]);
    review_route_command(&["route", "add", "198.51.100.2/32", "nhid", "1"]);
    // Off: a nexthop replacement is announced only on the nexthop group.
    std::fs::write("/proc/sys/net/ipv4/nexthop_compat_mode", "0").expect("compat mode off");
    let peer = crate::dataplane::Peer {
        key: PublicKey([2; 32]),
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("IPv4"),
            ipv6: "fd01::2".parse().expect("IPv6"),
        },
        endpoint: Some("192.0.2.2:51820".parse().expect("configured endpoint")),
    };
    let learned = [(peer.key, Some(endpoint))];
    let state = Arc::new(Mutex::new(PeerRouteState::default()));
    lock_route_state(&state).set_peers(std::slice::from_ref(&peer));
    let mut worker = RouteRepairWorker::start(Arc::clone(&state)).expect("start route repair");
    let refresh = || {
        ROUTE_LOOKUPS.with(|lookups| lookups.set(0));
        let written = update_live_peer_endpoints(&state, &learned).expect("refresh");
        (ROUTE_LOOKUPS.with(std::cell::Cell::get), written)
    };
    let first = refresh();
    let before = review_peer_routes();

    review_route_command(&["nexthop", "replace", "id", "1", "dev", "under1"]);
    let path = review_route_command(&["route", "get", "198.51.100.2"]);
    // The listener is asynchronous: refresh until one re-derives; the deadline only bounds it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let replaced = loop {
        let result = refresh();
        if result.0 > 0 || std::time::Instant::now() > deadline {
            break result;
        }
        // The nexthop announcement reaches the listener thread asynchronously, and the test
        // can observe it only through a refresh.
        // sleep: paces the polling refreshes; there is no event to wait on.
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let after = review_peer_routes();
    worker.stop();
    eprintln!(
        "nexthop replace: first={first:?} before={before:?} path={path:?} \
         replaced={replaced:?} after={after:?}"
    );
    assert_eq!(first, (1, 1));
    assert!(before.0.contains("mtu 1408"), "{before:?}");
    assert!(path.contains("dev under1"), "{path}");
    assert_eq!(
        replaced,
        (1, 1),
        "a nexthop replacement must re-derive the budget at the next refresh"
    );
    assert!(after.0.contains("mtu 1216"), "{after:?}");
    assert!(after.1.contains("mtu 1216"), "{after:?}");
}

/// A failed underlay lookup writes the safe fallback (1200) but is not an answer: the next
/// refresh looks the peer up again instead of trusting the fallback until the 30 s inventory
/// check (#489 J609 P3). A lookup that keeps failing is retried twice per underlay generation,
/// not on every refresh, so a dead path cannot turn steady traffic into a netlink loop.
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn live_endpoint_refresh_retries_a_failed_lookup() {
    use crate::mesh_mtu::{FAIL_ROUTE_LOOKUPS, ROUTE_LOOKUPS};
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    review_marked_tun(PublicKey([9; 32]));
    let endpoint = review_learned_underlay(1500);
    let peer = crate::dataplane::Peer {
        key: PublicKey([2; 32]),
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("IPv4"),
            ipv6: "fd01::2".parse().expect("IPv6"),
        },
        endpoint: Some("192.0.2.2:51820".parse().expect("configured endpoint")),
    };
    let learned = [(peer.key, Some(endpoint))];
    let state = Arc::new(Mutex::new(PeerRouteState::default()));
    lock_route_state(&state).set_peers(std::slice::from_ref(&peer));
    let mut worker = RouteRepairWorker::start(Arc::clone(&state)).expect("start route repair");
    let refresh = || {
        ROUTE_LOOKUPS.with(|lookups| lookups.set(0));
        let written = update_live_peer_endpoints(&state, &learned).expect("refresh");
        (ROUTE_LOOKUPS.with(std::cell::Cell::get), written)
    };

    // One transient failure: the fallback is written, then replaced at the next refresh.
    FAIL_ROUTE_LOOKUPS.with(|failures| failures.set(1));
    let failed = refresh();
    let fallback = review_peer_routes();
    let retried = refresh();
    let recovered = review_peer_routes();
    let steady = refresh();

    // A lookup that keeps failing: a full re-derivation (forced without netlink, so no
    // asynchronous announcement adds refreshes) writes the fallback, then retries are bounded.
    FAIL_ROUTE_LOOKUPS.with(|failures| failures.set(usize::MAX));
    lock_route_state(&state).forget_written();
    let persistent: Vec<_> = (0..6).map(|_| refresh()).collect();
    FAIL_ROUTE_LOOKUPS.with(|failures| failures.set(0));
    worker.stop();
    eprintln!(
        "failed lookup: failed={failed:?} fallback={fallback:?} retried={retried:?} \
         recovered={recovered:?} steady={steady:?} persistent={persistent:?}"
    );
    assert_eq!(failed, (1, 1));
    assert!(fallback.0.contains("mtu 1200"), "{fallback:?}");
    assert_eq!(
        retried,
        (1, 1),
        "a failed lookup must be retried at the next refresh"
    );
    assert!(recovered.0.contains("mtu 1408"), "{recovered:?}");
    assert!(recovered.1.contains("mtu 1408"), "{recovered:?}");
    assert_eq!(steady, (0, 0));
    assert_eq!(
        persistent,
        [(1, 1), (1, 0), (1, 0), (0, 0), (0, 0), (0, 0)],
        "a lookup that keeps failing is retried twice, then waits for the underlay to change"
    );
}

/// An IPv6 policy rule alone must move the watch (#489 J630). J609's test adds the IPv4 and
/// IPv6 rules back to back, so the IPv4 announcement alone forces a full re-derivation that
/// also re-reads the IPv6 path: nothing there pins the `RTNLGRP_IPV6_RULE` subscription. Here
/// only an IPv6 rule changes, so the refresh re-derives only if that group is bound.
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with ip."]
fn review_j630_ipv6_rule_alone_rederives_route_budgets() {
    use crate::mesh_mtu::ROUTE_LOOKUPS;
    use crate::policy::model::{Addresses, PublicKey};
    review_route_command(&["link", "set", "lo", "up"]);
    review_marked_tun(PublicKey([9; 32]));
    let _ = review_learned_underlay(1500);
    review_route_command(&[
        "-6",
        "address",
        "add",
        "2001:db8:1::1/64",
        "dev",
        "under0",
        "nodad",
    ]);
    let endpoint: std::net::SocketAddr = "[2001:db8:1::2]:51820".parse().expect("IPv6 endpoint");
    // The smaller underlay and its table exist before the worker starts, so their link and
    // route announcements cannot move the watch during the measured step.
    // No link-local address on it either: a late IPv6 autoconf route announcement would move
    // the watch by itself and hide a missing rule subscription.
    review_route_command(&["link", "add", "under1", "type", "dummy"]);
    review_route_command(&["link", "set", "under1", "addrgenmode", "none"]);
    review_route_command(&["link", "set", "under1", "mtu", "1300", "up"]);
    review_route_command(&[
        "-6",
        "route",
        "add",
        "2001:db8:1::/64",
        "dev",
        "under1",
        "table",
        "100",
    ]);
    let peer = crate::dataplane::Peer {
        key: PublicKey([2; 32]),
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().expect("IPv4"),
            ipv6: "fd01::2".parse().expect("IPv6"),
        },
        endpoint: Some("192.0.2.2:51820".parse().expect("configured endpoint")),
    };
    let learned = [(peer.key, Some(endpoint))];
    let state = Arc::new(Mutex::new(PeerRouteState::default()));
    lock_route_state(&state).set_peers(std::slice::from_ref(&peer));
    let mut worker = RouteRepairWorker::start(Arc::clone(&state)).expect("start route repair");
    let refresh = || {
        ROUTE_LOOKUPS.with(|lookups| lookups.set(0));
        let written = update_live_peer_endpoints(&state, &learned).expect("refresh");
        (ROUTE_LOOKUPS.with(std::cell::Cell::get), written)
    };
    let first = refresh();
    let before = review_peer_routes();
    let steady = refresh();

    review_route_command(&[
        "-6",
        "rule",
        "add",
        "to",
        "2001:db8:1::2",
        "lookup",
        "100",
        "pref",
        "100",
    ]);
    let path = review_route_command(&["-6", "route", "get", "2001:db8:1::2"]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let rule_added = loop {
        let result = refresh();
        if result.0 > 0 || std::time::Instant::now() > deadline {
            break result;
        }
        // The rule announcement reaches the listener thread asynchronously, and the test can
        // observe it only through a refresh.
        // sleep: paces the polling refreshes; there is no event to wait on.
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let after = review_peer_routes();
    worker.stop();
    eprintln!(
        "REVIEW J630 ipv6 rule: first={first:?} before={before:?} steady={steady:?} \
         path={path:?} rule_added={rule_added:?} after={after:?}"
    );
    assert!(before.0.contains("mtu 1408"), "{before:?}");
    assert_eq!(steady, (0, 0), "nothing changed, so nothing is looked up");
    assert!(path.contains("dev under1"), "{path}");
    assert_eq!(
        rule_added,
        (1, 1),
        "an IPv6 rule that moves the endpoint must re-derive at the next refresh"
    );
    assert!(after.0.contains("mtu 1216"), "{after:?}");
}
