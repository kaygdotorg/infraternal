//! Real-kernel privilege, chunked application, incremental update and bulk peer-retirement proofs [169], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::{
    dataplane::Peer,
    policy::model::Addresses,
    wireguard::{Client, Device, Key},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
    time::Instant,
};
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn bulk_retirement_preserves_identity_and_routes_at_1000_peers() {
    Device::create().unwrap();
    let (local, _) = Key::generate().unwrap();
    Device::configure(&local, 0).unwrap();
    let identity = Device::identity().unwrap();
    let peers: Vec<_> = (1_u32..=1000)
        .map(|id| Peer {
            key: Key::generate().unwrap().1,
            previous_key: None,
            previous_active: false,
            addresses: Addresses {
                ipv4: Ipv4Addr::from(0x0aff_0000 + id),
                ipv6: Ipv6Addr::from((0xfd02_u128 << 112) + u128::from(id)),
            },
            endpoint: None,
        })
        .collect();
    let mut client = Client::new().unwrap();
    client.peers(&peers, &[]).unwrap();
    Device::routes(&peers[..1], false).unwrap();
    assert_eq!(Device::counters().unwrap().len(), 1000);
    let started = Instant::now();
    client.clear_peers().unwrap();
    let elapsed = started.elapsed();
    assert!(Device::counters().unwrap().is_empty());
    assert_eq!(Device::identity().unwrap(), identity);
    for args in [
        vec!["-j", "route", "show", "10.255.0.1/32"],
        vec!["-j", "-6", "route", "show", "fd02::1/128"],
    ] {
        let output = Command::new("ip").args(args).output().unwrap();
        assert!(output.status.success());
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(routes.as_array().unwrap().len(), 1);
        assert_eq!(routes[0]["dev"], "infraternal0");
    }
    client.clear_peers().unwrap();
    assert_eq!(Device::identity().unwrap(), identity);
    Device::delete().unwrap();
    assert!(!Device::owned().unwrap());
    println!(
        "METRIC bulk_peer_retirement machine=infraternal-dev peers=1000 clear_us={} load={}",
        elapsed.as_micros(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn real_kernel_chunked_peers() {
    Device::create().unwrap();
    let (local, _) = Key::generate().unwrap();
    Device::configure(&local, 0).unwrap();
    let peers: Vec<_> = (1_u32..=1000)
        .map(|id| {
            let (_, key) = Key::generate().unwrap();
            Peer {
                key,
                previous_key: None,
                previous_active: false,
                addresses: Addresses {
                    ipv4: Ipv4Addr::from(0x0afe_0000 + id),
                    ipv6: Ipv6Addr::from((0xfd_u128 << 120) + u128::from(id)),
                },
                endpoint: Some("192.0.2.1:44000".parse().unwrap()),
            }
        })
        .collect();
    let mut client = Client::new().unwrap();
    let start = Instant::now();
    client.peers(&peers, &[]).unwrap();
    let thousand = start.elapsed();
    let mut change = peers[0].clone();
    change.endpoint = Some("192.0.2.2:44000".parse().unwrap());
    let start = Instant::now();
    client
        .endpoint(change.key, change.endpoint.unwrap())
        .unwrap();
    let single = start.elapsed();
    assert_eq!(Device::counters().unwrap().len(), 1000);
    let counters = Device::counters().unwrap();
    assert_eq!(
        counters
            .values()
            .filter(|peer| peer.persistent_keepalive_secs == 25)
            .count(),
        1000,
        "all configured peers need persistent keepalive"
    );
    println!(
        "METRIC kernel_peers machine=infraternal-dev peers=1000 apply_us={} single_peer_us={} load={}",
        thousand.as_micros(),
        single.as_micros(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    Device::delete().unwrap();
}

#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn real_kernel_ephemeral_identity() {
    Device::create().unwrap();
    let (local, public) = Key::generate().unwrap();
    Device::configure(&local, 0).unwrap();
    let (actual, port) = Device::identity().unwrap();
    assert_eq!(actual, public);
    assert_ne!(port, 0, "the advertised endpoint needs a bound UDP port");
    assert_ne!(port, 51820, "the mesh reserves no fixed UDP port");
    assert_eq!(
        Device::configure(&local, 51820).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    let changed = Device::allocate_port().unwrap();
    assert_ne!(changed, 51820);
    assert_eq!(Device::identity().unwrap(), (public, changed));
    Device::delete().unwrap();
}

#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn policy_table_route_conflict_is_refused() {
    use std::process::Command;
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    Device::create().unwrap();
    let (key, _) = Key::generate().unwrap();
    Device::configure(&key, 0).unwrap();
    assert!(
        Command::new("ip")
            .args(["route", "add", "10.254.0.0/16", "dev", "lo", "table", "100"])
            .status()
            .unwrap()
            .success()
    );
    let local = Addresses {
        ipv4: "10.254.0.1".parse().unwrap(),
        ipv6: "fd01:203:405::1".parse().unwrap(),
    };
    assert_eq!(
        Device::check_routes(&[local]).unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse
    );
    assert!(
        Command::new("ip")
            .args(["route", "del", "10.254.0.0/16", "dev", "lo", "table", "100"])
            .status()
            .unwrap()
            .success()
    );
    Device::check_routes(&[local]).unwrap();
    Device::delete().unwrap();
}

#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn retired_host_routes_can_be_replayed() {
    Device::create().unwrap();
    let (key, public) = Key::generate().unwrap();
    Device::configure(&key, 0).unwrap();
    let peer = Peer {
        key: public,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01:203:405::2".parse().unwrap(),
        },
        endpoint: None,
    };
    Device::routes(std::slice::from_ref(&peer), false).unwrap();
    Device::routes(std::slice::from_ref(&peer), true).unwrap();
    Device::routes(std::slice::from_ref(&peer), true).unwrap();
    Device::delete().unwrap();
}

#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn created_interface_is_marked_for_restart_adoption() {
    Device::create().unwrap();
    assert!(Device::owned().unwrap());
    Device::delete().unwrap();
}

/// During the overlap, routes stay on the old key, then move to the current key, and the old key is removed at retirement.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn rotation_overlap_keeps_routes_on_old_then_current_key_until_retirement() {
    Device::create().unwrap();
    let (local_previous, _) = Key::generate().unwrap();
    let (local_current, _) = Key::generate().unwrap();
    let (_, previous_key) = Key::generate().unwrap();
    let (_, current_key) = Key::generate().unwrap();
    Device::configure(&local_previous, 0).unwrap();
    let mut peer = Peer {
        key: previous_key,
        previous_key: Some(current_key),
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01:203:405::2".parse().unwrap(),
        },
        endpoint: None,
    };
    let mut client = Client::new().unwrap();
    client.peers(std::slice::from_ref(&peer), &[]).unwrap();

    let keys = Device::counters().unwrap();
    assert!(
        keys.contains_key(&previous_key),
        "previous key disappeared during overlap"
    );
    assert!(
        keys.contains_key(&current_key),
        "candidate key was not installed during overlap"
    );
    let routes = Device::peer_route_owners().unwrap();
    assert_eq!(
        routes.get(&IpAddr::V4(peer.addresses.ipv4)),
        Some(&previous_key),
        "routes must stay on the old key before local key activation"
    );
    assert_eq!(
        routes.get(&IpAddr::V6(peer.addresses.ipv6)),
        Some(&previous_key),
        "IPv6 routes must stay on the old key before local key activation"
    );

    Device::configure(&local_current, 0).unwrap();
    peer.key = current_key;
    peer.previous_key = Some(previous_key);
    client.peers(std::slice::from_ref(&peer), &[]).unwrap();
    let keys = Device::counters().unwrap();
    assert!(
        keys.contains_key(&previous_key),
        "old key left overlap too early"
    );
    assert!(
        keys.contains_key(&current_key),
        "current key was not installed"
    );
    let routes = Device::peer_route_owners().unwrap();
    assert_eq!(
        routes.get(&IpAddr::V4(peer.addresses.ipv4)),
        Some(&current_key),
        "IPv4 routes must follow the activated candidate"
    );
    assert_eq!(
        routes.get(&IpAddr::V6(peer.addresses.ipv6)),
        Some(&current_key),
        "IPv6 routes must follow the activated candidate"
    );

    peer.previous_key = None;
    client.peers(&[peer.clone()], &[previous_key]).unwrap();
    let keys = Device::counters().unwrap();
    assert!(
        !keys.contains_key(&previous_key),
        "retired key remains installed"
    );
    assert!(
        keys.contains_key(&current_key),
        "retirement removed the current key"
    );
    let routes = Device::peer_route_owners().unwrap();
    assert_eq!(
        routes.get(&IpAddr::V4(peer.addresses.ipv4)),
        Some(&current_key)
    );
    assert_eq!(
        routes.get(&IpAddr::V6(peer.addresses.ipv6)),
        Some(&current_key)
    );

    drop(local_previous);
    drop(local_current);
    Device::delete().unwrap();
}
