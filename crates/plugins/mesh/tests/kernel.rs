//! Real-kernel privilege probe, chunked 1,000-peer application and one-peer update measurement [169].
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::{
    dataplane::Peer,
    policy::model::Addresses,
    wireguard::{Client, Device, Key},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Instant,
};
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
