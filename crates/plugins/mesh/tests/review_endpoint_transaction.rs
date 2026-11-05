//! Verifies that a refused endpoint-only transaction preserves the installed public kernel view [166], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    configuration,
    dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
    netlink::{Socket, attribute, attributes},
    node::{EngineKind, Node},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
    wireguard::{Device, Key},
};
use nix::sys::socket::SockProtocol;
use std::{collections::BTreeMap, fs, net::SocketAddr, os::unix::fs::PermissionsExt};

fn endpoint(key: PublicKey) -> SocketAddr {
    let mut socket = Socket::open(SockProtocol::NetlinkGeneric).unwrap();
    let family = socket.family("wireguard").unwrap();
    let mut request = vec![0, 1, 0, 0];
    attribute(&mut request, 2, b"infraternal0\0").unwrap();
    for reply in socket.request(family, 0x300, &request).unwrap() {
        for device in attributes(&reply[4..]).unwrap() {
            if device.kind != 8 {
                continue;
            }
            for peer in attributes(device.payload).unwrap() {
                let fields = attributes(peer.payload).unwrap();
                if fields
                    .iter()
                    .any(|field| field.kind == 1 && field.payload == key.0)
                {
                    let bytes = fields.iter().find(|field| field.kind == 4).unwrap().payload;
                    let address = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
                    return SocketAddr::new(
                        address.into(),
                        u16::from_be_bytes([bytes[2], bytes[3]]),
                    );
                }
            }
        }
    }
    panic!("public peer endpoint absent");
}

/// A refused endpoint save keeps the kernel's endpoint.
#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn refused_endpoint_persistence_preserves_kernel_endpoint() {
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = target.join(format!("review-endpoint-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    node.up().unwrap();
    let (_, key) = Key::generate().unwrap();
    let initial: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    let mut config = Config {
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: "internal".to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::from([(
            NodeId(2),
            PeerPolicy {
                peer: Peer {
                    key,
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: "10.254.0.2".parse().unwrap(),
                        ipv6: "fd01::2".parse().unwrap(),
                    },
                    endpoint: Some(initial),
                },
                inbound: TrafficPolicy::None,
                outbound: TrafficPolicy::None,
            },
        )]),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
    };
    for chunk in configuration::chunks(None, &config).unwrap() {
        node.chunk(chunk).unwrap();
    }
    assert_eq!(endpoint(key), initial);
    let old = config.clone();
    config.version = 2;
    config.peers.get_mut(&NodeId(2)).unwrap().peer.endpoint =
        Some("192.0.2.2:51820".parse().unwrap());
    // A preexisting temporary file is a supported refusal boundary in Store::save.
    // It contains public fixture text only and must not be overwritten.
    let collision = directory.join(format!("mesh-public.{}.new", std::process::id()));
    fs::write(&collision, b"reserved fixture").unwrap();
    let chunks = configuration::chunks(Some(&old), &config).unwrap();
    assert_eq!(chunks.len(), 1);
    assert!(node.chunk(chunks.into_iter().next().unwrap()).is_err());
    assert_eq!(node.config().unwrap().version, 1);
    let installed = endpoint(key);
    fs::remove_file(collision).unwrap();
    node.down().unwrap();
    assert!(!Device::owned().unwrap());
    fs::remove_dir_all(directory).unwrap();
    assert_eq!(
        installed, initial,
        "refused endpoint update changed kernel state"
    );
}
