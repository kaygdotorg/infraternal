//! Verifies that a restarted infraternal agent recreates its `GotaTun` TUN with the persisted key [163,169].
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer, PeerPolicy},
    node::Node,
    policy::{
        model::{Addresses, NodeId},
        rules::TrafficPolicy,
    },
    wireguard::{Device, Key},
};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::PermissionsExt,
};

#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn restart_recreates_the_tun_and_persisted_mesh_identity() {
    let state = std::env::temp_dir().join(format!("gotatun-restore-{}", std::process::id()));
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

    let result = (|| {
        let mut first = Node::restore(&state)?;
        let identity = first.up()?;
        assert!(Device::owned_tun()?);
        drop(first);

        assert!(!Device::owned_tun()?);
        let mut restarted = Node::restore(&state)?;
        let restored = restarted.up()?;
        assert_eq!(restored.public_key, identity.public_key);
        assert!(Device::owned_tun()?);
        restarted.down()?;
        assert!(!Device::owned_tun()?);
        Ok::<_, std::io::Error>(())
    })();

    if Device::owned_tun().unwrap_or(false) {
        let _ = Device::delete();
    }
    fs::remove_dir_all(state).unwrap();
    result.unwrap();
}

#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn failed_gotatun_replay_keeps_the_accepted_coordinator_config() {
    let state = std::env::temp_dir().join(format!("gotatun-replay-{}", std::process::id()));
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

    let first = (|| {
        let mut node = Node::restore(&state)?;
        let identity = node.up()?;
        let (_, peer_key) = Key::generate()?;
        let chunk = Chunk {
            local_key: Some(identity.public_key),
            server: Some(NodeId(1)),
            node: NodeId(2),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: infraternal_plugin_mesh::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            from_version: None,
            version: 1,
            index: 0,
            last: true,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().unwrap(),
                ipv6: "fd01::2".parse().unwrap(),
            },
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            upserted: BTreeMap::from([(
                NodeId(1),
                PeerPolicy {
                    peer: Peer {
                        key: peer_key,
                        addresses: Addresses {
                            ipv4: "10.254.0.1".parse().unwrap(),
                            ipv6: "fd01::1".parse().unwrap(),
                        },
                        endpoint: Some("192.0.2.1:44000".parse().unwrap()),
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                },
            )]),
            merged: BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: BTreeMap::new(),
            #[cfg(feature = "mesh-dns-spike")]
            removed_peer_names: Vec::new(),
            access_updates: Vec::new(),
        };
        assert!(node.chunk(chunk).unwrap());
        Ok::<_, std::io::Error>(identity.public_key)
    })();
    let identity = first.unwrap();
    let public_path = state.join("mesh-public.json");
    let mut saved: serde_json::Value =
        serde_json::from_slice(&fs::read(&public_path).unwrap()).unwrap();
    let local_key = saved["config"]["local_key"].clone();
    let peer = saved["config"]["peers"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    // Simulate accepted state that cannot be replayed: the coordinator's peer key now collides
    // with this node's identity. The rejected replay must not erase the durable intent.
    peer["peer"]["key"] = local_key;
    let replay_intent = saved["config"].clone();
    let mut public_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&public_path)
        .unwrap();
    public_file
        .write_all(&serde_json::to_vec(&saved).unwrap())
        .unwrap();
    drop(public_file);

    let replay_failed = matches!(
        Node::restore(&state),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData
    );
    let after: serde_json::Value =
        serde_json::from_slice(&fs::read(&public_path).unwrap()).unwrap();
    let config_survived = after["config"] == replay_intent;
    if Device::owned_tun().unwrap_or(false) {
        let _ = Device::delete();
    }
    fs::remove_dir_all(&state).unwrap();

    assert!(
        replay_failed,
        "the intentionally invalid peer config should fail replay"
    );
    assert!(
        config_survived,
        "startup erased the accepted coordinator config for {identity:?}"
    );
}
