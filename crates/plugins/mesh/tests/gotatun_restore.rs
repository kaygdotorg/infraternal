//! Verifies that a restarted infraternal agent reattaches its persisted `GotaTun` TUN with the persisted key [163,169], D332.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer, PeerPolicy},
    node::{EngineKind, Node},
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

/// `ip -o link show infraternal0` in this namespace. `/sys/class/net` shows the network namespace
/// that mounted sysfs, which in a test namespace can be the host's.
fn link_line() -> String {
    let output = std::process::Command::new("ip")
        .args(["-o", "link", "show", "infraternal0"])
        .output()
        .unwrap();
    assert!(output.status.success(), "no infraternal0 in this namespace");
    String::from_utf8(output.stdout).unwrap()
}

fn index() -> u32 {
    link_line()
        .split(':')
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// The kernel's view of the mesh TUN's transmit queue, in packets, from this namespace.
fn tx_queue_len() -> u32 {
    let line = link_line();
    let mut words = line.split_whitespace().skip_while(|word| *word != "qlen");
    // `ip -o` ends each joined line with a backslash.
    words
        .nth(1)
        .unwrap()
        .trim_end_matches('\\')
        .parse()
        .unwrap()
}

fn private_state(name: &str) -> std::path::PathBuf {
    let state = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&state);
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    state
}

/// The owner fence for a persisted TUN (D332): another installation can neither adopt it nor
/// take its name, and only the installation whose recorded key and private key match its marker
/// reattaches it.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn another_installation_never_adopts_a_persisted_tun() {
    let ours = private_state("gotatun-persist-ours");
    let other = private_state("gotatun-persist-other");
    let result = (|| {
        let mut first = Node::restore_with_engine(&ours, EngineKind::GotaTun)?;
        first.up()?;
        let link = index();
        drop(first);

        let refused = Node::restore_with_engine(&other, EngineKind::GotaTun)
            .and_then(|mut node| node.up().map(|_| node));
        let refused_kind = refused.as_ref().err().map(std::io::Error::kind);
        drop(refused);
        let survived = Device::owned_tun()? && index() == link;

        let mut restarted = Node::restore_with_engine(&ours, EngineKind::GotaTun)?;
        restarted.up()?;
        let reattached = index() == link;
        restarted.down()?;
        Ok::<_, std::io::Error>((refused_kind, survived, reattached))
    })();
    if Device::owned_tun().unwrap_or(false) {
        let _ = Device::delete();
    }
    fs::remove_dir_all(&ours).unwrap();
    fs::remove_dir_all(&other).unwrap();
    let (refused_kind, survived, reattached) = result.unwrap();
    assert_eq!(
        refused_kind,
        Some(std::io::ErrorKind::AlreadyExists),
        "another installation must not take a persisted TUN"
    );
    assert!(
        survived,
        "the refused installation changed the persisted TUN"
    );
    assert!(
        reattached,
        "the owning installation did not reattach its TUN"
    );
}

/// Create a kernel link that carries the shared mesh marker, as another node on the host does.
fn add_marked_kernel_link() {
    for args in [
        &["link", "add", "infraternal0", "type", "wireguard"][..],
        &[
            "link",
            "set",
            "infraternal0",
            "alias",
            "infraternal.mesh.v1",
        ][..],
    ] {
        let status = std::process::Command::new("ip")
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "ip {args:?}");
    }
}

/// Restore records an engine only when it moves this node's own link to another engine (D346).
/// A fresh directory, such as a new or rootless infraternal agent on a host where another node
/// runs kernel `WireGuard`, and an older kernel-only directory both leave that node's link alone
/// and write nothing: a durable record there claimed another node's link and put two fsyncs on
/// every fresh start (#260).
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn restore_records_no_engine_for_another_nodes_kernel_link() {
    assert!(
        std::env::var_os("INFRATERNAL_MESH_ENGINE").is_none(),
        "this covers a machine with no engine choice"
    );
    let fresh = private_state("kernel-upgrade-fresh");
    let upgraded = private_state("kernel-upgrade-old");
    // The public snapshot an older kernel-only node left behind.
    fs::write(
        upgraded.join("mesh-public.json"),
        br#"{"enabled":true,"config":null}"#,
    )
    .unwrap();
    fs::set_permissions(
        upgraded.join("mesh-public.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    add_marked_kernel_link();
    let link = index();
    drop(Node::restore(&fresh));
    drop(Node::restore(&upgraded));
    let kept = Device::owned().unwrap_or(false) && index() == link;
    let fresh_record = fs::read_to_string(fresh.join("mesh-engine.json")).ok();
    let upgraded_record = fs::read_to_string(upgraded.join("mesh-engine.json")).ok();
    if Device::owned().unwrap_or(false) {
        Device::delete().unwrap();
    }
    fs::remove_dir_all(&fresh).unwrap();
    fs::remove_dir_all(&upgraded).unwrap();

    assert!(kept, "restore changed another node's kernel link");
    assert_eq!(
        fresh_record, None,
        "a fresh state directory recorded an engine"
    );
    assert_eq!(
        upgraded_record, None,
        "an older directory recorded an engine for another node's link"
    );
}

#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn restart_reattaches_the_persisted_tun_and_mesh_identity() {
    let state = std::env::temp_dir().join(format!("gotatun-restore-{}", std::process::id()));
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

    let result = (|| {
        let mut first = Node::restore_with_engine(&state, EngineKind::GotaTun)?;
        let identity = first.up()?;
        let link = index();
        // A TUN opens with a 500-packet transmit queue; the engine needs 1,024 (#260 J88e).
        let first_queue = (
            tx_queue_len(),
            first.engine_health().and_then(|health| health.tx_queue_len),
        );
        // A process end, as an infraternal agent restart: the TUN stays (D332).
        drop(first);
        assert!(Device::owned_tun()?, "the TUN outlives its process");
        assert_eq!(index(), link);

        let mut restarted = Node::restore_with_engine(&state, EngineKind::GotaTun)?;
        let restored = restarted.up()?;
        assert_eq!(restored.public_key, identity.public_key);
        assert_eq!(
            index(),
            link,
            "the restarted engine reattaches the same link"
        );
        let restarted_queue = (
            tx_queue_len(),
            restarted
                .engine_health()
                .and_then(|health| health.tx_queue_len),
        );
        let needed = infraternal_plugin_mesh::gotatun_node::TUN_TX_QUEUE_LEN;
        assert!(
            first_queue.0 >= needed && first_queue.1 == Some(first_queue.0),
            "the new TUN's transmit queue (kernel, reported): {first_queue:?}"
        );
        assert!(
            restarted_queue.0 >= needed && restarted_queue.1 == Some(restarted_queue.0),
            "the reattached TUN's transmit queue (kernel, reported): {restarted_queue:?}"
        );
        restarted.down()?;
        assert!(!Device::owned_tun()?, "down removes the persisted TUN");
        Ok::<_, std::io::Error>(())
    })();

    if Device::owned_tun().unwrap_or(false) {
        let _ = Device::delete();
    }
    fs::remove_dir_all(state).unwrap();
    result.unwrap();
}

/// A failed `GotaTun` replay keeps the accepted coordinator configuration.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
/// Keeps the accepted coordinator configuration when replay through `GotaTun` fails.
fn failed_gotatun_replay_keeps_the_accepted_coordinator_config() {
    let state = std::env::temp_dir().join(format!("gotatun-replay-{}", std::process::id()));
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

    let first = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::GotaTun)?;
        let identity = node.up()?;
        let (_, peer_key) = Key::generate()?;
        let chunk = Chunk {
            local_key: Some(identity.public_key),
            server: Some(NodeId(1)),
            node: NodeId(2),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: "internal".to_owned(),
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
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: "10.254.0.1".parse().unwrap(),
                            ipv6: "fd01::1".parse().unwrap(),
                        },
                        endpoint: Some("192.0.2.1:44000".parse().unwrap()),
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                },
            )]),
            merged: BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns")]
            peer_names: BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
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
        Node::restore_with_engine(&state, EngineKind::GotaTun),
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
