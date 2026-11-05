//! Two installations racing `down` and `up` must never leave the live node without its packet filter (#260 J143 P3-4).
//!
//! Run as root inside a disposable network namespace with `CAP_NET_ADMIN` and nft. The test seam
//! starts the second installation in the window after the first one's link is gone and before
//! it decides about the shared table.
#![cfg(all(feature = "test-support", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer, PeerPolicy},
    node::{BEFORE_SHARED_FILTER_DECISION, EngineKind, Node},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
    wireguard::Key,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

fn fresh_state(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn cleanup(directory: &Path) {
    let _ = Command::new("ip")
        .args(["link", "delete", "infraternal0"])
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "infraternal_mesh"])
        .stderr(Stdio::null())
        .status();
    let _ = fs::remove_dir_all(directory);
}

fn table_present() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", "infraternal_mesh"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

fn addresses(id: u32) -> Addresses {
    Addresses {
        ipv4: (0x0afe_0000 + id).into(),
        ipv6: ((0xfd01_u128 << 112) + u128::from(id)).into(),
    }
}

/// Apply one deny-by-default snapshot, which installs the shared table.
fn install_deny_policy(node: &mut Node, local_key: PublicKey) {
    let (_, peer_key) = Key::generate().unwrap();
    let chunk = Chunk {
        local_key: Some(local_key),
        server: Some(NodeId(1)),
        node: NodeId(2),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: "internal".to_owned(),
        from_version: None,
        version: 1,
        index: 0,
        last: true,
        addresses: addresses(2),
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        upserted: BTreeMap::from([(
            NodeId(1),
            PeerPolicy {
                peer: Peer {
                    key: peer_key,
                    addresses: addresses(1),
                    endpoint: None,
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
                access_ssh: None,
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
    assert!(node.chunk(chunk).unwrap(), "the policy chunk is applied");
}

fn racing_up_keeps_the_live_nodes_table(engine: EngineKind) {
    let old_state = fresh_state(&format!("filter-race-old-{engine:?}"));
    let new_state = fresh_state(&format!("filter-race-new-{engine:?}"));
    let mut old = Node::restore_with_engine(&old_state, engine).unwrap();
    let identity = old.up().unwrap();
    install_deny_policy(&mut old, identity.public_key);
    assert!(table_present(), "the old node installed the shared table");

    // In the window: the old link is gone, so a second installation can come up.
    let started: Arc<Mutex<Option<std::io::Result<Node>>>> = Arc::default();
    let slot = Arc::clone(&started);
    let state = new_state.clone();
    *BEFORE_SHARED_FILTER_DECISION.lock().unwrap() = Some(Box::new(move || {
        let node = Node::restore_with_engine(&state, engine).and_then(|mut node| {
            node.up()?;
            Ok(node)
        });
        *slot.lock().unwrap() = Some(node);
    }));
    let stopped = old.down();
    let table_after_down = table_present();
    let new = started.lock().unwrap().take();
    let new_stopped = new.map(|node| node.and_then(|mut node| node.down()));
    cleanup(&old_state);
    cleanup(&new_state);

    assert!(
        stopped.is_ok(),
        "{engine:?}: old node down failed: {stopped:?}"
    );
    assert!(
        matches!(new_stopped, Some(Ok(()))),
        "{engine:?}: the racing installation did not start and stop: {new_stopped:?}"
    );
    assert!(
        table_after_down,
        "{engine:?}: down removed the shared table under a live installation"
    );
}

#[test]
#[ignore = "Run as root in a disposable network namespace with CAP_NET_ADMIN and nft."]
fn racing_up_keeps_the_live_kernel_nodes_table() {
    racing_up_keeps_the_live_nodes_table(EngineKind::Kernel);
}

#[test]
#[ignore = "Run as root in a disposable network namespace with CAP_NET_ADMIN and nft."]
fn racing_up_keeps_the_live_gotatun_nodes_table() {
    racing_up_keeps_the_live_nodes_table(EngineKind::GotaTun);
}
