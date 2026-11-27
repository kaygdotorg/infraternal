//! The kernel mesh path changes or deletes only an `infraternal0` link this installation created
//! (D340, #260). The link name and its engine marker are shared by every installation on a host,
//! so a marked kernel link can be another installation's or another server's node, keyed or not
//! yet keyed. Restore, `up`, `down` and the uninstall plan must leave such a link exactly as found.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy},
    node::{EngineKind, Node},
    policy::model::{Addresses, NodeId, PublicKey},
    wireguard::{Device, INTERFACE, Key},
};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, process::Command};

fn private_state(name: &str) -> std::path::PathBuf {
    let state = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&state);
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    state
}

fn ip(args: &[&str]) {
    let status = Command::new("ip").args(args).status().unwrap();
    assert!(status.success(), "ip {args:?}");
}

/// The link's index in this namespace, from `ip` rather than our own netlink code.
fn link_index() -> Option<u32> {
    let output = Command::new("ip")
        .args(["-o", "link", "show", INTERFACE])
        .output()
        .unwrap();
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .unwrap()
        .split(':')
        .next()?
        .trim()
        .parse()
        .ok()
}

fn remove_link() {
    let _ = Command::new("ip").args(["link", "del", INTERFACE]).status();
}

/// A kernel link with the shared marker, as another installation (or a node of another server)
/// leaves it: keyed with its own key, or not keyed yet because it stopped mid-startup.
fn add_foreign_kernel_link(keyed: bool) -> Option<PublicKey> {
    let foreign = keyed.then(|| {
        // Key it as its own node would: create and configure through its own marker.
        let (key, public) = Key::generate().unwrap();
        let index = Device::create(public).unwrap();
        Device::configure(index, public, &key, 0).unwrap();
        public
    });
    if foreign.is_none() {
        ip(&["link", "add", INTERFACE, "type", "wireguard"]);
    }
    // Then give it the older shared marker, as a node of an earlier release carries it.
    ip(&["link", "set", INTERFACE, "alias", "infraternal.mesh.v1"]);
    foreign
}

/// Bring our node up once so its directory records the kernel engine and its own key, then let
/// another installation take the shared name after our link is gone.
fn our_node_then_foreign_link(
    state: &std::path::Path,
    keyed: bool,
) -> (PublicKey, Option<PublicKey>) {
    let mut node = Node::restore_with_engine(state, EngineKind::Kernel).unwrap();
    let ours = node.up().unwrap().public_key;
    drop(node);
    remove_link();
    (ours, add_foreign_kernel_link(keyed))
}

fn foreign_link_is_left_alone(name: &str, keyed: bool) {
    let state = private_state(name);
    let (ours, foreign) = our_node_then_foreign_link(&state, keyed);
    let before = (link_index(), Device::identity().ok());
    assert!(before.0.is_some(), "the foreign link is present");

    let mut took = None;
    if let Ok(mut node) = Node::restore_with_engine(&state, EngineKind::Kernel) {
        took = node.up().ok().map(|identity| identity.public_key);
        let _ = node.down();
    }
    let after = (link_index(), Device::identity().ok());
    let left = Node::plan_retirement(&state).map(|plan| plan.left().to_vec());

    remove_link();
    fs::remove_dir_all(&state).unwrap();
    assert_eq!(
        after, before,
        "our node changed or deleted another installation's marked kernel link"
    );
    assert!(
        foreign.is_none() || took != foreign,
        "our node reported another installation's key as its own: {took:?} (ours was {ours:?})"
    );
    assert!(
        left.as_ref().is_ok_and(|left| left.contains(&INTERFACE)),
        "uninstall would not leave another installation's link: {left:?}"
    );
}

#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_foreign_keyed_kernel_link_is_never_adopted_or_deleted() {
    foreign_link_is_left_alone("kernel-foreign-keyed", true);
}

#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_foreign_unkeyed_kernel_link_is_never_deleted() {
    foreign_link_is_left_alone("kernel-foreign-unkeyed", false);
}

/// The fence must not lock a node out of its own link: after a restart it reattaches the same link
/// with the same key, and `down` removes it.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn our_own_kernel_link_is_still_adopted_and_removed() {
    let state = private_state("kernel-own");
    let result = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let identity = node.up()?;
        let link = link_index();
        drop(node);
        let mut restarted = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let again = restarted.up()?;
        let same = link_index() == link && again.public_key == identity.public_key;
        restarted.down()?;
        Ok::<_, std::io::Error>((same, link_index()))
    })();
    remove_link();
    fs::remove_dir_all(&state).unwrap();
    let (same, after_down) = result.unwrap();
    assert!(same, "the restarted node did not reattach its own link");
    assert_eq!(after_down, None, "down left our own link behind");
}

/// A stop between creating our link and setting its key leaves a link with no key. Its marker
/// names our recorded key, so restore still removes that incomplete startup, and only it.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn our_own_unkeyed_kernel_link_is_still_cleaned_up() {
    let state = private_state("kernel-own-unkeyed");
    let result = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let ours = node.up()?.public_key;
        drop(node);
        remove_link();
        Device::create(ours)?;
        let unkeyed = link_index().is_some();
        drop(Node::restore_with_engine(&state, EngineKind::Kernel)?);
        Ok::<_, std::io::Error>((unkeyed, link_index()))
    })();
    remove_link();
    fs::remove_dir_all(&state).unwrap();
    let (unkeyed, after) = result.unwrap();
    assert!(unkeyed, "the unkeyed link was created");
    assert_eq!(after, None, "restore left our own incomplete link behind");
}

/// The smallest complete configuration the node saves: its own addresses and no peers.
fn snapshot_without_peers(local_key: PublicKey) -> Chunk {
    Chunk {
        local_key: Some(local_key),
        server: Some(NodeId(1)),
        authority_epoch: None,
        rotation_operation: None,
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
        upserted: BTreeMap::new(),
        merged: BTreeMap::new(),
        removed: Vec::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        removed_peer_names: Vec::new(),
        access_updates: Vec::new(),
    }
}

/// A reboot removes the link and keeps the saved configuration. A start that then stops between
/// creating the new link and setting its key leaves our own unkeyed link beside that
/// configuration. The next restart removes it, and the node starts again (#580).
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn an_installed_kernel_node_replaces_its_own_unkeyed_link() {
    let state = private_state("kernel-installed-unkeyed");
    let result = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let ours = node.up()?.public_key;
        node.chunk(snapshot_without_peers(ours))?;
        drop(node);
        remove_link();
        // What the interrupted start leaves: a link marked with the recorded key, with no key set.
        Device::create(ours)?;
        let mut restarted = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let removed = link_index().is_none();
        restarted.up()?;
        let started = link_index().is_some();
        restarted.down()?;
        Ok::<_, std::io::Error>((removed, started, link_index()))
    })();
    remove_link();
    fs::remove_dir_all(&state).unwrap();
    let (removed, started, after_down) = result.unwrap();
    assert!(removed, "restore kept our own unfinished link");
    assert!(started, "the node did not start again");
    assert_eq!(after_down, None);
}

/// J555 F3 (#483, D391): an explicit `INFRATERNAL_MESH_PORT` must bind exactly that port, even
/// when a restarted kernel node reattaches its retained link.
///
/// Kernel links outlive their process (D332), and restore adopts the link with whatever port it
/// already has. An operator who sets an override and restarts the infraternal agent keeps the old
/// port: the node neither binds the requested port nor fails, which D391 forbids. The parent
/// starts the node with the default port and keeps the link; a child process (the environment
/// is fixed per process) restarts it with an override.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn j555_restarted_kernel_link_honours_an_explicit_port_override() {
    const CHILD: &str = "J555_KERNEL_OVERRIDE_STATE";
    if let Some(state) = std::env::var_os(CHILD) {
        let mut node = Node::restore_with_engine(std::path::Path::new(&state), EngineKind::Kernel)
            .and_then(|mut node| node.up().map(|_| node))
            .unwrap();
        let bound = node.listen_port();
        node.down().unwrap();
        assert_eq!(
            bound,
            Some(32_002),
            "the reattached kernel link kept its old port instead of the explicit override"
        );
        return;
    }
    assert!(std::env::var_os("INFRATERNAL_MESH_PORT").is_none());
    let state = private_state("kernel-override");
    let first = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let identity = node.up()?;
        drop(node);
        Ok::<_, std::io::Error>(identity.port)
    })();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "--ignored",
            "j555_restarted_kernel_link_honours_an_explicit_port_override",
            "--nocapture",
        ])
        .env(CHILD, &state)
        .env("INFRATERNAL_MESH_PORT", "32002")
        .output()
        .unwrap();
    remove_link();
    fs::remove_dir_all(&state).unwrap();
    assert_eq!(first.unwrap(), 10_254, "the first start used the default");
    assert!(
        child.status.success(),
        "override restart: {}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}

/// D391 on a retained kernel link, the other two cases J555 F3 implies (J572, #483).
///
/// An explicit override whose port is taken fails the restart and leaves the link on its old
/// port. Removing the override afterwards moves a link that an override had moved back to the
/// saved default, as a `GotaTun` node does when it binds again on start. Each restart runs in a
/// child process, because the environment is fixed per process.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn restarted_kernel_link_refuses_a_taken_override_and_returns_to_its_saved_port() {
    const NAME: &str =
        "restarted_kernel_link_refuses_a_taken_override_and_returns_to_its_saved_port";
    const CHILD: &str = "J572_KERNEL_RESTART_STATE";
    if let Some(state) = std::env::var_os(CHILD) {
        let restored = Node::restore_with_engine(std::path::Path::new(&state), EngineKind::Kernel);
        let expected = std::env::var("J572_EXPECT").unwrap();
        if expected == "taken" {
            let Err(error) = restored else {
                panic!("a taken explicit port must fail the restart");
            };
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
            assert_eq!(
                Device::identity().unwrap().1,
                10_254,
                "the link moved anyway"
            );
        } else {
            let port = restored.unwrap().listen_port();
            assert_eq!(port, Some(expected.parse().unwrap()));
            assert_eq!(
                Device::identity().unwrap().1,
                expected.parse::<u16>().unwrap()
            );
        }
        return;
    }
    assert!(std::env::var_os("INFRATERNAL_MESH_PORT").is_none());
    let state = private_state("kernel-restart-ports");
    let first = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let identity = node.up()?;
        drop(node);
        Ok::<_, std::io::Error>(identity.port)
    })();
    let restart = |port: Option<&str>, expect: &str| {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "--ignored", NAME, "--nocapture"])
            .env(CHILD, &state)
            .env("J572_EXPECT", expect);
        if let Some(port) = port {
            child.env("INFRATERNAL_MESH_PORT", port);
        }
        child.output().unwrap()
    };
    let holder = std::net::UdpSocket::bind("[::]:32003").unwrap();
    let taken = restart(Some("32003"), "taken");
    drop(holder);
    let moved = restart(Some("32002"), "32002");
    let back = restart(None, "10254");
    remove_link();
    fs::remove_dir_all(&state).unwrap();
    assert_eq!(first.unwrap(), 10_254, "the first start used the default");
    for (case, output) in [
        ("taken override", taken),
        ("override", moved),
        ("override removed", back),
    ] {
        assert!(
            output.status.success(),
            "{case}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// An automatic fallback never lands on the reserved 51820 (J555 note, J572, #483).
///
/// With the default port taken, the kernel fallback asks for any free port. The namespace's
/// ephemeral range is narrowed to 51820-51821, so the kernel's first choice is the reserved
/// port half the time; over eight fresh starts the node must always move off it to 51821. A
/// start where the kernel picks 51820 on all 17 tries (odds about 1 in 130,000) fails.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn kernel_fallback_never_binds_the_reserved_port() {
    const RANGE: &str = "/proc/sys/net/ipv4/ip_local_port_range";
    assert!(std::env::var_os("INFRATERNAL_MESH_PORT").is_none());
    let original = fs::read_to_string(RANGE).unwrap();
    fs::write(RANGE, "51820 51821").unwrap();
    let holder = std::net::UdpSocket::bind("[::]:10254").unwrap();
    // A fresh state each time: a saved fallback would skip the kernel's choice next time.
    let ports = (0..8)
        .map(|run| {
            let state = private_state(&format!("kernel-fallback-reserved-{run}"));
            let port = (|| {
                let mut node = Node::restore_with_engine(&state, EngineKind::Kernel)?;
                let port = node.up()?.port;
                node.down()?;
                Ok::<_, std::io::Error>(port)
            })();
            remove_link();
            fs::remove_dir_all(&state).unwrap();
            port
        })
        .collect::<Result<Vec<_>, _>>();
    drop(holder);
    fs::write(RANGE, original).unwrap();
    assert_eq!(ports.unwrap(), vec![51_821; 8]);
}
