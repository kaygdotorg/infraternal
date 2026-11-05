//! Break-it review of host-uninstall kernel retirement: `Node::retire` must remove only what this installation made (#235).
//!
//! Run as root inside a disposable network namespace (a container with
//! `CAP_NET_ADMIN`). Each test builds its own fixture interface and state dir.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer, PeerPolicy},
    node::{EngineKind, Node},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
    wireguard::{Device, Key},
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

fn ip(args: &[&str]) -> bool {
    Command::new("ip").args(args).status().unwrap().success()
}
fn link_present() -> bool {
    ip(&["link", "show", "infraternal0"])
}
fn fresh_state(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn cleanup(directory: &Path) {
    let _ = ip(&["link", "delete", "infraternal0"]);
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "infraternal_mesh"])
        .status();
    let _ = fs::remove_dir_all(directory);
}
fn traced<T>(stage: &'static str, result: std::io::Result<T>) -> std::io::Result<T> {
    result.map_err(|error| {
        eprintln!("{stage}: {error:?}");
        error
    })
}

/// The server machine also joins its own mesh through its embedded infraternal
/// agent (D239), with the same fixed interface name and the same component
/// marker. A bootstrap installation on that machine whose state never recorded
/// a mesh node did not make that interface; its uninstall must leave it, or
/// removing the host cuts the server off its own mesh.
#[test]
#[ignore = "Run as root in a disposable network namespace."]
fn retire_leaves_a_marked_interface_this_installation_never_recorded() {
    let state = fresh_state("retire-unrecorded");
    assert!(ip(&["link", "add", "infraternal0", "type", "dummy"]));
    assert!(ip(&[
        "link",
        "set",
        "infraternal0",
        "alias",
        "infraternal.mesh.v1"
    ]));
    let result = Node::retire(&state);
    let survived = link_present();
    cleanup(&state);
    assert!(result.is_ok(), "{result:?}");
    assert!(
        survived,
        "uninstall deleted a mesh interface its installation never recorded"
    );
}

/// An interface with our name but without our marker is not ours. Leaving it
/// is correct; refusing the whole uninstall over it is not, because the helper
/// calls this after the service is already disabled and stopped, so a refusal
/// leaves an offline, still-installed host the server has already forgotten.
#[test]
#[ignore = "Run as root in a disposable network namespace."]
fn retire_leaves_a_foreign_interface_without_failing_the_uninstall() {
    let state = fresh_state("retire-foreign");
    assert!(ip(&["link", "add", "infraternal0", "type", "dummy"]));
    let result = Node::retire(&state);
    let survived = link_present();
    cleanup(&state);
    assert!(survived, "retire deleted an unmarked interface");
    assert!(
        result.is_ok(),
        "a foreign interface aborted the uninstall after the service stopped: {result:?}"
    );
}

/// Ownership of every object is decided before any is deleted: a foreign
/// packet-filter table must not leave the uninstall half done, with our
/// interface already gone and the files kept.
#[test]
#[ignore = "Run as root in a disposable network namespace with nft."]
fn retire_checks_every_object_before_deleting_any() {
    let state = fresh_state("retire-partial");
    assert!(ip(&["link", "add", "infraternal0", "type", "dummy"]));
    assert!(ip(&[
        "link",
        "set",
        "infraternal0",
        "alias",
        "infraternal.mesh.v1"
    ]));
    assert!(
        Command::new("nft")
            .args(["add", "table", "inet", "infraternal_mesh"])
            .status()
            .unwrap()
            .success()
    );
    let result = Node::retire(&state);
    let survived = link_present();
    cleanup(&state);
    assert!(
        result.is_ok() || survived,
        "retire deleted the interface, then refused the foreign table: half-done uninstall"
    );
}

fn owned_table() {
    assert!(
        Command::new("nft")
            .args([
                "add",
                "table",
                "inet",
                "infraternal_mesh",
                "{ comment \"infraternal.mesh.v1\"; }"
            ])
            .status()
            .unwrap()
            .success()
    );
}
fn table_present() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", "infraternal_mesh"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
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

fn install_deny_policy(node: &mut Node, local_key: PublicKey) -> std::io::Result<()> {
    let (_, peer_key) = Key::generate()?;
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
    let applied = node.chunk(chunk)?;
    assert!(applied, "the policy chunk must be applied");
    Ok(())
}

/// The interface and filter this installation's node created go with it (#235).
#[test]
#[ignore = "Run as root in a disposable network namespace with WireGuard and nft."]
fn retire_removes_the_interface_and_filter_this_installation_created() {
    let state = fresh_state("retire-own");
    Node::restore_with_engine(&state, EngineKind::Kernel)
        .unwrap()
        .up()
        .unwrap();
    owned_table();
    let result = Node::retire(&state);
    let (link, table) = (link_present(), table_present());
    cleanup(&state);
    assert!(result.is_ok(), "{result:?}");
    assert!(!link && !table, "link {link}, table {table} survived");
}

/// Two installations on one machine: removing one whose node never made the
/// live interface leaves that interface and its filter to the other (#235).
#[test]
#[ignore = "Run as root in a disposable network namespace with WireGuard and nft."]
fn retire_leaves_another_installations_interface_and_filter() {
    let other = fresh_state("retire-other-owner");
    let ours = fresh_state("retire-other-ours");
    // Ours once made an interface (its record names that key), since replaced.
    Node::restore_with_engine(&ours, EngineKind::Kernel)
        .unwrap()
        .up()
        .unwrap();
    assert!(ip(&["link", "delete", "infraternal0"]));
    Node::restore_with_engine(&other, EngineKind::Kernel)
        .unwrap()
        .up()
        .unwrap();
    owned_table();
    let result = Node::retire(&ours);
    let (link, table) = (link_present(), table_present());
    cleanup(&other);
    cleanup(&ours);
    assert!(result.is_ok(), "{result:?}");
    assert!(
        link && table,
        "link {link}, table {table}: another installation's mesh was removed"
    );
}

/// A `GotaTun` link has the same public name for every installation. Retirement
/// must match the live per-installation marker before deleting that link.
#[test]
#[ignore = "Run as root in a disposable network namespace with CAP_NET_ADMIN."]
fn retire_does_not_remove_another_installations_live_gotatun_tun() {
    let ours = fresh_state("retire-gotatun-old-owner");
    let other = fresh_state("retire-gotatun-live-owner");
    let result = (|| {
        let mut old = traced(
            "restore old",
            Node::restore_with_engine(&ours, EngineKind::GotaTun),
        )?;
        traced("start old", old.up())?;
        assert!(traced("query old TUN", Device::owned_tun())?);
        drop(old);
        // The old TUN outlives its process (D332); the other installation takes the name only
        // once that TUN is gone.
        assert!(ip(&["link", "delete", "infraternal0"]));

        let mut current = traced(
            "restore current",
            Node::restore_with_engine(&other, EngineKind::GotaTun),
        )?;
        traced("start current", current.up())?;
        let retired = traced("retire old", Node::retire(&ours))?;
        let current_tun_survived = traced("query current TUN", Device::owned_tun())?;
        let stopped = current.down();
        Ok::<_, std::io::Error>((retired, current_tun_survived, stopped))
    })();
    cleanup(&ours);
    cleanup(&other);
    let (retired, current_tun_survived, stopped) = result.unwrap();
    assert!(retired.contains(&"infraternal0"));
    assert!(
        current_tun_survived,
        "retiring the old state removed the live GotaTun link"
    );
    assert!(
        stopped.is_ok(),
        "the live installation could not stop: {stopped:?}"
    );
}

/// A stale live node may still own a worker after another installation
/// replaces its interface. `down` must stop only its worker and leave the new
/// installation's TUN and shared firewall in place.
#[test]
#[ignore = "Run as root in a disposable network namespace with CAP_NET_ADMIN."]
fn down_does_not_remove_another_installations_replacement_gotatun_tun() {
    let old_state = fresh_state("down-gotatun-old-owner");
    let current_state = fresh_state("down-gotatun-live-owner");
    let result = (|| {
        let mut old = traced(
            "restore old",
            Node::restore_with_engine(&old_state, EngineKind::GotaTun),
        )?;
        traced("start old", old.up())?;
        assert!(ip(&["link", "delete", "infraternal0"]));

        let mut current = traced(
            "restore current",
            Node::restore_with_engine(&current_state, EngineKind::GotaTun),
        )?;
        traced("start current", current.up())?;
        let old_stopped = old.down();
        let current_tun_survived = traced("query current TUN", Device::owned_tun())?;
        let current_stopped = current.down();
        Ok::<_, std::io::Error>((old_stopped, current_tun_survived, current_stopped))
    })();
    cleanup(&old_state);
    cleanup(&current_state);
    let (old_stopped, current_tun_survived, current_stopped) = result.unwrap();
    assert!(
        old_stopped.is_ok(),
        "stale node down failed: {old_stopped:?}"
    );
    assert!(
        current_tun_survived,
        "stale node down removed the replacement TUN"
    );
    assert!(
        current_stopped.is_ok(),
        "the current installation could not stop: {current_stopped:?}"
    );
}

/// Restoring a disabled installation must not adopt and remove another live
/// `GotaTun` node's shared policy table.
#[test]
#[ignore = "Run as root in a disposable network namespace with CAP_NET_ADMIN and nft."]
fn disabled_restore_leaves_another_gotatun_nodes_installed_policy() {
    let old_state = fresh_state("restore-disabled-gotatun-old-owner");
    let current_state = fresh_state("restore-disabled-gotatun-live-owner");
    let result = (|| {
        let mut old = traced(
            "restore old",
            Node::restore_with_engine(&old_state, EngineKind::GotaTun),
        )?;
        traced("start old", old.up())?;
        traced("stop old", old.down())?;

        let mut current = traced(
            "restore current",
            Node::restore_with_engine(&current_state, EngineKind::GotaTun),
        )?;
        let identity = traced("start current", current.up())?;
        traced(
            "install current policy",
            install_deny_policy(&mut current, identity.public_key),
        )?;
        assert!(
            table_present(),
            "the current node must own an installed policy"
        );

        let restored_old = traced(
            "restore disabled old",
            Node::restore_with_engine(&old_state, EngineKind::GotaTun),
        )?;
        let table_survived = table_present();
        let current_tun_survived = traced("query current TUN", Device::owned_tun())?;
        drop(restored_old);
        let stopped = current.down();
        Ok::<_, std::io::Error>((table_survived, current_tun_survived, stopped))
    })();
    cleanup(&old_state);
    cleanup(&current_state);
    let (table_survived, current_tun_survived, stopped) = result.unwrap();
    assert!(
        table_survived,
        "restoring the disabled old node removed the live node's policy table"
    );
    assert!(
        current_tun_survived,
        "restoring the disabled old node removed the live GotaTun interface"
    );
    assert!(
        stopped.is_ok(),
        "the current node could not stop: {stopped:?}"
    );
}

/// With a recorded interface, an unmarked link that replaced it is still not
/// ours: uninstall leaves it, names it, and does not fail (#235).
#[test]
#[ignore = "Run as root in a disposable network namespace with WireGuard and nft."]
fn retire_with_a_record_leaves_a_foreign_interface_and_names_it() {
    let state = fresh_state("retire-record-foreign");
    Node::restore_with_engine(&state, EngineKind::Kernel)
        .unwrap()
        .up()
        .unwrap();
    assert!(ip(&["link", "delete", "infraternal0"]));
    assert!(ip(&["link", "add", "infraternal0", "type", "dummy"]));
    let result = Node::retire(&state);
    let survived = link_present();
    cleanup(&state);
    assert_eq!(result.unwrap(), ["infraternal0"]);
    assert!(survived, "retire deleted an unmarked interface");
}

/// Our interface next to a foreign table of the filter's name: every object is
/// decided first, ours goes, the foreign table stays and is named (#235).
#[test]
#[ignore = "Run as root in a disposable network namespace with WireGuard and nft."]
fn retire_decides_every_object_and_leaves_a_foreign_table() {
    let state = fresh_state("retire-record-table");
    Node::restore_with_engine(&state, EngineKind::Kernel)
        .unwrap()
        .up()
        .unwrap();
    assert!(
        Command::new("nft")
            .args(["add", "table", "inet", "infraternal_mesh"])
            .status()
            .unwrap()
            .success()
    );
    let planned = Node::plan_retirement(&state).map(|plan| plan.left().to_vec());
    let planned_kept = link_present() && table_present();
    let result = Node::retire(&state);
    let (link, table) = (link_present(), table_present());
    cleanup(&state);
    assert_eq!(planned.unwrap(), ["infraternal_mesh"]);
    assert!(planned_kept, "planning changed the kernel");
    assert_eq!(result.unwrap(), ["infraternal_mesh"]);
    assert!(!link && table, "link {link}, table {table}");
}
