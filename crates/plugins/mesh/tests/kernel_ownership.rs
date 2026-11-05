//! The kernel mesh path changes or deletes only an `infraternal0` link this installation created
//! (D340, #260). The link name and its engine marker are shared by every installation on a host,
//! so a marked kernel link can be another installation's or another server's node, keyed or not
//! yet keyed. Restore, `up`, `down` and the uninstall plan must leave such a link exactly as found.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    node::{EngineKind, Node},
    policy::model::PublicKey,
    wireguard::{Device, INTERFACE, Key},
};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

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
