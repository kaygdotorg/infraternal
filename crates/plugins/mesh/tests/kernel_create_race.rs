//! Creating the kernel link never claims or deletes a same-name link another installation made
//! in the meantime (#260, J213 P2, D340). A test seam runs a racing creator between the moment
//! our link exists and the moment we claim the shared name.
#![cfg(all(feature = "test-support", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    node::{BEFORE_KERNEL_KEY, EngineKind, Node},
    policy::model::PublicKey,
    wireguard::{AFTER_LINK_CREATED, Device, INTERFACE},
};
use std::{
    process::Command,
    sync::{Arc, Mutex},
};

/// The owner marker of the racing installation, distinct from the key our tests create with.
const FOREIGN_ALIAS: &str =
    "infraternal.mesh.v2:2222222222222222222222222222222222222222222222222222222222222222";

/// Run `ip` with `args`; true when it succeeded.
fn ip(args: &[&str]) -> bool {
    Command::new("ip").args(args).status().unwrap().success()
}

/// Every link in this namespace as `(index, name, alias)`, read with `ip` rather than our code.
fn links() -> Vec<(u32, String, Option<String>)> {
    let output = Command::new("ip")
        .args(["-o", "-d", "link", "show"])
        .output()
        .unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, ": ");
            let index = parts.next()?.trim().parse().ok()?;
            let name = parts.next()?.split('@').next()?.to_owned();
            let alias = line.split(" alias ").nth(1).map(|rest| {
                rest.split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            });
            Some((index, name, alias))
        })
        .collect()
}

/// Another installation takes the shared name while our new link is not yet claimed: its link
/// keeps its marker, our creation fails, and nothing of ours is left behind.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_racing_creator_keeps_its_link_and_its_marker() {
    let _ = ip(&["link", "del", INTERFACE]);
    let before: Vec<u32> = links().iter().map(|link| link.0).collect();
    // Between our creation and our claim, another installation removes whatever holds the
    // name (it may only remove its own, so a miss is fine) and creates its own marked link.
    *AFTER_LINK_CREATED.lock().unwrap() = Some(Box::new(|_temporary| {
        let _ = ip(&["link", "del", INTERFACE]);
        assert!(ip(&["link", "add", INTERFACE, "type", "wireguard"]));
        assert!(ip(&["link", "set", INTERFACE, "alias", FOREIGN_ALIAS]));
    }));
    let created = Device::create(PublicKey([0x11; 32]));
    let after = links();
    let _ = ip(&["link", "del", INTERFACE]);

    let foreign = after.iter().find(|link| link.1 == INTERFACE);
    assert_eq!(
        foreign.and_then(|link| link.2.as_deref()),
        Some(FOREIGN_ALIAS),
        "create relabelled or deleted the racing installation's link: {after:?}"
    );
    assert!(
        created.is_err(),
        "create reported success for a name another installation holds"
    );
    let leftovers: Vec<_> = after
        .iter()
        .filter(|link| !before.contains(&link.0) && link.1 != INTERFACE)
        .collect();
    assert!(
        leftovers.is_empty(),
        "create left a link behind: {leftovers:?}"
    );
}

/// The index of the link named `name` in this namespace, if it exists.
fn index_named(name: &str) -> Option<u32> {
    links()
        .into_iter()
        .find(|link| link.1 == name)
        .map(|link| link.0)
}

/// Replace our new link under its temporary name with another privileged creator's link, and
/// optionally occupy the shared name too. Returns the replacement's name and index once the
/// hook has run.
fn replace_new_link(occupy_shared_name: bool) -> Arc<Mutex<Option<(String, u32)>>> {
    let replaced = Arc::new(Mutex::new(None));
    let record = Arc::clone(&replaced);
    *AFTER_LINK_CREATED.lock().unwrap() = Some(Box::new(move |temporary: &str| {
        assert!(ip(&["link", "del", temporary]));
        assert!(ip(&["link", "add", temporary, "type", "wireguard"]));
        if occupy_shared_name {
            assert!(ip(&["link", "add", INTERFACE, "type", "dummy"]));
        }
        let index = index_named(temporary).unwrap();
        *record.lock().unwrap() = Some((temporary.to_owned(), index));
    }));
    replaced
}

/// J220 P2, first window: another privileged process replaces our link under its temporary
/// name before we address it again. The replacement must keep its name and stay unmarked, and
/// creation must fail.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_replacement_before_lookup_is_never_claimed() {
    let _ = ip(&["link", "del", INTERFACE]);
    let replaced = replace_new_link(false);
    let created = Device::create(PublicKey([0x11; 32]));
    let after = links();
    let (name, index) = replaced.lock().unwrap().clone().unwrap();
    let _ = ip(&["link", "del", &name]);
    let _ = ip(&["link", "del", INTERFACE]);
    let replacement = after.iter().find(|link| link.0 == index);
    assert_eq!(
        replacement,
        Some(&(index, name.clone(), None)),
        "create renamed or marked a replacement link: {after:?}"
    );
    assert!(created.is_err(), "create claimed a link it did not make");
}

/// J220 P2, second window: when our claim then fails, cleanup must not delete the replacement.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn cleanup_never_deletes_a_replacement() {
    let _ = ip(&["link", "del", INTERFACE]);
    let replaced = replace_new_link(true);
    let created = Device::create(PublicKey([0x11; 32]));
    let after = links();
    let (name, index) = replaced.lock().unwrap().clone().unwrap();
    let _ = ip(&["link", "del", &name]);
    let _ = ip(&["link", "del", INTERFACE]);
    assert!(
        after.iter().any(|link| link.0 == index),
        "create's cleanup deleted a replacement link: {after:?}"
    );
    assert!(created.is_err(), "create succeeded without its own link");
}

/// J220 P2, third window: our claimed link is replaced before the private key goes in. The key
/// must never reach the replacement, and `up` must fail.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_replacement_after_the_claim_never_receives_the_key() {
    let _ = ip(&["link", "del", INTERFACE]);
    *BEFORE_KERNEL_KEY.lock().unwrap() = Some(Box::new(|| {
        assert!(ip(&["link", "del", INTERFACE]));
        assert!(ip(&["link", "add", INTERFACE, "type", "wireguard"]));
    }));
    let mut node = Node::default().with_engine(EngineKind::Kernel);
    let up = node.up().map(|identity| identity.public_key);
    let replacement_key = Device::identity().ok().map(|(key, _)| key);
    let _ = node.down();
    let _ = ip(&["link", "del", INTERFACE]);
    assert!(
        replacement_key.is_none_or(|key| key.0 == [0; 32]),
        "the replacement link received this node's private key: public {replacement_key:?}"
    );
    assert!(
        up.is_err(),
        "up succeeded on a link it did not make: {up:?}"
    );
}
