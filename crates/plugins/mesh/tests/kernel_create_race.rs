//! Creating the kernel link never claims or deletes a same-name link another installation made
//! in the meantime (#260, J213 P2, D340). A test seam runs a racing creator between the moment
//! our link exists and the moment we claim the shared name.
#![cfg(all(feature = "test-support", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    policy::model::PublicKey,
    wireguard::{AFTER_LINK_CREATED, Device, INTERFACE},
};
use std::process::Command;

const FOREIGN_ALIAS: &str =
    "infraternal.mesh.v2:2222222222222222222222222222222222222222222222222222222222222222";

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
    *AFTER_LINK_CREATED.lock().unwrap() = Some(Box::new(|| {
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
