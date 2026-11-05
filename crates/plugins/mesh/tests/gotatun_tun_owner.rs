//! Only the infraternal agent's own user can attach the persistent `GotaTun` TUN (#260, J213 P1).
//! The TUN outlives the agent (D332). A queue attached by another local user would read decrypted
//! mesh packets, inject packets, and keep the agent from reattaching after a restart.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    node::{EngineKind, Node},
    wireguard::INTERFACE,
};
use std::{
    fmt::Write as _,
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::Command,
};

/// Set in the child process that tries to attach as `nobody`.
const CHILD: &str = "INFRATERNAL_TUN_OWNER_CHILD";
/// The conventional unprivileged user and group.
const NOBODY: u32 = 65534;

/// A fresh, private (0700) state directory named for this test and process.
fn private_state(name: &str) -> std::path::PathBuf {
    let state = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&state);
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    state
}

/// Child half, run as `nobody`: try to attach one queue to the persisted TUN.
/// Exit 0 when attached, 1 on `EPERM`, 2 on any other error.
#[test]
#[ignore = "Child-only fixture for the TUN owner proof."]
fn attach_child() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let code = match infraternal_linux_tun::Device::open(INTERFACE) {
        Ok(_) => 0,
        Err(error) if error.raw_os_error() == Some(1) => 1,
        Err(error) => {
            eprintln!("attach failed differently: {error}");
            2
        }
    };
    std::process::exit(code);
}

/// The test binary must be readable and executable by `nobody`; run it from a world-readable
/// directory, as real root (an unmapped uid cannot be entered from a user namespace).
#[test]
#[ignore = "Run as real root inside a disposable network namespace; spawns a child as nobody."]
fn an_unprivileged_user_cannot_attach_the_persisted_tun() {
    let state = private_state("gotatun-tun-owner");
    let result = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::GotaTun)?;
        node.up()?;
        // Stopping the agent closes its queue; the TUN stays (D332).
        drop(node);
        let child = Command::new(std::env::current_exe()?)
            .args(["--ignored", "--exact", "attach_child", "--nocapture"])
            .env(CHILD, "1")
            .gid(NOBODY)
            .uid(NOBODY)
            .status()?;
        let mut restarted = Node::restore_with_engine(&state, EngineKind::GotaTun)?;
        let reattached = restarted.up().map(|_| ());
        let _ = restarted.down();
        Ok::<_, std::io::Error>((child.code(), reattached))
    })();
    let _ = Command::new("ip").args(["link", "del", INTERFACE]).status();
    fs::remove_dir_all(&state).unwrap();
    let (child, reattached) = result.unwrap();
    assert_eq!(
        child,
        Some(1),
        "an unprivileged user attached the persisted TUN (exit 0) or failed differently (exit 2)"
    );
    assert!(
        reattached.is_ok(),
        "the agent could not reattach after the refused attempt: {reattached:?}"
    );
}

/// Run `ip` with `args` and require success.
fn ip(args: &[&str]) {
    let status = Command::new("ip").args(args).status().unwrap();
    assert!(status.success(), "ip {args:?}");
}

/// `infraternal0`'s index and its TUN owner and group, as `ip -d link` prints them in the TUN
/// details (a user or group may print as a name).
fn tun_link() -> Option<(u32, Option<String>, Option<String>)> {
    let output = Command::new("ip")
        .args(["-o", "-d", "link", "show", INTERFACE])
        .output()
        .unwrap();
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8(output.stdout).unwrap();
    let index = line.split(':').next()?.trim().parse().ok()?;
    // Only the TUN details section names the TUN's owner; the link's own `group` comes earlier.
    let tun = line
        .split_once("tun type tun")
        .map_or("", |(_, details)| details);
    let after = |word: &str| {
        let mut words = tun.split_whitespace();
        words.find(|w| *w == word)?;
        words.next().map(str::to_owned)
    };
    Some((index, after("user"), after("group")))
}

/// An unrestricted TUN of ours, persisted by a build before #260 J213 P1, is never reattached:
/// the agent deletes it and starts a fresh TUN restricted to its own user and group.
#[test]
#[ignore = "Run as real root inside a disposable network namespace."]
fn an_old_unrestricted_tun_of_ours_is_replaced_by_a_restricted_one() {
    let state = private_state("gotatun-old-tun");
    let result = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::GotaTun)?;
        let key = node.up()?.public_key;
        drop(node);
        // What an earlier build left: a persistent TUN with our marker and no owner or group.
        ip(&["link", "del", INTERFACE]);
        ip(&["tuntap", "add", "dev", INTERFACE, "mode", "tun", "vnet_hdr"]);
        let marker = key.0.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        ip(&[
            "link",
            "set",
            INTERFACE,
            "alias",
            &format!("infraternal.mesh.gotatun.v2:{marker}"),
        ]);
        let old = tun_link();
        let mut restarted = Node::restore_with_engine(&state, EngineKind::GotaTun)?;
        restarted.up()?;
        let new = tun_link();
        restarted.down()?;
        Ok::<_, std::io::Error>((old, new))
    })();
    let _ = Command::new("ip").args(["link", "del", INTERFACE]).status();
    fs::remove_dir_all(&state).unwrap();
    let (old, new) = result.unwrap();
    let (old_index, old_user, old_group) = old.unwrap();
    assert_eq!(
        (old_user, old_group),
        (None, None),
        "the old TUN was not unrestricted"
    );
    let (new_index, new_user, new_group) = new.unwrap();
    assert_ne!(
        new_index, old_index,
        "the agent reattached an unrestricted TUN"
    );
    let root = |id: Option<String>| id.is_some_and(|id| id == "0" || id == "root");
    assert!(
        root(new_user.clone()) && root(new_group.clone()),
        "the new TUN is not restricted to the agent: user {new_user:?}, group {new_group:?}"
    );
}
