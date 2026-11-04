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
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::Command,
};

const CHILD: &str = "INFRATERNAL_TUN_OWNER_CHILD";
/// The conventional unprivileged user and group.
const NOBODY: u32 = 65534;

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
