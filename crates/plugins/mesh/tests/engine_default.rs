//! `GotaTun` is the Linux default engine, kernel `WireGuard` an explicit per-machine opt-out, and
//! a node that never chose moves to `GotaTun` with its identity kept (D346, #260).
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    node::{EngineKind, Node},
    wireguard::{Device, INTERFACE},
};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn private_state(name: &str) -> std::path::PathBuf {
    let state = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&state);
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    state
}

fn remove_link() {
    let _ = Command::new("ip").args(["link", "del", INTERFACE]).status();
}

/// Which engine holds the shared link name, read from the link itself.
fn running_engine() -> Option<&'static str> {
    if Device::owned_tun().unwrap_or(false) {
        Some("gotatun")
    } else if Device::owned().unwrap_or(false) {
        Some("kernel")
    } else {
        None
    }
}

fn no_choice_in_environment() {
    assert!(
        std::env::var_os("INFRATERNAL_MESH_ENGINE").is_none(),
        "these tests cover a machine with no engine choice in its environment"
    );
}

#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_new_node_runs_gotatun_by_default() {
    no_choice_in_environment();
    let state = private_state("engine-default-new");
    let result = (|| {
        let mut node = Node::restore(&state)?;
        node.up()?;
        let engine = running_engine();
        node.down()?;
        Ok::<_, std::io::Error>(engine)
    })();
    remove_link();
    fs::remove_dir_all(&state).unwrap();
    assert_eq!(result.unwrap(), Some("gotatun"));
}

#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn kernel_stays_an_explicit_opt_out_across_restarts() {
    let state = private_state("engine-opt-out");
    let result = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let first = node.up()?.public_key;
        let started = running_engine();
        drop(node);
        let mut restarted = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let again = restarted.up()?.public_key;
        let kept = running_engine();
        restarted.down()?;
        Ok::<_, std::io::Error>((started, kept, first == again))
    })();
    remove_link();
    fs::remove_dir_all(&state).unwrap();
    assert_eq!(result.unwrap(), (Some("kernel"), Some("kernel"), true));
}

/// A node that ran kernel `WireGuard` only because it was the default before D346 restarts on
/// `GotaTun` with the same public key, so its peers and the coordinator see no change.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_node_that_never_chose_moves_to_gotatun_and_keeps_its_key() {
    no_choice_in_environment();
    let state = private_state("engine-upgrade");
    let result = (|| {
        let mut old = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        let key = old.up()?.public_key;
        drop(old);
        // What the earlier release left: a kernel engine record it wrote because kernel was
        // the default, not because anyone chose it.
        let mut upgraded = Node::restore(&state)?;
        let again = upgraded.up()?.public_key;
        let engine = running_engine();
        upgraded.down()?;
        Ok::<_, std::io::Error>((engine, key == again))
    })();
    remove_link();
    fs::remove_dir_all(&state).unwrap();
    assert_eq!(result.unwrap(), (Some("gotatun"), true));
}

const PIN_CHILD: &str = "INFRATERNAL_ENGINE_PIN_CHILD";

/// Child half, run with `INFRATERNAL_MESH_ENGINE=gotatun`: restore with kernel chosen in code.
/// Exit 0 when kernel runs, 1 when `GotaTun` runs, 2 on an error.
#[test]
#[ignore = "Child-only fixture for the engine precedence proof."]
fn explicit_engine_child() {
    if std::env::var_os(PIN_CHILD).is_none() {
        return;
    }
    let state = private_state("engine-pin-child");
    let engine = (|| {
        let mut node = Node::restore_with_engine(&state, EngineKind::Kernel)?;
        node.up()?;
        let engine = running_engine();
        node.down()?;
        Ok::<_, std::io::Error>(engine)
    })();
    remove_link();
    let _ = fs::remove_dir_all(&state);
    std::process::exit(match engine {
        Ok(Some("kernel")) => 0,
        Ok(_) => 1,
        Err(error) => {
            eprintln!("explicit engine child failed: {error}");
            2
        }
    });
}

/// An engine chosen in code wins over `INFRATERNAL_MESH_ENGINE` (#260 J213 P3): the variable
/// selects the engine only where the code leaves the choice to the machine (`Node::restore`).
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn an_engine_chosen_in_code_wins_over_the_environment() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "explicit_engine_child",
            "--nocapture",
        ])
        .env(PIN_CHILD, "1")
        .env("INFRATERNAL_MESH_ENGINE", "gotatun")
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "the environment overrode the engine chosen in code (1 = GotaTun ran, 2 = error)"
    );
}

const DEFAULT_PATH_CHILD: &str = "INFRATERNAL_ENGINE_DEFAULT_PATH_CHILD";

/// Child half, run with `INFRATERNAL_MESH_ENGINE=kernel`: bring up a node that was not restored.
/// Exit 0 when `GotaTun` runs, 1 when kernel runs, 2 on an error.
#[test]
#[ignore = "Child-only fixture for the engine environment scope proof."]
fn default_path_child() {
    if std::env::var_os(DEFAULT_PATH_CHILD).is_none() {
        return;
    }
    let engine = (|| {
        let mut node = Node::default();
        node.up()?;
        let engine = running_engine();
        node.down()?;
        Ok::<_, std::io::Error>(engine)
    })();
    remove_link();
    std::process::exit(match engine {
        Ok(Some("gotatun")) => 0,
        Ok(_) => 1,
        Err(error) => {
            eprintln!("default path child failed: {error}");
            2
        }
    });
}

/// `INFRATERNAL_MESH_ENGINE` selects the engine only on the infraternal agent's restore path
/// (#260 J220 P3): a node that was not restored, such as the plugin's default `mesh.up`, runs the
/// default engine whatever the variable says.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn the_environment_selects_only_on_the_restore_path() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "default_path_child", "--nocapture"])
        .env(DEFAULT_PATH_CHILD, "1")
        .env("INFRATERNAL_MESH_ENGINE", "kernel")
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "the environment selected the engine outside restore (1 = kernel ran, 2 = error)"
    );
}
