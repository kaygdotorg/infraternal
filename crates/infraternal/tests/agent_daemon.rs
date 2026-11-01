//! Exercise inherited leg B and randomized and barrier-controlled abrupt daemon stops/restarts through the real binary [9][13][41].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::{path::PathBuf, process::Command};

#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_defers_backend_detection_until_first_terminal() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("scripts/verify-agent-lazy-manager.py")
        .args(["--binary", env!("CARGO_BIN_EXE_infraternal")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "lazy login backend oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn real_binary_preserves_input_and_output_across_24_abrupt_stops() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("scripts/verify-agent.py")
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_infraternal"),
            "--functional",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "real-binary daemon oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_readiness_and_person_terminal_use_own_account() {
    if nix::unistd::Uid::effective().is_root() {
        return; // This contract concerns a daemon without root privileges.
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-logins.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rootless login oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_person_preparation_honors_explicit_state_without_runtime_environment() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-explicit-state.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rootless explicit-state preparation refused:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// D18 inherits the account context; D240 still requires retiring the
/// revoked person's existing terminals without stopping another person's.
#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_person_revocation_stops_existing_shells() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-revoke-live.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rootless live-shell revocation oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Person ownership and detached descendant retirement survive daemon restart.
#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_revocation_after_restart_stops_every_owned_terminal() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-revoke-live.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .arg("--expanded")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "restart/descendant oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Ordinary owner links must not prevent explicit person cleanup [D18,D240].
#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_revocation_is_admitted_at_full_shim_peer_capacity() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-revoke-capacity.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rootless cleanup admission oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A terminal subreaper releases completed adopted jobs before shell exit [D18,D240].
#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_terminal_reaps_completed_adopted_children() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-adopted-children.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rootless adopted-child oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
/// A complete authenticated stop request remains owned after its sender closes.
#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_cleanup_survives_sender_disconnect_before_readiness() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-stop-disconnect.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rootless disconnected-cleanup oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Sealed retirement releases attribution independently of explicit access removal.
#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_retirement_releases_person_terminal_records() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-retired-records.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rootless retired-attribution oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A private canary is not a person terminal and cannot invalidate cleanup proof.
#[cfg(feature = "plugin-agent")]
#[test]
fn real_binary_rootless_private_readiness_does_not_refuse_person_revocation() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("-B")
        .arg("scripts/test-rootless-revoke-readiness.py")
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "private readiness cleanup oracle refused:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
