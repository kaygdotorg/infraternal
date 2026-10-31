//! Verifies that permitted home aliases preserve the open-descriptor recovery fence (#195, D17/D139).
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::{model::InstallMode, previous_attempt};
use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn check(home: &Path) -> Output {
    Command::new("/bin/sh")
        .args(["-c", &previous_attempt::check_script(InstallMode::Rootless)])
        .env("HOME", home)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent-review-bus",
        )
        .output()
        .unwrap()
}

#[test]
fn home_alias_keeps_open_setup_descriptor_live() {
    let scratch = common::scratch();
    let root = scratch.join(format!("liveness-{}", uuid::Uuid::new_v4().simple()));
    let fixture = Fixture(root.clone());
    let home = root.join("real-home");
    let parent = home.join(".local/share");
    let base = parent.join("infraternal");
    for directory in [&root, &home, &home.join(".local"), &parent, &base] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let host = uuid::Uuid::new_v4().simple().to_string();
    let transaction = uuid::Uuid::new_v4().simple().to_string();
    let marker = base.join(".bootstrap-owner");
    fs::write(&marker, format!("{host}\n")).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    let metadata = fs::metadata(&base).unwrap();
    let receipt = parent.join(format!("infraternal.bootstrap-rollback-{transaction}"));
    fs::write(
        &receipt,
        format!(
            "{host} {transaction} fresh {}:{}\n",
            metadata.dev(),
            metadata.ino()
        ),
    )
    .unwrap();
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = root.join("home-alias");
    symlink(&home, &alias).unwrap();

    // Keep the same inode open across both checks. The canonical control proves
    // this process's descriptor is visible to the production /proc traversal.
    let held = File::open(&marker).unwrap();
    assert_eq!(check(&home).status.code(), Some(73));
    let observed = check(&alias);
    let stale = observed
        .stdout
        .windows(b"INFRATERNAL_SETUP_STALE".len())
        .any(|window| window == b"INFRATERNAL_SETUP_STALE");
    println!(
        "canonical_status=73 alias_status={:?} alias_reports_stale={stale}",
        observed.status.code()
    );
    assert_eq!(
        observed.status.code(),
        Some(73),
        "a permitted home alias must keep the same open setup descriptor live"
    );
    drop(held);
    drop(fixture);
}
