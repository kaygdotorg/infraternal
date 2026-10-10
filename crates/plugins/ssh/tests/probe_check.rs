//! Executes the fixed system sniff with a service-manager oracle that refuses private environment access.
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::probe::{CHECK_SCRIPT, Check};
use std::os::unix::fs::PermissionsExt;

#[test]
fn manager_availability_does_not_request_its_private_environment() {
    let parent = common::scratch();
    let root = parent.join(format!("probe-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&root).unwrap();
    let marker = root.join("private-access-requested");
    let tool = root.join("systemctl");
    std::fs::write(&tool, format!("#!/bin/sh\ncase \"$*\" in\n*environment*) : > '{}'; exit 1;;\n'--user show --property=Version --value') printf '257\\n';;\n*) exit 1;;\nesac\n", marker.display())).unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", CHECK_SCRIPT])
        .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
        .output()
        .unwrap();
    let requested_private_environment = marker.exists();
    std::fs::remove_dir_all(root).unwrap();
    assert!(output.status.success());
    assert!(
        !requested_private_environment,
        "read-only sniff requested the service manager's private environment"
    );
    assert!(Check::parse(&output.stdout).unwrap().user_systemd);
}
