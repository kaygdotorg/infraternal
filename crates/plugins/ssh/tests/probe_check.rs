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

/// The real Alpine probe is canonical, but unsupported init needs an actionable explanation.
#[test]
fn breakit2_no_systemd_names_the_required_manager() {
    let alpine = b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nother\n1101\nno\nno\nno\nno\n";
    let refusal = Check::parse(alpine).unwrap_err();
    assert!(
        refusal.message.contains("systemd"),
        "a canonical unsupported-init record must name the required manager: {}",
        refusal.message
    );
}

/// Startup output and a shell that exits before the command must remain refused,
/// with a useful next step instead of silently accepting banner text.
#[test]
fn shell_startup_refusal_names_an_interactive_only_remedy() {
    for record in [b"".as_slice(), b"public startup greeting\nINFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1101\nno\nyes\nyes\nno\n".as_slice()] {
        let refused = Check::parse(record).unwrap_err();
        assert!(refused.message.contains("interactive"));
        assert!(!refused.message.contains("public startup greeting"));
    }
}
