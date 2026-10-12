//! Checks that a marker substring cannot authorize adoption or removal of another firewall's state [166,198], #173.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::firewall::Firewall;
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn command(tool: &str, args: &[&str]) {
    assert!(
        Command::new(tool)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}

#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nft_marker_substring_is_not_table_ownership() {
    let mut create = Command::new("/usr/sbin/nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    create.stdin.take().unwrap().write_all(b"add table inet infraternal_mesh { comment \"operator.reference.infraternal.mesh.v1\"; }\n").unwrap();
    assert!(create.wait().unwrap().success());
    let mut firewall = Firewall::default();
    let adopted = firewall.adopt();
    if adopted.is_ok() {
        firewall.remove().unwrap();
    }
    let retained = Command::new("/usr/sbin/nft")
        .args(["list", "table", "inet", "infraternal_mesh"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    if retained {
        command(
            "/usr/sbin/nft",
            &["delete", "table", "inet", "infraternal_mesh"],
        );
    }
    assert!(
        adopted.is_err() && retained,
        "different table marker accepted as ownership: adopted={} retained={retained}",
        adopted.is_ok()
    );
}

#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nf_tables_marker_substring_is_not_chain_ownership() {
    let tool = "/usr/sbin/iptables-nft";
    command(tool, &["-t", "raw", "-N", "IFM_GUARD"]);
    command(
        tool,
        &[
            "-t",
            "raw",
            "-A",
            "IFM_GUARD",
            "-m",
            "comment",
            "--comment",
            "operator.reference.infraternal.mesh.v1",
            "-j",
            "RETURN",
        ],
    );
    command(tool, &["-t", "raw", "-A", "PREROUTING", "-j", "IFM_GUARD"]);
    let mut firewall = Firewall::nf_tables();
    let adopted = firewall.adopt();
    if adopted.is_ok() {
        firewall.remove().unwrap();
    }
    let retained = Command::new(tool)
        .args(["-t", "raw", "-S", "IFM_GUARD"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    if retained {
        command(tool, &["-t", "raw", "-D", "PREROUTING", "-j", "IFM_GUARD"]);
        command(tool, &["-t", "raw", "-F", "IFM_GUARD"]);
        command(tool, &["-t", "raw", "-X", "IFM_GUARD"]);
    }
    assert!(
        adopted.is_err() && retained,
        "different chain marker accepted as ownership: adopted={} retained={retained}",
        adopted.is_ok()
    );
}
