//! Checks that exact infraternal table names define product ownership, D386, #173.
#![cfg(all(feature = "agent", feature = "test-support", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    firewall::Firewall,
    host_firewall::{NftTestPathOverride, discover_nft},
};
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
fn infraternal_mesh_table_is_owned_even_with_an_unfamiliar_comment() {
    let _nft_override = NftTestPathOverride::with_fixed_nft_fixture();
    let nft = discover_nft(None).expect("fixed-path test fixture");
    let mut create = Command::new(&nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    create.stdin.take().unwrap().write_all(b"add table inet infraternal_mesh { comment \"operator.reference.infraternal.mesh.v1\"; }\n").unwrap();
    assert!(create.wait().unwrap().success());
    let mut firewall = Firewall::default();
    firewall
        .adopt()
        .expect("the exact infraternal table name is product-owned");
    assert!(firewall.installed());
    firewall.remove().unwrap();
    let retained = Command::new(&nft)
        .args(["list", "table", "inet", "infraternal_mesh"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(
        !retained,
        "the exact infraternal table was not removed by the product"
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
