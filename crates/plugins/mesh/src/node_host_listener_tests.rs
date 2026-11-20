//! Namespace proofs that a `GotaTun` node keeps the host input table's mesh listener in step
//! with its own life, on a host where no firewall tool exists (#483, D384, D386).
//!
//! A server-role host has a default-drop host input table (D392). The mesh needs two holes
//! in it: traffic on `infraternal0` and the UDP port the node's socket bound. On the
//! `GotaTun` engine every grant is enforced in userspace, and the kernel guard is optional,
//! so these holes must open and close whether or not nft or iptables-nft is present.
//! Otherwise such a host drops all mesh traffic (soak finding F5).
//!
//! Each test drives a real node in its own network namespace. It hides every firewall tool
//! from the mesh ([`crate::firewall_tools::HiddenToolsForTest`]) and points the node's host
//! listener updates at a private policy layout under `/run`, applied with a private nft copy,
//! so the machine's own `/var/lib/infraternal` and firewall are never read or changed.
#![allow(clippy::expect_used)]
use super::*;
use crate::{
    dataplane::DefaultPolicy,
    firewall_tools::{HiddenToolsForTest, Tool},
    host_firewall::{
        AllowRule, HostFirewallPaths, HostFirewallPathsTestOverride, NftTestPathOverride, Policy,
        SshdPort, SshdPortsTestOverride, apply_from_config_at, discover_nft, write_policy_file,
    },
    policy::model::{Addresses, NodeId},
};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr as _,
    sync::atomic::{AtomicU64, Ordering},
};

/// Give each host fixture its own directory, even within one test process.
static NEXT_HOST_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// A server-role host with a default-drop host input table and no mesh firewall tool.
///
/// While it lives, this thread's mesh firewall lookups find nothing, the node's host
/// listener updates go to the private layout, and sshd is declared on port 22. Dropping
/// it removes the private layout and restores every override.
struct ServerHost {
    /// The private root holding the policy files and the stand-in systemctl.
    root: PathBuf,
    /// The private nft copy that applies and reads the host table.
    nft: PathBuf,
    // Field order is drop order: the overrides go before the nft copy they point at.
    /// Points `set_mesh_listener` at the private layout.
    _paths: HostFirewallPathsTestOverride,
    /// Declares the sshd the default-drop table must keep reachable.
    _sshd: SshdPortsTestOverride,
    /// Hides nft and iptables-nft from the mesh firewall.
    _hidden: HiddenToolsForTest,
    /// Lets the host firewall run its private nft copy.
    _nft: NftTestPathOverride,
}

impl ServerHost {
    /// Install a default-drop server host table that admits only SSH on port 22.
    fn new() -> Self {
        let nft_override = NftTestPathOverride::with_fixed_nft_fixture();
        let nft = discover_nft(None).expect("the private nft copy passes the fixed-path check");
        let root = Path::new("/run").join(format!(
            "j796-host-listener-{}-{}",
            std::process::id(),
            NEXT_HOST_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("private host root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("protect the private host root");
        let paths = HostFirewallPaths::under(&root);
        let policy_parent = paths
            .server_policy_path()
            .parent()
            .expect("policy folder")
            .to_owned();
        std::fs::create_dir_all(&policy_parent).expect("policy folders");
        // The policy check refuses group-writable folders, whatever the umask made them.
        let mut folder = policy_parent.as_path();
        while folder != root {
            std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o755))
                .expect("protect a policy folder");
            folder = folder.parent().expect("folders stay below the root");
        }
        let systemctl = root.join("systemctl");
        std::fs::write(&systemctl, "#!/bin/sh\nexit 0\n").expect("stand-in systemctl");
        std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755))
            .expect("make the stand-in runnable");
        let sshd = SshdPortsTestOverride::install(&[SshdPort::dual_stack(22)]);
        write_policy_file(
            paths.server_policy_path(),
            &Policy {
                admin_rules: vec![AllowRule::from_str("*,*,tcp,22").expect("SSH rule")],
                ..Policy::default()
            },
        )
        .expect("save the server policy");
        apply_from_config_at(&paths, Some(&nft), Some(&systemctl))
            .expect("install the default-drop server table");
        let hidden = HiddenToolsForTest::install();
        assert!(
            crate::firewall_tools::find(Tool::Nft).is_err()
                && crate::firewall_tools::find(Tool::IptablesNftRestore).is_err(),
            "the mesh must find no firewall tool on this host"
        );
        Self {
            root,
            nft,
            _paths: HostFirewallPathsTestOverride::install(&paths),
            _sshd: sshd,
            _hidden: hidden,
            _nft: nft_override,
        }
    }

    /// The match pairs of every accepting rule in the host input table.
    fn accepted(&self) -> Vec<Vec<(Value, Value)>> {
        let output = Command::new(&self.nft)
            .args(["-j", "list", "table", "inet", "infraternal_host"])
            .output()
            .expect("run nft");
        assert!(
            output.status.success(),
            "list the host table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listing: Value = serde_json::from_slice(&output.stdout).expect("nft JSON");
        let objects = listing["nftables"].as_array().expect("nftables array");
        let input = objects
            .iter()
            .map(|object| &object["chain"])
            .find(|chain| chain["hook"] == "input")
            .expect("an input base chain");
        assert_eq!(
            input["policy"], "drop",
            "the server table stays default-drop"
        );
        objects
            .iter()
            .filter_map(|object| object["rule"]["expr"].as_array())
            .filter(|expressions| expressions.iter().any(|item| item.get("accept").is_some()))
            .map(|expressions| {
                expressions
                    .iter()
                    .filter_map(|item| item.get("match"))
                    .map(|matched| (matched["left"].clone(), matched["right"].clone()))
                    .collect()
            })
            .collect()
    }

    /// Whether some accepting rule matches `left == right`.
    fn admits(&self, left: &Value, right: &Value) -> bool {
        self.accepted().iter().any(|rule| {
            rule.iter()
                .any(|(found_left, found_right)| found_left == left && found_right == right)
        })
    }

    /// Whether the host table admits the mesh: `infraternal0` and UDP to `port`.
    fn admits_mesh(&self, port: u16) -> (bool, bool) {
        (
            self.admits(&json!({"meta": {"key": "iifname"}}), &json!("infraternal0")),
            self.admits(
                &json!({"payload": {"protocol": "udp", "field": "dport"}}),
                &json!(port),
            ),
        )
    }

    /// Whether SSH on port 22 is still admitted, the invariant every host write keeps.
    fn admits_ssh(&self) -> bool {
        self.admits(
            &json!({"payload": {"protocol": "tcp", "field": "dport"}}),
            &json!(22),
        )
    }
}

impl Drop for ServerHost {
    /// Remove the private policy layout; the namespace takes its tables with it.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A one-node snapshot for the identity `key`, with no peers.
fn snapshot(key: crate::policy::model::PublicKey, version: u64) -> Config {
    Config {
        authority_epoch: None,
        rotation_operation: None,
        local_key: Some(key),
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().expect("IPv4"),
            ipv6: "fd01::1".parse().expect("IPv6"),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
    }
}

/// Bring `node` up and apply one snapshot, then check the listener and the missing guard.
fn up_and_apply(node: &mut Node, host: &ServerHost, version: u64) -> u16 {
    let identity = node.up().expect("GotaTun up without any firewall tool");
    assert_eq!(
        host.admits_mesh(identity.port),
        (true, true),
        "up opens infraternal0 and UDP {} in the default-drop host table",
        identity.port
    );
    node.apply(snapshot(identity.public_key, version))
        .expect("a snapshot applies while the optional guard is missing");
    let guard = node
        .kernel_guard_status()
        .expect("a GotaTun node reports its optional guard");
    assert_eq!(guard.state, "missing", "{}", guard.detail);
    assert_eq!(host.admits_mesh(identity.port), (true, true));
    assert!(host.admits_ssh(), "opening the mesh keeps SSH admitted");
    identity.port
}

/// Take `node` down and check that the listener it opened is closed again.
fn down_and_check_closed(node: &mut Node, host: &ServerHost, port: u16) {
    node.down().expect("GotaTun down without any firewall tool");
    assert_eq!(
        host.admits_mesh(port),
        (false, false),
        "down closes infraternal0 and UDP {port}"
    );
    assert!(host.admits_ssh(), "closing the mesh keeps SSH admitted");
}

/// J782's integration fix: with no nft or iptables-nft, a `GotaTun` node still opens its
/// listener in a default-drop host table on up, keeps it through a snapshot, and closes it on
/// down. Before the fix the guard-only paths returned before the host table was touched.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_without_firewall_tools_opens_the_host_listener_on_up_and_closes_it_on_down() {
    let host = ServerHost::new();
    assert_eq!(host.admits_mesh(10_254), (false, false), "closed before up");
    assert!(host.admits_ssh());
    let mut node = Node::default().with_engine(EngineKind::GotaTun);
    let port = up_and_apply(&mut node, &host, 1);
    down_and_check_closed(&mut node, &host, port);
}

/// A `GotaTun` node turned off and on again in one process keeps the optional-guard mode:
/// the second up reopens the listener and a snapshot applies with no firewall tool. A reset to
/// the full kernel policy would leave the listener closed and fail the snapshot.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_down_then_up_keeps_the_optional_guard_and_reopens_the_listener() {
    let host = ServerHost::new();
    let mut node = Node::default().with_engine(EngineKind::GotaTun);
    let first = up_and_apply(&mut node, &host, 1);
    down_and_check_closed(&mut node, &host, first);
    assert!(
        node.kernel_guard_status().is_some(),
        "a stopped GotaTun node keeps the optional-guard mode"
    );
    let second = up_and_apply(&mut node, &host, 2);
    down_and_check_closed(&mut node, &host, second);
}

/// A host write that would cut sshd off is refused even when it only closes the mesh, and the
/// node keeps that cleanup pending instead of forgetting it.
///
/// This keeps the intent of dev's `kernel_firewall_cleanup_failure_reports_stopping…` test,
/// which the D386 merge retired because an unmarked mesh table no longer makes cleanup fail.
/// Here sshd moves to 2222 while the saved server policy admits only 22, so the J671 check
/// refuses the listener close at `mesh.down`: the old table (SSH on 22 and the mesh listener)
/// stays, status reads `Stopping`, and a reconnect does not restart the mesh. Once sshd is back
/// on 22, a second `mesh.down` finishes the close.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn a_refused_listener_close_reports_stopping_and_keeps_explicit_off() {
    let host = ServerHost::new();
    let mut plugin = crate::node_actions::MeshNodePlugin::from_node(
        Node::default().with_engine(EngineKind::GotaTun),
    );
    let call = |plugin: &mut crate::node_actions::MeshNodePlugin, action: &str| {
        infraternal_plugin_api::AgentPlugin::call(plugin, action, b"{}")
    };
    let identity: Value =
        serde_json::from_slice(&call(&mut plugin, "mesh.up").expect("mesh up")).expect("JSON");
    let port = u16::try_from(identity["port"].as_u64().expect("bound port")).expect("UDP port");
    assert_eq!(host.admits_mesh(port), (true, true));
    {
        let _moved = SshdPortsTestOverride::install(&[SshdPort::dual_stack(2222)]);
        assert!(
            call(&mut plugin, "mesh.down").is_err(),
            "closing the listener would leave a table that drops sshd on 2222"
        );
        let status: Value =
            serde_json::from_slice(&call(&mut plugin, "mesh.status").expect("status"))
                .expect("JSON");
        assert_eq!(status["state"], "Stopping");
        assert_eq!(
            host.admits_mesh(port),
            (true, true),
            "a refused write leaves the old table in place"
        );
        assert!(host.admits_ssh());
        assert_eq!(
            call(&mut plugin, "mesh.identity").expect("reconnect"),
            b"null",
            "a reconnect keeps the explicit off"
        );
    }
    let down: Value =
        serde_json::from_slice(&call(&mut plugin, "mesh.down").expect("finish the close"))
            .expect("JSON");
    assert_eq!(down["state"], "Off");
    assert_eq!(host.admits_mesh(port), (false, false));
    assert!(host.admits_ssh());
}
