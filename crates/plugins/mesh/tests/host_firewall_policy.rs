//! Checks that typed settings produce the exact narrow host input policy.
#![cfg(target_os = "linux")]
#![expect(
    clippy::expect_used,
    reason = "fixture failures need the exact stage that failed"
)]

use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Command, Stdio},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use serde_json::{Value, json};

use infraternal_plugin_mesh::host_firewall::{
    AllowRule, HostFirewallPaths, Listener, Policy, PolicyRole, Protocol, apply_from_config_at,
    apply_with_ssh_connection, clear_role_from_config_at, discover_nft, read_policy_file, render,
    rollback_agent_policy, set_mesh_listener_at, validate, validate_ssh_connection_on,
    write_policy_file,
};

/// sshd as these namespace tests model it: listening on 22 in both families.
///
/// The namespaces have no sshd of their own and cannot read the host's, so
/// each test states the sshd its default-drop table must keep reachable;
/// the J671 check still runs on every apply (`check_sshd_admission`).
#[cfg(feature = "test-support")]
fn sshd_on_22() -> infraternal_plugin_mesh::host_firewall::SshdPortsTestOverride {
    infraternal_plugin_mesh::host_firewall::SshdPortsTestOverride::install(&[
        infraternal_plugin_mesh::host_firewall::SshdPort::dual_stack(22),
    ])
}

/// Supplies the private nft command and namespace setup used by these policy tests.
#[path = "support/nft_fixture.rs"]
mod nft_fixture;

use nft_fixture::NftFixture;

/// Give each temporary policy layout a unique private directory.
static NEXT_CONFIG_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// Catch accidental use of the installed policy before a fixture opens either role file.
#[cfg(feature = "test-support")]
#[test]
#[ignore = "Run with verify-privileged in a disposable user and mount namespace."]
fn privileged_fixture_refuses_live_policy_paths() {
    assert!(
        std::env::var_os("INFRATERNAL_VERIFY_OUTER_NETNS").is_some(),
        "run this fixture through scripts/verify-privileged"
    );
    let paths = HostFirewallPaths::system();
    let read = read_policy_file(paths.server_policy_path()).expect_err("refuse the system read");
    let write = write_policy_file(paths.agent_policy_path(), &Policy::default())
        .expect_err("refuse the system write");
    for error in [read, write] {
        assert!(
            error
                .to_string()
                .contains("privileged test refused to access live state"),
            "{error}"
        );
    }
}

/// Build a prod-shaped policy without depending on a host or installed nft tool.
fn prod_policy(mesh_enabled: bool) -> Policy {
    Policy {
        admin_rules: vec![
            AllowRule::from_str("eth0,*,udp,51820").expect("mesh transport ingress"),
            AllowRule::from_str("wt0,10.69.69.0/24,tcp,22").expect("admin SSH path"),
            AllowRule::from_str("wt0,10.69.69.99,tcp,7011").expect("private ingress source"),
            AllowRule::from_str("eth0,10.69.0.99,tcp,7011").expect("public ingress source"),
            AllowRule::from_str("eth0,10.69.0.99,tcp,7012").expect("proxy health listener"),
            AllowRule::from_str("wt0,10.69.69.0/24,tcp,7443").expect("existing remote TCP path"),
            AllowRule::from_str("wt0,10.69.69.0/24,udp,7443").expect("existing remote UDP path"),
        ],
        accept_interfaces: vec!["wt0".to_owned()],
        listeners: vec![
            Listener {
                interface: Some("eth0".to_owned()),
                address: "10.69.0.89:7011"
                    .parse::<SocketAddr>()
                    .expect("server address"),
                protocol: Protocol::Tcp,
                sources: vec!["10.69.0.99".parse().expect("trusted proxy source")],
            },
            Listener {
                interface: Some("wt0".to_owned()),
                address: "10.69.69.89:7443"
                    .parse::<SocketAddr>()
                    .expect("remote listener address"),
                protocol: Protocol::Tcp,
                sources: vec!["10.69.69.0/24".parse().expect("remote source network")],
            },
            Listener {
                interface: Some("wt0".to_owned()),
                address: "10.69.69.89:7443"
                    .parse::<SocketAddr>()
                    .expect("remote listener address"),
                protocol: Protocol::Udp,
                sources: vec!["10.69.69.0/24".parse().expect("remote source network")],
            },
        ],
        mesh_enabled,
        mesh_udp_port: None,
    }
}

/// Check that prod settings reproduce the ordered host table without duplicate listener rules.
#[test]
fn prod_shaped_policy_renders_listeners_admin_rules_and_default_drop() {
    let policy = prod_policy(false);
    let rules = render(&policy).expect("valid host policy");

    assert_eq!(
        rules,
        concat!(
            "table inet infraternal_host {\n",
            "    chain input {\n",
            "        type filter hook input priority filter - 10; policy drop;\n",
            "        iifname \"wt0\" accept\n",
            "        iifname \"lo\" accept\n",
            "        ct state invalid drop\n",
            "        ct state established,related accept\n",
            "        ip protocol icmp accept\n",
            "        meta l4proto ipv6-icmp accept\n",
            "        ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n",
            "        iifname \"eth0\" udp dport 51820 accept\n",
            "        iifname \"wt0\" ip saddr 10.69.69.0/24 tcp dport 22 accept\n",
            "        iifname \"wt0\" ip saddr 10.69.69.99 tcp dport 7011 accept\n",
            "        iifname \"eth0\" ip saddr 10.69.0.99 tcp dport 7011 accept\n",
            "        iifname \"eth0\" ip saddr 10.69.0.99 tcp dport 7012 accept\n",
            "        iifname \"wt0\" ip saddr 10.69.69.0/24 tcp dport 7443 accept\n",
            "        iifname \"wt0\" ip saddr 10.69.69.0/24 udp dport 7443 accept\n",
            "        iifname \"eth0\" ip saddr 10.69.0.99 ip daddr 10.69.0.89 tcp dport 7011 accept\n",
            "        iifname \"wt0\" ip saddr 10.69.69.0/24 ip daddr 10.69.69.89 tcp dport 7443 accept\n",
            "        iifname \"wt0\" ip saddr 10.69.69.0/24 ip daddr 10.69.69.89 udp dport 7443 accept\n",
            "    }\n",
            "}\n",
        )
    );
}

/// Render wildcard listeners without creating an impossible destination match.
#[test]
fn wildcard_listener_does_not_match_the_unspecified_address_as_a_destination() {
    let policy = Policy {
        admin_rules: vec![
            AllowRule::from_str("wt0,10.69.69.0/24,tcp,22").expect("typed SSH administrator rule"),
        ],
        listeners: vec![Listener {
            interface: Some("eth0".to_owned()),
            address: "0.0.0.0:7011".parse().expect("wildcard listener"),
            protocol: Protocol::Tcp,
            sources: vec!["10.69.0.99".parse().expect("trusted proxy source")],
        }],
        ..Policy::default()
    };

    let rules = render(&policy).expect("valid wildcard listener policy");

    assert!(rules.contains("iifname \"eth0\" ip saddr 10.69.0.99 tcp dport 7011 accept"));
    assert!(!rules.contains("ip daddr 0.0.0.0"));
}

/// Omit an impossible IPv6 destination match for a listener bound to every address.
#[test]
fn ipv6_wildcard_listener_omits_the_unspecified_destination() {
    let policy = Policy {
        admin_rules: vec![
            AllowRule::from_str("wt0,fd00::/64,tcp,22").expect("typed IPv6 SSH admin rule"),
        ],
        listeners: vec![Listener {
            interface: Some("eth0".to_owned()),
            address: "[::]:7011".parse().expect("IPv6 wildcard listener"),
            protocol: Protocol::Tcp,
            sources: vec!["fd00::99".parse().expect("trusted IPv6 proxy source")],
        }],
        ..Policy::default()
    };

    let rules = render(&policy).expect("valid IPv6 wildcard listener policy");

    assert!(rules.contains("iifname \"eth0\" ip6 saddr fd00::99 tcp dport 7011 accept"));
    assert!(!rules.contains("ip6 daddr ::"));
}

/// Check that mesh activation adds its TUN and UDP input while keeping default-drop.
#[test]
fn mesh_policy_adds_tun_and_fixed_udp_port_without_changing_default_drop() {
    let rules = render(&prod_policy(true)).expect("valid mesh host policy");

    assert!(rules.contains("iifname \"infraternal0\" accept"));
    assert!(rules.contains("udp dport 10254 accept"));
    assert!(rules.contains("policy drop;"));
}

/// Merge independent server and agent settings while keeping each firewall rule once.
#[test]
fn server_and_agent_policy_merge_listeners_admin_rules_and_mesh_state() {
    let server = prod_policy(false);
    let agent = Policy {
        admin_rules: vec![server.admin_rules[0].clone()],
        mesh_enabled: true,
        ..Policy::default()
    };

    let combined =
        infraternal_plugin_mesh::host_firewall::combine(Some(server.clone()), Some(agent));

    assert_eq!(combined.listeners, server.listeners);
    assert_eq!(combined.admin_rules, server.admin_rules);
    assert_eq!(combined.accept_interfaces, server.accept_interfaces);
    assert!(combined.mesh_enabled);
}

/// Reject a host policy that has no explicit TCP admin rule (sshd may use any port).
#[test]
fn policy_without_tcp_ssh_admin_rule_is_rejected() {
    let mut policy = prod_policy(false);
    policy
        .admin_rules
        .retain(|rule| rule.protocol != Protocol::Tcp);

    assert!(validate(&policy).is_err());
    assert!(render(&policy).is_err());
}

/// Preserve the active remote shell's source network before changing nft state.
#[test]
fn bad_policy_cannot_remove_the_ssh_source_running_the_apply_command() {
    let mut policy = prod_policy(false);
    policy.admin_rules.retain(|rule| rule.port != 22);
    policy
        .admin_rules
        .push(AllowRule::from_str("wt0,10.69.70.0/24,tcp,22").expect("different admin network"));

    assert!(
        validate_ssh_connection_on(&policy, "10.69.69.5 43122 10.69.69.89 22", Some("wt0"),)
            .is_err()
    );
}

/// Accept an active shell only when a typed admin rule covers its source and interface.
#[test]
fn current_ssh_source_is_preserved_by_a_valid_policy() {
    let policy = prod_policy(false);

    assert!(
        validate_ssh_connection_on(&policy, "10.69.69.5 43122 10.69.69.89 22", Some("wt0"),)
            .is_ok()
    );
}

/// Reject a source prefix from another family than the listener address.
#[test]
fn listener_rejects_a_source_from_the_other_address_family() {
    let mut policy = prod_policy(false);
    policy.listeners[0].sources = vec!["fd00::/64".parse().expect("IPv6 source")];

    assert!(validate(&policy).is_err());
}

/// Keep nft rule values inside the product's typed grammar.
#[test]
fn malformed_admin_rule_is_rejected_without_becoming_nft_source() {
    for value in [
        "eth0; flush ruleset,*,tcp,22",
        "../eth0,10.69.69.0/24,tcp,22",
        "wt0,10.69.69.0/24,icmp,22",
        "wt0,10.69.69.0/24,tcp,0",
    ] {
        assert!(AllowRule::from_str(value).is_err(), "accepted {value:?}");
    }
}

/// Keep distro and Nix executable candidates fixed instead of searching PATH.
#[test]
fn nft_search_plan_includes_fixed_nix_paths_without_path_lookup() {
    let candidates = infraternal_plugin_mesh::host_firewall::nft_candidates();

    assert!(candidates.contains(&"/nix/var/nix/profiles/default/bin/nft"));
    assert!(candidates.contains(&"/run/current-system/sw/bin/nft"));
    assert!(!candidates.iter().any(|path| path.contains("PATH")));
}

/// Name every checked location when no fixed nft candidate exists.
#[test]
fn missing_nft_error_reports_the_path_it_checked() {
    let missing = Path::new("/nix/store/J511-test-nft-does-not-exist");

    let error = discover_nft(Some(missing)).expect_err("missing executable");

    assert!(
        error
            .to_string()
            .contains(missing.to_str().expect("UTF-8 path"))
    );
}

/// Never replace a root-owned role file that does not carry the product marker.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn writing_host_policy_refuses_an_unmarked_role_file() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let config = ConfigFixture::new();
    let path = config.paths.server_policy_path();
    let foreign = br#"{"marker":"operator-owned","policy":{"admin_rules":[],"accept_interfaces":[],"listeners":[],"mesh_enabled":false}}"#;
    fs::create_dir_all(path.parent().expect("policy parent"))
        .expect("create private policy directory");
    fs::write(path, foreign).expect("write the unmarked policy");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("protect the unmarked policy");
    let policy = Policy {
        admin_rules: vec![
            AllowRule::from_str("wt0,10.69.69.0/24,tcp,22").expect("typed administrator rule"),
        ],
        ..Policy::default()
    };

    let error = write_policy_file(path, &policy).expect_err("foreign policy must stay untouched");

    assert!(error.to_string().contains(&path.display().to_string()));
    assert!(
        error
            .to_string()
            .contains("not marked as infraternal-owned"),
        "the writer must reject an unowned policy for its ownership marker, got: {error}"
    );
    assert_eq!(fs::read(path).expect("read the unmarked policy"), foreign);
}

/// Clear the server role through the product path and remove only its marked state.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn clearing_host_policy_removes_its_table_config_and_loader() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let config = ConfigFixture::new();
    let setup = run_nft(
        &nft,
        &["-f", "-"],
        Some(concat!(
            "add table inet infraternal_host\n",
            "add chain inet infraternal_host input { type filter hook input priority filter - 10; policy drop; }\n",
            "add rule inet infraternal_host input iifname \"wt0\" ip saddr 10.69.69.0/24 tcp dport 22 accept\n",
            "add table inet unrelated_control\n",
            "add chain inet unrelated_control keep\n",
            "add rule inet unrelated_control keep counter\n",
        )),
    );
    assert!(setup.status.success(), "host-policy fixture was rejected");
    let unrelated_before = table_json(&nft, "unrelated_control");
    write_policy_file(
        config.paths.server_policy_path(),
        &Policy {
            admin_rules: vec![
                AllowRule::from_str("wt0,10.69.69.0/24,tcp,22").expect("typed administrator rule"),
            ],
            ..Policy::default()
        },
    )
    .expect("save marked server policy");
    config.write_owned_loader();

    let report = clear_role_from_config_at(
        PolicyRole::Server,
        &config.paths,
        Some(&nft),
        Some(&config.systemctl),
    )
    .expect("remove the configured server policy");

    assert!(
        !run_nft(
            &nft,
            &["-n", "list", "table", "inet", "infraternal_host"],
            None
        )
        .status
        .success(),
        "the product host table must be removed"
    );
    assert_eq!(unrelated_before, table_json(&nft, "unrelated_control"));
    assert!(!config.paths.server_policy_path().exists());
    assert!(!config.paths.unit_path().exists());
    assert!(!config.paths.enabled_path().exists());
    assert!(
        report.contains("host firewall migration: current and desired rules differ"),
        "clearing the final role reports the semantic rules being removed: {report}"
    );
    assert!(report.contains("removed inet infraternal_host"));
    assert!(report.contains("removed server policy file"));
    assert!(report.contains("removed loader unit"));
}

/// An interrupted agent withdraws its live table and policy while its journal owns the loader.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn rollback_agent_policy_leaves_the_loader_for_install_journal_recovery() {
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let config = ConfigFixture::new();
    write_policy_file(config.paths.agent_policy_path(), &Policy::default())
        .expect("save the provisional agent policy");
    config.write_owned_loader();
    apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect("load the provisional host table");

    rollback_agent_policy(&config.paths, true, Some(&nft)).expect("withdraw the agent policy");
    assert!(!config.paths.agent_policy_path().exists());
    assert!(config.paths.unit_path().is_file());
    assert!(config.paths.enabled_path().is_symlink());
    assert!(
        !run_nft(
            &nft,
            &["-n", "list", "table", "inet", "infraternal_host"],
            None
        )
        .status
        .success(),
        "rollback must remove the only role's live table"
    );
}

/// Still withdraw the provisional policy when nft was never available to load it.
#[test]
#[ignore = "Run as root in a disposable namespace to exercise root-owned policies."]
fn rollback_agent_policy_without_nft_leaves_the_loader_for_the_journal() {
    let config = ConfigFixture::new();
    write_policy_file(config.paths.agent_policy_path(), &Policy::default())
        .expect("save the provisional agent policy");
    config.write_owned_loader();

    let absent_nft = config.paths.unit_path().with_file_name("missing-nft");
    rollback_agent_policy(&config.paths, true, Some(&absent_nft))
        .expect("withdraw provisional policy without nft");
    assert!(!config.paths.agent_policy_path().exists());
    assert!(config.paths.unit_path().is_file());
    assert!(config.paths.enabled_path().is_symlink());
}

/// The prior loader restores its own live rules after installer rollback.
#[test]
#[ignore = "Run as root in a disposable namespace to exercise root-owned policies."]
fn rollback_agent_policy_defers_live_rules_to_the_prior_loader() {
    let config = ConfigFixture::new();
    write_policy_file(config.paths.agent_policy_path(), &Policy::default())
        .expect("save the provisional agent policy");
    write_policy_file(config.paths.server_policy_path(), &Policy::default())
        .expect("save the server policy");
    config.write_owned_loader();
    let before = fs::read(config.paths.server_policy_path()).expect("read the server policy");

    let absent_nft = config.paths.unit_path().with_file_name("missing-nft");
    rollback_agent_policy(&config.paths, false, Some(&absent_nft))
        .expect("the journal restores the prior loader without running nft here");
    assert!(!config.paths.agent_policy_path().exists());
    assert_eq!(
        fs::read(config.paths.server_policy_path()).expect("read the server policy"),
        before
    );
    assert!(config.paths.unit_path().is_file());
    assert!(config.paths.enabled_path().is_symlink());
}

/// With both roles present, withdraw only the agent's contribution to the live table.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn rollback_agent_policy_restores_the_saved_server_rules() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let config = ConfigFixture::new();
    let saved = Policy {
        admin_rules: vec!["*,*,tcp,22".parse().expect("valid SSH rule")],
        ..Policy::default()
    };
    write_policy_file(config.paths.server_policy_path(), &saved).expect("save the server policy");
    config.write_owned_loader();
    apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect("load the server host table");
    let server = table_json(&nft, "infraternal_host");
    let agent = Policy {
        admin_rules: vec!["lo,*,tcp,8675".parse().expect("valid rule")],
        ..Policy::default()
    };
    write_policy_file(config.paths.agent_policy_path(), &agent).expect("save the agent policy");
    apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect("load both roles");
    assert_ne!(
        accept_rules(&table_json(&nft, "infraternal_host")),
        accept_rules(&server)
    );

    rollback_agent_policy(&config.paths, true, Some(&nft)).expect("restore the server rules");
    assert!(!config.paths.agent_policy_path().exists());
    assert!(config.paths.server_policy_path().is_file());
    assert!(config.paths.unit_path().is_file());
    assert!(config.paths.enabled_path().is_symlink());
    let restored = table_json(&nft, "infraternal_host");
    assert_eq!(
        input_chain(&restored)["policy"],
        input_chain(&server)["policy"]
    );
    assert_eq!(accept_rules(&restored), accept_rules(&server));
}

/// Repeating a clear after removal succeeds without changing unrelated nft state.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn clearing_an_already_removed_host_policy_is_a_noop() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let config = ConfigFixture::new();
    let setup = run_nft(
        &nft,
        &["-f", "-"],
        Some(concat!(
            "add table inet infraternal_host\n",
            "add chain inet infraternal_host input { type filter hook input priority filter - 10; policy drop; }\n",
            "add rule inet infraternal_host input iifname \"lo\" accept\n",
        )),
    );
    assert!(setup.status.success(), "host-policy fixture was rejected");

    clear_role_from_config_at(
        PolicyRole::Server,
        &config.paths,
        Some(&nft),
        Some(&config.systemctl),
    )
    .expect("the first clear removes the table");
    let repeated = clear_role_from_config_at(
        PolicyRole::Server,
        &config.paths,
        Some(&nft),
        Some(&config.systemctl),
    )
    .expect("a second clear is idempotent");

    assert!(repeated.contains("no rule differences"));
    assert!(
        !run_nft(
            &nft,
            &["-n", "list", "table", "inet", "infraternal_host"],
            None
        )
        .status
        .success(),
        "the removed product table must stay absent"
    );
}

/// Boot-time cleanup deletes infraternal-owned state but keeps foreign tables and units.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn empty_config_removes_only_the_product_table_and_marked_loader() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let config = ConfigFixture::new();
    let setup = run_nft(
        &nft,
        &["-f", "-"],
        Some(concat!(
            "add table inet infraternal_host\n",
            "add chain inet infraternal_host input { type filter hook input priority filter - 10; policy drop; }\n",
            "add rule inet infraternal_host input iifname \"lo\" accept\n",
            "add table inet unrelated_control\n",
            "add chain inet unrelated_control keep\n",
            "add rule inet unrelated_control keep counter\n",
        )),
    );
    assert!(setup.status.success(), "host-policy fixture was rejected");
    let unrelated_before = table_json(&nft, "unrelated_control");
    fs::create_dir_all(config.paths.unit_path().parent().expect("unit parent"))
        .expect("create fake systemd directory");
    fs::write(
        config.paths.unit_path(),
        "[Unit]\nDescription=operator-owned unit\n",
    )
    .expect("write an unmarked unit");
    fs::set_permissions(config.paths.unit_path(), fs::Permissions::from_mode(0o644))
        .expect("protect the foreign unit");
    fs::create_dir_all(
        config
            .paths
            .enabled_path()
            .parent()
            .expect("enablement parent"),
    )
    .expect("create fake enablement directory");
    symlink(
        "../infraternal-firewall.service",
        config.paths.enabled_path(),
    )
    .expect("write foreign enablement link");

    let report = apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect("empty configuration clears stale owned state");

    assert!(
        !run_nft(
            &nft,
            &["-n", "list", "table", "inet", "infraternal_host"],
            None
        )
        .status
        .success(),
        "the product table must be removed"
    );
    assert_eq!(unrelated_before, table_json(&nft, "unrelated_control"));
    assert!(
        config.paths.unit_path().exists(),
        "an unmarked unit is foreign"
    );
    assert!(
        config.paths.enabled_path().exists(),
        "an enablement link to an unmarked unit is foreign"
    );
    assert!(report.contains("kept unmarked loader unit"));
    assert!(report.contains("kept unmarked enablement link"));
}

/// Holds marked host-policy files below a disposable namespace-local directory.
struct ConfigFixture {
    /// The fixture root removed when this test ends.
    root: std::path::PathBuf,
    /// Product paths rooted in the fixture instead of the host filesystem.
    paths: HostFirewallPaths,
    /// A harmless systemctl stand-in used only to verify cleanup ordering.
    systemctl: std::path::PathBuf,
}

impl ConfigFixture {
    /// Create a private layout and a fixed executable that accepts daemon-reload.
    fn new() -> Self {
        let sequence = NEXT_CONFIG_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::path::Path::new("/run").join(format!(
            "j511-host-firewall-config-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create private policy fixture");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect private policy fixture");
        let paths = HostFirewallPaths::under(&root);
        let policy_parent = paths
            .server_policy_path()
            .parent()
            .expect("server policy parent");
        fs::create_dir_all(policy_parent).expect("create private policy directories");
        let mut directory = policy_parent.to_owned();
        while directory != root {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
                .expect("protect policy directory from group writes");
            directory = directory
                .parent()
                .expect("policy directories stay below the fixture root")
                .to_owned();
        }
        let systemctl = root.join("systemctl");
        fs::write(&systemctl, "#!/bin/sh\nexit 0\n").expect("write fake systemctl");
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755))
            .expect("make fake systemctl executable");
        Self {
            root,
            paths,
            systemctl,
        }
    }

    /// Install a loader unit and enablement link carrying the product marker.
    fn write_owned_loader(&self) {
        fs::create_dir_all(self.paths.unit_path().parent().expect("unit parent"))
            .expect("create fake systemd directory");
        fs::write(
            self.paths.unit_path(),
            "# Managed by infraternal: host-firewall/v1\n[Unit]\nDescription=infraternal host input firewall\n",
        )
        .expect("write marked loader unit");
        fs::set_permissions(self.paths.unit_path(), fs::Permissions::from_mode(0o644))
            .expect("protect marked loader unit");
        fs::create_dir_all(
            self.paths
                .enabled_path()
                .parent()
                .expect("enablement parent"),
        )
        .expect("create fake enablement directory");
        symlink("../infraternal-firewall.service", self.paths.enabled_path())
            .expect("write product enablement link");
    }
}

impl Drop for ConfigFixture {
    /// Remove only this test's temporary policy and systemd paths.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The host table admits exactly the UDP port the mesh node bound, and nothing once it stops.
///
/// The node reports its socket's real port (D386); a default, a fallback and a
/// rebind all reach the host policy only through `set_mesh_listener`. The mesh
/// table beside it must be left untouched by every step.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn mesh_listener_opens_exactly_the_bound_port_and_closes_on_stop() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let config = ConfigFixture::new();
    let setup = run_nft(
        &nft,
        &["-f", "-"],
        Some(concat!(
            "add table inet infraternal_mesh\n",
            "add chain inet infraternal_mesh keep\n",
            "add rule inet infraternal_mesh keep counter\n",
        )),
    );
    assert!(
        setup.status.success(),
        "mesh table fixture was rejected: {}",
        String::from_utf8_lossy(&setup.stderr)
    );
    write_policy_file(
        config.paths.server_policy_path(),
        &Policy {
            admin_rules: vec![
                AllowRule::from_str("wt0,10.69.69.0/24,tcp,22").expect("typed administrator rule"),
            ],
            ..Policy::default()
        },
    )
    .expect("save marked server policy");
    apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect("install the server host policy");
    let mesh_before = table_json(&nft, "infraternal_mesh");
    let admin_ssh = [
        (meta("iifname"), json!("wt0")),
        (
            payload("ip", "saddr"),
            json!({ "prefix": { "addr": "10.69.69.0", "len": 24 } }),
        ),
        (payload("tcp", "dport"), json!(22)),
    ];
    let tunnel = [(meta("iifname"), json!("infraternal0"))];
    let udp = |port: u16| [(payload("udp", "dport"), json!(port))];

    set_mesh_listener_at(&config.paths, Some(&nft), Some(32_001))
        .expect("record a fallback listener")
        .expect("role files exist, so the host table is managed");
    let fallback = table_json(&nft, "infraternal_host");
    assert!(has_accept_rule(&fallback, &udp(32_001)), "{fallback:?}");
    assert!(!has_accept_rule(&fallback, &udp(10_254)), "{fallback:?}");
    assert!(has_accept_rule(&fallback, &tunnel), "{fallback:?}");
    assert_eq!(
        read_policy_file(config.paths.agent_policy_path())
            .expect("read agent policy")
            .and_then(|policy| policy.mesh_udp_port),
        Some(32_001),
        "the agent policy file records the bound port"
    );

    set_mesh_listener_at(&config.paths, Some(&nft), Some(10_254))
        .expect("record a rebind to the standard port");
    let rebound = table_json(&nft, "infraternal_host");
    assert!(has_accept_rule(&rebound, &udp(10_254)), "{rebound:?}");
    assert!(!has_accept_rule(&rebound, &udp(32_001)), "{rebound:?}");

    let unchanged = set_mesh_listener_at(&config.paths, Some(&nft), Some(10_254))
        .expect("repeat the same listener")
        .expect("managed host table");
    assert!(unchanged.contains("no rule differences"), "{unchanged}");
    assert_eq!(rebound, table_json(&nft, "infraternal_host"));

    set_mesh_listener_at(&config.paths, Some(&nft), None).expect("stop the mesh listener");
    let stopped = table_json(&nft, "infraternal_host");
    assert!(!has_accept_rule(&stopped, &udp(10_254)), "{stopped:?}");
    assert!(!has_accept_rule(&stopped, &tunnel), "{stopped:?}");
    for table in [&fallback, &rebound, &stopped] {
        assert_eq!(input_chain(table)["policy"], "drop", "{table:?}");
        assert!(has_accept_rule(table, &admin_ssh), "{table:?}");
    }
    assert_eq!(
        mesh_before,
        table_json(&nft, "infraternal_mesh"),
        "host listener updates must leave the mesh table in place"
    );
}

/// J671 (#483): a default-drop table that would drop sshd is never applied, and the boot loader fails open.
///
/// The saved policy admits only tcp/22. sshd moves to 2222 (an edited
/// `sshd_config`, a `-p` in `SSHD_OPTS`, a socket drop-in). A later policy
/// change (the mesh listener) must refuse and leave the old table; the boot
/// loader must not enforce the saved table and must leave input open with
/// the mesh port, saying why. Once the policy admits 2222 the loader enforces
/// again.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
#[cfg(feature = "test-support")]
fn review_j671_boot_loader_fails_open_when_sshd_moved() {
    use infraternal_plugin_mesh::host_firewall::{
        PolicyError, SshdPort, SshdPortsTestOverride, boot_apply_from_config_at,
    };
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let config = ConfigFixture::new();
    let server = |rules: &[&str]| Policy {
        admin_rules: rules
            .iter()
            .map(|rule| AllowRule::from_str(rule).expect("admin rule"))
            .collect(),
        ..Policy::default()
    };
    write_policy_file(config.paths.server_policy_path(), &server(&["*,*,tcp,22"]))
        .expect("save marked server policy");
    {
        let _sshd = SshdPortsTestOverride::install(&[SshdPort::dual_stack(22)]);
        boot_apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
            .expect("sshd on 22: the saved table is enforced");
    }
    let enforced = table_json(&nft, "infraternal_host");
    assert_eq!(input_chain(&enforced)["policy"], "drop", "{enforced:?}");

    let _sshd = SshdPortsTestOverride::install(&[SshdPort::dual_stack(2222)]);
    // A later policy change refuses and leaves the live table alone.
    let refused = set_mesh_listener_at(&config.paths, Some(&nft), Some(10_254))
        .expect_err("the mesh listener must not re-apply a table that drops sshd");
    assert!(
        matches!(refused, PolicyError::SshdNotAdmitted { ref missing, .. } if missing == "2222"),
        "{refused}"
    );
    assert_eq!(enforced, table_json(&nft, "infraternal_host"));
    assert_eq!(
        read_policy_file(config.paths.agent_policy_path()).expect("read agent policy"),
        None,
        "a refused change saves nothing"
    );
    // The boot loader fails open: no default drop, the reason is loud.
    let error = boot_apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect_err("the loader must not enforce a table that drops sshd");
    let text = error.to_string();
    assert!(
        matches!(error, PolicyError::FailedOpen { .. })
            && text.contains("NOT enforced")
            && text.contains("sshd's port 2222")
            && text.contains("open mesh-only table is live"),
        "{text}"
    );
    let open = table_json(&nft, "infraternal_host");
    assert_eq!(input_chain(&open)["policy"], "accept", "{open:?}");
    // Once the policy admits sshd's new port, the loader enforces again.
    write_policy_file(
        config.paths.server_policy_path(),
        &server(&["*,*,tcp,22", "*,*,tcp,2222"]),
    )
    .expect("save the corrected policy");
    boot_apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect("the corrected policy is enforced");
    let again = table_json(&nft, "infraternal_host");
    assert_eq!(input_chain(&again)["policy"], "drop", "{again:?}");
}

/// A machine with only an agent policy gets mesh input and no default drop (J555, #483).
///
/// The agent policy saved by `infraternal up` carries the SSH port it ran
/// from; it must not turn into a default-drop table on a machine without a
/// server policy. Adding a server policy switches the same table to drop, and
/// removing it switches back.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn agent_only_host_gets_mesh_input_without_default_drop() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let config = ConfigFixture::new();
    write_policy_file(
        config.paths.agent_policy_path(),
        &Policy {
            admin_rules: vec![AllowRule::from_str("*,*,tcp,22").expect("recorded SSH port")],
            ..Policy::default()
        },
    )
    .expect("save marked agent policy");
    let udp = [(payload("udp", "dport"), json!(10_254))];
    let tunnel = [(meta("iifname"), json!("infraternal0"))];

    apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect("apply the agent-only policy");
    let idle = table_json(&nft, "infraternal_host");
    assert_eq!(input_chain(&idle)["policy"], "accept", "{idle:?}");
    assert!(accept_rules(&idle).is_empty(), "{idle:?}");

    set_mesh_listener_at(&config.paths, Some(&nft), Some(10_254))
        .expect("record the mesh listener")
        .expect("agent policy exists, so the host table is managed");
    let meshed = table_json(&nft, "infraternal_host");
    assert_eq!(input_chain(&meshed)["policy"], "accept", "{meshed:?}");
    assert!(has_accept_rule(&meshed, &udp), "{meshed:?}");
    assert!(has_accept_rule(&meshed, &tunnel), "{meshed:?}");
    assert_eq!(
        accept_rules(&meshed).len(),
        2,
        "only mesh input: {meshed:?}"
    );
    let repeated = set_mesh_listener_at(&config.paths, Some(&nft), Some(10_254))
        .expect("repeat the listener")
        .expect("managed host table");
    assert!(repeated.contains("no rule differences"), "{repeated}");

    write_policy_file(
        config.paths.server_policy_path(),
        &Policy {
            admin_rules: vec![
                AllowRule::from_str("wt0,10.69.69.0/24,tcp,22").expect("server admin rule"),
            ],
            ..Policy::default()
        },
    )
    .expect("save marked server policy");
    apply_from_config_at(&config.paths, Some(&nft), Some(&config.systemctl))
        .expect("a server policy switches the table to enforce");
    let enforced = table_json(&nft, "infraternal_host");
    assert_eq!(input_chain(&enforced)["policy"], "drop", "{enforced:?}");
    assert!(has_accept_rule(&enforced, &udp), "{enforced:?}");

    clear_role_from_config_at(
        PolicyRole::Server,
        &config.paths,
        Some(&nft),
        Some(&config.systemctl),
    )
    .expect("clear the server role");
    let back = table_json(&nft, "infraternal_host");
    assert_eq!(input_chain(&back)["policy"], "accept", "{back:?}");
    assert!(has_accept_rule(&back, &udp), "{back:?}");
}

/// Take over a hand-made host table without changing unrelated nft state.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn real_takeover_is_atomic_preserves_admin_and_leaves_other_tables_alone() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let setup = run_nft(
        &nft,
        &["-f", "-"],
        Some(concat!(
            "add table inet unrelated_control\n",
            "add chain inet unrelated_control keep\n",
            "add rule inet unrelated_control keep counter\n",
            "add table inet infraternal_mesh\n",
            "add chain inet infraternal_mesh keep\n",
            "add rule inet infraternal_mesh keep counter\n",
            "add table inet infraternal_host\n",
            "add chain inet infraternal_host input { type filter hook input priority filter - 10; policy drop; }\n",
            "add rule inet infraternal_host input iifname \"wt0\" accept\n",
            "add rule inet infraternal_host input iifname \"lo\" accept\n",
            "add rule inet infraternal_host input ct state invalid drop\n",
            "add rule inet infraternal_host input ct state established,related accept\n",
            "add rule inet infraternal_host input ip protocol icmp accept\n",
            "add rule inet infraternal_host input meta l4proto ipv6-icmp accept\n",
            "add rule inet infraternal_host input iifname \"eth0\" udp dport 51820 accept\n",
            "add rule inet infraternal_host input iifname \"wt0\" ip saddr 10.69.69.0/24 tcp dport 22 accept\n",
            "add rule inet infraternal_host input iifname \"wt0\" ip saddr 10.69.69.99 tcp dport 7011 accept\n",
            "add rule inet infraternal_host input iifname \"eth0\" ip saddr 10.69.0.99 tcp dport 7011 accept\n",
            "add rule inet infraternal_host input iifname \"eth0\" ip saddr 10.69.0.99 tcp dport 7012 accept\n",
            "add rule inet infraternal_host input iifname \"wt0\" ip saddr 10.69.69.0/24 tcp dport 7443 accept\n",
            "add rule inet infraternal_host input iifname \"wt0\" ip saddr 10.69.69.0/24 udp dport 7443 accept\n",
        )),
    );
    assert!(
        setup.status.success(),
        "initial nft fixture was rejected: {}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let unrelated_before = table_json(&nft, "unrelated_control");
    let mesh_before = table_json(&nft, "infraternal_mesh");
    let report = apply_with_ssh_connection(&prod_policy(true), Some(&nft), None)
        .expect("product policy takes over the legacy host table");
    let installed = table_json(&nft, "infraternal_host");
    let unrelated_after = table_json(&nft, "unrelated_control");
    let mesh_after = table_json(&nft, "infraternal_mesh");

    assert!(
        report.starts_with("host firewall migration: current and desired rules differ\n"),
        "takeover reports semantic differences from the hand-built table: {report}"
    );
    let chain = input_chain(&installed);
    assert_eq!(
        chain["policy"], "drop",
        "host input must default to drop: {chain}"
    );
    assert_eq!(
        chain["type"], "filter",
        "host input must be a filter chain: {chain}"
    );
    assert!(
        has_accept_rule(
            &installed,
            &[
                (meta("iifname"), json!("wt0")),
                (
                    payload("ip", "saddr"),
                    json!({ "prefix": { "addr": "10.69.69.0", "len": 24 } })
                ),
                (payload("tcp", "dport"), json!(22)),
            ]
        ),
        "the administrator SSH rule must survive the takeover: {installed:?}"
    );
    assert!(
        has_accept_rule(&installed, &[(payload("udp", "dport"), json!(10254))]),
        "the mesh UDP port must be open from any source: {installed:?}"
    );
    assert!(
        has_accept_rule(&installed, &[(meta("iifname"), json!("infraternal0"))]),
        "traffic arriving on the mesh interface must be admitted: {installed:?}"
    );
    assert_eq!(unrelated_before, unrelated_after);
    assert_eq!(
        mesh_before, mesh_after,
        "host policy updates must preserve the mesh table"
    );

    let installed_with_handles = installed.clone();
    let repeated = apply_with_ssh_connection(&prod_policy(true), Some(&nft), None)
        .expect("reapplying the current policy is safe");
    assert!(repeated.contains("no rule differences"));
    assert_eq!(
        installed_with_handles,
        table_json(&nft, "infraternal_host"),
        "an unchanged policy must not delete and recreate the nft table"
    );

    let before_bad_apply = installed;
    let bad_policy = Policy {
        admin_rules: vec![
            AllowRule::from_str("wt0,10.69.70.0/24,tcp,22")
                .expect("incorrect administrator source"),
        ],
        mesh_enabled: true,
        ..Policy::default()
    };
    assert!(
        apply_with_ssh_connection(
            &bad_policy,
            Some(&nft),
            Some("10.69.69.5 43122 10.69.69.89 22"),
        )
        .is_err()
    );
    assert_eq!(before_bad_apply, table_json(&nft, "infraternal_host"));

    assert!(
        !run_nft(
            &nft,
            &["-f", "-"],
            Some("delete table inet infraternal_host\ninvalid syntax\n"),
        )
        .status
        .success()
    );
    assert_eq!(before_bad_apply, table_json(&nft, "infraternal_host"));
}

/// Prove SSH, bidirectional mesh, fixed mesh UDP, and default-drop with real nft in netns.
#[test]
#[ignore = "Run in disposable network namespaces with CAP_NET_ADMIN."]
fn host_table_takeover_keeps_ssh_and_bidirectional_mesh_but_drops_other_ingress() {
    #[cfg(feature = "test-support")]
    let _sshd = sshd_on_22();
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let suffix = std::process::id().to_string();
    let host_a = format!("j511-{suffix}-a");
    let host_b = format!("j511-{suffix}-b");
    let outside = format!("j511-{suffix}-c");
    let _namespaces = NetworkNamespaces::create([&host_a, &host_b, &outside]);

    add_veth(
        &["mesh-a", &host_a, "infraternal0", "10.70.0.1/24"],
        &["mesh-b", &host_b, "infraternal0", "10.70.0.2/24"],
    );
    add_veth(
        &["admin-a", &host_a, "wt0", "10.70.1.1/24"],
        &["admin-b", &host_b, "admin0", "10.70.1.2/24"],
    );
    add_veth(
        &["drop-a", &host_a, "untrusted0", "10.70.2.1/24"],
        &["drop-c", &outside, "outside0", "10.70.2.2/24"],
    );

    let a = start_policy_host(
        host_a.clone(),
        nft.clone(),
        "10.70.0.1:17443".parse().expect("mesh listener address"),
        Some("10.70.1.1:22".parse().expect("SSH listener address")),
        Some("10.70.0.1:10254".parse().expect("mesh UDP address")),
        Some("10.70.2.1:17444".parse().expect("drop probe address")),
    )
    .join()
    .expect("host A policy and listeners");
    let b = start_policy_host(
        host_b.clone(),
        nft,
        "10.70.0.2:17443".parse().expect("mesh listener address"),
        None,
        Some("10.70.0.2:10254".parse().expect("mesh UDP address")),
        None,
    )
    .join()
    .expect("host B policy and listeners");

    let a_mesh = echo_once(a.mesh_tcp.expect("host A mesh listener"), *b"pong");
    let b_mesh = echo_once(b.mesh_tcp.expect("host B mesh listener"), *b"back");
    let ssh = echo_once(a.ssh_tcp.expect("host A SSH listener"), *b"live");

    let to_a = client_round_trip(host_b.clone(), "10.70.0.1:17443", *b"ping", *b"pong");
    let to_b = client_round_trip(host_a.clone(), "10.70.0.2:17443", *b"mesh", *b"back");
    let admin = client_round_trip(host_b.clone(), "10.70.1.1:22", *b"ssh!", *b"live");
    to_a.join().expect("mesh request B to A");
    to_b.join().expect("mesh request A to B");
    admin.join().expect("admin SSH path remains available");
    a_mesh.join().expect("host A replied over mesh");
    b_mesh.join().expect("host B replied over mesh");
    ssh.join().expect("host A replied over SSH");

    let a_mesh_udp = a.mesh_udp.expect("host A mesh UDP listener");
    let b_mesh_udp = b.mesh_udp.expect("host B mesh UDP listener");
    a_mesh_udp
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound UDP receive guard");
    b_mesh_udp
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound UDP receive guard");
    let receive_a = thread::spawn(move || receive_datagram(&a_mesh_udp));
    let receive_b = thread::spawn(move || receive_datagram(&b_mesh_udp));
    send_datagram(host_b.clone(), "10.70.0.2:0", "10.70.0.1:10254", *b"mesh");
    send_datagram(host_a.clone(), "10.70.0.1:0", "10.70.0.2:10254", *b"mesh");
    assert_eq!(receive_a.join().expect("host A UDP receive"), *b"mesh");
    assert_eq!(receive_b.join().expect("host B UDP receive"), *b"mesh");

    let blocked = a.drop_udp.expect("host A default-drop probe");
    blocked
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("bound UDP receive guard");
    send_datagram(outside, "10.70.2.2:0", "10.70.2.1:17444", *b"drop");
    let mut payload = [0; 4];
    let error = blocked
        .recv_from(&mut payload)
        .expect_err("untrusted ingress must be dropped by the default policy");
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "unexpected default-drop probe error: {error}"
    );
}

/// Own only the namespaces this test created, and remove them even on assertion failure.
struct NetworkNamespaces(Vec<String>);

impl NetworkNamespaces {
    /// Create a disposable collection of named network namespaces.
    fn create(names: [&str; 3]) -> Self {
        let namespaces = Self(names.into_iter().map(str::to_owned).collect());
        std::fs::create_dir_all("/run/netns").expect("private network namespace directory");
        for name in &namespaces.0 {
            run_ip(&["netns", "add", name]);
            run_netns_ip(name, &["link", "set", "lo", "up"]);
        }
        namespaces
    }
}

impl Drop for NetworkNamespaces {
    /// Remove only the names reserved by this test process.
    fn drop(&mut self) {
        for name in &self.0 {
            let _ = Command::new("ip").args(["netns", "del", name]).status();
        }
    }
}

/// Create and configure one point-to-point link between two isolated test hosts.
fn add_veth(left: &[&str; 4], right: &[&str; 4]) {
    run_ip(&[
        "link", "add", left[0], "type", "veth", "peer", "name", right[0],
    ]);
    run_ip(&["link", "set", left[0], "netns", left[1]]);
    run_ip(&["link", "set", right[0], "netns", right[1]]);
    for endpoint in [left, right] {
        run_netns_ip(
            endpoint[1],
            &["link", "set", endpoint[0], "name", endpoint[2]],
        );
        run_netns_ip(
            endpoint[1],
            &["address", "add", endpoint[3], "dev", endpoint[2]],
        );
        run_netns_ip(endpoint[1], &["link", "set", endpoint[2], "up"]);
    }
}

/// Run one ip command and fail with its captured diagnostic if setup is refused.
fn run_ip(arguments: &[&str]) {
    let result = Command::new("ip")
        .args(arguments)
        .output()
        .expect("iproute2 command");
    assert!(
        result.status.success(),
        "ip {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&result.stderr)
    );
}

/// Run one link or address command inside a named test namespace.
fn run_netns_ip(namespace: &str, arguments: &[&str]) {
    let mut command = vec!["-n", namespace];
    command.extend_from_slice(arguments);
    run_ip(&command);
}

/// Install one host policy and return listeners bound in that network namespace.
fn start_policy_host(
    namespace: String,
    nft: std::path::PathBuf,
    mesh_tcp: SocketAddr,
    ssh_tcp: Option<SocketAddr>,
    mesh_udp: Option<SocketAddr>,
    drop_udp: Option<SocketAddr>,
) -> thread::JoinHandle<HostSockets> {
    thread::spawn(move || {
        enter_network_namespace(&namespace);
        // The sshd override is per thread, so this host thread states its own.
        #[cfg(feature = "test-support")]
        let _sshd = sshd_on_22();
        let fixture = run_nft(
            &nft,
            &["-f", "-"],
            Some(concat!(
                "add table inet unrelated_control\n",
                "add chain inet unrelated_control keep\n",
                "add rule inet unrelated_control keep counter\n",
                "add table inet infraternal_host\n",
                "add chain inet infraternal_host input { type filter hook input priority filter - 10; policy drop; }\n",
                "add rule inet infraternal_host input iifname \"lo\" accept\n",
                "add rule inet infraternal_host input ct state established,related accept\n",
                "add rule inet infraternal_host input iifname \"wt0\" accept\n",
                "add rule inet infraternal_host input iifname \"wt0\" ip saddr 10.70.1.0/24 tcp dport 22 accept\n",
            )),
        );
        assert!(
            fixture.status.success(),
            "legacy host table fixture was rejected: {}",
            String::from_utf8_lossy(&fixture.stderr)
        );
        let unrelated_before = table_json(&nft, "unrelated_control");
        let policy = Policy {
            admin_rules: vec![
                AllowRule::from_str("wt0,10.70.1.0/24,tcp,22").expect("typed administrator rule"),
            ],
            accept_interfaces: vec!["wt0".to_owned()],
            mesh_enabled: true,
            ..Policy::default()
        };
        let active_admin = ssh_tcp.is_some().then_some("10.70.1.2 43122 10.70.1.1 22");
        let report = apply_with_ssh_connection(&policy, Some(&nft), active_admin)
            .expect("atomic takeover and default-drop host policy");
        assert!(report.contains("+ desired: iifname \"infraternal0\" accept"));
        assert!(report.contains("+ desired: udp dport 10254 accept"));
        assert_eq!(
            unrelated_before,
            table_json(&nft, "unrelated_control"),
            "the host takeover must not change another nft table"
        );
        HostSockets {
            mesh_tcp: Some(TcpListener::bind(mesh_tcp).expect("mesh TCP listener")),
            ssh_tcp: ssh_tcp.map(|address| TcpListener::bind(address).expect("SSH TCP listener")),
            mesh_udp: mesh_udp.map(|address| UdpSocket::bind(address).expect("mesh UDP listener")),
            drop_udp: drop_udp
                .map(|address| UdpSocket::bind(address).expect("drop probe listener")),
        }
    })
}

/// Hold listeners bound in a host namespace until their peers finish the proof.
struct HostSockets {
    mesh_tcp: Option<TcpListener>,
    ssh_tcp: Option<TcpListener>,
    mesh_udp: Option<UdpSocket>,
    drop_udp: Option<UdpSocket>,
}

/// Bind one listener that verifies a complete request and returns the expected reply.
fn echo_once(listener: TcpListener, reply: [u8; 4]) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("incoming mesh or SSH connection");
        let mut request = [0; 4];
        stream.read_exact(&mut request).expect("complete request");
        stream.write_all(&reply).expect("complete response");
    })
}

/// Connect from a peer namespace and verify request and response both cross the host policy.
fn client_round_trip(
    namespace: String,
    address: &'static str,
    request: [u8; 4],
    expected: [u8; 4],
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        enter_network_namespace(&namespace);
        let address = address.parse::<SocketAddr>().expect("peer address");
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .expect("host input accepted this TCP connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("TCP response guard");
        stream.write_all(&request).expect("send request");
        let mut response = [0; 4];
        stream.read_exact(&mut response).expect("receive response");
        assert_eq!(response, expected);
    })
}

/// Send one UDP probe from the named source namespace to a selected host rule.
fn send_datagram(
    namespace: String,
    source: &'static str,
    destination: &'static str,
    payload: [u8; 4],
) {
    thread::spawn(move || {
        enter_network_namespace(&namespace);
        let socket = UdpSocket::bind(source.parse::<SocketAddr>().expect("UDP source"))
            .expect("UDP source socket");
        socket
            .send_to(&payload, destination)
            .expect("send UDP probe");
    })
    .join()
    .expect("UDP sender");
}

/// Receive one UDP payload through a host namespace's bound socket.
fn receive_datagram(socket: &UdpSocket) -> [u8; 4] {
    let mut payload = [0; 4];
    let (length, _) = socket.recv_from(&mut payload).expect("mesh UDP admitted");
    assert_eq!(length, payload.len());
    payload
}

/// Enter one test-only network namespace on the calling thread.
fn enter_network_namespace(namespace: &str) {
    let handle = File::open(Path::new("/run/netns").join(namespace)).expect("namespace handle");
    nix::sched::setns(&handle, nix::sched::CloneFlags::CLONE_NEWNET)
        .expect("enter isolated network namespace");
}

/// Run one nft command from the absolute executable path found by the product.
///
/// stdout and stderr are always captured: `wait_with_output` only collects
/// streams that were piped, and an inherited stdout would leave every listing
/// empty, which made table comparisons pass without comparing anything.
fn run_nft(nft: &Path, arguments: &[&str], input: Option<&str>) -> std::process::Output {
    let mut command = Command::new(nft);
    command.args(arguments);
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().expect("start nft in namespace");
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("nft stdin")
            .write_all(input.as_bytes())
            .expect("write nft transaction");
    }
    child.wait_with_output().expect("wait for nft")
}

/// Read one table as nft's JSON objects so checks compare policy, not text layout.
///
/// The `metainfo` entry (nft and schema versions) is dropped. Handles are
/// kept on purpose: equal snapshots prove the kernel objects were left in
/// place, not merely replaced by equivalent ones. An empty listing is a
/// fixture failure, never a value to compare.
fn table_json(nft: &Path, name: &str) -> Vec<Value> {
    let output = run_nft(nft, &["-j", "list", "table", "inet", name], None);
    assert!(
        output.status.success(),
        "nft could not list inet {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("nft JSON listing");
    let objects: Vec<Value> = document["nftables"]
        .as_array()
        .expect("nft JSON has an nftables array")
        .iter()
        .filter(|object| object.get("metainfo").is_none())
        .cloned()
        .collect();
    assert!(
        objects.iter().any(|object| object["table"]["name"] == name),
        "nft listing for inet {name} has no table object: {objects:?}"
    );
    objects
}

/// Return the base chain hooked on input, the one whose default policy guards the host.
fn input_chain(table: &[Value]) -> &Value {
    table
        .iter()
        .map(|object| &object["chain"])
        .find(|chain| chain["hook"] == "input")
        .unwrap_or_else(|| panic!("no input base chain in {table:?}"))
}

/// Reduce each accepting rule to its `left == right` matches, as JSON pairs.
///
/// Only rules whose verdict is `accept` are returned, because the checks
/// below ask "which traffic does the host admit".
fn accept_rules(table: &[Value]) -> Vec<Vec<(Value, Value)>> {
    table
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter_map(|rule| {
            let expressions = rule["expr"].as_array()?;
            expressions
                .iter()
                .any(|expression| expression.get("accept").is_some())
                .then(|| {
                    expressions
                        .iter()
                        .filter_map(|expression| expression.get("match"))
                        .filter(|matched| matched["op"] == "==" || matched["op"] == "in")
                        .map(|matched| (matched["left"].clone(), matched["right"].clone()))
                        .collect()
                })
        })
        .collect()
}

/// The JSON left-hand side nft uses for a packet header field such as `tcp dport`.
fn payload(protocol: &str, field: &str) -> Value {
    json!({ "payload": { "protocol": protocol, "field": field } })
}

/// The JSON left-hand side nft uses for a meta key such as `iifname`.
fn meta(key: &str) -> Value {
    json!({ "meta": { "key": key } })
}

/// Find an accepting rule whose matches are exactly `wanted`, in any order.
///
/// Exact sets matter: a rule that also pinned an interface or a source would
/// admit less than the policy promises, and a missing match would admit more.
/// `meta l4proto` and `meta nfproto` matches are skipped unless `wanted` names
/// them, because some nft versions list them as the implied dependency of a
/// header match (`tcp dport` implies TCP), which selects no different packets.
fn has_accept_rule(table: &[Value], wanted: &[(Value, Value)]) -> bool {
    let implied = [meta("l4proto"), meta("nfproto")];
    accept_rules(table).iter().any(|matches| {
        let relevant: Vec<&(Value, Value)> = matches
            .iter()
            .filter(|(left, _)| {
                !implied.contains(left) || wanted.iter().any(|(wanted, _)| wanted == left)
            })
            .collect();
        relevant.len() == wanted.len() && wanted.iter().all(|pair| relevant.contains(&pair))
    })
}
