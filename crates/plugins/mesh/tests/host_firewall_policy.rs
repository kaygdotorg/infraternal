//! Checks that typed settings produce the exact narrow host input policy.
#![cfg(target_os = "linux")]
#![expect(
    clippy::expect_used,
    reason = "fixture failures need the exact stage that failed"
)]

use std::{
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    process::{Command, Stdio},
    str::FromStr,
    thread,
    time::Duration,
};

use infraternal_plugin_mesh::host_firewall::{
    AllowRule, Listener, Policy, Protocol, apply_with_ssh_connection, diff_report, discover_nft,
    render, validate, validate_ssh_connection_on,
};

/// Supplies the private nft command and namespace setup used by these policy tests.
#[path = "support/nft_fixture.rs"]
mod nft_fixture;

use nft_fixture::NftFixture;

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

/// Reject a host policy that has no explicit SSH admin rule.
#[test]
fn policy_without_tcp_ssh_admin_rule_is_rejected() {
    let mut policy = prod_policy(false);
    policy.admin_rules.retain(|rule| rule.port != 22);

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

/// Show additions and removals while the product takes over an old host table.
#[test]
fn takeover_diff_names_only_changed_rule_lines() {
    let before = "iifname \"wt0\" ip saddr 10.69.69.0/24 tcp dport 22 accept\n";
    let after = format!("{before}udp dport 10254 accept\n");

    let report = diff_report(before, &after);

    assert!(!report.contains("- current: udp dport 10254 accept"));
    assert!(report.contains("+ desired: udp dport 10254 accept"));
}

/// Show rule order changes because an nft input chain is ordered policy.
#[test]
fn takeover_diff_reports_reordered_rule_lines() {
    let before =
        "iifname \"lo\" accept\nct state established,related accept\nip protocol icmp accept\n";
    let after =
        "ct state established,related accept\nip protocol icmp accept\niifname \"lo\" accept\n";

    let report = diff_report(before, after);

    assert!(report.contains("- current: iifname \"lo\" accept"));
    assert!(report.contains("+ desired: iifname \"lo\" accept"));
}

/// Treat nft's numeric invalid-state mask as the named state rendered by the product.
#[test]
fn takeover_diff_normalizes_the_invalid_state_mask() {
    assert_eq!(
        diff_report("ct state 0x1 drop\n", "ct state invalid drop\n"),
        "host firewall migration: no rule differences\n"
    );
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

/// Take over a hand-made host table without changing unrelated nft state.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn real_takeover_is_atomic_preserves_admin_and_leaves_other_tables_alone() {
    let nft_fixture = NftFixture::new(infraternal_plugin_mesh::host_firewall::nft_candidates());
    let nft = discover_nft(Some(nft_fixture.path())).expect("sandbox-owned nft executable");
    let setup = run_nft(
        &nft,
        &["-f", "-"],
        Some(concat!(
            "add table inet unrelated_control\n",
            "add chain inet unrelated_control keep\n",
            "add rule inet unrelated_control keep counter\n",
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
    let unrelated_before = list_table(&nft, "unrelated_control");
    let report = apply_with_ssh_connection(&prod_policy(true), Some(&nft), None)
        .expect("product policy takes over the legacy host table");
    let installed = list_table(&nft, "infraternal_host");
    let unrelated_after = list_table(&nft, "unrelated_control");

    assert_eq!(
        report,
        concat!(
            "host firewall migration: current and desired rules differ\n",
            "+ desired: iifname \"eth0\" ip saddr 10.69.0.99 ip daddr 10.69.0.89 tcp dport 7011 accept\n",
            "+ desired: iifname \"wt0\" ip saddr 10.69.69.0/24 ip daddr 10.69.69.89 tcp dport 7443 accept\n",
            "+ desired: iifname \"wt0\" ip saddr 10.69.69.0/24 ip daddr 10.69.69.89 udp dport 7443 accept\n",
            "+ desired: iifname \"infraternal0\" accept\n",
            "+ desired: udp dport 10254 accept\n",
        )
    );
    assert!(installed.contains("policy drop"));
    assert!(installed.contains("10.69.69.0/24 tcp dport 22 accept"));
    assert!(installed.contains("udp dport 10254 accept"));
    assert_eq!(unrelated_before, unrelated_after);

    let installed_with_handles = list_table_with_handles(&nft, "infraternal_host");
    let repeated = apply_with_ssh_connection(&prod_policy(true), Some(&nft), None)
        .expect("reapplying the current policy is safe");
    assert!(repeated.contains("no rule differences"));
    assert_eq!(
        installed_with_handles,
        list_table_with_handles(&nft, "infraternal_host"),
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
    assert_eq!(before_bad_apply, list_table(&nft, "infraternal_host"));

    assert!(
        !run_nft(
            &nft,
            &["-f", "-"],
            Some("delete table inet infraternal_host\ninvalid syntax\n"),
        )
        .status
        .success()
    );
    assert_eq!(before_bad_apply, list_table(&nft, "infraternal_host"));
}

/// Prove SSH, bidirectional mesh, fixed mesh UDP, and default-drop with real nft in netns.
#[test]
#[ignore = "Run in disposable network namespaces with CAP_NET_ADMIN."]
fn host_table_takeover_keeps_ssh_and_bidirectional_mesh_but_drops_other_ingress() {
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
        let unrelated_before = list_table(&nft, "unrelated_control");
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
            list_table(&nft, "unrelated_control"),
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
fn run_nft(nft: &Path, arguments: &[&str], input: Option<&str>) -> std::process::Output {
    let mut command = Command::new(nft);
    command.args(arguments);
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
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

/// Read a named table's canonical text without handles.
fn list_table(nft: &Path, name: &str) -> String {
    let output = run_nft(nft, &["-n", "list", "table", "inet", name], None);
    assert!(output.status.success(), "nft table listing failed");
    String::from_utf8(output.stdout).expect("nft output is UTF-8")
}

/// Include nft handles to prove an unchanged policy avoids a replacement transaction.
fn list_table_with_handles(nft: &Path, name: &str) -> String {
    let output = run_nft(nft, &["-a", "-n", "list", "table", "inet", name], None);
    assert!(output.status.success(), "nft table listing failed");
    String::from_utf8(output.stdout).expect("nft output is UTF-8")
}
