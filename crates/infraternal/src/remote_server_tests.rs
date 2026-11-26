//! Checks explicit remote activation, required trust coordinates and service-install preservation without starting a listener (#78).

use super::*;

fn parsed(arguments: &[&str]) -> super::super::ServerArgs {
    let matches = crate::cli::command_tree::build(&crate::cli::actions::registry().unwrap())
        .try_get_matches_from(arguments)
        .unwrap();
    crate::server_args(crate::cli::command_tree::selected(&matches).matches).unwrap()
}

/// Keep the remote listener explicit and require its CA override to have a listener.
#[test]
fn remote_activation_is_explicit_and_ca_override_requires_listener() {
    let args = parsed(&["infraternal", "server", "--listen", "127.0.0.1:4701"]);
    assert!(args.remote.remote_listen.is_none());
    assert!(args.remote.remote_ca_dir.is_none());
    assert!(
        crate::cli::command_tree::build(&crate::cli::actions::registry().unwrap())
            .try_get_matches_from([
                "infraternal",
                "server",
                "--remote-ca-dir",
                "/unused/private/ca"
            ])
            .is_err()
    );
    let args = parsed(&[
        "infraternal",
        "server",
        "--remote-listen",
        "10.69.69.125:7443",
        "--remote-ca-dir",
        "/unused/private/ca",
    ]);
    assert_eq!(
        args.remote.remote_listen.unwrap(),
        "10.69.69.125:7443".parse().unwrap()
    );
    assert_eq!(
        args.remote.remote_ca_dir.unwrap(),
        PathBuf::from("/unused/private/ca")
    );
}

/// Build the prod-shaped host rules from server flags and typed admin entries.
#[test]
fn server_flags_accept_host_firewall_interfaces_and_admin_rules() {
    let matches = crate::cli::command_tree::build(&crate::cli::actions::registry().unwrap())
        .try_get_matches_from([
            "infraternal",
            "server",
            "--listen",
            "10.69.0.89:7011",
            "--behind-proxy",
            "--trusted-proxy",
            "10.69.0.99",
            "--remote-listen",
            "10.69.69.89:7443",
            "--host-firewall-listen-interface",
            "eth0",
            "--host-firewall-remote-interface",
            "wt0",
            "--host-firewall-remote-source",
            "10.69.69.0/24",
            "--host-firewall-accept-interface",
            "wt0",
            "--host-firewall-allow",
            "eth0,*,udp,51820",
            "--host-firewall-allow",
            "wt0,10.69.69.0/24,tcp,22",
            "--host-firewall-allow",
            "eth0,10.69.0.99,tcp,7012",
            "--host-firewall-allow",
            "wt0,10.69.69.99,tcp,7011",
            "--host-firewall-allow",
            "wt0,10.69.69.0/24,tcp,7443",
            "--host-firewall-allow",
            "wt0,10.69.69.0/24,udp,7443",
        ])
        .expect("server firewall options parse");
    let selected = crate::cli::command_tree::selected(&matches);

    assert_eq!(
        selected
            .matches
            .get_one::<String>("host_firewall_listen_interface")
            .map(String::as_str),
        Some("eth0")
    );
    assert_eq!(
        selected
            .matches
            .get_many::<String>("host_firewall_allow")
            .expect("extra firewall rules")
            .count(),
        6
    );
    assert_eq!(
        selected
            .matches
            .get_one::<String>("host_firewall_remote_interface")
            .map(String::as_str),
        Some("wt0")
    );
    assert_eq!(
        selected
            .matches
            .get_many::<String>("host_firewall_remote_source")
            .expect("remote listener source")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["10.69.69.0/24"]
    );
    assert_eq!(
        selected
            .matches
            .get_many::<String>("host_firewall_accept_interface")
            .expect("preserved broad interface")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["wt0"]
    );
}

/// Recreate every current production input allowance from server flags alone.
#[test]
fn server_flags_render_the_prod_host_policy() {
    let args = parsed(&[
        "infraternal",
        "server",
        "--listen",
        "10.69.0.89:7011",
        "--behind-proxy",
        "--trusted-proxy",
        "10.69.0.99",
        "--remote-listen",
        "10.69.69.89:7443",
        "--host-firewall-listen-interface",
        "eth0",
        "--host-firewall-remote-interface",
        "wt0",
        "--host-firewall-remote-source",
        "10.69.69.0/24",
        "--host-firewall-accept-interface",
        "wt0",
        "--host-firewall-allow",
        "eth0,*,udp,51820",
        "--host-firewall-allow",
        "wt0,10.69.69.0/24,tcp,22",
        "--host-firewall-allow",
        "wt0,10.69.69.99,tcp,7011",
        "--host-firewall-allow",
        "eth0,10.69.0.99,tcp,7011",
        "--host-firewall-allow",
        "eth0,10.69.0.99,tcp,7012",
        "--host-firewall-allow",
        "wt0,10.69.69.0/24,tcp,7443",
        "--host-firewall-allow",
        "wt0,10.69.69.0/24,udp,7443",
    ]);
    let policy = crate::host_firewall_policy(&args).expect("valid production policy flags");
    let rules = infraternal_plugin_mesh::host_firewall::render(&policy)
        .expect("default-drop production host policy");

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

/// Build the remote listener's interface and peer restrictions from its own flags.
#[test]
fn remote_listener_flags_become_host_input_rules() {
    let args = parsed(&[
        "infraternal",
        "server",
        "--remote-listen",
        "0.0.0.0:7444",
        "--host-firewall-remote-interface",
        "wt0",
        "--host-firewall-remote-source",
        "10.69.69.0/24",
        "--host-firewall-allow",
        "*,*,tcp,22",
    ]);
    let policy = crate::host_firewall_policy(&args).expect("valid remote listener settings");
    let rules = infraternal_plugin_mesh::host_firewall::render(&policy)
        .expect("valid remote listener policy");

    assert!(rules.contains("iifname \"wt0\" ip saddr 10.69.69.0/24 tcp dport 7444 accept"));
    assert!(rules.contains("iifname \"wt0\" ip saddr 10.69.69.0/24 udp dport 7444 accept"));
}

/// The persistent firewall entry follows the IPv4 relay socket even with an IPv6 TLS listener.
#[test]
fn relay_firewall_rule_matches_its_ipv4_listener() {
    let args = parsed(&[
        "infraternal",
        "server",
        "--remote-listen",
        "[::]:7444",
        "--relay-port",
        "3478",
        "--host-firewall-allow",
        "*,*,tcp,22",
    ]);
    let policy = crate::host_firewall_policy(&args).expect("valid relay policy flags");
    let relay = policy
        .listeners
        .iter()
        .find(|listener| listener.address.port() == 3478)
        .expect("relay UDP listener");

    assert_eq!(
        relay.protocol,
        infraternal_plugin_mesh::host_firewall::Protocol::Udp
    );
    assert_eq!(
        relay.address,
        "0.0.0.0:3478".parse().expect("IPv4 wildcard")
    );
}

#[test]
fn service_dry_run_preserves_remote_listener_and_private_trust_path() {
    let args = parsed(&[
        "infraternal",
        "server",
        "--listen",
        "127.0.0.1:4701",
        "--tls-cert",
        "server.pem",
        "--tls-key",
        "server.key",
        "--remote-listen",
        "10.69.69.125:7443",
        "--remote-ca-dir",
        "/unused/private ca",
    ]);
    let options = super::super::InstallArgs {
        system: false,
        user: true,
        dry_run: true,
        force: false,
        name: "remote-proof".into(),
    };
    let unit = super::super::install::install(&args, &options).unwrap();
    assert!(unit.contains("--remote-listen"));
    assert!(unit.contains("10.69.69.125:7443"));
    assert!(unit.contains("--remote-ca-dir"));
    assert!(unit.contains("/unused/private ca"));
    assert!(unit.contains("KillMode=process"));
}

/// A missing CA directory refuses before any database or listener exists.
#[tokio::test]
async fn missing_ca_refuses_before_database_or_listener_creation() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../.scratch/missing-ca-{}",
        uuid::Uuid::new_v4()
    ));
    let config = infraternal_server::ServerConfig {
        listen: "127.0.0.1:4701".parse().unwrap(),
        data_dir: directory.join("db"),
        public_origin: "https://localhost:4701".into(),
        web_root: None,
        tls: Some(infraternal_server::TlsFiles {
            certificate: directory.join("server.pem"),
            private_key: directory.join("server.key"),
        }),
        behind_proxy: false,
        trusted_proxies: vec![],
    };
    assert!(
        Box::pin(serve(
            config,
            Options {
                remote_listen: Some("127.0.0.1:7443".parse().unwrap()),
                remote_ca_dir: Some(directory.join("ca")),
                relay_port: None,
            }
        ))
        .await
        .is_err()
    );
    assert!(!directory.exists());
}

/// New remote operator commands must retain the scripting form required by
/// D199/D202. Parsing exercises the shipping Clap definitions without reading
/// local identity or sending an invitation to any endpoint.
#[test]
fn independent_review_remote_operator_commands_accept_json_output() {
    let accepted: Vec<bool> = [
        vec![
            "infraternal",
            "agent",
            "join",
            "https://localhost/remote/join",
            "--json",
        ],
        vec!["infraternal", "agent", "run", "--json"],
        vec![
            "infraternal",
            "server",
            "--remote-listen",
            "10.69.69.125:7443",
            "--json",
        ],
    ]
    .into_iter()
    .map(|arguments| {
        crate::cli::command_tree::build(&crate::cli::actions::registry().unwrap())
            .try_get_matches_from(arguments)
            .is_ok()
    })
    .collect();
    assert_eq!(
        accepted,
        vec![true; 3],
        "remote commands refuse the required JSON output option"
    );
}

/// A failed cold start still closes the inherited handoff stdin.
#[test]
fn failed_cold_configuration_still_disposes_handoff_stdin() {
    use std::process::{Command, Stdio};
    const NAME: &str =
        "remote_server::tests::failed_cold_configuration_still_disposes_handoff_stdin";
    if std::env::var_os("INFRATERNAL_COLD_FAILURE_TEST").is_some() {
        let directory = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/ca-handoff/missing-config");
        let config = infraternal_server::ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: directory.join("db"),
            public_origin: "https://localhost".into(),
            web_root: None,
            tls: Some(infraternal_server::TlsFiles {
                certificate: directory.join("missing.pem"),
                private_key: directory.join("missing.key"),
            }),
            behind_proxy: false,
            trusted_proxies: vec![],
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        assert!(
            runtime
                .block_on(serve(
                    config,
                    Options {
                        remote_listen: Some("127.0.0.1:7443".parse().unwrap()),
                        remote_ca_dir: Some(directory.join("ca")),
                        relay_port: None,
                    }
                ))
                .is_err()
        );
        assert_eq!(
            std::fs::read_link("/proc/self/fd/0").unwrap(),
            std::path::Path::new("/dev/null"),
            "import cleanup must run before cold_start can fail"
        );
        return;
    }
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(sender);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_COLD_FAILURE_TEST", "1")
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(receiver)))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn failed_restart_endpoint_does_not_prevent_http_serving() {
    use std::{
        os::unix::fs::DirBuilderExt,
        process::{Command, Stdio},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const NAME: &str =
        "remote_server::tests::failed_restart_endpoint_does_not_prevent_http_serving";
    if std::env::var_os("INFRATERNAL_CONTROL_FAILURE_TEST").is_some() {
        // Keep this socket fixture within the Unix pathname limit even when
        // the test runner supplies a long, isolated absolute HOME.
        let directory = std::env::temp_dir()
            .join("ca")
            .join(format!("endpoint-{}", uuid::Uuid::new_v4().simple()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .unwrap();
        std::fs::write(directory.join("restart"), b"occupied").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let serving = async move {
                let listener = tokio::net::TcpListener::bind(address).await.expect("HTTP bind");
                let (mut stream, _) = listener.accept().await.expect("HTTP accept");
                let mut request = [0_u8; 256];
                let _ = stream.read(&mut request).await.expect("HTTP request");
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.expect("HTTP reply");
                Ok::<(), infraternal_server::ServerError>(())
            };
            let serving = tokio::spawn(serve_behind_control(directory.clone(), serving));
            // Polls until the listener answers; the limit only catches a real hang, since a
            // debug-build startup under host load can exceed any short fixed budget.
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            loop {
                if serving.is_finished() {
                    let result = serving.await.expect("server task must not panic");
                    match result {
                        Err(error) => panic!("HTTP startup failed: {error}"),
                        Ok(_) => panic!("Control::start failure must not prevent server startup"),
                    }
                }
                if let Ok(mut stream) = tokio::net::TcpStream::connect(address).await {
                    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
                    let mut reply = Vec::new(); stream.read_to_end(&mut reply).await.unwrap();
                    assert!(reply.starts_with(b"HTTP/1.1 200"));
                    break;
                }
                assert!(std::time::Instant::now() < deadline, "HTTP startup deadline");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(matches!(serving.await.unwrap(), Ok(Outcome::Stopped)));
        });
        runtime.shutdown_timeout(Duration::from_secs(4));
        std::fs::remove_dir_all(directory).unwrap();
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_CONTROL_FAILURE_TEST", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
