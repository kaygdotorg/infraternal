/// Real SSH bootstrap, automatic kernel mesh joining and a surviving terminal in owned containers (#201).
/// Unrestricted Output callbacks are route diagnostics. A readiness PTY created
/// after the ingress fence and a separate fresh post-join marker supply causal
/// mesh-byte witnesses, separately labeled from unrestricted timings [263].
/// Optional release cycles retain the same writer across repeated path moves.
use super::*;
use crate::remote_runtime::tests::mesh_namespace::{
    Echo, local_daemon, namespace_pool, proof_routes, root_fixture_home, wait_link,
};
use infraternal_plugin_api::server_path::ServerLinkKind;
use infraternal_plugin_mesh::{policy::model::PublicKey, wireguard::Device};
use std::{
    io::Read,
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Stop only the daemon spawned by this fixture, including when an assertion fails.
struct Daemon(std::process::Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn nft(source: &str) {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            source
                .replace("} }", "}\n}")
                .replace("} chain", "}\nchain")
                .as_bytes(),
        )
        .unwrap();
    assert!(
        child.wait().unwrap().success(),
        "owned namespace firewall refused"
    );
}

fn wall_us(at: SystemTime) -> u128 {
    at.duration_since(UNIX_EPOCH).unwrap().as_micros()
}

/// Ack clocks bracket the local nft syscall/process overhead included in this
/// separate causal profile. No readiness PTY exists until the hook returns.
#[derive(Clone, Copy)]
struct CanaryFence {
    started: Instant,
    installed: Instant,
    wall_started: SystemTime,
    wall_installed: SystemTime,
}

fn fence_rules(node: std::net::IpAddr, controller: std::net::IpAddr, name: &str) -> String {
    format!(
        "table inet {name} {{ chain input {{ type filter hook input priority -10; policy accept; ip saddr {node} ip daddr {controller} udp dport 4930 counter drop; ip saddr {node} ip daddr {controller} tcp dport 4930 counter drop; }} }}"
    )
}

/// Hold only this fixture's encrypted outer path; enrolled control stays live.
fn mesh_cut_rules(port: u16, name: &str) -> String {
    format!("table inet {name} {{ chain input {{ type filter hook input priority -10; policy accept; udp dport {port} counter drop; }} chain output {{ type filter hook output priority -10; policy accept; udp sport {port} counter drop; }} }}")
}

fn save_canary_fence(
    scratch: &std::path::Path,
    capture: &crate::remote_autoswitch_probe::Capture,
    fence: &Mutex<Option<CanaryFence>>,
) {
    let observed = *fence.lock().unwrap();
    let Some(fence) = observed else {
        return;
    };
    let events = capture.events();
    let first = events
        .iter()
        .filter(|event| event.kind == crate::remote_autoswitch_probe::Kind::TerminalByte)
        .min_by_key(|event| event.monotonic);
    let report = serde_json::json!({"profile":"fenced-canary","prior_terminal_output_callbacks":0,"fence_started_wall_us":wall_us(fence.wall_started),
        "fence_installed_wall_us":wall_us(fence.wall_installed),"local_fence_overhead_us":fence.installed.duration_since(fence.started).as_micros(),
        "first_canary_output_wall_us":first.map(|event|wall_us(event.wall)),"first_canary_output_stream":first.map(|event|event.stream),
        "first_output_after_fence_ack":first.map(|event|event.wall>=fence.wall_installed && event.monotonic>=fence.installed),
        "first_fenced_canary_output_path_proven":first.is_some_and(|event|event.wall>=fence.wall_installed && event.monotonic>=fence.installed && event.stream!=0),"earliest_unrestricted_output_claimed":false});
    std::fs::write(
        scratch.join("fenced-canary-stage.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    let rules = Command::new("nft")
        .args(["list", "table", "inet", "acceptance_canary_fence"])
        .output()
        .unwrap();
    if rules.status.success() {
        std::fs::write(scratch.join("fenced-canary-firewall.nft"), rules.stdout).unwrap();
    }
}

/// Keep failure receipts restricted to typed public categories and trusted static
/// text. No process/database error, credential, SSH stderr or arbitrary log tail
/// is copied into evidence.
fn public_failure(failure: Option<&Failure>) -> serde_json::Value {
    failure.map_or(serde_json::Value::Null, |failure| {
        serde_json::json!({"kind":failure.kind,"message":failure.message,
            "failed_step":failure.failed_step,"exit_status":failure.exit_status})
    })
}

/// Snapshot bounded observer metadata even when bootstrap fails before Done.
/// Callback counts include TCP and QUIC; first events carry public coordinates,
/// never terminal contents or unrestricted packet-provenance claims.
fn observer_snapshot(capture: &crate::remote_autoswitch_probe::Capture) -> serde_json::Value {
    use crate::remote_autoswitch_probe::Kind;
    let mut events = capture.events();
    events.sort_by_key(|event| event.monotonic);
    let first_events: Vec<_> = events
        .iter()
        .take(64)
        .map(|event| {
            serde_json::json!({"kind":format!("{:?}",event.kind),"peer":event.peer.to_string(),
            "stream":event.stream,"wall_us":wall_us(event.wall)})
        })
        .collect();
    serde_json::json!({"tls_callbacks":capture.count(Kind::TlsHandshake),
        "admission_callbacks":capture.count(Kind::LedgerAdmission),
        "control_ready_callbacks":capture.count(Kind::ControlReady),
        "terminal_detach_already_retired":capture.count(Kind::TerminalDetachAlreadyRetired),
        "terminal_detach_write_errors":capture.count(Kind::TerminalDetachWriteError),
        "terminal_output_callbacks":capture.count(Kind::TerminalByte),
        "first_events":first_events,"first_event_limit":64,
        "first_events_truncated":events.len()>64,"earliest_unrestricted_output_claimed":false})
}

/// Exposes only public kernel peer counters in the disposable node namespace.
/// A query carries the server's public key, never a generated node private key.
#[tokio::test]
#[ignore = "Owned acceptance runner starts this public counter sidecar in the target container."]
async fn mesh_acceptance_node_counters() {
    let address: SocketAddr = std::env::var("ACCEPTANCE_COUNTER_ADDR")
        .unwrap()
        .parse()
        .unwrap();
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let unix = std::env::var_os("ACCEPTANCE_COUNTER_PIPE")
        .map(|path| tokio::net::UnixListener::bind(path).unwrap());
    loop {
        tokio::select! {
            accepted = listener.accept() => serve_peer_counter(accepted.unwrap().0).await,
            accepted = async { unix.as_ref().unwrap().accept().await }, if unix.is_some() => serve_peer_counter(accepted.unwrap().0).await,
        }
    }
}

/// Both fixture transports expose the identical bounded public counter query.
async fn serve_peer_counter<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut socket: S) {
        let mut key = [0_u8; 32];
        if socket.read_exact(&mut key).await.is_err() {
            return;
        }
        let peer = Device::counters()
            .ok()
            .and_then(|mut peers| peers.remove(&PublicKey(key)));
        let report = peer.map_or(serde_json::Value::Null, |peer| {
            serde_json::json!({"handshake_secs":peer.handshake_secs,
                "handshake_nanos":peer.handshake_nanos,"sent_bytes":peer.sent_bytes,"received_bytes":peer.received_bytes})
        });
        // A bounded diagnostic requester may have timed out and closed its
        // socket; that must not terminate this owned public-counter sidecar.
        let _ = socket
            .write_all(&serde_json::to_vec(&report).unwrap())
            .await;
        let _ = socket.shutdown().await;
}

/// One post-arrival query reads the node's exact public kernel timestamp without
/// a polling worker during joining. Read before later sessions in fenced mode.
async fn node_counters_observation(
    node: std::net::IpAddr,
    server_key: PublicKey,
) -> Option<serde_json::Value> {
    if let Some(path) = std::env::var_os("ACCEPTANCE_COUNTER_PIPE") {
        return read_node_counter_stream(tokio::net::UnixStream::connect(path).await.ok()?, server_key).await;
    }
    read_node_counter_stream(tokio::net::TcpStream::connect(SocketAddr::new(node, 4931))
        .await
        .ok()?, server_key).await
}

/// Read one bounded response; the private fixture pipe avoids emulated RTT.
async fn read_node_counter_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut socket: S, server_key: PublicKey) -> Option<serde_json::Value> {
    socket.write_all(&server_key.0).await.ok()?;
    let mut reply = Vec::new();
    socket.take(4096).read_to_end(&mut reply).await.ok()?;
    let value: serde_json::Value = serde_json::from_slice(&reply).ok()?;
    (!value.is_null()).then_some(value)
}

async fn node_counters(node: std::net::IpAddr, server_key: PublicKey) -> serde_json::Value {
    node_counters_observation(node, server_key)
        .await
        .expect("selected public node peer counters unavailable")
}

/// Both containers are fresh. Mesh stays enabled through the genuine bootstrap;
/// joining can precede Done and the report retains that order with signed deltas.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Run scripts/mesh-addhost-acceptance.py on the pinned perf VM under its shared lock."]
async fn mesh_acceptance_real_addhost() {
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
    // The runner supplies fresh Docker mount/network namespaces, never host mode.
    assert_eq!(std::env::var("ACCEPTANCE_OWNED_CONTAINER").unwrap(), "1");
    let scratch = PathBuf::from(std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap());
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_string_lossy(),
        std::env::var("ACCEPTANCE_HOST_NETNS").unwrap()
    );
    assert_ne!(
        std::fs::read_link("/proc/self/ns/mnt")
            .unwrap()
            .to_string_lossy(),
        std::env::var("ACCEPTANCE_HOST_MNTNS").unwrap()
    );
    root_fixture_home(&scratch);
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").unwrap());
    let controller: std::net::IpAddr = std::env::var("BREAKIT2_CONTROLLER_IP")
        .unwrap()
        .parse()
        .unwrap();
    let node: std::net::IpAddr = std::env::var("ACCEPTANCE_NODE_IP")
        .unwrap()
        .parse()
        .unwrap();
    let mut private = Vec::new();
    std::io::stdin()
        .take(24577)
        .read_to_end(&mut private)
        .unwrap();
    assert!(private.len() <= 24576);
    let pool = namespace_pool(sqlx::sqlite::SqlitePoolOptions::new()).await;
    let (store, pool, prior) = crate::enrollment::authority::tests::enrolled_with_pool(pool).await;
    let f = fixture_with_store(true, store.clone(), pool.clone(), prior).await;
    let (identity, material) =
        crate::remote_runtime::tests::server_material_for_name("addhost-breakit2.test");
    let source: Arc<dyn CaKeySource> = Arc::new(Signer(Some(material.clone())));
    let hosts = RemoteHosts::from_source(Some(source.clone()));
    let listeners = crate::remote_runtime::RemoteListeners::start(
        SocketAddr::new(controller, 4930),
        &identity,
        &[material.issuer().clone()],
        store.clone(),
        hosts.clone(),
    )
    .await
    .unwrap();
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: listeners.local_addr().unwrap(),
        server_name: "addhost-breakit2.test".into(),
    };
    let auth = Auth::new(
        pool.clone(),
        "addhost-breakit2.test",
        "https://addhost-breakit2.test:4929",
    )
    .await
    .unwrap();
    let service = EnrollmentService {
        source: source.clone(),
        endpoint: endpoint.clone(),
    };
    let http = crate::remote_http::router_with_store(
        auth.clone(),
        pool.clone(),
        store.clone(),
        source.clone(),
        endpoint,
    );
    let tls = axum_server::tls_openssl::OpenSSLConfig::from_der(
        &identity.certificate.to_der().unwrap(),
        &identity.key.private_key_to_der().unwrap(),
    )
    .unwrap();
    let http_task = tokio::spawn(
        axum_server::bind_openssl(SocketAddr::new(controller, 4929), tls)
            .serve(http.into_make_service_with_connect_info::<SocketAddr>()),
    );
    let runtime = crate::plugins::compiled(&pool).await.unwrap();
    let (daemon, local) = local_daemon(&binary, &scratch.join("d"));
    let _daemon = Daemon(daemon);
    runtime
        .attach_node(Arc::new(crate::node_bridge::NodeBridge {
            id: "server".into(),
            ip: controller,
            server: true,
            server_paths: true,
            actor: local.clone(),
            authority: None,
            listeners: Some(hosts.clone()),
            peer_routes: None,
        }))
        .await
        .unwrap();
    hosts.bind_plugins(&runtime).await.unwrap();
    let server_mesh: infraternal_plugin_mesh::dataplane::Identity = serde_json::from_slice(
        &local
            .call("mesh.identity".into(), b"{}".to_vec())
            .await
            .unwrap(),
    )
    .unwrap();
    // A separate controlled profile creates a real enrolled PTY before joining.
    // Its intentional hold is reported, never counted as natural join latency.
    let standing = std::env::var("ACCEPTANCE_MODE").is_ok_and(|mode| mode == "standing-switch");
    if standing {
        nft(&mesh_cut_rules(server_mesh.port, "acceptance_initial_hold"));
    }
    let inventory = infraternal_plugin_mesh::api::MeshService::new(pool.clone()).dataplane();
    inventory
        .attach(
            "server",
            server_mesh.public_key,
            Some(SocketAddr::new(controller, server_mesh.port)),
            true,
        )
        .await
        .unwrap();
    let backend = Arc::new(RemoteBackend {
        base: PendingRemoteRuntime {
            auth: Some(auth.clone()),
            key: Arc::new(crate::ssh_key::UnavailableSshKey),
        },
        issuer: InvitationIssuer::new(auth, pool.clone(), store, service),
        hosts: hosts.clone(),
        attempts: Mutex::default(),
    });
    let transport = Arc::new(super::breakit2_live::FixtureTransport {
        transport: Arc::new(super::breakit2_live::TimedTransport {
            adapter: infraternal_plugin_ssh::openssh::OpenSsh {
                ssh: scratch.join("ssh"),
                ssh_agent: "/usr/bin/ssh-agent".into(),
                ssh_add: "/usr/bin/ssh-add".into(),
                ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
                ssh_keygen: "/usr/bin/ssh-keygen".into(),
                askpass_binary: binary.clone(),
                scratch: scratch.clone(),
                command_timeout: Duration::from_secs(30),
            },
        }),
        private: Mutex::new(Some(Secret::new(private))),
    });
    let capture = Arc::new(
        crate::remote_autoswitch_probe::Capture::start(|_| true)
            .with_routes(proof_routes(&listeners)),
    );
    let baseline_transport = std::env::var("ACCEPTANCE_TRANSPORT_EXPECTATION")
        .unwrap_or_else(|_| "preserved".into())
        == "baseline";
    let fenced_canary = std::env::var("ACCEPTANCE_MODE").unwrap_or_else(|_| "unrestricted".into())
        == "fenced-canary";
    let canary_fence = Arc::new(Mutex::new(None::<CanaryFence>));
    let canary_hook = if fenced_canary {
        let capture = capture.clone();
        let fence = canary_fence.clone();
        let rules = fence_rules(node, controller, "acceptance_canary_fence");
        Some(Arc::new(move || {
            assert_eq!(
                capture.count(crate::remote_autoswitch_probe::Kind::TerminalByte),
                0,
                "fresh canary profile already received terminal bytes"
            );
            assert!(
                fence.lock().unwrap().is_none(),
                "canary fence installed twice"
            );
            let started = Instant::now();
            let wall_started = SystemTime::now();
            nft(&rules);
            *fence.lock().unwrap() = Some(CanaryFence {
                started,
                installed: Instant::now(),
                wall_started,
                wall_installed: SystemTime::now(),
            });
            Ok(())
        }) as super::breakit2_live::CanaryHook)
    } else {
        None
    };
    let diagnostic_profile = std::env::var("ACCEPTANCE_DIAGNOSTICS")
        .unwrap_or_else(|_| "none".into())
        == "canary-return";
    let after_canary = if diagnostic_profile {
        let capture = capture.clone();
        let backend = backend.clone();
        let scratch = scratch.clone();
        let server_key = server_mesh.public_key;
        Some(Arc::new(move |host, failure: Option<Failure>| {
            let capture = capture.clone();
            let backend = backend.clone();
            let scratch = scratch.clone();
            Box::pin(async move {
                // Both queries start strictly after production readiness returns.
                // Their bounded overhead delays rollback/Done in this explicit
                // diagnostic profile, and is never ordinary timing evidence.
                let returned = Instant::now();
                let returned_wall = SystemTime::now();
                let observation = observer_snapshot(&capture);
                std::fs::write(
                    scratch.join("canary-internal-stages.json"),
                    serde_json::to_vec_pretty(&super::canary_stage_receipt()).unwrap(),
                )
                .unwrap();
                let node_query = tokio::time::timeout(
                    Duration::from_secs(2),
                    node_counters_observation(node, server_key),
                );
                let status_query = tokio::time::timeout(Duration::from_secs(2), async {
                    let actor = backend.hosts.actor(host).await?;
                    let bytes = actor
                        .call("mesh.status".into(), b"{}".to_vec())
                        .await
                        .ok()?;
                    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                    serde_json::from_value::<infraternal_plugin_api::server_path::ServerLink>(
                        value["server_link"].clone(),
                    )
                    .ok()
                });
                let (node_result, status_result) = tokio::join!(node_query, status_query);
                let report = serde_json::json!({"kind":"canary_return_diagnostic","diagnostic_profile":"canary-return",
                    "before_bootstrap_rollback":true,"canary_return_wall_us":wall_us(returned_wall),
                    "canary_ok":failure.is_none(),"public_failure":public_failure(failure.as_ref()),
                    "callbacks_at_canary_return":observation,"selected_node_peer":node_result.as_ref().ok().and_then(|node|node.as_ref()),
                    "node_query_timed_out":node_result.is_err(),"server_link":status_result.as_ref().ok().and_then(|status|status.as_ref()),
                    "server_link_query_timed_out":status_result.is_err(),"query_timeout_ms":2000,
                    "post_canary_diagnostic_query_overhead_us":returned.elapsed().as_micros(),
                    "diagnostic_file_write_in_bootstrap_completion":true,
                    "diagnostic_overhead_in_bootstrap_completion":true,"ordinary_latency_acceptance":false});
                std::fs::write(
                    scratch.join("canary-return-diagnostic.json"),
                    serde_json::to_vec_pretty(&report).unwrap(),
                )
                .unwrap();
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        }) as super::breakit2_live::CanaryReturnHook)
    } else {
        None
    };
    let runner = Bootstrap::new(
        transport,
        Arc::new(super::breakit2_live::ObservedBackend(
            backend,
            canary_hook,
            after_canary,
        )),
        BinaryPaths {
            x86_64: binary.clone(),
            aarch64: binary,
        },
    );
    let start = Instant::now();
    let start_wall = SystemTime::now();
    let batch = runner
        .start_authenticated(
            "owner".into(),
            Secret::new(f.cookie.as_bytes().to_vec()),
            vec![Target {
                id: "live".into(),
                address: TargetAddress::Manual(std::env::var("BREAKIT2_TARGET").unwrap()),
                credential: None,
                mode: InstallMode::Root,
                root_consent: true,
            }],
            None,
        )
        .unwrap();
    let mut changed = batch.subscribe();
    let done = tokio::time::timeout(Duration::from_secs(220), async {
        loop {
            if let Some(event) = batch
                .events(0)
                .1
                .into_iter()
                .find(|event| matches!(event.step, Step::Done | Step::Failed))
            {
                let completed = Instant::now();
                save_canary_fence(&scratch, &capture, &canary_fence);
                let stage = serde_json::json!({"kind":"real_ssh_bootstrap_terminal_stage",
                    "step":format!("{:?}",event.step),"completed_wall_us":wall_us(SystemTime::now()),
                    "bootstrap_elapsed_us":completed.duration_since(start).as_micros(),
                    "public_failure":public_failure(event.failure.as_ref()),"callbacks":observer_snapshot(&capture),
                    "diagnostic_profile":if diagnostic_profile {"canary-return"} else {"none"},
                    "ordinary_latency_acceptance":!diagnostic_profile && !cfg!(debug_assertions)});
                std::fs::write(scratch.join("bootstrap-terminal-stage.json"), serde_json::to_vec_pretty(&stage).unwrap()).unwrap();
                if event.step == Step::Failed && event.failure.is_some() {
                    let report = serde_json::json!({"kind":"real_ssh_addhost_mesh_acceptance",
                        "transport_expectation":if baseline_transport {"baseline"} else {"preserved"},
                        "acceptance_mode":if fenced_canary {"fenced-canary"} else {"unrestricted"},
                        "rtt_ms":std::env::var("INFRATERNAL_TEST_RTT").unwrap(),"fresh_real_ssh_install":true,
                        "bootstrap_succeeded":false,"recorded_operation_failure":true,
                        "bootstrap_elapsed_us":completed.duration_since(start).as_micros(),
                        "public_failure":public_failure(event.failure.as_ref()),"callbacks":observer_snapshot(&capture),
                        "terminal_byte_integrity":false,"connection_preservation_claimed":false,
                        "first_fenced_canary_output_path_proven":false,"earliest_unrestricted_output_claimed":false,
                        "node_handshake_to_first_fenced_canary_output_us":null,
                        "diagnostic_profile":if diagnostic_profile {"canary-return"} else {"none"},
                        "ordinary_latency_acceptance":!diagnostic_profile && !cfg!(debug_assertions)});
                    std::fs::write(scratch.join("acceptance.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
                    if baseline_transport { return None; }
                }
                assert_eq!(event.step, Step::Done, "real SSH bootstrap failed at {:?}", event.failure.as_ref().and_then(|f|f.failed_step));
                return Some(completed);
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let Some(done) = done else {
        return;
    };
    let done_wall = SystemTime::now();
    let first_canary = if fenced_canary {
        let first = capture
            .events()
            .into_iter()
            .filter(|event| event.kind == crate::remote_autoswitch_probe::Kind::TerminalByte)
            .min_by_key(|event| event.monotonic)
            .expect("production canary returned without a nonempty Output witness");
        let fence = canary_fence.lock().unwrap().unwrap();
        assert!(first.wall >= fence.wall_installed && first.monotonic >= fence.installed);
        assert_ne!(first.stream, 0);
        let wall_elapsed = first.wall.duration_since(start_wall).unwrap();
        let elapsed = first.monotonic.duration_since(start);
        assert!(
            elapsed < Duration::from_secs(60)
                && wall_elapsed.abs_diff(elapsed) < Duration::from_millis(5),
            "fenced canary clock or lifecycle invalid"
        );
        nft("delete table inet acceptance_canary_fence");
        Some(first)
    } else {
        None
    };

    let early_peer = if fenced_canary {
        Some(node_counters(node, server_mesh.public_key).await)
    } else {
        None
    };
    let id: Vec<u8> =
        sqlx::query_scalar("SELECT id FROM remote_hosts WHERE id<>? AND revoked_at IS NULL")
            .bind(prior.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    let host = Uuid::from_slice(&id).unwrap();
    let remote = hosts.actor(host).await.unwrap();
    wait_link(&remote, if standing { ServerLinkKind::Fallback } else { ServerLinkKind::Mesh }).await;
    let session = remote
        .open(TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        })
        .await
        .unwrap();
    let mut echo = Echo::start(&remote, Uuid::from_bytes(session)).await;
    let terminal_writer = echo.writer_id();
    let mut expected = b"unrestricted|".to_vec();
    echo.send(&expected).await;
    echo.wait(&expected).await;
    let diagnostic = capture.events();
    let tls_count = capture.count(crate::remote_autoswitch_probe::Kind::TlsHandshake);
    let admission_count = capture.count(crate::remote_autoswitch_probe::Kind::LedgerAdmission);
    let control_count = capture.count(crate::remote_autoswitch_probe::Kind::ControlReady);
    if !baseline_transport {
        // An unused losing dial can finish TLS and its authority lookup before
        // sending Hello. Only control activation creates the host transport.
        if control_count != 1 {
            std::fs::write(
                scratch.join("bootstrap-transport-failure.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "phase":"after_initial_echo_before_mesh_release",
                    "done_wall_us":wall_us(done_wall),
                    "callbacks":observer_snapshot(&capture),
                })).unwrap(),
            ).unwrap();
        }
        assert!(tls_count >= 1, "bootstrap TLS handshake was not observed");
        assert_eq!(control_count, 1, "bootstrap activated multiple transports");
        assert!(
            admission_count >= 1,
            "bootstrap authority lookup was not observed"
        );
    }
    let stage_observer = std::env::var_os("ACCEPTANCE_STANDING_STAGES").is_some();
    let mut standing_stages = None;
    let mut standing_first = None;
    let mut standing_peer = None;
    let mut release_wall = None;
    if standing {
        assert!(std::env::var_os("ACCEPTANCE_COUNTER_PIPE").is_some(), "standing observer must bypass the emulated network");
        let prepared = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if let Some(peer) = node_counters_observation(node, server_mesh.public_key).await { break peer; }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await.unwrap();
        assert_eq!(prepared["handshake_secs"], 0, "held mesh already joined");
        release_wall = Some(SystemTime::now());
        nft("delete table inet acceptance_initial_hold");
        // Observe the exact node clock over the private fixture pipe. A TCP
        // counter RPC would add the emulated RTT before generating the marker.
        // Polling and firewall overhead remain in the result; subtract nothing.
        standing_peer = Some(tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if let Some(peer) = node_counters_observation(node, server_mesh.public_key).await
                    && peer["handshake_secs"].as_u64().is_some_and(|seconds|seconds != 0) { break peer; }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await.unwrap());
        let counter_finished = stage_observer.then(SystemTime::now);
        capture.clear_terminal_milestones();
        let fence_started = stage_observer.then(SystemTime::now);
        nft(&fence_rules(node, controller, "acceptance_standing_fence"));
        let fence_finished = stage_observer.then(SystemTime::now);
        let boundary = Instant::now();
        let marker = format!("standing-mesh-{}|", Uuid::new_v4());
        expected.extend_from_slice(marker.as_bytes());
        let send_started = stage_observer.then(SystemTime::now);
        echo.send(marker.as_bytes()).await;
        let send_finished = stage_observer.then(SystemTime::now);
        echo.wait(&expected).await;
        standing_first = capture.first_terminal_after(terminal_writer, boundary);
        assert!(standing_first.is_some(), "fresh standing marker has no authenticated Output witness");
        if stage_observer {
            // Attribute fixture scheduling separately; no overhead is removed
            // from the causal handshake-to-Output acceptance boundary.
            standing_stages = Some(serde_json::json!({
                "scope":"observer-cost stage attribution; not adjusted acceptance latency",
                "counter_finished_wall_us":wall_us(counter_finished.unwrap()),
                "fence_started_wall_us":wall_us(fence_started.unwrap()),
                "fence_finished_wall_us":wall_us(fence_finished.unwrap()),
                "send_started_wall_us":wall_us(send_started.unwrap()),
                "send_finished_wall_us":wall_us(send_finished.unwrap())
            }));
        }
        nft("delete table inet acceptance_standing_fence");
        wait_link(&remote, ServerLinkKind::Mesh).await;
    }
    // Query kernel public state only after unrestricted output. This worker did
    // not poll or add wakeups during the measured automatic joining interval.
    let peer = match standing_peer.or(early_peer) {
        Some(peer) => peer,
        None => node_counters(node, server_mesh.public_key).await,
    };
    let joined = UNIX_EPOCH
        + Duration::new(
            peer["handshake_secs"].as_u64().unwrap(),
            u32::try_from(peer["handshake_nanos"].as_u64().unwrap()).unwrap(),
        );
    if let Some(first) = &first_canary {
        assert!(
            joined >= start_wall && joined <= first.wall,
            "node handshake does not precede first causal canary Output"
        );
    }
    if let Some(first) = &standing_first {
        assert!(joined >= release_wall.unwrap() && joined <= first.wall, "standing witness is not after the fresh node handshake");
    }
    assert!(
        joined >= start_wall && joined <= SystemTime::now(),
        "fresh lifecycle handshake unavailable"
    );
    // Reuse the existing post-success fence: readiness and commit have already
    // completed without a mesh hold. Earlier Echo bytes are fully drained.
    // This supplies an upper bound on natural mesh usability, including all
    // intervening fixture work; it cannot identify the earliest natural byte.
    let natural_witness = !standing && !fenced_canary;
    if natural_witness {
        capture.clear_terminal_milestones();
    }
    // Established traffic must hit this earlier chain before an established
    // accept. Both enrolled directions/ports differ from the WireGuard outer
    // datagrams; decrypted mesh traffic retains its mesh destination address.
    nft(&format!(
        "table inet acceptance_fence {{ chain input {{ type filter hook input priority -10; policy accept; ip saddr {node} ip daddr {controller} udp dport 4930 counter drop; ip saddr {node} ip daddr {controller} tcp dport 4930 counter drop; }} }}"
    ));
    let fence = Instant::now();
    let marker = format!("mesh-witness-{}|", Uuid::new_v4());
    expected.extend_from_slice(marker.as_bytes());
    echo.send(marker.as_bytes()).await;
    echo.wait(&expected).await;
    let witness = Instant::now();
    let witness_wall = SystemTime::now();
    let natural_first = natural_witness.then(|| {
        let first = capture
            .first_terminal_after(terminal_writer, fence)
            .expect("post-success marker has no authenticated Output witness");
        assert!(first.wall >= joined && first.monotonic >= done);
        first
    });
    if !baseline_transport {
        assert_eq!(
            capture.count(crate::remote_autoswitch_probe::Kind::TlsHandshake),
            tls_count,
            "marker transport replaced"
        );
        assert_eq!(
            capture.count(crate::remote_autoswitch_probe::Kind::LedgerAdmission),
            admission_count,
            "marker authority readmitted"
        );
    }
    assert!(
        peer["sent_bytes"].as_u64().unwrap() > 0 && peer["received_bytes"].as_u64().unwrap() > 0
    );
    let rules = Command::new("nft")
        .args(["list", "table", "inet", "acceptance_fence"])
        .output()
        .unwrap();
    assert!(rules.status.success());
    std::fs::write(scratch.join("exclusive-path-firewall.nft"), rules.stdout).unwrap();
    nft("delete table inet acceptance_fence");
    // Silent mesh cut preserves interface and routes; the very same attachment
    // and shell must continue over the original enrolled fallback.
    nft(&mesh_cut_rules(server_mesh.port, "acceptance_cut"));
    let cut = Instant::now();
    // Queue fresh input while the mesh is still cut. Status and byte receipt
    // observations run concurrently, so no status RTT precedes the actual echo.
    let fallback_marker = format!("fallback-survived-{}|", Uuid::new_v4());
    expected.extend_from_slice(fallback_marker.as_bytes());
    let fallback_sent = echo.send_result(fallback_marker.as_bytes()).await;
    let fallback_marker_queued = fallback_sent.is_ok();
    let (fallback_status, (fallback_echo, fallback_echo_at)) = tokio::join!(
        async {
            wait_link(&remote, ServerLinkKind::Fallback).await;
            Instant::now()
        },
        async {
            let result = match fallback_sent {
                Ok(()) => echo.wait_result(&expected).await,
                Err(error) => Err(error),
            };
            let arrived = result.as_ref().ok().map(|()| Instant::now());
            (result, arrived)
        }
    );
    nft("delete table inet acceptance_cut");
    // The release trial retains this one writer through every repeated path
    // move. The existing enrolled-ingress fence proves fresh mesh Output.
    let release_cycle_count =
        std::env::var("ACCEPTANCE_RELEASE_CYCLES").map_or(0, |value| value.parse::<u32>().unwrap());
    assert!(
        release_cycle_count <= 10,
        "release cycle count exceeds its lab bound"
    );
    assert!(release_cycle_count == 0 || (standing && !baseline_transport),
        "release cycles require a preserved standing terminal");
    let mut release_path_cycles = Vec::new();
    if fallback_echo.is_ok() {
        for cycle in 1..=release_cycle_count {
            wait_link(&remote, ServerLinkKind::Mesh).await;
            println!("RELEASE_CYCLE cycle={cycle} phase=mesh writer={terminal_writer}");
            nft(&fence_rules(node, controller, "release_cycle_fence"));
            capture.clear_terminal_milestones();
            let mesh_started = Instant::now();
            let marker = format!("release-cycle-{cycle}-mesh-{}|", Uuid::new_v4());
            expected.extend_from_slice(marker.as_bytes());
            echo.send(marker.as_bytes()).await;
            echo.wait(&expected).await;
            let mesh_echo_us = mesh_started.elapsed().as_micros();
            assert!(
                capture
                    .first_terminal_after(terminal_writer, mesh_started)
                    .is_some()
            );
            nft("delete table inet release_cycle_fence");
            println!("RELEASE_CYCLE cycle={cycle} phase=fallback writer={terminal_writer}");
            nft(&mesh_cut_rules(server_mesh.port, "release_cycle_cut"));
            let fallback_started = Instant::now();
            let marker = format!("release-cycle-{cycle}-fallback-{}|", Uuid::new_v4());
            expected.extend_from_slice(marker.as_bytes());
            echo.send(marker.as_bytes()).await;
            echo.wait(&expected).await;
            let fallback_echo_us = fallback_started.elapsed().as_micros();
            wait_link(&remote, ServerLinkKind::Fallback).await;
            assert_eq!(echo.writer_id(), terminal_writer);
            assert_eq!(
                capture.count(crate::remote_autoswitch_probe::Kind::TlsHandshake),
                tls_count
            );
            assert_eq!(
                capture.count(crate::remote_autoswitch_probe::Kind::LedgerAdmission),
                admission_count
            );
            assert_eq!(
                capture.count(crate::remote_autoswitch_probe::Kind::ControlReady),
                control_count
            );
            // Echo::wait requires the entire received stream to equal expected.
            release_path_cycles.push(serde_json::json!({
                "cycle":cycle,"writer_id":terminal_writer,"expected_bytes":expected.len(),
                "verified_bytes":expected.len(),"mesh_output_path_proven":true,
                "mesh_echo_us":mesh_echo_us,"fallback_echo_us":fallback_echo_us,
                "tls_admission_control_unchanged":true
            }));
            std::fs::write(
                scratch.join("release-path-cycles.json"),
                serde_json::to_vec_pretty(&release_path_cycles).unwrap(),
            )
            .unwrap();
            nft("delete table inet release_cycle_cut");
        }
    }
    // Optional full lifecycle coverage reuses the real installed daemon and
    // its writer after the measured cut. Its work cannot alter earlier clocks.
    let mesh_disable_checked = std::env::var_os("ACCEPTANCE_DISABLE_LIFECYCLE").is_some();
    if mesh_disable_checked {
        runtime
            .set_enabled("mesh", false)
            .await
            .expect("mesh disable failed after fallback");
        wait_link(&remote, ServerLinkKind::Fallback).await;
        let enabled: i64 = sqlx::query_scalar(
            "SELECT enabled FROM plugin_settings WHERE role='server' AND plugin='mesh'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(enabled, 0, "mesh disable was not durably committed");
        let marker = format!("disabled-survived-{}|", Uuid::new_v4());
        expected.extend_from_slice(marker.as_bytes());
        echo.send(marker.as_bytes()).await;
        echo.wait(&expected).await;
    }
    let final_tls = capture.count(crate::remote_autoswitch_probe::Kind::TlsHandshake);
    let final_admissions = capture.count(crate::remote_autoswitch_probe::Kind::LedgerAdmission);
    let final_controls = capture.count(crate::remote_autoswitch_probe::Kind::ControlReady);
    if !baseline_transport {
        assert_eq!(final_controls, control_count, "fallback control replaced");
        assert_eq!(final_tls, tls_count, "fallback transport replaced");
        assert_eq!(
            final_admissions, admission_count,
            "fallback authority readmitted"
        );
    }
    // A legacy reconnect may repaint or close the original stream. Record that
    // failure in the baseline receipt; it is never accepted as raw byte proof.
    let byte_integrity = fallback_echo.is_ok();
    let first_output = diagnostic
        .iter()
        .filter(|event| event.kind == crate::remote_autoswitch_probe::Kind::TerminalByte)
        .min_by_key(|event| event.monotonic);
    let first_mesh_hint = diagnostic
        .iter()
        .filter(|event| {
            event.kind == crate::remote_autoswitch_probe::Kind::TerminalByte
                && event.peer.ip() != node
        })
        .min_by_key(|event| event.monotonic);
    let mut report = serde_json::json!({"kind":"real_ssh_addhost_mesh_acceptance","bootstrap_succeeded":true,"recorded_operation_failure":false,"diagnostic_profile":if diagnostic_profile {"canary-return"} else {"none"},"ordinary_latency_acceptance":!diagnostic_profile && !cfg!(debug_assertions),"transport_expectation":if baseline_transport {"baseline"} else {"preserved"},"acceptance_mode":if fenced_canary {"fenced-canary"} else {"unrestricted"},"rtt_ms":std::env::var("INFRATERNAL_TEST_RTT").unwrap(),
        "start_wall_us":wall_us(start_wall),"done_wall_us":wall_us(done_wall),"node_handshake_wall_us":wall_us(joined),
        "start_to_done_us":done.duration_since(start).as_micros(),"done_to_handshake_signed_us":i128::try_from(wall_us(joined)).unwrap()-i128::try_from(wall_us(done_wall)).unwrap(),
        "first_output_us":first_output.map(|e|e.monotonic.duration_since(start).as_micros()),
        "first_mesh_route_hint_output_us":first_mesh_hint.map(|e|e.monotonic.duration_since(start).as_micros()),
    });
    let canary_report = serde_json::json!({
        "first_fenced_canary_output_path_proven":fenced_canary,"exact_first_fenced_canary_output_measured":fenced_canary,"canary_output_boundary":"authenticated_transport_arrival_before_actor_delivery",
        "first_fenced_canary_output_wall_us":first_canary.as_ref().map(|e|wall_us(e.wall)),
        "node_handshake_to_first_fenced_canary_output_us":first_canary.as_ref().map(|e|e.wall.duration_since(joined).unwrap().as_micros()),
        "start_to_first_fenced_canary_output_us":first_canary.as_ref().map(|e|e.monotonic.duration_since(start).as_micros()),
        "fence_started_to_first_canary_output_us":first_canary.as_ref().map(|e|e.monotonic.duration_since(canary_fence.lock().unwrap().unwrap().started).as_micros()),
        "fenced_canary_includes_local_nft_overhead":fenced_canary,"unrestricted_output_path_proven":false,"route_hint_is_packet_provenance":false,"exact_first_mesh_byte_measured":false,
    });
    let session_report = serde_json::json!({
        "post_fence_fresh_marker_mesh_path_proven":true,"fence_to_complete_marker_us":witness.duration_since(fence).as_micros(),
        "marker_timing_includes_input_and_echo":true,"cut_to_fallback_status_us":fallback_status.duration_since(cut).as_micros(),
        "cut_to_complete_fallback_echo_us":fallback_echo_at.map(|at|at.duration_since(cut).as_micros()),
        "fallback_echo_error":fallback_echo.err(),"fallback_echo_boundary":"cut installed to complete terminal byte receipt","baseline_observation_only":baseline_transport,"fallback_marker_queued_before_status_wait":fallback_marker_queued,
        "same_terminal_attachment":true,"connection_preservation_required":!baseline_transport,"connection_preservation_claimed":!baseline_transport,
        "initial_tls_callbacks":tls_count,"final_tls_callbacks":final_tls,"initial_control_callbacks":control_count,"final_control_callbacks":final_controls,"initial_admission_callbacks":admission_count,"final_admission_callbacks":final_admissions,
        "tls_admission_counts_unchanged":tls_count==final_tls && admission_count==final_admissions,"control_counts_unchanged":control_count==final_controls,"terminal_opened_after_initial_mesh_join":true,"initial_ssh_shell_handoff_proven":false,"terminal_byte_integrity":byte_integrity,"fresh_real_ssh_install":true,"inventory_only_extra_peers":0});
    let standing_report = serde_json::json!({"mesh_disable_checked":mesh_disable_checked,"standing_stage_observer":stage_observer,"standing_stage_observations":standing_stages,"controlled_standing_session_switch":standing,"intentional_initial_mesh_hold":standing,"standing_release_wall_us":release_wall.map(wall_us),"standing_first_mesh_output_wall_us":standing_first.as_ref().map(|event|wall_us(event.wall)),"node_handshake_to_standing_first_mesh_output_us":standing_first.as_ref().map(|event|event.wall.duration_since(joined).unwrap().as_micros()),"standing_first_output_path_proven":standing_first.is_some(),"standing_uses_same_writer_and_attachment":standing,"terminal_opened_after_initial_mesh_join":!standing,"acceptance_mode":if standing {"standing-switch"} else if fenced_canary {"fenced-canary"} else {"unrestricted"},"ordinary_latency_acceptance":!standing && !diagnostic_profile && !cfg!(debug_assertions)});
    let natural_report = serde_json::json!({
        "natural_unheld_join_post_success_witness":natural_witness,
        "natural_witness_scope":"upper bound after normal readiness, commit, terminal setup, initial echo, counter query, local fence, and marker input/echo; no overhead subtracted",
        "natural_earliest_mesh_output_claimed":false,
        "natural_first_post_fence_output_path_proven":natural_first.is_some(),
        "natural_first_post_fence_output_boundary":"authenticated Output arrival before actor delivery on the existing Echo stream",
        "natural_first_post_fence_output_wall_us":natural_first.as_ref().map(|event|wall_us(event.wall)),
        "natural_start_to_first_post_fence_output_us":natural_first.as_ref().map(|event|event.monotonic.duration_since(start).as_micros()),
        "natural_success_to_first_post_fence_output_us":natural_first.as_ref().map(|event|event.monotonic.duration_since(done).as_micros()),
        "natural_node_handshake_to_first_post_fence_output_us":natural_first.as_ref().map(|event|event.wall.duration_since(joined).unwrap().as_micros()),
        "natural_complete_post_fence_marker_wall_us":natural_witness.then(||wall_us(witness_wall)),
        "natural_start_to_complete_post_fence_marker_us":natural_witness.then(||witness.duration_since(start).as_micros()),
        "natural_success_to_complete_post_fence_marker_us":natural_witness.then(||witness.duration_since(done).as_micros()),
        "natural_node_handshake_to_complete_post_fence_marker_us":natural_witness.then(||witness_wall.duration_since(joined).unwrap().as_micros()),
    });
    for fields in [canary_report, session_report, standing_report, natural_report] {
        report
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
    }
    if stage_observer {
        // Retain late cleanup observations too; the Done snapshot may precede
        // terminal detach. All measured byte boundaries are already captured.
        report["final_transport_observations"] = observer_snapshot(&capture);
    }
    report["release_path_cycles"] = serde_json::json!(release_path_cycles);
    report["release_path_cycle_count"] = serde_json::json!(release_cycle_count);
    report["expected_terminal_bytes"] = serde_json::json!(expected.len());
    report["verified_terminal_bytes"] = serde_json::json!(byte_integrity.then_some(expected.len()));
    report["terminal_writer_id"] = serde_json::json!(terminal_writer);
    report["standing_first_output_writer_id"] = serde_json::json!(standing_first.as_ref().map(|event|event.stream));
    std::fs::write(
        scratch.join("acceptance.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("ACCEPTANCE {}", serde_json::to_string(&report).unwrap());
    http_task.abort();
    if !baseline_transport {
        assert!(
            byte_integrity,
            "preserved transport lost fallback echo bytes"
        );
    }
}

/// Failure evidence deliberately excludes ancillary model fields and log tails.
#[test]
fn acceptance_failure_receipt_has_only_bounded_public_fields() {
    let mut failure = Failure::install("Public fixture failure.");
    failure.failed_step = Some(infraternal_plugin_ssh::model::InstallStep::Readiness);
    failure.exit_status = Some(1);
    failure.log_tail.push("Omitted fixture detail.");
    let report = public_failure(Some(&failure));
    let fields = report.as_object().unwrap();
    assert_eq!(fields.len(), 4);
    for key in ["kind", "message", "failed_step", "exit_status"] {
        assert!(fields.contains_key(key));
    }
    assert_eq!(report["kind"], "install");
    assert_eq!(report["failed_step"], "readiness");
    assert_eq!(report["exit_status"], 1);
    assert!(public_failure(None).is_null());
}
