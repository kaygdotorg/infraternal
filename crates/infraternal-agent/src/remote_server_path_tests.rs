//! Proves destination preference, rejected candidates and automatic fallback over real mutually authenticated QUIC [215].
use super::*;
use crate::{
    remote_native::NativeChannel,
    remote_tls::tests::{leaf, root},
    transport::{Receive, Transmit},
};
use infraternal_plugin_api::{
    ActionDef, AgentPlugin, PluginDescriptor, PluginError, PluginRegistry,
};
use infraternal_protocol::Frame;
use std::net::IpAddr;

const ACTION: ActionDef = ActionDef {
    id: "path.configure",
    summary: "Set fixture destination",
    input: infraternal_plugin_api::SchemaRef("FixtureAddress"),
    output: infraternal_plugin_api::SchemaRef("Empty"),
    effect: infraternal_plugin_api::Effect::Write,
    instructions: &["Set the fixture destination."],
    permission: infraternal_plugin_api::Permission::One("fixture"),
    target: infraternal_plugin_api::Target::Node,
    dry_run: infraternal_plugin_api::DryRun::Unsupported,
    opens: None,
};
const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "path",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[
        ACTION,
        ActionDef {
            id: "path.status",
            summary: "Read fixture link",
            effect: infraternal_plugin_api::Effect::Read,
            ..ACTION
        },
    ],
    topics: &[],
    settings: None,
    events: &[],
    streams: &[],
    defaults: &[],
    dependencies: &[],
    can_enable_components: &[],
    roles: &[infraternal_plugin_api::RoleDef {
        id: "node",
        requires: &[],
        default_enabled: true,
    }],
    max_frame_len: infraternal_plugin_api::MAX_ACTION_BYTES,
    unavailable: b"{}",
    unavailable_event: b"{}",
};
#[derive(Default)]
struct Fixture {
    destination: Option<IpAddr>,
    link: ServerLink,
}
impl AgentPlugin for Fixture {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn preferred_server(&self) -> Option<IpAddr> {
        self.destination
    }
    fn set_server_link(&mut self, link: &ServerLink) {
        self.link = link.clone();
    }
    fn call(&mut self, action: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        if action == "path.configure" {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request {
                address: Option<IpAddr>,
            }
            self.destination = serde_json::from_slice::<Request>(input)
                .map_err(|_| PluginError::Rejected)?
                .address;
            Ok(b"{}".to_vec())
        } else {
            serde_json::to_vec(&self.link).map_err(|_| PluginError::Rejected)
        }
    }
}

struct Accepted {
    control: std::sync::Arc<NativeChannel>,
    receive: Receive,
}
struct Server {
    endpoint: quinn::Endpoint,
    accepted: tokio::sync::mpsc::Receiver<Accepted>,
    parked: tokio::sync::mpsc::Receiver<()>,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    fn new(
        identity: &remote_tls::Identity,
        roots: &[openssl::x509::X509],
        address: SocketAddr,
    ) -> Self {
        Self::with_proof(identity, roots, address, true)
    }
    fn with_proof(
        identity: &remote_tls::Identity,
        roots: &[openssl::x509::X509],
        address: SocketAddr,
        valid: bool,
    ) -> Self {
        Self::with_options(identity, roots, address, valid, false)
    }
    // Keep handshake, parking and connection ownership in one fixture boundary.
    #[allow(clippy::too_many_lines)]
    fn with_options(
        identity: &remote_tls::Identity,
        roots: &[openssl::x509::X509],
        address: SocketAddr,
        valid: bool,
        standby: bool,
    ) -> Self {
        let endpoint = quinn::Endpoint::server(
            remote_quic::server_config(identity, roots).unwrap(),
            address,
        )
        .unwrap();
        let listen = endpoint.clone();
        let (notices, accepted) = tokio::sync::mpsc::channel(8);
        let (parking, parked) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            while let Some(incoming) = listen.accept().await {
                while sessions.try_join_next().is_some() {}
                let notices = notices.clone();
                let parking = parking.clone();
                sessions.spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let Ok((send, receive)) = connection.accept_bi().await else {
                        return;
                    };
                    let control =
                        std::sync::Arc::new(NativeChannel::control(send, receive).unwrap());
                    let mut rx = Receive::default();
                    let Ok(first) = rx.next(control.as_ref()).await else {
                        return;
                    };
                    if let Frame::Ping { nonce, sent_us } = first.frame {
                        Transmit::default()
                            .send(
                                control.as_ref(),
                                0,
                                &Frame::Pong {
                                    nonce: if valid { nonce } else { nonce.wrapping_add(1) },
                                    sent_us,
                                },
                            )
                            .await
                            .unwrap();
                        let Ok(hello) = rx.next(control.as_ref()).await else {
                            return;
                        };
                        if standby
                            && matches!(
                                hello.frame,
                                Frame::Call {
                                    call_id: 0,
                                    action_id: "transport.standby",
                                    input_json: b"{}"
                                }
                            )
                        {
                            let mut transmit = Transmit::default();
                            transmit
                                .send(
                                    control.as_ref(),
                                    0,
                                    &Frame::Result {
                                        call_id: 0,
                                        ok: true,
                                        json: b"{}",
                                    },
                                )
                                .await
                                .unwrap();
                            transmit
                                .send(
                                    control.as_ref(),
                                    0,
                                    &Frame::Hello {
                                        version: 1,
                                        caps: remote_quic::REMOTE_WRITER_BINDING
                                            | infraternal_plugin_api::channel::REMOTE_STANDBY,
                                        client_info: "fixture",
                                    },
                                )
                                .await
                                .unwrap();
                            parking.send(()).await.unwrap();
                            let Ok(hello) = rx.next(control.as_ref()).await else {
                                return;
                            };
                            if !matches!(hello.frame, Frame::Hello { version: 1, .. }) {
                                return;
                            }
                            notices
                                .send(Accepted {
                                    control: control.clone(),
                                    receive: rx,
                                })
                                .await
                                .unwrap();
                            let _ = connection.closed().await;
                            return;
                        }
                        if !matches!(hello.frame, Frame::Hello { version: 1, .. }) {
                            return;
                        }
                    } else if !matches!(first.frame, Frame::Hello { version: 1, .. }) {
                        return;
                    }
                    Transmit::default()
                        .send(
                            control.as_ref(),
                            0,
                            &Frame::Hello {
                                version: 1,
                                caps: remote_quic::REMOTE_WRITER_BINDING
                                    | if standby {
                                        infraternal_plugin_api::channel::REMOTE_STANDBY
                                    } else {
                                        0
                                    },
                                client_info: "fixture",
                            },
                        )
                        .await
                        .unwrap();
                    notices
                        .send(Accepted {
                            control: control.clone(),
                            receive: rx,
                        })
                        .await
                        .unwrap();
                    let _ = connection.closed().await;
                });
            }
        });
        Self {
            endpoint,
            accepted,
            parked,
            task,
        }
    }
    async fn admitted(&mut self) {
        let _ = self.admitted_channel().await;
    }
    async fn admitted_channel(&mut self) -> Accepted {
        tokio::time::timeout(Duration::from_secs(3), self.accepted.recv())
            .await
            .unwrap()
            .unwrap()
    }
    async fn parked(&mut self) {
        tokio::time::timeout(Duration::from_secs(3), self.parked.recv())
            .await
            .unwrap()
            .unwrap();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
        self.task.abort();
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let parent = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/mesh-agent-transport-round2");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join(format!(
            "p{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        Self(crate::sessions::state(Some(path)).unwrap())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
async fn preference(registry: &crate::plugin_control::Registry, address: Option<IpAddr>) {
    registry
        .call(
            "path.configure".into(),
            serde_json::to_vec(&serde_json::json!({"address":address})).unwrap(),
        )
        .await
        .unwrap();
}
async fn status(registry: &crate::plugin_control::Registry) -> ServerLink {
    serde_json::from_slice(
        &registry
            .call("path.status".into(), b"{}".to_vec())
            .await
            .unwrap(),
    )
    .unwrap()
}
fn registry() -> crate::plugin_control::Registry {
    let mut plugins = PluginRegistry::default();
    plugins.register(Box::<Fixture>::default()).unwrap();
    crate::plugin_control::Registry::new(plugins)
}

#[tokio::test]
async fn proven_mesh_destination_is_preferred_and_failure_returns_to_enrolled_port() {
    let ca = root();
    let server = leaf(&ca, true);
    let mut fallback = Server::new(
        &server,
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let address = fallback.endpoint.local_addr().unwrap();
    let mut mesh = Server::new(
        &server,
        std::slice::from_ref(&ca.certificate),
        SocketAddr::new("127.0.0.2".parse().unwrap(), address.port()),
    );
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: address,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    let registry = registry();
    let control = registry.clone();
    let state = directory.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, state, None, control).await });
    fallback.admitted().await;
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    mesh.admitted().await;
    assert_eq!(status(&registry).await.kind, ServerLinkKind::Mesh);
    mesh.endpoint.close(0u32.into(), b"");
    fallback.admitted().await;
    let link = status(&registry).await;
    assert_eq!(link.kind, ServerLinkKind::Fallback);
    assert_eq!(link.reason, ServerLinkReason::MeshInterrupted);
    assert_eq!(link.endpoint, Some(address));
    supervisor.abort();
    let _ = supervisor.await;
}

#[tokio::test]
async fn untrusted_candidate_never_retires_the_authenticated_fallback() {
    let ca = root();
    let wrong = root();
    let mut fallback = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let address = fallback.endpoint.local_addr().unwrap();
    let _invalid = Server::new(
        &leaf(&wrong, true),
        std::slice::from_ref(&wrong.certificate),
        SocketAddr::new("127.0.0.2".parse().unwrap(), address.port()),
    );
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: address,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    let registry = registry();
    let control = registry.clone();
    let state = directory.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, state, None, control).await });
    fallback.admitted().await;
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while status(&registry).await.reason != ServerLinkReason::MeshRefused {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(status(&registry).await.kind, ServerLinkKind::Fallback);
    assert!(fallback.accepted.try_recv().is_err());
    assert!(!supervisor.is_finished());
    supervisor.abort();
    let _ = supervisor.await;
}

#[tokio::test]
async fn retained_mesh_proposal_connects_when_the_fallback_port_is_unavailable() {
    let ca = root();
    let mut mesh = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.2:0".parse().unwrap(),
    );
    let address = mesh.endpoint.local_addr().unwrap();
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: SocketAddr::new("127.0.0.1".parse().unwrap(), address.port()),
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let registry = registry();
    preference(&registry, Some(address.ip())).await;
    let directory = Directory::new();
    let control = registry.clone();
    let state = directory.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, state, None, control).await });
    mesh.admitted().await;
    let link = status(&registry).await;
    assert_eq!(link.kind, ServerLinkKind::Mesh);
    assert_eq!(link.endpoint, Some(address));
    supervisor.abort();
    let _ = supervisor.await;
}

#[tokio::test]
async fn invalid_application_proof_keeps_the_live_fallback() {
    let ca = root();
    let server = leaf(&ca, true);
    let mut fallback = Server::new(
        &server,
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let address = fallback.endpoint.local_addr().unwrap();
    let mut invalid = Server::with_proof(
        &server,
        std::slice::from_ref(&ca.certificate),
        SocketAddr::new("127.0.0.2".parse().unwrap(), address.port()),
        false,
    );
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: address,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    let registry = registry();
    let control = registry.clone();
    let state = directory.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, state, None, control).await });
    fallback.admitted().await;
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while status(&registry).await.reason != ServerLinkReason::MeshRefused {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(status(&registry).await.kind, ServerLinkKind::Fallback);
    assert!(fallback.accepted.try_recv().is_err());
    assert!(invalid.accepted.try_recv().is_err());
    assert!(!supervisor.is_finished());
    supervisor.abort();
    let _ = supervisor.await;
}

#[tokio::test]
async fn component_down_replaces_mesh_with_a_proven_fallback() {
    component_down(false).await;
}

#[tokio::test]
async fn component_down_keeps_its_reason_when_mesh_closes_during_replacement() {
    component_down(true).await;
}

async fn component_down(close_mesh: bool) {
    let ca = root();
    let server = leaf(&ca, true);
    let mut fallback = Server::new(
        &server,
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let address = fallback.endpoint.local_addr().unwrap();
    let mut mesh = Server::new(
        &server,
        std::slice::from_ref(&ca.certificate),
        SocketAddr::new("127.0.0.2".parse().unwrap(), address.port()),
    );
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: address,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    let registry = registry();
    let control = registry.clone();
    let state = directory.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, state, None, control).await });
    fallback.admitted().await;
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    mesh.admitted().await;
    preference(&registry, None).await;
    if close_mesh {
        mesh.endpoint.close(0u32.into(), b"");
    }
    fallback.admitted().await;
    let link = status(&registry).await;
    assert_eq!(link.kind, ServerLinkKind::Fallback);
    assert_eq!(link.reason, ServerLinkReason::MeshDisabled);
    supervisor.abort();
    let _ = supervisor.await;
}

#[tokio::test]
async fn healthy_mesh_probes_do_not_inherit_the_previous_paths_rtt() {
    let ca = root();
    let server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let address = server.endpoint.local_addr().unwrap();
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: address,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let link = connect(&identity, None, address, ServerLinkKind::Mesh, true)
        .await
        .unwrap();
    let Connected::Quic(connection) = &link.connected else {
        panic!("mesh proof did not establish native QUIC");
    };
    let mut freshness = remote_quic::PeerFreshness::new(connection);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(700),
            freshness.interrupted_adaptive(connection)
        )
        .await
        .is_err(),
        "a healthy new mesh path expired before its inherited keepalive could run"
    );
}

#[tokio::test]
async fn component_down_proves_tcp_fallback_when_enrolled_udp_is_unavailable() {
    let ca = root();
    let server = leaf(&ca, true);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor =
        remote_tls::server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap();
    let (notices, mut accepted) = tokio::sync::mpsc::channel(8);
    let tcp = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let notices = notices.clone();
            sessions.spawn(async move {
                let connection = remote_tls::accept(socket, &acceptor).await.unwrap();
                let mut receive = Receive::default();
                let first = receive.next(&connection.channel).await.unwrap();
                if let Frame::Ping { nonce, sent_us } = first.frame {
                    Transmit::default()
                        .send(&connection.channel, 0, &Frame::Pong { nonce, sent_us })
                        .await
                        .unwrap();
                    assert!(matches!(
                        receive.next(&connection.channel).await.unwrap().frame,
                        Frame::Hello { .. }
                    ));
                } else {
                    assert!(matches!(first.frame, Frame::Hello { .. }));
                }
                Transmit::default()
                    .send(
                        &connection.channel,
                        0,
                        &Frame::Hello {
                            version: 1,
                            caps: 0,
                            client_info: "fixture",
                        },
                    )
                    .await
                    .unwrap();
                notices.send(()).await.unwrap();
                let _ = receive.next(&connection.channel).await;
            });
            while sessions.try_join_next().is_some() {}
        }
    });
    let mut mesh = Server::new(
        &server,
        std::slice::from_ref(&ca.certificate),
        SocketAddr::new("127.0.0.2".parse().unwrap(), address.port()),
    );
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: address,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    let registry = registry();
    let control = registry.clone();
    let state = directory.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, state, None, control).await });
    tokio::time::timeout(Duration::from_secs(3), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    mesh.admitted().await;
    preference(&registry, None).await;
    tokio::time::timeout(Duration::from_secs(3), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    let link = status(&registry).await;
    assert_eq!(link.kind, ServerLinkKind::Fallback);
    assert_eq!(link.reason, ServerLinkReason::MeshDisabled);
    assert_eq!(link.endpoint, Some(address));
    supervisor.abort();
    let _ = supervisor.await;
    tcp.abort();
    let _ = tcp.await;
}

/// The live path is interrupted by discarding UDP, without sending a close or
/// removing the interface. This measures the silent-failure case seen on a
/// network change; the enrolled fallback remains reachable throughout.
#[tokio::test]
#[ignore = "Run alone in the local CPUWeight scope for silent-path recovery measurements."]
async fn review_silent_mesh_interruption_returns_to_fallback_within_local_reconnect_budget() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let ca = root();
    let server = leaf(&ca, true);
    let mut fallback = Server::new(
        &server,
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let address = fallback.endpoint.local_addr().unwrap();
    let mut mesh = Server::new(
        &server,
        std::slice::from_ref(&ca.certificate),
        "127.0.0.3:0".parse().unwrap(),
    );
    let upstream = mesh.endpoint.local_addr().unwrap();
    let socket = tokio::net::UdpSocket::bind(SocketAddr::new(
        "127.0.0.2".parse().unwrap(),
        address.port(),
    ))
    .await
    .unwrap();
    let cut = Arc::new(AtomicBool::new(false));
    let refused = cut.clone();
    let relay = tokio::spawn(async move {
        let mut client = None;
        let mut packet = vec![0; 65536];
        loop {
            let (count, source) = socket.recv_from(&mut packet).await.unwrap();
            if refused.load(Ordering::Acquire) {
                continue;
            }
            let destination = if source == upstream {
                let Some(client) = client else {
                    continue;
                };
                client
            } else {
                client = Some(source);
                upstream
            };
            socket.send_to(&packet[..count], destination).await.unwrap();
        }
    });
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: address,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let parent = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join(format!("review-path-{}", uuid::Uuid::new_v4().simple()));
    let directory = Directory(crate::sessions::state(Some(parent)).unwrap());
    let registry = registry();
    let control = registry.clone();
    let state = directory.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, state, None, control).await });
    fallback.admitted().await;
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    mesh.admitted().await;
    assert_eq!(status(&registry).await.kind, ServerLinkKind::Mesh);
    // Allow healthy keepalives before the cut so failure detection begins from
    // an established path rather than from negotiation or initial scheduling.
    tokio::time::sleep(Duration::from_millis(350)).await;
    cut.store(true, Ordering::Release);
    let started = tokio::time::Instant::now();
    let recovered = tokio::time::timeout(Duration::from_secs(6), fallback.accepted.recv()).await;
    let elapsed = started.elapsed();
    let observed = status(&registry).await;
    supervisor.abort();
    let _ = supervisor.await;
    relay.abort();
    let _ = relay.await;
    assert!(
        matches!(recovered, Ok(Some(_))),
        "reachable fallback must recover"
    );
    assert_eq!(observed.kind, ServerLinkKind::Fallback);
    // Local authenticated handshake RTT is negligible. D41 also supplies the
    // less strict 300 ms reconnect reference at zero network overhead.
    println!(
        "METRIC review_silent_mesh_cut fallback_us={} budget_us=300000 load={}",
        elapsed.as_micros(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    assert!(
        elapsed < Duration::from_millis(300),
        "silent mesh interruption exceeded the local reconnect budget: {elapsed:?}"
    );
}

/// The server-side transport stays usable through parked activation and a new
/// mesh proof; the cached greeting must not leak into the next control exchange.
#[tokio::test]
async fn parked_fallback_recovers_mesh_and_keeps_control_actions_usable() {
    let ca = root();
    let server = leaf(&ca, true);
    let roots = std::slice::from_ref(&ca.certificate);
    let mut fallback =
        Server::with_options(&server, roots, "127.0.0.1:0".parse().unwrap(), true, true);
    let address = fallback.endpoint.local_addr().unwrap();
    let mesh_address = SocketAddr::new("127.0.0.2".parse().unwrap(), address.port());
    let mut mesh = Server::with_options(&server, roots, mesh_address, true, true);
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate.clone()],
        endpoint: address,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    let registry = registry();
    let control = registry.clone();
    let state = directory.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, state, None, control).await });
    fallback.admitted().await;
    preference(&registry, Some(mesh_address.ip())).await;
    mesh.admitted().await;
    fallback.parked().await;
    drop(mesh);
    let mut active = fallback.admitted_channel().await;
    assert_remote_status(&mut active, ServerLinkKind::Fallback).await;
    // Quinn's owned driver releases the old fixture socket asynchronously.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match tokio::net::UdpSocket::bind(mesh_address).await {
                Ok(socket) => {
                    drop(socket);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => panic!("fixture address refused: {error}"),
            }
        }
    })
    .await
    .unwrap();
    let mut restored = Server::with_options(&server, roots, mesh_address, true, true);
    let mut active = restored.admitted_channel().await;
    assert_remote_status(&mut active, ServerLinkKind::Mesh).await;
    fallback.parked().await;
    assert_remote_status(&mut active, ServerLinkKind::Mesh).await;
    assert!(!supervisor.is_finished());
    supervisor.abort();
    let _ = supervisor.await;
}

async fn assert_remote_status(active: &mut Accepted, expected: ServerLinkKind) {
    Transmit::default()
        .send(
            active.control.as_ref(),
            0,
            &Frame::Call {
                call_id: 77,
                action_id: "path.status",
                input_json: b"{}",
            },
        )
        .await
        .unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(3),
        active.receive.next(active.control.as_ref()),
    )
    .await
    .unwrap()
    .unwrap();
    let Frame::Result {
        call_id: 77,
        ok: true,
        json,
    } = reply.frame
    else {
        panic!("control action failed");
    };
    let status: ServerLink = serde_json::from_slice(json).unwrap();
    assert_eq!(status.kind, expected);
}
