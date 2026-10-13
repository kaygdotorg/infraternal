//! Proves in-place moves to a proposed mesh address, refusal, silent-cut return and component down over real mutually authenticated QUIC, one connection throughout [215], #201.
use super::*;
use crate::{
    remote_native::NativeChannel,
    remote_tls::tests::{leaf, root},
    transport::{Receive, Transmit},
};
use infraternal_plugin_api::{
    ActionDef, AgentPlugin, PluginDescriptor, PluginError, PluginRegistry,
};
use infraternal_plugin_remote::remote_bindings::{Bindings, LeasedBinding};
use infraternal_protocol::Frame;
use std::net::IpAddr;

/// Exercise the shipping retry owner around a fixture registry and real transport.
async fn run(
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
) -> io::Result<()> {
    super::super::supervisor::run(|connected| {
        super::run(
            identity,
            state.clone(),
            renewal,
            registry.clone(),
            connected,
        )
    })
    .await
}

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
/// One QUIC endpoint answering on its primary address and, while leased, a
/// second address: the production server's shared socket set.
struct Server {
    endpoint: quinn::Endpoint,
    bindings: std::sync::Arc<Bindings>,
    lease: Option<LeasedBinding>,
    accepted: tokio::sync::mpsc::Receiver<Accepted>,
    task: tokio::task::JoinHandle<()>,
    connection_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl Server {
    // Keep handshake, proof and connection ownership in one fixture boundary.
    #[allow(clippy::too_many_lines)]
    fn new(
        identity: &remote_tls::Identity,
        roots: &[openssl::x509::X509],
        address: SocketAddr,
    ) -> Self {
        use quinn::Runtime as _;
        let bindings = Bindings::new(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind(address).unwrap())
                .unwrap(),
        );
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(remote_quic::server_config(identity, roots).unwrap()),
            bindings.clone(),
            std::sync::Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let listen = endpoint.clone();
        let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connections = connection_count.clone();
        let (notices, accepted) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            while let Some(incoming) = listen.accept().await {
                while sessions.try_join_next().is_some() {}
                let notices = notices.clone();
                let connections = connections.clone();
                sessions.spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Ok((send, receive)) = connection.accept_bi().await else {
                        return;
                    };
                    let control =
                        std::sync::Arc::new(NativeChannel::control(send, receive).unwrap());
                    let mut rx = Receive::default();
                    let Ok(mut hello) = rx.next(control.as_ref()).await else {
                        return;
                    };
                    if let Frame::Ping { nonce, sent_us } = hello.frame {
                        Transmit::default()
                            .send(control.as_ref(), 0, &Frame::Pong { nonce, sent_us })
                            .await
                            .unwrap();
                        let Ok(next) = rx.next(control.as_ref()).await else {
                            return;
                        };
                        hello = next;
                    }
                    if !matches!(hello.frame, Frame::Hello { version: 1, .. }) {
                        return;
                    }
                    Transmit::default()
                        .send(
                            control.as_ref(),
                            0,
                            &Frame::Hello {
                                version: 1,
                                caps: remote_quic::REMOTE_WRITER_BINDING,
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
            bindings,
            lease: None,
            accepted,
            task,
            connection_count,
        }
    }
    /// Answer on `ip` at the primary port too (the server's mesh address).
    fn lease(&mut self, ip: &str) -> SocketAddr {
        use quinn::Runtime as _;
        let address = SocketAddr::new(
            ip.parse().unwrap(),
            self.endpoint.local_addr().unwrap().port(),
        );
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind(address).unwrap())
            .unwrap();
        self.lease = Some(self.bindings.lease(socket).unwrap());
        address
    }
    /// Silently stop answering on the leased address: no close, no reset.
    fn cut(&mut self) {
        self.lease = None;
    }
    fn connections(&self) -> usize {
        self.connection_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    async fn admitted_channel(&mut self) -> Accepted {
        tokio::time::timeout(Duration::from_secs(3), self.accepted.recv())
            .await
            .unwrap()
            .unwrap()
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
async fn until(
    registry: &crate::plugin_control::Registry,
    kind: ServerLinkKind,
    reason: ServerLinkReason,
) -> ServerLink {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let link = status(registry).await;
            if link.kind == kind && link.reason == reason {
                return link;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("link never reached {kind:?}/{reason:?}"))
}
fn registry() -> crate::plugin_control::Registry {
    let mut plugins = PluginRegistry::default();
    plugins.register(Box::<Fixture>::default()).unwrap();
    crate::plugin_control::Registry::new(plugins)
}
fn identity(ca: &remote_tls::Identity, endpoint: SocketAddr) -> RemoteIdentity {
    RemoteIdentity {
        identity: leaf(ca, false),
        roots: vec![ca.certificate.clone()],
        endpoint,
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    }
}
fn supervise(
    identity: RemoteIdentity,
    registry: &crate::plugin_control::Registry,
) -> (tokio::task::JoinHandle<io::Result<()>>, Directory) {
    let directory = Directory::new();
    let control = registry.clone();
    let state = directory.0.clone();
    (
        tokio::spawn(async move { run(&identity, state, None, control).await }),
        directory,
    )
}

/// The proposal moves the admitted connection itself; a silent cut returns it.
#[tokio::test]
async fn proposed_mesh_moves_the_live_connection_and_a_silent_cut_returns_it() {
    let ca = root();
    let roots = std::slice::from_ref(&ca.certificate);
    let mut server = Server::new(&leaf(&ca, true), roots, "127.0.0.1:0".parse().unwrap());
    let enrolled = server.endpoint.local_addr().unwrap();
    let mesh = server.lease("127.0.0.2");
    let registry = registry();
    let (supervisor, _directory) = supervise(identity(&ca, enrolled), &registry);
    let mut active = server.admitted_channel().await;
    preference(&registry, Some(mesh.ip())).await;
    let link = until(
        &registry,
        ServerLinkKind::Mesh,
        ServerLinkReason::MeshProven,
    )
    .await;
    assert_eq!(link.endpoint, Some(mesh));
    assert_remote_status(&mut active, ServerLinkKind::Mesh).await;
    server.cut();
    let link = until(
        &registry,
        ServerLinkKind::Fallback,
        ServerLinkReason::MeshInterrupted,
    )
    .await;
    assert_eq!(link.endpoint, Some(enrolled));
    assert_remote_status(&mut active, ServerLinkKind::Fallback).await;
    assert_eq!(server.connections(), 1, "the session never reconnected");
    assert!(server.accepted.try_recv().is_err());
    supervisor.abort();
    let _ = supervisor.await;
}

/// A recovered mesh is retried on the same connection after the cool-down.
#[tokio::test]
async fn interrupted_mesh_is_retried_on_the_same_connection() {
    let ca = root();
    let roots = std::slice::from_ref(&ca.certificate);
    let mut server = Server::new(&leaf(&ca, true), roots, "127.0.0.1:0".parse().unwrap());
    let enrolled = server.endpoint.local_addr().unwrap();
    let mesh = server.lease("127.0.0.2");
    let registry = registry();
    let (supervisor, _directory) = supervise(identity(&ca, enrolled), &registry);
    let mut active = server.admitted_channel().await;
    preference(&registry, Some(mesh.ip())).await;
    until(
        &registry,
        ServerLinkKind::Mesh,
        ServerLinkReason::MeshProven,
    )
    .await;
    server.cut();
    until(
        &registry,
        ServerLinkKind::Fallback,
        ServerLinkReason::MeshInterrupted,
    )
    .await;
    server.lease("127.0.0.2");
    until(
        &registry,
        ServerLinkKind::Mesh,
        ServerLinkReason::MeshProven,
    )
    .await;
    assert_remote_status(&mut active, ServerLinkKind::Mesh).await;
    assert_eq!(server.connections(), 1);
    supervisor.abort();
    let _ = supervisor.await;
}

/// No answer from the proposed address: the live connection stays put and works.
#[tokio::test]
async fn unanswered_mesh_address_keeps_the_live_connection() {
    let ca = root();
    let roots = std::slice::from_ref(&ca.certificate);
    let mut server = Server::new(&leaf(&ca, true), roots, "127.0.0.1:0".parse().unwrap());
    let enrolled = server.endpoint.local_addr().unwrap();
    let registry = registry();
    let (supervisor, _directory) = supervise(identity(&ca, enrolled), &registry);
    let mut active = server.admitted_channel().await;
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    let link = until(
        &registry,
        ServerLinkKind::Fallback,
        ServerLinkReason::MeshRefused,
    )
    .await;
    assert_eq!(link.endpoint, Some(enrolled));
    assert_remote_status(&mut active, ServerLinkKind::Fallback).await;
    assert_eq!(server.connections(), 1);
    assert!(!supervisor.is_finished());
    supervisor.abort();
    let _ = supervisor.await;
}

/// A different server answering on the proposed address cannot authenticate
/// this connection's packets, so the move is refused and the session stays.
#[tokio::test]
async fn untrusted_server_on_the_mesh_address_never_takes_the_connection() {
    let ca = root();
    let wrong = root();
    let roots = std::slice::from_ref(&ca.certificate);
    let mut server = Server::new(&leaf(&ca, true), roots, "127.0.0.1:0".parse().unwrap());
    let enrolled = server.endpoint.local_addr().unwrap();
    let mut impostor = Server::new(
        &leaf(&wrong, true),
        std::slice::from_ref(&wrong.certificate),
        SocketAddr::new("127.0.0.2".parse().unwrap(), enrolled.port()),
    );
    let registry = registry();
    let (supervisor, _directory) = supervise(identity(&ca, enrolled), &registry);
    let mut active = server.admitted_channel().await;
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    until(
        &registry,
        ServerLinkKind::Fallback,
        ServerLinkReason::MeshRefused,
    )
    .await;
    assert_remote_status(&mut active, ServerLinkKind::Fallback).await;
    assert!(impostor.accepted.try_recv().is_err());
    assert_eq!(impostor.connections(), 0);
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
    let registry = registry();
    preference(&registry, Some(address.ip())).await;
    let (supervisor, _directory) = supervise(
        identity(
            &ca,
            SocketAddr::new("127.0.0.1".parse().unwrap(), address.port()),
        ),
        &registry,
    );
    let _ = mesh.admitted_channel().await;
    let link = status(&registry).await;
    assert_eq!(link.kind, ServerLinkKind::Mesh);
    assert_eq!(link.endpoint, Some(address));
    supervisor.abort();
    let _ = supervisor.await;
}

#[tokio::test]
async fn component_down_returns_the_live_connection_to_the_enrolled_address() {
    component_down(false, false).await;
}

#[tokio::test]
async fn component_down_keeps_its_reason_when_the_mesh_also_stops_answering() {
    component_down(true, false).await;
}

async fn component_down(cut: bool, refuse_admission: bool) {
    let ca = root();
    let roots = std::slice::from_ref(&ca.certificate);
    let mut server = Server::new(&leaf(&ca, true), roots, "127.0.0.1:0".parse().unwrap());
    let enrolled = server.endpoint.local_addr().unwrap();
    let mesh = server.lease("127.0.0.2");
    let registry = registry();
    let (supervisor, _directory) = supervise(identity(&ca, enrolled), &registry);
    let mut active = server.admitted_channel().await;
    preference(&registry, Some(mesh.ip())).await;
    until(
        &registry,
        ServerLinkKind::Mesh,
        ServerLinkReason::MeshProven,
    )
    .await;
    if refuse_admission {
        // The already admitted connection must survive refusal of every new handshake.
        server.endpoint.set_server_config(None);
    }
    preference(&registry, None).await;
    if cut {
        server.cut();
    }
    let link = until(
        &registry,
        ServerLinkKind::Fallback,
        ServerLinkReason::MeshDisabled,
    )
    .await;
    assert_eq!(link.endpoint, Some(enrolled));
    assert_remote_status(&mut active, ServerLinkKind::Fallback).await;
    assert_eq!(server.connections(), 1);
    supervisor.abort();
    let _ = supervisor.await;
}

/// Acknowledged probes keep a healthy mesh path; it is never declared lost.
#[tokio::test]
async fn healthy_mesh_path_is_never_declared_interrupted() {
    let ca = root();
    let roots = std::slice::from_ref(&ca.certificate);
    let mut server = Server::new(&leaf(&ca, true), roots, "127.0.0.1:0".parse().unwrap());
    let enrolled = server.endpoint.local_addr().unwrap();
    let mesh = server.lease("127.0.0.2");
    let registry = registry();
    let (supervisor, _directory) = supervise(identity(&ca, enrolled), &registry);
    let _active = server.admitted_channel().await;
    preference(&registry, Some(mesh.ip())).await;
    until(
        &registry,
        ServerLinkKind::Mesh,
        ServerLinkReason::MeshProven,
    )
    .await;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let link = status(&registry).await;
        assert_eq!(
            (link.kind, link.reason),
            (ServerLinkKind::Mesh, ServerLinkReason::MeshProven)
        );
    }
    supervisor.abort();
    let _ = supervisor.await;
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
    let registry = registry();
    let (supervisor, _directory) = supervise(identity(&ca, address), &registry);
    tokio::time::timeout(Duration::from_secs(3), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    preference(&registry, Some("127.0.0.2".parse().unwrap())).await;
    let _ = mesh.admitted_channel().await;
    preference(&registry, None).await;
    tokio::time::timeout(Duration::from_secs(5), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    let link = until(
        &registry,
        ServerLinkKind::Fallback,
        ServerLinkReason::MeshDisabled,
    )
    .await;
    assert_eq!(link.endpoint, Some(address));
    supervisor.abort();
    let _ = supervisor.await;
    tcp.abort();
    let _ = tcp.await;
}

/// The mesh address stops answering without a close or an interface change,
/// the silent case seen on a network change. Timing belongs to the perf VM.
#[tokio::test]
#[ignore = "Run alone on the perf VM under the shared benchmark lock."]
async fn review_silent_mesh_interruption_returns_to_fallback_within_local_reconnect_budget() {
    let ca = root();
    let roots = std::slice::from_ref(&ca.certificate);
    let mut server = Server::new(&leaf(&ca, true), roots, "127.0.0.1:0".parse().unwrap());
    let enrolled = server.endpoint.local_addr().unwrap();
    let mesh = server.lease("127.0.0.2");
    let registry = registry();
    let (supervisor, _directory) = supervise(identity(&ca, enrolled), &registry);
    let _active = server.admitted_channel().await;
    preference(&registry, Some(mesh.ip())).await;
    until(
        &registry,
        ServerLinkKind::Mesh,
        ServerLinkReason::MeshProven,
    )
    .await;
    // Healthy probes first, so detection starts from an established path.
    tokio::time::sleep(Duration::from_millis(350)).await;
    server.cut();
    let started = tokio::time::Instant::now();
    until(
        &registry,
        ServerLinkKind::Fallback,
        ServerLinkReason::MeshInterrupted,
    )
    .await;
    let elapsed = started.elapsed();
    supervisor.abort();
    let _ = supervisor.await;
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
    let status = tokio::time::timeout(Duration::from_secs(3), async {
        // Each daemon publishes its initial census before action replies.
        // Validate that additive event, then retain exact correlation.
        loop {
            let reply = active.receive.next(active.control.as_ref()).await.unwrap();
            assert_eq!(reply.stream_id, 0);
            match reply.frame {
                Frame::Event {
                    sub_id: 0,
                    event_json,
                } => {
                    let event: serde_json::Value = serde_json::from_slice(event_json).unwrap();
                    assert_eq!(
                        event,
                        serde_json::json!({"type": "terminal.sessions.snapshot", "session_ids": []})
                    );
                }
                Frame::Result {
                    call_id: 77,
                    ok: true,
                    json,
                } => {
                    return serde_json::from_slice::<ServerLink>(json).unwrap();
                }
                other => panic!("control action failed: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(status.kind, expected);
}

/// An admitted fallback remains usable when new handshakes are refused.
#[tokio::test]
async fn component_down_activates_the_warm_fallback_without_a_new_connection() {
    component_down(false, true).await;
}

/// Credential validity can change during an outage; it must not retire the dialer.
#[tokio::test]
async fn unavailable_credentials_do_not_end_server_link() {
    use openssl::{asn1::Asn1Time, hash::MessageDigest, x509::X509};
    let ca = root();
    let mut credentials = leaf(&ca, false);
    let mut expired = X509::builder().unwrap();
    expired.set_version(2).unwrap();
    expired
        .set_subject_name(credentials.certificate.subject_name())
        .unwrap();
    expired
        .set_issuer_name(ca.certificate.subject_name())
        .unwrap();
    expired.set_pubkey(&credentials.key).unwrap();
    expired
        .set_not_before(&Asn1Time::from_unix(1).unwrap())
        .unwrap();
    expired
        .set_not_after(&Asn1Time::from_unix(2).unwrap())
        .unwrap();
    expired.sign(&ca.key, MessageDigest::null()).unwrap();
    credentials.certificate = expired.build();
    let identity = RemoteIdentity {
        identity: credentials,
        roots: vec![ca.certificate],
        endpoint: "127.0.0.1:1".parse().unwrap(),
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(250),
            run(&identity, directory.0.clone(), None, registry()),
        )
        .await
        .is_err(),
        "a recoverable credential error ended the server link"
    );
}

/// A live transport cannot repair a worker whose one-shot factory has failed.
#[tokio::test]
async fn failed_control_worker_returns_to_retry_owner() {
    let ca = root();
    let identity = RemoteIdentity {
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: "127.0.0.1:1".parse().unwrap(),
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        super::run(
            &identity,
            directory.0.clone(),
            None,
            crate::plugin_control::Registry::unavailable(),
            tokio::sync::watch::channel(false).0,
        ),
    )
    .await
    .expect("failed worker must return to the owner that recreates its service");
    assert!(result.is_err());
}
