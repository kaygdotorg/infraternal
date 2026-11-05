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

/// Only TLS alert codes count as an identity refusal; other QUIC failures do not trigger the fallback.
#[test]
fn identity_admission_refusal_only_matches_tls_crypto_errors() {
    let closed_with = |error_code| {
        io::Error::other(quinn::ConnectionError::ConnectionClosed(
            quinn::ConnectionClose {
                error_code,
                frame_type: None,
                reason: String::new().into(),
            },
        ))
    };
    let crypto_close = quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
        error_code: quinn::TransportErrorCode::crypto(0x33),
        frame_type: None,
        reason: String::new().into(),
    });
    assert!(identity_admission_refused(&io::Error::other(
        quinn::ReadError::ConnectionLost(crypto_close.clone())
    )));
    assert!(identity_admission_refused(&io::Error::other(
        quinn::WriteError::ConnectionLost(crypto_close)
    )));
    assert!(!identity_admission_refused(&closed_with(
        quinn::TransportErrorCode::PROTOCOL_VIOLATION
    )));
    assert!(!identity_admission_refused(&io::ErrorKind::TimedOut.into()));
    assert!(identity_admission_refused(&io::Error::new(
        io::ErrorKind::PermissionDenied,
        "identity refused",
    )));
}

/// Exercise the shipping retry owner around a fixture registry and real transport.
async fn run(
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
) -> io::Result<()> {
    Box::pin(super::super::supervisor::run(|connected| {
        super::run(
            identity,
            state.clone(),
            renewal,
            registry.clone(),
            connected,
        )
    }))
    .await
}

// Manual-control fixtures use this module's current authenticated server. Their
// pending session future does not consume Hello, so publish its known support
// explicitly; the no-opt-in regression withdraws it to model an older peer.
async fn connect(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    address: SocketAddr,
    kind: ServerLinkKind,
    prove: bool,
) -> io::Result<Link> {
    let link = super::connect(identity, renewal, address, kind, prove).await?;
    link.negotiated(infraternal_plugin_api::channel::REMOTE_PATH_PROOF);
    Ok(link)
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
    api_scope: None,
    fresh_passkey: false,
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

/// A functional packet-loss fixture: the endpoint still owns its socket and
/// connection while selected outgoing datagrams disappear below QUIC.
#[derive(Debug)]
struct DroppedReplies {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    dropping: Arc<std::sync::atomic::AtomicBool>,
    marker: Arc<tokio::sync::Notify>,
}
/// Public, deliberately invalid QUIC input witnesses physical copying only.
const BACKUP_MARKER: &[u8] = b"infraternal-test-enrolled-backup";
impl quinn::AsyncUdpSocket for DroppedReplies {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if self.dropping.load(std::sync::atomic::Ordering::Acquire) {
            Ok(())
        } else {
            self.inner.try_send(transmit)
        }
    }
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<io::Result<usize>> {
        let result = self.inner.poll_recv(cx, bufs, meta);
        if let std::task::Poll::Ready(Ok(count)) = &result {
            for (buffer, received) in bufs.iter().zip(meta.iter()).take(*count) {
                if buffer[..received.len] == *BACKUP_MARKER {
                    self.marker.notify_one();
                }
            }
        }
        result
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
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
    dropping: Arc<std::sync::atomic::AtomicBool>,
    marker: Arc<tokio::sync::Notify>,
    reserved: Option<std::net::UdpSocket>,
}

/// Reserve both address tuples before publishing either port to another task.
fn udp_pair(ip: std::net::IpAddr) -> (std::net::UdpSocket, std::net::UdpSocket) {
    let other = if ip == "127.0.0.1".parse::<std::net::IpAddr>().unwrap() {
        "127.0.0.2"
    } else {
        "127.0.0.1"
    };
    for _ in 0..64 {
        let primary = std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        if let Ok(alternate) = std::net::UdpSocket::bind(SocketAddr::new(
            other.parse().unwrap(),
            primary.local_addr().unwrap().port(),
        )) {
            return (primary, alternate);
        }
    }
    panic!("could not jointly reserve the fixture UDP paths");
}

/// TCP port allocation does not reserve UDP, so keep all three descriptors.
fn tcp_mesh_pair() -> (
    tokio::net::TcpListener,
    std::net::UdpSocket,
    std::net::UdpSocket,
) {
    for _ in 0..64 {
        let (mesh, enrolled) = udp_pair("127.0.0.2".parse().unwrap());
        if let Ok(tcp) = std::net::TcpListener::bind(enrolled.local_addr().unwrap()) {
            tcp.set_nonblocking(true).unwrap();
            return (
                tokio::net::TcpListener::from_std(tcp).unwrap(),
                mesh,
                enrolled,
            );
        }
    }
    panic!("could not jointly reserve TCP and both UDP paths");
}

impl Server {
    fn new(
        identity: &remote_tls::Identity,
        roots: &[openssl::x509::X509],
        address: SocketAddr,
    ) -> Self {
        assert_eq!(
            address.port(),
            0,
            "fixed ports must transfer their reserved descriptor"
        );
        let (socket, reserved) = udp_pair(address.ip());
        Self::from_socket(identity, roots, socket, Some(reserved))
    }
    // Keep handshake, proof and connection ownership in one fixture boundary.
    #[allow(clippy::too_many_lines)]
    fn from_socket(
        identity: &remote_tls::Identity,
        roots: &[openssl::x509::X509],
        socket: std::net::UdpSocket,
        reserved: Option<std::net::UdpSocket>,
    ) -> Self {
        use quinn::Runtime as _;
        let dropping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = Arc::new(tokio::sync::Notify::new());
        let bindings = Bindings::new(Arc::new(DroppedReplies {
            inner: quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(),
            dropping: dropping.clone(),
            marker: marker.clone(),
        }));
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
        let responder = bindings.clone();
        let task = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            while let Some(incoming) = listen.accept().await {
                while sessions.try_join_next().is_some() {}
                let notices = notices.clone();
                let connections = connections.clone();
                let responder = responder.clone();
                sessions.spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let _proof = responder.connection_proof(&connection).unwrap();
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
                                caps: remote_quic::REMOTE_WRITER_BINDING
                                    | infraternal_plugin_api::channel::REMOTE_PATH_PROOF,
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
            dropping,
            marker,
            reserved,
        }
    }
    /// Answer on `ip` at the primary port too (the server's mesh address).
    fn lease(&mut self, ip: &str) -> SocketAddr {
        use quinn::Runtime as _;
        let address = SocketAddr::new(
            ip.parse().unwrap(),
            self.endpoint.local_addr().unwrap().port(),
        );
        let reserved = self
            .reserved
            .as_ref()
            .expect("fixture lacks a reserved mesh path");
        assert_eq!(reserved.local_addr().unwrap(), address);
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(reserved.try_clone().unwrap())
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
        let parent = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
            || {
                PathBuf::from(std::env::var_os("HOME").unwrap())
                    .join(".cache/codex-scratch/mesh-agent-transport-round2")
            },
            PathBuf::from,
        );
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
        host_id: uuid::Uuid::new_v4(),
        identity: leaf(ca, false),
        roots: vec![ca.certificate.clone()],
        endpoint: Some(endpoint),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    }
}

/// A host identity signed by the test CA for `host`.
fn host_identity(
    ca: &remote_tls::Identity,
    host: uuid::Uuid,
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    serial: u32,
) -> remote_tls::Identity {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        },
    };

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "test host").unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name.build()).unwrap();
    builder
        .set_issuer_name(ca.certificate.subject_name())
        .unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(7).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder
        .append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
        .unwrap();
    let san = {
        let context = builder.x509v3_context(Some(&ca.certificate), None);
        SubjectAlternativeName::new()
            .uri(&format!("urn:infraternal:host:{host}"))
            .build(&context)
            .unwrap()
    };
    builder.append_extension(san).unwrap();
    builder.sign(&ca.key, MessageDigest::null()).unwrap();
    remote_tls::Identity {
        certificate: builder.build(),
        key,
    }
}

/// An in-memory rotation store that starts with one pending rotation.
struct PendingRotationPublisher(
    std::sync::Mutex<Option<infraternal_plugin_remote::identity_rotation::RotationStorage>>,
);
impl infraternal_plugin_remote::identity_rotation::RotationPublisher for PendingRotationPublisher {
    fn load(&self) -> io::Result<infraternal_plugin_remote::identity_rotation::RotationStorage> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("fixture lock poisoned"))?
            .take()
            .ok_or_else(|| io::Error::other("fixture state already loaded"))
    }
    fn store_candidate(
        &self,
        _: &infraternal_plugin_remote::identity_rotation::Challenge,
        _: &[u8],
    ) -> io::Result<()> {
        Ok(())
    }
    fn store_certificate(&self, _: uuid::Uuid, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn promote(
        &self,
        _: &infraternal_plugin_remote::identity_rotation::CompletedRotation,
    ) -> io::Result<()> {
        Ok(())
    }
}

/// A certificate publisher that accepts every renewal without storing it.
struct TestCertificatePublisher;
impl crate::remote_renewal::CertificatePublisher for TestCertificatePublisher {
    fn publish(&self, _: &openssl::x509::X509) -> io::Result<()> {
        Ok(())
    }
}

/// SHA-256 over a certificate's DER encoding.
fn certificate_fingerprint(certificate: &openssl::x509::X509) -> [u8; 32] {
    use openssl::hash::MessageDigest;
    certificate
        .digest(MessageDigest::sha256())
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap()
}

fn supervise(
    identity: RemoteIdentity,
    registry: &crate::plugin_control::Registry,
) -> (tokio::task::JoinHandle<io::Result<()>>, Directory) {
    let directory = Directory::new();
    let control = registry.clone();
    let state = directory.0.clone();
    (
        tokio::spawn(async move { Box::pin(run(&identity, state, None, control)).await }),
        directory,
    )
}

#[tokio::test]
/// Keep the real TLS refusal, fallback dial and admission proof in one fixture.
#[allow(clippy::too_many_lines)]
async fn candidate_mtls_refusal_retries_the_pending_predecessor() {
    use infraternal_plugin_remote::identity_rotation::{
        Challenge, PendingRotation, RotationStorage,
    };
    use openssl::pkey::PKey;

    let predecessor_ca = root();
    let candidate_ca = root();
    let host = uuid::Uuid::from_u128(285);
    let predecessor = host_identity(&predecessor_ca, host, PKey::generate_ed25519().unwrap(), 10);
    let candidate_key = PKey::generate_ed25519().unwrap();
    let candidate = host_identity(&candidate_ca, host, candidate_key.clone(), 11);
    let predecessor_issuer = predecessor_ca.certificate.public_key().unwrap();
    let candidate_issuer = candidate_ca.certificate.public_key().unwrap();
    assert_ne!(
        certificate_fingerprint(&predecessor_ca.certificate),
        certificate_fingerprint(&candidate_ca.certificate)
    );
    assert!(candidate.certificate.verify(&candidate_issuer).unwrap());
    assert!(!candidate.certificate.verify(&predecessor_issuer).unwrap());
    let challenge = Challenge {
        host_id: host,
        operation_id: uuid::Uuid::from_u128(286),
        sequence: 1,
        challenge: [7; 32],
        predecessor_fingerprint: certificate_fingerprint(&predecessor.certificate),
        issuer_fingerprint: certificate_fingerprint(&candidate_ca.certificate),
        issuer_generation: 1,
    };
    let stored = RotationStorage {
        pending: Some(PendingRotation {
            challenge,
            candidate_key_pkcs8: zeroize::Zeroizing::new(
                candidate_key.private_key_to_pkcs8().unwrap(),
            ),
            candidate_certificate_der: Some(candidate.certificate.to_der().unwrap()),
        }),
        completed: None,
    };
    let roots = vec![
        predecessor_ca.certificate.clone(),
        candidate_ca.certificate.clone(),
    ];
    let identity = RemoteIdentity {
        host_id: host,
        identity: predecessor,
        roots,
        endpoint: Some("127.0.0.1:0".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let mut renewal = crate::remote_renewal::RenewalIdentity::new(
        &identity.identity,
        &identity.roots,
        Arc::new(TestCertificatePublisher),
    );
    renewal
        .enable_identity_rotation(Arc::new(PendingRotationPublisher(std::sync::Mutex::new(
            Some(stored),
        ))))
        .unwrap();
    let active_fingerprint = certificate_fingerprint(&renewal.current().unwrap().certificate);
    assert_eq!(
        active_fingerprint,
        certificate_fingerprint(&candidate.certificate),
        "restored active credentials must be the candidate being refused"
    );
    assert_ne!(
        active_fingerprint,
        certificate_fingerprint(&identity.identity.certificate)
    );
    let renewal = Arc::new(renewal);

    let mut server = Server::new(
        &leaf(&predecessor_ca, true),
        std::slice::from_ref(&predecessor_ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let enrolled = server.endpoint.local_addr().unwrap();
    let mesh = server.lease("127.0.0.2");
    let identity = RemoteIdentity {
        endpoint: Some(enrolled),
        ..identity
    };
    let registry = registry();
    // The fixture trusts only the predecessor issuer, so the admitted connection
    // proves the candidate refusal selected the retained predecessor.
    let mut link = connect_with_predecessor_fallback(
        &identity,
        Some(&renewal),
        mesh,
        ServerLinkKind::Mesh,
        true,
    )
    .await
    .expect("refused candidate must retry with the predecessor");
    assert_eq!(link.current().0, ServerLinkKind::Mesh);
    let session_identity = identity;
    let session_renewal = renewal.clone();
    let session_registry = registry.clone();
    let session_task = tokio::spawn(async move {
        let proof = link.proof.take();
        let directory = Directory::new();
        session(
            &link,
            &session_identity,
            directory.0.clone(),
            Some(session_renewal.as_ref()),
            session_registry,
            proof,
        )
        .await
    });
    let _accepted = server.admitted_channel().await;
    assert_eq!(
        server.connections(),
        1,
        "only predecessor mTLS may be admitted"
    );
    assert_eq!(
        certificate_fingerprint(&renewal.current().unwrap().certificate),
        active_fingerprint,
        "fallback must not demote the persisted candidate"
    );
    session_task.abort();
    let _ = session_task.await;
}

#[tokio::test]
async fn a_future_mesh_lease_and_silent_cut_keep_their_port_reserved() {
    let ca = root();
    let mut server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let mesh = SocketAddr::new(
        "127.0.0.2".parse().unwrap(),
        server.endpoint.local_addr().unwrap().port(),
    );
    assert!(
        std::net::UdpSocket::bind(mesh).is_err(),
        "a parallel fixture can steal the later mesh binding"
    );
    server.lease("127.0.0.2");
    server.cut();
    assert!(
        std::net::UdpSocket::bind(mesh).is_err(),
        "a silent cut must absorb UDP without ICMP or port reuse"
    );
}

#[tokio::test]
async fn returning_publishes_the_selected_path_before_its_proof_finishes() {
    use std::future::Future as _;
    let ca = root();
    let mut server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let enrolled = server.endpoint.local_addr().unwrap();
    let mesh = server.lease("127.0.0.2");
    let registry = registry();
    let link = connect(
        &identity(&ca, enrolled),
        None,
        enrolled,
        ServerLinkKind::Fallback,
        false,
    )
    .await
    .unwrap();
    let path = link.path.as_ref().expect("fixture requires native QUIC");
    path.use_mesh(mesh);
    report(&registry, Some(&link), ServerLinkReason::MeshProven);
    server
        .dropping
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let returning = to_enrolled(&link, &registry, ServerLinkReason::MeshInterrupted);
    tokio::pin!(returning);
    // Check publication on the first poll, without any elapsed-time assertion.
    std::future::poll_fn(|cx| {
        let _ = returning.as_mut().poll(cx);
        std::task::Poll::Ready(())
    })
    .await;
    let selected = status(&registry).await;
    assert_eq!(
        selected.kind,
        ServerLinkKind::Fallback,
        "the cached status still names the failed path"
    );
    assert_eq!(selected.endpoint, Some(enrolled));
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

/// Losing early enrolled replies must not retire the existing writer-bearing
/// connection before QUIC has had a chance to recover those packets.
#[tokio::test]
async fn dropped_return_replies_keep_the_admitted_connection() {
    let ca = root();
    let mut server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
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
    server
        .dropping
        .store(true, std::sync::atomic::Ordering::Release);
    preference(&registry, None).await;
    server.cut();
    tokio::time::sleep(Duration::from_millis(400)).await;
    server
        .dropping
        .store(false, std::sync::atomic::Ordering::Release);
    until(
        &registry,
        ServerLinkKind::Fallback,
        ServerLinkReason::MeshDisabled,
    )
    .await;
    assert_remote_status(&mut active, ServerLinkKind::Fallback).await;
    assert_eq!(
        server.connections(),
        1,
        "lost return-path replies replaced the admitted connection"
    );
    assert!(server.accepted.try_recv().is_err());
    supervisor.abort();
    let _ = supervisor.await;
}

/// A late physical reply schedules proof without selecting a new path itself.
#[tokio::test]
async fn a_latched_mesh_reply_wakes_retry_without_selecting_the_path() {
    use quinn::{AsyncUdpSocket as _, Runtime as _};
    let mesh = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = socket.local_addr().unwrap();
    let path = PathSocket::new(
        quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(),
        "127.0.0.1:1".parse().unwrap(),
    );
    path.use_mesh(mesh.local_addr().unwrap());
    path.use_enrolled();
    let since = std::time::Instant::now();
    mesh.send_to(b"route hint", local).await.unwrap();
    let mut bytes = [0; 64];
    let mut buffers = [std::io::IoSliceMut::new(&mut bytes)];
    let mut metadata = [quinn::udp::RecvMeta::default()];
    std::future::poll_fn(|cx| path.poll_recv(cx, &mut buffers, &mut metadata))
        .await
        .unwrap();
    assert!(path.heard_since(since));
    let mut retry = std::pin::pin!(retry_path(
        &path,
        tokio::time::Instant::now() + Duration::from_secs(3600),
        since,
    ));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        std::future::Future::poll(retry.as_mut(), &mut context).is_ready(),
        "a latched mesh reply remained hidden behind the retry timer"
    );
    assert_eq!(
        path.path(),
        Path::Enrolled,
        "a route hint is not path proof"
    );
    // The prior healthy reply must not defeat a subsequent interruption's
    // backoff. Register first, then deliver a new hint, covering both ordering
    // directions without relying on an elapsed-time assertion.
    let fresh_since = std::time::Instant::now();
    let mut waiting = std::pin::pin!(retry_path(
        &path,
        tokio::time::Instant::now() + Duration::from_secs(3600),
        fresh_since,
    ));
    assert!(std::future::Future::poll(waiting.as_mut(), &mut context).is_pending());
    mesh.send_to(b"new route hint", local).await.unwrap();
    std::future::poll_fn(|cx| path.poll_recv(cx, &mut buffers, &mut metadata))
        .await
        .unwrap();
    assert!(std::future::Future::poll(waiting.as_mut(), &mut context).is_ready());
    assert_eq!(path.path(), Path::Enrolled);
}

/// Latch a non-authoritative hint without letting paused recovery expire.
async fn latch_retry_hint(path: &PathSocket, sender: &std::net::UdpSocket) {
    use quinn::AsyncUdpSocket as _;
    use std::future::Future as _;
    // Latch precisely the raw routing hint accepted by retry_path's existing
    // isolated test. It grants no authority and must trigger fresh proof.
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let since = std::time::Instant::now();
    sender
        .send_to(b"late route hint", path.local_addr().unwrap())
        .unwrap();
    let mut bytes = [0; 64];
    let mut buffers = [std::io::IoSliceMut::new(&mut bytes)];
    let mut metadata = [quinn::udp::RecvMeta::default()];
    for _ in 0..10_000 {
        if path.heard_since(since) {
            break;
        }
        // Keep the test runnable while UDP readiness is dispatched, preventing
        // paused time from auto-advancing the enrolled proof's deadline.
        std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(result) = path.poll_recv(cx, &mut buffers, &mut metadata)
            {
                result.unwrap();
            }
            std::task::Poll::Ready(())
        })
        .await;
        tokio::task::yield_now().await;
    }
    assert!(path.heard_since(since), "late hint was not latched");
    let mut control = std::pin::pin!(retry_path(
        path,
        tokio::time::Instant::now() + Duration::from_secs(3600),
        since
    ));
    assert!(
        control.as_mut().poll(&mut context).is_ready(),
        "isolated retry did not see the hint"
    );
}

/// Exercise caller retry ordering while the admitted enrolled path is silent.
async fn retry_during_enrolled_proof(late_hint: bool, backup: bool) {
    use std::future::Future as _;
    let ca = root();
    let server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let enrolled = server.endpoint.local_addr().unwrap();
    let identity = identity(&ca, enrolled);
    let registry = registry();
    let link = connect(&identity, None, enrolled, ServerLinkKind::Fallback, false)
        .await
        .unwrap();
    let path = link.path.as_ref().expect("fixture requires native QUIC");
    // The authenticated session normally publishes this negotiated flag.
    if backup {
        link.negotiated(
            infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                | infraternal_plugin_api::channel::REMOTE_PATH_PROOF,
        );
    }
    let mesh_socket = server.reserved.as_ref().unwrap().try_clone().unwrap();
    mesh_socket.set_nonblocking(true).unwrap();
    let mesh = tokio::net::UdpSocket::from_std(mesh_socket).unwrap();
    preference(&registry, Some(mesh.local_addr().unwrap().ip())).await;
    server
        .dropping
        .store(true, std::sync::atomic::Ordering::Release);
    // Real mutual TLS has completed. Virtual time now controls only expiry
    // ordering; no assertion depends on a measured wall-clock duration.
    tokio::time::pause();
    let mut active = std::pin::pin!(std::future::pending::<io::Result<()>>());
    let mut reason = ServerLinkReason::MeshProven;
    let mut steering = std::pin::pin!(steer(
        &link,
        &identity,
        &registry,
        false,
        &mut reason,
        active.as_mut(),
    ));
    for _ in 0..10_000 {
        std::future::poll_fn(|cx| {
            assert!(steering.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        if matches!(path.path(), Path::Mesh(_)) {
            break;
        }
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    assert!(matches!(path.path(), Path::Mesh(_)));
    tokio::time::advance(Duration::from_secs(if backup { 4 } else { 10 })).await;
    std::future::poll_fn(|cx| {
        assert!(steering.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(
        matches!(path.path(), Path::Mesh(_)),
        backup,
        "candidate refusal did not preserve backed discovery or legacy return"
    );
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    if late_hint {
        latch_retry_hint(path, server.reserved.as_ref().unwrap()).await;
    } else {
        // A handshake can drain only packets already copied on enrolled. With
        // no fresh mesh reply, discovery must still resume on its owned clock.
        // Dispatch the timer wheel beyond its millisecond rounding boundary.
        tokio::time::advance(BACKUP_PROBE_INTERVAL + Duration::from_millis(1)).await;
    }
    assert!(steering.as_mut().poll(&mut context).is_pending());
    assert!(
        matches!(path.path(), Path::Mesh(_)) == (late_hint || backup),
        "retry ignored the discovery clock or bypassed legacy cooling"
    );
}

/// A late hint can wake fresh proof while enrolled recovery is pending.
#[tokio::test]
async fn pending_enrolled_proof_does_not_hide_a_latched_mesh_hint() {
    retry_during_enrolled_proof(true, false).await;
}

/// The shared dial owns the mesh handshake deadline even without an outer timer.
#[tokio::test]
async fn silent_mesh_handshake_keeps_the_shared_timeout_classification() {
    use std::future::Future as _;
    let ca = root();
    let silent = std::net::UdpSocket::bind("127.0.0.2:0").unwrap();
    let address = silent.local_addr().unwrap();
    let identity = identity(&ca, address);
    tokio::time::pause();
    let mut candidate = std::pin::pin!(connect(
        &identity,
        None,
        address,
        ServerLinkKind::Mesh,
        false,
    ));
    std::future::poll_fn(|cx| {
        assert!(candidate.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::advance(PROBE_TIMEOUT + Duration::from_millis(1)).await;
    let result = candidate.await;
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
}

/// Mesh discovery cannot depend on a reply to already duplicated queued packets.
#[tokio::test]
async fn pending_enrolled_proof_does_not_hide_the_mesh_discovery_clock() {
    retry_during_enrolled_proof(false, true).await;
}

/// An unnegotiated peer keeps its existing outage cooling rather than losing
/// enrolled service to repeated candidates without ciphertext backup.
#[tokio::test]
async fn unnegotiated_backup_preserves_the_enrolled_retry_cooling() {
    retry_during_enrolled_proof(false, false).await;
}

/// Dispatch the initial retry timer without advancing a pending proof's clock.
async fn start_mesh_candidate(
    mut steering: std::pin::Pin<&mut impl std::future::Future<Output = Steered>>,
    path: &PathSocket,
) {
    for _ in 0..100 {
        std::future::poll_fn(|cx| {
            assert!(steering.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        if matches!(path.path(), Path::Mesh(_)) {
            return;
        }
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    panic!("fixture did not start its mesh candidate");
}

/// Late capability publication must activate physical enrolled copies during
/// pending proof. Real QUIC establishes the link, but the opaque marker bypasses
/// QUIC pacing and proves only socket routing, not authenticated stream delivery.
#[tokio::test]
async fn backup_published_during_candidate_proof_keeps_enrolled_control_live() {
    use quinn::AsyncUdpSocket as _;
    use std::future::Future as _;
    let ca = root();
    let mut server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let enrolled = server.endpoint.local_addr().unwrap();
    let identity = identity(&ca, enrolled);
    let registry = registry();
    let link = connect(&identity, None, enrolled, ServerLinkKind::Fallback, false)
        .await
        .unwrap();
    let Connected::Quic(connection) = &link.connected else {
        panic!("fixture requires native QUIC")
    };
    let (send, receive) = connection.open_bi().await.unwrap();
    let control = NativeChannel::control(send, receive).unwrap();
    Transmit::default()
        .send(&control, 0, &super::super::client_greeting(false, false))
        .await
        .unwrap();
    assert!(matches!(
        Receive::default().next(&control).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let _accepted = server.admitted_channel().await;
    // Keep the reserved mesh tuple silent. Publish the negotiated capability
    // separately, just as the session future does after decoding server Hello.
    preference(
        &registry,
        Some(server.reserved.as_ref().unwrap().local_addr().unwrap().ip()),
    )
    .await;
    tokio::time::pause();
    let path = link.path.as_ref().unwrap();
    let mut active = std::pin::pin!(std::future::pending::<io::Result<()>>());
    let mut reason = ServerLinkReason::Connecting;
    let mut steering = std::pin::pin!(steer(
        &link,
        &identity,
        &registry,
        false,
        &mut reason,
        active.as_mut(),
    ));
    start_mesh_candidate(steering.as_mut(), path).await;
    link.negotiated(
        infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
            | infraternal_plugin_api::channel::REMOTE_PATH_PROOF,
    );
    // Publication synchronously applies backup through the production method.
    // Only subsequent datagrams need copies; no older queued packet is replayed.
    std::future::poll_fn(|cx| {
        assert!(steering.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    path.try_send(&quinn::udp::Transmit {
        destination: enrolled,
        ecn: None,
        contents: BACKUP_MARKER,
        segment_size: None,
        src_ip: None,
    })
    .unwrap();
    // The direct successful send is the physical mesh boundary. Advance beyond
    // the existing 20 ms copy deadline, then explicitly poll the owning adapter
    // to flush its due copies, independently of Quinn's connection pacing.
    tokio::time::advance(Duration::from_millis(21)).await;
    let mut buffer = [0; 2048];
    let mut buffers = [std::io::IoSliceMut::new(&mut buffer)];
    let mut metadata = [quinn::udp::RecvMeta::default()];
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(result) = path.poll_recv(cx, &mut buffers, &mut metadata) {
            result.unwrap();
        }
        std::task::Poll::Ready(())
    })
    .await;
    let observed = server.marker.notified();
    tokio::pin!(observed);
    // The actual pending proof owns failure: once refusal selects enrolled,
    // delivery would no longer establish overlap during the candidate. No
    // number of scheduler polls or wall-clock threshold decides success.
    std::future::poll_fn(|cx| {
        assert!(steering.as_mut().poll(cx).is_pending());
        assert!(
            matches!(path.path(), Path::Mesh(_)),
            "late backup negotiation did not copy the marker before candidate refusal"
        );
        observed.as_mut().poll(cx)
    })
    .await;
    assert_eq!(server.connections(), 1);
}

/// A raw tuple hint must not complete authenticated path proof. The single
/// poll runs on one runtime thread, so no QUIC driver can change authenticated
/// frame counters between answered's freshness snapshot and its first check.
#[tokio::test(flavor = "current_thread")]
async fn invalid_mesh_hint_cannot_complete_fresh_path_proof() {
    use quinn::AsyncUdpSocket as _;
    use std::future::Future as _;
    let ca = root();
    let mut server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let enrolled = server.endpoint.local_addr().unwrap();
    let identity = identity(&ca, enrolled);
    let link = connect(&identity, None, enrolled, ServerLinkKind::Fallback, false)
        .await
        .unwrap();
    let Connected::Quic(connection) = &link.connected else {
        panic!("fixture requires native QUIC")
    };
    let (send, receive) = connection.open_bi().await.unwrap();
    let control = NativeChannel::control(send, receive).unwrap();
    Transmit::default()
        .send(&control, 0, &super::super::client_greeting(false, false))
        .await
        .unwrap();
    assert!(matches!(
        Receive::default().next(&control).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let _accepted = server.admitted_channel().await;
    server
        .dropping
        .store(true, std::sync::atomic::Ordering::Release);
    let mesh_socket = server.reserved.as_ref().unwrap().try_clone().unwrap();
    mesh_socket.set_nonblocking(true).unwrap();
    let mesh = tokio::net::UdpSocket::from_std(mesh_socket).unwrap();
    let path = link.path.as_ref().unwrap();
    path.use_mesh(mesh.local_addr().unwrap());
    let since = tokio::time::Instant::now();
    // This is the trusted candidate tuple, but its public payload cannot
    // authenticate as a packet on the established connection.
    mesh.send_to(BACKUP_MARKER, path.local_addr().unwrap())
        .await
        .unwrap();
    path.mesh_heard(since.into_std()).await;
    assert!(path.heard_since(since.into_std()));
    // Separate caller since from the forthcoming freshness snapshot without
    // an elapsed-wall-time assertion. Only the first answered poll is tested.
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(1)).await;
    let mut proof = std::pin::pin!(answered(connection, path, since, true));
    std::future::poll_fn(|cx| {
        assert!(
            proof.as_mut().poll(cx).is_pending(),
            "raw mesh hint completed proof without an authenticated frame change"
        );
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(server.connections(), 1);
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

/// A lost initial announcement must not leave candidate proof waiting only
/// for QUIC's loss timer. Count fresh ack-eliciting probes, not elapsed time.
#[tokio::test]
async fn candidate_proof_keeps_probing_after_its_first_packet_is_lost() {
    let ca = root();
    let roots = std::slice::from_ref(&ca.certificate);
    let server = Server::new(&leaf(&ca, true), roots, "127.0.0.1:0".parse().unwrap());
    let enrolled = server.endpoint.local_addr().unwrap();
    let link = connect(
        &identity(&ca, enrolled),
        None,
        enrolled,
        ServerLinkKind::Fallback,
        true,
    )
    .await
    .unwrap();
    let Connected::Quic(connection) = &link.connected else {
        panic!("expected QUIC");
    };
    let path = link.path.as_ref().unwrap();
    // The reserved alternative tuple remains unread, so every candidate
    // datagram is silently lost without ICMP or a transport close.
    let mesh = SocketAddr::new("127.0.0.2".parse().unwrap(), enrolled.port());
    let initial = connection.stats().frame_tx.datagram;
    let since = tokio::time::Instant::now();
    path.use_mesh(mesh);
    remote_quic::probe_liveness(connection);
    assert!(!answered(connection, path, since, true).await);
    assert!(
        connection.stats().frame_tx.datagram >= initial + 3,
        "candidate sent only its initial probe and waited for the loss timer"
    );
    assert!(connection.close_reason().is_none());
    assert_eq!(server.connections(), 1);
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
    let mut impostor = Server::from_socket(
        &leaf(&wrong, true),
        std::slice::from_ref(&wrong.certificate),
        server.reserved.take().unwrap(),
        None,
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

/// Functional control traffic retains exact reply ordering on the one
/// admitted connection. Idle liveness deadlines have a separate VM check.
#[tokio::test]
async fn healthy_mesh_preserves_every_control_reply_on_the_admitted_connection() {
    let ca = root();
    let mut server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
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
    for nonce in 1..=64 {
        Transmit::default()
            .send(
                active.control.as_ref(),
                0,
                &Frame::Ping { nonce, sent_us: 0 },
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let reply = active.receive.next(active.control.as_ref()).await.unwrap();
                assert_eq!(reply.stream_id, 0);
                match reply.frame {
                    Frame::Pong {
                        nonce: received,
                        sent_us,
                    } => {
                        assert_eq!((received, sent_us), (nonce, 0));
                        break;
                    }
                    Frame::Event { .. } => {}
                    other => panic!("unexpected control reply: {other:?}"),
                }
            }
        })
        .await
        .unwrap();
    }
    assert_eq!(server.connections(), 1);
    assert!(server.accepted.try_recv().is_err());
    supervisor.abort();
    let _ = supervisor.await;
}

/// Acknowledged probes keep a healthy mesh path; its RTT-scale timing is
/// validated only on the perf VM, independently of concurrent build-host jobs.
#[tokio::test]
#[ignore = "Timing assertion: run on the perf VM under the shared benchmark lock."]
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
    let (listener, mesh_socket, _enrolled_blackhole) = tcp_mesh_pair();
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
                // Initial census and later control frames do not end a live TCP link.
                while receive.next(&connection.channel).await.is_ok() {}
            });
            while sessions.try_join_next().is_some() {}
        }
    });
    let mut mesh = Server::from_socket(
        &server,
        std::slice::from_ref(&ca.certificate),
        mesh_socket,
        None,
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
        host_id: uuid::Uuid::new_v4(),
        identity: credentials,
        roots: vec![ca.certificate],
        endpoint: Some("127.0.0.1:1".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    assert!(
        Box::pin(tokio::time::timeout(
            Duration::from_millis(250),
            run(&identity, directory.0.clone(), None, registry()),
        ))
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
        host_id: uuid::Uuid::new_v4(),
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: Some("127.0.0.1:1".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = Directory::new();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        Box::pin(super::run(
            &identity,
            directory.0.clone(),
            None,
            crate::plugin_control::Registry::unavailable(),
            tokio::sync::watch::channel(false).0,
        )),
    )
    .await
    .expect("failed worker must return to the owner that recreates its service");
    assert!(result.is_err());
}

/// Retain the authenticated control handles while testing unproven discovery.
async fn backed_candidate_fixture() -> (
    Server,
    RemoteIdentity,
    crate::plugin_control::Registry,
    Link,
    tokio::net::UdpSocket,
    NativeChannel,
    Accepted,
) {
    let ca = root();
    let mut server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let enrolled = server.endpoint.local_addr().unwrap();
    let identity = identity(&ca, enrolled);
    let registry = registry();
    let link = connect(&identity, None, enrolled, ServerLinkKind::Fallback, false)
        .await
        .unwrap();
    let Connected::Quic(connection) = &link.connected else {
        panic!("fixture requires native QUIC")
    };
    let (send, receive) = connection.open_bi().await.unwrap();
    let control = NativeChannel::control(send, receive).unwrap();
    Transmit::default()
        .send(&control, 0, &super::super::client_greeting(false, false))
        .await
        .unwrap();
    assert!(matches!(
        Receive::default().next(&control).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let accepted = server.admitted_channel().await;
    let mesh_socket = server.reserved.as_ref().unwrap().try_clone().unwrap();
    mesh_socket.set_nonblocking(true).unwrap();
    let mesh = tokio::net::UdpSocket::from_std(mesh_socket).unwrap();
    preference(&registry, Some(mesh.local_addr().unwrap().ip())).await;
    link.negotiated(
        infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
            | infraternal_plugin_api::channel::REMOTE_PATH_PROOF,
    );
    (server, identity, registry, link, mesh, control, accepted)
}

/// Negotiated backup must retain physical mesh discovery across candidate
/// refusal. This witnesses raw socket routing, not authenticated stream latency.
#[tokio::test]
async fn backed_candidate_refusal_keeps_new_datagrams_on_mesh_discovery() {
    use quinn::AsyncUdpSocket as _;
    use std::future::Future as _;
    let (server, identity, registry, link, mesh, _control, _accepted) =
        backed_candidate_fixture().await;
    let enrolled = identity.endpoint.unwrap();
    tokio::time::pause();
    let path = link.path.as_ref().unwrap();
    let mut active = std::pin::pin!(std::future::pending::<io::Result<()>>());
    let mut reason = ServerLinkReason::Connecting;
    let mut steering = std::pin::pin!(steer(
        &link,
        &identity,
        &registry,
        false,
        &mut reason,
        active.as_mut(),
    ));
    start_mesh_candidate(steering.as_mut(), path).await;
    // No mesh listener answers. Advance beyond the maximum candidate guard
    // (two RTTs capped at three seconds, plus margin), then poll exactly once to
    // process refusal. Any new recovery/retry timers start at this boundary.
    let unproven_since = std::time::Instant::now();
    tokio::time::advance(Duration::from_secs(4)).await;
    std::future::poll_fn(|cx| {
        assert!(steering.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(
        !path.heard_since(unproven_since),
        "silent candidate unexpectedly answered"
    );
    path.try_send(&quinn::udp::Transmit {
        destination: enrolled,
        ecn: None,
        contents: BACKUP_MARKER,
        segment_size: None,
        src_ip: None,
    })
    .unwrap();
    let mesh_marker = async {
        let mut packet = [0; 2048];
        loop {
            let count = mesh.recv(&mut packet).await.unwrap();
            if packet[..count] == *BACKUP_MARKER {
                return;
            }
        }
    };
    // Both witnesses are actual UDP receipts. Routing is frozen at the
    // post-refusal boundary; waiting neither polls steering nor advances its
    // retry timer. Earlier encrypted probes cannot satisfy the public marker.
    let reached_mesh = tokio::select! {
        biased;
        () = mesh_marker => true,
        () = server.marker.notified() => false,
    };
    assert!(
        reached_mesh,
        "candidate refusal sent the new datagram only to enrolled, leaving a mesh discovery gap"
    );
    assert_eq!(server.connections(), 1);
}

/// Pending discovery must react to control changes without pretending it proved
/// mesh. Independent authenticated silence must still retire both-dead UDP.
#[tokio::test]
async fn backed_discovery_keeps_control_cancellation_and_udp_recovery_bounded() {
    use std::future::Future as _;
    for change in 0..5 {
        let (server, identity, registry, link, _mesh, _control, _accepted) =
            backed_candidate_fixture().await;
        if change == 2 {
            server
                .dropping
                .store(true, std::sync::atomic::Ordering::Release);
        }
        report(&registry, Some(&link), ServerLinkReason::Connecting);
        tokio::time::pause();
        let path = link.path.as_ref().unwrap();
        let mut active = std::pin::pin!(std::future::pending::<io::Result<()>>());
        let mut reason = ServerLinkReason::Connecting;
        let mut steering = std::pin::pin!(steer(
            &link,
            &identity,
            &registry,
            false,
            &mut reason,
            active.as_mut(),
        ));
        start_mesh_candidate(steering.as_mut(), path).await;
        tokio::time::advance(Duration::from_secs(4)).await;
        std::future::poll_fn(|cx| {
            assert!(steering.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(
            matches!(path.path(), Path::Mesh(_)),
            "backed discovery opened an enrolled-only gap"
        );
        assert_eq!(
            status(&registry).await.kind,
            ServerLinkKind::Fallback,
            "unanswered discovery was reported as proven mesh"
        );
        if change == 0 {
            preference(&registry, None).await;
        } else if change == 1 {
            link.negotiated(infraternal_plugin_api::channel::REMOTE_PATH_PROOF);
        } else if change == 3 {
            preference(&registry, Some("127.0.0.3".parse().unwrap())).await;
        } else if change == 4 {
            link.negotiated(infraternal_plugin_api::channel::REMOTE_PATH_BACKUP);
        } else {
            // Every proof epoch is shorter than this virtual step. Even if a
            // final pre-cut ACK is observed at the first boundary, it must not
            // let repeated candidate epochs reset the independent silence guard.
            let mut ended = false;
            for _ in 0..4 {
                tokio::time::advance(Duration::from_secs(6)).await;
                ended = std::future::poll_fn(|cx| match steering.as_mut().poll(cx) {
                    std::task::Poll::Ready(Steered::Ended) => std::task::Poll::Ready(true),
                    std::task::Poll::Ready(Steered::Replaced(..)) => {
                        panic!("QUIC discovery replaced its own link")
                    }
                    std::task::Poll::Pending => std::task::Poll::Ready(false),
                })
                .await;
                if ended {
                    break;
                }
            }
            assert!(
                ended,
                "both dead UDP paths stayed in mesh discovery instead of releasing the TCP dial race"
            );
            tokio::time::resume();
            continue;
        }
        std::future::poll_fn(|cx| {
            assert!(steering.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(
            path.path(),
            Path::Enrolled,
            "control change failed to cancel unproven mesh discovery"
        );
        assert_eq!(status(&registry).await.kind, ServerLinkKind::Fallback);
        tokio::time::resume();
    }
}

/// Session completion cancels continuous discovery before another proof epoch.
#[tokio::test]
async fn backed_discovery_ends_with_its_owned_session() {
    use std::future::Future as _;
    let (_server, identity, registry, link, _mesh, _control, _accepted) =
        backed_candidate_fixture().await;
    tokio::time::pause();
    let path = link.path.as_ref().unwrap();
    let (finished, completion) = tokio::sync::oneshot::channel::<()>();
    let mut active = std::pin::pin!(async {
        completion.await.unwrap();
        Ok(())
    });
    let mut reason = ServerLinkReason::Connecting;
    let mut steering = std::pin::pin!(steer(
        &link,
        &identity,
        &registry,
        false,
        &mut reason,
        active.as_mut(),
    ));
    start_mesh_candidate(steering.as_mut(), path).await;
    tokio::time::advance(Duration::from_secs(4)).await;
    std::future::poll_fn(|cx| {
        assert!(steering.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(matches!(path.path(), Path::Mesh(_)));
    finished.send(()).unwrap();
    std::future::poll_fn(|cx| {
        assert!(matches!(
            steering.as_mut().poll(cx),
            std::task::Poll::Ready(Steered::Ended)
        ));
        std::task::Poll::Ready(())
    })
    .await;
}

/// A live older peer must keep its enrolled transport rather than entering an
/// unsupported proof and forcing a reconnect. No elapsed-time oracle is needed.
#[tokio::test]
async fn unadvertised_path_proof_keeps_the_existing_enrolled_connection() {
    use std::future::Future as _;
    let ca = root();
    let mut server = Server::new(
        &leaf(&ca, true),
        std::slice::from_ref(&ca.certificate),
        "127.0.0.1:0".parse().unwrap(),
    );
    let enrolled = server.endpoint.local_addr().unwrap();
    let mesh = server.lease("127.0.0.2");
    let identity = identity(&ca, enrolled);
    let link = connect(&identity, None, enrolled, ServerLinkKind::Fallback, false)
        .await
        .unwrap();
    link.negotiated(0);
    let registry = registry();
    preference(&registry, Some(mesh.ip())).await;
    let path = link.path.as_ref().unwrap();
    let mut active = std::pin::pin!(std::future::pending::<io::Result<()>>());
    let mut reason = ServerLinkReason::Connecting;
    let mut steering = std::pin::pin!(steer(
        &link,
        &identity,
        &registry,
        false,
        &mut reason,
        active.as_mut()
    ));
    std::future::poll_fn(|cx| {
        assert!(steering.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(path.path(), Path::Enrolled);
}
