//! An iPhone's slice-1 path end to end, on Linux, against the real server
//! (#580, L3): a software P-256 key stands in for the Secure Enclave and uses
//! only `infraternal-link` (no OpenSSL on the device side).
//!
//! The device is approved through the real device-code routes, joins over
//! real HTTPS (rustls, the invitation's pinned root) at `/remote/join`, and
//! holds its QUIC link to the real leg-B listeners. The tests then prove
//! what a device link may never do, and what ends it: a server leaf
//! rotation it survives, a copied old leaf and a wrong CA it refuses, its
//! removal, a revoked or expired certificate, and a newer link.
//!
//! Every socket is on 127.0.0.1; nothing leaves the host.
use super::*;
use crate::{
    remote_device_link::{EXPIRED, REFUSED, REPLACED, REVOKED},
    remote_runtime::{RemoteHosts, RemoteListeners},
};
use infraternal_agent::remote_tls::Identity;
use infraternal_link::{
    device::DeviceLink,
    identity::{IdentitySigner, SoftwareP256},
    join::{JoinError, Joined},
    server_leaf_floor::ServerLeafFloor,
};
use infraternal_protocol::Frame;
use quinn::rustls::pki_types::CertificateDer;
use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// The `client_info` the test device sends in its Hello.
const DEVICE: &str = "infraternal-test-device/1";

/// Counts the test devices, so each one asks from its own source address.
static SOURCES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// `request`, as the runtime's source admission would deliver it from
/// `source`: device-code starts are limited per source, and a test that
/// approves many devices must not share one. The address is only a label
/// inside this process; nothing is sent to it.
async fn request_from(
    app: &Router,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    origin: &str,
    source: std::net::IpAddr,
) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("origin", origin)
        .extension(crate::runtime::ClientAddress(source));
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", format!("__Host-infraternal={cookie}"));
    }
    app.clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// One running server: the app routes over real HTTPS, the leg-B listeners,
/// and what the tests need to reach into.
struct DeviceServer {
    app: Router,
    auth: Auth,
    pool: SqlitePool,
    store: EnrollmentStore,
    session: String,
    material: crate::ca::CaMaterial,
    leaf: Identity,
    listeners: RemoteListeners,
    https: SocketAddr,
    https_task: tokio::task::JoinHandle<()>,
}

impl Drop for DeviceServer {
    fn drop(&mut self) {
        self.https_task.abort();
    }
}

/// Unix seconds now.
fn unix_now() -> i64 {
    super::now().unwrap()
}

/// Start a server whose CA is unlocked, whose leg-B listeners serve a fresh
/// leaf for `localhost`, and whose `/remote/join` is served over HTTPS with
/// that same CA-issued leaf.
async fn device_server() -> DeviceServer {
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let session = session(&pool).await;
    let material = crate::ca::tests::test_material();
    let leaf = crate::server_leaf::issue(&material, "localhost", None, unix_now() - 3600).unwrap();
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &leaf,
        std::slice::from_ref(material.issuer()),
        store.clone(),
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: listeners.local_addr().unwrap(),
        server_name: "localhost".into(),
    };
    let issuer = InvitationIssuer::new(
        auth.clone(),
        pool.clone(),
        store.clone(),
        EnrollmentService {
            source: source.clone(),
            endpoint: endpoint.clone(),
        },
    );
    let app = crate::auth::router_with_invitation_issuer(auth.clone(), Some(issuer)).merge(
        router_with_store(
            auth.clone(),
            pool.clone(),
            store.clone(),
            source.clone(),
            endpoint,
        ),
    );
    source
        .unlock_from(&Administrator(material.clone()))
        .unwrap();
    let config = axum_server::tls_openssl::OpenSSLConfig::from_der(
        &leaf.certificate.to_der().unwrap(),
        &leaf.key.private_key_to_der().unwrap(),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let https = listener.local_addr().unwrap();
    let served = app.clone();
    let https_task = tokio::spawn(async move {
        let _ = axum_server::from_tcp(listener)
            .unwrap()
            .acceptor(crate::server_tls::acceptor(config))
            .serve(served.into_make_service())
            .await;
    });
    DeviceServer {
        app,
        auth,
        pool,
        store,
        session,
        material,
        leaf,
        listeners,
        https,
        https_task,
    }
}

impl DeviceServer {
    /// Approve `signer`'s key as a new device through the device-code routes
    /// (start, owner inspect and approve, redeem) and return its invitation,
    /// pointed at this server's real HTTPS listener.
    async fn invitation(&self, signer: &dyn IdentitySigner) -> JoinInvitation {
        let now = unix_now();
        self.auth.set_test_http_time(now);
        let digest = infraternal_link::csr::key_digest(signer).unwrap();
        let fingerprint = format!("SHA256:{}", FINGERPRINT_B64.encode(digest));
        let [_, _, high, low] = SOURCES
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_be_bytes();
        let source = std::net::IpAddr::from([127, high, low, 1]);
        let start = request_from(
            &self.app,
            "/auth/device-start",
            json!({"kind": "join_machine", "device": "iphone", "request": {
                "host_id": Uuid::new_v4(), "hostname": "test-iphone", "mode": "device",
                "key_fingerprint": fingerprint}}),
            None,
            "https://auth.example.test",
            source,
        )
        .await;
        assert_eq!(start.status(), StatusCode::OK);
        let approval: Value =
            serde_json::from_slice(&start.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let inspected = request(
            &self.app,
            "/auth/device-inspect",
            json!({"code": approval["user_code"]}),
            Some(&self.session),
            "https://auth.example.test",
        )
        .await;
        assert_eq!(inspected.status(), StatusCode::OK);
        self.auth
            .approve_without_passkey_for_tests(
                &self.session,
                approval["user_code"].as_str().unwrap(),
                now,
            )
            .await
            .unwrap();
        let redeemed = request_from(
            &self.app,
            "/auth/device-redeem",
            json!({"token": approval["poll_token"]}),
            None,
            "",
            source,
        )
        .await;
        assert_eq!(redeemed.status(), StatusCode::OK);
        let mut invitation: JoinInvitation =
            serde_json::from_slice(&redeemed.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        // The approval page's origin is a test name; the join goes to the
        // real HTTPS listener, as a device would reach the public origin.
        invitation.public_origin = format!("https://localhost:{}", self.https.port());
        invitation
    }

    /// Approve and join a fresh software P-256 device; returns its join
    /// result and how long the HTTPS join took.
    async fn joined_device(&self) -> (Joined, Duration) {
        let signer = Arc::new(SoftwareP256::generate().unwrap());
        let invitation = self.invitation(signer.as_ref()).await;
        let started = Instant::now();
        let joined = infraternal_link::join::join(invitation, signer)
            .await
            .unwrap();
        (joined, started.elapsed())
    }
}

/// A QUIC client endpoint for `joined`'s identity, trusting only its CA.
fn device_endpoint(joined: &Joined) -> quinn::Endpoint {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        infraternal_link::quic::client_config_with_liveness(
            &joined.identity,
            std::slice::from_ref(&joined.ca),
            Duration::from_secs(15),
            Duration::from_secs(60),
        )
        .unwrap(),
    );
    endpoint
}

/// Dial and open a device link at `address`, holding the server leaf to `floor`.
async fn open_link(
    endpoint: &quinn::Endpoint,
    address: SocketAddr,
    floor: &ServerLeafFloor,
) -> io::Result<DeviceLink> {
    let connection = infraternal_link::quic::connect(endpoint, address, "localhost", floor).await?;
    DeviceLink::open(connection, DEVICE).await
}

/// The application close code that ended `link`, if the server closed it.
async fn close_code(link: &DeviceLink) -> Option<u64> {
    match tokio::time::timeout(Duration::from_secs(10), link.closed()).await {
        Ok(quinn::ConnectionError::ApplicationClosed(close)) => Some(close.error_code.into_inner()),
        _ => None,
    }
}

/// The happy path: approve, join over HTTPS, link over QUIC, ping; the
/// device is held as a device and never published as a host.
#[tokio::test]
async fn a_device_joins_and_holds_its_quic_link() {
    let server = device_server().await;
    let (joined, _) = server.joined_device().await;
    assert_eq!(joined.mode, Mode::Device);
    let address = joined.quic_address().await.unwrap();
    assert_eq!(address, server.listeners.local_addr().unwrap());
    let endpoint = device_endpoint(&joined);
    let floor = ServerLeafFloor::default();
    let mut link = open_link(&endpoint, address, &floor).await.unwrap();
    assert_eq!(link.server_caps(), 0, "the server offers a device nothing");
    link.ping().await.unwrap();
    assert!(server.listeners.diagnostic_devices.holds(joined.host_id));
    assert!(
        !server
            .listeners
            .diagnostic_hosts
            .online(joined.host_id)
            .await,
        "a device is never published where terminals, sessions or host calls look"
    );
    assert!(
        server
            .listeners
            .diagnostic_hosts
            .actor(joined.host_id)
            .await
            .is_none()
    );
    assert_eq!(
        floor.newest(),
        Some(
            infraternal_link::server_leaf_floor::not_before_seconds(
                &server.leaf.certificate.to_der().unwrap()
            )
            .unwrap()
        )
    );
}

/// Each request a host would serve is refused over the real link: the link
/// closes with REFUSED and nothing is answered first.
#[tokio::test]
async fn a_device_link_serves_nothing() {
    let server = device_server().await;
    let (joined, _) = server.joined_device().await;
    let address = joined.quic_address().await.unwrap();
    let endpoint = device_endpoint(&joined);
    let floor = ServerLeafFloor::default();
    let session = [7u8; 16];
    let resume = [9u8; 32];
    let call = |action_id: &'static str| Frame::Call {
        call_id: 1,
        action_id,
        input_json: b"{}",
    };
    let refused: Vec<(&str, Frame<'_>)> = vec![
        (
            "terminal attach",
            Frame::AttachTerm {
                session_id: &session,
                last_out_seq: 0,
                last_in_seq: 0,
            },
        ),
        (
            "session resume",
            Frame::Resume {
                connection_id: &session,
                resume_token: &resume,
            },
        ),
        (
            "terminal input",
            Frame::Input {
                in_seq: 0,
                bytes: b"id\n",
            },
        ),
        ("login", call("terminal.login.revoke")),
        ("host facts", call("host.facts.read")),
        ("ssh", call("ssh.session.open")),
        ("mesh status", call("mesh.status")),
        ("mesh enrol", call("mesh.node.enroll")),
        ("transport standby", call("transport.standby")),
        (
            "subscription",
            Frame::Subscribe {
                sub_id: 1,
                filter_json: b"{}",
            },
        ),
        (
            "second hello",
            Frame::Hello {
                version: 1,
                caps: u64::MAX,
                client_info: DEVICE,
            },
        ),
    ];
    let step = Duration::from_secs(10);
    for (what, frame) in refused {
        let mut link = tokio::time::timeout(step, open_link(&endpoint, address, &floor))
            .await
            .unwrap_or_else(|_| panic!("{what}: dial timed out"))
            .unwrap();
        tokio::time::timeout(step, link.send(&frame))
            .await
            .unwrap_or_else(|_| panic!("{what}: send timed out"))
            .unwrap();
        let reply = tokio::time::timeout(step, link.next_frame())
            .await
            .unwrap_or_else(|_| panic!("{what}: the link stayed open"));
        assert!(reply.is_err(), "{what}: no reply");
        assert_eq!(close_code(&link).await, Some(REFUSED.into()), "{what}");
    }
    // A second stream (where a terminal would run) cannot even be opened:
    // the server's QUIC limits grant a client one bidirectional stream, the
    // control stream, and no unidirectional ones.
    let mut link = open_link(&endpoint, address, &floor).await.unwrap();
    let quiet = Duration::from_secs(1);
    assert!(
        tokio::time::timeout(quiet, link.connection().open_bi())
            .await
            .is_err(),
        "no credit for a second bidirectional stream"
    );
    assert!(
        tokio::time::timeout(quiet, link.connection().open_uni())
            .await
            .is_err(),
        "no credit for a unidirectional stream"
    );
    link.ping().await.unwrap();
    // A datagram (where app-window lanes would run) closes the link.
    let link = open_link(&endpoint, address, &floor).await.unwrap();
    link.connection()
        .send_datagram(bytes::Bytes::from_static(b"\x01"))
        .unwrap();
    assert_eq!(close_code(&link).await, Some(REFUSED.into()), "a datagram");
}

/// A server leaf rotation: the held link stays up; a redial takes the new
/// leaf and raises the floor; then a copy of the old leaf is refused, as the
/// infraternal agent refuses it (#559). The redial replaces the older link.
#[tokio::test]
async fn a_device_survives_a_server_leaf_rotation() {
    let server = device_server().await;
    let (joined, _) = server.joined_device().await;
    let address = joined.quic_address().await.unwrap();
    let endpoint = device_endpoint(&joined);
    let floor = ServerLeafFloor::default();
    let mut held = open_link(&endpoint, address, &floor).await.unwrap();
    let old_floor = floor.newest().unwrap();

    let new = crate::server_leaf::issue(
        &server.material,
        "localhost",
        Some(&server.leaf.certificate),
        unix_now(),
    )
    .unwrap();
    server.listeners.install_server_leaf(&new).unwrap();
    held.ping()
        .await
        .expect("the held link survives the rotation");

    let mut redialed = open_link(&endpoint, address, &floor).await.unwrap();
    redialed.ping().await.unwrap();
    assert!(
        floor.newest().unwrap() > old_floor,
        "the new leaf raised the floor"
    );
    assert_eq!(
        close_code(&held).await,
        Some(REPLACED.into()),
        "one link per device"
    );
    assert!(server.listeners.diagnostic_devices.holds(joined.host_id));

    // A copy of the server's old state, serving the old leaf from elsewhere.
    let impostor = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server.leaf,
        std::slice::from_ref(server.material.issuer()),
        server.store.clone(),
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let refused = open_link(&endpoint, impostor.local_addr().unwrap(), &floor)
        .await
        .err()
        .unwrap();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    redialed.ping().await.unwrap();
}

/// A server whose leaf comes from another CA is refused in the handshake,
/// and so is an HTTPS join pinned to the wrong root.
#[tokio::test]
async fn a_device_refuses_a_wrong_ca() {
    let server = device_server().await;
    let (joined, _) = server.joined_device().await;
    let other = crate::ca::tests::test_material();
    let stranger_leaf =
        crate::server_leaf::issue(&other, "localhost", None, unix_now() - 60).unwrap();
    let stranger = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &stranger_leaf,
        std::slice::from_ref(other.issuer()),
        server.store.clone(),
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let endpoint = device_endpoint(&joined);
    let floor = ServerLeafFloor::default();
    let refused = open_link(&endpoint, stranger.local_addr().unwrap(), &floor)
        .await
        .err()
        .unwrap();
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        floor.newest(),
        None,
        "nothing from a stranger is remembered"
    );

    // The join refuses an HTTPS server it cannot verify against its pin.
    let signer = Arc::new(SoftwareP256::generate().unwrap());
    let mut invitation = server.invitation(signer.as_ref()).await;
    invitation.https_der = Some(B64.encode(other.issuer().to_der().unwrap()));
    assert!(matches!(
        infraternal_link::join::join(invitation, signer).await,
        Err(JoinError::Network(_))
    ));
}

/// The join's HTTPS may also pin the server's exact HTTPS leaf, as the CLI's
/// partial-chain pin allows; the name is still checked.
#[tokio::test]
async fn a_device_joins_through_an_exactly_pinned_https_leaf() {
    let server = device_server().await;
    let signer = Arc::new(SoftwareP256::generate().unwrap());
    let mut invitation = server.invitation(signer.as_ref()).await;
    invitation.https_der = Some(B64.encode(server.leaf.certificate.to_der().unwrap()));
    let joined = infraternal_link::join::join(invitation, signer)
        .await
        .unwrap();
    assert_eq!(joined.mode, Mode::Device);

    // The same pin under another name is refused.
    let signer = Arc::new(SoftwareP256::generate().unwrap());
    let mut invitation = server.invitation(signer.as_ref()).await;
    invitation.https_der = Some(B64.encode(server.leaf.certificate.to_der().unwrap()));
    invitation.public_origin = format!("https://127.0.0.1:{}", server.https.port());
    assert!(matches!(
        infraternal_link::join::join(invitation, signer).await,
        Err(JoinError::Network(_))
    ));
}

/// The device's removal closes its held link at once (the revocation cut),
/// and its certificate is refused when it dials again.
#[tokio::test]
async fn removing_a_device_closes_its_link_at_once() {
    let server = device_server().await;
    let (joined, _) = server.joined_device().await;
    let address = joined.quic_address().await.unwrap();
    let endpoint = device_endpoint(&joined);
    let floor = ServerLeafFloor::default();
    let mut link = open_link(&endpoint, address, &floor).await.unwrap();
    link.ping().await.unwrap();

    // The removal's own commit path (`retire_device`): revoke the row, then
    // commit through the revocation fence.
    let mut transaction = server.pool.begin().await.unwrap();
    sqlx::query("UPDATE remote_hosts SET revoked_at=? WHERE id=?")
        .bind(unix_now())
        .bind(joined.host_id.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .unwrap();
    let removed = Instant::now();
    server
        .store
        .commit_device_retirement(transaction, joined.host_id)
        .await
        .unwrap();
    assert_eq!(close_code(&link).await, Some(REVOKED.into()));
    let latency = removed.elapsed();
    assert!(latency < Duration::from_secs(1), "closed in {latency:?}");
    eprintln!("device removal to link close: {latency:?}");
    assert!(!server.listeners.diagnostic_devices.holds(joined.host_id));
    assert!(open_link(&endpoint, address, &floor).await.is_err());
}

/// A certificate revoked on its own (an old one after a rotation) closes its
/// link within the recheck period.
#[tokio::test]
async fn a_revoked_certificate_closes_its_link_within_the_recheck() {
    let server = device_server().await;
    let (joined, _) = server.joined_device().await;
    let address = joined.quic_address().await.unwrap();
    let endpoint = device_endpoint(&joined);
    let floor = ServerLeafFloor::default();
    let link = open_link(&endpoint, address, &floor).await.unwrap();
    let fingerprint =
        ring::digest::digest(&ring::digest::SHA256, joined.identity.chain[0].as_ref());
    sqlx::query("UPDATE remote_certificates SET revoked_at=? WHERE fingerprint=?")
        .bind(unix_now())
        .bind(fingerprint.as_ref())
        .execute(&server.pool)
        .await
        .unwrap();
    let revoked = Instant::now();
    assert_eq!(close_code(&link).await, Some(REVOKED.into()));
    let latency = revoked.elapsed();
    assert!(
        latency <= crate::remote_device_link::RECHECK + Duration::from_millis(500),
        "closed in {latency:?}"
    );
}

/// A link closes when its certificate's validity ends.
#[tokio::test]
async fn an_expiring_certificate_closes_its_link() {
    let server = device_server().await;
    let (joined, _) = server.joined_device().await;
    let address = joined.quic_address().await.unwrap();
    let endpoint = device_endpoint(&joined);
    let floor = ServerLeafFloor::default();
    // The ledger's validity window is what admission reads, and it is always
    // exactly seven days long: move the whole window so it ends in 2 s.
    let fingerprint =
        ring::digest::digest(&ring::digest::SHA256, joined.identity.chain[0].as_ref());
    let ends = unix_now() + 2;
    sqlx::query("UPDATE remote_certificates SET not_before=?, not_after=? WHERE fingerprint=?")
        .bind(ends - 604_800)
        .bind(ends)
        .bind(fingerprint.as_ref())
        .execute(&server.pool)
        .await
        .unwrap();
    let link = open_link(&endpoint, address, &floor).await.unwrap();
    assert_eq!(close_code(&link).await, Some(EXPIRED.into()));
    assert!(unix_now() >= ends);
}

/// Measurement, not a gate (run with `--ignored --nocapture`): HTTPS join
/// time, QUIC handshake plus Hello time, Ping round trip, and the memory one
/// held device link costs (server and client together in this process).
#[tokio::test]
#[ignore = "measurement: run on purpose"]
async fn device_link_numbers() {
    /// Resident set size of this process, in bytes.
    fn rss() -> u64 {
        let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
        let pages: u64 = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
        pages * 4096
    }
    /// The p50 and p95 of `samples`, in microseconds.
    fn percentiles(samples: &mut [Duration]) -> (u128, u128) {
        samples.sort();
        // Nearest rank, in whole percent, so no float casts are needed.
        let at = |percent: usize| samples[(samples.len() - 1) * percent / 100].as_micros();
        (at(50), at(95))
    }
    let server = device_server().await;
    let mut joins = Vec::new();
    let mut devices = Vec::new();
    for _ in 0..100 {
        let (joined, took) = server.joined_device().await;
        joins.push(took);
        devices.push(joined);
    }
    let address = devices[0].quic_address().await.unwrap();
    let endpoint = device_endpoint(&devices[0]);
    let floor = ServerLeafFloor::default();
    let mut handshakes = Vec::new();
    let mut hellos = Vec::new();
    let mut pings = Vec::new();
    for _ in 0..50 {
        let started = Instant::now();
        let connection = infraternal_link::quic::connect(&endpoint, address, "localhost", &floor)
            .await
            .unwrap();
        handshakes.push(started.elapsed());
        let mut link = DeviceLink::open(connection, DEVICE).await.unwrap();
        hellos.push(started.elapsed());
        for _ in 0..5 {
            pings.push(link.ping().await.unwrap());
        }
        drop(link);
    }
    // Memory: hold one link per device, many devices, all from one client
    // endpoint (one socket, as one phone would have), and compare RSS. The
    // delta is both ends of each link: the server's and the client's.
    let configs: Vec<_> = devices
        .iter()
        .map(|joined| {
            infraternal_link::quic::client_config_with_liveness(
                &joined.identity,
                std::slice::from_ref(&joined.ca),
                Duration::from_secs(15),
                Duration::from_secs(60),
            )
            .unwrap()
        })
        .collect();
    // sleep: let the links dropped above finish closing before the baseline.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = rss();
    let mut held = Vec::new();
    for config in configs {
        let connection = endpoint
            .connect_with(config, address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut link = DeviceLink::open(connection, DEVICE).await.unwrap();
        link.ping().await.unwrap();
        held.push(link);
    }
    let after = rss();
    assert_eq!(server.listeners.diagnostic_devices.len(), devices.len());
    let (join50, join95) = percentiles(&mut joins);
    let (hs50, hs95) = percentiles(&mut handshakes);
    let (hello50, hello95) = percentiles(&mut hellos);
    let (ping50, ping95) = percentiles(&mut pings);
    eprintln!(
        "DEVICE-NUMBERS joins={} join_p50_us={join50} join_p95_us={join95} \
         dials={} quic_handshake_p50_us={hs50} quic_handshake_p95_us={hs95} \
         handshake_plus_hello_p50_us={hello50} handshake_plus_hello_p95_us={hello95} \
         ping_p50_us={ping50} ping_p95_us={ping95} held_links={} \
         rss_delta_bytes={} rss_per_link_bytes={}",
        joins.len(),
        handshakes.len(),
        held.len(),
        after.saturating_sub(before),
        after.saturating_sub(before) / u64::try_from(held.len()).unwrap()
    );
}

/// The join's verified certificate is exactly what the server stored for
/// the device, so the link's fingerprint admission matches the join.
#[tokio::test]
async fn the_joined_certificate_is_the_stored_one() {
    let server = device_server().await;
    let (joined, took) = server.joined_device().await;
    assert!(took < Duration::from_secs(10));
    let leaf: &CertificateDer<'_> = &joined.identity.chain[0];
    let fingerprint = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
    let stored: (String, Option<i64>) = sqlx::query_as(
        "SELECT key_algorithm, execution_uid FROM remote_certificates WHERE fingerprint=?",
    )
    .bind(fingerprint.as_ref())
    .fetch_one(&server.pool)
    .await
    .unwrap();
    assert_eq!(stored, ("p256".to_owned(), None));
}

/// A device removed between its admission and its signal's registration is
/// refused by the second ledger read; it does not keep a link for a recheck
/// period (J1242 F2).
#[tokio::test]
async fn a_removal_between_admission_and_registration_is_caught() {
    let server = device_server().await;
    let (joined, _) = server.joined_device().await;
    let leaf: &CertificateDer<'_> = &joined.identity.chain[0];
    let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
    let fingerprint: [u8; 32] = digest.as_ref().try_into().unwrap();
    let authority = crate::remote_device_link::admit(&server.store, &fingerprint)
        .await
        .unwrap();
    // The removal lands in the gap: no signal is registered yet, so nothing
    // is cut; only the ledger knows.
    sqlx::query("UPDATE remote_hosts SET revoked_at=? WHERE id=?")
        .bind(unix_now())
        .bind(joined.host_id.as_bytes().as_slice())
        .execute(&server.pool)
        .await
        .unwrap();
    assert!(
        crate::remote_device_link::watch_admitted(&server.store, &authority, &fingerprint)
            .await
            .is_err()
    );
}
