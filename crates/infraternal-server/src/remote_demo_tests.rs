//! Two-process operator enrollment and browser-to-PTY proof with memory-only CA fixture keys, #78.

use super::*;
use axum::{
    Router,
    extract::{ConnectInfo, Request, State, WebSocketUpgrade, ws},
    http::{HeaderValue, StatusCode, header},
    response::Response,
    routing::get,
};
use axum_server::{accept::Accept, tls_openssl::OpenSSLAcceptor};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use futures_util::{SinkExt, StreamExt};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use openssl::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    future::Future,
    io::Write,
    pin::Pin,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, client::IntoClientRequest},
};
use tower::ServiceExt;

type Browser = WebSocketStream<tokio_openssl::SslStream<tokio::net::TcpStream>>;
type NegotiatedAlpn = Arc<Mutex<Vec<Option<Vec<u8>>>>>;

/// Records protocols selected by the test TLS terminator for the real agent sockets.
#[derive(Clone)]
struct RecordingProxyAcceptor {
    inner: OpenSSLAcceptor<axum_server::accept::NoDelayAcceptor>,
    negotiated: NegotiatedAlpn,
}

impl<S> Accept<TcpStream, S> for RecordingProxyAcceptor
where
    S: Send + 'static,
{
    type Stream = tokio_openssl::SslStream<TcpStream>;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<(Self::Stream, S)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let accepted = self.inner.accept(stream, service);
        let negotiated = self.negotiated.clone();
        Box::pin(async move {
            let (stream, service) = accepted.await?;
            negotiated
                .lock()
                .unwrap()
                .push(stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec));
            Ok((stream, service))
        })
    }
}

#[derive(Clone)]
struct TlsProxyState {
    app: Router,
    backend: SocketAddr,
}

/// Accept both HTTP/2 and HTTP/1.1 at a TLS edge, then forward to the plain app listener.
fn tls_proxy(app: Router, backend: SocketAddr) -> Router {
    Router::new()
        .route("/remote/agent", get(proxy_websocket))
        .route("/v1/ws", get(proxy_websocket))
        .fallback(proxy_http)
        .with_state(TlsProxyState { app, backend })
}

async fn proxy_http(
    State(proxy): State<TlsProxyState>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    mut request: Request,
) -> Response {
    request.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_str(&client.ip().to_string()).unwrap(),
    );
    request
        .headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("https"));
    // The app sees the trusted local proxy as its TCP peer, as it does behind a TLS terminator.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 443))));
    proxy
        .app
        .oneshot(request)
        .await
        .unwrap_or_else(|never| match never {})
}

async fn proxy_websocket(
    State(proxy): State<TlsProxyState>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    upgrade: WebSocketUpgrade,
    request: Request,
) -> Response {
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", axum::http::uri::PathAndQuery::as_str);
    let mut upstream_request = format!("ws://{}{path}", proxy.backend)
        .into_client_request()
        .unwrap();
    for name in [header::ORIGIN, header::COOKIE] {
        if let Some(value) = request.headers().get(&name) {
            upstream_request.headers_mut().insert(name, value.clone());
        }
    }
    upstream_request.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_str(&client.ip().to_string()).unwrap(),
    );
    upstream_request
        .headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("https"));
    upgrade.on_upgrade(move |downstream| async move {
        let Ok((upstream, _)) = tokio_tungstenite::connect_async(upstream_request).await else {
            return;
        };
        bridge_proxy_websocket(downstream, upstream).await;
    })
}

async fn bridge_proxy_websocket(
    mut downstream: ws::WebSocket,
    mut upstream: WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
) {
    loop {
        tokio::select! {
            message = downstream.recv() => {
                let Some(Ok(message)) = message else {
                    let _ = upstream.close(None).await;
                    return;
                };
                let message = proxy_message_to_upstream(message);
                if upstream.send(message).await.is_err() {
                    return;
                }
            }
            message = upstream.next() => {
                let Some(Ok(message)) = message else {
                    let _ = downstream.close().await;
                    return;
                };
                let Some(message) = proxy_message_to_downstream(message) else {
                    continue;
                };
                if downstream.send(message).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn proxy_message_to_upstream(message: ws::Message) -> Message {
    match message {
        ws::Message::Text(text) => Message::Text(text.as_str().to_owned().into()),
        ws::Message::Binary(bytes) => Message::Binary(bytes),
        ws::Message::Ping(bytes) => Message::Ping(bytes),
        ws::Message::Pong(bytes) => Message::Pong(bytes),
        ws::Message::Close(frame) => Message::Close(frame.map(|frame| {
            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.as_str().to_owned().into(),
            }
        })),
    }
}

fn proxy_message_to_downstream(message: Message) -> Option<ws::Message> {
    Some(match message {
        Message::Text(text) => ws::Message::Text(text.as_str().to_owned().into()),
        Message::Binary(bytes) => ws::Message::Binary(bytes),
        Message::Ping(bytes) => ws::Message::Ping(bytes),
        Message::Pong(bytes) => ws::Message::Pong(bytes),
        Message::Close(frame) => ws::Message::Close(frame.map(|frame| ws::CloseFrame {
            code: frame.code.into(),
            reason: frame.reason.as_str().to_owned().into(),
        })),
        Message::Frame(_) => return None,
    })
}

/// Prove the front listener negotiates HTTP/2 and reaches its backend over the forwarded route.
async fn assert_tls_proxy_http2(address: SocketAddr, root: &X509) {
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::PEER);
    let mut trust = X509StoreBuilder::new().unwrap();
    trust.add_cert(root.clone()).unwrap();
    connector.set_cert_store(trust.build());
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let ssl = connector
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    let mut stream =
        tokio_openssl::SslStream::new(ssl, TcpStream::connect(address).await.unwrap()).unwrap();
    Pin::new(&mut stream).connect().await.unwrap();
    assert_eq!(
        stream.ssl().selected_alpn_protocol(),
        Some(b"h2".as_slice())
    );
    let (mut sender, connection) = h2::client::handshake(stream).await.unwrap();
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/healthz", address.port()))
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    connection.abort();
}

/// Copied process fixtures can run on the measurement host without a checkout.
fn fixture_repository() -> PathBuf {
    std::env::var_os("INFRATERNAL_REMOTE_FIXTURE_REPOSITORY").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
        PathBuf::from,
    )
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
            || PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/codex-scratch/ra6"),
            PathBuf::from,
        );
        let path = root.join(format!("{:08x}", rand::random::<u32>()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        set_private_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // Reuse the authenticated rendezvous cleanup; never match unrelated PIDs.
        let script = "import sys;sys.dont_write_bytecode=True;sys.path.insert(0,'scripts');from pathlib import Path;from agent_fixture import cleanup;cleanup(Path(sys.argv[1]))";
        let cleanup = Command::new("python3")
            .current_dir(fixture_repository())
            .args(["-c", script])
            .arg(self.0.join("s"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if cleanup.is_ok_and(|status| status.success()) {
            let _ = std::fs::remove_dir_all(&self.0);
        } else {
            eprintln!("remote fixture cleanup failed; private state retained for recovery");
        }
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Administrator(crate::ca::CaMaterial);
impl crate::ca_memory::AdministratorCaUnlock for Administrator {
    fn unlock(&self) -> Result<crate::ca::CaMaterial, crate::ca::CaError> {
        Ok(self.0.clone())
    }
}

async fn tls(address: SocketAddr, root: &X509) -> tokio_openssl::SslStream<tokio::net::TcpStream> {
    let mut config = SslConnector::builder(SslMethod::tls_client()).unwrap();
    config.set_verify(SslVerifyMode::PEER);
    let mut trust = X509StoreBuilder::new().unwrap();
    trust.add_cert(root.clone()).unwrap();
    config.set_cert_store(trust.build());
    let ssl = config
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.set_nodelay(true).unwrap();
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).unwrap();
    std::pin::Pin::new(&mut stream).connect().await.unwrap();
    stream
}

async fn invitation(
    address: SocketAddr,
    root: &X509,
    origin: &str,
    cookie: &str,
    host: uuid::Uuid,
    expected_key_digest: [u8; 32],
) -> Vec<u8> {
    invitation_for_uid(
        address,
        root,
        origin,
        cookie,
        host,
        nix::unistd::Uid::effective().as_raw(),
        expected_key_digest,
    )
    .await
}

async fn invitation_for_uid(
    address: SocketAddr,
    root: &X509,
    origin: &str,
    cookie: &str,
    host: uuid::Uuid,
    uid: u32,
    expected_key_digest: [u8; 32],
) -> Vec<u8> {
    use http_body_util::BodyExt;
    let stream = tls(address, root).await;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    let task = tokio::spawn(connection);
    let body = serde_json::to_vec(
        &serde_json::json!({"host_id":host,"mode":"rootless","execution_uid":uid,"expected_key_digest":expected_key_digest}),
    )
    .unwrap();
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/remote/invitations")
        .header("host", format!("localhost:{}", address.port()))
        .header("origin", origin)
        .header("cookie", format!("__Host-infraternal={cookie}"))
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let bytes = http_body_util::Limited::new(response.into_body(), 8192)
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    task.abort();
    bytes
}

/// Model the verified-SSH key preparation before issuing the integration invitation.
fn prepare_pending_join_key(data: &Path) -> [u8; 32] {
    std::fs::DirBuilder::new().mode(0o700).create(data).unwrap();
    let key = PKey::generate_ed25519().unwrap();
    let mut private = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(data.join("join-key.pk8"))
        .unwrap();
    private
        .write_all(&key.private_key_to_pkcs8().unwrap())
        .unwrap();
    private.sync_all().unwrap();
    std::fs::File::open(data).unwrap().sync_all().unwrap();
    let public = key.raw_public_key().unwrap();
    openssl::sha::sha256(&public)
}

async fn send(browser: &mut Browser, stream: u32, frame: &Frame<'_>) {
    let mut wire = Vec::new();
    encode_muxed_frame_into(stream, frame, &mut wire).unwrap();
    browser.send(Message::Binary(wire.into())).await.unwrap();
}
async fn next(browser: &mut Browser) -> bytes::Bytes {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), browser.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            Message::Binary(bytes) => {
                // The replacement server can prove browser liveness while host
                // admission is pending. Answer it without issuing another open.
                if let Ok(decoded) = decode_muxed_frame(&bytes)
                    && decoded.stream_id == 0
                    && let Frame::Ping { nonce, sent_us } = decoded.frame
                {
                    send(browser, 0, &Frame::Pong { nonce, sent_us }).await;
                    continue;
                }
                return bytes;
            }
            Message::Ping(bytes) => browser.send(Message::Pong(bytes)).await.unwrap(),
            Message::Close(_) => panic!("browser transport closed"),
            _ => {}
        }
    }
}

struct Fixture {
    signer: Arc<crate::ca_memory::MemoryCaSource>,
    material: crate::ca::CaMaterial,
    identity: infraternal_agent::remote_tls::Identity,
    pool: sqlx::SqlitePool,
    root: X509,
    cookie: String,
    address: SocketAddr,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    proxy_backend: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    proxy_alpn: Option<NegotiatedAlpn>,
    listeners: Option<crate::remote_runtime::RemoteListeners>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        if let Some(backend) = &self.proxy_backend {
            backend.abort();
        }
    }
}

async fn fixture(directory: &Directory) -> Fixture {
    fixture_at(
        directory,
        "127.0.0.1:4701".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
}

async fn fixture_at(directory: &Directory, address: SocketAddr, endpoint: SocketAddr) -> Fixture {
    fixture_at_with_lock(directory, address, endpoint, false).await
}

async fn fixture_at_with_lock(
    directory: &Directory,
    address: SocketAddr,
    endpoint: SocketAddr,
    cold_locked: bool,
) -> Fixture {
    fixture_at_with_options(directory, address, endpoint, cold_locked, false).await
}

async fn fixture_at_through_tls_proxy(
    directory: &Directory,
    address: SocketAddr,
    endpoint: SocketAddr,
) -> Fixture {
    fixture_at_with_options(directory, address, endpoint, false, true).await
}

#[allow(clippy::too_many_lines)]
async fn fixture_at_with_options(
    directory: &Directory,
    address: SocketAddr,
    endpoint: SocketAddr,
    cold_locked: bool,
    behind_proxy: bool,
) -> Fixture {
    let backend_listener = if behind_proxy {
        Some(TcpListener::bind("127.0.0.1:0").await.unwrap())
    } else {
        None
    };
    let listen = backend_listener
        .as_ref()
        .map_or(address, |listener| listener.local_addr().unwrap());
    let server_data = directory.0.join("server");
    let pool = open_database(&server_data).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('owner','owner',1,'unused','owner','Owner')").execute(&pool).await.unwrap();
    let cookie = B64.encode(rand::random::<[u8; 32]>());
    let now = unix_seconds().unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'owner','fixture',?,?,1)")
        .bind(crate::auth::hash(&cookie)).bind(now+3600).bind(now).execute(&pool).await.unwrap();
    let (identity, material) = crate::remote_runtime::tests::server_material();
    let root = material.issuer().clone();
    let signer = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(root.clone()));
    if !cold_locked {
        signer
            .unlock_from(&Administrator(material.clone()))
            .unwrap();
    }
    let origin = if address.port() == 443 {
        "https://localhost".to_owned()
    } else {
        format!("https://localhost:{}", address.port())
    };
    let config = ServerConfig {
        listen,
        data_dir: server_data,
        public_origin: origin,
        web_root: std::env::var_os("INFRATERNAL_REMOTE_BROWSER_PROOF")
            .map(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/tracer/dist")),
        tls: (!behind_proxy).then(|| TlsFiles {
            certificate: "unused".into(),
            private_key: "unused".into(),
        }),
        behind_proxy,
        trusted_proxies: if behind_proxy {
            vec!["127.0.0.1".parse().unwrap()]
        } else {
            vec![]
        },
    };
    let http_tls = axum_server::tls_openssl::OpenSSLConfig::from_der(
        &identity.certificate.to_der().unwrap(),
        &identity.key.private_key_to_der().unwrap(),
    )
    .unwrap();
    let service = crate::remote_runtime::RemoteService {
        ca_administration: None,
        enrollment: crate::remote_http::EnrollmentService {
            source: signer.clone(),
            endpoint: crate::remote_http::EnrollmentEndpoint {
                ca_der: root.to_der().unwrap(),
                endpoint,
                server_name: "localhost".into(),
            },
        },
        identity: Some(infraternal_agent::remote_tls::Identity {
            certificate: identity.certificate.clone(),
            key: identity.key.clone(),
        }),
        roots: vec![root.clone()],
    };
    let (app, setup, listeners, _) = build_router_core(
        config,
        Some(EmbeddedAgent::unavailable()),
        Some(service.enrollment.clone()),
        Some(service),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(setup.is_none());
    if std::env::var_os("INFRATERNAL_REMOTE_FORCE_TCP").is_some() {
        listeners.as_ref().unwrap().refuse_quic();
    }
    let (server, proxy_backend, proxy_alpn) = if let Some(backend_listener) = backend_listener {
        let backend_address = backend_listener.local_addr().unwrap();
        let backend_app = app.clone();
        let backend = tokio::spawn(async move {
            axum::serve(
                backend_listener,
                backend_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        let listener = std::net::TcpListener::bind(address).unwrap();
        listener.set_nonblocking(true).unwrap();
        let negotiated = Arc::new(Mutex::new(Vec::new()));
        let proxy_server = tokio::spawn(
            axum_server::from_tcp(listener)
                .unwrap()
                .acceptor(RecordingProxyAcceptor {
                    inner: OpenSSLAcceptor::new(http_tls)
                        .acceptor(axum_server::accept::NoDelayAcceptor::new()),
                    negotiated: negotiated.clone(),
                })
                .serve(
                    tls_proxy(app, backend_address)
                        .into_make_service_with_connect_info::<SocketAddr>(),
                ),
        );
        (proxy_server, Some(backend), Some(negotiated))
    } else {
        let listener = std::net::TcpListener::bind(address).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = tokio::spawn(
            axum_server::from_tcp(listener)
                .unwrap()
                .acceptor(crate::server_tls::acceptor(http_tls))
                .serve(app.into_make_service_with_connect_info::<SocketAddr>()),
        );
        (server, None, None)
    };
    Fixture {
        signer,
        material,
        identity,
        pool,
        root,
        cookie,
        address,
        server,
        proxy_backend,
        proxy_alpn,
        listeners,
    }
}

async fn browser(address: SocketAddr, root: &X509, origin: &str, cookie: &str) -> Browser {
    let websocket_url = format!("wss://localhost:{}/v1/ws", address.port());
    let mut request = websocket_url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("origin", origin.parse().unwrap());
    request.headers_mut().insert(
        "cookie",
        format!("__Host-infraternal={cookie}").parse().unwrap(),
    );
    let (mut browser, _) = tokio_tungstenite::client_async(request, tls(address, root).await)
        .await
        .unwrap();
    assert!(matches!(
        decode_muxed_frame(&next(&mut browser).await).unwrap().frame,
        Frame::Hello { version: 1, .. }
    ));
    send(
        &mut browser,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "remote-demo",
        },
    )
    .await;
    assert!(matches!(
        decode_muxed_frame(&next(&mut browser).await).unwrap().frame,
        Frame::Welcome { .. }
    ));
    browser
}

#[tokio::test]
#[ignore = "requires exclusive loopback port 4701"]
async fn agent_websocket_upgrade_uses_the_app_listener_and_starts_key_proof() {
    let directory = Directory::new();
    let fixture = fixture(&directory).await;
    infraternal_agent::remote_websocket::preflight(
        "https://localhost:4701",
        Some(&fixture.root),
        false,
    )
    .await
    .expect("target preflight must complete the app's WebSocket challenge");
    let request = "wss://localhost:4701/remote/agent"
        .into_client_request()
        .unwrap();
    // This TLS connector has ordinary server trust and no client certificate.
    // Agent identity must be proved after the application's WebSocket upgrade.
    let upgraded =
        tokio_tungstenite::client_async(request, tls(fixture.address, &fixture.root).await).await;
    assert!(
        upgraded.is_ok(),
        "the app listener must upgrade the agent WebSocket: {:?}",
        upgraded.err()
    );
    let (mut socket, _) = upgraded.unwrap();
    let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Text(challenge) = message else {
        panic!("the app listener did not send its agent key challenge");
    };
    let challenge: infraternal_plugin_remote::agent_link::AgentLinkChallenge =
        serde_json::from_str(&challenge).unwrap();
    assert_eq!(challenge.message_type, "challenge");
    assert_eq!(B64.decode(challenge.nonce).unwrap().len(), 32);
    socket.close(None).await.unwrap();
}

async fn open_remote(browser: &mut Browser, host: uuid::Uuid, started: Instant) -> uuid::Uuid {
    open_remote_with_budget(browser, host, started, Duration::from_secs(10)).await
}

/// Release outage checks allow the complete bounded reconnect backoff.
async fn open_remote_with_budget(
    browser: &mut Browser,
    host: uuid::Uuid,
    started: Instant,
    budget: Duration,
) -> uuid::Uuid {
    try_open_remote_with_budget(browser, host, started, budget)
        .await
        .expect("remote host did not register")
}

async fn try_open_remote_with_budget(
    browser: &mut Browser,
    host: uuid::Uuid,
    started: Instant,
    budget: Duration,
) -> Option<uuid::Uuid> {
    // Retry only host admission, without creating any successful duplicate PTYs.
    let mut first_refusal = None;
    loop {
        if started.elapsed() >= budget {
            eprintln!("remote open first refusal: {first_refusal:?}");
            return None;
        }
        let input = serde_json::json!({"host_id":host}).to_string();
        send(
            browser,
            0,
            &Frame::Call {
                call_id: 1,
                action_id: "ssh.session.open",
                input_json: input.as_bytes(),
            },
        )
        .await;
        let wire = next(browser).await;
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Result { ok: true, json, .. } => {
                let result: serde_json::Value = serde_json::from_slice(json).unwrap();
                return Some(
                    uuid::Uuid::parse_str(result["session_id"].as_str().unwrap()).unwrap(),
                );
            }
            Frame::Result {
                ok: false, json, ..
            } if first_refusal.is_none() => {
                first_refusal = Some(String::from_utf8_lossy(json).into_owned());
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn until(browser: &mut Browser, output: &mut Vec<u8>, cursor: &mut u64, marker: &[u8]) {
    loop {
        let wire = next(browser).await;
        if let Frame::Output { out_seq, bytes } = decode_muxed_frame(&wire).unwrap().frame {
            assert_eq!(out_seq, *cursor, "lost or duplicated remote output");
            *cursor += bytes.len() as u64;
            output.extend_from_slice(bytes);
            if output.windows(marker.len()).any(|window| window == marker) {
                break;
            }
        }
    }
}

/// Wait for the shell's first output without assuming which shell owns the account.
async fn first_terminal_output(browser: &mut Browser, output: &mut Vec<u8>, cursor: &mut u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let wire = next(browser).await;
            if let Frame::Output { out_seq, bytes } = decode_muxed_frame(&wire).unwrap().frame {
                assert_eq!(out_seq, *cursor, "lost or duplicated remote output");
                *cursor += bytes.len() as u64;
                output.extend_from_slice(bytes);
                if !bytes.is_empty() {
                    break;
                }
            }
        }
    })
    .await
    .expect("terminal shell produced no initial output");
}

/// A missing socket path is insufficient proof: a failed helper could leave detached shims alive.
fn remaining_shims(state: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;
    let expected = state.as_os_str().as_bytes();
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            let Ok(command) = std::fs::read(entry.path().join("cmdline")) else {
                return false;
            };
            let args: Vec<_> = command.split(|byte| *byte == 0).collect();
            args.contains(&b"__shim".as_slice())
                && args
                    .windows(2)
                    .any(|pair| pair[0] == b"--state" && pair[1] == expected)
        })
        .count()
}

/// Observe the real CLI after startup has drained; the canary opens no application socket.
async fn idle_canary(process: &Process) {
    if std::env::var_os("INFRATERNAL_REMOTE_IDLE_CANARY").is_none() {
        return;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    let pid = process.0.id();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let rss = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap();
    println!(
        "remote_idle {rss} scale=1 full_daemon=true harness_profile={} cli_profile=external_artifact",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    let result = tokio::process::Command::new("python3")
        .args([
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/idle_canary.py")
                .to_str()
                .unwrap(),
            "--pid",
            &pid.to_string(),
            "--label",
            "remote infraternal agent",
            "--seconds",
            "10",
            "--events",
        ])
        .output()
        .await
        .unwrap();
    if !result.status.success() {
        eprint!("{}", String::from_utf8_lossy(&result.stderr));
    }
    assert!(
        result.status.success(),
        "remote infraternal agent idle canary failed"
    );
    print!("{}", String::from_utf8(result.stdout).unwrap());
}

/// A registered, connected host still belongs only to its durable owner.
async fn foreign_owner_cannot_open(fixture: &Fixture, host: uuid::Uuid, origin: &str) {
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('viewer','viewer',0,'unused','viewer','Viewer')")
        .execute(&fixture.pool).await.unwrap();
    let cookie = B64.encode(rand::random::<[u8; 32]>());
    let now = unix_seconds().unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'viewer','fixture',?,?,1)")
        .bind(crate::auth::hash(&cookie)).bind(now+3600).bind(now).execute(&fixture.pool).await.unwrap();
    let mut client = browser(fixture.address, &fixture.root, origin, &cookie).await;
    let input = serde_json::json!({"host_id":host}).to_string();
    send(
        &mut client,
        0,
        &Frame::Call {
            call_id: 1,
            action_id: "ssh.session.open",
            input_json: input.as_bytes(),
        },
    )
    .await;
    assert!(matches!(
        decode_muxed_frame(&next(&mut client).await).unwrap().frame,
        Frame::Result {
            call_id: 1,
            ok: false,
            ..
        }
    ));
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(before, after, "foreign owner created a remote session");
    println!("remote_authority foreign_owner_denied=true session_count_unchanged=true");
}

/// The production browser receives the existing session and cookie over private stdin only.
async fn browser_proof(fixture: &Fixture, host: uuid::Uuid, session: uuid::Uuid) {
    use tokio::io::AsyncWriteExt;
    if std::env::var_os("INFRATERNAL_REMOTE_BROWSER_PROOF").is_none() {
        return;
    }
    let mut child = tokio::process::Command::new("bun")
        .current_dir(fixture_repository())
        .arg("scripts/verify-remote-browser.mjs")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let private = serde_json::to_vec(&serde_json::json!({
        "cookie":fixture.cookie,"host":host,"session":session,
        "resolver_address": (!fixture.address.ip().is_loopback()).then(|| fixture.address.ip().to_string()),
        "screenshot_prefix": if fixture.address.ip().is_loopback() { "run7-real-remote" } else { "run8-o1-real-remote" }
    }))
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&private)
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(90), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    print!("{}", String::from_utf8(result.stdout).unwrap());
    if !result.status.success() {
        eprint!("{}", String::from_utf8_lossy(&result.stderr));
    }
    assert!(
        result.status.success(),
        "real remote browser fixture failed"
    );
    let writers: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT writer_id,input_acked FROM terminal_writers WHERE session_id=? ORDER BY writer_id",
    )
    .bind(session.as_bytes().as_slice())
    .fetch_all(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(
        writers.len(),
        3,
        "devices did not retain independent writers"
    );
    for (id, ack) in writers {
        assert!(id > 0);
        assert!(u64::from_be_bytes(ack.try_into().unwrap()) > 0);
    }
    println!("remote_browser durable_writers=3 independently_acked=true");
}

/// Keep join and restart process isolation identical, including the shell fixture profile.
fn cli(binary: &Path, directory: &Directory, join: bool, public_origin: &str) -> Process {
    let mut command = Command::new(binary);
    command
        .args(["agent", "--data"])
        .arg(directory.0.join("data"))
        .arg("--state")
        .arg(directory.0.join("s"));
    if join {
        command
            .arg("join")
            .arg(format!("{public_origin}/remote/join"));
    } else {
        command.arg("run");
    }
    Process(
        command
            .env(
                "ZDOTDIR",
                fixture_repository().join("crates/infraternal/tests/profile"),
            )
            .stdin(Stdio::piped())
            .stdout(
                if std::env::var_os("INFRATERNAL_RECONNECT_CONTROL").is_some() {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .stderr(
                if std::env::var_os("INFRATERNAL_RECONNECT_CONTROL").is_some()
                    || std::env::var_os("INFRATERNAL_REMOTE_LINK_TRACE").is_some()
                {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .spawn()
            .unwrap(),
    )
}

/// Restart only the supervising process; preserve its enrolled identity and live shim.
// The proof passes the live fixture state directly so restart behavior stays visible in one place.
#[allow(clippy::too_many_arguments)]
async fn restart_proof(
    directory: &Directory,
    binary: &Path,
    child: &mut Process,
    browser: &mut Browser,
    output: &mut Vec<u8>,
    cursor: &mut u64,
    in_seq: u64,
    public_origin: &str,
) {
    if std::env::var_os("INFRATERNAL_REMOTE_RESTART_PROOF").is_none() {
        return;
    }
    let command = b"printf 'RESTART_%s\\n' BEGIN; sleep 0.5; printf 'RESTART_%s\\n' END\n";
    send(
        browser,
        1,
        &Frame::Input {
            in_seq,
            bytes: command,
        },
    )
    .await;
    until(browser, output, cursor, b"RESTART_BEGIN").await;
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let stopped = Instant::now();
    // The shim must produce END while its supervising process is absent.
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert_eq!(remaining_shims(&directory.0.join("s")), 1);
    *child = cli(binary, directory, false, public_origin);
    let restarted = Instant::now();
    until(browser, output, cursor, b"RESTART_END").await;
    println!(
        "remote_restart recovery_us={} disconnected_us={} output_bytes={cursor} lost=0 duplicated=0 shims=1 load={}",
        restarted.elapsed().as_micros(),
        stopped.elapsed().as_micros(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}

#[tokio::test]
#[ignore = "two-process proof requires INFRATERNAL_REMOTE_TEST_BINARY and exclusive port 4701"]
async fn remote_cli_enrollment_and_browser_terminal_two_processes() {
    let binary = PathBuf::from(
        std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").expect("real CLI binary required"),
    );
    assert!(binary.is_file());
    remote_cli_enrollment_and_browser_terminal_at(
        &binary,
        "127.0.0.1:4701".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        false,
    )
    .await;
}

#[tokio::test]
#[ignore = "Run via scripts/verify-addhost-https-namespace with TCP/UDP 7443 blackholed and app HTTPS on 443"]
async fn remote_cli_enrollment_and_browser_terminal_443_without_agent_port() {
    let binary = PathBuf::from(
        std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").expect("real CLI binary required"),
    );
    assert!(binary.is_file());
    assert_ne!(
        nix::unistd::Uid::effective().as_raw(),
        0,
        "rootless fixture required"
    );
    remote_cli_enrollment_and_browser_terminal_at(
        &binary,
        "127.0.0.1:443".parse().unwrap(),
        "127.0.0.1:7443".parse().unwrap(),
        false,
    )
    .await;
}

#[tokio::test]
#[ignore = "Run via scripts/verify-addhost-https-namespace with TCP/UDP 7443 blackholed and a TLS HTTP/2 proxy on 443"]
async fn remote_cli_enrollment_and_browser_terminal_443_through_tls_http2_proxy() {
    let binary = PathBuf::from(
        std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").expect("real CLI binary required"),
    );
    assert!(binary.is_file());
    assert_ne!(
        nix::unistd::Uid::effective().as_raw(),
        0,
        "rootless fixture required"
    );
    remote_cli_enrollment_and_browser_terminal_at(
        &binary,
        "127.0.0.1:443".parse().unwrap(),
        "127.0.0.1:7443".parse().unwrap(),
        true,
    )
    .await;
}

/// Exercise enrollment and a real PTY through a chosen public app-listener port.
// Keep the complete cross-process proof together so its ordering remains auditable.
#[allow(clippy::too_many_lines)]
async fn remote_cli_enrollment_and_browser_terminal_at(
    binary: &Path,
    address: SocketAddr,
    endpoint: SocketAddr,
    through_tls_proxy: bool,
) {
    let directory = Directory::new();
    let mut fixture = if through_tls_proxy {
        fixture_at_through_tls_proxy(&directory, address, endpoint).await
    } else {
        fixture_at(&directory, address, endpoint).await
    };
    if through_tls_proxy {
        assert_tls_proxy_http2(fixture.address, &fixture.root).await;
    }
    // Current terminal authorization resolves the account UUID and preferred OS
    // username. Keep the acceptance fixture shaped like a real passkey user.
    let owner = uuid::Uuid::new_v4().to_string();
    let account = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap()
        .name;
    sqlx::query("UPDATE users SET owner=0 WHERE id='owner'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'owner',1,'unused',?,'Owner')")
        .bind(&owner)
        .bind(account)
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE sessions SET user_id=? WHERE token_hash=?")
        .bind(owner)
        .bind(crate::auth::hash(&fixture.cookie))
        .execute(&fixture.pool)
        .await
        .unwrap();
    let root = fixture.root.clone();
    let cookie = fixture.cookie.clone();
    let address = fixture.address;
    let origin = if address.port() == 443 {
        "https://localhost".to_owned()
    } else {
        format!("https://localhost:{}", address.port())
    };
    let host = uuid::Uuid::new_v4();
    let owner_marker = directory.0.join(".bootstrap-owner");
    std::fs::write(&owner_marker, format!("{}\n", host.simple())).unwrap();
    std::fs::set_permissions(&owner_marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    let data = directory.0.join("data");
    let expected_key_digest = prepare_pending_join_key(&data);
    let invitation = invitation(address, &root, &origin, &cookie, host, expected_key_digest).await;
    let started = Instant::now();
    let mut child = cli(binary, &directory, true, &origin);
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(&invitation)
        .unwrap();
    drop(invitation);
    let mut browser = browser(address, &root, &origin, &cookie).await;
    let session = try_open_remote_with_budget(
        &mut browser,
        host,
        started,
        Duration::from_secs(10),
    )
    .await
    .unwrap_or_else(|| {
        let status = child.0.try_wait().ok().flatten();
        let child_exited = status.is_some();
        let child_exit_code = status.and_then(|status| status.code());
        let identity_published = directory.0.join("data/identity.json").is_file();
        panic!(
            "remote host did not register; child_exited={child_exited} child_exit_code={child_exit_code:?} identity_published={identity_published}"
        );
    });
    let join_us = started.elapsed().as_micros();
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT remote_host_id FROM terminal_sessions WHERE id=?")
            .bind(session.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(stored, host.as_bytes());
    let identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.0.join("data/identity.json")).unwrap())
            .unwrap();
    assert_eq!(identity["public_origin"], origin);
    assert!(identity["endpoint"].is_null());
    send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: session.as_bytes(),
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    send(&mut browser, 1, &Frame::Credit { bytes: 1024 * 1024 }).await;
    let mut output = Vec::new();
    let mut cursor = 0;
    first_terminal_output(&mut browser, &mut output, &mut cursor).await;
    idle_canary(&child).await;
    let entered = b"printf 'REMOTE_%s\\n' OK\n";
    let keystroke = Instant::now();
    send(
        &mut browser,
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: entered,
        },
    )
    .await;
    until(&mut browser, &mut output, &mut cursor, b"REMOTE_OK").await;
    println!(
        "remote_demo control_processes=2 rootless=true join_to_terminal_us={join_us} keystroke_roundtrip_us={} output_bytes={cursor} lost=0 duplicated=0 load={}",
        keystroke.elapsed().as_micros(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    foreign_owner_cannot_open(&fixture, host, &origin).await;
    browser_proof(&fixture, host, session).await;
    restart_proof(
        &directory,
        binary,
        &mut child,
        &mut browser,
        &mut output,
        &mut cursor,
        entered.len() as u64,
        &origin,
    )
    .await;
    drop(browser);
    drop(child);
    if through_tls_proxy {
        let protocols = fixture.proxy_alpn.as_ref().unwrap().lock().unwrap().clone();
        assert!(
            protocols
                .iter()
                .any(|protocol| protocol.as_deref() == Some(b"h2")),
            "the TLS proxy did not negotiate HTTP/2 for its h2 probe"
        );
        let http1_count = protocols
            .iter()
            .filter(|protocol| protocol.as_deref() == Some(b"http/1.1"))
            .count();
        assert!(
            http1_count >= 3,
            "the enrolling infraternal agent must select HTTP/1.1 for enrollment, preflight, and its steady-state link; negotiated {protocols:?}"
        );
        println!(
            "tls_proxy h2_probe=true agent_http1_connections={http1_count} trusted_proxy=true"
        );
    }
    fixture.server.abort();
    let _ = (&mut fixture.server).await;
    fixture.listeners.take();
    fixture.pool.close().await;
    let state = directory.0.join("s");
    drop(directory);
    assert_eq!(remaining_shims(&state), 0, "fixture left a surviving shim");
}

#[path = "remote_host_tests.rs"]
mod real_host;

#[path = "remote_cold_tests.rs"]
mod cold_start;

#[path = "remote_live_renewal_tests.rs"]
mod renewal;

#[path = "remote_renewal_ack_tests.rs"]
mod renewal_ack;

#[path = "remote_renewal_cli_tests.rs"]
mod renewal_cli;

#[path = "remote_shipping_route_tests.rs"]
mod shipping_route;
