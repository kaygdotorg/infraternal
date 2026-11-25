//! The HTTPS agent link runs leg-B mutual TLS inside its WebSocket (#559):
//! real `/remote/agent` routes behind real HTTPS acceptors or a
//! TLS-terminating reverse proxy, real listeners whose acceptor the route
//! uses, the real infraternal agent `connect`, and relays in between that hold
//! an HTTPS certificate the agent trusts.
//!
//! Every socket here is on 127.0.0.1; nothing leaves the host.
use super::*;
use infraternal_agent::{
    remote_tls::TcpTls,
    remote_websocket::{self, WebSocketCarrier, carrier_config},
    server_leaf_floor::ServerLeafFloor,
};
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// Unix seconds now.
fn now() -> i64 {
    crate::runtime::unix_seconds().unwrap()
}

/// The `client_info` every test agent sends in its Hello. A relay that ever
/// sees it in clear text has read the link.
const MARKER: &str = "j1201-https-link-marker";

/// One server: its leg-B listeners (whose acceptor `/remote/agent` uses)
/// and an HTTPS or plain-HTTP app listener with the agent route.
struct Server {
    /// Keeps the leg-B listeners (and so the current acceptor) alive.
    listeners: RemoteListeners,
    /// The app listener's address.
    app: SocketAddr,
    /// The app listener's task.
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start a server serving leg-B `leaf`, whose app listener terminates TLS
/// with `https` (as `config.tls` does), or speaks plain HTTP when `https` is
/// `None` (behind a reverse proxy).
async fn start_server(
    leaf: &Identity,
    root: &X509,
    store: EnrollmentStore,
    https: Option<&Identity>,
) -> Server {
    let hosts = RemoteHosts::default();
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        leaf,
        std::slice::from_ref(root),
        store.clone(),
        hosts.clone(),
    )
    .await
    .unwrap();
    let app = crate::remote_agent_http::router(hosts, store)
        .into_make_service_with_connect_info::<SocketAddr>();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let task = if let Some(https) = https {
        let config = axum_server::tls_openssl::OpenSSLConfig::from_der(
            &https.certificate.to_der().unwrap(),
            &https.key.private_key_to_der().unwrap(),
        )
        .unwrap();
        tokio::spawn(async move {
            let _ = axum_server::from_tcp(listener)
                .unwrap()
                .acceptor(crate::server_tls::acceptor(config))
                .serve(app)
                .await;
        })
    } else {
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        })
    };
    Server {
        listeners,
        app: address,
        task,
    }
}

/// A TLS acceptor presenting `certificate`, as a proxy or relay would.
fn outer_acceptor(certificate: &Identity) -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(&certificate.certificate).unwrap();
    acceptor.set_private_key(&certificate.key).unwrap();
    acceptor.build()
}

/// A TLS-terminating proxy at a fresh address: it presents `certificate` to
/// whoever connects and forwards the decrypted bytes to `upstream`, over a new
/// TLS session when `upstream_tls` (a relay in front of a `config.tls`
/// server) or as plain TCP (a reverse proxy in front of a plain-HTTP server).
/// Every byte it reads from the agent in clear text is recorded in the
/// returned capture, one entry per connection.
async fn proxy(
    certificate: &Identity,
    upstream: SocketAddr,
    upstream_tls: bool,
) -> (SocketAddr, Capture, tokio::task::JoinHandle<()>) {
    let acceptor = outer_acceptor(certificate);
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    // The relay does not care whom it talks to upstream.
    connector.set_verify(SslVerifyMode::NONE);
    let connector = connector.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let capture = Capture::default();
    let captured = capture.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let connector = connector.clone();
            let capture = captured.clone();
            tokio::spawn(async move {
                let capture = capture.connection();
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut downstream = tokio_openssl::SslStream::new(ssl, socket).unwrap();
                if std::pin::Pin::new(&mut downstream).accept().await.is_err() {
                    return;
                }
                let Ok(upstream) = TcpStream::connect(upstream).await else {
                    return;
                };
                if upstream_tls {
                    let ssl = connector
                        .configure()
                        .unwrap()
                        .into_ssl("localhost")
                        .unwrap();
                    let mut upstream = tokio_openssl::SslStream::new(ssl, upstream).unwrap();
                    if std::pin::Pin::new(&mut upstream).connect().await.is_ok() {
                        relay(downstream, upstream, capture).await;
                    }
                } else {
                    relay(downstream, upstream, capture).await;
                }
            });
        }
    });
    (address, capture, task)
}

/// The bytes one proxied connection read from the agent.
type Recorded = Arc<Mutex<Vec<u8>>>;

/// What a proxy decrypted from the agent: the bytes of each connection.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Recorded>>>);

impl Capture {
    /// Start recording a new connection.
    fn connection(&self) -> Recorded {
        let connection = Arc::default();
        self.0.lock().unwrap().push(Arc::clone(&connection));
        connection
    }

    /// The WebSocket payload each connection carried, unmasked.
    fn payloads(&self) -> Vec<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|connection| unmasked_payload(&connection.lock().unwrap()))
            .collect()
    }
}

/// The concatenated payload of the binary (and continuation) WebSocket
/// frames after the HTTP upgrade request in `capture`, with the client's
/// masks removed: what the agent put inside the WebSocket.
fn unmasked_payload(capture: &[u8]) -> Vec<u8> {
    let Some(start) = capture.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Vec::new();
    };
    let mut rest = &capture[start + 4..];
    let mut payload = Vec::new();
    while rest.len() >= 2 {
        let opcode = rest[0] & 0x0f;
        let masked = rest[1] & 0x80 != 0;
        let (length, mut at) = match rest[1] & 0x7f {
            126 if rest.len() >= 4 => (usize::from(u16::from_be_bytes([rest[2], rest[3]])), 4),
            127 if rest.len() >= 10 => (
                usize::try_from(u64::from_be_bytes(rest[2..10].try_into().unwrap())).unwrap(),
                10,
            ),
            126 | 127 => break,
            short => (usize::from(short), 2),
        };
        let mask = if masked {
            let Some(mask) = rest.get(at..at + 4) else {
                break;
            };
            at += 4;
            [mask[0], mask[1], mask[2], mask[3]]
        } else {
            [0; 4]
        };
        let Some(data) = rest.get(at..at + length) else {
            break;
        };
        if opcode == 0 || opcode == 2 {
            payload.extend(
                data.iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % 4]),
            );
        }
        rest = &rest[at + length..];
    }
    payload
}

/// Check that every connection in `capture` carried TLS records inside its
/// WebSocket and never the agent's Hello in clear text.
fn assert_only_inner_ciphertext(capture: &Capture, who: &str) {
    let payloads = capture.payloads();
    assert!(!payloads.is_empty(), "the {who} carried no connection");
    for payload in payloads {
        // A TLS handshake record (type 22) opens the inner stream, so the
        // frame parser above really saw the agent's bytes.
        assert_eq!(payload.first(), Some(&0x16), "the {who} saw no inner TLS");
        assert!(
            !payload
                .windows(MARKER.len())
                .any(|window| window == MARKER.as_bytes()),
            "the {who} read the agent's Hello in clear text"
        );
    }
}

/// Copy both ways until either side ends, recording the agent's bytes.
async fn relay<D, U>(downstream: D, upstream: U, capture: Recorded)
where
    D: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut agent_read, mut agent_write) = tokio::io::split(downstream);
    let (mut server_read, mut server_write) = tokio::io::split(upstream);
    let up = async {
        let mut buffer = vec![0; 16 * 1024];
        while let Ok(read) = agent_read.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            capture.lock().unwrap().extend_from_slice(&buffer[..read]);
            if server_write.write_all(&buffer[..read]).await.is_err() {
                break;
            }
        }
    };
    let down = tokio::io::copy(&mut server_read, &mut agent_write);
    tokio::select! {
        () = up => {}
        _ = down => {}
    }
}

/// A relay that holds an HTTPS certificate the agent trusts and answers
/// `/remote/agent` itself, running the inner TLS with `inner` (which is not
/// the server's CA-issued leaf; the relay has no such key). It trusts the
/// agent's CA so that only the agent's own checks can stop it.
async fn impostor(
    outer: &Identity,
    inner: &Identity,
    root: &X509,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let acceptor = outer_acceptor(outer);
    let inner = Arc::new(remote_tls::server_config(inner, std::slice::from_ref(root)).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let inner = inner.clone();
            tokio::spawn(async move {
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut outer = tokio_openssl::SslStream::new(ssl, socket).unwrap();
                if std::pin::Pin::new(&mut outer).accept().await.is_err() {
                    return;
                }
                let Ok(socket) =
                    tokio_tungstenite::accept_async_with_config(outer, Some(carrier_config()))
                        .await
                else {
                    return;
                };
                let _ =
                    remote_tls::accept_over(WebSocketCarrier::new(socket).into_carrier(), &inner)
                        .await;
            });
        }
    });
    (address, task)
}

/// What one infraternal agent knows: its identity and enrollment trust.
struct Agent {
    identity: Identity,
    root: X509,
    floor: ServerLeafFloor,
}

impl Agent {
    /// Run the real HTTPS link setup against `origin`, pinning `https` as the
    /// agent does for a `config.tls` server.
    async fn connect(&self, origin: SocketAddr, https: &X509) -> io::Result<TcpTls> {
        let roots = [self.root.clone()];
        remote_websocket::connect(
            &format!("https://localhost:{}", origin.port()),
            &self.identity,
            Some(https),
            false,
            &remote_websocket::ServerTrust {
                roots: &roots,
                server_name: "localhost",
                floor: &self.floor,
            },
        )
        .await
    }

    /// Connect, send Hello and wait for the server's Hello: the link is up
    /// and the host admitted.
    async fn admitted(&self, origin: SocketAddr, https: &X509) -> io::Result<()> {
        let channel = self.connect(origin, https).await?;
        greet(&channel).await
    }
}

/// Send the agent's Hello on `channel` and wait for the server's.
async fn greet(channel: &TcpTls) -> io::Result<()> {
    Transmit::default()
        .send(
            channel,
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: MARKER,
            },
        )
        .await?;
    let mut receive = Receive::default();
    let answer = tokio::time::timeout(Duration::from_secs(5), receive.next(channel))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if matches!(answer.frame, Frame::Hello { .. }) {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

/// A server certificate for `localhost` from a CA of its own, as an
/// operator's HTTPS certificate (or a relay's publicly trusted one) would be.
fn https_certificate() -> Identity {
    identities().0
}

/// The fixtures every case needs: CA material, an enrolled agent, and the
/// HTTPS certificate a `config.tls` server would serve (from another CA, as
/// an operator's certificate would be).
async fn setup() -> (crate::ca::CaMaterial, Agent, EnrollmentStore, Identity) {
    let (_, node, root, material) = identities();
    let (store, _pool, _host, _) = super::revocation::admitted_store(&node, &root).await;
    let https = https_certificate();
    let agent = Agent {
        identity: node,
        root,
        floor: ServerLeafFloor::default(),
    };
    (material, agent, store, https)
}

/// The real server, terminating TLS itself: the link completes, the host is
/// admitted, and the floor records the leaf the listeners serve.
#[tokio::test]
async fn direct_https_link_runs_leg_b_and_records_the_leaf() {
    let (material, agent, store, https) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let server = start_server(&leaf, &agent.root, store, Some(&https)).await;
    agent
        .admitted(server.app, &https.certificate)
        .await
        .expect("the real server completes leg-B TLS inside the WebSocket");
    assert_eq!(
        agent.floor.newest(),
        Some(
            infraternal_plugin_remote::server_leaf_floor::not_before_seconds(
                &leaf.certificate.to_der().unwrap(),
            )
            .unwrap()
        )
    );
}

/// The case J1163 could not close: the server sits behind a TLS-terminating
/// reverse proxy, and a relay in front holds an HTTPS certificate the agent
/// trusts for the name (here: the very certificate the proxy serves).
///
/// - A relay that answers the link itself cannot: whatever key it runs the
///   inner TLS with (its HTTPS key, or a leaf for the name from another CA),
///   the agent refuses it, and its floor does not move.
/// - A relay that forwards completes the link, but only as transport: the
///   bytes it decrypted from the outer TLS never contain the agent's Hello.
#[tokio::test]
async fn relay_behind_a_reverse_proxy_cannot_complete_or_read_the_link() {
    let (material, agent, store, https) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let server = start_server(&leaf, &agent.root, store, None).await;
    let (front, front_capture, front_task) = proxy(&https, server.app, false).await;
    agent
        .admitted(front, &https.certificate)
        .await
        .expect("the reverse proxy carries the link");
    let floor = agent.floor.newest();

    let (_, _, _, stranger) = identities();
    let stranger_leaf = crate::server_leaf::issue(&stranger, "localhost", None, now()).unwrap();
    for inner in [&https, &stranger_leaf] {
        let (relay, task) = impostor(&https, inner, &agent.root).await;
        let refused = agent
            .connect(relay, &https.certificate)
            .await
            .err()
            .expect("a relay answering the inner TLS must be refused");
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        task.abort();
    }
    assert_eq!(agent.floor.newest(), floor);

    let (relay, capture, task) = proxy(&https, front, true).await;
    agent
        .admitted(relay, &https.certificate)
        .await
        .expect("a forwarding relay only carries bytes");
    assert_only_inner_ciphertext(&capture, "relay");
    // The proxy that terminates the outer TLS sees only inner ciphertext too.
    assert_only_inner_ciphertext(&front_capture, "reverse proxy");
    task.abort();
    front_task.abort();
}

/// An impostor holding a copied state directory: its HTTPS certificate is
/// accepted, and its leg-B leaf is CA-signed and unexpired. An agent with no
/// history accepts it (the same residual as on the direct dials), but once
/// it has seen the server's newer leaf it refuses the copy. A leaf from
/// another CA is never accepted.
#[tokio::test]
async fn copied_older_leaf_is_refused_on_the_https_link_too() {
    let (material, agent, store, https) = setup().await;
    let old = crate::server_leaf::issue(&material, "localhost", None, now() - 3 * 86_400).unwrap();
    let new =
        crate::server_leaf::issue(&material, "localhost", Some(&old.certificate), now()).unwrap();
    let impostor = start_server(&old, &agent.root, store.clone(), Some(&https)).await;
    agent
        .admitted(impostor.app, &https.certificate)
        .await
        .expect("chain and name checks alone accept the copied leaf");
    let real = start_server(&new, &agent.root, store.clone(), Some(&https)).await;
    agent.admitted(real.app, &https.certificate).await.unwrap();
    let refused = agent
        .connect(impostor.app, &https.certificate)
        .await
        .err()
        .unwrap();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);

    let (_, _, _, stranger) = identities();
    let foreign = crate::server_leaf::issue(&stranger, "localhost", None, now()).unwrap();
    let foreign = start_server(&foreign, &agent.root, store, Some(&https)).await;
    let refused = agent
        .connect(foreign.app, &https.certificate)
        .await
        .err()
        .unwrap();
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
}

/// A rotation reaches the HTTPS link at once: the next handshake serves the
/// new leaf and raises the floor; a server still serving the replaced leaf
/// is refused from then on, while the old leaf kept working until then.
#[tokio::test]
async fn rotation_reaches_the_https_link_and_retires_the_old_leaf() {
    let (material, agent, store, https) = setup().await;
    let first =
        crate::server_leaf::issue(&material, "localhost", None, now() - 3 * 86_400).unwrap();
    let second =
        crate::server_leaf::issue(&material, "localhost", Some(&first.certificate), now()).unwrap();
    let server = start_server(&first, &agent.root, store.clone(), Some(&https)).await;
    let behind = start_server(&first, &agent.root, store, Some(&https)).await;
    agent
        .admitted(server.app, &https.certificate)
        .await
        .unwrap();
    agent
        .admitted(behind.app, &https.certificate)
        .await
        .expect("the current leaf is accepted again until it is replaced");
    server.listeners.install_server_leaf(&second).unwrap();
    agent
        .admitted(server.app, &https.certificate)
        .await
        .unwrap();
    assert_eq!(
        agent.floor.newest(),
        Some(
            infraternal_plugin_remote::server_leaf_floor::not_before_seconds(
                &second.certificate.to_der().unwrap(),
            )
            .unwrap()
        )
    );
    assert!(agent.connect(behind.app, &https.certificate).await.is_err());
}

/// A host whose certificate the ledger does not hold gets no link, whether
/// the certificate comes from the server's CA (not enrolled) or from another
/// CA (refused by the inner TLS itself).
#[tokio::test]
async fn unenrolled_host_gets_no_link() {
    let (material, agent, store, https) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let server = start_server(&leaf, &agent.root, store, Some(&https)).await;
    // Same CA, never enrolled in this store.
    let (_, unenrolled, _, _) = identities();
    let (_, foreign, _, _) = identities();
    for identity in [unenrolled, foreign] {
        let stranger = Agent {
            identity,
            root: agent.root.clone(),
            floor: ServerLeafFloor::default(),
        };
        assert!(
            stranger
                .admitted(server.app, &https.certificate)
                .await
                .is_err(),
            "an unenrolled host was admitted"
        );
    }
    agent
        .admitted(server.app, &https.certificate)
        .await
        .expect("the enrolled host still gets its link");
}

/// Preflight reaches the leg-B listener inside the WebSocket without any
/// identity, and reports a route that does not answer it.
#[tokio::test]
async fn preflight_reaches_leg_b_tls_and_reports_a_route_without_it() {
    let (material, agent, store, https) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let server = start_server(&leaf, &agent.root, store, Some(&https)).await;
    remote_websocket::preflight(
        &format!("https://localhost:{}", server.app.port()),
        Some(&https.certificate),
        false,
    )
    .await
    .expect("preflight completes against the real route");

    // A WebSocket route that talks but is not a leg-B listener.
    let acceptor = outer_acceptor(&https);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut outer = tokio_openssl::SslStream::new(ssl, socket).unwrap();
            if std::pin::Pin::new(&mut outer).accept().await.is_err() {
                continue;
            }
            if let Ok(mut socket) = tokio_tungstenite::accept_async(outer).await {
                use futures_util::SinkExt;
                let _ = socket
                    .send(tokio_tungstenite::tungstenite::Message::Binary(
                        b"not tls".to_vec().into(),
                    ))
                    .await;
                let _ = socket.close(None).await;
            }
        }
    });
    assert_eq!(
        remote_websocket::preflight(
            &format!("https://localhost:{}", address.port()),
            Some(&https.certificate),
            false,
        )
        .await,
        Err(remote_websocket::PreflightFailure::Link)
    );
    task.abort();
}

/// Cost of the HTTPS link, run by hand on the perf VM (`--ignored`):
/// link setup through the real route, and the data path with and without the
/// inner TLS layer over the same outer HTTPS WebSocket.
// Printed rates and averages only: counts stay far below 2^52.
#[allow(clippy::cast_precision_loss)]
mod bench {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

    /// CPU time this process has used so far, in microseconds.
    fn cpu_us() -> u128 {
        let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_PROCESS_CPUTIME_ID).unwrap();
        Duration::from(time).as_micros()
    }

    /// The median and the 90th percentile of `samples`, in microseconds.
    fn percentiles(samples: &mut [u128]) -> (u128, u128) {
        samples.sort_unstable();
        (samples[samples.len() / 2], samples[samples.len() * 9 / 10])
    }

    /// A TCP proxy that holds every chunk for `delay` in each direction, in
    /// order, so a round trip costs `2 * delay`.
    async fn delayed(upstream: SocketAddr, delay: Duration) -> SocketAddr {
        /// Forward `from` to `to`, releasing each chunk `delay` after it arrived.
        async fn pipe(
            mut from: tokio::net::tcp::OwnedReadHalf,
            mut to: tokio::net::tcp::OwnedWriteHalf,
            delay: Duration,
        ) {
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
            let reader = async move {
                let mut buffer = vec![0; 64 * 1024];
                while let Ok(read) = from.read(&mut buffer).await {
                    if read == 0
                        || sender
                            .send((tokio::time::Instant::now() + delay, buffer[..read].to_vec()))
                            .is_err()
                    {
                        break;
                    }
                }
            };
            let writer = async move {
                while let Some((due, chunk)) = receiver.recv().await {
                    tokio::time::sleep_until(due).await;
                    if to.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(reader, writer);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(upstream).await else {
                    continue;
                };
                socket.set_nodelay(true).unwrap();
                server.set_nodelay(true).unwrap();
                let (client_read, client_write) = socket.into_split();
                let (server_read, server_write) = server.into_split();
                tokio::spawn(pipe(client_read, server_write, delay));
                tokio::spawn(pipe(server_read, client_write, delay));
            }
        });
        address
    }

    /// Link setup through the real route on a `config.tls` server: outer
    /// TLS, upgrade, inner leg-B TLS, ledger admission and the Hello exchange.
    /// Prints wall time and process CPU (both ends) per link, then the setup
    /// time over a proxy adding 25 ms each way (50 ms per round trip).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "bench: run on the perf VM"]
    async fn bench_https_link_setup() {
        let (material, agent, store, https) = setup().await;
        let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
        let server = start_server(&leaf, &agent.root, store, Some(&https)).await;
        for _ in 0..20 {
            agent
                .admitted(server.app, &https.certificate)
                .await
                .unwrap();
        }
        let links = 300;
        let mut wall = Vec::with_capacity(links);
        let cpu = cpu_us();
        for _ in 0..links {
            let started = std::time::Instant::now();
            agent
                .admitted(server.app, &https.certificate)
                .await
                .unwrap();
            wall.push(started.elapsed().as_micros());
        }
        let cpu = (cpu_us() - cpu) / links as u128;
        let (median, p90) = percentiles(&mut wall);
        println!(
            "BENCH setup links={links} wall_median_us={median} wall_p90_us={p90} cpu_per_link_us={cpu}"
        );

        let slow = delayed(server.app, Duration::from_millis(25)).await;
        let mut wall = Vec::new();
        for _ in 0..9 {
            let started = std::time::Instant::now();
            agent.admitted(slow, &https.certificate).await.unwrap();
            wall.push(started.elapsed().as_micros());
        }
        let (median, _) = percentiles(&mut wall);
        println!(
            "BENCH setup_rtt50 links=9 wall_median_us={median} round_trips={:.2}",
            median as f64 / 50_000.0
        );
    }

    /// The outer HTTPS session and WebSocket both ends of the link share,
    /// over loopback: (agent side, server side).
    async fn outer_pair(
        https: &Identity,
        config: tokio_tungstenite::tungstenite::protocol::WebSocketConfig,
    ) -> (
        WebSocketStream<tokio_openssl::SslStream<TcpStream>>,
        WebSocketStream<tokio_openssl::SslStream<TcpStream>>,
    ) {
        let acceptor = outer_acceptor(https);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_openssl::SslStream::new(ssl, socket).unwrap();
            std::pin::Pin::new(&mut tls).accept().await.unwrap();
            tokio_tungstenite::accept_async_with_config(tls, Some(config))
                .await
                .unwrap()
        });
        let socket = TcpStream::connect(address).await.unwrap();
        socket.set_nodelay(true).unwrap();
        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let mut tls = tokio_openssl::SslStream::new(ssl, socket).unwrap();
        std::pin::Pin::new(&mut tls).connect().await.unwrap();
        let (client, _) = tokio_tungstenite::client_async_with_config(
            "ws://localhost/remote/agent",
            tls,
            Some(config),
        )
        .await
        .unwrap();
        (client, server.await.unwrap())
    }

    /// One end of a link's data path, as each version carries frames.
    enum Path {
        /// Before #559's inner TLS: each frame is one WebSocket binary message.
        Plain(
            Box<tokio::sync::Mutex<WebSocketStream<tokio_openssl::SslStream<TcpStream>>>>,
            tokio::sync::Mutex<Vec<u8>>,
        ),
        /// Now: leg-B TLS inside the WebSocket carrier.
        Inner(TcpTls),
    }

    impl Path {
        /// Write one frame.
        async fn write(&self, frame: &[u8]) {
            match self {
                Self::Plain(socket, _) => socket
                    .lock()
                    .await
                    .send(Message::Binary(bytes::Bytes::copy_from_slice(frame)))
                    .await
                    .unwrap(),
                Self::Inner(channel) => channel.write(frame).await.unwrap(),
            }
        }

        /// Read exactly `into.len()` bytes.
        async fn read_exact(&self, into: &mut [u8]) {
            let mut filled = 0;
            while filled < into.len() {
                match self {
                    Self::Plain(socket, pending) => {
                        let mut pending = pending.lock().await;
                        if pending.is_empty() {
                            let Some(Ok(Message::Binary(data))) = socket.lock().await.next().await
                            else {
                                panic!("the plain path ended");
                            };
                            pending.extend_from_slice(&data);
                        }
                        let count = (into.len() - filled).min(pending.len());
                        into[filled..filled + count].copy_from_slice(&pending[..count]);
                        pending.drain(..count);
                        filled += count;
                    }
                    Self::Inner(channel) => {
                        let read = channel.read(&mut into[filled..]).await.unwrap();
                        assert!(read > 0, "the inner path ended");
                        filled += read;
                    }
                }
            }
        }
    }

    /// Both ends of one data path: (agent side, server side).
    async fn paths(inner: bool) -> (Path, Path) {
        let (material, agent, _store, https) = setup().await;
        if !inner {
            let mut config = carrier_config();
            config.max_message_size = Some(infraternal_protocol::MAX_FRAME_LEN + 64);
            config.max_frame_size = Some(infraternal_protocol::MAX_FRAME_LEN + 64);
            let (client, server) = outer_pair(&https, config).await;
            return (
                Path::Plain(Box::new(client.into()), Vec::new().into()),
                Path::Plain(Box::new(server.into()), Vec::new().into()),
            );
        }
        let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
        let (client, server) = outer_pair(&https, carrier_config()).await;
        let roots = [agent.root.clone()];
        let acceptor = remote_tls::server_config(&leaf, &roots).unwrap();
        let connector = remote_tls::client_config(&agent.identity, &roots).unwrap();
        let accepting = tokio::spawn(async move {
            remote_tls::accept_over(WebSocketCarrier::new(server).into_carrier(), &acceptor)
                .await
                .unwrap()
        });
        let dialed = remote_tls::dial_over(
            WebSocketCarrier::new(client).into_carrier(),
            "localhost",
            &connector,
        )
        .await
        .unwrap();
        let accepted = accepting.await.unwrap();
        (Path::Inner(dialed.channel), Path::Inner(accepted.channel))
    }

    /// Bulk throughput (agent to server, 16 KiB frames) and a 64-byte frame
    /// echo, on the data path before (`plain`) and with the inner TLS layer.
    /// Prints MB/s, process CPU per MB (both ends) and the echo round trip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "bench: run on the perf VM"]
    async fn bench_https_link_data_path() {
        for inner in [false, true] {
            let name = if inner { "inner_tls" } else { "plain" };
            let (agent, server) = paths(inner).await;
            let (agent, server) = (Arc::new(agent), Arc::new(server));
            let frame = vec![0x5a; 16 * 1024];
            let total: usize = 256 << 20;
            let receiver = {
                let server = server.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0; 16 * 1024];
                    let mut left = total;
                    while left > 0 {
                        let take = left.min(buffer.len());
                        server.read_exact(&mut buffer[..take]).await;
                        left -= take;
                    }
                })
            };
            let cpu = cpu_us();
            let started = std::time::Instant::now();
            for _ in 0..total / frame.len() {
                agent.write(&frame).await;
            }
            receiver.await.unwrap();
            let elapsed = started.elapsed();
            let cpu = cpu_us() - cpu;
            let megabytes = (total >> 20) as f64;
            println!(
                "BENCH bulk path={name} mb={megabytes} mb_per_s={:.0} cpu_us_per_mb={:.0}",
                megabytes / elapsed.as_secs_f64(),
                cpu as f64 / megabytes
            );

            let echo = {
                let server = server.clone();
                tokio::spawn(async move {
                    let mut small = [0; 64];
                    for _ in 0..20_000 {
                        server.read_exact(&mut small).await;
                        server.write(&small).await;
                    }
                })
            };
            let mut samples = Vec::with_capacity(20_000);
            let small = [0x33; 64];
            let mut back = [0; 64];
            let cpu = cpu_us();
            for _ in 0..20_000 {
                let started = std::time::Instant::now();
                agent.write(&small).await;
                agent.read_exact(&mut back).await;
                samples.push(started.elapsed().as_nanos());
            }
            let cpu = (cpu_us() - cpu) as f64 / 20_000.0;
            echo.await.unwrap();
            let (median, p90) = percentiles(&mut samples);
            println!(
                "BENCH echo path={name} frames=20000 rtt_median_us={:.1} rtt_p90_us={:.1} cpu_us_per_round_trip={cpu:.1}",
                median as f64 / 1000.0,
                p90 as f64 / 1000.0
            );
        }
    }
}

/// A real WebSocket pair over loopback, configured as the HTTPS fallback
/// configures it (`carrier_config`): (agent side, server side). The outer TLS
/// is not under test here, so the pair runs on plain TCP.
async fn websocket_pair() -> (
    tokio_tungstenite::WebSocketStream<TcpStream>,
    tokio_tungstenite::WebSocketStream<TcpStream>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        tokio_tungstenite::accept_async_with_config(
            socket,
            Some(remote_websocket::carrier_config()),
        )
        .await
        .unwrap()
    });
    let socket = TcpStream::connect(address).await.unwrap();
    let (client, _) = tokio_tungstenite::client_async_with_config(
        "ws://localhost/remote/agent",
        socket,
        Some(remote_websocket::carrier_config()),
    )
    .await
    .unwrap();
    (client, server.await.unwrap())
}

/// A raw TLS client for one probe: it trusts `roots`, presents `identity` when
/// given, offers only `alpn`, and stays on TLS 1.2 when `tls12`. It is built
/// by hand, not with `client_config`, so each case can break one rule.
fn probe_client(
    roots: &[X509],
    identity: Option<&Identity>,
    alpn: &[u8],
    tls12: bool,
) -> SslConnector {
    use openssl::{
        ssl::{SslVerifyMode, SslVersion},
        x509::store::X509StoreBuilder,
    };
    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
    let mut trust = X509StoreBuilder::new().unwrap();
    for root in roots {
        trust.add_cert(root.clone()).unwrap();
    }
    builder.set_cert_store(trust.build());
    builder.set_verify(SslVerifyMode::PEER);
    if let Some(identity) = identity {
        builder.set_certificate(&identity.certificate).unwrap();
        builder.set_private_key(&identity.key).unwrap();
    }
    builder.set_alpn_protos(alpn).unwrap();
    if tls12 {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
    }
    builder.build()
}

/// Run the server side of the inner handshake with `accept_over` (the path
/// `/remote/agent` takes) over one real WebSocket carrier, and the client side
/// as a bare TLS connect over the other end. Returns (server result, whether
/// the client finished its TLS handshake).
///
/// The client is a bare connect, not `dial_over`, on purpose: `dial_over` also
/// requires `infraternal/1` as the negotiated ALPN, so it would report every
/// recovery-ALPN handshake as a failure, even one the TLS layer completed.
async fn inner_handshake(config: &SslAcceptor, client: &SslConnector) -> (io::Result<()>, bool) {
    let (agent_socket, server_socket) = websocket_pair().await;
    let server =
        remote_tls::accept_over(WebSocketCarrier::new(server_socket).into_carrier(), config);
    let ssl = client.configure().unwrap().into_ssl("localhost").unwrap();
    let mut stream =
        tokio_openssl::SslStream::new(ssl, WebSocketCarrier::new(agent_socket).into_carrier())
            .unwrap();
    let client_completes = std::pin::Pin::new(&mut stream).connect();
    let (server, client_completes) = tokio::join!(server, client_completes);
    (server.map(|_| ()), client_completes.is_ok())
}

/// The production `/remote/agent` acceptor is `recovery_server_config`, which
/// offers the recovery ALPN as well as `infraternal/1` (`start_with_recovery`,
/// runtime.rs). Over the WebSocket, only a valid enrolled host may get a link:
/// every other peer is refused by `accept_over`, including one that speaks
/// the recovery ALPN with a valid certificate. J1232 found this case
/// unpinned, so a later change to `accept_over` or `finish` could open it
/// without a test failing.
///
/// Each row says whether the client finishes its own TLS handshake. For a
/// TLS 1.3 client that is true even when the server refuses, because the
/// server's check runs after the client has sent its Finished. A TLS 1.2-only
/// client must fail at the handshake, since the server speaks TLS 1.3 only.
#[tokio::test]
async fn recovery_aware_acceptor_admits_only_a_valid_host_over_the_websocket() {
    const RECOVERY: &[u8] = b"\x1dinfraternal/remote-recovery/1";
    const HOST: &[u8] = b"\x0dinfraternal/1";
    let (material, agent, _store, foreign) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let roots = std::slice::from_ref(&agent.root);
    let config = remote_tls::recovery_server_config(&leaf, roots).unwrap();
    let host = Some(&agent.identity);
    let foreign = Some(&foreign);
    // (case, client, client completes its handshake, server admits the host)
    let cases = [
        (
            "recovery ALPN, no certificate",
            probe_client(roots, None, RECOVERY, false),
            true,
            false,
        ),
        (
            "recovery ALPN, foreign-CA certificate",
            probe_client(roots, foreign, RECOVERY, false),
            true,
            false,
        ),
        (
            "recovery ALPN, valid host certificate",
            probe_client(roots, host, RECOVERY, false),
            true,
            false,
        ),
        (
            "infraternal/1, no certificate",
            probe_client(roots, None, HOST, false),
            true,
            false,
        ),
        (
            "infraternal/1, foreign-CA certificate",
            probe_client(roots, foreign, HOST, false),
            true,
            false,
        ),
        (
            "infraternal/1, TLS 1.2 only",
            probe_client(roots, host, HOST, true),
            false,
            false,
        ),
        (
            "infraternal/1, valid host certificate",
            probe_client(roots, host, HOST, false),
            true,
            true,
        ),
    ];
    for (case, client, client_completes, admitted) in cases {
        let (server, completed) = inner_handshake(&config, &client).await;
        assert_eq!(completed, client_completes, "{case}: client TLS handshake");
        if admitted {
            server.unwrap_or_else(|error| panic!("{case}: refused: {error}"));
        } else {
            assert_eq!(
                server.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "{case}: server must refuse with the transport's denial"
            );
        }
    }
}
