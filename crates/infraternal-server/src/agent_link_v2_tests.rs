//! The HTTPS agent link proves the server's current leg-B leaf (#559): real
//! `/remote/agent` routes behind real HTTPS acceptors, real listeners whose
//! leaf they sign with, the real infraternal agent `connect`, and relaying
//! TLS proxies in between.
//!
//! Every socket here is on 127.0.0.1; nothing leaves the host.
use super::*;
use infraternal_agent::{remote_websocket, server_leaf_floor::ServerLeafFloor};
use infraternal_plugin_remote::agent_link;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
use tokio::net::{TcpListener, TcpStream};

/// Unix seconds now.
fn now() -> i64 {
    crate::runtime::unix_seconds().unwrap()
}

/// One server: its leg-B listeners (whose leaf `/remote/agent` signs with)
/// and an HTTPS or plain-HTTP app listener with the agent route.
struct Server {
    /// Keeps the leg-B listeners (and so the current leaf) alive.
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

/// A TLS-terminating proxy at a fresh address: it presents `certificate` to
/// whoever connects and forwards the decrypted bytes to `upstream`, over a new
/// TLS session when `upstream_tls` (a relay, or a re-encrypting proxy) or as
/// plain TCP (a reverse proxy in front of a plain-HTTP server).
async fn proxy(
    certificate: &Identity,
    upstream: SocketAddr,
    upstream_tls: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(&certificate.certificate).unwrap();
    acceptor.set_private_key(&certificate.key).unwrap();
    let acceptor = acceptor.build();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    // The relay does not care whom it talks to upstream.
    connector.set_verify(SslVerifyMode::NONE);
    let connector = connector.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let connector = connector.clone();
            tokio::spawn(async move {
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
                        let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                    }
                } else {
                    let mut upstream = upstream;
                    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                }
            });
        }
    });
    (address, task)
}

/// What one infraternal agent knows: its identity and enrollment trust.
struct Agent {
    host: Uuid,
    identity: Identity,
    root: X509,
    floor: ServerLeafFloor,
}

impl Agent {
    /// Run the real HTTPS link handshake against `origin`, pinning `https`
    /// as the agent does for a `config.tls` server, with the given binding
    /// rule. Returns the error, if any.
    async fn connect(
        &self,
        origin: SocketAddr,
        https: &X509,
        require_binding: bool,
    ) -> io::Result<()> {
        let roots = [self.root.clone()];
        remote_websocket::connect(
            &format!("https://localhost:{}", origin.port()),
            self.host,
            &self.identity,
            Some(https),
            false,
            &remote_websocket::ServerTrust {
                roots: &roots,
                server_name: "localhost",
                floor: &self.floor,
                require_binding,
            },
        )
        .await
        .map(drop)
    }
}

/// A server certificate for `localhost` from a CA of its own, as an
/// operator's HTTPS certificate (or a relay's) would be.
fn https_certificate() -> Identity {
    identities().0
}

/// The fixtures every case needs: CA material, an enrolled agent, and the
/// HTTPS certificate a `config.tls` server would serve (from another CA, as
/// an operator's certificate would be).
async fn setup() -> (crate::ca::CaMaterial, Agent, EnrollmentStore, Identity) {
    let (_, node, root, material) = identities();
    let (store, _pool, host, _) = super::revocation::admitted_store(&node, &root).await;
    let https = https_certificate();
    let agent = Agent {
        host,
        identity: node,
        root,
        floor: ServerLeafFloor::default(),
    };
    (material, agent, store, https)
}

/// The real server, terminating TLS itself: the link completes, the answer
/// is bound, and the floor records the leaf the listeners serve.
#[tokio::test]
async fn direct_https_link_proves_the_current_leaf() {
    let (material, agent, store, https) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let server = start_server(&leaf, &agent.root, store, Some(&https)).await;
    agent
        .connect(server.app, &https.certificate, true)
        .await
        .expect("the real server proves its leaf over a bound link");
    assert_eq!(
        agent.floor.newest(),
        Some(
            infraternal_plugin_remote::server_leaf_floor::not_before_seconds(
                &leaf.certificate.to_der().unwrap()
            )
            .unwrap()
        )
    );
}

/// A relay between the agent and the real server, with its own certificate
/// (which this agent was made to trust) or with a copy of the server's own
/// HTTPS key: the agent's proof is bound to the agent-relay session, the
/// server sees the relay-server session, and refuses. Nothing is admitted
/// and the agent's floor does not move.
#[tokio::test]
async fn relaying_proxy_cannot_complete_the_link() {
    let (material, agent, store, https) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let server = start_server(&leaf, &agent.root, store, Some(&https)).await;
    let other = https_certificate();
    for relay_certificate in [&other, &https] {
        let (relay, task) = proxy(relay_certificate, server.app, true).await;
        // Even an agent that does not insist on a bound answer is protected:
        // the server itself refuses the relayed proof.
        for require_binding in [false, true] {
            agent
                .connect(relay, &relay_certificate.certificate, require_binding)
                .await
                .expect_err("a relayed proof must be refused");
        }
        task.abort();
    }
    assert_eq!(agent.floor.newest(), None);
    // The same agent reaches the real server directly.
    agent
        .connect(server.app, &https.certificate, true)
        .await
        .unwrap();
}

/// The server's own binding check, with the agent's check out of the way: a
/// hand-built client sends a validly signed v2 proof whose channel binding
/// is wrong, then one with no binding at all, to a `config.tls` server. Both
/// must get no `ready-v2`, so no authority is admitted. The real agent's own
/// check would otherwise hide a missing server check.
#[tokio::test]
async fn server_refuses_wrong_or_missing_binding_on_its_own_tls() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (material, agent, store, https) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let server = start_server(&leaf, &agent.root, store, Some(&https)).await;
    for binding in [Some([7u8; agent_link::BINDING_LEN]), None] {
        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        // The pinned certificate is a self-issued leaf, so it must be
        // trusted as a partial chain, as the agent's own connector does.
        let mut trust = openssl::x509::store::X509StoreBuilder::new().unwrap();
        trust.add_cert(https.certificate.clone()).unwrap();
        trust
            .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
            .unwrap();
        connector.set_cert_store(trust.build());
        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let tcp = TcpStream::connect(server.app).await.unwrap();
        let mut tls = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        std::pin::Pin::new(&mut tls).connect().await.unwrap();
        let url = format!("wss://localhost:{}/remote/agent", server.app.port());
        let (mut socket, _) = tokio_tungstenite::client_async(url, tls).await.unwrap();
        let Some(Ok(Message::Text(text))) = socket.next().await else {
            panic!("expected a challenge");
        };
        let challenge: agent_link::AgentLinkChallenge =
            serde_json::from_str(text.as_str()).unwrap();
        let nonce: [u8; agent_link::NONCE_LEN] =
            B64.decode(&challenge.nonce).unwrap().try_into().unwrap();
        let client_nonce = [9u8; agent_link::NONCE_LEN];
        let message =
            agent_link::agent_proof_bytes_v2(agent.host, &nonce, &client_nonce, binding.as_ref());
        let key = &agent.identity.key;
        let mut signer = openssl::sign::Signer::new_without_digest(key)
            .or_else(|_| openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), key))
            .unwrap();
        let proof = agent_link::AgentLinkProofV2 {
            message_type: agent_link::PROOF_V2.to_owned(),
            host_id: agent.host,
            certificate_der: B64.encode(agent.identity.certificate.to_der().unwrap()),
            client_nonce: B64.encode(client_nonce),
            channel_binding: binding.map(|value| B64.encode(value)),
            signature: B64.encode(signer.sign_oneshot_to_vec(&message).unwrap()),
        };
        let proof = serde_json::to_string(&proof).unwrap();
        socket.send(Message::Text(proof.into())).await.unwrap();
        if let Some(Ok(Message::Text(answer))) = socket.next().await {
            assert!(!answer.contains("ready-v2"), "server answered {answer}");
        }
    }
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
        .connect(impostor.app, &https.certificate, true)
        .await
        .expect("chain and name checks alone accept the copied leaf");
    let real = start_server(&new, &agent.root, store.clone(), Some(&https)).await;
    agent
        .connect(real.app, &https.certificate, true)
        .await
        .unwrap();
    let refused = agent
        .connect(impostor.app, &https.certificate, true)
        .await
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);

    let (_, _, _, stranger) = identities();
    let foreign = crate::server_leaf::issue(&stranger, "localhost", None, now()).unwrap();
    let foreign = start_server(&foreign, &agent.root, store, Some(&https)).await;
    let refused = agent
        .connect(foreign.app, &https.certificate, true)
        .await
        .unwrap_err();
    assert_eq!(
        refused.to_string(),
        agent_link::server_unproved().to_string()
    );
}

/// A rotation reaches the HTTPS link at once: the next handshake proves the
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
        .connect(server.app, &https.certificate, true)
        .await
        .unwrap();
    agent
        .connect(behind.app, &https.certificate, true)
        .await
        .expect("the current leaf is accepted again until it is replaced");
    server.listeners.install_server_leaf(&second).unwrap();
    agent
        .connect(server.app, &https.certificate, true)
        .await
        .unwrap();
    assert_eq!(
        agent.floor.newest(),
        Some(
            infraternal_plugin_remote::server_leaf_floor::not_before_seconds(
                &second.certificate.to_der().unwrap()
            )
            .unwrap()
        )
    );
    assert!(
        agent
            .connect(behind.app, &https.certificate, true)
            .await
            .is_err()
    );
}

/// Behind a reverse proxy the server cannot see the agent's TLS session and
/// answers "unbound". An agent in reverse-proxy mode (system roots) accepts
/// that; one that pins the server's own certificate does not, because that
/// server would terminate TLS itself.
#[tokio::test]
async fn reverse_proxy_link_is_unbound_and_only_accepted_without_a_pin() {
    let (material, agent, store, https) = setup().await;
    let leaf = crate::server_leaf::issue(&material, "localhost", None, now()).unwrap();
    let server = start_server(&leaf, &agent.root, store, None).await;
    let (front, task) = proxy(&https, server.app, false).await;
    agent
        .connect(front, &https.certificate, false)
        .await
        .expect("reverse-proxy mode accepts a signed unbound answer");
    let refused = agent
        .connect(front, &https.certificate, true)
        .await
        .unwrap_err();
    assert_eq!(refused.to_string(), agent_link::not_bound().to_string());
    task.abort();
}

/// Which enrollments insist on a bound answer: a pinned HTTPS certificate of
/// the server's own, not system roots and not a CA-root pin.
#[test]
fn binding_is_required_only_for_a_pinned_server_certificate() {
    let (_, _, root, _) = identities();
    let https = https_certificate();
    let roots = [root.clone()];
    assert!(remote_websocket::binding_required(
        Some(&https.certificate),
        false,
        &roots
    ));
    assert!(!remote_websocket::binding_required(None, true, &roots));
    assert!(!remote_websocket::binding_required(
        Some(&root),
        false,
        &roots
    ));
}
