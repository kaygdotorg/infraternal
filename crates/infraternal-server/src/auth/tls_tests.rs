//! Real native TLS/HTTP2 and proxy HTTP/1 registration probes using the ES256 fixture.
//! Certificates, private keys and auth capabilities stay in memory throughout each test.
//! Independent review covers split ceremony reuse and duplicate denial before proof consumption.
use super::*;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum_server::tls_openssl::{OpenSSLAcceptor, OpenSSLConfig};
use openssl::{
    asn1::Asn1Time,
    ssl::{SslConnector, SslMethod},
    x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};
use std::pin::Pin;
use tokio::net::TcpStream;

fn localhost_certificate() -> (PKey<Private>, X509) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    (key, cert.build())
}

struct Client {
    sender: h2::client::SendRequest<Bytes>,
    connection: tokio::task::JoinHandle<()>,
    origin: String,
}
impl Client {
    async fn new(address: SocketAddr, cert: &X509) -> Self {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.cert_store_mut().add_cert(cert.clone()).unwrap();
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
        let (sender, connection) = h2::client::handshake(stream).await.unwrap();
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self {
            sender,
            connection,
            origin: format!("https://localhost:{}", address.port()),
        }
    }
    async fn post(
        &mut self,
        action: &str,
        value: Value,
        cookies: &[&str],
        origin: Option<&str>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{}/auth/{action}", self.origin))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, origin.unwrap_or(&self.origin))
            // Invalid metadata must be ignored by standalone source admission.
            .header("x-forwarded-for", "not-an-address");
        for cookie in cookies {
            request = request.header(header::COOKIE, *cookie);
        }
        let request = request.body(()).unwrap();
        // Each sequential request waits for its response before opening another stream.
        let (response, mut body) = self.sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from(serde_json::to_vec(&value).unwrap()), true)
            .unwrap();
        let response = response.await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, headers, value)
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

#[tokio::test]
async fn standalone_tls_registration_session_split_cookies() {
    registration_session(false).await;
}

#[tokio::test]
async fn proxy_tls_registration_session_split_cookies() {
    registration_session(true).await;
}

async fn registration_session(behind_proxy: bool) {
    let _serial = SERIAL.lock().await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("https://localhost:{}", address.port());
    let data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.job-evidence")
        .join(format!("tls-data-{}", rand::random::<u64>()));
    let (agent, _peer) = UnixStream::pair().unwrap();
    let (app, setup) = router_with_agent(
        ServerConfig {
            listen: address,
            data_dir: data_dir.clone(),
            public_origin: origin.clone(),
            web_root: None,
            tls: Some(TlsFiles {
                certificate: "unused.pem".into(),
                private_key: "unused.pem".into(),
            }),
            behind_proxy,
            trusted_proxies: if behind_proxy {
                vec!["127.0.0.1".parse().unwrap()]
            } else {
                vec![]
            },
        },
        EmbeddedAgent::from_test_socket(agent),
    )
    .await
    .unwrap();
    let (key, cert) = localhost_certificate();
    // A TLS-terminating front combines HTTP/2 cookie fields on the HTTP/1 hop.
    let (app, upstream_server) = if behind_proxy {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(
                upstream,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let front = axum::Router::new()
            .route("/auth/{action}", axum::routing::post(proxy_forward))
            .with_state(upstream_address);
        (front, Some(task))
    } else {
        (app, None)
    };
    let config = OpenSSLConfig::from_pem(
        &cert.to_pem().unwrap(),
        &key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        axum_server::from_tcp(listener)
            .unwrap()
            .acceptor(OpenSSLAcceptor::new(config))
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    let mut client = Client::new(address, &cert).await;
    assert_eq!(
        client.post("status", json!({}), &[], None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        client
            .post("setup-check", json!({"token":setup}), &[], None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (status, headers, start) = client
        .post(
            "setup-start",
            json!({"token":setup,"name":"owner"}),
            &[],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let ceremony = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    // Two pages sharing a cookie jar must retain their common browser binding.
    let (status, shared_headers, _) = client
        .post(
            "setup-start",
            json!({"token":setup,"name":"owner"}),
            &["unrelated=value", &ceremony],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let shared_binding = shared_headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    // Report only reuse success; assertion output must never print capabilities.
    let binding_reused = shared_binding == ceremony;
    assert!(
        binding_reused,
        "split fields must reuse the browser binding"
    );
    let user = str_field(&start, "user_id");
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    let mut software = Software::new();
    software.rp_id = "localhost";
    let dek = rand::random::<[u8; 32]>();
    let proof = software.registration(&start, &origin, true);
    let finish = json!({
        "ceremony":start["ceremony"], "proof":proof,
        "passkey_wrap":browser_wrap(&software.prf(&start), &dek, user, "passkey"),
        "recovery_wrap":browser_wrap(&recovery_material(&words,"wrap"), &dek, user,"recovery"),
        "recovery_verifier":recovery_verifier(&words),
    });
    // Independent review: rejected bindings must leave the signed proof usable.
    // A distinct duplicate, or a malformed duplicate on either side, must deny.
    let invalid = "__Host-infraternal-ceremony=short";
    let foreign = format!("__Host-infraternal-ceremony={}", "A".repeat(43));
    for fields in [
        vec![ceremony.as_str(), foreign.as_str()],
        vec![ceremony.as_str(), invalid],
        vec![invalid, ceremony.as_str()],
    ] {
        assert_eq!(
            client
                .post("registration-finish", finish.clone(), &fields, None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (status, headers, _) = client
        .post(
            "registration-finish",
            finish,
            &["unrelated=value", &ceremony],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let session = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let joined = format!("{ceremony}; {session}");
    assert_eq!(
        client.post("session", json!({}), &[&joined], None).await.0,
        StatusCode::OK
    );
    let (status, _, identity) = client
        .post("session", json!({}), &[&ceremony, &session], None)
        .await;
    println!(
        "TLS_HTTP2 proxy={behind_proxy} registration=200 joined_session=200 split_session={status}"
    );
    let reversed = client
        .post("session", json!({}), &[&session, &ceremony], None)
        .await
        .0;
    let duplicate = client
        .post("session", json!({}), &[&session, &session], None)
        .await
        .0;
    let wrong_origin = client
        .post(
            "session",
            json!({}),
            &[&ceremony, &session],
            Some("https://foreign.test"),
        )
        .await
        .0;
    let missing = client
        .post("session", json!({}), &[&ceremony], None)
        .await
        .0;
    // Clean up before asserting so a failing reproducer leaves no database or listener.
    server.abort();
    let _ = server.await;
    if let Some(upstream) = upstream_server {
        upstream.abort();
        let _ = upstream.await;
    }
    drop(client);
    std::fs::remove_dir_all(data_dir).unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(identity["user_id"], user);
    assert_eq!(reversed, StatusCode::OK);
    assert_eq!(duplicate, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_origin, StatusCode::UNAUTHORIZED);
    assert_eq!(missing, StatusCode::UNAUTHORIZED);
}

/// A real HTTP/1 upstream hop, with the same cookie recombination as a TLS proxy.
async fn proxy_forward(
    axum::extract::State(address): axum::extract::State<SocketAddr>,
    request: Request<axum::body::Body>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (parts, body) = request.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let cookies = parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let mut wire = format!(
        "POST {} HTTP/1.1\r\nHost: localhost\r\nOrigin: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-Forwarded-For: 198.51.100.149\r\n",
        parts.uri.path(),
        parts.headers[header::ORIGIN].to_str().unwrap(),
        body.len()
    );
    if !cookies.is_empty() {
        wire.push_str("Cookie: ");
        wire.push_str(&cookies);
        wire.push_str("\r\n");
    }
    wire.push_str("\r\n");
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(wire.as_bytes()).await.unwrap();
    socket.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    let mut lines = headers.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut result = (
        StatusCode::from_u16(status).unwrap(),
        response[split + 4..].to_vec(),
    )
        .into_response();
    for line in lines {
        let (name, value) = line.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("set-cookie") {
            result
                .headers_mut()
                .append(header::SET_COOKIE, value.trim().parse().unwrap());
        }
    }
    result
}
