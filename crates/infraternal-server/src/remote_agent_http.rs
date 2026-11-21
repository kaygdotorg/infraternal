//! Admits D168 host links over an app-listener WebSocket proof [168,196], #291.

use crate::{
    enrollment::EnrollmentStore, remote_guard::AuthorityGuard, remote_runtime::RemoteHosts,
};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use infraternal_plugin_remote::agent_link::{
    AgentLinkChallenge, AgentLinkProof, AgentLinkReady, proof_bytes,
};
use openssl::{hash::MessageDigest, pkey::Id, rand::rand_bytes, sign::Verifier, x509::X509};
use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};
use uuid::Uuid;

const MAX_PROOF_MESSAGE: usize = 8192;
const MAX_MESSAGE: usize = infraternal_protocol::MAX_FRAME_LEN + 64;
const HANDSHAKE: Duration = Duration::from_secs(5);
/// Bytes an unproved peer may make the server read: one proof message plus
/// the largest masked frame header (2 + 8 length + 4 mask bytes). The
/// infraternal agent sends the proof as a single frame and nothing else until
/// it reads `ready`, so an honest peer never comes near this (#572 finding 6).
const PROOF_READ_BUDGET: usize = MAX_PROOF_MESSAGE + 14;

/// The WebSocket an enrolled host link runs on after `/remote/agent` admits it.
/// The read budget is lifted by then, so it carries full protocol frames.
pub(crate) type AgentSocket = WebSocketStream<ProofBudget<TokioIo<hyper::upgrade::Upgraded>>>;

/// Caps how many bytes an unauthenticated `/remote/agent` socket may read
/// before its proof passes (#572 finding 6).
///
/// The socket must accept 4 MiB messages once the host is admitted, and the
/// WebSocket layer cannot change its size limit after the upgrade. Without
/// this cap, any peer could make each of the 64 handshake slots buffer up to
/// 4 MiB for the 5 s handshake deadline before the 8 KiB proof check ran.
/// The budget counts raw bytes read from the connection, so it also covers
/// fragmented and control frames. A read past it fails with `InvalidData`,
/// which ends the handshake. [`ProofBudget::lift`] removes the cap once the
/// proof is authenticated.
pub(crate) struct ProofBudget<S> {
    inner: S,
    /// Bytes still allowed, or `None` once the proof has passed.
    remaining: Option<usize>,
}

impl<S> ProofBudget<S> {
    /// Wrap `inner` so at most `budget` bytes can be read until [`Self::lift`].
    fn new(inner: S, budget: usize) -> Self {
        Self {
            inner,
            remaining: Some(budget),
        }
    }

    /// Remove the cap: the peer has proved it holds an enrolled host key.
    fn lift(&mut self) {
        self.remaining = None;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProofBudget<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(remaining) = this.remaining else {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if remaining == 0 {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        // Read into a window no larger than the budget. Zeroing it costs at
        // most the budget once per read, and only before the proof.
        let window = buf.initialize_unfilled_to(remaining.min(buf.remaining()));
        let mut limited = ReadBuf::new(window);
        let result = Pin::new(&mut this.inner).poll_read(cx, &mut limited);
        let read = limited.filled().len();
        if let Poll::Ready(Ok(())) = result {
            buf.advance(read);
            this.remaining = Some(remaining - read);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProofBudget<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, data)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Clone)]
struct Api {
    hosts: RemoteHosts,
    store: EnrollmentStore,
    admission: Arc<Semaphore>,
    sources: Arc<crate::remote_admission::SourceSlots>,
}

fn trace_test_phase<T>(phase: &'static str, result: io::Result<T>) -> io::Result<T> {
    #[cfg(test)]
    match &result {
        Ok(_) => eprintln!("remote agent HTTPS phase={phase} complete"),
        Err(error) => eprintln!("remote agent HTTPS phase={phase} error={error:?}"),
    }
    let _ = phase;
    result
}

/// Add the agent path only when D168 enrollment is configured for this runtime.
/// Admission limits cover unauthenticated handshake work; enrolled links use `RemoteHosts`.
pub(crate) fn router(hosts: RemoteHosts, store: EnrollmentStore) -> Router {
    Router::new()
        .route("/remote/agent", get(upgrade))
        .with_state(Api {
            hosts,
            store,
            admission: Arc::new(Semaphore::new(64)),
            sources: Arc::new(crate::remote_admission::SourceSlots::new(4)),
        })
}

/// Accept the WebSocket upgrade by hand so the socket starts under a
/// [`ProofBudget`]. The infraternal agent connects over HTTP/1.1 only, so
/// this checks exactly the RFC 6455 opening handshake and answers 101.
async fn upgrade(State(api): State<Api>, mut request: Request) -> Response {
    let address = request
        .extensions()
        .get::<crate::runtime::ClientAddress>()
        .map(|address| address.0)
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<std::net::SocketAddr>>()
                .map(|address| address.0.ip())
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let Some(accept) = websocket_accept(request.headers()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(on_upgrade) = request
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>()
    else {
        return StatusCode::UPGRADE_REQUIRED.into_response();
    };
    let Some(source) = api.sources.reserve(address) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let Ok(permit) = api.admission.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    tokio::spawn(async move {
        // The permits move into this task, so a failed upgrade returns them.
        let Ok(upgraded) = on_upgrade.await else {
            return;
        };
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(MAX_MESSAGE);
        config.max_frame_size = Some(MAX_MESSAGE);
        let socket = WebSocketStream::from_raw_socket(
            ProofBudget::new(TokioIo::new(upgraded), PROOF_READ_BUDGET),
            Role::Server,
            Some(config),
        )
        .await;
        if let Err(error) = admit(socket, api, address, source, permit).await {
            eprintln!("Infraternal agent HTTPS link ended ({:?})", error.kind());
        }
    });
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let headers = response.headers_mut();
    headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(header::SEC_WEBSOCKET_ACCEPT, accept);
    response
}

/// Check an HTTP/1.1 WebSocket opening request and return the
/// `Sec-WebSocket-Accept` value for it, or `None` when it is not one.
fn websocket_accept(headers: &HeaderMap) -> Option<HeaderValue> {
    let has_token = |name: header::HeaderName, token: &str| {
        headers.get_all(name).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(token))
            })
        })
    };
    let version = headers.get(header::SEC_WEBSOCKET_VERSION)?;
    if !has_token(header::CONNECTION, "upgrade")
        || !has_token(header::UPGRADE, "websocket")
        || version.as_bytes() != b"13"
    {
        return None;
    }
    let key = headers.get(header::SEC_WEBSOCKET_KEY)?;
    HeaderValue::from_str(&derive_accept_key(key.as_bytes())).ok()
}

/// Authenticate the host proof and protocol Hello before returning handshake
/// capacity. The bounded per-host cleanup lane owns durable delivery from here.
async fn admit(
    mut socket: AgentSocket,
    api: Api,
    address: IpAddr,
    source: OwnedSemaphorePermit,
    permit: OwnedSemaphorePermit,
) -> io::Result<()> {
    let mut nonce = [0; 32];
    rand_bytes(&mut nonce).map_err(io::Error::other)?;
    let challenge = AgentLinkChallenge {
        message_type: "challenge".to_owned(),
        nonce: B64.encode(nonce),
    };
    trace_test_phase("challenge-send", send_text(&mut socket, &challenge).await)?;
    let proof = trace_test_phase(
        "proof-receive",
        tokio::time::timeout(HANDSHAKE, socket.next())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?
            .map_err(io::Error::other),
    )?;
    let Message::Text(proof) = proof else {
        return Err(io::ErrorKind::PermissionDenied.into());
    };
    if proof.len() > MAX_PROOF_MESSAGE {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let proof: AgentLinkProof = serde_json::from_str(proof.as_str())
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let authority = trace_test_phase(
        "proof-authenticate",
        authenticate(api.store.clone(), &proof, &nonce).await,
    )?;
    // The peer holds an enrolled host key: from here it may send full frames.
    socket.get_mut().lift();
    trace_test_phase(
        "ready-send",
        send_text(
            &mut socket,
            &AgentLinkReady {
                message_type: "ready".to_owned(),
            },
        )
        .await,
    )?;
    let link = trace_test_phase(
        "protocol-greeting",
        crate::remote_link::RemoteLink::websocket(socket).await,
    )?;
    // Proof and Hello are validated. Cleanup has its own bounded per-host
    // lane, so neither its queue nor its durable receipt may hold handshake slots.
    drop((source, permit));
    trace_test_phase(
        "host-admission",
        api.hosts
            .admit_observed(authority, link, Some(address))
            .await,
    )
}

/// Send one handshake message as JSON text, within the handshake deadline.
async fn send_text<T: serde::Serialize>(socket: &mut AgentSocket, message: &T) -> io::Result<()> {
    let text = serde_json::to_string(message).map_err(io::Error::other)?;
    tokio::time::timeout(HANDSHAKE, socket.send(Message::Text(text.into())))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(io::Error::other)
}

fn canonical_base64(value: &str) -> io::Result<Vec<u8>> {
    let decoded = B64
        .decode(value)
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    if B64.encode(&decoded) != value {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(decoded)
}

fn verify_signature(certificate: &X509, host_id: Uuid, nonce: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = certificate.public_key() else {
        return false;
    };
    let verifier = match key.id() {
        Id::ED25519 => Verifier::new_without_digest(&key),
        Id::EC
            if key.ec_key().is_ok_and(|key| {
                key.group().curve_name() == Some(openssl::nid::Nid::X9_62_PRIME256V1)
            }) =>
        {
            Verifier::new(MessageDigest::sha256(), &key)
        }
        _ => return false,
    };
    verifier.is_ok_and(|mut verifier| {
        verifier
            .verify_oneshot(signature, &proof_bytes(host_id, nonce))
            .unwrap_or(false)
    })
}

/// Verify the exact certificate's challenge proof and admit either live authority
/// or a delivery capability for its server-retained refusal, never both.
async fn authenticate(
    store: EnrollmentStore,
    proof: &AgentLinkProof,
    nonce: &[u8],
) -> io::Result<AuthorityGuard> {
    if proof.message_type != "proof" || nonce.len() != 32 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let der = canonical_base64(&proof.certificate_der)?;
    if der.len() > 4096 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let certificate = X509::from_der(&der).map_err(|_| io::ErrorKind::PermissionDenied)?;
    if certificate.to_der().map_err(io::Error::other)? != der {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let signature = canonical_base64(&proof.signature)?;
    if signature.len() > 512 || !verify_signature(&certificate, proof.host_id, nonce, &signature) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let digest = certificate
        .digest(MessageDigest::sha256())
        .map_err(io::Error::other)?;
    let fingerprint: [u8; 32] = digest
        .as_ref()
        .try_into()
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let authority = tokio::time::timeout(
        HANDSHAKE,
        AuthorityGuard::admit_transport(store, fingerprint),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if authority.identity.host != proof.host_id {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(authority)
}

#[cfg(test)]
mod tests {
    //! Host proof validation and handshake capacity through cleanup delivery.
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::{PKey, Private},
        sign::Signer,
        x509::{X509Builder, X509NameBuilder},
    };

    /// A self-signed Ed25519 host certificate and its key, valid for a day.
    pub(super) fn signing_certificate() -> (X509, PKey<Private>) {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "fixture").unwrap();
        let name = name.build();
        let mut certificate = X509Builder::new().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::null()).unwrap();
        (certificate.build(), key)
    }

    #[test]
    fn challenge_signature_requires_the_d168_key_host_and_nonce() {
        let (certificate, key) = signing_certificate();
        let host_id = Uuid::from_u128(1);
        let nonce = [9; 32];
        let mut signer = Signer::new_without_digest(&key).unwrap();
        let signature = signer
            .sign_oneshot_to_vec(&proof_bytes(host_id, &nonce))
            .unwrap();
        assert!(verify_signature(&certificate, host_id, &nonce, &signature));
        assert!(!verify_signature(
            &certificate,
            Uuid::from_u128(2),
            &nonce,
            &signature
        ));
        assert!(!verify_signature(
            &certificate,
            host_id,
            &[8; 32],
            &signature
        ));
    }
    /// A validated cleanup WebSocket must return both handshake permits before
    /// its durable receipt. Receiving the revoke request is the ordering fence.
    #[tokio::test]
    async fn websocket_cleanup_returns_handshake_slots_before_receipt() {
        use futures_util::{SinkExt, StreamExt};
        use infraternal_protocol::{Frame, encode_muxed_frame_into};
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let (certificate, key) = signing_certificate();
        let fingerprint = certificate.digest(MessageDigest::sha256()).unwrap();
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let person = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,'cleanup','cleanup',0,'test')")
            .bind(person.to_string()).execute(&pool).await.unwrap();
        sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
            .bind(person.to_string())
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE remote_certificates SET fingerprint=?,not_before=unixepoch()-1,not_after=unixepoch()+604799")
            .bind(fingerprint.as_ref()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES (?,?)")
            .bind(host.as_bytes().as_slice())
            .bind(person.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let global = Arc::new(Semaphore::new(1));
        let sources = Arc::new(crate::remote_admission::SourceSlots::new(1));
        let address: IpAddr = "127.0.0.1".parse().unwrap();
        let api = Api {
            hosts: RemoteHosts::default(),
            store,
            admission: global.clone(),
            sources: sources.clone(),
        };
        let router = Router::new()
            .route("/remote/agent", get(upgrade))
            .with_state(api);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let (mut socket, _) =
            tokio_tungstenite::connect_async(format!("ws://{endpoint}/remote/agent"))
                .await
                .unwrap();
        let challenge = socket.next().await.unwrap().unwrap();
        let challenge: AgentLinkChallenge =
            serde_json::from_str(challenge.to_text().unwrap()).unwrap();
        let nonce = B64.decode(challenge.nonce).unwrap();
        let signature = Signer::new_without_digest(&key)
            .unwrap()
            .sign_oneshot_to_vec(&proof_bytes(host, &nonce))
            .unwrap();
        let proof = AgentLinkProof {
            message_type: "proof".to_owned(),
            host_id: host,
            certificate_der: B64.encode(certificate.to_der().unwrap()),
            signature: B64.encode(signature),
        };
        socket
            .send(ClientMessage::Text(
                serde_json::to_string(&proof).unwrap().into(),
            ))
            .await
            .unwrap();
        let ready = socket.next().await.unwrap().unwrap();
        assert!(ready.to_text().unwrap().contains("ready"));
        let mut hello = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "cleanup-admission-test",
            },
            &mut hello,
        )
        .unwrap();
        socket
            .send(ClientMessage::Binary(hello.into()))
            .await
            .unwrap();
        let _hello = socket.next().await.unwrap().unwrap();
        let revoke = socket.next().await.unwrap().unwrap();
        let bytes = revoke.into_data();
        let request = infraternal_protocol::decode_muxed_frame(&bytes).unwrap();
        assert!(
            matches!(
                request.frame,
                Frame::Call {
                    action_id: "terminal.login.revoke",
                    ..
                }
            ),
            "expected cleanup request before receipt"
        );
        assert_eq!(
            global.available_permits(),
            1,
            "cleanup retained global handshake slot"
        );
        assert!(
            sources.reserve(address).is_some(),
            "cleanup retained source handshake slot"
        );
        drop(socket);
        server.abort();
        let _ = server.await;
    }

    /// The budget hands out at most its size, refuses the next read, and
    /// passes every byte once lifted, without losing any in between.
    #[tokio::test]
    async fn proof_budget_caps_reads_until_lifted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut peer, local) = tokio::io::duplex(64);
        let mut budget = ProofBudget::new(local, 4);
        peer.write_all(b"abcdefgh").await.unwrap();
        let mut read = [0; 8];
        assert_eq!(budget.read(&mut read).await.unwrap(), 4);
        assert_eq!(&read[..4], b"abcd");
        assert_eq!(
            budget.read(&mut read).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        budget.lift();
        assert_eq!(budget.read(&mut read).await.unwrap(), 4);
        assert_eq!(&read[..4], b"efgh");
    }

    /// #572 finding 6: a peer that has not proved anything may not make the
    /// server buffer a 4 MiB message. The test announces a 4 MiB text message
    /// as its "proof" and sends 64 KiB of it. The server must drop the socket
    /// once it has read a proof's worth of bytes, long before the 5 s
    /// handshake deadline, and return its handshake slots. Before the fix it
    /// kept reading until the deadline.
    #[tokio::test]
    async fn unproved_peer_is_cut_off_after_a_proofs_worth_of_bytes() {
        use futures_util::StreamExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (store, _pool, _host) = crate::enrollment::authority::tests::enrolled().await;
        let global = Arc::new(Semaphore::new(1));
        let sources = Arc::new(crate::remote_admission::SourceSlots::new(1));
        let api = Api {
            hosts: RemoteHosts::default(),
            store,
            admission: global.clone(),
            sources,
        };
        let router = Router::new()
            .route("/remote/agent", get(upgrade))
            .with_state(api);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let tcp = tokio::net::TcpStream::connect(endpoint).await.unwrap();
        let (mut socket, _) =
            tokio_tungstenite::client_async(format!("ws://{endpoint}/remote/agent"), tcp)
                .await
                .unwrap();
        let _challenge = socket.next().await.unwrap().unwrap();
        // Write the frame by hand: FIN + text, masked, 64-bit length 4 MiB,
        // a zero mask key, then 64 KiB of the payload.
        let tcp = socket.get_mut();
        let mut header = vec![0x81, 0x80 | 127];
        header.extend_from_slice(&(4_u64 << 20).to_be_bytes());
        header.extend_from_slice(&[0; 4]);
        tcp.write_all(&header).await.unwrap();
        // The server may reset the stream while we write; that is the result
        // we want, so write errors are ignored here and judged by the read.
        let _ = tcp.write_all(&vec![b'a'; 64 * 1024]).await;
        let mut byte = [0; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0) | Err(_))),
            "server kept buffering an unproved 4 MiB message: {closed:?}"
        );
        // The permit returns when the admission task ends; give it a moment.
        tokio::time::timeout(Duration::from_secs(2), async {
            while global.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("handshake slot returned after the cut-off");
        server.abort();
        let _ = server.await;
    }
}

/// The removal outbox delivers the uninstall after the receipt (#409).
#[cfg(test)]
#[path = "remote_removal_outbox_tests.rs"]
mod removal_outbox_tests;
