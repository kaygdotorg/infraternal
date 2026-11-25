//! Admits D168 host links that arrive through the app listener's WebSocket [168,196], #291, #559.
//!
//! `/remote/agent` upgrades to a WebSocket and then runs the server side of
//! the leg-B mutual TLS session inside it, with the acceptor the QUIC and
//! TCP/TLS listeners use right now (our CA, the current rotating leaf, ALPN
//! `infraternal/1`, client certificate required). Whatever terminated the
//! outer HTTPS session, this process or a reverse proxy, only ever carried
//! leg-B ciphertext. The host's verified certificate then passes the same
//! durable ledger admission as a TCP/TLS link, and the link runs as one.
//!
//! The recovery ALPN is not accepted here: certificate recovery uses the
//! server's own port only.

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
use hyper_util::rt::TokioIo;
use infraternal_agent::{
    remote_tls,
    remote_websocket::{WebSocketCarrier, carrier_config},
};
use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{handshake::derive_accept_key, protocol::Role},
};

const HANDSHAKE: Duration = Duration::from_secs(5);
/// Bytes an unauthenticated peer may make the server read before its TLS
/// client certificate is verified and admitted: the inner TLS client
/// flights (a `ClientHello`, including a post-quantum key share, then the
/// host certificate, its signature and Finished, together about 4 KiB),
/// possibly the first protocol frame sent with them, and the WebSocket
/// headers around each, with room to spare (#572 finding 6).
const PROOF_READ_BUDGET: usize = 16 * 1024;

/// Caps how many bytes an unauthenticated `/remote/agent` socket may read
/// until its host is admitted (#572 finding 6).
///
/// It sits below the WebSocket layer, so it counts raw bytes, including
/// fragmented and control frames: without it, each of the 64 handshake slots
/// could be made to buffer a full WebSocket message for the 5 s handshake
/// deadline before TLS rejected anything. A read past the budget fails with
/// `InvalidData`, which ends the handshake. [`BudgetLift::lift`] removes the
/// cap once the host is admitted; the handle is shared because by then the
/// socket is owned by the TLS channel.
pub(crate) struct ProofBudget<S> {
    /// The upgraded connection.
    inner: S,
    /// Bytes still allowed while `lifted` is false.
    remaining: usize,
    /// Set by the [`BudgetLift`] handle once the host is admitted.
    lifted: Arc<AtomicBool>,
}

/// Lifts a [`ProofBudget`]: the peer has proved it holds an enrolled host key.
pub(crate) struct BudgetLift(Arc<AtomicBool>);

impl BudgetLift {
    /// Let the socket read without limit from now on.
    pub(crate) fn lift(&self) {
        self.0.store(true, Ordering::Release);
    }
}

impl<S> ProofBudget<S> {
    /// Wrap `inner` so at most `budget` bytes can be read until the returned
    /// handle lifts the cap.
    fn new(inner: S, budget: usize) -> (Self, BudgetLift) {
        let lifted = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                remaining: budget,
                lifted: lifted.clone(),
            },
            BudgetLift(lifted),
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProofBudget<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.lifted.load(Ordering::Acquire) {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.remaining == 0 {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        // Read into a window no larger than the budget. Zeroing it costs at
        // most the budget once per read, and only before admission.
        let window = buf.initialize_unfilled_to(this.remaining.min(buf.remaining()));
        let mut limited = ReadBuf::new(window);
        let result = Pin::new(&mut this.inner).poll_read(cx, &mut limited);
        let read = limited.filled().len();
        if let Poll::Ready(Ok(())) = result {
            buf.advance(read);
            this.remaining -= read;
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
        let (budgeted, lift) = ProofBudget::new(TokioIo::new(upgraded), PROOF_READ_BUDGET);
        let socket =
            WebSocketStream::from_raw_socket(budgeted, Role::Server, Some(carrier_config())).await;
        if let Err(error) = admit(socket, lift, api, address, source, permit).await {
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

/// Run leg-B TLS inside the upgraded socket, admit the verified host
/// certificate and its protocol Hello, then hand the link to the host
/// registry. Handshake capacity returns once the Hello is validated; the
/// bounded per-host cleanup lane owns durable delivery from there.
async fn admit<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: WebSocketStream<ProofBudget<S>>,
    lift: BudgetLift,
    api: Api,
    address: IpAddr,
    source: OwnedSemaphorePermit,
    permit: OwnedSemaphorePermit,
) -> io::Result<()> {
    // The acceptor current now, as on the TCP listener: a rotated leaf
    // applies from the next handshake (#559). Before the listeners start
    // there is no leaf to serve, so nothing can be admitted.
    let tls = api
        .hosts
        .current_acceptor()
        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let connection = trace_test_phase(
        "tls",
        remote_tls::accept_over(WebSocketCarrier::new(socket).into_carrier(), &tls).await,
    )?;
    let authority = trace_test_phase(
        "host-ledger",
        tokio::time::timeout(
            HANDSHAKE,
            AuthorityGuard::admit_transport(api.store.clone(), connection.peer_fingerprint),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
    )?;
    // The peer holds an enrolled host key: from here it may send full frames.
    lift.lift();
    let link = trace_test_phase(
        "protocol-greeting",
        crate::remote_link::RemoteLink::tcp_admitted(connection.channel, None).await,
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

#[cfg(test)]
pub(crate) mod tests {
    //! The route's admission, budget and handshake capacity, driven by a
    //! host that runs the real inner leg-B TLS over a loopback WebSocket.
    use super::*;
    use crate::remote_runtime::RemoteListeners;
    use infraternal_agent::{
        channel::Channel,
        remote_tls::{Identity, TcpTls},
        transport::Receive,
    };
    use infraternal_protocol::{DecodedMuxedFrame, Frame, encode_muxed_frame_into};
    use openssl::x509::X509;
    use std::net::SocketAddr;
    use uuid::Uuid;

    /// A `/remote/agent` route on plain loopback HTTP (as behind a reverse
    /// proxy) whose inner TLS uses the acceptor of real leg-B listeners.
    pub(crate) struct Route {
        /// Where the route listens.
        pub(crate) endpoint: SocketAddr,
        /// Keeps the leg-B listeners, and so the current acceptor, alive.
        _listeners: RemoteListeners,
        /// The HTTP server task, aborted on drop.
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Route {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    /// Serve `api` with leg-B listeners that present `leaf` and trust `root`.
    async fn serve(api: Api, leaf: &Identity, root: &X509) -> Route {
        let listeners = RemoteListeners::start(
            "127.0.0.1:0".parse().unwrap(),
            leaf,
            std::slice::from_ref(root),
            api.store.clone(),
            api.hosts.clone(),
        )
        .await
        .unwrap();
        let router = Router::new()
            .route("/remote/agent", get(upgrade))
            .with_state(api);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        Route {
            endpoint,
            _listeners: listeners,
            server,
        }
    }

    /// Serve a route over `store` and `hosts` with the given handshake slots.
    pub(crate) async fn route(
        store: EnrollmentStore,
        hosts: RemoteHosts,
        admission: Arc<Semaphore>,
        sources: Arc<crate::remote_admission::SourceSlots>,
        leaf: &Identity,
        root: &X509,
    ) -> Route {
        let api = Api {
            hosts,
            store,
            admission,
            sources,
        };
        serve(api, leaf, root).await
    }

    /// The host side of one `/remote/agent` link, as a real infraternal agent
    /// holds it: the inner leg-B TLS channel and its frame decoder.
    pub(crate) struct HostLink {
        /// The inner TLS channel.
        pub(crate) channel: TcpTls,
        /// Decodes frames from the channel.
        receive: Receive,
    }

    impl HostLink {
        /// Upgrade `ws://endpoint/remote/agent` and run leg-B TLS inside it
        /// as `identity`, trusting `root` for the server `localhost`.
        pub(crate) async fn dial(
            endpoint: SocketAddr,
            identity: &Identity,
            root: &X509,
        ) -> io::Result<Self> {
            let tcp = tokio::net::TcpStream::connect(endpoint).await?;
            let (socket, _) = tokio_tungstenite::client_async_with_config(
                format!("ws://{endpoint}/remote/agent"),
                tcp,
                Some(carrier_config()),
            )
            .await
            .map_err(io::Error::other)?;
            let config = remote_tls::client_config(identity, std::slice::from_ref(root))?;
            let connection = remote_tls::dial_over(
                WebSocketCarrier::new(socket).into_carrier(),
                "localhost",
                &config,
            )
            .await?;
            Ok(Self {
                channel: connection.channel,
                receive: Receive::default(),
            })
        }

        /// Write one control-stream frame.
        pub(crate) async fn send(&self, frame: &Frame<'_>) -> io::Result<()> {
            let mut bytes = Vec::new();
            encode_muxed_frame_into(0, frame, &mut bytes)
                .map_err(|_| io::ErrorKind::InvalidData)?;
            self.channel.write(&bytes).await
        }

        /// Read the next frame from the server.
        pub(crate) async fn next(&mut self) -> io::Result<DecodedMuxedFrame<'_>> {
            self.receive.next(&self.channel).await
        }
    }

    /// The Hello an infraternal agent sends first.
    pub(crate) fn hello(client_info: &str) -> Frame<'_> {
        Frame::Hello {
            version: 1,
            caps: 0,
            client_info,
        }
    }

    /// A validated cleanup link must return both handshake permits before
    /// its durable receipt. Receiving the revoke request is the ordering fence.
    #[tokio::test]
    async fn websocket_cleanup_returns_handshake_slots_before_receipt() {
        let (leaf, node, root, _) = crate::remote_runtime::tests::identities();
        let (store, pool, host, _) =
            crate::remote_runtime::tests::revocation::admitted_store(&node, &root).await;
        let person = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,'cleanup','cleanup',0,'test')")
            .bind(person.to_string()).execute(&pool).await.unwrap();
        sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
            .bind(person.to_string())
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES (?,?)")
            .bind(host.as_bytes().as_slice())
            .bind(person.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let global = Arc::new(Semaphore::new(1));
        let sources = Arc::new(crate::remote_admission::SourceSlots::new(1));
        let address: IpAddr = "127.0.0.1".parse().unwrap();
        let route = route(
            store,
            RemoteHosts::default(),
            global.clone(),
            sources.clone(),
            &leaf,
            &root,
        )
        .await;
        let mut link = HostLink::dial(route.endpoint, &node, &root).await.unwrap();
        link.send(&hello("cleanup-admission-test")).await.unwrap();
        assert!(matches!(
            link.next().await.unwrap().frame,
            Frame::Hello { .. }
        ));
        let request = link.next().await.unwrap();
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
    }

    /// The budget hands out at most its size, refuses the next read, and
    /// passes every byte once lifted, without losing any in between.
    #[tokio::test]
    async fn proof_budget_caps_reads_until_lifted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut peer, local) = tokio::io::duplex(64);
        let (mut budget, lift) = ProofBudget::new(local, 4);
        peer.write_all(b"abcdefgh").await.unwrap();
        let mut read = [0; 8];
        assert_eq!(budget.read(&mut read).await.unwrap(), 4);
        assert_eq!(&read[..4], b"abcd");
        assert_eq!(
            budget.read(&mut read).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        lift.lift();
        assert_eq!(budget.read(&mut read).await.unwrap(), 4);
        assert_eq!(&read[..4], b"efgh");
    }

    /// #572 finding 6: a peer that has not been admitted may not make the
    /// server buffer a whole WebSocket message. The test announces a binary
    /// message just under the carrier's limit and sends 32 KiB of it. The
    /// server must drop the socket once it has read a TLS client flight's
    /// worth of bytes, long before the 5 s handshake deadline, and return its
    /// handshake slots.
    #[tokio::test]
    async fn unproved_peer_is_cut_off_after_a_client_flights_worth_of_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (leaf, _node, root, _) = crate::remote_runtime::tests::identities();
        let (store, _pool, _host) = crate::enrollment::authority::tests::enrolled().await;
        let global = Arc::new(Semaphore::new(1));
        let route = route(
            store,
            RemoteHosts::default(),
            global.clone(),
            Arc::new(crate::remote_admission::SourceSlots::new(1)),
            &leaf,
            &root,
        )
        .await;
        let tcp = tokio::net::TcpStream::connect(route.endpoint)
            .await
            .unwrap();
        let (mut socket, _) =
            tokio_tungstenite::client_async(format!("ws://{}/remote/agent", route.endpoint), tcp)
                .await
                .unwrap();
        // Write the frame by hand: FIN + binary, masked, 16-bit length just
        // under the carrier limit, a zero mask key, then 32 KiB of payload.
        let tcp = socket.get_mut();
        let mut header = vec![0x82, 0x80 | 0x7e];
        header.extend_from_slice(&u16::try_from(60 * 1024).unwrap().to_be_bytes());
        header.extend_from_slice(&[0; 4]);
        tcp.write_all(&header).await.unwrap();
        // The server may reset the stream while we write; that is the result
        // we want, so write errors are ignored here and judged by the read.
        let _ = tcp.write_all(&vec![0x16; 32 * 1024]).await;
        let mut byte = [0; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0) | Err(_))),
            "server kept buffering an unproved message: {closed:?}"
        );
        // The permit returns when the admission task ends; give it a moment.
        tokio::time::timeout(Duration::from_secs(2), async {
            while global.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("handshake slot returned after the cut-off");
    }
}

/// The removal outbox delivers the uninstall after the receipt (#409).
#[cfg(test)]
#[path = "remote_removal_outbox_tests.rs"]
mod removal_outbox_tests;
