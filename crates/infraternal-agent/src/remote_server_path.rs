//! Moves the host's one authenticated server connection onto plugin-proposed paths and back, below QUIC, without a reconnect [128,198,215,263], #201.
//!
//! Every QUIC connection names the enrolled server address. Its `PathSocket`
//! decides where datagrams physically go. A mesh proposal moves the live
//! connection in place: a fresh encrypted probe announces the selected route,
//! and the server's shared endpoint maps admitted source aliases and
//! authenticates every datagram. Streams, writer
//! bindings and terminal offsets never change, so no application data is
//! replayed or reattached. While on the mesh the host asks for an acknowledgement every
//! probe interval; the first unanswered probe after one RTT plus a margin
//! returns the connection to the enrolled address, resending a bounded recent
//! history of encrypted mesh datagrams at once.
//!
//! A TCP connection (UDP to the enrolled address unavailable) cannot move. It
//! keeps the earlier behaviour: a separately proven QUIC connection to the mesh
//! address replaces it.
use super::{
    Connected, RemoteIdentity, dial_preferred,
    dial_runtime::DialRuntime,
    quic_session_on,
    supervisor::{MAX_BACKOFF, retry_delay},
};
use crate::{channel::Channel, daemon, remote_quic, remote_tls};
use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind, ServerLinkReason};
use infraternal_plugin_remote::remote_path_socket::{Path, PathSocket};
use std::{io, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Acknowledgement requests while on the mesh; this is the path's idle cost.
const MESH_PROBE_INTERVAL: Duration = Duration::from_millis(100);
/// Beyond one RTT: the server's 25 ms maximum ACK delay plus scheduling jitter.
const MESH_PROBE_MARGIN: Duration = Duration::from_millis(50);
/// Negotiated copies carry data during detection. Allocate 15 ms for the
/// next existing probe and 30 ms for ACK delay/scheduling in the RTT+50 ms target.
const BACKUP_PROBE_INTERVAL: Duration = Duration::from_millis(15);
const BACKUP_PROBE_MARGIN: Duration = Duration::from_millis(30);
/// A switched path must answer within this much beyond two RTTs (a possible
/// `WireGuard` handshake, then the server's reply) before it is used.
const SWITCH_MARGIN: Duration = Duration::from_millis(200);

/// The dial drivers belong to a single transport, including losing probes.
struct Link {
    connected: Connected,
    endpoint: Option<quinn::Endpoint>,
    driver: Option<DialRuntime>,
    /// QUIC links only: where the connection's datagrams physically go.
    path: Option<Arc<PathSocket>>,
    address: SocketAddr,
    /// Dialing creates this once; the owning run loop moves it into the session.
    proof: Option<super::ProvedControl>,
    standby: tokio::sync::watch::Sender<u64>,
}
impl Drop for Link {
    fn drop(&mut self) {
        match &self.connected {
            Connected::Quic(connection) => connection.close(0u32.into(), b""),
            Connected::Tcp(connection) => connection.channel.retire(),
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"");
        }
        self.driver.take();
    }
}
impl Link {
    /// The path actually carrying traffic now, which a QUIC link can change.
    fn current(&self) -> (ServerLinkKind, SocketAddr) {
        match self.path.as_ref().map(|path| (path.path(), path.logical())) {
            Some((Path::Mesh(address), _)) => (ServerLinkKind::Mesh, address),
            Some((Path::Enrolled, logical)) => (ServerLinkKind::Fallback, logical),
            // Only the enrolled dial can return TCP; mesh dials require QUIC.
            None => (ServerLinkKind::Fallback, self.address),
        }
    }
}

fn current(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    address: SocketAddr,
) -> io::Result<RemoteIdentity> {
    let credentials = match renewal {
        Some(renewal) => renewal.current()?,
        None => remote_tls::Identity {
            certificate: identity.identity.certificate.clone(),
            key: identity.identity.key.clone(),
        },
    };
    crate::remote_renewal::require_current(&credentials)?;
    Ok(RemoteIdentity {
        identity: credentials,
        roots: identity.roots.clone(),
        endpoint: address,
        server_name: identity.server_name.clone(),
        execution_uid: identity.execution_uid,
    })
}

/// Dial the enrolled server address. A mesh dial sends the same connection's
/// datagrams to `address` from the start, so a later return needs no new dial.
async fn connect(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    address: SocketAddr,
    kind: ServerLinkKind,
    prove: bool,
) -> io::Result<Link> {
    let identity = current(identity, renewal, identity.endpoint)?;
    let driver = DialRuntime::new();
    let path = PathSocket::new(
        driver.runtime().wrap_udp_socket(std::net::UdpSocket::bind(
            if identity.endpoint.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            },
        )?)?,
        identity.endpoint,
    );
    if kind == ServerLinkKind::Mesh {
        path.use_mesh(address);
    }
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        path.clone(),
        driver.runtime(),
    )?;
    endpoint.set_default_client_config(remote_quic::client_config(
        &identity.identity,
        &identity.roots,
    )?);
    let connected = if kind == ServerLinkKind::Mesh {
        // Mutual TLS keeps the enrolled SAN and identity unchanged. Application
        // proof below completes before any Hello can replace the server actor.
        // The shared dial already owns the five-second handshake deadline.
        Connected::Quic(super::quic_connect(&endpoint, &identity).await?)
    } else {
        let tls = remote_tls::client_config(&identity.identity, &identity.roots)?;
        dial_preferred(&endpoint, &identity, &tls).await?
    };
    let (endpoint, driver, path) = if matches!(&connected, Connected::Tcp(_)) {
        drop(endpoint);
        drop(driver);
        (None, None, None)
    } else {
        (Some(endpoint), Some(driver), Some(path))
    };
    let mut link = Link {
        connected,
        endpoint,
        driver,
        path,
        address,
        proof: None,
        standby: tokio::sync::watch::channel(0).0,
    };
    if prove {
        // Only QUIC mesh candidates need pre-admission control proof. TCP
        // is the enrolled fallback and uses the common raw control adapter.
        let Connected::Quic(connection) = &link.connected else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        let proof = tokio::time::timeout(PROBE_TIMEOUT, async {
            let (send, receive) = connection.open_bi().await.map_err(io::Error::other)?;
            let control = crate::remote_native::NativeChannel::control(send, receive)?;
            let mut receive = crate::transport::Receive::default();
            prove_channel(&control, &mut receive).await?;
            Ok::<_, io::Error>(super::ProvedControl { control, receive })
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        link.proof = Some(proof);
    }
    Ok(link)
}

async fn prove_channel<C: Channel>(
    channel: &C,
    receive: &mut crate::transport::Receive,
) -> io::Result<()> {
    let nonce = u64::from_le_bytes(
        uuid::Uuid::new_v4().as_bytes()[..8]
            .try_into()
            .map_err(io::Error::other)?,
    );
    crate::transport::Transmit::default()
        .send(
            channel,
            0,
            &infraternal_protocol::Frame::Ping { nonce, sent_us: 0 },
        )
        .await?;
    let response = receive.next(channel).await?;
    if response.stream_id != 0
        || response.frame != (infraternal_protocol::Frame::Pong { nonce, sent_us: 0 })
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn report(
    registry: &crate::plugin_control::Registry,
    link: Option<&Link>,
    reason: ServerLinkReason,
) {
    let current = link.map(Link::current);
    registry.set_server_link(ServerLink {
        kind: current.map_or(ServerLinkKind::Disconnected, |(kind, _)| kind),
        endpoint: current.map(|(_, address)| address),
        source_port: link.and_then(|link| link.path.as_ref()).and_then(|path| {
            use quinn::AsyncUdpSocket as _;
            path.local_addr().ok().map(|address| address.port())
        }),
        reason,
    });
}

async fn session(
    link: &Link,
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
    proof: Option<super::ProvedControl>,
) -> io::Result<()> {
    match &link.connected {
        Connected::Quic(connection) => {
            quic_session_on(
                connection.clone(),
                identity,
                state,
                renewal,
                registry,
                proof,
                &link.standby,
            )
            .await
        }
        Connected::Tcp(connection) => {
            // Both remote transports use this one concrete control adapter,
            // sharing the daemon/relay code without decoding raw TCP twice.
            let channel = super::ControlChannel::Tcp(&connection.channel);
            daemon::run_authenticated_with_plugins(
                &channel,
                state,
                identity.execution_uid,
                renewal,
                registry,
            )
            .await
        }
    }
}

/// Wait until the current path answers: a datagram from that exact address,
/// then newly authenticated traffic. Returns false at the deadline.
pub(super) async fn answered(
    connection: &quinn::Connection,
    path: &PathSocket,
    since: tokio::time::Instant,
    mesh: bool,
) -> bool {
    let mut freshness = remote_quic::PeerFreshness::new(connection);
    let deadline = connection
        .rtt()
        .saturating_mul(2)
        .min(Duration::from_secs(3))
        + SWITCH_MARGIN;
    // Routing and encrypted replay already changed synchronously. A missing
    // early enrolled ACK must not destroy the writer-bearing connection before
    // QUIC can recover lost packets. The longer proof guard adds no wait when
    // the enrolled path answers, while still bounding recovery to TCP if both
    // UDP paths are unavailable.
    let deadline = if mesh {
        deadline
    } else {
        deadline.max(Duration::from_secs(1))
    };
    tokio::time::timeout(deadline, async {
        // A candidate's first encrypted packet can precede the leased listener
        // or be lost during the kernel handshake. DATAGRAM probes are fresh,
        // ack-eliciting traffic; they do not wait for QUIC's loss timer and do
        // not replay application input. The clock is owned by this proof only.
        let mut probes = tokio::time::interval(BACKUP_PROBE_INTERVAL);
        probes.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let heard = if mesh {
                path.heard_since(since.into_std())
            } else {
                path.enrolled_heard_since(since.into_std())
            };
            // Quinn decrypts the datagram after the socket reports it; the
            // frame signature changes on the endpoint driver's next pass.
            if heard && freshness.silence(connection) < since.elapsed() {
                return;
            }
            tokio::select! {
                _ = probes.tick() => remote_quic::probe_liveness(connection),
                () = path.mesh_heard(since.into_std()), if mesh && !heard => {},
                () = tokio::time::sleep(Duration::from_millis(if heard || !mesh { 1 } else { 5 })) => {},
            }
        }
    })
    .await
    .is_ok()
}

/// Return in place to the enrolled address, resending bounded recent ciphertext.
async fn to_enrolled(
    link: &Link,
    registry: &crate::plugin_control::Registry,
    reason: ServerLinkReason,
) -> bool {
    let (Connected::Quic(connection), Some(path)) = (&link.connected, link.path.as_ref()) else {
        return false;
    };
    let since = tokio::time::Instant::now();
    path.use_enrolled();
    // Status describes the selected physical path. Its proof continues on the
    // same connection, without hiding the completed route change for another RTT.
    report(registry, Some(link), reason);
    remote_quic::probe_liveness(connection);
    answered(connection, path, since, false).await
}

enum Steered {
    /// The session or its transport ended; the caller reconnects.
    Ended,
    /// A TCP link was replaced by a separately proven QUIC link.
    Replaced(Box<Link>, ServerLinkReason),
}

/// A late mesh reply wakes a fresh authenticated proof rather than waiting for
/// retry backoff. This routing hint neither changes the path nor admits a peer.
async fn retry_path(path: &PathSocket, deadline: tokio::time::Instant, since: std::time::Instant) {
    tokio::select! {
        () = tokio::time::sleep_until(deadline) => {},
        () = path.mesh_heard(since) => {},
    }
}

/// Drive one QUIC link: move it between paths in place until its session ends.
#[allow(clippy::too_many_lines)]
async fn steer(
    link: &Link,
    identity: &RemoteIdentity,
    registry: &crate::plugin_control::Registry,
    cooling: bool,
    reason: &mut ServerLinkReason,
    mut active: std::pin::Pin<&mut impl std::future::Future<Output = io::Result<()>>>,
) -> Steered {
    let (Connected::Quic(connection), Some(path)) = (&link.connected, link.path.as_ref()) else {
        return Steered::Ended;
    };
    let mut proposals = registry.server_paths();
    let mut capabilities = link.standby.subscribe();
    let mut retry = Duration::from_secs(1);
    let mut not_before = tokio::time::Instant::now() + if cooling { retry } else { Duration::ZERO };
    let mut retry_since = std::time::Instant::now();
    loop {
        let proposed = (*proposals.borrow_and_update())
            .map(|ip| SocketAddr::new(ip, identity.endpoint.port()));
        match path.path() {
            Path::Enrolled => {
                let Some(mesh) = proposed else {
                    tokio::select! {
                        _ = &mut active => return Steered::Ended,
                        changed = proposals.changed() => if changed.is_err() { return Steered::Ended },
                    }
                    continue;
                };
                tokio::select! {
                    _ = &mut active => return Steered::Ended,
                    changed = proposals.changed() => {
                        if changed.is_err() { return Steered::Ended }
                        continue;
                    }
                    () = retry_path(path, not_before, retry_since) => {}
                }
                let since = tokio::time::Instant::now();
                path.use_mesh(mesh);
                path.set_backup(
                    *capabilities.borrow_and_update()
                        & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                        != 0,
                );
                remote_quic::probe_liveness(connection);
                let moved = tokio::select! {
                    _ = &mut active => return Steered::Ended,
                    moved = answered(connection, path, since, true) => moved,
                };
                if moved {
                    retry = Duration::from_secs(1);
                    *reason = ServerLinkReason::MeshProven;
                } else {
                    // An unanswered switch keeps the session: its datagrams are
                    // resent on the enrolled path and the move retries later.
                    *reason = ServerLinkReason::MeshRefused;
                    retry_since = std::time::Instant::now();
                    let backed = *capabilities.borrow_and_update()
                        & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                        != 0;
                    // A joining peer can release only queued copies, yielding
                    // no fresh mesh reply. Negotiated backup keeps enrolled
                    // traffic live while discovery retries on the probe clock.
                    // Without it, preserve recovery and exponential cooling;
                    // its bounded enrolled guard always ends before five seconds.
                    not_before = tokio::time::Instant::now()
                        + if backed {
                            BACKUP_PROBE_INTERVAL
                        } else {
                            PROBE_TIMEOUT
                        };
                    // Selecting enrolled is synchronous. A late mesh reply may
                    // start fresh proof without waiting for enrolled recovery;
                    // the hint itself neither proves nor changes the path.
                    tokio::select! {
                        // Poll the return first so a pre-latched hint cannot
                        // skip selecting enrolled after the candidate miss.
                        biased;
                        _ = &mut active => return Steered::Ended,
                        _ = to_enrolled(link, registry, *reason) => {},
                        () = retry_path(path, not_before, retry_since) => {},
                    }
                    if !backed {
                        not_before = tokio::time::Instant::now() + retry;
                        retry = (retry * 2).min(Duration::from_secs(30));
                    }
                }
                report(registry, Some(link), *reason);
            }
            Path::Mesh(current) => {
                let backup = *capabilities.borrow_and_update()
                    & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                    != 0;
                path.set_backup(backup);
                let (interval, margin) = if backup {
                    (BACKUP_PROBE_INTERVAL, BACKUP_PROBE_MARGIN)
                } else {
                    (MESH_PROBE_INTERVAL, MESH_PROBE_MARGIN)
                };
                if proposed.is_some_and(|proposed| {
                    proposed.ip().to_canonical() == current.ip().to_canonical()
                }) {
                    let interrupted = tokio::select! {
                        _ = &mut active => return Steered::Ended,
                        changed = proposals.changed() => {
                            if changed.is_err() { return Steered::Ended }
                            false
                        }
                        changed = capabilities.changed() => {
                            if changed.is_err() { return Steered::Ended }
                            false
                        }
                        result = remote_quic::path_interrupted(connection, path, interval, margin) => result.is_err(),
                    };
                    if !interrupted {
                        continue;
                    }
                }
                // A component edit and an interruption deadline can become
                // ready in the same poll. The latest proposal owns the reason,
                // even when select chose the deadline instead of the edit.
                let proposed = (*proposals.borrow_and_update())
                    .map(|ip| SocketAddr::new(ip, identity.endpoint.port()));
                *reason = if proposed.is_none() {
                    ServerLinkReason::MeshDisabled
                } else {
                    ServerLinkReason::MeshInterrupted
                };
                if proposed.is_some_and(|proposed| {
                    proposed.ip().to_canonical() == current.ip().to_canonical()
                }) {
                    not_before = tokio::time::Instant::now() + retry;
                    retry = (retry * 2).min(Duration::from_secs(30));
                } else {
                    not_before = tokio::time::Instant::now();
                }
                retry_since = std::time::Instant::now();
                let returned = tokio::select! {
                    _ = &mut active => return Steered::Ended,
                    returned = to_enrolled(link, registry, *reason) => returned,
                };
                if proposed.is_none() {
                    path.forget_mesh();
                }
                report(registry, Some(link), *reason);
                if !returned {
                    // The enrolled address is not answering either (for example
                    // UDP is blocked there). End this session; the caller's dial
                    // race, including TCP, owns recovery.
                    return Steered::Ended;
                }
            }
        }
    }
}

/// A TCP link cannot move below its transport. A separately proven QUIC link
/// to the mesh address replaces it; a failed candidate leaves the session live.
async fn replacement(
    live: &Link,
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: &crate::plugin_control::Registry,
    cooling: bool,
) -> io::Result<(Link, ServerLinkReason)> {
    let mut paths = registry.server_paths();
    let mut retry = Duration::from_secs(1);
    if cooling {
        tokio::time::sleep(retry).await;
    }
    loop {
        let Some(ip) = *paths.borrow_and_update() else {
            paths
                .changed()
                .await
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            retry = Duration::from_secs(1);
            continue;
        };
        let destination = SocketAddr::new(ip, identity.endpoint.port());
        // A changed preference cancels only this candidate's owned socket. In
        // particular, an explicit component down cannot leave a probe running.
        tokio::select! {
            result = connect(identity, renewal, destination, ServerLinkKind::Mesh, true) => {
                if let Ok(link) = result { return Ok((link, ServerLinkReason::MeshProven)); }
                report(registry, Some(live), ServerLinkReason::MeshRefused);
            }
            changed = paths.changed() => {
                changed.map_err(|_| io::ErrorKind::BrokenPipe)?;
                continue;
            }
        }
        tokio::select! {
            () = tokio::time::sleep(retry) => {},
            changed = paths.changed() => { changed.map_err(|_| io::ErrorKind::BrokenPipe)?; },
        }
        retry = (retry * 2).min(MAX_BACKOFF);
    }
}

/// Run a TCP link's session while a QUIC mesh candidate is proven beside it.
async fn replace_tcp(
    link: &Link,
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: &crate::plugin_control::Registry,
    cooling: bool,
    active: std::pin::Pin<&mut impl std::future::Future<Output = io::Result<()>>>,
) -> Steered {
    let replacing = replacement(link, identity, renewal, registry, cooling);
    tokio::select! {
        result = replacing => result.map_or(Steered::Ended, |(next, why)| Steered::Replaced(Box::new(next), why)),
        _ = active => Steered::Ended,
    }
}

/// A component down retains its meaning when transport closure wins its race.
fn interruption_reason(
    registry: &crate::plugin_control::Registry,
    was: ServerLinkKind,
    reason: ServerLinkReason,
) -> ServerLinkReason {
    if was != ServerLinkKind::Mesh
        && !matches!(
            reason,
            ServerLinkReason::MeshInterrupted | ServerLinkReason::MeshDisabled
        )
    {
        return ServerLinkReason::Connecting;
    }
    if registry.server_paths().borrow().is_none() {
        ServerLinkReason::MeshDisabled
    } else {
        ServerLinkReason::MeshInterrupted
    }
}

/// Keeps enrolled fallback available, moving only after authenticated path proof.
/// Existing durable shim offsets make transport replacement independent of leg A.
/// Retained applied intent can reconnect even when the enrollment port is unavailable.
/// Fresh nodes have no proposal and use the unchanged enrollment dial race.
async fn available(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: &crate::plugin_control::Registry,
    force_fallback: bool,
) -> io::Result<Link> {
    let mut paths = registry.server_paths();
    let proposed = *paths.borrow_and_update();
    let Some(ip) = proposed.filter(|_| !force_fallback) else {
        return connect(
            identity,
            renewal,
            identity.endpoint,
            ServerLinkKind::Fallback,
            false,
        )
        .await;
    };
    let mesh = connect(
        identity,
        renewal,
        SocketAddr::new(ip, identity.endpoint.port()),
        ServerLinkKind::Mesh,
        true,
    );
    let fallback = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        connect(
            identity,
            renewal,
            identity.endpoint,
            ServerLinkKind::Fallback,
            false,
        )
        .await
    };
    tokio::pin!(mesh, fallback);
    tokio::select! {
        result = &mut mesh => match result { Ok(link) => Ok(link), Err(_) => fallback.await },
        result = &mut fallback => match result { Ok(link) => Ok(link), Err(_) => mesh.await },
        _ = paths.changed() => Err(io::ErrorKind::Interrupted.into()),
    }
}

// Keep pinned-session retirement and reconnect accounting in the same owning scope.
#[allow(clippy::too_many_lines)]
pub(super) async fn run(
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
    connected: tokio::sync::watch::Sender<bool>,
) -> io::Result<()> {
    // No preference is valid; an error means the local worker is unavailable.
    // The retry owner replaces only a terminated worker before reconnecting.
    registry
        .initialize_paths()
        .await
        .map_err(|_| io::ErrorKind::Other)?;
    let mut live = None;
    let mut force_fallback = false;
    let mut reason = ServerLinkReason::MeshUnavailable;
    let mut backoff = Duration::from_millis(200);
    let mut cooling = false;
    loop {
        let attempt_started = tokio::time::Instant::now();
        // Reconnection itself never waits for a failed mesh probe. Once the
        // fallback is healthy, moves run on the live connection itself.
        let mut link = if let Some(link) = live.take() {
            link
        } else {
            match available(identity, renewal, &registry, force_fallback).await {
                Ok(link) => {
                    force_fallback = false;
                    // Available proves only its mesh dial before activation.
                    if link.proof.is_some() {
                        reason = ServerLinkReason::MeshProven;
                    }
                    link
                }
                Err(error) => {
                    force_fallback = false;
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    current(identity, renewal, identity.endpoint)?;
                    if backoff == Duration::from_millis(200) {
                        eprintln!(
                            "Infraternal agent server unavailable ({:?}); retrying with bounded backoff",
                            error.kind()
                        );
                    }
                    report(&registry, None, reason);
                    tokio::time::sleep(retry_delay(backoff, attempt_started.elapsed())).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            }
        };
        let started = tokio::time::Instant::now();
        report(&registry, Some(&link), reason);
        connected.send_replace(true);
        // Construct the session once, rather than embedding its large future
        // in both path drivers. Borrowing the same pinned future adds no heap
        // allocation. This scope drops it before the old Link retires; a
        // cancelled partial write is safe only while that Link closes channel.
        let steered = {
            // This loop exclusively owns the Link. Transfer the dial proof
            // before borrowing it for concurrent session and path futures;
            // neither future can consume the control stream a second time.
            let proof = link.proof.take();
            let active = session(
                &link,
                identity,
                state.clone(),
                renewal,
                registry.clone(),
                proof,
            );
            tokio::pin!(active);
            if link.path.is_some() {
                steer(
                    &link,
                    identity,
                    &registry,
                    cooling,
                    &mut reason,
                    active.as_mut(),
                )
                .await
            } else {
                replace_tcp(
                    &link,
                    identity,
                    renewal,
                    &registry,
                    cooling,
                    active.as_mut(),
                )
                .await
            }
        };
        connected.send_replace(false);
        let (was, _) = link.current();
        match steered {
            Steered::Replaced(next, why) => {
                live = Some(*next);
                reason = why;
                cooling = false;
            }
            Steered::Ended => {
                // A transport close can race a component down; the current
                // applied preference owns the reason.
                reason = interruption_reason(&registry, was, reason);
                cooling = reason == ServerLinkReason::MeshInterrupted;
                force_fallback = cooling;
                report(&registry, None, reason);
                if was == ServerLinkKind::Fallback {
                    let elapsed = if started.elapsed() > Duration::from_secs(10) {
                        backoff = Duration::from_millis(200);
                        Duration::ZERO
                    } else {
                        attempt_started.elapsed()
                    };
                    tokio::time::sleep(retry_delay(backoff, elapsed)).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
        drop(link);
    }
}

#[cfg(test)]
#[path = "remote_server_path_tests.rs"]
mod tests;
