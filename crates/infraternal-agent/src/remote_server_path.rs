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
    supervisor::{LinkNotes, MAX_BACKOFF, retry_delay},
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
    // None is pre-Hello; Some(0) is an authenticated peer without extensions.
    standby: tokio::sync::watch::Sender<Option<u64>>,
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
    /// Apply authenticated Hello capabilities before publishing their status.
    /// Selecting enrolled keeps the copy clock idle until mesh traffic resumes.
    fn negotiated(&self, caps: u64) {
        if let Some(path) = &self.path {
            path.set_backup(caps & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP != 0);
        }
        self.standby.send_replace(Some(caps));
    }
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

/// Validate one renewal snapshot; otherwise borrow the original credentials.
/// Root trust, the enrolled address and SAN always belong to the caller.
fn current_credentials(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
) -> io::Result<Option<remote_tls::Identity>> {
    let refreshed = renewal
        .map(crate::remote_renewal::RenewalIdentity::current)
        .transpose()?;
    crate::remote_renewal::require_current(refreshed.as_ref().unwrap_or(&identity.identity))?;
    Ok(refreshed)
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
    let enrolled_address = identity
        .endpoint
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
    let refreshed = current_credentials(identity, renewal)?;
    let credentials = refreshed.as_ref().unwrap_or(&identity.identity);
    let driver = DialRuntime::new();
    let path = PathSocket::from_udp(
        std::net::UdpSocket::bind(if enrolled_address.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })?,
        enrolled_address,
        driver.runtime().as_ref(),
    )?;
    if kind == ServerLinkKind::Mesh {
        path.use_mesh(address);
    }
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        path.clone(),
        driver.runtime(),
    )?;
    endpoint.set_default_client_config(remote_quic::client_config(credentials, &identity.roots)?);
    let connected = if kind == ServerLinkKind::Mesh {
        // Mutual TLS keeps the enrolled SAN and identity unchanged. Application
        // proof below completes before any Hello can replace the server actor.
        // The shared dial already owns the five-second handshake deadline.
        Connected::Quic(super::quic_connect(&endpoint, identity).await?)
    } else {
        let tls = remote_tls::client_config(credentials, &identity.roots)?;
        dial_preferred(&endpoint, identity, &tls).await?
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
        standby: tokio::sync::watch::channel(None).0,
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

/// Whether the server refused this host's TLS identity, directly or as a QUIC TLS alert under a stream error.
/// Only that refusal falls back to the pending predecessor identity.
fn identity_admission_refused(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::PermissionDenied {
        return true;
    }
    let Some(source) = error.get_ref() else {
        return false;
    };
    if let Some(connection) = source.downcast_ref::<quinn::ConnectionError>() {
        return connection_refused_by_tls(connection);
    }
    if let Some(read) = source.downcast_ref::<quinn::ReadError>() {
        return matches!(read, quinn::ReadError::ConnectionLost(error) if connection_refused_by_tls(error));
    }
    if let Some(write) = source.downcast_ref::<quinn::WriteError>() {
        return matches!(write, quinn::WriteError::ConnectionLost(error) if connection_refused_by_tls(error));
    }
    source
        .downcast_ref::<io::Error>()
        .is_some_and(identity_admission_refused)
}

/// Whether a QUIC connection ended with a TLS alert code.
fn connection_refused_by_tls(error: &quinn::ConnectionError) -> bool {
    match error {
        quinn::ConnectionError::TransportError(error) => is_tls_crypto_error(error.code),
        quinn::ConnectionError::ConnectionClosed(error) => is_tls_crypto_error(error.error_code),
        _ => false,
    }
}

/// QUIC reserves 0x100–0x1ff for TLS alert codes; other close codes can be
/// network, application, or protocol failures and must not trigger identity fallback.
fn is_tls_crypto_error(code: quinn::TransportErrorCode) -> bool {
    (0x100..0x200).contains(&u64::from(code))
}

/// Retry a refused candidate once with its durable predecessor, without demoting it.
async fn connect_with_predecessor_fallback(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    address: SocketAddr,
    kind: ServerLinkKind,
    prove: bool,
) -> io::Result<Link> {
    match connect(identity, renewal, address, kind, prove).await {
        Ok(link) => Ok(link),
        Err(candidate_error) if identity_admission_refused(&candidate_error) => {
            let Some(renewal) = renewal else {
                return Err(candidate_error);
            };
            let Some(predecessor) = renewal.predecessor_for()? else {
                return Err(candidate_error);
            };
            let predecessor_identity = RemoteIdentity {
                host_id: identity.host_id,
                identity: predecessor,
                roots: identity.roots.clone(),
                endpoint: identity.endpoint,
                server_name: identity.server_name.clone(),
                public_origin: identity.public_origin.clone(),
                https_root: identity.https_root.clone(),
                https_system_roots: identity.https_system_roots,
                execution_uid: identity.execution_uid,
            };
            connect(&predecessor_identity, None, address, kind, prove).await
        }
        Err(error) => Err(error),
    }
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
                |caps| link.negotiated(caps),
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
    let Ok(_epoch) = path.proof_epoch(connection) else {
        return false;
    };
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
            let heard = if mesh { path.heard_since(since.into_std()) } else { path.enrolled_heard_since(since.into_std()) };
            if path.path_authenticated_since(since.into_std(), mesh) {
                return;
            }
            tokio::select! {
                _ = probes.tick() => {
                    // Retransmit the outstanding sequence; a new sequence
                    // must not overtake its response on a WAN.
                    let _ = path.send_path_proof(mesh);
                    remote_quic::probe_liveness(connection);
                },
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

/// Candidate proof is separate from proven-path interruption. Backed discovery
/// retains its physical mesh sends and bounded history across failed epochs.
#[derive(PartialEq, Eq)]
enum Candidate {
    Proven,
    Refused,
    Unreachable,
}

async fn candidate(
    connection: &quinn::Connection,
    path: &PathSocket,
    proposals: &mut tokio::sync::watch::Receiver<Option<std::net::IpAddr>>,
    capabilities: &mut tokio::sync::watch::Receiver<Option<u64>>,
) -> Candidate {
    // This observer outlives individual mesh proof epochs. Resetting it with
    // every unanswered candidate would strand both-dead UDP until QUIC expiry.
    let mut alive = remote_quic::PeerFreshness::new(connection);
    loop {
        let caps = (*capabilities.borrow_and_update()).unwrap_or_default();
        if caps & infraternal_plugin_api::channel::REMOTE_PATH_PROOF == 0 {
            return Candidate::Refused;
        }
        let mut backed = caps & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP != 0;
        let proof = answered(connection, path, tokio::time::Instant::now(), true);
        tokio::pin!(proof);
        let moved = loop {
            tokio::select! {
                _ = proposals.changed() => return Candidate::Refused,
                changed = capabilities.changed() => {
                    if changed.is_err() {
                        return Candidate::Refused;
                    }
                    let caps = (*capabilities.borrow_and_update()).unwrap_or_default();
                    let next = caps & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP != 0;
                    if caps & infraternal_plugin_api::channel::REMOTE_PATH_PROOF == 0
                        || (backed && !next) {
                        return Candidate::Refused;
                    }
                    backed = next;
                }
                moved = &mut proof => break moved,
            }
        };
        if moved {
            // A reply and capability withdrawal can become ready together.
            // Admission follows the current contract, regardless of select order.
            let caps = (*capabilities.borrow_and_update()).unwrap_or_default();
            if caps & infraternal_plugin_api::channel::REMOTE_PATH_PROOF == 0
                || (backed && caps & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP == 0)
            {
                return Candidate::Refused;
            }
            return Candidate::Proven;
        }
        if (*capabilities.borrow_and_update()).unwrap_or_default()
            & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
            == 0
        {
            return Candidate::Refused;
        }
        if alive.silence(connection) >= PROBE_TIMEOUT {
            return Candidate::Unreachable;
        }
        // Keep copies and ciphertext history intact. A new answered epoch
        // requires a fresh tuple-bound response and keeps probing on its
        // existing clock; an old reply cannot become proof through elapsed time.
    }
}

/// Drive one QUIC link: move it between paths in place until its session ends.
async fn steer(
    link: &Link,
    identity: &RemoteIdentity,
    registry: &crate::plugin_control::Registry,
    cooling: bool,
    reason: &mut ServerLinkReason,
    mut active: std::pin::Pin<&mut impl std::future::Future<Output = io::Result<()>>>,
) -> Steered {
    let Some(enrolled_address) = identity.endpoint else {
        return Steered::Ended;
    };
    let (Connected::Quic(connection), Some(path)) = (&link.connected, link.path.as_ref()) else {
        return Steered::Ended;
    };
    let mut proposals = registry.server_paths();
    let mut capabilities = link.standby.subscribe();
    let mut retry = Duration::from_secs(1);
    let mut not_before = tokio::time::Instant::now() + if cooling { retry } else { Duration::ZERO };
    let mut retry_since = std::time::Instant::now();
    loop {
        let proposed =
            (*proposals.borrow_and_update()).map(|ip| SocketAddr::new(ip, enrolled_address.port()));
        let Some(caps) = *capabilities.borrow_and_update() else {
            // A retained mesh dial is already authenticated, but its active
            // session must consume Hello before missing bits mean refusal.
            tokio::select! {
                _ = &mut active => return Steered::Ended,
                changed = capabilities.changed() => if changed.is_err() { return Steered::Ended },
                changed = proposals.changed() => if changed.is_err() { return Steered::Ended },
            }
            continue;
        };
        let supports_proof = caps & infraternal_plugin_api::channel::REMOTE_PATH_PROOF != 0;
        match path.path() {
            Path::Enrolled => {
                let Some(mesh) = proposed.filter(|_| supports_proof) else {
                    tokio::select! {
                        _ = &mut active => return Steered::Ended,
                        changed = proposals.changed() => if changed.is_err() { return Steered::Ended },
                        changed = capabilities.changed() => if changed.is_err() { return Steered::Ended },
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
                path.use_mesh(mesh);
                path.set_backup(
                    (*capabilities.borrow_and_update()).unwrap_or_default()
                        & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                        != 0,
                );
                remote_quic::probe_liveness(connection);
                let moved = tokio::select! {
                    _ = &mut active => return Steered::Ended,
                    moved = candidate(connection, path, &mut proposals, &mut capabilities) => moved,
                };
                let latest = *proposals.borrow_and_update();
                if moved == Candidate::Proven && latest == Some(mesh.ip()) {
                    retry = Duration::from_secs(1);
                    *reason = ServerLinkReason::MeshProven;
                } else {
                    // Legacy refusal and cancelled intent return synchronously;
                    // healthy backed discovery never selects this enrolled-only
                    // gap. Only independent silence can expire both UDP paths.
                    *reason = if latest.is_none() {
                        ServerLinkReason::MeshDisabled
                    } else {
                        ServerLinkReason::MeshRefused
                    };
                    retry_since = std::time::Instant::now();
                    not_before = tokio::time::Instant::now() + PROBE_TIMEOUT;
                    // One return future owns the same replay/status/proof in
                    // both cases. Only legacy refusal may stop waiting on a hint;
                    // both-dead recovery must finish this proof before redialing.
                    let returned = tokio::select! {
                        biased;
                        _ = &mut active => return Steered::Ended,
                        returned = to_enrolled(link, registry, *reason) => returned,
                        () = retry_path(path, not_before, retry_since),
                            if moved != Candidate::Unreachable => true,
                    };
                    if moved == Candidate::Unreachable && !returned {
                        return Steered::Ended;
                    }
                    if latest.is_none() {
                        path.forget_mesh();
                    }
                    let backed = (*capabilities.borrow_and_update()).unwrap_or_default()
                        & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                        != 0;
                    not_before = tokio::time::Instant::now();
                    if !backed && latest == Some(mesh.ip()) {
                        not_before += retry;
                        retry = (retry * 2).min(Duration::from_secs(30));
                    }
                }
                report(registry, Some(link), *reason);
            }
            Path::Mesh(current) => {
                let backup = (*capabilities.borrow_and_update()).unwrap_or_default()
                    & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                    != 0;
                path.set_backup(backup);
                let (interval, margin) = if backup {
                    (BACKUP_PROBE_INTERVAL, BACKUP_PROBE_MARGIN)
                } else {
                    (MESH_PROBE_INTERVAL, MESH_PROBE_MARGIN)
                };
                if supports_proof
                    && proposed.is_some_and(|proposed| {
                        proposed.ip().to_canonical() == current.ip().to_canonical()
                    })
                {
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
                    .map(|ip| SocketAddr::new(ip, enrolled_address.port()));
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
    let enrolled_address = identity
        .endpoint
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
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
        let destination = SocketAddr::new(ip, enrolled_address.port());
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
    let enrolled_address = identity
        .endpoint
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
    let mut paths = registry.server_paths();
    let proposed = *paths.borrow_and_update();
    let Some(ip) = proposed.filter(|_| !force_fallback) else {
        return connect_with_predecessor_fallback(
            identity,
            renewal,
            enrolled_address,
            ServerLinkKind::Fallback,
            false,
        )
        .await;
    };
    let mesh = connect_with_predecessor_fallback(
        identity,
        renewal,
        SocketAddr::new(ip, enrolled_address.port()),
        ServerLinkKind::Mesh,
        true,
    );
    let fallback = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        connect_with_predecessor_fallback(
            identity,
            renewal,
            enrolled_address,
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
pub(super) async fn run(
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
    connected: tokio::sync::watch::Sender<bool>,
) -> io::Result<()> {
    Box::pin(run_observed(
        identity,
        state,
        renewal,
        registry,
        connected,
        #[cfg(any(test, feature = "native-streams"))]
        None,
    ))
    .await
}

// One supervisor loop owns path selection, proof and the optional failure
// observer; splitting it would pass the same retained link state around.
pub(super) async fn run_observed(
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
    connected: tokio::sync::watch::Sender<bool>,
    #[cfg(any(test, feature = "native-streams"))] observer: Option<&super::FailureObserver<'_>>,
) -> io::Result<()> {
    if identity.endpoint.is_none() {
        return run_https(identity, state, renewal, registry, connected).await;
    }
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
    // One line per minute at most, so a flapping link cannot flood the agent log.
    let notes = LinkNotes::new();
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
                    #[cfg(any(test, feature = "native-streams"))]
                    super::observe_failure(observer, "dial", &error);
                    force_fallback = false;
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    current_credentials(identity, renewal)?;
                    if let Some(line) = notes.note(attempt_started, || {
                        format!(
                            "Infraternal agent server link refused or unreachable (closed by: server or network, error {:?}, path reason {reason:?}); retrying with bounded backoff",
                            error.kind()
                        )
                    }) {
                        eprintln!("{line}");
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
                let lasted = started.elapsed();
                reason = interruption_reason(&registry, was, reason);
                if let Some(line) = notes.note(tokio::time::Instant::now(), || {
                    format!(
                        "Infraternal agent server link closed (closed by: server or network, link {was:?}, path reason {reason:?}, lasted {} ms); reconnecting",
                        lasted.as_millis()
                    )
                }) {
                    eprintln!("{line}");
                }
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
        registry.capabilities(0);
        drop(link);
    }
}

/// Keep identities enrolled on the public app origin on the 443 fallback path [196,291].
/// Mesh selection is deliberately separate; this link proves D168 key possession at the app.
async fn run_https(
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
    connected: tokio::sync::watch::Sender<bool>,
) -> io::Result<()> {
    let public_origin = identity
        .public_origin
        .as_deref()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut backoff = Duration::from_millis(200);
    let notes = LinkNotes::new();
    loop {
        let started = tokio::time::Instant::now();
        let credentials = match current_credentials(identity, renewal) {
            Ok(refreshed) => refreshed,
            Err(error) => {
                registry.set_server_link(ServerLink {
                    kind: ServerLinkKind::Disconnected,
                    endpoint: None,
                    source_port: None,
                    reason: ServerLinkReason::MeshUnavailable,
                });
                return Err(error);
            }
        };
        let credentials = credentials.as_ref().unwrap_or(&identity.identity);
        let channel = crate::remote_websocket::connect(
            public_origin,
            identity.host_id,
            credentials,
            identity.https_root.as_ref(),
            identity.https_system_roots,
        )
        .await;
        let channel = match channel {
            Ok(channel) => channel,
            Err(error) => {
                if let Some(line) = notes.note(started, || {
                    format!(
                        "Infraternal agent HTTPS server link refused or unreachable (error {:?}); retrying",
                        error.kind()
                    )
                }) {
                    eprintln!("{line}");
                }
                registry.set_server_link(ServerLink {
                    kind: ServerLinkKind::Disconnected,
                    endpoint: None,
                    source_port: None,
                    reason: ServerLinkReason::MeshUnavailable,
                });
                tokio::time::sleep(retry_delay(backoff, started.elapsed())).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        registry.set_server_link(ServerLink {
            kind: ServerLinkKind::Fallback,
            endpoint: None,
            source_port: None,
            reason: ServerLinkReason::MeshUnavailable,
        });
        connected.send_replace(true);
        let active = daemon::run_authenticated_with_plugins(
            &channel,
            state.clone(),
            identity.execution_uid,
            renewal,
            registry.clone(),
        )
        .await;
        connected.send_replace(false);
        channel.retire();
        registry.set_server_link(ServerLink {
            kind: ServerLinkKind::Disconnected,
            endpoint: None,
            source_port: None,
            reason: ServerLinkReason::MeshUnavailable,
        });
        if let Some(line) = notes.note(started, || {
            format!(
                "Infraternal agent HTTPS server link closed (error {:?}); reconnecting",
                active.err().map(|error| error.kind())
            )
        }) {
            eprintln!("{line}");
        }
        if started.elapsed() >= Duration::from_secs(10) {
            backoff = Duration::from_millis(200);
        }
        tokio::time::sleep(retry_delay(backoff, started.elapsed())).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
#[path = "remote_server_path_tests.rs"]
mod tests;
