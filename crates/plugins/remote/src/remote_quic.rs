//! Uses owner-selected quinn/BBR and mTLS, binding native streams to durable server writer ids before terminal frames [11][64][130], #78.

pub use crate::remote_path_proof::path_probe_header;
use crate::remote_tls::Identity;
use openssl::x509::X509;
use std::{io, sync::Arc};

/// Server-authorized writer identity plus its independent native QUIC stream.
pub struct BoundStream {
    /// Stable even leg-B writer id; never derived from the native stream id.
    pub writer_id: u32,
    /// Raw v1 wire frames, without the TCP mux envelope.
    pub send: quinn::SendStream,
    /// Raw v1 wire frames; the binding parser leaves all following bytes here.
    pub receive: quinn::RecvStream,
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "remote infraternal agent QUIC transport refused",
    )
}

/// Additive leg-B capability; leg-A `RESUME_NEXT` bit0 is independent.
pub use infraternal_plugin_api::channel::REMOTE_WRITER_BINDING;

/// Peer Hello has opted into durable writer binding. Raw mTLS alone cannot
/// enable a new protocol action on a peer that only supports legacy v1.
pub struct BindingConnection(quinn::Connection);

/// Require the current peer's decoded control Hello before opening terminal streams.
/// # Errors
/// Refuses missing/wrong Hello version or absent binding capability.
pub fn negotiate_binding(
    connection: &quinn::Connection,
    peer_hello: &infraternal_protocol::Frame<'_>,
) -> io::Result<BindingConnection> {
    if matches!(peer_hello, infraternal_protocol::Frame::Hello {version:1,caps,..} if caps & REMOTE_WRITER_BINDING != 0)
    {
        Ok(BindingConnection(connection.clone()))
    } else {
        Err(denied())
    }
}

const ALPN: &[u8] = b"infraternal/1";
const BINDING_LIMIT: usize = 128;
const BINDING_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

fn roots(certificates: &[X509]) -> io::Result<rustls::RootCertStore> {
    if certificates.is_empty() || certificates.len() > 16 {
        return Err(denied());
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(rustls::pki_types::CertificateDer::from(
                certificate.to_der().map_err(|_| denied())?,
            ))
            .map_err(|_| denied())?;
    }
    Ok(roots)
}
fn identity(
    identity: &Identity,
) -> io::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let certificate = rustls::pki_types::CertificateDer::from(
        identity.certificate.to_der().map_err(|_| denied())?,
    );
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        identity.key.private_key_to_pkcs8().map_err(|_| denied())?,
    );
    Ok((vec![certificate], key.into()))
}
/// Largest UDP payload a host connection may discover. The connection can move
/// onto the mesh below QUIC without seeing a path change (`remote_path_socket`),
/// so its discovered size must also fit the mesh interface: 1380-byte interface
/// MTU minus the 20-byte IPv4 and 8-byte UDP headers. A larger datagram would
/// be dropped locally (EMSGSIZE) and stall until black-hole detection.
pub const PATH_SAFE_UDP_PAYLOAD: u16 = 1352;
/// Received QUIC DATAGRAM bytes buffered per connection. This is also the
/// largest DATAGRAM the peer may send. Terminal-only builds receive only
/// one-byte liveness probes while on the mesh and nothing reads them; the bound
/// keeps that buffer at a few entries instead of Quinn's default.
#[cfg(not(feature = "native-streams"))]
const DATAGRAM_BUFFER: usize = 64;
/// Native plugin lanes (desktop video, #146) send 1 KiB fragments over the same
/// connection and read them as they arrive, so builds with them accept a full
/// fragment and a short burst of a keyframe. A cap, not an allocation.
#[cfg(feature = "native-streams")]
const DATAGRAM_BUFFER: usize = 128 * 1024;

fn transport(incoming_streams: u32) -> std::sync::Arc<quinn::TransportConfig> {
    transport_with_liveness(
        incoming_streams,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
        false,
    )
}
fn transport_with_liveness(
    incoming_streams: u32,
    keep_alive: std::time::Duration,
    idle: std::time::Duration,
    client: bool,
) -> std::sync::Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    if client {
        // Enrolled ciphertext copies and ACK delay share the backed path's
        // 30ms response margin. Negotiate 5ms without extending loss detection;
        // preserve the ordinary immediate ACK on the first reordered packet.
        let mut frequency = quinn::AckFrequencyConfig::default();
        frequency.max_ack_delay(Some(std::time::Duration::from_millis(5)));
        frequency.reordering_threshold(1u32.into());
        config.ack_frequency_config(Some(frequency));
    }
    // Both directions retain their learned MTU across a socket-level mesh move.
    let mut discovery = quinn::MtuDiscoveryConfig::default();
    discovery.upper_bound(PATH_SAFE_UDP_PAYLOAD);
    config.mtu_discovery_config(Some(discovery));
    config.congestion_controller_factory(std::sync::Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));
    // Transport probes preserve stateful mappings without database or authority
    // work. The caller chooses its measured liveness profile; acknowledged
    // traffic resets idle expiry, with QUIC retaining its minimum PTO bound.
    config
        .max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            u32::try_from(idle.as_millis()).unwrap_or(60_000),
        ))))
        .keep_alive_interval(Some(keep_alive));
    config.max_concurrent_uni_streams(0u32.into());
    // Quinn preallocates slots up to this limit. Hosts initiate only control0;
    // server-opened terminals use the daemon's existing attachment bound, not
    // the deployment-wide viewer count multiplied across every idle host.
    config.max_concurrent_bidi_streams(incoming_streams.into());
    // Credit bounds outstanding bytes across streams, not just stream count.
    // 1MiB per peer is <=1GiB outstanding at the 1000-host admission target.
    config
        .receive_window(1_048_576u32.into())
        .stream_receive_window(262_144u32.into())
        .send_window(1_048_576);
    std::sync::Arc::new(config)
}
/// Configure authenticated server admission and event-driven BBR transport.
/// Callers must bound `Incoming`/`Connecting` and control-Hello negotiation
/// explicitly; the transport idle deadline is separate from application admission.
/// # Errors
/// Refuses invalid identity/trust or unavailable crypto configuration.
pub fn server_config(
    endpoint: &Identity,
    certificates: &[X509],
) -> io::Result<quinn::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(certificates)?),
        provider.clone(),
    )
    .build()
    .map_err(|_| denied())?;
    let (chain, key) = identity(endpoint)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| denied())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| denied())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| denied())?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport(1));
    Ok(config)
}
/// Configure outgoing mTLS and retained public server trust.
/// Callers must bound `Connecting` and control-Hello negotiation explicitly;
/// healthy established connections remain live through acknowledged transport probes.
/// # Errors
/// Refuses invalid identity/trust or unavailable crypto configuration.
pub fn client_config(
    endpoint: &Identity,
    certificates: &[X509],
) -> io::Result<quinn::ClientConfig> {
    client_config_with_liveness(
        endpoint,
        certificates,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    )
}

/// Configure transport-only liveness for a proven alternative path.
/// The caller measures RTT; credential verification and all stream limits stay identical.
/// # Errors
/// Refuses invalid identity/trust or a zero, inverted, or excessive timer interval.
pub fn client_config_with_liveness(
    endpoint: &Identity,
    certificates: &[X509],
    keep_alive: std::time::Duration,
    idle: std::time::Duration,
) -> io::Result<quinn::ClientConfig> {
    if keep_alive < std::time::Duration::from_millis(1)
        || keep_alive >= idle
        || idle > std::time::Duration::from_secs(60)
    {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let (chain, key) = identity(endpoint)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| denied())?
        .with_root_certificates(roots(certificates)?)
        .with_client_auth_cert(chain, key)
        .map_err(|_| denied())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // No replayable 0-RTT: terminal input and enrollment are stateful authority.
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| denied())?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport_with_liveness(
        u32::try_from(infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS)
            .map_err(|_| denied())?,
        keep_alive,
        idle,
        true,
    ));
    Ok(config)
}
/// Samples authenticated frames after path proof; raw UDP arrivals cannot keep
/// a failed path alive. Stream and flow-control frames also count, because a
/// healthy one-way output stream need not acknowledge new client data.
pub struct PeerFreshness {
    frames: [u64; 24],
    observed: tokio::time::Instant,
}
impl PeerFreshness {
    /// Start only after the caller has proved the peer's enrolled identity.
    #[must_use]
    pub fn new(connection: &quinn::Connection) -> Self {
        Self {
            frames: authenticated_frames(connection),
            observed: tokio::time::Instant::now(),
        }
    }
    /// Return time without newly authenticated traffic. Counter wrap still
    /// changes this signature; duplicate and invalid packets never advance it.
    pub fn silence(&mut self, connection: &quinn::Connection) -> std::time::Duration {
        self.recorded_silence(authenticated_frames(connection))
    }
    fn recorded_silence(&mut self, frames: [u64; 24]) -> std::time::Duration {
        if frames != self.frames {
            self.frames = frames;
            self.observed = tokio::time::Instant::now();
        }
        self.observed.elapsed()
    }
    /// Observe an authenticated signature change since the previous observation.
    /// Raw or duplicate UDP cannot satisfy a path proof through elapsed time.
    #[must_use]
    pub fn observe_change(&mut self, connection: &quinn::Connection) -> bool {
        let previous = self.frames;
        let _ = self.silence(connection);
        self.frames != previous
    }
    /// Watch an established path without application traffic or ledger work.
    /// The future owns no detached task; cancellation stops every observation.
    /// # Errors
    /// Returns a fixed interruption, expiry, or invalid interval error.
    pub async fn interrupted(
        &mut self,
        connection: &quinn::Connection,
        deadline: std::time::Duration,
    ) -> io::Result<()> {
        if deadline < std::time::Duration::from_millis(100)
            || deadline > std::time::Duration::from_secs(60)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut observations = tokio::time::interval(std::time::Duration::from_millis(50));
        observations.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = connection.closed() => return Err(io::ErrorKind::BrokenPipe.into()),
                _ = observations.tick() => if self.silence(connection) >= deadline { return Err(io::ErrorKind::TimedOut.into()); },
            }
        }
    }
    /// Detect a proven mesh interruption from current authenticated ACK/keepalive
    /// timing. RTT changes update the budget rather than freezing a dial-time timer.
    /// # Errors
    /// Returns transport closure or interruption after one RTT plus scheduler margin.
    pub async fn interrupted_adaptive(&mut self, connection: &quinn::Connection) -> io::Result<()> {
        let mut observations = tokio::time::interval(std::time::Duration::from_millis(50));
        observations.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Preserve one closure subscription across observations instead of
        // repeatedly locking Quinn and registering/cancelling its Notify waiter.
        let mut closed = std::pin::pin!(connection.closed());
        loop {
            tokio::select! {
                _ = closed.as_mut() => return Err(io::ErrorKind::BrokenPipe.into()),
                _ = observations.tick() => {
                    // One coherent state snapshot supplies both current RTT
                    // and authenticated counters; raw UDP cannot buy liveness.
                    let stats = connection.stats();
                    let budget = stats.path.rtt.saturating_add(std::time::Duration::from_millis(200));
                    if self.recorded_silence(authenticated_signature(stats.frame_rx)) >= budget { return Err(io::ErrorKind::TimedOut.into()); }
                }
            }
        }
    }
}
/// Bounded public failure evidence for opt-in transport measurements only.
#[cfg(feature = "test-support")]
#[derive(Debug, serde::Serialize)]
pub struct ProbeFailure {
    /// Public counters and clocks distinguish missing physical replies from
    /// authentication/driver progress. No packet or terminal contents survive.
    pub mesh_reply_after_first_send: bool,
    pub first_send_age_us: u128,
    pub flush_age_us: u128,
    pub authenticated_silence_us: u128,
    pub authenticated_progress_not_observed: bool,
    pub constructed_datagrams_before: u64,
    pub constructed_datagrams_after: u64,
    pub rtt_us: u128,
}
#[cfg(feature = "test-support")]
impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
#[cfg(feature = "test-support")]
impl std::error::Error for ProbeFailure {}

/// Watch a path by asking for acknowledgements every `interval`. It is
/// interrupted when a probe sees no newly authenticated frame within the
/// current RTT plus `margin` (the server's ACK delay and scheduling jitter).
/// Detection therefore follows the first unanswered probe, not a fixed silence
/// window measured from the last packet. One timer and one probe per interval
/// are the whole idle cost; cancellation stops both.
/// # Errors
/// Returns `TimedOut` on interruption or `BrokenPipe` when the connection closes.
pub async fn path_interrupted(
    connection: &quinn::Connection,
    path: &crate::remote_path_socket::PathSocket,
    interval: std::time::Duration,
    margin: std::time::Duration,
) -> io::Result<()> {
    if matches!(path.path(), crate::remote_path_socket::Path::Mesh(address) if address != path.logical())
    {
        return authenticated_path_interrupted(connection, path, interval, margin).await;
    }
    // One physical tuple needs only the existing adaptive QUIC health guard.
    // Keep its ordinary 100 ms probe cadence at the design point rather than
    // flooding the shared receiver with the alias path's low-latency probes.
    let mut freshness = PeerFreshness::new(connection);
    let mut interrupted = std::pin::pin!(freshness.interrupted_adaptive(connection));
    let mut probes = tokio::time::interval(std::time::Duration::from_millis(100));
    probes.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = interrupted.as_mut() => return result,
            _ = probes.tick() => probe_liveness(connection),
        }
    }
}

// Kept for the one-tuple case and emission regressions: authenticated counters
// are path-specific only when no distinct physical response can be normalized.
#[cfg(test)]
pub(crate) async fn quic_path_interrupted(
    connection: &quinn::Connection,
    path: &crate::remote_path_socket::PathSocket,
    interval: std::time::Duration,
    margin: std::time::Duration,
) -> io::Result<()> {
    let mut freshness = PeerFreshness::new(connection);
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut closed = std::pin::pin!(connection.closed());
    // The endpoint may queue a probe while its socket is not writable. Only
    // a successful encrypted socket send starts the network-response clock.
    let mut queued: Option<crate::remote_path_socket::MeshTransmission<'_>> = None;
    let mut datagrams_before = 0;
    let mut pending: Option<(tokio::time::Instant, tokio::time::Instant)> = None;
    loop {
        let deadline = pending.map(|(_, flushed)| flushed + connection.rtt() + margin);
        tokio::select! {
            _ = closed.as_mut() => return Err(io::ErrorKind::BrokenPipe.into()),
            _ = ticks.tick() => {
                let stats = connection.stats();
                let silence = freshness.recorded_silence(authenticated_signature(stats.frame_rx));
                if pending.is_some_and(|(sent, _)| path.heard_since(sent.into_std()) && silence < sent.elapsed()) {
                    pending = None;
                }
                if pending.is_none() && queued.is_none() {
                    datagrams_before = stats.frame_tx.datagram;
                    queued = Some(path.mesh_transmitted_after(std::time::Instant::now())?);
                }
                probe_liveness(connection);
            }
            sent = async {
                queued.as_ref().ok_or(io::ErrorKind::Interrupted)?.probe_sent(connection, datagrams_before).await
            }, if queued.is_some() => {
                let (first, flushed) = sent?;
                pending = Some((first.into(), flushed.into()));
                queued = None;
            }
            () = async { tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)).await }, if deadline.is_some() => {
                let Some((sent, _)) = pending else { continue };
                // Let an already-ready endpoint receive authenticate its ACK
                // before deciding a timer that became ready in the same pass.
                tokio::task::yield_now().await;
                // Authenticated enrolled copies preserve data but cannot prove
                // the mesh. Require a response from its physical tuple too.
                if !path.heard_since(sent.into_std()) || freshness.silence(connection) >= sent.elapsed() {
                    #[cfg(feature = "test-support")]
                    {
                        let stats = connection.stats();
                        return Err(io::Error::new(io::ErrorKind::TimedOut, ProbeFailure {
                            mesh_reply_after_first_send: path.heard_since(sent.into_std()),
                            first_send_age_us: sent.elapsed().as_micros(),
                            flush_age_us: pending.map_or(0, |(_, flushed)| flushed.elapsed().as_micros()),
                            authenticated_silence_us: freshness.observed.elapsed().as_micros(),
                            authenticated_progress_not_observed: authenticated_signature(stats.frame_rx) != freshness.frames,
                            constructed_datagrams_before: datagrams_before,
                            constructed_datagrams_after: stats.frame_tx.datagram,
                            rtt_us: stats.path.rtt.as_micros(),
                        }));
                    }
                    #[cfg(not(feature = "test-support"))]
                    return Err(io::ErrorKind::TimedOut.into());
                }
                pending = None;
            }
        }
    }
}

/// A distinct mesh tuple must answer its own session-authenticated challenge.
/// Enrolled stream progress, raw mesh UDP and old replies are all insufficient.
async fn authenticated_path_interrupted(
    connection: &quinn::Connection,
    path: &crate::remote_path_socket::PathSocket,
    interval: std::time::Duration,
    margin: std::time::Duration,
) -> io::Result<()> {
    let _epoch = path.proof_epoch(connection)?;
    // Independent sessions must not repeatedly fill one server receive queue
    // together. Spread their first probes over 15 ms and subsequent probes
    // over at most 5 ms; the authenticated response deadline is unchanged.
    // The existing public UDP port spreads scheduling only; it never authenticates a path.
    let mut phase = u64::from(quinn::AsyncUdpSocket::local_addr(path)?.port());
    let mut skew = || {
        phase ^= phase << 13;
        phase ^= phase >> 7;
        phase ^= phase << 17;
        std::time::Duration::from_micros(phase % 5001)
    };
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + skew() * 3, interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending: Option<(
        std::time::Instant,
        tokio::time::Instant,
        std::time::Duration,
    )> = None;
    let mut local_delay = std::time::Duration::ZERO;
    let mut closed = std::pin::pin!(connection.closed());
    loop {
        tokio::select! {
            _ = closed.as_mut() => return Err(io::ErrorKind::BrokenPipe.into()),
            expected = ticks.tick() => {
                // Scheduling a local task late is not evidence that the remote
                // path failed. Keep the measured delay, decaying after healthy
                // scheduling, and combine it with this tuple's authenticated RTT.
                local_delay = (local_delay * 7 / 8)
                    .max(expected.elapsed().saturating_mul(4))
                    .min(std::time::Duration::from_millis(200));
                // A slower requested cadence must leave room for a response
                // and a retry instead of silently becoming a faster poller.
                let measured = path.proof_allowance(connection.rtt(), margin)
                    .max(interval.saturating_mul(2)) + local_delay;
                // This response supplies its own authenticated RTT sample.
                // Ordinary QUIC keepalive remains owned by the connection;
                // sending a second probe here would duplicate every idle poll.
                if pending.is_some_and(|(sent, _, _)| path.mesh_authenticated_since(sent)) {
                    pending = None;
                }
                // A response already waiting on observed load keeps that
                // allowance. Decaying scheduler jitter must not move its deadline
                // earlier; only an answered challenge starts a smaller window.
                let allowance = pending.as_mut().map_or(measured, |(_, _, budget)| {
                    *budget = (*budget).max(measured);
                    *budget
                });
                if pending.is_some_and(|(_, sent, _)| sent.elapsed() >= allowance) {
                    #[cfg(feature = "test-support")]
                    eprintln!("path_proof_timeout pending_us={} allowance_us={} local_delay_us={} quic_rtt_us={}",
                        pending.map_or(0, |(_, sent, _)| sent.elapsed().as_micros()),
                        allowance.as_micros(), local_delay.as_micros(), connection.rtt().as_micros());
                    return Err(io::ErrorKind::TimedOut.into());
                }
                // After this tuple's measured RTT/variation has elapsed, spend
                // the remaining margin retrying brief receive-queue loss. Keep
                // the original sequence and first-send deadline on every retry.
                let retry = pending.is_some_and(|(_, sent, _)| sent.elapsed() >= allowance.saturating_sub(margin));
                // A repeated challenge retains its sequence and first physical
                // clock, so retransmission cannot postpone a failed path forever.
                match path.send_proof() {
                    Ok(sent) if pending.is_none() => {
                        // Physical observations use one monotonic clock across
                        // endpoint runtimes; the owned async deadline also follows
                        // virtual time in functional cancellation tests.
                        let now = tokio::time::Instant::now();
                        pending = Some((sent, now.checked_sub(sent.elapsed()).unwrap_or(now), allowance));
                    },
                    Ok(_) => {},
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                    Err(error) => return Err(error),
                }
                // Busy paths amortize probes over their measured response budget;
                // a quiet LAN keeps its original interval and byte-delivery gains.
                // Space ordinary probes by half the response allowance to reduce
                // shared receive pressure; short retries alone spend its tail.
                let cadence = if retry {
                    interval.min(std::time::Duration::from_millis(5))
                } else {
                    interval.max((allowance / 2).min(std::time::Duration::from_millis(100)))
                };
                let spread = skew();
                let mut next = cadence + if retry { spread.min(std::time::Duration::from_millis(1)) } else { spread };
                if let Some((_, sent, _)) = pending {
                    // An adaptive ordinary interval must not jump over the
                    // response margin. Wake at its start, then retry within it;
                    // neither phase spreading nor retries may skip the deadline.
                    let boundary = if retry { allowance } else { allowance.saturating_sub(margin).max(interval) };
                    next = next.min(boundary.saturating_sub(sent.elapsed()));
                }
                ticks.reset_after(next);
            }
        }
    }
}

/// Ask the server for an acknowledgement: one ack-eliciting, one-byte QUIC
/// DATAGRAM. Its ACK is authenticated traffic that keeps [`PeerFreshness`]
/// current on an otherwise idle path; the payload carries no meaning.
pub fn probe_liveness(connection: &quinn::Connection) {
    // An unsupported or full datagram queue only delays detection; QUIC's own
    // keepalive and idle timeout still bound the connection.
    let _ = connection.send_datagram(bytes::Bytes::from_static(&[0]));
}
fn authenticated_frames(connection: &quinn::Connection) -> [u64; 24] {
    authenticated_signature(connection.stats().frame_rx)
}
fn authenticated_signature(frames: quinn::FrameStats) -> [u64; 24] {
    // Quinn records these only after decryption and packet deduplication. Do
    // not substitute udp_rx: unauthenticated datagrams can change that count.
    [
        frames.acks,
        frames.ack_frequency,
        frames.crypto,
        frames.connection_close,
        frames.data_blocked,
        frames.datagram,
        u64::from(frames.handshake_done),
        frames.immediate_ack,
        frames.max_data,
        frames.max_stream_data,
        frames.max_streams_bidi,
        frames.max_streams_uni,
        frames.new_connection_id,
        frames.new_token,
        frames.path_challenge,
        frames.path_response,
        frames.ping,
        frames.reset_stream,
        frames.retire_connection_id,
        frames.stream_data_blocked,
        frames.streams_blocked_bidi,
        frames.streams_blocked_uni,
        frames.stop_sending,
        frames.stream,
    ]
}

/// Return verified leaf identity for durable server-side revocation admission.
/// # Errors
/// Refuses absent/non-certificate peer identity.
pub fn peer_fingerprint(connection: &quinn::Connection) -> io::Result<[u8; 32]> {
    let identity = connection.peer_identity().ok_or_else(denied)?;
    let chain = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| denied())?;
    Ok(openssl::sha::sha256(
        chain.first().ok_or_else(denied)?.as_ref(),
    ))
}
/// Open a terminal stream and bind its server-assigned writer before any terminal frame.
/// # Errors
/// Refuses reserved/odd ids, connection failure or a bounded binding write deadline.
pub async fn open_bound(connection: &BindingConnection, writer_id: u32) -> io::Result<BoundStream> {
    if writer_id == 0 || writer_id & 1 != 0 {
        return Err(denied());
    }
    tokio::time::timeout(BINDING_DEADLINE, async {
        let (mut send, receive) = connection.0.open_bi().await.map_err(|_| denied())?;
        // Server→host terminal input is interactive; host→server bulk is priority0.
        send.set_priority(100).map_err(|_| denied())?;
        let json = serde_json::to_vec(&serde_json::json!({"writer_id":writer_id}))
            .map_err(|_| denied())?;
        let mut bytes = Vec::new();
        infraternal_protocol::encode_frame_into(
            &infraternal_protocol::Frame::Call {
                call_id: 0,
                action_id: "transport.bind",
                input_json: &json,
            },
            &mut bytes,
        )
        .map_err(|_| denied())?;
        send.write_all(&bytes).await.map_err(|_| denied())?;
        Ok(BoundStream {
            writer_id,
            send,
            receive,
        })
    })
    .await
    .map_err(|_| denied())?
}

/// Validate the first binding frame; public for parser fuzzing, grants no host authority.
/// # Errors
/// Refuses oversized/incomplete/trailing frames, wrong action, unknown JSON fields or reserved ids.
pub fn binding_writer(bytes: &[u8]) -> io::Result<u32> {
    use infraternal_protocol::{Frame, decode_frame};
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Binding {
        writer_id: u32,
    }
    if bytes.len() > BINDING_LIMIT {
        return Err(denied());
    }
    let decoded = decode_frame(bytes).map_err(|_| denied())?;
    if decoded.wire_len != bytes.len() {
        return Err(denied());
    }
    if let Frame::Call {
        call_id: 0,
        action_id: "transport.bind",
        input_json,
    } = decoded.frame
    {
        let binding: Binding = serde_json::from_slice(input_json).map_err(|_| denied())?;
        if binding.writer_id != 0 && binding.writer_id & 1 == 0 {
            return Ok(binding.writer_id);
        }
    }
    Err(denied())
}
/// Admit one bounded first-frame binding without consuming any following frame.
/// # Errors
/// Refuses invalid framing/action/JSON/id, EOF or a binding deadline.
pub async fn accept_bound(connection: &BindingConnection) -> io::Result<BoundStream> {
    // Waiting for an unopened stream is ordinary healthy idle. Only an opened
    // stream gets a first-frame deadline; idle time is not an authority expiry.
    let (send, mut receive) = connection.0.accept_bi().await.map_err(|_| denied())?;
    send.set_priority(0).map_err(|_| denied())?;
    let writer_id = tokio::time::timeout(BINDING_DEADLINE, async {
        let mut bytes = Vec::with_capacity(BINDING_LIMIT);
        loop {
            let mut byte = [0];
            if receive.read(&mut byte).await.map_err(|_| denied())? != Some(1) {
                return Err(denied());
            }
            bytes.push(byte[0]);
            match infraternal_protocol::decode_frame(&bytes) {
                Ok(_) => return binding_writer(&bytes),
                Err(infraternal_protocol::DecodeError::Incomplete)
                    if bytes.len() < BINDING_LIMIT => {}
                Err(_) => return Err(denied()),
            }
        }
    })
    .await
    .map_err(|_| denied())??;
    Ok(BoundStream {
        writer_id,
        send,
        receive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_tls::tests::{leaf, root};
    use openssl::hash::MessageDigest;

    /// Exercise acknowledged idle traffic and a lost NAT path using the same
    /// production configuration helper at accelerated transport-only intervals.
    // Keep relay ownership and failure proof together so every socket retires at the fixture boundary.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn acknowledged_idle_survives_and_replayed_packets_cannot_mask_failure() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let ca = root();
        let server_identity = leaf(&ca, true);
        let client_identity = leaf(&ca, false);
        let config = transport_with_liveness(
            1,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_secs(5),
            false,
        );
        let mut server_config =
            server_config(&server_identity, std::slice::from_ref(&ca.certificate)).unwrap();
        server_config.transport_config(config.clone());
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_address = server.local_addr().unwrap();
        let proxy = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy_address = proxy.local_addr().unwrap();
        let forwarding = Arc::new(AtomicBool::new(true));
        let state = forwarding.clone();
        let captured = Arc::new(std::sync::Mutex::new(None));
        let last_reply = captured.clone();
        let relay_socket = proxy.clone();
        let relay = tokio::spawn(async move {
            let mut bytes = vec![0; 65536];
            let mut client = None;
            loop {
                let (count, source) = relay_socket.recv_from(&mut bytes).await.unwrap();
                let target = if source == server_address {
                    client
                } else {
                    client = Some(source);
                    Some(server_address)
                };
                if state.load(Ordering::Relaxed)
                    && let Some(target) = target
                {
                    if source == server_address {
                        *last_reply.lock().unwrap() = Some((bytes[..count].to_vec(), target));
                    }
                    relay_socket.send_to(&bytes[..count], target).await.unwrap();
                }
            }
        });
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client_config = client_config(&client_identity, &[ca.certificate]).unwrap();
        client_config.transport_config(config);
        client.set_default_client_config(client_config);
        let (dial, accept) =
            tokio::join!(client.connect(proxy_address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            });
        let dial = dial.unwrap();
        let accept = accept.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        assert!(dial.close_reason().is_none());
        assert!(accept.close_reason().is_none());
        let mut freshness = PeerFreshness::new(&dial);
        forwarding.store(false, Ordering::Relaxed);
        let (packet, target) = captured.lock().unwrap().clone().unwrap();
        // Replay only an already delivered encrypted datagram. Neither valid
        // duplicates nor arbitrary UDP arrivals prove fresh peer reachability.
        let duplicate_packets = tokio::spawn(async move {
            loop {
                proxy.send_to(&packet, target).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        });
        let failure = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            freshness.interrupted(&dial, std::time::Duration::from_millis(250)),
        )
        .await;
        duplicate_packets.abort();
        assert!(
            matches!(failure, Ok(Err(error)) if error.kind() == io::ErrorKind::TimedOut),
            "replayed packets must not keep the route alive"
        );
        assert!(
            dial.close_reason().is_none(),
            "freshness expiry precedes the handshake-safe transport deadline"
        );
        relay.abort();
        client.close(0u32.into(), b"");
        server.close(0u32.into(), b"");
    }

    #[tokio::test]
    async fn one_way_authenticated_output_keeps_the_path_fresh() {
        let ca = root();
        let server_identity = leaf(&ca, true);
        let client_identity = leaf(&ca, false);
        let server = quinn::Endpoint::server(
            server_config(&server_identity, std::slice::from_ref(&ca.certificate)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        // Disable path-MTU probes in this fixture so unrelated ACKs cannot
        // mask the one-way stream. Production retains its selected defaults.
        let mut traffic = transport(1);
        std::sync::Arc::get_mut(&mut traffic)
            .unwrap()
            .mtu_discovery_config(None);
        let mut config = client_config(&client_identity, &[ca.certificate]).unwrap();
        config.transport_config(traffic);
        client.set_default_client_config(config);
        let (dial, accept) = tokio::join!(
            client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let dial = dial.unwrap();
        let accept = accept.unwrap();
        let writer = tokio::spawn(async move {
            let (mut send, _) = accept.open_bi().await.unwrap();
            for _ in 0..20 {
                send.write_all(b"x").await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            send.finish().unwrap();
            // Retain the transport until its receiver drains the stream.
            let _ = send.stopped().await;
        });
        let (_, mut receive) = dial.accept_bi().await.unwrap();
        let mut guard = PeerFreshness::new(&dial);
        let watched = tokio::time::timeout(
            std::time::Duration::from_millis(750),
            guard.interrupted(&dial, std::time::Duration::from_millis(250)),
        );
        let (received, watched) = tokio::join!(receive.read_to_end(64), watched);
        assert_eq!(received.unwrap(), vec![b'x'; 20]);
        assert!(watched.is_err(), "one-way output must not trigger fallback");
        writer.await.unwrap();
        client.close(0_u32.into(), b"");
        server.close(0_u32.into(), b"");
    }

    #[tokio::test]
    async fn repeated_native_id_has_distinct_server_writer_authority_and_preserves_suffix() {
        let ca = root();
        let server = leaf(&ca, true);
        let client = leaf(&ca, false);
        let expected: [u8; 32] = client
            .certificate
            .digest(MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let server = quinn::Endpoint::server(
            server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint
            .set_default_client_config(client_config(&client, &[ca.certificate]).unwrap());
        let mut native_ids = Vec::new();
        for writer_id in [42, 44] {
            let dial = client_endpoint
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap();
            let (remote, local) =
                tokio::join!(dial, async { server.accept().await.unwrap().await });
            let remote = remote.unwrap();
            let local = local.unwrap();
            assert_eq!(peer_fingerprint(&local).unwrap(), expected);
            let mut hello = infraternal_protocol::Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "test peer",
            };
            assert!(negotiate_binding(&local, &hello).is_err());
            if let infraternal_protocol::Frame::Hello { caps, .. } = &mut hello {
                *caps = REMOTE_WRITER_BINDING;
            }
            let local_binding = negotiate_binding(&local, &hello).unwrap();
            let remote_binding = negotiate_binding(&remote, &hello).unwrap();
            let mut outgoing = open_bound(&local_binding, writer_id).await.unwrap();
            outgoing
                .send
                .write_all(b"following raw frames")
                .await
                .unwrap();
            outgoing.send.finish().unwrap();
            let mut bound = accept_bound(&remote_binding).await.unwrap();
            assert_eq!(bound.writer_id, writer_id);
            native_ids.push(bound.receive.id());
            assert_eq!(
                bound.receive.read_to_end(128).await.unwrap(),
                b"following raw frames"
            );
            assert!(open_bound(&local_binding, 0).await.is_err());
            assert!(open_bound(&local_binding, 3).await.is_err());
            local.close(0u32.into(), b"");
            remote.close(0u32.into(), b"");
        }
        assert_eq!(native_ids[0], native_ids[1]);
        server.close(0u32.into(), b"");
        client_endpoint.close(0u32.into(), b"");
    }
    #[tokio::test]
    async fn wrong_server_name_never_yields_authenticated_connection() {
        let ca = root();
        let server = leaf(&ca, true);
        let client = leaf(&ca, false);
        let server = quinn::Endpoint::server(
            server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint
            .set_default_client_config(client_config(&client, &[ca.certificate]).unwrap());
        let connect = client_endpoint
            .connect(server.local_addr().unwrap(), "wrong.example")
            .unwrap();
        let (dial, accepted) =
            tokio::join!(connect, async { server.accept().await.unwrap().await });
        assert!(dial.is_err());
        assert!(accepted.is_err());
        server.close(0u32.into(), b"");
        client_endpoint.close(0u32.into(), b"");
    }
    #[tokio::test]
    async fn host_cannot_open_a_second_server_control_stream() {
        let ca = root();
        let server_identity = leaf(&ca, true);
        let client_identity = leaf(&ca, false);
        let server = quinn::Endpoint::server(
            server_config(&server_identity, std::slice::from_ref(&ca.certificate)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client
            .set_default_client_config(client_config(&client_identity, &[ca.certificate]).unwrap());
        let (dial, accepted) = tokio::join!(
            client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let dial = dial.unwrap();
        let accepted = accepted.unwrap();
        let _control = dial.open_bi().await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), dial.open_bi())
                .await
                .is_err()
        );
        dial.close(0u32.into(), b"");
        accepted.close(0u32.into(), b"");
        server.close(0u32.into(), b"");
        client.close(0u32.into(), b"");
    }
    #[test]
    fn mesh_liveness_keeps_authentication_and_refuses_invalid_intervals() {
        use std::time::Duration;
        let ca = root();
        let identity = leaf(&ca, false);
        let roots = std::slice::from_ref(&ca.certificate);
        for (keepalive, idle) in [
            (Duration::ZERO, Duration::from_millis(200)),
            (Duration::from_nanos(1), Duration::from_nanos(2)),
            (Duration::from_millis(200), Duration::from_millis(200)),
            (Duration::from_millis(300), Duration::from_millis(200)),
            (Duration::from_millis(50), Duration::from_secs(61)),
        ] {
            assert!(
                matches!(client_config_with_liveness(&identity, roots, keepalive, idle), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
            );
        }
        assert!(
            client_config_with_liveness(
                &identity,
                &[],
                Duration::from_millis(50),
                Duration::from_millis(200)
            )
            .is_err()
        );
        assert!(
            client_config_with_liveness(
                &identity,
                roots,
                Duration::from_millis(50),
                Duration::from_millis(200)
            )
            .is_ok()
        );
        assert!(client_config(&identity, roots).is_ok());
    }
}

#[cfg(test)]
#[path = "remote_probe_tests.rs"]
mod probe_tests;

#[cfg(test)]
#[path = "remote_mtu_tests.rs"]
mod mtu_tests;

#[cfg(test)]
#[path = "remote_design_scale_review.rs"]
mod design_scale_review;
