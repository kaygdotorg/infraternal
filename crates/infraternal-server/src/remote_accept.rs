//! Separates bounded first-byte probes from TLS work and reserves handshake capacity for previously authenticated sources [40][168], #78.
#[cfg(all(test, feature = "mesh-transport-proof"))]
use crate::remote_autoswitch_probe as probe;
use crate::{
    enrollment::EnrollmentStore, remote_admission::SourceSlots, remote_guard::AuthorityGuard,
    remote_link::RemoteLink, remote_runtime::RemoteHosts,
};
use infraternal_agent::{remote_quic, remote_tls};
use std::{
    collections::HashSet,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
/// Concurrent handshakes from sources not yet known to be hosts.
const ANONYMOUS_LANES: usize = 48;
/// Concurrent handshakes reserved for sources that admitted a host before.
const KNOWN_LANES: usize = 16;
/// Concurrent handshakes one source network may hold in either lane.
const SOURCE_LANES: usize = 4;

/// Handshake capacity for the host-link listeners, shared by QUIC and TCP/TLS.
pub(crate) struct Limits {
    admission: Arc<Semaphore>,
    reserved: Arc<Semaphore>,
    sources: Arc<SourceSlots>,
    reserved_sources: Arc<SourceSlots>,
    known: Arc<Mutex<HashSet<IpAddr>>>,
    standby: Arc<crate::remote_standby::Slots>,
    /// The device links held through these listeners (#580), one per device.
    pub(crate) devices: Arc<crate::remote_device_link::DeviceLinks>,
}
impl Limits {
    /// Fresh limits for one listener set: empty lanes and no known sources.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            admission: Arc::new(Semaphore::new(ANONYMOUS_LANES)),
            reserved: Arc::new(Semaphore::new(KNOWN_LANES)),
            sources: Arc::new(SourceSlots::new(SOURCE_LANES)),
            reserved_sources: Arc::new(SourceSlots::new(SOURCE_LANES)),
            known: Arc::default(),
            standby: Arc::default(),
            devices: Arc::default(),
        })
    }
    /// The lane `address` draws from: its slots, their total, and its per-source slots.
    fn lane(&self, address: IpAddr) -> (&Arc<Semaphore>, usize, &Arc<SourceSlots>) {
        if self
            .known
            .lock()
            .is_ok_and(|known| known.contains(&address))
        {
            (&self.reserved, KNOWN_LANES, &self.reserved_sources)
        } else {
            (&self.admission, ANONYMOUS_LANES, &self.sources)
        }
    }
    /// Take a handshake slot from `address`'s lane and source, or `None` when either is full.
    fn handshake(&self, address: IpAddr) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let (slots, _, sources) = self.lane(address);
        reserve(slots, sources, address)
    }
    /// True when a QUIC Initial from an address that has not proved it receives
    /// packets there should get a Retry instead of a handshake slot (#572
    /// finding 2): its lane, or its source's slots, are more than half held.
    ///
    /// Source addresses of UDP Initials can be forged, and every Initial holds
    /// its slots for the 5 s handshake deadline. Without this, about 10 forged
    /// packets a second kept all 48 anonymous lanes full. A Retry costs the
    /// server no state, and only a peer that receives it can come back with a
    /// validated address. Below half, nothing changes: a reconnecting host keeps
    /// its round-trip count, and pays one extra round trip only under pressure.
    pub(crate) fn wants_retry(&self, address: IpAddr) -> bool {
        let (slots, total, sources) = self.lane(address);
        slots.available_permits() * 2 < total || sources.more_than_half_held(address)
    }
    /// Handshake slots currently held in the anonymous lane, for tests.
    #[cfg(test)]
    pub(crate) fn anonymous_in_use(&self) -> usize {
        ANONYMOUS_LANES - self.admission.available_permits()
    }
}
fn reserve(
    slots: &Arc<Semaphore>,
    sources: &SourceSlots,
    address: IpAddr,
) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
    let source = sources.reserve(address)?;
    Some((source, slots.clone().try_acquire_owned().ok()?))
}
fn remember(known: &Mutex<HashSet<IpAddr>>, address: IpAddr) {
    // This is an admission hint, never host authority. Bound stale hints without
    // timers; every admitted peer still proves its certificate against the ledger.
    if let Ok(mut known) = known.lock()
        && known.len() < 10000
    {
        known.insert(address);
    }
}
/// Accept bounded authenticated QUIC links, including pending-cleanup reconnects.
pub(crate) async fn quic(
    quic: quinn::Endpoint,
    hosts: RemoteHosts,
    store: EnrollmentStore,
    limits: Arc<Limits>,
) {
    let mut handshakes = JoinSet::new();
    while let Some(incoming) = quic.accept().await {
        while handshakes.try_join_next().is_some() {}
        let address = incoming.remote_address().ip().to_canonical();
        if !incoming.remote_address_validated()
            && incoming.may_retry()
            && limits.wants_retry(address)
        {
            // Stateless: the peer's next Initial carries the token and a validated address.
            if let Err(unsent) = incoming.retry() {
                unsent.into_incoming().refuse();
            }
            continue;
        }
        let Some((source_permit, permit)) = limits.handshake(address) else {
            incoming.refuse();
            continue;
        };
        let hosts = hosts.for_local(incoming.local_ip());
        let store = store.clone();
        let known = limits.known.clone();
        let standby = limits.standby.clone();
        let devices = limits.devices.clone();
        handshakes.spawn(async move {
            let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(5), incoming).await
            else {
                return;
            };
            let Ok(fingerprint) = remote_quic::peer_fingerprint(&connection) else {
                return;
            };
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            crate::remote_autoswitch_probe::record(
                crate::remote_autoswitch_probe::Kind::TlsHandshake,
                connection.remote_address(),
                0,
            );
            let authority = match tokio::time::timeout(
                Duration::from_secs(5),
                AuthorityGuard::admit_transport(store.clone(), fingerprint),
            )
            .await
            {
                Ok(Ok(authority)) => authority,
                Ok(Err(_)) => {
                    if retired(&store, &fingerprint).await {
                        crate::remote_link::send_quic_retirement(connection).await;
                        return;
                    }
                    // Not a host. A device (#580) is admitted only by its own
                    // guard and gets a link that serves nothing; the host
                    // path below never sees it. The handshake lane stays
                    // held until its Hellos are done.
                    if let Ok(Ok(device)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        crate::remote_device_link::admit(&store, &fingerprint),
                    )
                    .await
                    {
                        let _ = crate::remote_device_link::serve(
                            connection,
                            device,
                            fingerprint,
                            store,
                            devices,
                            (source_permit, permit),
                        )
                        .await;
                    }
                    return;
                }
                Err(_) => return,
            };
            let mut admission =
                crate::remote_standby::Admission::new(authority, (source_permit, permit), standby);
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            crate::remote_autoswitch_probe::record(
                crate::remote_autoswitch_probe::Kind::LedgerAdmission,
                connection.remote_address(),
                0,
            );
            let admitted = async {
                let link =
                    RemoteLink::quic_admitted(connection.clone(), Some(&mut admission)).await?;
                // Cleanup has its own bounded lane; release ordinary handshake capacity.
                admission.release_cleanup_handshake();
                #[cfg(all(test, feature = "mesh-transport-proof"))]
                crate::remote_autoswitch_probe::record(
                    crate::remote_autoswitch_probe::Kind::ControlReady,
                    connection.remote_address(),
                    0,
                );
                #[cfg(all(test, feature = "mesh-transport-proof"))]
                if std::env::var_os("ACCEPTANCE_STANDING_STAGES").is_some() {
                    crate::remote_autoswitch_probe::record(
                        crate::remote_autoswitch_probe::Kind::QuicControlReady,
                        connection.remote_address(),
                        0,
                    );
                }
                hosts
                    .admit_observed(admission.authority, link, Some(address))
                    .await?;
                remember(&known, address);
                Ok::<(), io::Error>(())
            }
            .await;
            if admitted.is_err() {
                connection.close(0u32.into(), b"");
            }
        });
    }
}
/// What every accepted TCP connection needs: TLS, the host registry, the store, limits and, when enabled, recovery.
#[derive(Clone)]
struct TcpContext {
    tls: Arc<crate::remote_runtime::ServerTls>,
    hosts: RemoteHosts,
    store: EnrollmentStore,
    limits: Arc<Limits>,
    recovery: Option<Arc<crate::remote_recovery::Service>>,
}

/// One connection's admission: its source, whether that source is known, its first-byte permits and its deadline.
struct TcpAdmission {
    address: IpAddr,
    known_source: bool,
    first_byte: (OwnedSemaphorePermit, OwnedSemaphorePermit),
    deadline: Duration,
    #[cfg(all(test, feature = "mesh-transport-proof"))]
    diagnostic_peer: std::net::SocketAddr,
}

/// Accept host TCP connections: TLS, then mTLS admission or, when enabled, certificate recovery.
pub(crate) async fn tcp(
    tcp: TcpListener,
    tls: Arc<crate::remote_runtime::ServerTls>,
    hosts: RemoteHosts,
    store: EnrollmentStore,
    limits: Arc<Limits>,
    recovery: Option<Arc<crate::remote_recovery::Service>>,
) {
    let context = TcpContext {
        tls,
        hosts,
        store,
        limits,
        recovery,
    };
    let idle = Arc::new(Semaphore::new(48));
    let idle_sources = Arc::new(SourceSlots::new(4));
    let probes = Arc::new(Semaphore::new(16));
    let probe_sources = Arc::new(SourceSlots::new(1));

    let mut handshakes = JoinSet::new();
    while let Ok((socket, address)) = tcp.accept().await {
        while handshakes.try_join_next().is_some() {}
        #[cfg(all(test, feature = "mesh-transport-proof"))]
        let diagnostic_peer = address;
        let address = address.ip().to_canonical();
        let known_source = context
            .limits
            .known
            .lock()
            .is_ok_and(|known| known.contains(&address));
        let regular_sources = if known_source {
            &context.limits.reserved_sources
        } else {
            &idle_sources
        };
        let regular_slots = if known_source {
            &context.limits.reserved
        } else {
            &idle
        };
        let regular = reserve(regular_slots, regular_sources, address);
        if known_source && regular.is_none() {
            continue;
        }
        let (first_byte, deadline) = if let Some(permits) = regular {
            (permits, Duration::from_secs(2))
        } else {
            let Some(source) = probe_sources.reserve(address) else {
                continue;
            };
            let Ok(permit) = probes.clone().try_acquire_owned() else {
                continue;
            };
            // A short separate probe lane admits a ClientHello even when
            // that same NAT address already has idle anonymous sockets.
            ((source, permit), Duration::from_millis(100))
        };
        handshakes.spawn(handle_tcp_connection(
            socket,
            context.clone(),
            TcpAdmission {
                address,
                known_source,
                first_byte,
                deadline,
                #[cfg(all(test, feature = "mesh-transport-proof"))]
                diagnostic_peer,
            },
        ));
    }
}

/// Accept one TCP connection: run TLS, and send the recovery ALPN to the recovery service, everything else to mTLS
/// admission. Recovery never reaches host admission.
async fn handle_tcp_connection(
    socket: tokio::net::TcpStream,
    context: TcpContext,
    pending: TcpAdmission,
) {
    let address = pending.address;
    let local_ip = socket.local_addr().ok().map(|address| address.ip());
    #[cfg(all(test, feature = "mesh-transport-proof"))]
    let diagnostic_peer = pending.diagnostic_peer;

    let mut byte = [0];
    if !matches!(
        tokio::time::timeout(pending.deadline, socket.peek(&mut byte)).await,
        Ok(Ok(1))
    ) {
        return;
    }
    // Known sources reserve their complete path before peeking, so idle
    // anonymous probes cannot consume the reserved TLS capacity.
    let permits = if pending.known_source {
        Some(pending.first_byte)
    } else {
        drop(pending.first_byte);
        context.limits.handshake(address)
    };
    let Some(permits) = permits else {
        return;
    };
    // The acceptor current now: a rotated leaf applies from the next handshake (#559).
    let tls = context.tls.current();
    let connection = if let Some(service) = context.recovery.as_ref() {
        match remote_tls::accept_recovery_aware(socket, &tls).await {
            Ok(remote_tls::AcceptedConnection::Host(connection)) => connection,
            Ok(remote_tls::AcceptedConnection::Recovery(connection)) => {
                service.serve(connection.channel, address).await;
                return;
            }
            Err(_) => return,
        }
    } else {
        let Ok(connection) = remote_tls::accept(socket, &tls).await else {
            return;
        };
        connection
    };
    #[cfg(all(test, feature = "mesh-transport-proof"))]
    probe::record(probe::Kind::TlsHandshake, diagnostic_peer, 0);
    let authority = match tokio::time::timeout(
        Duration::from_secs(5),
        AuthorityGuard::admit_transport(context.store.clone(), connection.peer_fingerprint),
    )
    .await
    {
        Ok(Ok(authority)) => authority,
        Ok(Err(_)) => {
            if retired(&context.store, &connection.peer_fingerprint).await {
                let _ = crate::remote_link::send_retirement(&connection.channel).await;
            }
            return;
        }
        Err(_) => return,
    };
    let mut admission =
        crate::remote_standby::Admission::new(authority, permits, context.limits.standby.clone());
    #[cfg(all(test, feature = "mesh-transport-proof"))]
    probe::record(probe::Kind::LedgerAdmission, diagnostic_peer, 0);
    let Ok(link) = RemoteLink::tcp_admitted(connection.channel, Some(&mut admission)).await else {
        return;
    };
    // Cleanup has its own bounded lane; release ordinary handshake capacity.
    admission.release_cleanup_handshake();
    #[cfg(all(test, feature = "mesh-transport-proof"))]
    let link = {
        probe::record(probe::Kind::ControlReady, diagnostic_peer, 0);
        if std::env::var_os("ACCEPTANCE_STANDING_STAGES").is_some() {
            probe::record(probe::Kind::TcpControlReady, diagnostic_peer, 0);
        }
        link.with_diagnostic_peer(diagnostic_peer)
    };
    let hosts = context.hosts.for_local(local_ip);
    if hosts
        .admit_observed(admission.authority, link, Some(address))
        .await
        .is_ok()
    {
        remember(&context.limits.known, address);
    }
}

/// Bound the fallback ledger lookup. Any failure keeps the original retryable refusal.
pub(crate) async fn retired(store: &EnrollmentStore, fingerprint: &[u8; 32]) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            store.installation_retired(fingerprint)
        )
        .await,
        Ok(Ok(true))
    )
}

/// Lane separation and the Retry pressure rule.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn anonymous_capacity_and_single_source_cannot_consume_known_reserve() {
        let limits = Limits::new();
        let mut held = Vec::new();
        for address in 1..=12u32 {
            for _ in 0..4 {
                held.push(limits.handshake(IpAddr::V4(address.into())).unwrap());
            }
        }
        assert!(limits.handshake(IpAddr::V4(13u32.into())).is_none());
        let known = IpAddr::V4(100u32.into());
        remember(&limits.known, known);
        let reserved: Vec<_> = (0..4).map(|_| limits.handshake(known).unwrap()).collect();
        assert!(limits.handshake(known).is_none());
        assert_eq!(limits.reserved.available_permits(), 12);
        drop(reserved);
        assert_eq!(limits.reserved.available_permits(), 16);
        drop(held);
        assert!(limits.handshake(IpAddr::V4(13u32.into())).is_some());
    }

    /// #572 finding 2: Retry starts only once a lane or one source's slots are
    /// more than half held, so an idle server keeps the plain handshake.
    #[test]
    fn retry_only_when_a_lane_or_source_is_more_than_half_held() {
        let limits = Limits::new();
        let host = IpAddr::V4(200u32.into());
        assert!(!limits.wants_retry(host));
        let mut held = Vec::new();
        for address in 1..=12u32 {
            for _ in 0..2 {
                held.push(limits.handshake(IpAddr::V4(address.into())).unwrap());
            }
        }
        assert_eq!(limits.anonymous_in_use(), 24);
        assert!(!limits.wants_retry(host), "exactly half is not pressure");
        held.push(limits.handshake(IpAddr::V4(13u32.into())).unwrap());
        assert!(limits.wants_retry(host));
        drop(held);
        let one = IpAddr::V4(1u32.into());
        let source: Vec<_> = (0..3).map(|_| limits.handshake(one).unwrap()).collect();
        assert!(limits.wants_retry(one), "a source more than half held");
        assert!(!limits.wants_retry(host));
        drop(source);
    }
}
