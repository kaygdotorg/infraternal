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
pub(crate) struct Limits {
    admission: Arc<Semaphore>,
    reserved: Arc<Semaphore>,
    sources: Arc<SourceSlots>,
    reserved_sources: Arc<SourceSlots>,
    known: Arc<Mutex<HashSet<IpAddr>>>,
    standby: Arc<crate::remote_standby::Slots>,
}
impl Limits {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            admission: Arc::new(Semaphore::new(48)),
            reserved: Arc::new(Semaphore::new(16)),
            sources: Arc::new(SourceSlots::new(4)),
            reserved_sources: Arc::new(SourceSlots::new(4)),
            known: Arc::default(),
            standby: Arc::default(),
        })
    }
    fn handshake(&self, address: IpAddr) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        if self
            .known
            .lock()
            .is_ok_and(|known| known.contains(&address))
        {
            reserve(&self.reserved, &self.reserved_sources, address)
        } else {
            reserve(&self.admission, &self.sources, address)
        }
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
/// Accept bounded authenticated QUIC links, including refusal-only reconnects
/// whose server-owned cleanup obligation is still unconfirmed.
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
        let Some((source_permit, permit)) = limits.handshake(address) else {
            incoming.refuse();
            continue;
        };
        let hosts = hosts.for_local(incoming.local_ip());
        let store = store.clone();
        let known = limits.known.clone();
        let standby = limits.standby.clone();
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
            let Ok(Ok(authority)) = tokio::time::timeout(
                Duration::from_secs(5),
                AuthorityGuard::admit_transport(store, fingerprint),
            )
            .await
            else {
                return;
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
                // The validated cleanup link now uses its own bounded host lane,
                // so queued delivery must not retain normal reconnect capacity.
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
/// Accept bounded TLS links with normal authority or cleanup-only admission;
/// retired hosts never regain ordinary host routing through this listener.
pub(crate) async fn tcp(
    tcp: TcpListener,
    tls: Arc<openssl::ssl::SslAcceptor>,
    hosts: RemoteHosts,
    store: EnrollmentStore,
    limits: Arc<Limits>,
) {
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
        let known_source = limits
            .known
            .lock()
            .is_ok_and(|known| known.contains(&address));
        let regular_sources = if known_source {
            &limits.reserved_sources
        } else {
            &idle_sources
        };
        let regular_slots = if known_source {
            &limits.reserved
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
        let limits = limits.clone();
        let hosts = hosts.for_local(socket.local_addr().ok().map(|address| address.ip()));
        let store = store.clone();
        let tls = tls.clone();
        handshakes.spawn(async move {
            let mut byte = [0];
            if !matches!(
                tokio::time::timeout(deadline, socket.peek(&mut byte)).await,
                Ok(Ok(1))
            ) {
                return;
            }
            // Known sources reserve their complete path before peeking, so idle
            // anonymous probes cannot consume the reserved TLS capacity.
            let permits = if known_source {
                Some(first_byte)
            } else {
                drop(first_byte);
                limits.handshake(address)
            };
            let Some(permits) = permits else {
                return;
            };
            let Ok(connection) = remote_tls::accept(socket, &tls).await else {
                return;
            };
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            probe::record(probe::Kind::TlsHandshake, diagnostic_peer, 0);
            let Ok(Ok(authority)) = tokio::time::timeout(
                Duration::from_secs(5),
                AuthorityGuard::admit_transport(store, connection.peer_fingerprint),
            )
            .await
            else {
                return;
            };
            let mut admission =
                crate::remote_standby::Admission::new(authority, permits, limits.standby.clone());
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            probe::record(probe::Kind::LedgerAdmission, diagnostic_peer, 0);
            let Ok(link) = RemoteLink::tcp_admitted(connection.channel, Some(&mut admission)).await
            else {
                return;
            };
            // Cleanup's bounded identity lane replaces handshake ownership.
            admission.release_cleanup_handshake();
            #[cfg(all(test, feature = "mesh-transport-proof"))]
            let link = {
                probe::record(probe::Kind::ControlReady, diagnostic_peer, 0);
                if std::env::var_os("ACCEPTANCE_STANDING_STAGES").is_some() {
                    probe::record(probe::Kind::TcpControlReady, diagnostic_peer, 0);
                }
                link.with_diagnostic_peer(diagnostic_peer)
            };
            if hosts
                .admit_observed(admission.authority, link, Some(address))
                .await
                .is_ok()
            {
                remember(&limits.known, address);
            }
        });
    }
}

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
}
