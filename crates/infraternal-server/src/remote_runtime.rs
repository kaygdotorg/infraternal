//! Admits dial-out hosts against the durable certificate ledger and supplies their transport to the existing terminal actor [9][64], #78.

use crate::{embedded::EmbeddedAgent, enrollment::EnrollmentStore, remote_link::RemoteLink};
use infraternal_agent::{
    remote_quic,
    remote_tls::{self, Identity},
};
use openssl::x509::X509;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore, mpsc},
    task::JoinSet,
};
use uuid::Uuid;

/// Trusted server transport identity and public issuers, supplied independently of the CA lock.
pub struct RemoteService {
    /// Enrollment signer source and transport coordinates.
    pub enrollment: crate::remote_http::EnrollmentService,
    /// Server-only TLS key and certificate.
    pub identity: Identity,
    /// Public issuer overlap for mutual TLS.
    pub roots: Vec<X509>,
}

/// One durable host actor survives transport replacement; every new peer is readmitted.
#[derive(Clone, Default)]
pub(crate) struct RemoteHosts(Arc<Mutex<HashMap<Uuid, Host>>>);
struct Host {
    uid: u32,
    actor: EmbeddedAgent,
    accepts: mpsc::Sender<RemoteLink>,
}
impl RemoteHosts {
    pub(crate) async fn actor(&self, id: Uuid) -> Option<EmbeddedAgent> {
        self.0.lock().await.get(&id).map(|host| host.actor.clone())
    }
    async fn admit(&self, id: Uuid, uid: u32, link: RemoteLink) -> io::Result<()> {
        let mut hosts = self.0.lock().await;
        if !hosts.contains_key(&id) && hosts.len() >= 10_000 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let host = hosts.entry(id).or_insert_with(|| {
            let (actor, accepts) = EmbeddedAgent::remote(uid);
            Host {
                uid,
                actor,
                accepts,
            }
        });
        if host.uid != uid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        host.accepts
            .try_send(link)
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))
    }
}

fn now() -> io::Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    i64::try_from(seconds).map_err(io::Error::other)
}

/// Bound both UDP and TCP to the server's chosen dial-out port. Drop aborts listener tasks.
pub(crate) struct RemoteListeners {
    tasks: JoinSet<()>,
    endpoint: quinn::Endpoint,
}
impl Drop for RemoteListeners {
    fn drop(&mut self) {
        self.tasks.abort_all();
        self.endpoint.close(0u32.into(), b"");
    }
}
impl RemoteListeners {
    #[cfg(test)]
    pub(crate) fn refuse_quic(&self) {
        self.endpoint.close(0u32.into(), b"");
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub(crate) async fn start(
        address: SocketAddr,
        identity: &Identity,
        roots: &[X509],
        store: EnrollmentStore,
        hosts: RemoteHosts,
    ) -> io::Result<Self> {
        let endpoint =
            quinn::Endpoint::server(remote_quic::server_config(identity, roots)?, address)?;
        let tcp = TcpListener::bind(endpoint.local_addr()?).await?;
        let tls = Arc::new(remote_tls::server_config(identity, roots)?);
        let admission = Arc::new(Semaphore::new(64));
        let mut tasks = JoinSet::new();
        let quic = endpoint.clone();
        let quic_hosts = hosts.clone();
        let quic_store = store.clone();
        let quic_admission = admission.clone();
        tasks.spawn(async move {
            let mut handshakes = JoinSet::new();
            while let Some(incoming) = quic.accept().await {
                while handshakes.try_join_next().is_some() {}
                let Ok(permit) = quic_admission.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let hosts = quic_hosts.clone();
                let store = quic_store.clone();
                handshakes.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(connection)) =
                        tokio::time::timeout(Duration::from_secs(5), incoming).await
                    else {
                        return;
                    };
                    let admitted = tokio::time::timeout(Duration::from_secs(5), async {
                        let fingerprint = remote_quic::peer_fingerprint(&connection)?;
                        let authority = store
                            .admit(&fingerprint, now()?)
                            .await
                            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
                        let link = RemoteLink::quic(connection.clone()).await?;
                        hosts
                            .admit(authority.host, authority.execution_uid, link)
                            .await
                    })
                    .await;
                    if !matches!(admitted, Ok(Ok(()))) {
                        connection.close(0u32.into(), b"");
                    }
                });
            }
        });
        tasks.spawn(async move {
            let mut handshakes = JoinSet::new();
            while let Ok((socket, _)) = tcp.accept().await {
                while handshakes.try_join_next().is_some() {}
                let Ok(permit) = admission.clone().try_acquire_owned() else {
                    continue;
                };
                let hosts = hosts.clone();
                let store = store.clone();
                let tls = tls.clone();
                handshakes.spawn(async move {
                    let _permit = permit;
                    let Ok(connection) = remote_tls::accept(socket, &tls).await else {
                        return;
                    };
                    let Ok(instant) = now() else {
                        return;
                    };
                    let Ok(Ok(authority)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        store.admit(&connection.peer_fingerprint, instant),
                    )
                    .await
                    else {
                        return;
                    };
                    let Ok(link) = RemoteLink::tcp(connection.channel).await else {
                        return;
                    };
                    let _ = hosts
                        .admit(authority.host, authority.execution_uid, link)
                        .await;
                });
            }
        });
        Ok(Self { tasks, endpoint })
    }
}

#[cfg(test)]
#[path = "remote_runtime_tests.rs"]
pub(crate) mod tests;
