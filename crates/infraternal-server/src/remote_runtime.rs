//! Admits dial-out hosts against the durable certificate ledger and supplies their transport to the existing terminal actor [9][64], #78.

use crate::{
    embedded::EmbeddedAgent, enrollment::EnrollmentStore, remote_guard::AuthorityGuard,
    remote_link::RemoteLink,
};
use infraternal_agent::{
    remote_quic,
    remote_tls::{self, Identity},
};
use openssl::x509::X509;
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
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
    authority: AuthorityGuard,
    actor: EmbeddedAgent,
    accepts: mpsc::Sender<RemoteLink>,
    generation: Uuid,
    retirement: Retirement,
}

/// The registry owns its one event/deadline waiter. Superseding or dropping a
/// host aborts that waiter; neither it nor its weak map reference keeps a host
/// alive after the runtime is dropped.
struct Retirement(tokio::task::JoinHandle<()>);
impl Drop for Retirement {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl RemoteHosts {
    pub(crate) async fn actor(&self, id: Uuid) -> Option<EmbeddedAgent> {
        self.0
            .lock()
            .await
            .get(&id)
            .filter(|host| host.authority.permits())
            .map(|host| host.actor.clone())
    }
    async fn admit(&self, authority: AuthorityGuard, link: RemoteLink) -> io::Result<()> {
        if !authority.permits() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let id = authority.identity.host;
        let uid = authority.identity.execution_uid;
        let mut hosts = self.0.lock().await;
        if !hosts.contains_key(&id) && hosts.len() >= 10_000 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let generation = Uuid::new_v4();
        if let Some(host) = hosts.get_mut(&id) {
            if host.uid != uid {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            host.accepts
                .try_send(link.authorize(authority.clone()))
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            // Publish only after queue admission. A rejected replacement must
            // not alter a valid actor or cancel its existing retirement waiter.
            host.generation = generation;
            host.retirement = self.retirement(id, generation, authority.clone());
            host.authority = authority;
        } else {
            let (actor, accepts) = EmbeddedAgent::remote(uid);
            accepts
                .try_send(link.authorize(authority.clone()))
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            let retirement = self.retirement(id, generation, authority.clone());
            hosts.insert(
                id,
                Host {
                    uid,
                    authority,
                    actor,
                    accepts,
                    generation,
                    retirement,
                },
            );
        }
        Ok(())
    }

    fn retirement(&self, id: Uuid, generation: Uuid, authority: AuthorityGuard) -> Retirement {
        let registry = Arc::downgrade(&self.0);
        Retirement(tokio::spawn(async move {
            // Healthy idle has only its certificate expiry deadline, never a
            // heartbeat. Ordinary socket loss keeps the actor for offset resume.
            authority.cancelled().await;
            let Some(registry) = registry.upgrade() else {
                return;
            };
            let mut hosts = registry.lock().await;
            if hosts
                .get(&id)
                .is_some_and(|host| host.generation == generation && !host.authority.permits())
            {
                // Dropping accepts ends the actor and its retained browser
                // routes. No shim or host-local identity/state is removed here.
                hosts.remove(&id);
            }
        }))
    }
}

#[cfg(test)]
fn now() -> io::Result<i64> {
    use std::time::{SystemTime, UNIX_EPOCH};
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
    #[cfg(test)]
    pub(crate) diagnostic_hosts: RemoteHosts,
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
        #[cfg(test)]
        let diagnostic_hosts = hosts.clone();
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
                        let authority = AuthorityGuard::admit(store, fingerprint).await?;
                        let link = RemoteLink::quic(connection.clone()).await?;
                        hosts.admit(authority, link).await
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
                    let Ok(Ok(authority)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        AuthorityGuard::admit(store, connection.peer_fingerprint),
                    )
                    .await
                    else {
                        return;
                    };
                    let Ok(link) = RemoteLink::tcp(connection.channel).await else {
                        return;
                    };
                    let _ = hosts.admit(authority, link).await;
                });
            }
        });
        Ok(Self {
            tasks,
            endpoint,
            #[cfg(test)]
            diagnostic_hosts,
        })
    }
}

#[cfg(test)]
#[path = "remote_runtime_tests.rs"]
pub(crate) mod tests;
