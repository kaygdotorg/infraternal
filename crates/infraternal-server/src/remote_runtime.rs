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
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc},
    task::JoinSet,
};
use uuid::Uuid;

/// Trusted server transport identity and public issuers, supplied independently of the CA lock.
pub struct RemoteService {
    /// Cold signer and private copy store for the shipping administrator adapter.
    pub ca_administration: Option<crate::ca_administration::CaAdministrationConfig>,
    /// Enrollment signer source and transport coordinates.
    pub enrollment: crate::remote_http::EnrollmentService,
    /// Server-only TLS key and certificate.
    pub identity: Identity,
    /// Public issuer overlap for mutual TLS.
    pub roots: Vec<X509>,
}

/// One durable host actor survives transport replacement; every new peer is readmitted.
#[derive(Clone, Default)]
pub(crate) struct RemoteHosts(
    Arc<Mutex<HashMap<Uuid, Host>>>,
    Option<Arc<dyn crate::ca::CaKeySource>>,
);
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
    pub(crate) fn from_source(source: Option<Arc<dyn crate::ca::CaKeySource>>) -> Self {
        Self(Arc::default(), source)
    }
    pub(crate) async fn actor(&self, id: Uuid) -> Option<EmbeddedAgent> {
        self.0
            .lock()
            .await
            .get(&id)
            .filter(|host| host.authority.permits())
            .map(|host| host.actor.clone())
    }
    #[cfg(test)]
    pub(crate) async fn admission_for_test(&self, id: Uuid) -> Option<AuthorityGuard> {
        self.0
            .lock()
            .await
            .get(&id)
            .map(|host| host.authority.clone())
    }
    pub(crate) async fn admit(
        &self,
        authority: AuthorityGuard,
        link: RemoteLink,
    ) -> io::Result<()> {
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
            host.retirement =
                self.retirement(id, generation, authority.clone(), host.actor.clone());
            host.authority = authority;
        } else {
            let (actor, accepts) = EmbeddedAgent::remote(uid);
            accepts
                .try_send(link.authorize(authority.clone()))
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            let retirement = self.retirement(id, generation, authority.clone(), actor.clone());
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

    fn retirement(
        &self,
        id: Uuid,
        generation: Uuid,
        authority: AuthorityGuard,
        actor: EmbeddedAgent,
    ) -> Retirement {
        let registry = Arc::downgrade(&self.0);
        let source = self.1.clone();
        Retirement(tokio::spawn(async move {
            // Healthy idle has only its certificate expiry deadline, never a
            // heartbeat. Ordinary socket loss keeps the actor for offset resume.
            if let Some(source) = source {
                tokio::select! {
                    biased;
                    () = authority.cancelled() => {},
                    () = crate::remote_renewal::run(&authority, &actor, source) => {},
                }
            } else {
                authority.cancelled().await;
            }
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

// Port zero belongs to separate UDP/TCP allocation pools. Reserve TCP first
// and retry only ephemeral UDP collisions; explicit operator ports never move.
async fn reserve_transports(
    address: SocketAddr,
    config: &quinn::ServerConfig,
    mut on_reserved: impl FnMut(SocketAddr) -> io::Result<()>,
) -> io::Result<(quinn::Endpoint, TcpListener)> {
    let attempts = if address.port() == 0 { 16 } else { 1 };
    for _ in 0..attempts {
        let tcp = TcpListener::bind(address).await?;
        let reserved = tcp.local_addr()?;
        on_reserved(reserved)?;
        match quinn::Endpoint::server(config.clone(), reserved) {
            Ok(endpoint) => return Ok((endpoint, tcp)),
            Err(error) if address.port() == 0 && error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
        // Dropping this candidate releases its TCP reservation before retrying.
    }
    Err(io::ErrorKind::AddrInUse.into())
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
        let (endpoint, tcp) = reserve_transports(
            address,
            &remote_quic::server_config(identity, roots)?,
            |_| Ok(()),
        )
        .await?;
        let tls = Arc::new(remote_tls::server_config(identity, roots)?);
        let limits = crate::remote_accept::Limits::new();
        let mut tasks = JoinSet::new();
        tasks.spawn(crate::remote_accept::quic(
            endpoint.clone(),
            hosts.clone(),
            store.clone(),
            limits.clone(),
        ));
        tasks.spawn(crate::remote_accept::tcp(tcp, tls, hosts, store, limits));
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
