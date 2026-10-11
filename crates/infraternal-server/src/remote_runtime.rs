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
    pub identity: Option<Identity>,
    /// Public issuer overlap for mutual TLS.
    pub roots: Vec<X509>,
}

/// One durable host actor survives transport replacement; every new peer is readmitted.
#[derive(Clone, Default)]
pub(crate) struct RemoteHosts(
    Arc<Mutex<HashMap<Uuid, Host>>>,
    Option<Arc<dyn crate::ca::CaKeySource>>,
    Arc<Mutex<crate::plugins::WeakRuntime>>,
    Arc<std::sync::Mutex<Option<Arc<ListenerFactory>>>>,
    bool,
);

/// Identity and admission limits are shared; this factory never retains its host map.
struct ListenerFactory {
    identity: Identity,
    roots: Vec<X509>,
    store: EnrollmentStore,
    address: SocketAddr,
    destinations: std::sync::Mutex<HashMap<std::net::IpAddr, usize>>,
    limits: Arc<crate::remote_accept::Limits>,
}
struct Host {
    ip: std::net::IpAddr,
    channel: Option<Arc<dyn infraternal_plugin_api::node_channel::NodeChannel>>,
    uid: u32,
    server_paths: bool,
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
        Self(
            Arc::default(),
            source,
            Arc::default(),
            Arc::default(),
            false,
        )
    }
    /// Classify the accepted destination, including a pre-existing wildcard listener.
    pub(crate) fn for_local(&self, local: Option<std::net::IpAddr>) -> Self {
        let mut hosts = self.clone();
        if let Some(local) = local
            && let Ok(factory) = self.3.lock()
            && let Some(factory) = &*factory
            && factory
                .destinations
                .lock()
                .is_ok_and(|destinations| destinations.contains_key(&local.to_canonical()))
        {
            hosts.4 = true;
        }
        hosts
    }
    pub(crate) async fn listen(
        &self,
        address: std::net::IpAddr,
    ) -> io::Result<Option<AdditionalListener>> {
        let factory = self.3.lock().map_err(|_| io::ErrorKind::Other)?.clone();
        let Some(factory) = factory else {
            return Ok(None);
        };
        let mut overlay = self.clone();
        overlay.4 = true;
        // An operator-selected wildcard already covers this destination. Its
        // enrolled listener stays shared; only the destination lease is new.
        let listener = if factory.address.ip().is_unspecified() {
            None
        } else {
            Some(
                RemoteListeners::start_with_limits(
                    SocketAddr::new(address, factory.address.port()),
                    &factory.identity,
                    &factory.roots,
                    factory.store.clone(),
                    overlay,
                    factory.limits.clone(),
                )
                .await?,
            )
        };
        *factory
            .destinations
            .lock()
            .map_err(|_| io::ErrorKind::Other)?
            .entry(address.to_canonical())
            .or_default() += 1;
        Ok(Some(AdditionalListener {
            listener,
            factory,
            address: address.to_canonical(),
        }))
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
    /// Called after plugin settings are loaded; listeners may already have admitted hosts.
    pub(crate) async fn bind_plugins(
        &self,
        runtime: &crate::plugins::PluginRuntime,
    ) -> io::Result<()> {
        *self.2.lock().await = runtime.downgrade();
        let mut hosts = self.0.lock().await;
        for (id, host) in &mut *hosts {
            Self::attach(runtime, *id, host).await?;
        }
        Ok(())
    }
    async fn attach(
        runtime: &crate::plugins::PluginRuntime,
        id: Uuid,
        host: &mut Host,
    ) -> io::Result<()> {
        let channel: Arc<dyn infraternal_plugin_api::node_channel::NodeChannel> =
            Arc::new(crate::node_bridge::NodeBridge {
                id: id.to_string(),
                ip: host.ip,
                server: false,
                server_paths: host.server_paths,
                actor: host.actor.clone(),
                authority: Some(host.authority.clone()),
                listeners: None,
            });
        runtime
            .attach_node(channel.clone())
            .await
            .map_err(|_| io::ErrorKind::Other)?;
        host.channel = Some(channel);
        Ok(())
    }
    pub(crate) async fn admit_observed(
        &self,
        authority: AuthorityGuard,
        link: RemoteLink,
        ip: std::net::IpAddr,
    ) -> io::Result<()> {
        if !authority.permits() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let id = authority.identity.host;
        let uid = authority.identity.execution_uid;
        let runtime = self.2.lock().await.upgrade();
        let mut hosts = self.0.lock().await;
        if !hosts.contains_key(&id) && hosts.len() >= 10_000 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let generation = Uuid::new_v4();
        let server_paths = link.supports_server_paths();
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
            host.server_paths = server_paths;
            host.retirement =
                self.retirement(id, generation, authority.clone(), host.actor.clone());
            host.authority = authority;
            // Tunnel source addresses are not underlay discovery. Preserve the
            // existing address, including its canonical IPv4 representation.
            host.ip = if self.4 {
                host.ip.to_canonical()
            } else {
                ip.to_canonical()
            };
        } else {
            let (actor, accepts) = EmbeddedAgent::remote(uid);
            accepts
                .try_send(link.authorize(authority.clone()))
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            let retirement = self.retirement(id, generation, authority.clone(), actor.clone());
            hosts.insert(
                id,
                Host {
                    ip: if self.4 {
                        std::net::Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        ip.to_canonical()
                    },
                    channel: None,
                    uid,
                    server_paths,
                    authority,
                    actor,
                    accepts,
                    generation,
                    retirement,
                },
            );
        }
        if let Some(runtime) = runtime
            && let Some(host) = hosts.get_mut(&id)
        {
            Self::attach(&runtime, id, host).await?;
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
        let plugins = self.2.clone();
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
                let channel = hosts.remove(&id).and_then(|host| host.channel);
                drop(hosts);
                if let Some(channel) = channel
                    && let Some(runtime) = plugins.lock().await.upgrade()
                {
                    runtime.detach_node_if(&channel).await;
                }
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

/// Owns an additional binding or the routing classification of an existing wildcard.
pub(crate) struct AdditionalListener {
    listener: Option<RemoteListeners>,
    factory: Arc<ListenerFactory>,
    address: std::net::IpAddr,
}
impl Drop for AdditionalListener {
    fn drop(&mut self) {
        drop(self.listener.take());
        if let Ok(mut destinations) = self.factory.destinations.lock()
            && let Some(count) = destinations.get_mut(&self.address)
        {
            *count -= 1;
            if *count == 0 {
                destinations.remove(&self.address);
            }
        }
    }
}
impl AdditionalListener {
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.as_ref().map_or(
            Ok(SocketAddr::new(self.address, self.factory.address.port())),
            RemoteListeners::local_addr,
        )
    }
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
        let limits = crate::remote_accept::Limits::new();
        let listener = Self::start_with_limits(
            address,
            identity,
            roots,
            store.clone(),
            hosts.clone(),
            limits.clone(),
        )
        .await?;
        let factory = ListenerFactory {
            identity: Identity {
                certificate: identity.certificate.clone(),
                key: identity.key.clone(),
            },
            roots: roots.to_vec(),
            store,
            address: listener.local_addr()?,
            destinations: std::sync::Mutex::default(),
            limits,
        };
        *hosts.3.lock().map_err(|_| io::ErrorKind::Other)? = Some(Arc::new(factory));
        Ok(listener)
    }

    async fn start_with_limits(
        address: SocketAddr,
        identity: &Identity,
        roots: &[X509],
        store: EnrollmentStore,
        hosts: RemoteHosts,
        limits: Arc<crate::remote_accept::Limits>,
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
