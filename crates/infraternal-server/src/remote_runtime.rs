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
    pub(crate) crate::remote_inventory::InventoryChanges,
);

/// Identity and admission limits are shared; this factory never retains its host map.
struct ListenerFactory {
    identity: Identity,
    roots: Vec<X509>,
    store: EnrollmentStore,
    address: SocketAddr,
    destinations: std::sync::Mutex<HashMap<std::net::IpAddr, usize>>,
    limits: Arc<crate::remote_accept::Limits>,
    /// Leased destinations join the agent address's endpoint (one CID space).
    bindings: Arc<infraternal_plugin_remote::remote_bindings::Bindings>,
}
/// Resolves an admitted tuple only during a call; node channels never own the
/// host registry or listener factory through their routing capability.
pub(crate) struct PeerRouting {
    registry: std::sync::Weak<Mutex<HashMap<Uuid, Host>>>,
    factory: std::sync::Weak<std::sync::Mutex<Option<Arc<ListenerFactory>>>>,
}
impl PeerRouting {
    pub(crate) async fn route_peer(
        &self,
        id: Uuid,
        alternate: SocketAddr,
    ) -> io::Result<Option<infraternal_plugin_remote::remote_bindings::PeerBinding>> {
        let Some(registry) = self.registry.upgrade() else {
            return Ok(None);
        };
        let logical = registry
            .lock()
            .await
            .get(&id)
            .filter(|host| host.authority.permits())
            .and_then(|host| host.peer);
        let factory = self
            .factory
            .upgrade()
            .and_then(|factory| factory.lock().ok().and_then(|factory| factory.clone()));
        match (logical, factory) {
            (Some(logical), Some(factory)) => {
                factory.bindings.route_peer(logical, alternate).map(Some)
            }
            _ => Ok(None),
        }
    }
}
struct Host {
    peer: Option<SocketAddr>,
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
            crate::remote_inventory::InventoryChanges::default(),
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
            Some(LeasedListener::start(&factory, address, overlay).await?)
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
    /// Node channels are stored in this registry; a route handle must be weak
    /// so it cannot retain its own actor registry after server shutdown.
    fn peer_capability(&self) -> PeerRouting {
        PeerRouting {
            registry: Arc::downgrade(&self.0),
            factory: Arc::downgrade(&self.3),
        }
    }
    pub(crate) async fn online(&self, id: Uuid) -> bool {
        self.actor(id).await.is_some_and(|actor| {
            matches!(
                *actor.session_inventory().borrow(),
                crate::embedded::SessionInventoryState::Available(_)
            )
        })
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
            self.attach(runtime, *id, host).await?;
        }
        Ok(())
    }
    async fn attach(
        &self,
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
                peer_routes: Some(self.peer_capability()),
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
        if link.primed() {
            return self.admit_primed(authority, link).await;
        }
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
        let peer = link.peer_address();
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
            host.peer = peer;
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
                    peer,
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
            self.attach(&runtime, id, host).await?;
        }
        Ok(())
    }

    /// A primed native link belongs to the existing actor. Its admission waiter
    /// publishes metadata after activation, outside the actor's plugin turn.
    async fn admit_primed(&self, authority: AuthorityGuard, link: RemoteLink) -> io::Result<()> {
        authority.admit_operation().await?;
        let id = authority.identity.host;
        let uid = authority.identity.execution_uid;
        let (actor, expected_generation) = {
            let hosts = self.0.lock().await;
            let host = hosts.get(&id).ok_or(io::ErrorKind::PermissionDenied)?;
            if host.uid != uid || !host.authority.permits() {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            (host.actor.clone(), host.generation)
        };
        let peer = link.peer_address();
        let server_paths = link.supports_server_paths();
        let (activated, activation) = tokio::sync::oneshot::channel();
        link.activation(activated)?;
        actor
            .prime(link.authorize(authority.clone()))
            .await
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        tokio::select! {
            biased;
            () = authority.cancelled() => return Err(io::ErrorKind::PermissionDenied.into()),
            signal = activation => signal.map_err(|_| io::ErrorKind::BrokenPipe)?,
        }
        authority.admit_operation().await?;
        let runtime = self.2.lock().await.upgrade();
        let mut hosts = self.0.lock().await;
        let host = hosts.get_mut(&id).ok_or(io::ErrorKind::PermissionDenied)?;
        if host.uid != uid || host.generation != expected_generation {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let generation = Uuid::new_v4();
        host.peer = peer;
        host.generation = generation;
        host.server_paths = server_paths;
        host.retirement = self.retirement(id, generation, authority.clone(), actor);
        host.authority = authority;
        // A parked underlay is a path replacement, not a new discovery source.
        // The existing remote registry retains the authoritative observed IP.
        if let Some(runtime) = runtime {
            self.attach(&runtime, id, host).await?;
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
) -> io::Result<(
    quinn::Endpoint,
    TcpListener,
    Arc<infraternal_plugin_remote::remote_bindings::Bindings>,
)> {
    use quinn::Runtime as _;
    let attempts = if address.port() == 0 { 16 } else { 1 };
    for _ in 0..attempts {
        let tcp = TcpListener::bind(address).await?;
        let reserved = tcp.local_addr()?;
        on_reserved(reserved)?;
        match std::net::UdpSocket::bind(reserved) {
            Ok(socket) => {
                let bindings = infraternal_plugin_remote::remote_bindings::Bindings::new(
                    quinn::TokioRuntime.wrap_udp_socket(socket)?,
                );
                let endpoint = quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    Some(config.clone()),
                    bindings.clone(),
                    Arc::new(quinn::TokioRuntime),
                )?;
                return Ok((endpoint, tcp, bindings));
            }
            Err(error) if address.port() == 0 && error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
        // Dropping this candidate releases its TCP reservation before retrying.
    }
    Err(io::ErrorKind::AddrInUse.into())
}

/// A leased mesh destination: its UDP socket joins the shared endpoint and its
/// TCP fallback listener is its own. Dropping it releases both.
pub(crate) struct LeasedListener {
    _binding: infraternal_plugin_remote::remote_bindings::LeasedBinding,
    tasks: JoinSet<()>,
    #[cfg(test)]
    address: SocketAddr,
}
impl Drop for LeasedListener {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}
impl LeasedListener {
    async fn start(
        factory: &ListenerFactory,
        address: std::net::IpAddr,
        overlay: RemoteHosts,
    ) -> io::Result<Self> {
        use quinn::Runtime as _;
        let address = SocketAddr::new(address, factory.address.port());
        let tcp = TcpListener::bind(address).await?;
        let socket = quinn::TokioRuntime.wrap_udp_socket(std::net::UdpSocket::bind(address)?)?;
        let binding = factory.bindings.lease(socket)?;
        let tls = Arc::new(remote_tls::server_config(
            &factory.identity,
            &factory.roots,
        )?);
        let mut tasks = JoinSet::new();
        tasks.spawn(crate::remote_accept::tcp(
            tcp,
            tls,
            overlay,
            factory.store.clone(),
            factory.limits.clone(),
        ));
        Ok(Self {
            _binding: binding,
            tasks,
            #[cfg(test)]
            address,
        })
    }
}

/// Owns an additional binding or the routing classification of an existing wildcard.
pub(crate) struct AdditionalListener {
    listener: Option<LeasedListener>,
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
            |listener| Ok(listener.address),
        )
    }
}

/// Bound both UDP and TCP to the server's chosen dial-out port. Drop aborts listener tasks.
pub(crate) struct RemoteListeners {
    tasks: JoinSet<()>,
    endpoint: quinn::Endpoint,
    bindings: Arc<infraternal_plugin_remote::remote_bindings::Bindings>,
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
            bindings: listener.bindings.clone(),
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
        let (endpoint, tcp, bindings) = reserve_transports(
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
            bindings,
            #[cfg(test)]
            diagnostic_hosts,
        })
    }
}

#[cfg(test)]
#[path = "remote_runtime_tests.rs"]
pub(crate) mod tests;
