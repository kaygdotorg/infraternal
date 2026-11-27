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
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    },
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, mpsc},
    task::JoinSet,
};
use uuid::Uuid;

/// Cleanup-only connections share eight active slots and sixteen waiting host
/// claims. Ordinary traffic uses separate admission; repeated cleanup links from
/// one host cannot occupy another host's slot or FIFO queue position.
static LOGIN_CLEANUPS: std::sync::LazyLock<CleanupSlots> =
    std::sync::LazyLock::new(CleanupSlots::default);

/// Fixed delivery capacity and a bounded set of distinct active or waiting hosts.
struct CleanupSlots {
    slots: tokio::sync::Semaphore,
    hosts: std::sync::Mutex<std::collections::HashSet<Uuid>>,
}
impl Default for CleanupSlots {
    /// Reserve eight concurrent deliveries and at most sixteen queued hosts.
    fn default() -> Self {
        Self {
            slots: tokio::sync::Semaphore::new(8),
            hosts: std::sync::Mutex::default(),
        }
    }
}

/// Own one host's queue position until cancellation or delivery completion.
struct CleanupClaim<'a> {
    hosts: &'a std::sync::Mutex<std::collections::HashSet<Uuid>>,
    host: Uuid,
}
impl Drop for CleanupClaim<'_> {
    /// Cancelled waiting connections must immediately release their host claim.
    fn drop(&mut self) {
        self.hosts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.host);
    }
}

/// A delivery keeps both its global slot and its unique host claim alive.
struct CleanupPermit<'a> {
    _slot: tokio::sync::SemaphorePermit<'a>,
    _claim: CleanupClaim<'a>,
}
impl CleanupSlots {
    /// Claim one host before joining the semaphore's FIFO queue. Duplicate and
    /// excess hosts return busy before retaining any actor or queue entry.
    async fn acquire(&self, host: Uuid) -> io::Result<CleanupPermit<'_>> {
        let claim = {
            let mut hosts = self.hosts.lock().map_err(|_| io::ErrorKind::Other)?;
            if hosts.len() >= 24 || !hosts.insert(host) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            CleanupClaim {
                hosts: &self.hosts,
                host,
            }
        };
        let slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(CleanupPermit {
            _slot: slot,
            _claim: claim,
        })
    }
}

/// Deliver one server-retained refusal without publishing a host or normal actor.
/// Busy admission and failed/lost replies leave the durable obligation untouched.
///
/// This is the removal outbox, and the only path that asks a person's host
/// to uninstall itself (#409). In order: the login revocation and its durable
/// receipt (D352); then, if the removal asked for it and the host has not
/// accepted yet, the uninstall request; then one transaction records the
/// host's answer and confirms the receipt, which retires the entry. The
/// receipt is in before the uninstall can stop the agent, and a lost answer
/// confirms nothing, so the next reconnect asks again.
async fn deliver_login_cleanup(
    authority: AuthorityGuard,
    link: RemoteLink,
    person: Uuid,
) -> io::Result<()> {
    let _cleanup = tokio::select! {
        biased;
        () = authority.cancelled() => return Ok(()),
        permit = LOGIN_CLEANUPS.acquire(authority.identity.host) => permit?,
    };
    // This transport never enters inventory, plugin routing or the host
    // actor map. The distinct-host lane bounds active and waiting cleanup jobs.
    // A lost acknowledgement leaves the durable outbox for next reconnect.
    let store = authority.store();
    let host = authority.identity.host;
    let uninstall = store
        .pending_uninstall(host)
        .await
        .map_err(io::Error::other)?;
    // D398: a removal asks for no access report; revoking a person while
    // the host stays does.
    let report = !store
        .removal_requested(host)
        .await
        .map_err(io::Error::other)?;
    let (actor, accepts) = EmbeddedAgent::remote(authority.identity.execution_uid);
    let mut inventory = actor.session_inventory();
    accepts
        .try_send(link.authorize(authority.clone()))
        .map_err(|_| io::ErrorKind::WouldBlock)?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        async {
            tokio::select! {
                biased;
                () = authority.cancelled() => None,
                delivered = async {
                    let revoked = crate::remote_guard::durable_cleanup(actor.downgrade(), person, report).await?;
                    if !uninstall {
                        return Some((revoked, None));
                    }
                    match crate::remote_removal::ask_uninstall(&actor, host).await {
                        // Its report of the kernel objects it leaves is kept
                        // with the answer, for the removal result (#235, #409).
                        crate::remote_removal::UninstallReply::Accepted(left) => Some((revoked, Some(("requested", left)))),
                        // The host answered no: the install stays, and the
                        // removal toast already handed over the manual command.
                        crate::remote_removal::UninstallReply::Refused => Some((revoked, Some(("unreachable", Vec::new())))),
                        crate::remote_removal::UninstallReply::Lost => None,
                    }
                } => delivered,
                // This private actor owns one transport. After a busy reply,
                // disconnect can precede the next retry; its unavailable census
                // ends that attempt instead of awaiting an impossible replacement.
                _ = inventory.wait_for(|state| matches!(state, crate::embedded::SessionInventoryState::Unavailable)) => None,
            }
        },
    )
    .await;
    if let Ok(Some((revoked, answer))) = result {
        store
            .confirm_removal_cleanup(
                host,
                person,
                answer
                    .as_ref()
                    .map(|(cleanup, left)| (*cleanup, left.as_slice())),
                revoked.report.as_ref(),
            )
            .await
            .map_err(io::Error::other)?;
    }
    Ok(())
}

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
    /// Clock health shared by expiry status, local diagnostics and renewal recovery.
    pub clock_health: Arc<crate::clock_health::ClockHealth>,
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
    pub(crate) Arc<std::sync::Mutex<crate::terminal_queries::Registry>>,
    /// Root upgrades' successors waiting for their promotion's driver (D376).
    pub(crate) Arc<crate::remote_successor::Successors>,
    /// Short-lived per-host state that closes terminal admission during promotion.
    Arc<std::sync::Mutex<HashMap<Uuid, std::sync::Weak<TerminalAdmission>>>>,
);

/// Tracks one host's in-flight opens and whether a promotion has closed admission.
///
/// The promotion bit and opener count share one atomic word, so opening and
/// closing admission have a single linearization point without a lock held over
/// remote or database awaits.
struct TerminalAdmission {
    /// The high bit closes admission; the remaining bits count admitted opens.
    state: AtomicUsize,
    /// Wakes the single promotion that is waiting for admitted opens to finish.
    opens_drained: Notify,
}

/// Why a host's terminal admission turned an open away.
///
/// Only [`AdmissionRefused::Upgrading`] tells the person the host is being upgraded (D393), so it
/// must come from the promotion guard's own bit and nothing else: a broken admission map would
/// otherwise make every host look "being upgraded" for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionRefused {
    /// A root upgrade (D376) holds this host's admission closed. It reopens by itself when the
    /// promotion guard drops: on commit, rollback, failure or cancel.
    Upgrading,
    /// Any other refusal: the admission map's lock was poisoned, or the open counter is full.
    Unavailable,
}

/// Keeps a remote terminal open inside its admission window until its row is persisted.
pub(crate) struct TerminalOpenGuard {
    /// Its count keeps a promotion from passing the final session census.
    admission: Arc<TerminalAdmission>,
}

/// Keeps a host's terminal-open admission closed for one complete promotion.
#[cfg(any(feature = "ssh", test))]
pub(crate) struct TerminalPromotionGuard {
    /// Dropping the guard reopens this host without holding a lock across awaits.
    admission: Arc<TerminalAdmission>,
}

/// The highest bit marks a promotion; every lower bit is available for open counts.
const PROMOTION_ACTIVE: usize = 1usize << (usize::BITS - 1);
/// Counts in-flight opens without allowing the promotion flag to be overwritten.
const OPEN_COUNT_MASK: usize = !PROMOTION_ACTIVE;

impl TerminalAdmission {
    /// Admit one open if promotion has not closed this host, refusing counter overflow.
    ///
    /// The refusal names its cause: the promotion bit is `Upgrading`, a full counter is
    /// `Unavailable`. Both are read from the same atomic word the open would claim, so the reason
    /// is exact at the moment of refusal.
    fn admit(self: &Arc<Self>) -> Result<TerminalOpenGuard, AdmissionRefused> {
        let mut current = self.state.load(AtomicOrdering::Acquire);
        loop {
            if current & PROMOTION_ACTIVE != 0 {
                return Err(AdmissionRefused::Upgrading);
            }
            if current & OPEN_COUNT_MASK == OPEN_COUNT_MASK {
                return Err(AdmissionRefused::Unavailable);
            }
            match self.state.compare_exchange_weak(
                current,
                current + 1,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(TerminalOpenGuard {
                        admission: Arc::clone(self),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Close admission, then wait until every already-admitted open has finished.
    #[cfg(any(feature = "ssh", test))]
    async fn block(self: &Arc<Self>) -> Result<TerminalPromotionGuard, ()> {
        let mut current = self.state.load(AtomicOrdering::Acquire);
        loop {
            if current & PROMOTION_ACTIVE != 0 {
                return Err(());
            }
            match self.state.compare_exchange_weak(
                current,
                current | PROMOTION_ACTIVE,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }

        // Construct the reopening guard before waiting so cancellation cannot
        // leave terminal admission closed forever.
        let promotion = TerminalPromotionGuard {
            admission: Arc::clone(self),
        };
        loop {
            let notified = self.opens_drained.notified();
            if self.state.load(AtomicOrdering::Acquire) & OPEN_COUNT_MASK == 0 {
                break;
            }
            notified.await;
        }
        Ok(promotion)
    }
}

impl Drop for TerminalOpenGuard {
    /// Release this open and wake a promotion when it was the final in-flight one.
    fn drop(&mut self) {
        let previous = self.admission.state.fetch_sub(1, AtomicOrdering::AcqRel);
        if previous & OPEN_COUNT_MASK == 1 && previous & PROMOTION_ACTIVE != 0 {
            self.admission.opens_drained.notify_one();
        }
    }
}

#[cfg(any(feature = "ssh", test))]
impl Drop for TerminalPromotionGuard {
    /// Reopen this host when promotion commits, rolls back or is cancelled.
    fn drop(&mut self) {
        self.admission
            .state
            .fetch_and(OPEN_COUNT_MASK, AtomicOrdering::Release);
    }
}

/// The TCP/TLS acceptor every listener of one server uses, replaceable when
/// the server's leaf rotates (#559).
///
/// Each accepted socket takes the acceptor current at its first byte, so a
/// replacement applies to new handshakes only and never touches a connection
/// already established. A read costs one uncontended lock and an `Arc` clone.
pub(crate) struct ServerTls(std::sync::RwLock<Arc<openssl::ssl::SslAcceptor>>);
impl ServerTls {
    /// Hold `acceptor` as the current configuration.
    pub(crate) fn new(acceptor: openssl::ssl::SslAcceptor) -> Self {
        Self(std::sync::RwLock::new(Arc::new(acceptor)))
    }
    /// The configuration for a handshake starting now.
    pub(crate) fn current(&self) -> Arc<openssl::ssl::SslAcceptor> {
        // A poisoned lock still holds a complete Arc; nothing is half-written.
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    /// Make `acceptor` the configuration for every later handshake.
    fn replace(&self, acceptor: openssl::ssl::SslAcceptor) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(acceptor);
    }
}

/// Identity and admission limits are shared; this factory never retains its host map.
struct ListenerFactory {
    /// The TLS configuration shared with the primary listener. Leased
    /// destinations use the same handshake settings and durable admission
    /// checks, and see a rotated leaf at the same moment (#559).
    tls: Arc<ServerTls>,
    store: EnrollmentStore,
    address: SocketAddr,
    destinations: std::sync::Mutex<HashMap<std::net::IpAddr, usize>>,
    limits: Arc<crate::remote_accept::Limits>,
    /// Recovery uses the same signer, server-clock health and durable enrollment store.
    recovery: Option<Arc<crate::remote_recovery::Service>>,
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
            .and_then(|host| host.peer.map(|peer| (peer, host.caps)));
        let factory = self
            .factory
            .upgrade()
            .and_then(|factory| factory.lock().ok().and_then(|factory| factory.clone()));
        match (logical, factory) {
            (Some((logical, caps)), Some(factory)) => {
                let route = factory.bindings.route_peer(logical, alternate)?;
                route.set_backup(caps & infraternal_plugin_api::channel::REMOTE_PATH_BACKUP != 0);
                Ok(Some(route))
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
    caps: u64,
    authority: AuthorityGuard,
    #[cfg(any(test, feature = "native-streams"))]
    admission: Arc<std::sync::RwLock<AuthorityGuard>>,
    actor: EmbeddedAgent,
    accepts: mpsc::Sender<RemoteLink>,
    generation: Uuid,
    changed: tokio::sync::watch::Sender<Uuid>,
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
    /// The port the remote listener actually bound, once it runs. Every
    /// infraternal agent reaches the server over the mesh on this port, TCP
    /// (TLS) and UDP (QUIC), at the server's mesh address (`LeasedListener`).
    /// `None` before the listener starts (a fresh server starts it after its
    /// CA is set up).
    pub(crate) fn listener_port(&self) -> Option<u16> {
        let factory = self.3.lock().ok()?;
        factory.as_ref().map(|factory| factory.address.port())
    }

    /// The TCP/TLS acceptor the listeners use for a handshake starting now.
    /// `/remote/agent` runs its inner leg-B TLS with it, so the HTTPS link
    /// serves exactly the leaf QUIC and TCP/TLS serve, rotation included
    /// (#559). `None` before the listeners start; the route then admits
    /// nothing.
    pub(crate) fn current_acceptor(&self) -> Option<Arc<openssl::ssl::SslAcceptor>> {
        let factory = self.3.lock().ok()?;
        factory.as_ref().map(|factory| factory.tls.current())
    }

    #[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
    pub(crate) async fn node(
        &self,
        id: Uuid,
        owner: String,
        pool: sqlx::SqlitePool,
    ) -> Option<Arc<dyn infraternal_plugin_api::streams::NodeHost>> {
        let hosts = self.0.lock().await;
        let host = hosts.get(&id).filter(|host| host.authority.permits())?;
        Some(Arc::new(crate::node_host::EnrolledNode::new(
            id,
            owner,
            pool,
            host.actor.clone(),
            host.admission.clone(),
        )))
    }
    /// An empty registry whose enrollment signs with `source` (none: no CA yet).
    pub(crate) fn from_source(source: Option<Arc<dyn crate::ca::CaKeySource>>) -> Self {
        Self(
            Arc::default(),
            source,
            Arc::default(),
            Arc::default(),
            false,
            crate::remote_inventory::InventoryChanges::default(),
            Arc::default(),
            Arc::default(),
            Arc::default(),
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
    /// Find or create a host's admission state without keeping one per host forever.
    ///
    /// The map mutex protects only a lookup or insertion; no await happens while it is held.
    /// Weak entries let state disappear after its last open or promotion finishes.
    fn terminal_admission(&self, id: Uuid) -> Result<Arc<TerminalAdmission>, ()> {
        let mut admissions = self.8.lock().map_err(|_| ())?;
        admissions.retain(|_, admission| admission.strong_count() > 0);
        if let Some(admission) = admissions.get(&id).and_then(std::sync::Weak::upgrade) {
            return Ok(admission);
        }
        let admission = Arc::new(TerminalAdmission {
            state: AtomicUsize::new(0),
            opens_drained: Notify::new(),
        });
        admissions.insert(id, Arc::downgrade(&admission));
        Ok(admission)
    }

    /// Refuse terminal opens while a promotion owns its admission window.
    ///
    /// The error says why (see [`AdmissionRefused`]); a poisoned admission map is `Unavailable`,
    /// never `Upgrading`. Callers check that the person owns the host first, so the upgrade state
    /// is only ever told to the host's owner.
    pub(crate) fn admit_terminal_open(
        &self,
        id: Uuid,
    ) -> Result<TerminalOpenGuard, AdmissionRefused> {
        self.terminal_admission(id)
            .map_err(|()| AdmissionRefused::Unavailable)?
            .admit()
    }

    /// Acquire terminal-open exclusion for the duration of a promotion.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn block_terminal_opens(
        &self,
        id: Uuid,
    ) -> Result<TerminalPromotionGuard, ()> {
        self.terminal_admission(id)?.block().await
    }

    /// The CA key source the enrollment issuer uses; mesh SSH signs with it too (#221).
    #[cfg(any(feature = "ssh", test))]
    pub(crate) fn ca_source(&self) -> Option<Arc<dyn crate::ca::CaKeySource>> {
        self.1.clone()
    }
    /// The live link of host `id`, which a root upgrade binds itself to
    /// (D376, J415 R7): its actor, its uid, the exact certificate it was
    /// admitted with, and its generation (which changes when another link
    /// replaces it). `None` when the host has no live link.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn binding(&self, id: Uuid) -> Option<(EmbeddedAgent, u32, [u8; 32], Uuid)> {
        let hosts = self.0.lock().await;
        let host = hosts.get(&id)?;
        host.authority.permits().then(|| {
            (
                host.actor.clone(),
                host.uid,
                host.authority.predecessor(),
                host.generation,
            )
        })
    }

    /// The current link generation of host `id`, if it has a live link.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn generation(&self, id: Uuid) -> Option<Uuid> {
        let hosts = self.0.lock().await;
        hosts
            .get(&id)
            .filter(|host| host.authority.permits())
            .map(|host| host.generation)
    }

    /// Root upgrades' successors waiting for their driver.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) fn successors(&self) -> &crate::remote_successor::Successors {
        &self.7
    }

    pub(crate) async fn actor(&self, id: Uuid) -> Option<EmbeddedAgent> {
        self.0
            .lock()
            .await
            .get(&id)
            .filter(|host| host.authority.permits())
            .map(|host| host.actor.clone())
    }
    #[cfg(feature = "ssh")]
    pub(crate) async fn cancelled(&self, id: Uuid) {
        let Some(mut changed) = self
            .0
            .lock()
            .await
            .get(&id)
            .map(|host| host.changed.subscribe())
        else {
            return;
        };
        loop {
            let Some(authority) = self
                .0
                .lock()
                .await
                .get(&id)
                .map(|host| host.authority.clone())
            else {
                return;
            };
            if !authority.permits() {
                return;
            }
            tokio::select! {
                () = authority.cancelled() => {},
                result = changed.changed() => { if result.is_err() { return; } },
            }
        }
    }
    #[cfg(feature = "ssh")]
    pub(crate) async fn stop_provisioning(&self) -> io::Result<()> {
        let actors = {
            let mut hosts = self.0.lock().await;
            hosts.retain(|_, host| host.authority.installed());
            hosts
                .values()
                .map(|host| host.actor.clone())
                .collect::<Vec<_>>()
        };
        // Installed admission can coexist briefly with an unacknowledged SSH
        // fallback. Retire that fallback without stopping its installed role.
        for actor in actors {
            actor
                .retire_ssh()
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
        Ok(())
    }
    #[cfg(feature = "ssh")]
    pub(crate) async fn installed(&self, id: Uuid) -> bool {
        self.0
            .lock()
            .await
            .get(&id)
            .is_some_and(|host| host.authority.permits() && host.authority.installed())
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
                server_paths: host.caps & infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS
                    != 0,
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
    fn prove_paths(&self, link: &mut RemoteLink) -> io::Result<()> {
        if link.peer_capabilities() & infraternal_plugin_api::channel::REMOTE_PATH_PROOF == 0 {
            return Ok(());
        }
        if let Some(factory) = self.3.lock().map_err(|_| io::ErrorKind::Other)?.clone() {
            link.prove_paths(&factory.bindings)?;
        }
        Ok(())
    }

    /// Admit a link and update its source only when this transport exposes one.
    /// SSH pipes have no observed socket IP; preserve an existing value or use
    /// the unspecified address until the enrolled network link is admitted.
    /// Cleanup-only admission owns a bounded private actor and never publishes
    /// host availability, plugins, sessions or positive login authority.
    pub(crate) async fn admit_observed(
        &self,
        authority: AuthorityGuard,
        mut link: RemoteLink,
        observed_ip: Option<std::net::IpAddr>,
    ) -> io::Result<()> {
        if let Some(person) = authority.cleanup_person() {
            return deliver_login_cleanup(authority, link, person).await;
        }
        // A root upgrade's successor never enters the registry (J415 R2).
        if authority.successor_authority().is_some() {
            return crate::remote_successor::deliver(&self.7, authority, link).await;
        }
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
        let caps = link.peer_capabilities();
        // After a root upgrade's handover the host's uid changed. The old
        // epoch's actor was cut, but its retirement task may not have removed
        // it yet; a live actor of another uid is still refused (R2).
        if hosts
            .get(&id)
            .is_some_and(|host| host.uid != uid && !host.authority.permits())
        {
            let channel = hosts.remove(&id).and_then(|host| host.channel);
            if let Some(channel) = channel
                && let Some(runtime) = &runtime
            {
                runtime.detach_node_if(&channel).await;
            }
        }
        let rootful = authority.identity.mode == crate::enrollment::Mode::Rootful;
        if let Some(host) = hosts.get_mut(&id) {
            if host.uid != uid {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.prove_paths(&mut link)?;
            host.accepts
                .try_send(link.authorize(authority.clone()))
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            // Publish only after queue admission. A rejected replacement must
            // not alter a valid actor or cancel its existing retirement waiter.
            host.peer = peer;
            host.generation = generation;
            host.caps = caps;
            host.retirement = self.retirement(
                id,
                generation,
                authority.clone(),
                host.actor.clone(),
                caps & infraternal_plugin_api::channel::LIVE_IDENTITY_ROTATION != 0,
            );
            #[cfg(any(test, feature = "native-streams"))]
            {
                *host
                    .admission
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = authority.clone();
            }
            host.authority = authority;
            // Tunnel source addresses are not underlay discovery. Preserve the
            // existing address, including its canonical IPv4 representation.
            if !self.4
                && let Some(ip) = observed_ip
            {
                host.ip = ip.to_canonical();
            }
            host.changed.send_replace(generation);
        } else {
            self.prove_paths(&mut link)?;
            let (actor, accepts) = EmbeddedAgent::remote(uid);
            accepts
                .try_send(link.authorize(authority.clone()))
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            let retirement = self.retirement(
                id,
                generation,
                authority.clone(),
                actor.clone(),
                caps & infraternal_plugin_api::channel::LIVE_IDENTITY_ROTATION != 0,
            );
            hosts.insert(
                id,
                Host {
                    peer,
                    ip: if self.4 {
                        std::net::Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        observed_ip.map_or_else(
                            || std::net::Ipv4Addr::UNSPECIFIED.into(),
                            |ip| ip.to_canonical(),
                        )
                    },
                    channel: None,
                    uid,
                    caps,
                    #[cfg(any(test, feature = "native-streams"))]
                    admission: Arc::new(std::sync::RwLock::new(authority.clone())),
                    authority,
                    actor,
                    accepts,
                    generation,
                    changed: tokio::sync::watch::channel(generation).0,
                    retirement,
                },
            );
        }
        if let Some(host) = hosts.get(&id) {
            host.authority.bind_login_actor(&host.actor);
            // A promoted host's new root agent retires the rootless install
            // and leaves standby, from the durable outbox (J415 R5).
            if rootful {
                tokio::spawn(crate::remote_successor::retire_predecessor(
                    host.authority.store(),
                    host.actor.clone(),
                    id,
                ));
            }
        }
        if let Some(runtime) = runtime
            && let Some(host) = hosts.get_mut(&id)
        {
            self.attach(&runtime, id, host).await?;
        }
        self.5.publish();
        Ok(())
    }

    /// A primed native link belongs to the existing actor. Its admission waiter
    /// publishes metadata after activation, outside the actor's plugin turn.
    async fn admit_primed(
        &self,
        authority: AuthorityGuard,
        mut link: RemoteLink,
    ) -> io::Result<()> {
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
        let caps = link.peer_capabilities();
        self.prove_paths(&mut link)?;
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
        host.caps = caps;
        host.retirement = self.retirement(
            id,
            generation,
            authority.clone(),
            actor,
            caps & infraternal_plugin_api::channel::LIVE_IDENTITY_ROTATION != 0,
        );
        // Retained NodeHost handles follow the promoted certificate and its
        // subsequent renewals, rather than the retired connection's expiry.
        #[cfg(any(test, feature = "native-streams"))]
        {
            *host
                .admission
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = authority.clone();
        }
        host.authority = authority;
        self.5.publish();
        // A parked underlay is a path replacement, not a new discovery source.
        // The existing remote registry retains the authoritative observed IP.
        if let Some(runtime) = runtime {
            self.attach(&runtime, id, host).await?;
        }
        Ok(())
    }

    /// Decide what retiring host `id` removes.
    fn retirement(
        &self,
        id: Uuid,
        generation: Uuid,
        authority: AuthorityGuard,
        actor: EmbeddedAgent,
        identity_rotation: bool,
    ) -> Retirement {
        let registry = Arc::downgrade(&self.0);
        let source = self.1.clone();
        let plugins = self.2.clone();
        Retirement(tokio::spawn(async move {
            // Healthy idle has only its certificate expiry deadline, never a
            // heartbeat. Ordinary socket loss keeps the actor for offset resume.
            if let Some(source) = source.filter(|_| authority.installed()) {
                tokio::select! {
                    biased;
                    () = authority.cancelled() => {},
                    () = crate::remote_renewal::run(&authority, &actor, source, identity_rotation) => {},
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
    /// Start a leased listener on `address`.
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
        let mut tasks = JoinSet::new();
        tasks.spawn(crate::remote_accept::tcp(
            tcp,
            factory.tls.clone(),
            overlay,
            factory.store.clone(),
            factory.limits.clone(),
            factory.recovery.clone(),
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
    /// What a leaf rotation replaces: the TCP/TLS acceptor (the QUIC endpoint
    /// takes a new server configuration directly).
    tls: Arc<ServerTls>,
    /// Client-certificate trust both transports keep across a rotation.
    roots: Vec<X509>,
    /// Whether the TCP/TLS acceptor also offers the recovery ALPN.
    recovery: bool,
    #[cfg(test)]
    pub(crate) diagnostic_hosts: RemoteHosts,
    /// The device links these listeners hold (#580), for tests to inspect.
    #[cfg(test)]
    pub(crate) diagnostic_devices: Arc<crate::remote_device_link::DeviceLinks>,
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

    /// The address both transports are bound to.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Run `task` for the listeners' lifetime; dropping the listeners aborts it (the server
    /// node's relay leaf rotation, D402, lives here).
    pub(crate) fn keep_task(
        &mut self,
        task: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        self.tasks.spawn(task);
    }

    /// Keep the served leaf fresh for the listeners' lifetime (#559): start
    /// the `server_leaf` rotation task, which reissues the leaf while the CA
    /// is unlocked and installs each durable new leaf here. `current` is the
    /// leaf the listeners were started with. Dropping the listeners stops it.
    pub(crate) fn rotate_server_leaf(
        &mut self,
        rotation: crate::server_leaf::Rotation,
        current: X509,
    ) {
        let swap = LeafSwap {
            endpoint: self.endpoint.clone(),
            tls: self.tls.clone(),
            roots: self.roots.clone(),
            recovery: self.recovery,
        };
        self.tasks.spawn(crate::server_leaf::run(
            rotation,
            Some(current),
            move |identity| swap.install(identity),
        ));
    }

    /// Serve `identity` to every new QUIC and TCP/TLS handshake from now on.
    /// # Errors
    /// Refuses an identity either transport cannot be configured with; then
    /// neither transport changes.
    #[cfg(test)]
    pub(crate) fn install_server_leaf(&self, identity: &Identity) -> io::Result<()> {
        LeafSwap {
            endpoint: self.endpoint.clone(),
            tls: self.tls.clone(),
            roots: self.roots.clone(),
            recovery: self.recovery,
        }
        .install(identity)
    }

    /// Start the remote listeners on `address` with this identity and its trust roots.
    pub(crate) async fn start(
        address: SocketAddr,
        identity: &Identity,
        roots: &[X509],
        store: EnrollmentStore,
        hosts: RemoteHosts,
    ) -> io::Result<Self> {
        Self::start_configured(address, identity, roots, store, hosts, None).await
    }

    /// Start normal mTLS admission with the separate expired-certificate recovery ALPN.
    /// The recovery service never receives a host-admitted control channel.
    /// # Errors
    /// Refuses invalid TLS identity, trust or listener configuration.
    pub(crate) async fn start_with_recovery(
        address: SocketAddr,
        identity: &Identity,
        roots: &[X509],
        store: EnrollmentStore,
        hosts: RemoteHosts,
        source: Arc<dyn crate::ca::CaKeySource>,
        clock: Arc<crate::clock_health::ClockHealth>,
    ) -> io::Result<Self> {
        let recovery = Arc::new(crate::remote_recovery::Service::new(
            store.clone(),
            source,
            clock,
            Arc::new(crate::remote_recovery::Limiter::default()),
        ));
        Self::start_configured(address, identity, roots, store, hosts, Some(recovery)).await
    }

    /// Start the listener with or without the recovery service.
    async fn start_configured(
        address: SocketAddr,
        identity: &Identity,
        roots: &[X509],
        store: EnrollmentStore,
        hosts: RemoteHosts,
        recovery: Option<Arc<crate::remote_recovery::Service>>,
    ) -> io::Result<Self> {
        let limits = crate::remote_accept::Limits::new();
        let (listener, tls) = Self::start_with_limits(
            address,
            identity,
            roots,
            store.clone(),
            hosts.clone(),
            limits.clone(),
            recovery.clone(),
        )
        .await?;
        let factory = ListenerFactory {
            tls: tls.clone(),
            store,
            address: listener.local_addr()?,
            destinations: std::sync::Mutex::default(),
            limits,
            recovery,
            bindings: listener.bindings.clone(),
        };
        *hosts.3.lock().map_err(|_| io::ErrorKind::Other)? = Some(Arc::new(factory));
        Ok(listener)
    }

    /// Start the listeners with explicit admission limits.
    async fn start_with_limits(
        address: SocketAddr,
        identity: &Identity,
        roots: &[X509],
        store: EnrollmentStore,
        hosts: RemoteHosts,
        limits: Arc<crate::remote_accept::Limits>,
        recovery: Option<Arc<crate::remote_recovery::Service>>,
    ) -> io::Result<(Self, Arc<ServerTls>)> {
        #[cfg(test)]
        let diagnostic_hosts = hosts.clone();
        #[cfg(test)]
        let diagnostic_devices = limits.devices.clone();
        let (endpoint, tcp, bindings) = reserve_transports(
            address,
            &remote_quic::server_config(identity, roots)?,
            |_| Ok(()),
        )
        .await?;
        let tls = Arc::new(ServerTls::new(tcp_acceptor(
            identity,
            roots,
            recovery.is_some(),
        )?));
        let recovering = recovery.is_some();
        let mut tasks = JoinSet::new();
        tasks.spawn(crate::remote_accept::quic(
            endpoint.clone(),
            hosts.clone(),
            store.clone(),
            limits.clone(),
        ));
        tasks.spawn(crate::remote_accept::tcp(
            tcp,
            tls.clone(),
            hosts,
            store,
            limits,
            recovery,
        ));
        Ok((
            Self {
                tasks,
                endpoint,
                bindings,
                tls: tls.clone(),
                roots: roots.to_vec(),
                recovery: recovering,
                #[cfg(test)]
                diagnostic_hosts,
                #[cfg(test)]
                diagnostic_devices,
            },
            tls,
        ))
    }
}

/// The TCP/TLS acceptor for `identity`, with or without the recovery ALPN.
fn tcp_acceptor(
    identity: &Identity,
    roots: &[X509],
    recovery: bool,
) -> io::Result<openssl::ssl::SslAcceptor> {
    if recovery {
        remote_tls::recovery_server_config(identity, roots)
    } else {
        remote_tls::server_config(identity, roots)
    }
}

/// Installs a rotated server leaf into both transports of one listener set.
struct LeafSwap {
    /// The QUIC endpoint, which takes a new server configuration in place.
    endpoint: quinn::Endpoint,
    /// The TCP/TLS acceptor shared by the primary and leased listeners.
    tls: Arc<ServerTls>,
    /// Client-certificate trust, unchanged by a rotation.
    roots: Vec<X509>,
    /// Whether the TCP/TLS acceptor also offers the recovery ALPN.
    recovery: bool,
}
impl LeafSwap {
    /// Build both configurations first, then switch both, so a failure leaves
    /// the previous leaf on both transports. Established connections keep
    /// the leaf they were made with.
    fn install(&self, identity: &Identity) -> io::Result<()> {
        let quic = remote_quic::server_config(identity, &self.roots)?;
        let tcp = tcp_acceptor(identity, &self.roots, self.recovery)?;
        self.endpoint.set_server_config(Some(quic));
        self.tls.replace(tcp);
        Ok(())
    }
}

#[cfg(test)]
#[path = "remote_runtime_tests.rs"]
pub(crate) mod tests;

/// Cleanup admission must isolate a repeated host and queue distinct hosts fairly.
#[cfg(test)]
mod cleanup_admission_tests {
    use super::*;

    /// A stalled host cannot occupy another host's delivery slot.
    #[tokio::test]
    async fn cleanup_delivery_deduplicates_hosts() {
        let lane = CleanupSlots::default();
        let host = Uuid::new_v4();
        let _first = lane.acquire(host).await.unwrap();
        assert!(
            lane.acquire(host).await.is_err(),
            "duplicate host occupied another slot"
        );
    }
}

/// Distinct hosts receive FIFO admission with a finite waiting population.
#[cfg(test)]
mod cleanup_fairness_tests {
    use super::*;
    use std::{future::Future, task::Poll};

    /// A returning host cannot jump a queued host; excess waiting is refused,
    /// and dropping a queued connection releases its host claim immediately.
    #[tokio::test]
    async fn cleanup_delivery_is_fair_and_bounded() {
        let lane = CleanupSlots::default();
        let mut active = Vec::new();
        for _ in 0..8 {
            active.push(lane.acquire(Uuid::new_v4()).await.unwrap());
        }
        let mut waiting = Vec::new();
        let mut ids = Vec::new();
        for _ in 0..16 {
            let id = Uuid::new_v4();
            let mut request = Box::pin(lane.acquire(id));
            assert!(
                matches!(
                    std::future::poll_fn(|cx| Poll::Ready(request.as_mut().poll(cx))).await,
                    Poll::Pending
                ),
                "a distinct host must queue"
            );
            waiting.push(request);
            ids.push(id);
        }
        assert!(
            lane.acquire(Uuid::new_v4()).await.is_err(),
            "waiting queue grew past sixteen"
        );
        drop(waiting.pop());
        let mut replacement = Box::pin(lane.acquire(*ids.last().unwrap()));
        assert!(
            matches!(
                std::future::poll_fn(|cx| Poll::Ready(replacement.as_mut().poll(cx))).await,
                Poll::Pending
            ),
            "cancelled host claim was retained"
        );
        drop(active.pop());
        assert!(
            matches!(
                std::future::poll_fn(|cx| Poll::Ready(replacement.as_mut().poll(cx))).await,
                Poll::Pending
            ),
            "new host jumped the FIFO queue"
        );
        let admitted = waiting.remove(0).await.unwrap();
        drop(admitted);
        let _next = waiting.remove(0).await.unwrap();
    }
}
