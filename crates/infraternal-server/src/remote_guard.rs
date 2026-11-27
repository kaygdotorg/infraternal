//! Fences admitted remote writes across durable revocation and certificate expiry, without per-keystroke ledger reads [134], #78.

use crate::enrollment::{EnrollmentStore, HostAuthority};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, time::Instant};
use uuid::Uuid;

/// One event source per runtime store, shared by its clones. Weak entries do not
/// retain transports, and dead registrations are pruned at the cap.
///
/// Signals are kept per authority epoch: a host *and* the uid its infraternal
/// agent runs as (J415 R2). A host has one epoch in its life, except during a
/// root upgrade, when the rootless epoch (host, 1001 say) and the root
/// successor's epoch (host, 0) briefly coexist. The handover cuts only the old
/// epoch, so the new one keeps its link. Removing a host cuts every epoch it
/// has, and keeps refusing new ones until the tombstone commits.
#[derive(Default)]
pub(crate) struct Revocations {
    signals: Mutex<HashMap<Epoch, Weak<Revocation>>>,
    /// Device links' signals (#580), kept apart from `signals` so the two
    /// kinds cannot starve each other at the cap: always-on devices must not
    /// lock out host connections, reconnects after a restart included.
    device_signals: Mutex<HashMap<Epoch, Weak<Revocation>>>,
    /// Login cleanup has its own signal because ordinary removal opens this
    /// delivery path after cutting normal host access. Forget cuts both.
    cleanup_signals: Mutex<HashMap<Epoch, Weak<Revocation>>>,
    // Storage refusal must not let the last transport drop the cancellation
    // signal and permit a reconnect. Successful tombstones release this hold.
    cuts: Mutex<Cuts>,
    pub(crate) plugins: Mutex<crate::plugins::WeakRuntime>,
    #[cfg(test)]
    pub(crate) publication_pause: Mutex<Option<Arc<PublicationPause>>>,
}

/// One authority epoch: the host and the uid its infraternal agent runs as.
pub(crate) type Epoch = (Uuid, u32);

/// The cuts still held until their tombstone commits.
#[derive(Default)]
struct Cuts {
    /// Cut epochs, each holding its (already cancelled) signal alive.
    epochs: HashMap<Epoch, Arc<Revocation>>,
    /// Hosts cut as a whole (removal): every epoch, including ones that
    /// register later, starts cancelled until [`Revocations::tombstoned`].
    hosts: std::collections::HashSet<Uuid>,
}

/// The signals one cut cancelled. Holding it keeps them registered, so a
/// reconnect in the gap before the tombstone finds them already cancelled.
pub(crate) struct Cut(Vec<Arc<Revocation>>);

#[cfg(test)]
#[derive(Default)]
pub(crate) struct PublicationPause {
    pub(crate) committed: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}
/// Cancellation is visible before draining admitted writes. Retaining this
/// registration through COMMIT prevents admission from creating a fresh false
/// signal while the tombstone is not yet visible to a different reader.
pub(crate) struct Revocation {
    login_actor: Mutex<Option<crate::embedded::WeakEmbeddedAgent>>,
    changed: watch::Sender<bool>,
    writes: Arc<tokio::sync::RwLock<()>>,
}

impl Revocation {
    /// A fresh signal, cancelled from the start when `cut`.
    fn new(cut: bool) -> Arc<Self> {
        Arc::new(Self {
            login_actor: Mutex::default(),
            changed: watch::channel(cut).0,
            writes: Arc::default(),
        })
    }
}

impl Revocation {
    /// Watch this epoch's cut: the value turns `true` once the epoch or its
    /// host is cut, and never back. A device link (#580) holds one so a
    /// device's removal closes its link at once, without a ledger read.
    pub(crate) fn cut_receiver(&self) -> watch::Receiver<bool> {
        self.changed.subscribe()
    }
}

impl Revocations {
    #[cfg(test)]
    pub(crate) async fn after_commit(&self) {
        let pause = self.publication_pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.committed.notify_one();
            pause.release.notified().await;
        }
    }

    /// Every live signal of `host`, host epochs and device links alike.
    fn live_of(&self, host: Uuid) -> Vec<Arc<Revocation>> {
        [&self.signals, &self.device_signals]
            .into_iter()
            .flat_map(|list| {
                list.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .iter()
                    .filter(|((id, _), _)| *id == host)
                    .filter_map(|(_, signal)| signal.upgrade())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The live signal for `epoch`, creating it when there is none. A signal
    /// created while its host or epoch is cut starts cancelled.
    pub(crate) fn register(&self, host: Uuid, uid: u32) -> io::Result<Arc<Revocation>> {
        // Lock order: cuts, then signals (the same as `cut`).
        let cuts = self
            .cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // This map contains only independent weak registrations; Rust containers
        // retain their invariants after unwinding, so poison can be recovered.
        let list = if uid == crate::remote_device_link::DEVICE_EPOCH_UID {
            &self.device_signals
        } else {
            &self.signals
        };
        Self::register_signal(list, (host, uid), cuts.hosts.contains(&host))
    }

    /// Register a cleanup-only connection without reusing the cut for normal host access.
    fn register_cleanup(&self, host: Uuid) -> io::Result<Arc<Revocation>> {
        Self::register_signal(&self.cleanup_signals, (host, 0), false)
    }

    /// Reuse the live signal for this lane, with a bound on retained registrations.
    fn register_signal(
        list: &Mutex<HashMap<Epoch, Weak<Revocation>>>,
        epoch: Epoch,
        cut: bool,
    ) -> io::Result<Arc<Revocation>> {
        let mut signals = list
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(signal) = signals.get(&epoch).and_then(Weak::upgrade) {
            return Ok(signal);
        }
        if signals.len() >= 10_000 {
            signals.retain(|_, signal| signal.strong_count() != 0);
            if signals.len() >= 10_000 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let signal = Revocation::new(cut);
        signals.insert(epoch, Arc::downgrade(&signal));
        Ok(signal)
    }

    /// Route the test fixture's retained actor through the same durable receipt
    /// helper as a cleanup-only reconnect; absent actors are never confirmed.
    #[cfg(test)]
    pub(crate) async fn revoke_login(&self, host: Uuid, person: Uuid) -> bool {
        // Device signals carry no login actor, so skip to one that does.
        let actor = self.live_of(host).into_iter().find_map(|signal| {
            signal
                .login_actor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        });
        let Some(actor) = actor else {
            return false;
        };
        durable_cleanup(actor, person, true).await.is_some()
    }

    /// Cut every epoch of `host`, then wait until each one's admitted writes
    /// have drained. Hold the result until the tombstone commits.
    pub(crate) async fn quiesce(
        &self,
        host: Uuid,
    ) -> io::Result<(Cut, Vec<tokio::sync::OwnedRwLockWriteGuard<()>>)> {
        Ok(Self::drain(self.cut(host)?).await)
    }

    /// Stop both ordinary and cleanup-only writes before Forget commits.
    /// Pin both cleanup lanes even when disconnected, so a concurrent
    /// admission observes a cut signal or rechecks the committed ledger.
    pub(crate) async fn quiesce_forget(
        &self,
        host: Uuid,
    ) -> io::Result<(Cut, Vec<tokio::sync::OwnedRwLockWriteGuard<()>>)> {
        let cleanup = self.register_cleanup(host)?;
        let _successor = self.register(host, 0)?;
        let mut cut = self.cut(host)?;
        cleanup.changed.send_replace(true);
        cut.0.push(cleanup);
        Ok(Self::drain(cut).await)
    }

    /// Wait for writes already admitted in each cut lane to leave the transport.
    async fn drain(cut: Cut) -> (Cut, Vec<tokio::sync::OwnedRwLockWriteGuard<()>>) {
        let mut drained = Vec::with_capacity(cut.0.len());
        for signal in &cut.0 {
            drained.push(signal.writes.clone().write_owned().await);
        }
        (cut, drained)
    }

    /// Fence new writes on every epoch of `host` before waiting for SQLite's
    /// writer slot. The caller retains the cut until the durable tombstone
    /// has committed, so a reconnect, as any uid, cannot allocate an
    /// uncancelled registration in that gap.
    pub(crate) fn cut(&self, host: Uuid) -> io::Result<Cut> {
        let mut cuts = self
            .cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cuts.hosts.len() >= 10_000 && !cuts.hosts.contains(&host) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        cuts.hosts.insert(host);
        let live = self.live_of(host);
        for signal in &live {
            signal.changed.send_replace(true);
        }
        Ok(Cut(live))
    }

    /// Cut one epoch only: the old rootless authority right after a root
    /// upgrade's handover commits (J415 R2). The host's other epochs, the new
    /// root one included, are untouched. Release it with
    /// [`Self::tombstoned_epoch`] once the change is durable.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) fn cut_epoch(&self, host: Uuid, uid: u32) -> io::Result<Arc<Revocation>> {
        let signal = self.register(host, uid)?;
        let mut cuts = self
            .cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cuts.epochs.len() >= 10_000 && !cuts.epochs.contains_key(&(host, uid)) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        cuts.epochs.insert((host, uid), signal.clone());
        signal.changed.send_replace(true);
        Ok(signal)
    }

    /// The host's tombstone committed: release every cut of it.
    pub(crate) fn tombstoned(&self, host: Uuid) {
        let mut cuts = self
            .cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cuts.hosts.remove(&host);
        cuts.epochs.retain(|(id, _), _| *id != host);
    }

    /// One epoch's end is durable (its certificates are revoked): release its
    /// cut. Admission refuses that epoch's certificates from here on anyway.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) fn tombstoned_epoch(&self, host: Uuid, uid: u32) {
        self.cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .epochs
            .remove(&(host, uid));
    }
}

/// Wait for an actual durable reply rather than treating a short timeout as
/// completion. The bounded transport owner supplies the whole-attempt deadline;
/// errors may retry, but an unanswered save is never duplicated in its queue.
/// `None` means not confirmed; a confirmation carries the host's D356 report
/// when `report` asked for one (never for a host removal, D398).
pub(crate) async fn durable_cleanup(
    actor: crate::embedded::WeakEmbeddedAgent,
    person: Uuid,
    report: bool,
) -> Option<crate::embedded::Revoked> {
    loop {
        match actor.revoke_login(person, report).await {
            Ok(revoked) => return Some(revoked),
            Err(crate::embedded::AgentError::Rejected) => {
                // Busy capacity and failed persistence leave server authority
                // pending. Yield between active retries; never retire on a
                // finite retry budget or enqueue an unanswered save twice.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // A lost transport leaves the persisted intent for reconnect.
            Err(_) => return None,
        }
    }
}

/// Exact acknowledged public identity; only durable host Ack may advance its monotonic expiry cap.
#[derive(Clone)]
pub(crate) struct AuthorityGuard {
    store: EnrollmentStore,
    provisioning_owner: Option<String>,
    /// A revoked certificate can carry only this retained durable cleanup.
    cleanup_person: Option<Uuid>,
    /// Set only for a root upgrade's successor (J415 R1, R2): admitted by its
    /// own check, never published as the host, and limited to proof calls
    /// (or, once abandoned, to uninstalling itself).
    successor: Option<crate::enrollment::promotion::SuccessorAuthority>,
    pub(crate) identity: HostAuthority,
    signal: Arc<Revocation>,
    certificate: Arc<watch::Sender<Admission>>,
}
#[derive(Clone)]
struct Admission {
    fingerprint: [u8; 32],
    identity: HostAuthority,
    expires: Instant,
}
impl AuthorityGuard {
    pub(crate) async fn admit(store: EnrollmentStore, fingerprint: [u8; 32]) -> io::Result<Self> {
        let admitted = Instant::now();
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let now = i64::try_from(elapsed.as_secs()).map_err(io::Error::other)?;
        let identity = store.admit(&fingerprint, now).await.map_err(|_| denied())?;
        let signal = store.1.register(identity.host, identity.execution_uid)?;
        // Register before the final ledger read, so revocation racing initial
        // admission either denies that read or marks the already registered guard.
        let live = store.admit(&fingerprint, now).await.map_err(|_| denied())?;
        if live != identity || *signal.changed.borrow() {
            return Err(denied());
        }
        let remaining_at_admission =
            Duration::from_secs(u64::try_from(identity.not_after).map_err(|_| denied())?)
                .checked_sub(elapsed)
                .ok_or_else(denied)?;
        let initial_deadline = admitted
            .checked_add(remaining_at_admission)
            .ok_or_else(denied)?;
        let monotonic = Instant::now();
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let lifetime =
            Duration::from_secs(u64::try_from(identity.not_after).map_err(|_| denied())?)
                .checked_sub(elapsed)
                .ok_or_else(denied)?;
        // A wall-clock rollback during admission cannot extend the original cap.
        let expires = monotonic
            .checked_add(lifetime)
            .ok_or_else(denied)?
            .min(initial_deadline);
        Ok(Self {
            store,
            provisioning_owner: None,
            cleanup_person: None,
            successor: None,
            certificate: Arc::new(
                watch::channel(Admission {
                    fingerprint,
                    identity: identity.clone(),
                    expires,
                })
                .0,
            ),
            identity,
            signal,
        })
    }

    /// Admit ordinary authority, or a bounded cleanup-only reconnect when its
    /// durable server outbox is still unconfirmed. Never publish the latter as a host.
    pub(crate) async fn admit_transport(
        store: EnrollmentStore,
        fingerprint: [u8; 32],
    ) -> io::Result<Self> {
        if let Ok(authority) = Self::admit(store.clone(), fingerprint).await {
            return Ok(authority);
        }
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let now = i64::try_from(elapsed.as_secs()).map_err(io::Error::other)?;
        if let Ok(successor) = store.admit_successor(&fingerprint, now).await {
            return Self::successor(store, successor, elapsed, now).await;
        }
        let (identity, person) = store
            .admit_cleanup(&fingerprint, now)
            .await
            .map_err(|_| denied())?;
        let signal = store.1.register_cleanup(identity.host)?;
        let live = store
            .admit_cleanup(&fingerprint, now)
            .await
            .map_err(|_| denied())?;
        if live.0 != identity || live.1 != person || *signal.changed.borrow() {
            return Err(denied());
        }
        let lifetime =
            Duration::from_secs(u64::try_from(identity.not_after).map_err(|_| denied())?)
                .checked_sub(elapsed)
                .ok_or_else(denied)?
                .min(Duration::from_secs(300));
        Ok(Self {
            store,
            provisioning_owner: None,
            cleanup_person: Some(person),
            successor: None,
            identity: identity.clone(),
            signal,
            certificate: Arc::new(
                watch::channel(Admission {
                    fingerprint,
                    identity,
                    expires: Instant::now() + lifetime,
                })
                .0,
            ),
        })
    }

    /// Only the private cleanup path may consume this person; ordinary admission refuses it.
    pub(crate) fn cleanup_person(&self) -> Option<Uuid> {
        self.cleanup_person
    }

    /// A root upgrade's successor, admitted for its promotion only (J415 R1).
    ///
    /// Its signal is the host's root epoch, `(host, 0)`, which the handover's
    /// cut of the rootless epoch leaves alone, and which host removal cuts
    /// with every other epoch (R2). Its lifetime ends with the promotion's
    /// deadline (or its certificate, for an uninstall).
    async fn successor(
        store: EnrollmentStore,
        successor: crate::enrollment::promotion::SuccessorAuthority,
        elapsed: Duration,
        now: i64,
    ) -> io::Result<Self> {
        let lifetime =
            Duration::from_secs(u64::try_from(successor.not_after).map_err(|_| denied())?)
                .checked_sub(elapsed)
                .ok_or_else(denied)?;
        let signal = store.1.register(successor.host, 0)?;
        // Forget can end the promotion's cleanup between the initial lookup
        // and registration. Check again with the signal already pinned.
        let live = store
            .admit_successor(&successor.fingerprint, now)
            .await
            .map_err(|_| denied())?;
        if live != successor || *signal.changed.borrow() {
            return Err(denied());
        }
        let identity = HostAuthority {
            host: successor.host,
            mode: crate::enrollment::Mode::Rootful,
            execution_uid: 0,
            not_after: successor.not_after,
        };
        Ok(Self {
            store,
            provisioning_owner: None,
            cleanup_person: None,
            certificate: Arc::new(
                watch::channel(Admission {
                    fingerprint: successor.fingerprint,
                    identity: identity.clone(),
                    expires: Instant::now() + lifetime,
                })
                .0,
            ),
            successor: Some(successor),
            identity,
            signal,
        })
    }

    /// The successor this guard admitted, if it is one. Only the private
    /// successor path in the runtime consumes it; the host registry refuses it.
    pub(crate) fn successor_authority(
        &self,
    ) -> Option<&crate::enrollment::promotion::SuccessorAuthority> {
        self.successor.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&self) {
        self.certificate
            .send_modify(|admission| admission.expires = Instant::now());
    }

    /// SSH publication is admitted by exact pending host ownership, never by
    /// a fabricated certificate. Only the trusted bootstrap backend calls this.
    #[cfg(feature = "ssh")]
    pub(crate) async fn provisioning(
        store: EnrollmentStore,
        owner: &str,
        host: Uuid,
        uid: u32,
    ) -> io::Result<Self> {
        let row: Option<(String, i64)> = sqlx::query_as("SELECT mode,execution_uid FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=remote_hosts.id AND q.confirmed=0) AND EXISTS(SELECT 1 FROM remote_bootstrap_retirement_intents WHERE host_id=remote_hosts.id)")
            .bind(host.as_bytes().as_slice()).bind(owner).fetch_optional(&store.0).await.map_err(|_| denied())?;
        let (mode, execution_uid) = row.ok_or_else(denied)?;
        if execution_uid != i64::from(uid) {
            return Err(denied());
        }
        let mode = match mode.as_str() {
            "rootful" => crate::enrollment::Mode::Rootful,
            "rootless" => crate::enrollment::Mode::Rootless,
            _ => return Err(denied()),
        };
        let identity = HostAuthority {
            host,
            mode,
            execution_uid: uid,
            not_after: 0,
        };
        let signal = store.1.register(host, uid)?;
        if *signal.changed.borrow() {
            return Err(denied());
        }
        Ok(Self {
            store,
            provisioning_owner: Some(owner.to_owned()),
            cleanup_person: None,
            successor: None,
            signal,
            certificate: Arc::new(
                watch::channel(Admission {
                    // This slot is never read as certificate authority on SSH.
                    fingerprint: [0; 32],
                    identity: identity.clone(),
                    // A failed setup must keep its shell usable. Worker admission has
                    // its separate 180-second bound; the retained transport uses
                    // the browser lifetime ceiling and immediate host revocation.
                    expires: Instant::now() + Duration::from_hours(30 * 24),
                })
                .0,
            ),
            identity,
        })
    }

    pub(crate) fn installed(&self) -> bool {
        self.provisioning_owner.is_none()
    }

    /// Bind only after this exact host's actor has been admitted; weak routing
    /// preserves the existing retirement ownership and registry memory bound.
    pub(crate) fn bind_login_actor(&self, actor: &crate::embedded::EmbeddedAgent) {
        *self
            .signal
            .login_actor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(actor.downgrade());
    }

    pub(crate) fn permits(&self) -> bool {
        !*self.signal.changed.borrow() && Instant::now() < self.certificate.borrow().expires
    }

    /// A frame holds this permit until its write completes or cancellation
    /// drops it. Revocation drains these permits before committing its tombstone.
    pub(crate) async fn write_permit(&self) -> io::Result<tokio::sync::OwnedRwLockReadGuard<()>> {
        if !self.permits() {
            return Err(denied());
        }
        let permit = self.signal.writes.clone().read_owned().await;
        if !self.permits() {
            return Err(denied());
        }
        Ok(permit)
    }

    pub(crate) async fn cancelled(&self) {
        let mut changed = self.signal.changed.subscribe();
        let mut certificate = self.certificate.subscribe();
        loop {
            let expires = certificate.borrow_and_update().expires;
            if !self.permits() {
                return;
            }
            tokio::select! {
                biased;
                _ = changed.changed() => return,
                _ = certificate.changed() => {},
                () = tokio::time::sleep_until(expires) => {
                    if !self.permits() { return; }
                },
            }
        }
    }

    pub(crate) fn store(&self) -> EnrollmentStore {
        self.store.clone()
    }
    /// The admitted host's ID.
    pub(crate) fn host_id(&self) -> Uuid {
        self.identity.host
    }
    pub(crate) fn predecessor(&self) -> [u8; 32] {
        self.certificate.borrow().fingerprint
    }
    pub(crate) fn renewal_deadline(&self) -> Instant {
        // Issued leaves have exactly seven days; half-life is three and a half.
        self.certificate
            .borrow()
            .expires
            .checked_sub(Duration::from_hours(84))
            .unwrap_or_else(Instant::now)
    }
    pub(crate) async fn acknowledge(&self, fingerprint: [u8; 32]) -> io::Result<()> {
        // A successor never renews: its promotion is far shorter than a week.
        if self.successor.is_some() || !self.permits() {
            return Err(denied());
        }
        let fresh = Self::admit(self.store.clone(), fingerprint).await?;
        if fresh.identity.host != self.identity.host
            || fresh.identity.mode != self.identity.mode
            || fresh.identity.execution_uid != self.identity.execution_uid
            || !self.permits()
        {
            return Err(denied());
        }
        let admission = fresh.certificate.borrow().clone();
        self.certificate.send_replace(admission);
        Ok(())
    }

    /// New operations recheck the public ledger; streaming bytes use only the
    /// event/deadline guard. A caller holding an old actor cannot bypass expiry.
    pub(crate) async fn admit_operation(&self) -> io::Result<()> {
        if self.cleanup_person.is_some() || !self.permits() {
            return Err(denied());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let now = i64::try_from(now.as_secs()).map_err(io::Error::other)?;
        if let Some(successor) = &self.successor {
            // A successor's operations recheck its own admission: the same
            // promotion and purpose, still live (abandonment or the handover
            // end it at once).
            let live = tokio::time::timeout(
                Duration::from_secs(5),
                self.store.admit_successor(&successor.fingerprint, now),
            )
            .await
            .map_err(|_| denied())?
            .map_err(|_| denied())?;
            return if live.attempt == successor.attempt
                && live.purpose == successor.purpose
                && self.permits()
            {
                Ok(())
            } else {
                Err(denied())
            };
        }
        if let Some(owner) = &self.provisioning_owner {
            let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND execution_uid=? AND revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=remote_hosts.id AND q.confirmed=0))")
                .bind(self.identity.host.as_bytes().as_slice()).bind(owner).bind(i64::from(self.identity.execution_uid))
                .fetch_one(&self.store.0).await.map_err(|_| denied())?;
            return if live && self.permits() {
                Ok(())
            } else {
                Err(denied())
            };
        }
        let admitted = self.certificate.borrow().clone();
        let live = tokio::time::timeout(
            Duration::from_secs(5),
            self.store.admit(&admitted.fingerprint, now),
        )
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
        if live != admitted.identity || !self.permits() {
            return Err(denied());
        }
        Ok(())
    }
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

#[cfg(test)]
#[path = "login_revocation_tests.rs"]
mod login_revocation_tests;

#[cfg(test)]
mod cut_tests {
    //! A storage refusal cannot make transport retirement disappear on reconnect.
    use super::*;

    /// A host-wide cut outlives its last transport: every epoch that
    /// registers before the tombstone starts cancelled.
    #[test]
    fn cancellation_survives_last_transport_until_durable_tombstone() {
        let revocations = Revocations::default();
        let host = Uuid::new_v4();
        drop(revocations.cut(host).unwrap());
        let reconnect = revocations.register(host, 1000).unwrap();
        assert!(*reconnect.changed.borrow());
        // Every epoch of a removed host starts cancelled, root included.
        assert!(*revocations.register(host, 0).unwrap().changed.borrow());
        revocations.tombstoned(host);
        drop(reconnect);
        let cuts = revocations.cuts.lock().unwrap();
        assert!(cuts.hosts.is_empty() && cuts.epochs.is_empty());
    }

    /// J415 R2: the handover cuts the rootless epoch only. The root
    /// successor's signal, on the same host, stays live, and a fresh rootless
    /// registration stays cancelled until that epoch's end is durable.
    /// Device links fill their own list: at its cap new devices wait, but a
    /// host (a reconnect after a restart, a root-upgrade handover) still
    /// registers, and a host's removal still cuts its device signal (#580).
    #[test]
    fn full_device_signals_do_not_lock_out_hosts() {
        let revocations = Revocations::default();
        let device = crate::remote_device_link::DEVICE_EPOCH_UID;
        let held: Vec<_> = (0..10_000u128)
            .map(|n| {
                revocations
                    .register(Uuid::from_u128(n + 1), device)
                    .unwrap()
            })
            .collect();
        assert!(
            revocations
                .register(Uuid::from_u128(99_999), device)
                .is_err()
        );
        let host = Uuid::from_u128(0xabc);
        let signal = revocations.register(host, 1000).unwrap();
        assert!(revocations.register(host, 0).is_ok());
        let device_signal = &held[0];
        let cut = revocations.cut(Uuid::from_u128(1)).unwrap();
        assert!(*device_signal.changed.borrow());
        assert!(!*signal.changed.borrow());
        drop(cut);
    }

    #[test]
    fn an_epoch_cut_leaves_the_hosts_other_epoch_live() {
        let revocations = Revocations::default();
        let host = Uuid::new_v4();
        let rootless = revocations.register(host, 1000).unwrap();
        let root = revocations.register(host, 0).unwrap();
        let _cut = revocations.cut_epoch(host, 1000).unwrap();
        assert!(*rootless.changed.borrow());
        assert!(!*root.changed.borrow());
        drop(rootless);
        assert!(*revocations.register(host, 1000).unwrap().changed.borrow());
        revocations.tombstoned_epoch(host, 1000);
        assert!(!*revocations.register(host, 0).unwrap().changed.borrow());
        // A host-wide cut reaches the root epoch too.
        let _removal = revocations.cut(host).unwrap();
        assert!(*root.changed.borrow());
    }
    #[cfg(feature = "ssh")]
    #[tokio::test]
    async fn provisional_ssh_authority_requires_exact_pending_owner_and_uid() {
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        assert!(
            AuthorityGuard::provisioning(store.clone(), "owner", host, 1002)
                .await
                .is_err()
        );
        sqlx::query("INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES(?)")
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            AuthorityGuard::provisioning(store.clone(), "foreign", host, 1002)
                .await
                .is_err()
        );
        assert!(
            AuthorityGuard::provisioning(store.clone(), "owner", host, 0)
                .await
                .is_err()
        );
        let guard = AuthorityGuard::provisioning(store.clone(), "owner", host, 1002)
            .await
            .unwrap();
        assert!(!guard.installed());
        assert!(guard.permits());
        guard.admit_operation().await.unwrap();
        store.revoke("owner", host, 2_000_000_000).await.unwrap();
        assert!(!guard.permits());
        assert!(guard.admit_operation().await.is_err());
        guard.cancelled().await;
        assert!(
            AuthorityGuard::provisioning(store, "owner", host, 1002)
                .await
                .is_err()
        );
    }
}
