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
/// retain transports, and dead host registrations are pruned at the host cap.
#[derive(Default)]
pub(crate) struct Revocations {
    signals: Mutex<HashMap<Uuid, Weak<Revocation>>>,
    // Storage refusal must not let the last transport drop the cancellation
    // signal and permit a reconnect. Successful tombstones release this hold.
    cuts: Mutex<HashMap<Uuid, Arc<Revocation>>>,
    pub(crate) plugins: Mutex<crate::plugins::WeakRuntime>,
    #[cfg(test)]
    pub(crate) publication_pause: Mutex<Option<Arc<PublicationPause>>>,
}
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
    changed: watch::Sender<bool>,
    writes: Arc<tokio::sync::RwLock<()>>,
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
    fn register(&self, host: Uuid) -> io::Result<Arc<Revocation>> {
        // This map contains only independent weak registrations; Rust containers
        // retain their invariants after unwinding, so poison can be recovered.
        let mut signals = self
            .signals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(signal) = signals.get(&host).and_then(Weak::upgrade) {
            return Ok(signal);
        }
        if signals.len() >= 10_000 {
            signals.retain(|_, signal| signal.strong_count() != 0);
            if signals.len() >= 10_000 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let signal = Arc::new(Revocation {
            changed: watch::channel(false).0,
            writes: Arc::default(),
        });
        signals.insert(host, Arc::downgrade(&signal));
        Ok(signal)
    }

    pub(crate) async fn quiesce(
        &self,
        host: Uuid,
    ) -> io::Result<(Arc<Revocation>, tokio::sync::OwnedRwLockWriteGuard<()>)> {
        let signal = self.cut(host)?;
        let drained = signal.writes.clone().write_owned().await;
        Ok((signal, drained))
    }

    /// Fence new writes before waiting for SQLite's writer slot. The caller
    /// retains the signal until the durable tombstone has committed, so a
    /// reconnect cannot allocate an uncancelled registration in that gap.
    pub(crate) fn cut(&self, host: Uuid) -> io::Result<Arc<Revocation>> {
        let signal = self.register(host)?;
        let mut cuts = self
            .cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cuts.len() >= 10_000 && !cuts.contains_key(&host) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        cuts.insert(host, signal.clone());
        signal.changed.send_replace(true);
        Ok(signal)
    }

    pub(crate) fn tombstoned(&self, host: Uuid) {
        self.cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&host);
    }
}

/// Exact acknowledged public identity; only durable host Ack may advance its monotonic expiry cap.
#[derive(Clone)]
pub(crate) struct AuthorityGuard {
    store: EnrollmentStore,
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
        let signal = store.1.register(identity.host)?;
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
        if !self.permits() {
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
        if !self.permits() {
            return Err(denied());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let now = i64::try_from(now.as_secs()).map_err(io::Error::other)?;
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
mod cut_tests {
    //! A storage refusal cannot make transport retirement disappear on reconnect.
    use super::*;

    #[test]
    fn cancellation_survives_last_transport_until_durable_tombstone() {
        let revocations = Revocations::default();
        let host = Uuid::new_v4();
        drop(revocations.cut(host).unwrap());
        let reconnect = revocations.register(host).unwrap();
        assert!(*reconnect.changed.borrow());
        revocations.tombstoned(host);
        drop(reconnect);
        assert!(revocations.cuts.lock().unwrap().is_empty());
    }
}
