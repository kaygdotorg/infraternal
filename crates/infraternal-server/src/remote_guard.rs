//! Cancels retained remote authority on durable revocation or certificate expiry, with ledger reads at admission rather than per keystroke [134], #78.

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
pub(crate) struct Revocations(Mutex<HashMap<Uuid, Weak<watch::Sender<bool>>>>);
impl Revocations {
    fn register(&self, host: Uuid) -> io::Result<Arc<watch::Sender<bool>>> {
        // This map contains only independent weak registrations; Rust containers
        // retain their invariants after unwinding, so poison can be recovered.
        let mut signals = self
            .0
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
        let signal = Arc::new(watch::channel(false).0);
        signals.insert(host, Arc::downgrade(&signal));
        Ok(signal)
    }

    pub(crate) fn revoke(&self, host: Uuid) {
        let signals = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(signal) = signals.get(&host).and_then(Weak::upgrade) {
            // Publish before the storage API returns. Readers and partially
            // blocked writes wake without a heartbeat or a database polling task.
            signal.send_replace(true);
        }
    }
}

/// Exact admitted public identity plus a monotonic, non-extending expiry cap.
#[derive(Clone)]
pub(crate) struct AuthorityGuard {
    store: EnrollmentStore,
    fingerprint: [u8; 32],
    pub(crate) identity: HostAuthority,
    signal: Arc<watch::Sender<bool>>,
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
        if live != identity || *signal.borrow() {
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
            fingerprint,
            identity,
            signal,
            expires,
        })
    }

    pub(crate) fn permits(&self) -> bool {
        !*self.signal.borrow() && Instant::now() < self.expires
    }

    pub(crate) async fn cancelled(&self) {
        let mut changed = self.signal.subscribe();
        if !self.permits() {
            return;
        }
        tokio::select! {
            biased;
            _ = changed.changed() => {},
            () = tokio::time::sleep_until(self.expires) => {},
        }
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
        let live = tokio::time::timeout(
            Duration::from_secs(5),
            self.store.admit(&self.fingerprint, now),
        )
        .await
        .map_err(|_| denied())?
        .map_err(|_| denied())?;
        if live != self.identity || !self.permits() {
            return Err(denied());
        }
        Ok(())
    }
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
