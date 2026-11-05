//! Retains bounded per-person login refusals independently of ordinary saves.
//!
//! One registry owns at most eighteen accepted people and one retry worker.
//! Duplicate requests share a receipt. A full security queue returns busy before
//! retaining another intent or opening descriptors; the authoritative server
//! keeps that person's durable intent unconfirmed and retries. Unrelated people
//! remain permitted. Accepted work survives caller cancellation and retries until
//! durable. Idle registries retain no worker, descriptors or retry timer.
use super::{Manager, Path, PathBuf, io};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, LazyLock, Mutex, Weak},
};
use tokio::sync::watch;

/// Bound security intent metadata independently of the ordinary disk queue.
pub(super) const CAPACITY: usize = 18;
/// Errors are copied for finite callers while the original intent keeps retrying.
type Reply = Result<(), (io::ErrorKind, String)>;
/// A shared receipt completes on durability or reports an error without dropping intent.
type Receipt = watch::Sender<Option<Reply>>;

/// One person's retained refusal, including the host cleanup mode and shared receipt.
#[derive(Clone)]
struct Intent {
    /// Host manager used for the matching login cleanup.
    manager: Manager,
    /// Rootless cleanup shares the admission through its final directory sync.
    rootless: bool,
    /// Callers can leave without cancelling the authority transition.
    reply: Receipt,
}

/// Mutable bounded state for one configured private login registry.
#[derive(Default)]
struct State {
    /// Includes the currently executing person so duplicate requests coalesce.
    pending: HashMap<uuid::Uuid, Intent>,
    /// Failed people go to the back, allowing unrelated security work to progress.
    queue: VecDeque<uuid::Uuid>,
    /// Submission starts exactly one owner before yielding to the runtime.
    running: bool,
}

/// One configured state root, never a root supplied by a remote request.
struct Registry {
    /// Identifies the same authority directory used by open, restore and revoke.
    root: PathBuf,
    /// Short synchronous sections publish denial before any await.
    state: Mutex<State>,
}

/// Weak entries avoid retaining finished test or retired configuration roots.
static REGISTRIES: LazyLock<Mutex<HashMap<PathBuf, Weak<Registry>>>> =
    LazyLock::new(Mutex::default);

/// Find retained denial without creating state during ordinary login checks.
pub(super) fn denied(root: &Path, person: uuid::Uuid) -> bool {
    let registries = REGISTRIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registries
        .get(root)
        .and_then(Weak::upgrade)
        .is_some_and(|registry| {
            let state = registry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.pending.contains_key(&person)
        })
}

/// Record denial synchronously, then wait on a shared result rather than owning disk work.
/// A failed persistence attempt reports its error but remains queued for retry.
pub(super) async fn submit(
    root: &Path,
    manager: Manager,
    person: uuid::Uuid,
    rootless: bool,
) -> io::Result<()> {
    let registry = {
        let mut registries = REGISTRIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registries.retain(|_, value| value.strong_count() != 0);
        if let Some(registry) = registries.get(root).and_then(Weak::upgrade) {
            registry
        } else {
            let registry = Arc::new(Registry {
                root: root.to_owned(),
                state: Mutex::default(),
            });
            registries.insert(root.to_owned(), Arc::downgrade(&registry));
            registry
        }
    };
    let (mut receipt, start) = {
        let mut state = registry
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let receipt = if let Some(intent) = state.pending.get(&person) {
            intent.reply.subscribe()
        } else {
            if state.pending.len() == CAPACITY {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "security write queue is busy",
                ));
            }
            let (reply, receipt) = watch::channel(None);
            let intent = Intent {
                manager,
                rootless,
                reply,
            };
            state.pending.insert(person, intent);
            state.queue.push_back(person);
            receipt
        };
        let start = !state.running;
        state.running = true;
        (receipt, start)
    };
    if start {
        // Detach only the single bounded owner; leaving a receipt cannot cancel refusal.
        drop(tokio::spawn(run(registry)));
    }
    loop {
        let result = receipt.borrow_and_update().clone();
        if let Some(result) = result {
            return result.map_err(|(kind, message)| io::Error::new(kind, message));
        }
        receipt.changed().await.map_err(io::Error::other)?;
    }
}

/// Drain retained refusals on reserved capacity; failed attempts rotate and retry.
/// The owner holds the registry until refusal and cleanup are durable, even when
/// every receipt has been dropped or all finite callers have exhausted retries.
async fn run(registry: Arc<Registry>) {
    loop {
        let work = {
            let mut state = registry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(person) = state.queue.pop_front() {
                state
                    .pending
                    .get(&person)
                    .cloned()
                    .map(|intent| (person, intent))
            } else {
                state.running = false;
                None
            }
        };
        let Some((person, intent)) = work else {
            return;
        };
        let result =
            super::revoke_once(&registry.root, intent.manager, person, intent.rootless).await;
        let failed = result.is_err();
        // Remove a completed intent before waking callers: an immediate explicit
        // restoration must observe completed cleanup. Disk is already durable.
        {
            let mut state = registry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if failed {
                state.queue.push_back(person);
            } else {
                state.pending.remove(&person);
            }
        }
        intent.reply.send_replace(Some(
            result.map_err(|error| (error.kind(), error.to_string())),
        ));
        if failed {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// Count retained security intents so flood tests observe the real owner queue.
#[cfg(test)]
pub(super) fn retained(root: &Path) -> usize {
    let registries = REGISTRIES.lock().unwrap();
    registries
        .get(root)
        .and_then(Weak::upgrade)
        .map_or(0, |registry| {
            let state = registry.state.lock().unwrap();
            state.pending.len()
        })
}
