//! Causal checks for stalled disk writes on the current-thread host reactor.
//!
//! Thread identity rejects a durable write on the reactor without a disk-speed
//! deadline. Off-reactor writes remain held until unrelated reactor work answers;
//! admission delays and filesystem contention cannot release that hold early.
use std::{
    collections::HashMap,
    future::Future,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// One write waits here until unrelated reactor work has answered.
struct Gate {
    /// The sole reactor thread of the current-thread test runtime.
    reactor: std::thread::ThreadId,
    /// Published before `entered` if the disk hook runs on that reactor.
    on_reactor: AtomicBool,
    /// The disk hook has either held a worker or detected an inline write.
    entered: AtomicBool,
    /// Only the reactor releases an off-reactor write after its causal checks.
    released: Mutex<bool>,
    /// Wake the held disk worker once unrelated reactor work has answered.
    changed: Condvar,
}

/// Release the worker and unregister its hook even if a causal assertion panics.
/// This owns cleanup separately from the worker's reference to the shared gate.
struct HeldWrite {
    /// The unique hook registration removed when this check ends.
    path: PathBuf,
    /// A worker may retain this gate until the reactor releases its write.
    gate: Arc<Gate>,
}

impl Drop for HeldWrite {
    /// Unwinding must never leave runtime shutdown waiting on a held disk worker.
    fn drop(&mut self) {
        *self.gate.released.lock().unwrap() = true;
        self.gate.changed.notify_all();
        GATES.lock().unwrap().remove(&self.path);
    }
}

/// Paths isolate simultaneously running tests from each other and ordinary saves.
static GATES: LazyLock<Mutex<HashMap<PathBuf, Arc<Gate>>>> = LazyLock::new(Mutex::default);

/// Make a private, unique state directory on the VM's real filesystem.
pub(crate) fn directory() -> PathBuf {
    let root = crate::test_state_root().join(uuid::Uuid::new_v4().simple().to_string());
    std::fs::create_dir(&root).unwrap();
    root
}

/// Stand in for a disk write that cannot finish until the reactor releases it.
pub(crate) fn hold(path: &Path) {
    let Some(gate) = GATES.lock().unwrap().get(path).cloned() else {
        return;
    };
    if std::thread::current().id() == gate.reactor {
        // Record the regression instead of deadlocking the only reactor thread.
        // The caller asserts this after releasing and joining the operation.
        gate.on_reactor.store(true, Ordering::Relaxed);
        gate.entered.store(true, Ordering::Release);
        return;
    }
    let mut released = gate.released.lock().unwrap();
    gate.entered.store(true, Ordering::Release);
    while !*released {
        released = gate.changed.wait(released).unwrap();
    }
}

/// Require another reactor task to answer before releasing the blocked save.
/// A write on the sole reactor thread fails by identity, not elapsed time.
/// Slow admission or unrelated disk work cannot masquerade as a held reactor.
pub(crate) async fn responsive<T: Send + 'static>(
    path: PathBuf,
    operation: impl Future<Output = T> + Send + 'static,
) -> T {
    check(path, operation, None).await.unwrap()
}

/// Cancel a held save and verify its person fence survives until the disk finishes.
pub(crate) async fn cancellation_keeps_fence<T: Send + 'static>(
    path: PathBuf,
    operation: impl Future<Output = T> + Send + 'static,
    lock: PathBuf,
) {
    let _ = check(path, operation, Some(lock)).await;
}

/// Exercise the common held-write ordering, optionally cancelling its caller.
async fn check<T: Send + 'static>(
    path: PathBuf,
    operation: impl Future<Output = T> + Send + 'static,
    cancel: Option<PathBuf>,
) -> Option<T> {
    assert_eq!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::CurrentThread,
        "durable write checks require a single reactor thread"
    );
    let gate = Arc::new(Gate {
        reactor: std::thread::current().id(),
        on_reactor: AtomicBool::new(false),
        entered: AtomicBool::new(false),
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    GATES.lock().unwrap().insert(path.clone(), gate.clone());
    let held_write = HeldWrite {
        path,
        gate: gate.clone(),
    };
    let save = tokio::spawn(operation);
    while !gate.entered.load(Ordering::Acquire) && !save.is_finished() {
        tokio::task::yield_now().await;
    }
    let held = !save.is_finished();
    let answer = tokio::spawn(async { "answered" }).await.unwrap();
    assert_eq!(answer, "answered");
    let fenced = if let Some(lock) = &cancel {
        save.abort();
        while !save.is_finished() {
            tokio::task::yield_now().await;
        }
        matches!(
            nix::fcntl::Flock::lock(
                std::fs::File::open(lock).unwrap(),
                nix::fcntl::FlockArg::LockExclusiveNonblock,
            ),
            Err((_, nix::errno::Errno::EWOULDBLOCK))
        )
    } else {
        true
    };
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    let result = save.await;
    drop(held_write);
    assert!(
        !gate.on_reactor.load(Ordering::Acquire),
        "durable write ran on the reactor thread"
    );
    assert!(
        held,
        "save must remain pending until the reactor releases its disk write"
    );
    assert!(
        fenced,
        "cancelled save released its person fence before disk completion"
    );
    if cancel.is_some() {
        assert!(matches!(result, Err(error) if error.is_cancelled()));
        None
    } else {
        Some(result.unwrap())
    }
}
