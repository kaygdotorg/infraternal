//! Causal checks for stalled disk writes on the current-thread host reactor.
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
#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
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
    let mut released = gate.released.lock().unwrap();
    gate.entered.store(true, Ordering::Release);
    while !*released {
        released = gate.changed.wait(released).unwrap();
    }
}

/// Require another reactor task to answer before releasing the blocked save.
/// The watchdog only frees a deadlocked test; no elapsed time determines success.
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
    let gate = Arc::new(Gate::default());
    GATES.lock().unwrap().insert(path.clone(), gate.clone());
    let watchdog = std::thread::spawn({
        let gate = gate.clone();
        move || {
            let (mut released, waited) = gate
                .changed
                .wait_timeout_while(
                    gate.released.lock().unwrap(),
                    std::time::Duration::from_secs(30),
                    |released| !*released,
                )
                .unwrap();
            *released = true;
            gate.changed.notify_all();
            waited.timed_out()
        }
    });
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
    let fired = watchdog.join().unwrap();
    GATES.lock().unwrap().remove(&path);
    assert!(
        !fired,
        "durable write held the reactor until the watchdog released it"
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
