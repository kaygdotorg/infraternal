//! Independent cancellation and prolonged-outage regressions for the enrolled link owner [128,198], #225.
use super::*;
use infraternal_plugin_api::{AgentPlugin, PluginDescriptor, PluginError, PluginRegistry};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "review",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[],
    topics: &[],
    settings: None,
    events: &[],
    streams: &[],
    defaults: &[],
    dependencies: &[],
    can_enable_components: &[],
    roles: &[],
    max_frame_len: infraternal_plugin_api::MAX_ACTION_BYTES,
    unavailable: b"{}",
    unavailable_event: b"{}",
};

/// A synchronous component may be waiting on local storage when its async
/// caller is cancelled. Always release the fixture, including assertion failures.
#[derive(Default)]
struct Release {
    open: Mutex<bool>,
    changed: Condvar,
}
impl Release {
    fn unblock(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
struct Cleanup(Arc<Release>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        self.0.unblock();
    }
}
struct WaitingComponent {
    release: Arc<Release>,
    active: Arc<AtomicUsize>,
    started: mpsc::Sender<()>,
    finished: mpsc::Sender<()>,
}
impl AgentPlugin for WaitingComponent {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::Rejected)
    }
    fn preferred_server(&self) -> Option<std::net::IpAddr> {
        self.active.fetch_add(1, Ordering::SeqCst);
        self.started.send(()).unwrap();
        let mut open = self.release.open.lock().unwrap();
        while !*open {
            open = self.release.changed.wait(open).unwrap();
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        None
    }
}
impl Drop for WaitingComponent {
    fn drop(&mut self) {
        let _ = self.finished.send(());
    }
}

#[tokio::test(start_paused = true)]
async fn watchdog_bounds_workers_when_local_path_discovery_stalls() {
    let release = Arc::new(Release::default());
    let cleanup = Cleanup(release.clone());
    let active = Arc::new(AtomicUsize::new(0));
    let observed = active.clone();
    let (started, starts) = mpsc::channel();
    let (finished, finishes) = mpsc::channel();
    let task = tokio::spawn(run(move |_| {
        let mut plugins = PluginRegistry::default();
        plugins
            .register(Box::new(WaitingComponent {
                release: release.clone(),
                active: active.clone(),
                started: started.clone(),
                finished: finished.clone(),
            }))
            .unwrap();
        let registry = crate::plugin_control::Registry::new(plugins);
        async move {
            registry
                .initialize_paths()
                .await
                .map_err(|_| io::ErrorKind::Other.into())
        }
    }));
    for index in 0..3 {
        tokio::task::yield_now().await;
        // The dedicated worker runs outside Tokio's virtual clock. Wait for
        // entry before advancing the actual production watchdog deadline.
        starts.recv_timeout(Duration::from_secs(5)).unwrap();
        if index < 2 {
            tokio::time::advance(OFFLINE_LIMIT + Duration::from_secs(1)).await;
        }
    }
    let retained = observed.load(Ordering::SeqCst);
    task.abort();
    let _ = task.await;
    drop(cleanup);
    for _ in 0..3 {
        finishes.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    assert!(
        retained <= 1,
        "offline recovery retained {retained} synchronous workers; local work must stay bounded"
    );
}
