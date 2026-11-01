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
    peak: Arc<AtomicUsize>,
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
        let count = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(count, Ordering::SeqCst);
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

/// Private real control-socket state, kept outside the checkout.
struct StateDirectory(std::path::PathBuf);
impl StateDirectory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let parent = crate::test_state_root().join("agent-reconnect-review");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join(format!(
            "r1-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for StateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type PluginFactory = Arc<dyn Fn() -> Result<PluginRegistry, PluginError> + Send + Sync>;
const TEST_LIMIT: Duration = Duration::from_secs(2);

/// Drive the actual enrollment runner and Service lifetime, rather than copying
/// its attempt factory. The held listener cannot accidentally contact another job.
fn enrolled(
    factory: PluginFactory,
    state: std::path::PathBuf,
) -> tokio::task::JoinHandle<io::Result<()>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ca = crate::remote_tls::tests::root();
    let identity = crate::remote_client::RemoteIdentity {
        host_id: uuid::Uuid::new_v4(),
        identity: crate::remote_tls::tests::leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: Some(listener.local_addr().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    tokio::spawn(crate::plugin_control::TEST_FACTORY.scope(
        factory,
        TEST_OFFLINE_LIMIT.scope(TEST_LIMIT, async move {
            let _listener = listener;
            crate::remote_client::run(&identity, Some(state)).await
        }),
    ))
}

#[tokio::test]
async fn watchdog_bounds_workers_when_local_path_discovery_stalls() {
    let directory = StateDirectory::new();
    let release = Arc::new(Release::default());
    let cleanup = Cleanup(release.clone());
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let observed = peak.clone();
    let (started, entry) = mpsc::channel();
    let (finished, completions) = mpsc::channel();
    let task = enrolled(
        Arc::new(move || {
            let mut plugins = PluginRegistry::default();
            plugins.register(Box::new(WaitingComponent {
                release: release.clone(),
                active: active.clone(),
                peak: peak.clone(),
                started: started.clone(),
                finished: finished.clone(),
            }))?;
            Ok(plugins)
        }),
        directory.0.clone(),
    );
    tokio::task::yield_now().await;
    entry.recv_timeout(Duration::from_secs(30)).unwrap();
    for _ in 0..2 {
        tokio::time::sleep(TEST_LIMIT + Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
    }
    task.abort();
    let _ = task.await;
    drop(cleanup);
    tokio::task::yield_now().await;
    // All factory/worker sender clones close after the real Service and listener
    // are cancelled. Drain to disconnection, including workers scheduled late.
    loop {
        match completions.recv_timeout(Duration::from_secs(30)) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(error) => panic!("worker cleanup did not complete: {error:?}"),
        }
    }
    let retained = observed.load(Ordering::SeqCst);
    assert!(
        retained <= 1,
        "offline recovery retained {retained} synchronous workers; local work must stay bounded"
    );
}

#[tokio::test(start_paused = true)]
async fn six_hour_server_outage_keeps_one_retry_owner_with_bounded_attempts() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = attempts.clone();
    let result = tokio::time::timeout(
        Duration::from_hours(6),
        run(move |_| {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err(io::ErrorKind::ConnectionRefused.into()) }
        }),
    )
    .await;
    assert!(
        result.is_err(),
        "server downtime must not return to the service manager"
    );
    let count = observed.load(Ordering::SeqCst);
    println!("virtual_outage_seconds=21600 attempts={count} service_returned=false");
    // Six hours at a 30-second cap gives 720 attempts, plus startup and
    // watchdog boundaries. This is a virtual-clock correctness assertion.
    assert!(
        (720..850).contains(&count),
        "unexpected retry count: {count}"
    );
}

#[cfg(all(feature = "mesh", target_os = "linux"))]
mod durable_state {
    //! Exercises acknowledged public intent against a superseded callback using the real state store and local socket.
    use super::*;
    use infraternal_plugin_api::{ActionDef, Effect, SchemaRef};
    use infraternal_plugin_mesh::{
        dataplane::{Config, DefaultPolicy},
        node_state::{State, Store},
        policy::model::{Addresses, NodeId},
    };
    use std::sync::atomic::AtomicBool;

    const REPLACE: ActionDef = ActionDef {
        id: "review.replace",
        summary: "Replace fixture network access",
        input: SchemaRef("Empty"),
        output: SchemaRef("Empty"),
        effect: Effect::Write,
        instructions: &["Replace the fixture's public network access."],
        permission: infraternal_plugin_api::Permission::One("review.replace"),
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
    };
    const SPEC: PluginDescriptor = PluginDescriptor {
        actions: &[REPLACE],
        ..DESCRIPTOR
    };

    struct Restore {
        path: std::path::PathBuf,
        first: AtomicBool,
        release: Arc<Release>,
        entered: mpsc::Sender<()>,
        restored: mpsc::Sender<bool>,
        finished: mpsc::Sender<()>,
    }
    impl AgentPlugin for Restore {
        fn descriptor(&self) -> &'static PluginDescriptor {
            &SPEC
        }
        fn preferred_server(&self) -> Option<std::net::IpAddr> {
            if self.first.swap(false, Ordering::SeqCst) {
                // Node restore reads retained intent before publishing/replaying
                // it. Pause at that boundary, retaining the actual Store snapshot.
                let (store, snapshot) = Store::open(&self.path).unwrap();
                self.entered.send(()).unwrap();
                let mut open = self.release.open.lock().unwrap();
                while !*open {
                    open = self.release.changed.wait(open).unwrap();
                }
                let committed = store.save(&snapshot).is_ok();
                self.restored.send(committed).unwrap();
            }
            None
        }
        fn call(&mut self, action: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
            if action != REPLACE.id || input != b"{}" {
                return Err(PluginError::Rejected);
            }
            let (store, mut current) = Store::open(&self.path).unwrap();
            let config = current.config.as_mut().unwrap();
            config.version = 2;
            config.default_policy = DefaultPolicy::Deny;
            store.save(&current).map_err(|_| PluginError::Rejected)?;
            Ok(b"{}".to_vec())
        }
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = self.finished.send(());
        }
    }

    #[tokio::test]
    async fn acknowledged_network_access_survives_superseded_worker_completion() {
        let directory = StateDirectory::new();
        let (store, _) = Store::open(&directory.0).unwrap();
        store
            .save(&State {
                enabled: true,
                config: Some(Config {
                    local_key: None,
                    server: None,
                    node: NodeId(1),
                    version: 1,
                    addresses: Addresses {
                        ipv4: "10.254.0.1".parse().unwrap(),
                        ipv6: "fd01::1".parse().unwrap(),
                    },
                    default_policy: DefaultPolicy::Allow,
                    peers: std::collections::BTreeMap::new(),
                }),
                backend: None,
            })
            .unwrap();
        let release = Arc::new(Release::default());
        let cleanup = Cleanup(release.clone());
        let attempts = AtomicUsize::new(0);
        let (entered, observed_start) = mpsc::channel();
        let (restored, prior_write) = mpsc::channel();
        let (finished, terminations) = mpsc::channel();
        let path = directory.0.clone();
        let task = enrolled(
            Arc::new(move || {
                let mut plugins = PluginRegistry::default();
                plugins.register(Box::new(Restore {
                    path: path.clone(),
                    first: AtomicBool::new(attempts.fetch_add(1, Ordering::SeqCst) == 0),
                    release: release.clone(),
                    entered: entered.clone(),
                    restored: restored.clone(),
                    finished: finished.clone(),
                }))?;
                Ok(plugins)
            }),
            directory.0.clone(),
        );
        tokio::task::yield_now().await;
        observed_start
            .recv_timeout(Duration::from_secs(30))
            .unwrap();
        tokio::time::sleep(TEST_LIMIT + Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        let state = directory.0.clone();
        let mut change =
            tokio::spawn(
                async move { crate::plugin_control::call(&state, REPLACE.id, b"{}").await },
            );
        // A serialized owner may queue this call until the older callback ends.
        // A replacement owner can acknowledge it first; both must preserve it.
        let early = tokio::time::timeout(Duration::from_secs(1), &mut change).await;
        let accepted_before_release = matches!(&early, Ok(Ok(Ok(_))));
        drop(cleanup);
        let old_committed = prior_write.recv_timeout(Duration::from_secs(30)).unwrap();
        let result = match early {
            Ok(joined) => joined.unwrap(),
            Err(_) => tokio::time::timeout(Duration::from_secs(10), change)
                .await
                .unwrap()
                .unwrap(),
        };
        task.abort();
        let _ = task.await;
        tokio::task::yield_now().await;
        loop {
            match terminations.recv_timeout(Duration::from_secs(30)) {
                Ok(()) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(error) => panic!("state worker cleanup did not complete: {error:?}"),
            }
        }
        if result.is_ok() {
            let (_, persisted) = Store::open(&directory.0).unwrap();
            let config = persisted.config.unwrap();
            println!(
                "newer_ack_before_old_release={accepted_before_release} superseded_write_committed={old_committed} persisted_version={} persisted_access={:?}",
                config.version, config.default_policy
            );
            assert_eq!(
                config.version, 2,
                "an acknowledged newer intent was replaced by a superseded callback"
            );
            assert_eq!(config.default_policy, DefaultPolicy::Deny);
        }
    }
}

#[tokio::test]
async fn terminated_factory_is_replaced_without_overlapping_live_workers() {
    let directory = StateDirectory::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = attempts.clone();
    let started = Arc::new(tokio::sync::Notify::new());
    let ready = started.clone();
    let task = enrolled(
        Arc::new(move || {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(PluginError::Rejected);
            }
            ready.notify_one();
            Ok(PluginRegistry::default())
        }),
        directory.0.clone(),
    );
    tokio::time::timeout(Duration::from_secs(30), started.notified())
        .await
        .unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 2);
    assert!(!task.is_finished());
    task.abort();
    let _ = task.await;
    tokio::task::yield_now().await;
}
