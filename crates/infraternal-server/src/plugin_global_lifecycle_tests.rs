//! Tests feature retirement of server-owned work without any browser socket [D104,D198,#146].
use super::*;
use infraternal_plugin_api::{Operation, PluginDescriptor, RoleDef};

static DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "global-probe",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[],
    topics: &[],
    settings: None,
    events: &[],
    streams: &[],
    defaults: &[],
    dependencies: &[],
    can_enable_components: &[],
    roles: &[RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: false,
    }],
    max_frame_len: 1024,
    unavailable: b"{}",
    unavailable_event: b"{}",
};
struct Probe {
    enabled: AtomicBool,
    stopping: watch::Sender<bool>,
    worker: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    finished: Arc<AtomicBool>,
}
impl Probe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(false),
            stopping: watch::channel(false).0,
            worker: tokio::sync::Mutex::new(None),
            finished: Arc::new(AtomicBool::new(false)),
        })
    }
    async fn start(&self) {
        assert!(self.enabled.load(Ordering::Acquire));
        let mut stopping = self.stopping.subscribe();
        let finished = self.finished.clone();
        *self.worker.lock().await = Some(tokio::spawn(async move {
            while !*stopping.borrow_and_update() {
                stopping.changed().await.unwrap();
            }
            finished.store(true, Ordering::Release);
        }));
    }
}
impl Plugin for Probe {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn configure(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        self.stopping.send_replace(!enabled);
    }
    fn stopped(&self) -> Operation<'_, ()> {
        Box::pin(async {
            if let Some(worker) = self.worker.lock().await.take() {
                worker.await.unwrap();
            }
        })
    }
    fn run(
        &self,
        _: Arc<dyn SocketHost>,
        _: mpsc::Receiver<Bytes>,
        _: ReplySender,
        _: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        Box::pin(async {})
    }
}
#[tokio::test]
async fn disable_joins_global_work_without_any_socket_and_reenable_is_lazy() {
    let probe = Probe::new();
    let runtime = PluginRuntime::new(vec![probe.clone()], "server");
    assert!(!probe.enabled.load(Ordering::Acquire));
    assert!(probe.worker.lock().await.is_none());
    runtime.set_enabled("global-probe", true).await.unwrap();
    probe.start().await;
    runtime.set_enabled("global-probe", false).await.unwrap();
    assert!(!probe.enabled.load(Ordering::Acquire));
    assert!(probe.finished.load(Ordering::Acquire));
    assert!(probe.worker.lock().await.is_none());
    runtime.set_enabled("global-probe", true).await.unwrap();
    assert!(probe.worker.lock().await.is_none());
    drop(runtime);
    assert!(!probe.enabled.load(Ordering::Acquire));
}
#[tokio::test]
async fn restored_settings_configure_plugin_before_admission() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO plugin_settings(role,plugin,enabled) VALUES ('server','global-probe',1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let probe = Probe::new();
    let runtime = PluginRuntime::new(vec![probe.clone()], "server")
        .with_store(pool.clone())
        .await
        .unwrap();
    assert!(probe.enabled.load(Ordering::Acquire));
    assert!(probe.worker.lock().await.is_none());
    probe.start().await;
    drop(runtime);
    probe.stopped().await;
    assert!(probe.finished.load(Ordering::Acquire));
    pool.close().await;
}

#[tokio::test]
async fn compiled_desktop_is_optional_and_defaults_disabled() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let runtime = compiled(&pool).await.unwrap();
    let listing = runtime.list();
    let desktop = listing["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|plugin| plugin["descriptor"]["id"] == "desktop");
    assert_eq!(desktop.is_some(), cfg!(feature = "desktop"));
    if let Some(desktop) = desktop {
        assert_eq!(desktop["enabled"], false);
        runtime.set_enabled("desktop", true).await.unwrap();
        runtime.set_enabled("desktop", false).await.unwrap();
    }
    drop(runtime);
    pool.close().await;
}

#[cfg(feature = "desktop")]
#[test]
fn browser_desktop_capability_does_not_advertise_the_native_transport_bit() {
    let runtime = PluginRuntime::new(
        vec![Arc::new(
            infraternal_plugin_desktop::server::DesktopServer::new(1),
        )],
        "server",
    );
    assert_eq!(
        runtime.wire_capabilities(),
        infraternal_protocol::desktop::CAPABILITY
    );
    assert_eq!(
        infraternal_plugin_desktop::wire::WIRE.capability,
        infraternal_protocol::desktop::NATIVE_CAPABILITY
    );
}
