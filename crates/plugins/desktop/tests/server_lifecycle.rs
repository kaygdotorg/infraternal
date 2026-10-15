//! Exercises server-generated preparation, ownership, viewer-independent retention and joined feature retirement [D104,D198,D208,#146].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_api::{
    Operation, Plugin,
    streams::{NodeHost, WireLane, WireStreamDef},
};
use infraternal_plugin_desktop::{
    protocol::{Size, Start, Target},
    server::DesktopServer,
    session::Error,
};
use infraternal_protocol::desktop::Delivery;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::Notify;
struct Host {
    live: AtomicBool,
    starts: AtomicUsize,
    stops: AtomicUsize,
    ids: Mutex<Vec<uuid::Uuid>>,
    pending: bool,
    fail_open: AtomicBool,
    starting: Notify,
    stopping: Notify,
    stop_gate: Mutex<Option<Arc<Notify>>>,
}
impl Host {
    fn new(pending: bool) -> Arc<Self> {
        Arc::new(Self {
            live: AtomicBool::new(true),
            starts: AtomicUsize::new(0),
            stops: AtomicUsize::new(0),
            ids: Mutex::new(Vec::new()),
            pending,
            fail_open: AtomicBool::new(false),
            starting: Notify::new(),
            stopping: Notify::new(),
            stop_gate: Mutex::new(None),
        })
    }
}
impl NodeHost for Host {
    fn id(&self) -> &'static str {
        "enrolled-host"
    }
    fn owner_id(&self) -> &'static str {
        "owner"
    }
    fn permits(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            if !self.permits() {
                return Err(());
            }
            operation.await
        })
    }
    fn call<'a>(&'a self, action: &'a str, input: &'a [u8]) -> Operation<'a, Result<Vec<u8>, ()>> {
        Box::pin(async move {
            let input: serde_json::Value = serde_json::from_slice(input).unwrap();
            let id: uuid::Uuid = serde_json::from_value(input["session_id"].clone()).unwrap();
            match action {
                "desktop.source.start" => {
                    self.ids.lock().unwrap().push(id);
                    self.starts.fetch_add(1, Ordering::Relaxed);
                    self.starting.notify_one();
                    if self.pending {
                        std::future::pending::<()>().await;
                    }
                }
                "desktop.source.stop" => {
                    let _ = id;
                    self.stops.fetch_add(1, Ordering::Relaxed);
                    let gate = self.stop_gate.lock().unwrap().clone();
                    self.stopping.notify_one();
                    if let Some(gate) = gate {
                        gate.notified().await;
                    }
                }
                _ => return Err(()),
            }
            Ok(serde_json::to_vec(&serde_json::json!({"session_id":id})).unwrap())
        })
    }
    fn open<'a>(
        &'a self,
        _: &'static WireStreamDef,
        _: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>> {
        Box::pin(async move {
            if self.fail_open.load(Ordering::Acquire) {
                Err(())
            } else {
                std::future::pending().await
            }
        })
    }
}
fn request() -> Start {
    Start {
        target: Target::Window {
            window_id: 9,
            owner_pid: 42,
        },
        size: Size {
            width: 960,
            height: 600,
            canvas_width: 480.0,
            canvas_height: 300.0,
            backing_scale: 2.0,
        },
    }
}
#[tokio::test]
async fn disabled_start_and_foreign_stop_never_invoke_native_work() {
    let host = Host::new(false);
    let server = DesktopServer::new(10);
    assert!(
        server
            .start(host.clone(), request(), Delivery::Reliable)
            .await
            .is_err()
    );
    assert_eq!(host.starts.load(Ordering::Relaxed), 0);
    server.configure(true);
    let id = server
        .start(host.clone(), request(), Delivery::Reliable)
        .await
        .unwrap();
    assert_eq!(
        host.ids.lock().unwrap().as_slice(),
        &[uuid::Uuid::from_bytes(id)]
    );
    assert!(server.stop(id, "foreign").await.is_err());
    assert_eq!(host.stops.load(Ordering::Relaxed), 0);
    server.stop(id, "owner").await.unwrap();
    assert_eq!(host.stops.load(Ordering::Relaxed), 1);
    server.configure(false);
    server.stopped().await;
}
#[tokio::test]
async fn disable_joins_sessions_without_any_viewer() {
    let host = Host::new(false);
    let server = DesktopServer::new(10);
    server.configure(true);
    let _ = server
        .start(host.clone(), request(), Delivery::Datagram)
        .await
        .unwrap();
    assert_eq!(host.stops.load(Ordering::Relaxed), 0);
    server.configure(false);
    server.stopped().await;
    assert_eq!(host.stops.load(Ordering::Relaxed), 1);
    server.configure(true);
    assert_eq!(host.starts.load(Ordering::Relaxed), 1);
    server.configure(false);
    server.stopped().await;
}
#[tokio::test]
async fn cancelled_preparation_is_tracked_until_native_stop_finishes() {
    let host = Host::new(true);
    let server = DesktopServer::new(10);
    server.configure(true);
    let starting = host.starting.notified();
    let starter = {
        let server = server.clone();
        let host = host.clone();
        tokio::spawn(async move { server.start(host, request(), Delivery::Reliable).await })
    };
    starting.await;
    starter.abort();
    let _ = starter.await;
    server.configure(false);
    server.stopped().await;
    assert_eq!(host.starts.load(Ordering::Relaxed), 1);
    assert_eq!(host.stops.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn withdrawal_before_producer_is_polled_never_starts_capture() {
    let host = Host::new(false);
    let server = DesktopServer::new(10);
    server.configure(true);
    let start = server.start(host.clone(), request(), Delivery::Reliable);
    tokio::pin!(start);
    tokio::select! { biased;
        result = &mut start => panic!("unexpected completed preparation: {result:?}"),
        () = std::future::ready(()) => server.configure(false),
    }
    assert!(start.await.is_err());
    server.stopped().await;
    assert_eq!(host.starts.load(Ordering::Relaxed), 0);
}

struct Login(AtomicBool);
impl infraternal_plugin_api::streams::Authority for Login {
    fn permits(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn cancelled(&self) -> Operation<'_, ()> {
        Box::pin(std::future::pending())
    }
}
struct Socket {
    user: &'static str,
    login: Arc<Login>,
}
impl infraternal_plugin_api::SocketHost for Socket {
    fn user_id(&self) -> &str {
        self.user
    }
    fn token_hash(&self) -> &'static str {
        "test-projection"
    }
    fn authority(&self) -> Arc<dyn infraternal_plugin_api::streams::Authority> {
        self.login.clone()
    }
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        operation
    }
    fn fresh(&self, _: i64) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
}
#[tokio::test]
async fn viewers_require_current_host_owner_and_their_own_login() {
    let host = Host::new(false);
    let server = DesktopServer::new(10);
    server.configure(true);
    let login = Arc::new(Login(AtomicBool::new(true)));
    let socket = Socket {
        user: "owner",
        login: login.clone(),
    };
    assert!(server.attach(&[0; 16], &socket).is_err());
    assert_eq!(host.starts.load(Ordering::Relaxed), 0);
    let id = server
        .start(host.clone(), request(), Delivery::Reliable)
        .await
        .unwrap();
    let viewer = server.attach(&id, &socket).unwrap();
    assert!(
        server
            .attach(
                &id,
                &Socket {
                    user: "foreign",
                    login: login.clone()
                }
            )
            .is_err()
    );
    login.0.store(false, Ordering::Release);
    assert!(server.attach(&id, &socket).is_err());
    login.0.store(true, Ordering::Release);
    host.live.store(false, Ordering::Release);
    assert!(server.attach(&id, &socket).is_err());
    drop(viewer);
    server.configure(false);
    server.stopped().await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_stop_remains_joinable_by_feature_disable() {
    let host = Host::new(false);
    let gate = Arc::new(Notify::new());
    *host.stop_gate.lock().unwrap() = Some(gate.clone());
    let server = DesktopServer::new(10);
    server.configure(true);
    let id = server
        .start(host.clone(), request(), Delivery::Reliable)
        .await
        .unwrap();
    let stopping = host.stopping.notified();
    let stopper = {
        let server = server.clone();
        tokio::spawn(async move { server.stop(id, "owner").await })
    };
    stopping.await;
    stopper.abort();
    let _ = stopper.await;
    server.configure(false);
    let joining = server.stopped();
    tokio::pin!(joining);
    let finished_early = tokio::select! { biased;
        () = &mut joining => true,
        () = std::future::ready(()) => false,
    };
    gate.notify_one();
    if !finished_early {
        joining.await;
    }
    assert!(
        !finished_early,
        "disable returned while native stop was pending"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn worker_capacity_counts_pending_native_retirements() {
    let host = Host::new(false);
    let gate = Arc::new(Notify::new());
    *host.stop_gate.lock().unwrap() = Some(gate.clone());
    let server = DesktopServer::new(1);
    server.configure(true);
    let id = server
        .start(host.clone(), request(), Delivery::Reliable)
        .await
        .unwrap();
    let stopping = host.stopping.notified();
    let stopper = {
        let server = server.clone();
        tokio::spawn(async move { server.stop(id, "owner").await })
    };
    stopping.await;
    stopper.abort();
    let _ = stopper.await;
    let second = server
        .start(host.clone(), request(), Delivery::Reliable)
        .await;
    // Release all fixture workers before asserting, including any incorrectly
    // admitted second capture, so the failing-before run leaves no background job.
    *host.stop_gate.lock().unwrap() = None;
    gate.notify_waiters();
    server.configure(false);
    server.stopped().await;
    assert!(
        second.is_err(),
        "retiring capture freed its capacity too early"
    );
    assert_eq!(host.starts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn reconnect_prepares_the_same_server_identity_before_reopening_capture() {
    let host = Host::new(false);
    host.fail_open.store(true, Ordering::Release);
    let server = DesktopServer::new(10);
    server.configure(true);
    let id = server
        .start(host.clone(), request(), Delivery::Reliable)
        .await
        .unwrap();
    let prepared = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while host.starts.load(Ordering::Acquire) < 2 {
            host.starting.notified().await;
        }
    })
    .await;
    assert!(
        prepared.is_ok(),
        "failed capture was reopened without re-preparing its session"
    );
    assert!(
        host.ids
            .lock()
            .unwrap()
            .iter()
            .all(|seen| *seen.as_bytes() == id)
    );
    server.stop(id, "owner").await.unwrap();
    server.configure(false);
    server.stopped().await;
}

struct RefusedStop {
    host: Arc<Host>,
    refuse: AtomicBool,
}
impl NodeHost for RefusedStop {
    fn id(&self) -> &str {
        self.host.id()
    }
    fn owner_id(&self) -> &str {
        self.host.owner_id()
    }
    fn permits(&self) -> bool {
        self.host.permits()
    }
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        self.host.authorized(operation)
    }
    fn call<'a>(&'a self, action: &'a str, input: &'a [u8]) -> Operation<'a, Result<Vec<u8>, ()>> {
        Box::pin(async move {
            // A transient transport refusal happens before native stop delivery.
            if action == "desktop.source.stop" && self.refuse.swap(false, Ordering::AcqRel) {
                return Err(());
            }
            self.host.call(action, input).await
        })
    }
    fn open<'a>(
        &'a self,
        definition: &'static WireStreamDef,
        opening: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>> {
        self.host.open(definition, opening)
    }
}

#[tokio::test]
async fn refused_native_stop_remains_tracked_for_owner_retry() {
    let native = Host::new(false);
    let host = Arc::new(RefusedStop {
        host: native.clone(),
        refuse: AtomicBool::new(true),
    });
    let server = DesktopServer::new(1);
    server.configure(true);
    let id = server
        .start(host, request(), Delivery::Reliable)
        .await
        .unwrap();
    assert!(server.stop(id, "owner").await.is_err());
    assert_eq!(native.stops.load(Ordering::Acquire), 0);
    let retried = server.stop(id, "owner").await;
    server.configure(false);
    server.stopped().await;
    assert!(
        retried.is_ok() && native.stops.load(Ordering::Acquire) == 1,
        "refused stop discarded the only server record before native retirement"
    );
}

#[tokio::test]
async fn failed_native_retirement_holds_capacity_until_disable_retries() {
    let native = Host::new(false);
    let host = Arc::new(RefusedStop {
        host: native.clone(),
        refuse: AtomicBool::new(true),
    });
    let server = DesktopServer::new(1);
    server.configure(true);
    let id = server
        .start(host.clone(), request(), Delivery::Reliable)
        .await
        .unwrap();
    assert!(server.stop(id, "owner").await.is_err());
    assert_eq!(
        server.start(host, request(), Delivery::Reliable).await,
        Err(Error::Limit)
    );
    server.configure(false);
    server.stopped().await;
    assert_eq!(native.stops.load(Ordering::Acquire), 1);
    server.configure(true);
    let next = server
        .start(native.clone(), request(), Delivery::Reliable)
        .await
        .unwrap();
    server.stop(next, "owner").await.unwrap();
    server.configure(false);
    server.stopped().await;
}
