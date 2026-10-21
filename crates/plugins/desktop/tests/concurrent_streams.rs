//! Runs ten source workers through the production desktop server relay with a synthetic companion [D198,D200,D232], #146.
#![cfg(all(feature = "source", feature = "server"))]
#![allow(clippy::unwrap_used)]

use bytes::Bytes;
use infraternal_plugin_api::{
    AgentPlugin, ComponentPlugin, Operation, Plugin, SocketHost,
    streams::{Authority, NodeHost, WireLane, WireProvider, WireStreamDef},
};
use infraternal_plugin_desktop::{
    protocol::{Size, Start, Target},
    server::DesktopServer,
    source::SourceBridge,
};
use infraternal_protocol::desktop::Delivery;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Notify, mpsc, watch};

const STREAMS: usize = 10;

struct Lane {
    id: u32,
    incoming: Mutex<mpsc::Receiver<Bytes>>,
    outgoing: mpsc::Sender<Bytes>,
    retired: watch::Receiver<bool>,
    retire: watch::Sender<bool>,
}

impl WireLane for Lane {
    fn stream_id(&self) -> u32 {
        self.id
    }

    fn receive(&self) -> Operation<'_, Result<Bytes, ()>> {
        Box::pin(async move {
            let mut retired = self.retired.clone();
            let mut incoming = self.incoming.lock().await;
            tokio::select! {
                packet = incoming.recv() => packet.ok_or(()),
                () = async {
                    if !*retired.borrow_and_update() {
                        let _ = retired.changed().await;
                    }
                } => Err(()),
            }
        })
    }

    fn send<'a>(&'a self, packet: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            let mut retired = self.retired.clone();
            if *retired.borrow_and_update() {
                return Err(());
            }
            tokio::select! {
                result = self.outgoing.send(Bytes::copy_from_slice(packet)) => result.map_err(|_| ()),
                _ = retired.changed() => Err(()),
            }
        })
    }

    fn retire(&self) {
        self.retire.send_replace(true);
    }
}

fn lanes(id: u32) -> (Arc<Lane>, Arc<Lane>) {
    let (to_server, server_rx) = mpsc::channel(8);
    let (to_source, source_rx) = mpsc::channel(8);
    let (retire, retired) = watch::channel(false);
    let server = Arc::new(Lane {
        id,
        incoming: Mutex::new(server_rx),
        outgoing: to_source,
        retired: retired.clone(),
        retire: retire.clone(),
    });
    let source = Arc::new(Lane {
        id,
        incoming: Mutex::new(source_rx),
        outgoing: to_server,
        retired,
        retire,
    });
    (server, source)
}

struct Node {
    source: SourceBridge,
    next_stream: AtomicU32,
    opened: AtomicUsize,
    opened_notify: Notify,
    serve_results: Arc<Mutex<Vec<bool>>>,
}

impl NodeHost for Node {
    fn id(&self) -> &'static str {
        "synthetic-node"
    }

    fn owner_id(&self) -> &'static str {
        "owner"
    }

    fn permits(&self) -> bool {
        true
    }

    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        operation
    }

    fn call<'a>(&'a self, action: &'a str, input: &'a [u8]) -> Operation<'a, Result<Vec<u8>, ()>> {
        let mut source = self.source.clone();
        let action = action.to_owned();
        let input = input.to_vec();
        Box::pin(async move {
            let operation = source.call_async(&action, &input).ok_or(())?;
            Ok(operation.await.map_err(|_| ())?.json)
        })
    }

    fn open<'a>(
        &'a self,
        definition: &'static WireStreamDef,
        opening: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>> {
        let source = self.source.clone();
        let opening = Bytes::copy_from_slice(opening);
        Box::pin(async move {
            let id = self.next_stream.fetch_add(2, Ordering::Relaxed);
            let (server, peer) = lanes(id);
            let serving = source.serve(definition, opening, peer);
            let serve_results = self.serve_results.clone();
            tokio::spawn(async move {
                let result = serving.await.is_ok();
                serve_results.lock().await.push(result);
            });
            self.opened.fetch_add(1, Ordering::AcqRel);
            self.opened_notify.notify_one();
            Ok(server as Arc<dyn WireLane>)
        })
    }
}

struct Login;

impl Authority for Login {
    fn permits(&self) -> bool {
        true
    }

    fn cancelled(&self) -> Operation<'_, ()> {
        Box::pin(std::future::pending())
    }
}

struct Socket;

impl SocketHost for Socket {
    fn user_id(&self) -> &'static str {
        "owner"
    }

    fn token_hash(&self) -> &'static str {
        "synthetic-viewer"
    }

    fn authority(&self) -> Arc<dyn Authority> {
        Arc::new(Login)
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

fn start(index: usize) -> Start {
    Start {
        target: Target::Window {
            window_id: u32::try_from(index + 1).unwrap(),
            owner_pid: 123,
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
#[allow(clippy::too_many_lines)]
async fn ten_concurrent_streams_deliver_their_first_keyframe_through_the_server_relay() {
    // The job target path is longer than Linux's AF_UNIX limit once the source UUID is appended.
    let target = PathBuf::from("target");
    let target_preexisted = target.exists();
    fs::create_dir_all(&target).unwrap();
    let runtime = target.join(format!("concurrent-source-{}", std::process::id()));
    let _ = fs::remove_dir_all(&runtime);
    fs::DirBuilder::new().mode(0o700).create(&runtime).unwrap();
    let executable =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source-helper.py");
    let source = SourceBridge::new(runtime.clone(), executable, STREAMS);
    source.set_enabled(true).await.unwrap();
    let node = Arc::new(Node {
        source: source.clone(),
        next_stream: AtomicU32::new(1),
        opened: AtomicUsize::new(0),
        opened_notify: Notify::new(),
        serve_results: Arc::new(Mutex::new(Vec::new())),
    });
    let host: Arc<dyn NodeHost> = node.clone();
    let server = DesktopServer::new(STREAMS);
    server.configure(true);

    let mut starters = tokio::task::JoinSet::new();
    for index in 0..STREAMS {
        let server = server.clone();
        let host = host.clone();
        starters.spawn(async move {
            let id = server
                .start(host, start(index), Delivery::Reliable)
                .await
                .map_err(|error| format!("start: {error:?}"))?;
            // Attach as soon as preparation returns so Repair may race the
            // source lane registration, matching the production event order.
            let viewer = server
                .attach(&id, &Socket)
                .map_err(|error| format!("viewer attach: {error:?}"));
            Ok::<_, String>((id, viewer))
        });
    }
    let mut ids = Vec::new();
    let mut start_failures = Vec::new();
    let mut deliveries = tokio::task::JoinSet::new();
    let mut viewers = 0;
    while let Some(result) = starters.join_next().await {
        match result {
            Ok(Ok((id, viewer))) => {
                ids.push(id);
                match viewer {
                    Ok(mut viewer) => {
                        viewers += 1;
                        deliveries.spawn(async move {
                            tokio::time::timeout(Duration::from_secs(10), viewer.next())
                                .await
                                .map_err(|_| "first keyframe timed out")
                                .and_then(|result| result.map_err(|_| "viewer ended"))
                        });
                    }
                    Err(error) => start_failures.push(error),
                }
            }
            Ok(Err(error)) => start_failures.push(error),
            Err(error) => start_failures.push(format!("{error:?}")),
        }
    }

    let all_lanes_opened = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let changed = node.opened_notify.notified();
            if node.opened.load(Ordering::Acquire) >= STREAMS {
                break;
            }
            changed.await;
        }
    })
    .await
    .is_ok();

    let mut delivered = 0;
    let mut delivery_failures = Vec::new();
    while let Some(result) = deliveries.join_next().await {
        match result {
            Ok(Ok(video)) if video.sequence == 1 && video.keyframe => delivered += 1,
            Ok(Ok(video)) => delivery_failures.push(format!(
                "unexpected first access unit sequence={} keyframe={}",
                video.sequence, video.keyframe
            )),
            Ok(Err(error)) => delivery_failures.push(error.to_owned()),
            Err(error) => delivery_failures.push(format!("{error:?}")),
        }
    }

    for id in ids {
        let _ = server.stop(id, "owner").await;
    }
    server.configure(false);
    server.stopped().await;
    let helper_cleanup = source.set_enabled(false).await;
    let serve_results = node.serve_results.lock().await.clone();
    let helper_event_kinds: Vec<u64> = fs::read_to_string(runtime.join("events.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|event| event["kind"].as_u64())
        .collect();
    let _ = fs::remove_dir_all(runtime);
    if !target_preexisted {
        let _ = fs::remove_dir(target);
    }

    assert!(
        start_failures.is_empty(),
        "start or attach errors: {start_failures:?}"
    );
    assert!(
        all_lanes_opened,
        "only {} of {STREAMS} relay lanes opened",
        node.opened.load(Ordering::Acquire)
    );
    assert_eq!(
        node.opened.load(Ordering::Acquire),
        STREAMS,
        "a failed source lane must not be replaced with a retry; source serve outcomes: {serve_results:?}; helper command kinds: {helper_event_kinds:?}"
    );
    assert_eq!(viewers, STREAMS);
    assert_eq!(
        helper_event_kinds.iter().filter(|&&kind| kind == 2).count(),
        STREAMS,
        "the synthetic companion must receive one Start for each stream: {helper_event_kinds:?}"
    );
    assert!(
        helper_event_kinds.iter().filter(|&&kind| kind == 7).count() >= STREAMS,
        "each stream must receive a keyframe request: {helper_event_kinds:?}"
    );
    assert!(
        delivery_failures.is_empty(),
        "delivery errors: {delivery_failures:?}; source serve outcomes: {serve_results:?}"
    );
    assert_eq!(
        delivered, STREAMS,
        "every concurrent stream needs its own first keyframe"
    );
    assert!(
        helper_cleanup.is_ok(),
        "helper cleanup failed: {helper_cleanup:?}"
    );
    assert_eq!(source.status().active_work, 0);
}
