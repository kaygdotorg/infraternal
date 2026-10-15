//! Proves source routing, helper ownership and retained resize/sequence over real mTLS QUIC plus local framed-process fixtures [D203,D232].
use super::*;
use bytes::Bytes;
use infraternal_agent::{
    remote_native::NativeChannel,
    remote_quic,
    wire::{Lane, Side},
};
use infraternal_plugin_api::{
    AgentPlugin,
    streams::{WireLane, WireProvider},
};
use infraternal_plugin_desktop::wire::WIRE;
use infraternal_plugin_remote::{
    remote_tls::tests::{leaf, root},
    wire_datagrams::NativeDatagrams,
};
use infraternal_protocol::{
    Frame, decode_frame,
    desktop::{Delivery, Input, Message},
    encode_frame_into,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
static NEXT: AtomicU64 = AtomicU64::new(1);
#[derive(Default)]
struct TargetParent {
    active_fixtures: usize,
    created_by_fixtures: bool,
}
static TARGET_PARENT: OnceLock<Mutex<TargetParent>> = OnceLock::new();
fn target_parent() -> &'static Mutex<TargetParent> {
    TARGET_PARENT.get_or_init(|| Mutex::new(TargetParent::default()))
}
struct Fixture {
    runtime: PathBuf,
    bridge: SourceBridge,
}
impl Fixture {
    fn new() -> Self {
        // Cargo may put build output elsewhere; serialize parent creation so a
        // last fixture cannot remove it while another fixture is starting.
        let runtime = {
            let mut parent = target_parent().lock().unwrap();
            let target = PathBuf::from("target");
            if !target.exists() {
                fs::create_dir_all(&target).unwrap();
                parent.created_by_fixtures = true;
            }
            let runtime = target.join(format!(
                "sb-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&runtime).unwrap();
            parent.active_fixtures += 1;
            runtime
        };
        let executable =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source-helper.py");
        let bridge = SourceBridge::new(runtime.clone(), executable, 10);
        Self { runtime, bridge }
    }
    fn events(&self) -> Vec<Value> {
        fs::read_to_string(self.runtime.join("events.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    async fn call(
        &self,
        action: &str,
        value: Value,
    ) -> Result<Value, infraternal_plugin_api::PluginError> {
        let mut bridge = self.bridge.clone();
        let bytes = serde_json::to_vec(&value).unwrap();
        let reply = bridge.call_async(action, &bytes).unwrap().await?;
        assert!(reply.json.len() <= infraternal_plugin_api::MAX_ACTION_BYTES);
        Ok(serde_json::from_slice(&reply.json).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let mut parent = target_parent().lock().unwrap();
        let _ = fs::remove_dir_all(&self.runtime);
        parent.active_fixtures -= 1;
        if parent.active_fixtures == 0
            && parent.created_by_fixtures
            && fs::remove_dir("target").is_ok()
        {
            parent.created_by_fixtures = false;
        }
    }
}

#[tokio::test]
async fn whole_display_and_layout_text_reach_the_same_user_helper() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(146);
    let mut selected = start();
    selected.target = Target::Screen { display_id: 42 };
    selected.size.backing_scale = 2.0;
    selected.size.canvas_width = 480.0;
    selected.size.canvas_height = 300.0;
    fixture.bridge.prepare(id, selected).unwrap();
    let pair = Pair::new().await;
    let (requester, provider, opening) = pair.lanes(id, 42, Delivery::Reliable).await;
    let bridge = fixture.bridge.clone();
    let serving = tokio::spawn(async move { bridge.serve(&WIRE, opening, provider).await });
    next_video(requester.as_ref()).await;
    requester
        .send(&packet(Message::Input(Input::Control { active: true })))
        .await
        .unwrap();
    requester
        .send(&packet(Message::Input(Input::Text {
            scalar: 0x0001_f600,
        })))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if fixture.events().iter().any(|event| {
                event["kind"] == 4 && event["body"] == json!({"type":"text","scalar":0x0001_f600})
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("committed layout text must reach the helper before retirement");
    let events = fixture.events();
    assert!(
        events
            .iter()
            .any(|event| event["kind"] == 10 && event["body"] == json!({"active":true}))
    );
    assert!(events.iter().any(|event| event["kind"] == 2
        && event["body"]["target"] == json!({"type":"screen","display_id":42})
        && event["body"]["size"]["backing_scale"] == 2.0));
    fixture.bridge.set_enabled(false).await.unwrap();
    serving.await.unwrap().unwrap();
}
struct Pair {
    _server: quinn::Endpoint,
    _host: quinn::Endpoint,
    server: quinn::Connection,
    host: quinn::Connection,
    request_datagrams: Arc<NativeDatagrams>,
    provider_datagrams: Arc<NativeDatagrams>,
}
impl Pair {
    async fn new() -> Self {
        let ca = root();
        let server = quinn::Endpoint::server(
            remote_quic::server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate))
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut host = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        host.set_default_client_config(
            remote_quic::client_config(&leaf(&ca, false), &[ca.certificate]).unwrap(),
        );
        let (dial, accepted) = tokio::join!(
            host.connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let server_connection = accepted.unwrap();
        let host_connection = dial.unwrap();
        Self {
            _server: server,
            _host: host,
            request_datagrams: NativeDatagrams::new(server_connection.clone()),
            provider_datagrams: NativeDatagrams::new(host_connection.clone()),
            server: server_connection,
            host: host_connection,
        }
    }
    async fn lanes(
        &self,
        id: Uuid,
        writer: u32,
        mode: Delivery,
    ) -> (Arc<dyn WireLane>, Arc<dyn WireLane>, Bytes) {
        self.lanes_available(id, writer, mode, mode == Delivery::Datagram)
            .await
    }
    async fn lanes_available(
        &self,
        id: Uuid,
        writer: u32,
        mode: Delivery,
        datagrams: bool,
    ) -> (Arc<dyn WireLane>, Arc<dyn WireLane>, Bytes) {
        let hello = Frame::Hello {
            version: 1,
            caps: remote_quic::REMOTE_WRITER_BINDING | WIRE.capability,
            client_info: "source fixture",
        };
        let server = remote_quic::negotiate_binding(&self.server, &hello).unwrap();
        let host = remote_quic::negotiate_binding(&self.host, &hello).unwrap();
        let (request, response) = tokio::join!(
            remote_quic::open_bound(&server, writer),
            remote_quic::accept_bound(&host)
        );
        let requester: Arc<dyn WireLane> = Arc::new(
            Lane::new(
                NativeChannel::terminal(request.unwrap()).unwrap(),
                &WIRE,
                Side::Requester,
                datagrams.then(|| self.request_datagrams.admit(&WIRE, *id.as_bytes()).unwrap()),
            )
            .unwrap(),
        );
        let provider: Arc<dyn WireLane> = Arc::new(
            Lane::new(
                NativeChannel::terminal(response.unwrap()).unwrap(),
                &WIRE,
                Side::Provider,
                datagrams.then(|| {
                    self.provider_datagrams
                        .admit(&WIRE, *id.as_bytes())
                        .unwrap()
                }),
            )
            .unwrap(),
        );
        let packet = packet(Message::Attach {
            session_id: id.as_bytes(),
            delivery: mode,
        });
        requester.send(&packet).await.unwrap();
        let opening = provider.receive().await.unwrap();
        (requester, provider, opening)
    }
}
fn packet(message: Message<'_>) -> Bytes {
    let mut bytes = Vec::new();
    encode_frame_into(&Frame::Desktop(message), &mut bytes).unwrap();
    bytes.into()
}
async fn next_video(lane: &dyn WireLane) -> (u64, u64) {
    let bytes = tokio::time::timeout(Duration::from_secs(3), lane.receive())
        .await
        .unwrap()
        .unwrap();
    let Frame::Desktop(Message::Video {
        sequence,
        capture_ns,
        keyframe: true,
        bytes: payload,
    }) = decode_frame(&bytes).unwrap().frame
    else {
        panic!("expected video")
    };
    assert_eq!(&payload[..5], &[0, 0, 0, 1, 0x65]);
    (sequence, capture_ns)
}

#[tokio::test]
async fn unknown_attach_never_launches_helper() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let pair = Pair::new().await;
    let (_requester, provider, opening) = pair
        .lanes(Uuid::from_u128(99), 42, Delivery::Reliable)
        .await;
    assert!(
        fixture
            .bridge
            .serve(&WIRE, opening, provider)
            .await
            .is_err()
    );
    assert_eq!(fixture.events(), Vec::<Value>::new());
    assert_eq!(fs::read_dir(&fixture.runtime).unwrap().count(), 0);
    fixture.bridge.set_enabled(false).await.unwrap();
}

#[tokio::test]
async fn fresh_runtime_is_created_privately_only_for_explicit_helper_work() {
    let fixture = Fixture::new();
    let runtime = fixture.runtime.join("fresh").join("source");
    let executable =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source-helper.py");
    let bridge = SourceBridge::new(runtime.clone(), executable, 10);
    bridge.set_enabled(true).await.unwrap();
    assert!(!runtime.exists());
    let pair = Pair::new().await;
    let (_, provider, opening) = pair
        .lanes(Uuid::from_u128(77), 42, Delivery::Reliable)
        .await;
    assert!(bridge.serve(&WIRE, opening, provider).await.is_err());
    assert!(!runtime.exists(), "unknown Attach created a runtime");
    let mut plugin = bridge.clone();
    let reply = plugin
        .call_async("desktop.source.windows", b"{}")
        .unwrap()
        .await
        .unwrap();
    assert!(
        serde_json::from_slice::<Value>(&reply.json).unwrap()["inventory"]["windows"]
            .as_array()
            .is_some()
    );
    assert_eq!(
        fs::symlink_metadata(&runtime).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::symlink_metadata(runtime.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    bridge.set_enabled(false).await.unwrap();
}

#[tokio::test]
async fn fresh_source_resumes_above_sequence_floor_and_keeps_higher_local_sequence() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(12);
    let prepared = fixture
        .call(
            "desktop.source.start",
            json!({"session_id":id,"start":start(),"sequence_floor":41}),
        )
        .await
        .unwrap();
    assert_eq!(prepared["sequence"], 41);
    let pair = Pair::new().await;
    let (requester, provider, opening) = pair.lanes(id, 42, Delivery::Reliable).await;
    let bridge = fixture.bridge.clone();
    let worker = tokio::spawn(async move { bridge.serve(&WIRE, opening, provider).await });
    assert_eq!(next_video(requester.as_ref()).await.0, 42);
    let prepared = fixture
        .call(
            "desktop.source.start",
            json!({"session_id":id,"start":start(),"sequence_floor":7}),
        )
        .await
        .unwrap();
    assert_eq!(prepared["sequence"], 42);
    assert!(
        fixture
            .call(
                "desktop.source.start",
                json!({"session_id":Uuid::from_u128(13),"start":start(),"sequence_floor":u64::MAX})
            )
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .call("desktop.source.status", json!({}))
            .await
            .unwrap()["prepared_count"],
        1
    );
    fixture.bridge.set_enabled(false).await.unwrap();
    worker.await.unwrap().unwrap();
}

#[tokio::test]
async fn known_session_reconnect_keeps_resize_sequence_and_input_clock_routing() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(1);
    fixture.bridge.prepare(id, start()).unwrap();
    let pair = Pair::new().await;
    let (requester, provider, opening) = pair.lanes(id, 42, Delivery::Reliable).await;
    let bridge = fixture.bridge.clone();
    let serving = tokio::spawn(async move { bridge.serve(&WIRE, opening, provider).await });
    assert_eq!(next_video(requester.as_ref()).await, (1, 123_456_789));
    requester
        .send(&packet(Message::Size {
            width: 1280,
            height: 720,
            density_milli: 2000,
        }))
        .await
        .unwrap();
    assert_eq!(next_video(requester.as_ref()).await.0, 2);
    requester
        .send(&packet(Message::Input(Input::Mouse {
            x: 500_000,
            y: 500_000,
            button: 0,
            state: 1,
            modifiers: 0,
        })))
        .await
        .unwrap();
    // A successful transport write is not helper consumption. Observe the
    // routed input before deliberately retiring its lane; clock reads only
    // capture state and cannot fence another native stream's queued work.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if fixture.events().iter().any(|event| {
                event["kind"] == 4 && event["body"]["x"] == 640.0 && event["body"]["y"] == 360.0
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("helper must consume routed mouse input before disconnection");
    let clock = fixture
        .call("desktop.source.clock", json!({"session_id":id}))
        .await
        .unwrap();
    assert_eq!(clock["capture_ns"], 123_456_789);
    let prepared = fixture.bridge.prepare(id, start()).unwrap();
    assert_eq!(prepared["size"]["width"], 1280);
    assert_eq!(prepared["sequence"], 2);
    requester.retire();
    drop(requester);
    assert!(
        tokio::time::timeout(Duration::from_secs(3), serving)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let (requester, provider, opening) = pair.lanes(id, 44, Delivery::Reliable).await;
    let bridge = fixture.bridge.clone();
    let serving = tokio::spawn(async move { bridge.serve(&WIRE, opening, provider).await });
    assert_eq!(next_video(requester.as_ref()).await.0, 3);
    fixture.bridge.stop(id).await.unwrap();
    serving.await.unwrap().unwrap();
    let events = fixture.events();
    let starts: Vec<_> = events.iter().filter(|event| event["kind"] == 2).collect();
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[1]["body"]["size"]["width"], 1280);
    assert!(events.iter().any(|event| event["kind"] == 4
        && event["body"]["x"] == 640.0
        && event["body"]["y"] == 360.0));
    assert!(
        events
            .iter()
            .all(|event| event["companion"] == fixture.runtime.to_string_lossy().as_ref())
    );
    assert!(pair.server.close_reason().is_none());
    fixture.bridge.set_enabled(false).await.unwrap();
    assert_eq!(fixture.bridge.status().active_work, 0);
}

#[tokio::test]
async fn inventory_pages_preserve_metadata_and_stop_withdraws_cursor() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let mut page = fixture
        .call("desktop.source.windows", json!({}))
        .await
        .unwrap();
    let first_cursor = page["cursor"].as_str().unwrap().to_owned();
    let mut ids = Vec::new();
    loop {
        assert_eq!(page["inventory"]["displays"][0]["pixel_width"], 1920);
        assert_eq!(
            page["inventory"]["permission_state"]["screen_recording"],
            true
        );
        ids.extend(
            page["inventory"]["windows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|window| window["window_id"].as_u64().unwrap()),
        );
        let Some(cursor) = page["cursor"].as_str() else {
            break;
        };
        page = fixture
            .call("desktop.source.windows", json!({"cursor":cursor}))
            .await
            .unwrap();
    }
    assert_eq!(ids, (1..=100).collect::<Vec<_>>());
    assert_eq!(
        fixture
            .events()
            .iter()
            .filter(|event| event["kind"] == 1)
            .count(),
        1
    );
    fixture.bridge.stop(Uuid::from_u128(5)).await.unwrap();
    assert!(
        fixture
            .call("desktop.source.windows", json!({"cursor":first_cursor}))
            .await
            .is_err()
    );
    fixture.bridge.set_enabled(false).await.unwrap();
}

#[tokio::test]
async fn helper_runtime_refuses_a_public_directory_before_process_start() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    fs::set_permissions(&fixture.runtime, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        fixture
            .call("desktop.source.windows", json!({}))
            .await
            .is_err()
    );
    assert_eq!(fixture.events(), Vec::<Value>::new());
    fs::set_permissions(&fixture.runtime, fs::Permissions::from_mode(0o700)).unwrap();
    // A failed helper operation owns no process; an off still joins its worker.
    fixture.bridge.set_enabled(false).await.unwrap();
}

#[tokio::test]
async fn ten_concurrent_sources_own_distinct_helpers_and_off_joins_every_group() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let pair = Pair::new().await;
    let mut viewers = Vec::new();
    let mut workers = Vec::new();
    for index in 0..10u32 {
        let id = Uuid::from_u128(u128::from(index) + 1);
        let writer = 42 + 2 * index;
        fixture.bridge.prepare(id, start()).unwrap();
        let (requester, provider, opening) = pair.lanes(id, writer, Delivery::Reliable).await;
        let bridge = fixture.bridge.clone();
        workers.push(tokio::spawn(async move {
            bridge.serve(&WIRE, opening, provider).await
        }));
        viewers.push(requester);
    }
    for viewer in &viewers {
        assert_eq!(next_video(viewer.as_ref()).await.0, 1);
    }
    assert_eq!(fixture.bridge.status().active_work, 10);
    let pids: Vec<_> = fixture
        .events()
        .into_iter()
        .filter(|event| event["kind"] == 2)
        .map(|event| event["pid"].as_u64().unwrap())
        .collect();
    assert_eq!(pids.len(), 10);
    assert_eq!(
        pids.iter().collect::<std::collections::HashSet<_>>().len(),
        10
    );
    fixture.bridge.set_enabled(false).await.unwrap();
    for worker in workers {
        worker.await.unwrap().unwrap();
    }
    for pid in pids {
        assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    }
    assert_eq!(fixture.bridge.status().active_work, 0);
    assert!(pair.server.close_reason().is_none());
}

#[tokio::test]
async fn explicit_datagram_source_delivers_fragments_and_unavailable_mode_starts_no_helper() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(7);
    fixture.bridge.prepare(id, start()).unwrap();
    let pair = Pair::new().await;
    let (_requester, provider, opening) = pair
        .lanes_available(id, 42, Delivery::Datagram, false)
        .await;
    assert!(
        fixture
            .bridge
            .serve(&WIRE, opening, provider)
            .await
            .is_err()
    );
    assert_eq!(fixture.events(), Vec::<Value>::new());
    let (requester, provider, opening) = pair.lanes(id, 44, Delivery::Datagram).await;
    let provider_datagrams = provider.datagrams().unwrap();
    let bridge = fixture.bridge.clone();
    let worker = tokio::spawn(async move { bridge.serve(&WIRE, opening, provider).await });
    let datagrams = requester.datagrams().unwrap();
    let mut assembly = infraternal_plugin_desktop::datagram::Reassembler::new(*id.as_bytes());
    let video = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let packet = datagrams.receive().await.unwrap();
            let Frame::Desktop(fragment) = decode_frame(&packet).unwrap().frame else {
                panic!("expected fragment")
            };
            if let Some(video) = assembly.push(fragment, std::time::Instant::now()).unwrap() {
                break video;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(video.sequence, 1);
    assert_eq!(video.capture_ns, 123_456_789);
    assert_eq!(&video.bytes[..5], &[0, 0, 0, 1, 0x65]);
    fixture.bridge.set_enabled(false).await.unwrap();
    worker.await.unwrap().unwrap();
    assert!(provider_datagrams.max_payload().is_none());
    requester.retire();
    assert!(datagrams.max_payload().is_none());
}

#[tokio::test]
async fn cancelled_provider_future_keeps_cleanup_owned_until_off_joins_it() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(1);
    fixture.bridge.prepare(id, start()).unwrap();
    let pair = Pair::new().await;
    let (requester, provider, opening) = pair.lanes(id, 42, Delivery::Reliable).await;
    let bridge = fixture.bridge.clone();
    let worker = tokio::spawn(async move { bridge.serve(&WIRE, opening, provider).await });
    next_video(requester.as_ref()).await;
    let pid = fixture
        .events()
        .into_iter()
        .find(|event| event["kind"] == 2)
        .unwrap()["pid"]
        .as_u64()
        .unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    fixture.bridge.set_enabled(false).await.unwrap();
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    assert_eq!(fixture.bridge.status().active_work, 0);
}

#[tokio::test]
async fn valid_wire_scroll_preserves_capture_and_reaches_helper() {
    let fixture = Fixture::new();
    fixture.bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(81);
    fixture.bridge.prepare(id, start()).unwrap();
    let pair = Pair::new().await;
    let (requester, provider, opening) = pair.lanes(id, 42, Delivery::Reliable).await;
    let bridge = fixture.bridge.clone();
    let worker = tokio::spawn(async move { bridge.serve(&WIRE, opening, provider).await });
    next_video(requester.as_ref()).await;
    // The wire contract permits the entire i32 range. A legal scroll must not
    // retire capture at the narrower private-helper validation boundary.
    requester
        .send(&packet(Message::Input(Input::Scroll {
            x: 500_000,
            y: 500_000,
            dx: 4097,
            dy: 0,
            modifiers: 0,
        })))
        .await
        .unwrap();
    let repair = requester
        .send(&packet(Message::Repair { last_sequence: 1 }))
        .await;
    let resumed = tokio::time::timeout(Duration::from_secs(3), requester.receive()).await;
    fixture.bridge.set_enabled(false).await.unwrap();
    let outcome = worker.await.unwrap();
    let delivered = fixture
        .events()
        .iter()
        .any(|event| event["kind"] == 4 && event["body"]["dx"] == 4097);
    assert!(
        repair.is_ok() && matches!(resumed, Ok(Ok(_))) && outcome.is_ok() && delivered,
        "valid wire scroll retired capture before helper delivery"
    );
}
