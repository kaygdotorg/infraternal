//! Reviews solicited control retirement on an already active helper, separately from idle video [D203,D232,#146].
#![cfg(all(feature = "source", target_os = "linux"))]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use bytes::Bytes;
use infraternal_plugin_api::{
    AgentPlugin, ComponentPlugin, Operation,
    streams::{WireLane, WireProvider},
};
use infraternal_plugin_desktop::{
    protocol::{Size, Start, Target},
    source::SourceBridge,
    wire::WIRE,
};
use infraternal_protocol::{
    Frame,
    desktop::{Delivery, Message},
    encode_frame_into,
};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

struct Lane(tokio::sync::Notify);
impl WireLane for Lane {
    fn stream_id(&self) -> u32 {
        2
    }
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>> {
        Box::pin(std::future::pending())
    }
    fn send<'a>(&'a self, _: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async {
            self.0.notify_one();
            Ok(())
        })
    }
    fn retire(&self) {}
}

/// The helper answers Start once, then keeps the solicited Status silent.
const SILENT_HELPER: &str = concat!(
    "#!/usr/bin/env python3\n",
    include_str!("fixtures/atomic_marker.py"),
    r#"# Role: starts real framed capture, then records a solicited status without sending a reply.
import json, os, socket, struct, sys
os.umask(0o077)
base = sys.argv[sys.argv.index("--companion-runtime") + 1]
listener = socket.socket(socket.AF_UNIX)
listener.bind(os.path.join(sys.argv[1], "desktop.sock"))
listener.listen(1)
connection, _ = listener.accept()
listener.close()
source = connection.makefile("rb", buffering=0)
def exact(n):
    data = b""
    while len(data) < n:
        part = source.read(n - len(data))
        if not part: return None
        data += part
    return data
def send(kind, body):
    connection.sendall(struct.pack(">IBB", len(body)+2, 1, kind)+body)
while True:
    header = exact(6)
    if header is None: break
    length, version, kind = struct.unpack(">IBB", header)
    assert version == 1 and 2 <= length <= 65536
    if exact(length-2) is None: break
    if kind == 2:
        send(66, b'{"capture_rect":{"x":0,"y":0,"width":960,"height":600}}')
        send(70, struct.pack(">Q", 1)+b'\x01\x00\x00\x00\x01\x65'+bytes(100))
    elif kind == 6:
        body = json.dumps({"kind":kind,"pid":os.getpid()}).encode()
        publish_marker(os.path.join(base, "received"), body)
connection.close()
"#,
);

/// Wait for a fixture marker to contain complete JSON, retrying while its writer is publishing.
/// `on_incomplete` runs after each missing or partial read so tests can coordinate a paused writer.
async fn wait_for_marker_json(
    path: &std::path::Path,
    timeout: Duration,
    mut on_incomplete: impl FnMut(),
) -> Result<serde_json::Value, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_parse_error = None;
    loop {
        match fs::read(path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(value) => return Ok(value),
                Err(error) => last_parse_error = Some(error.to_string()),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("cannot read marker {}: {error}", path.display()));
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            let detail = last_parse_error
                .map(|error| format!(": last JSON read was incomplete ({error})"))
                .unwrap_or_default();
            return Err(format!(
                "marker {} was not ready within {} ms{detail}",
                path.display(),
                timeout.as_millis()
            ));
        }
        on_incomplete();
        // sleep: retry marker reads until the writer publishes complete JSON.
        tokio::time::sleep(Duration::from_millis(10).min(remaining)).await;
    }
}

/// The active helper must retire after a silent solicited status reaches its control deadline.
#[tokio::test]
async fn active_helper_silent_status_retires_after_control_deadline() {
    // A relative private runtime keeps the owned helper socket within sun_path.
    let target = PathBuf::from("target");
    let remove_target_afterward = !target.exists();
    fs::create_dir_all(&target).unwrap();
    let runtime = target.join(format!("ac-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&runtime).unwrap();
    let executable = runtime.join("silent-status.py");
    fs::write(&executable, SILENT_HELPER).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
    let mut bridge = SourceBridge::new(runtime.clone(), fs::canonicalize(executable).unwrap(), 1);
    bridge.set_enabled(true).await.unwrap();
    let id = uuid::Uuid::from_u128(146);
    bridge
        .prepare(
            id,
            Start {
                passive_geometry: false,
                target: Target::Screen { display_id: 1 },
                size: Size {
                    width: 960,
                    height: 600,
                    canvas_width: 960.0,
                    canvas_height: 600.0,
                    backing_scale: 1.0,
                },
            },
        )
        .unwrap();
    let mut opening = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Attach {
            session_id: id.as_bytes(),
            delivery: Delivery::Reliable,
        }),
        &mut opening,
    )
    .unwrap();
    let lane = Arc::new(Lane(tokio::sync::Notify::new()));
    let serving = tokio::spawn(bridge.serve(&WIRE, opening.into(), lane.clone()));
    tokio::time::timeout(Duration::from_secs(3), lane.0.notified())
        .await
        .unwrap();
    let input = serde_json::to_vec(&serde_json::json!({"session_id":id})).unwrap();
    let mut status = tokio::spawn(bridge.call_async("desktop.source.clock", &input).unwrap());
    let marker_path = runtime.join("received");
    let marker = wait_for_marker_json(&marker_path, Duration::from_secs(3), || {})
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(marker["kind"], 6);
    // This checks the contract's functional deadline, not a performance budget.
    let completed = tokio::time::timeout(Duration::from_secs(4), &mut status).await;
    let bounded = matches!(completed, Ok(Ok(Err(_))));
    let active = bridge.status().active_work;
    bridge.set_enabled(false).await.unwrap();
    if !status.is_finished() {
        let _ = status.await;
    }
    let _ = serving.await.unwrap();
    let pid = marker["pid"].as_u64().unwrap();
    let retired = !PathBuf::from(format!("/proc/{pid}")).exists();
    fs::remove_dir_all(runtime).unwrap();
    // Keep parallel tests safe: remove only an empty parent that this test created.
    if remove_target_afterward {
        let _ = fs::remove_dir(target);
    }
    assert!(retired, "explicit disable did not join the owned helper");
    assert!(
        bounded && active == 0,
        "silent active status remains pending beyond the control deadline (active_work={active})"
    );
}

/// A reader must wait while a writer holds an empty or partial JSON marker open.
#[tokio::test(start_paused = true)]
async fn marker_reader_retries_while_writer_is_paused_with_empty_and_partial_json() {
    let directory = std::env::temp_dir().join(format!(
        "infraternal-marker-race-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("received");
    let mut writer = fs::File::create(&path).unwrap();

    let reader_path = path.clone();
    let observations = Arc::new(tokio::sync::Notify::new());
    let observed = Arc::clone(&observations);
    let reader = tokio::spawn(async move {
        wait_for_marker_json(&reader_path, Duration::from_secs(2), move || {
            observed.notify_one();
        })
        .await
    });
    // The writer stays paused until the reader confirms it observed the empty file.
    assert!(
        tokio::time::timeout(Duration::from_secs(3), observations.notified())
            .await
            .is_ok(),
        "reader did not observe the empty marker before its deadline"
    );

    writer.write_all(b"{\"kind\":").unwrap();
    writer.flush().unwrap();
    // The writer stays paused until the reader confirms it observed partial JSON.
    tokio::time::advance(Duration::from_millis(10)).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(3), observations.notified())
            .await
            .is_ok(),
        "reader did not retry the partial marker before its deadline"
    );

    writer.write_all(b"6,\"pid\":123}").unwrap();
    writer.sync_all().unwrap();
    tokio::time::advance(Duration::from_millis(10)).await;
    let marker = reader.await.unwrap().unwrap();
    assert_eq!(marker["kind"], 6);
    assert_eq!(marker["pid"], 123);
    fs::remove_dir_all(directory).unwrap();
}

/// A marker that never becomes valid must stop retrying at its monotonic deadline.
#[tokio::test(start_paused = true)]
async fn marker_reader_stops_after_its_bounded_wait() {
    let directory = std::env::temp_dir().join(format!(
        "infraternal-marker-deadline-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("received");
    let _writer = fs::File::create(&path).unwrap();
    let reader_path = path.clone();
    let observations = Arc::new(tokio::sync::Notify::new());
    let observed = Arc::clone(&observations);
    let reader = tokio::spawn(async move {
        wait_for_marker_json(&reader_path, Duration::from_secs(1), move || {
            observed.notify_one();
        })
        .await
    });
    observations.notified().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = reader.await.unwrap();
    fs::remove_dir_all(directory).unwrap();
    assert!(
        result.unwrap_err().contains("was not ready within 1000 ms"),
        "an unfinished marker must report its bounded wait deadline"
    );
}
