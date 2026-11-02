//! Proves a forgotten node preparation is rebuilt from server-held geometry, without replaying input [D104,D208,D232,#146].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use bytes::Bytes;
use infraternal_plugin_api::{
    Operation, Plugin,
    streams::{NodeHost, WireLane, WireStreamDef},
};
use infraternal_plugin_desktop::{
    protocol::{Size, Start, Target},
    server::DesktopServer,
};
use infraternal_protocol::{
    Frame, decode_frame,
    desktop::{Delivery, Message},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Notify, mpsc};
struct Lane {
    media: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    controls: mpsc::Sender<Bytes>,
}
impl WireLane for Lane {
    fn stream_id(&self) -> u32 {
        2
    }
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>> {
        Box::pin(async { self.media.lock().await.recv().await.ok_or(()) })
    }
    fn send<'a>(&'a self, frame: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async {
            self.controls
                .send(Bytes::copy_from_slice(frame))
                .await
                .map_err(|_| ())
        })
    }
    fn retire(&self) {}
}
struct Node {
    lane: Arc<Lane>,
    opens: AtomicUsize,
    second_lane: Option<Arc<Lane>>,
    floors: Mutex<Vec<u64>>,
    preparations: Mutex<Vec<Start>>,
    prepared: Notify,
}
impl NodeHost for Node {
    fn id(&self) -> &'static str {
        "restarting-node"
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
        Box::pin(async move {
            let input: serde_json::Value = serde_json::from_slice(input).unwrap();
            if action == "desktop.source.start" {
                self.preparations
                    .lock()
                    .unwrap()
                    .push(serde_json::from_value(input["start"].clone()).unwrap());
                self.floors.lock().unwrap().push(
                    input
                        .get("sequence_floor")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                );
                self.prepared.notify_one();
            }
            Ok(serde_json::to_vec(&serde_json::json!({"session_id":input["session_id"]})).unwrap())
        })
    }
    fn open<'a>(
        &'a self,
        _: &'static WireStreamDef,
        _: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>> {
        Box::pin(async move {
            match self.opens.fetch_add(1, Ordering::Relaxed) {
                0 => Ok(self.lane.clone() as Arc<dyn WireLane>),
                1 => {
                    if let Some(lane) = &self.second_lane {
                        Ok(lane.clone() as Arc<dyn WireLane>)
                    } else {
                        std::future::pending().await
                    }
                }
                _ => std::future::pending().await,
            }
        })
    }
}
struct Login;
impl infraternal_plugin_api::streams::Authority for Login {
    fn permits(&self) -> bool {
        true
    }
    fn cancelled(&self) -> Operation<'_, ()> {
        Box::pin(std::future::pending())
    }
}
struct Host;
impl infraternal_plugin_api::SocketHost for Host {
    fn user_id(&self) -> &'static str {
        "owner"
    }
    fn token_hash(&self) -> &'static str {
        "fixture"
    }
    fn authority(&self) -> Arc<dyn infraternal_plugin_api::streams::Authority> {
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

// The node fixture retains no metadata across a dropped capture leg: each
// preparation records precisely what a fresh node process would receive.
#[tokio::test]
async fn source_restart_reprepares_the_last_forwarded_size_instead_of_the_initial_size() {
    let (media, rx) = mpsc::channel(4);
    let (controls, mut received) = mpsc::channel(8);
    let node = Arc::new(Node {
        lane: Arc::new(Lane {
            media: tokio::sync::Mutex::new(rx),
            controls,
        }),
        opens: AtomicUsize::new(0),
        second_lane: None,
        floors: Mutex::new(Vec::new()),
        preparations: Mutex::new(Vec::new()),
        prepared: Notify::new(),
    });
    let server = DesktopServer::new(10);
    server.configure(true);
    let id = server
        .start(
            node.clone(),
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
            },
            Delivery::Reliable,
        )
        .await
        .unwrap();
    // Two startup controls establish the live native leg before the viewer.
    received.recv().await.unwrap();
    received.recv().await.unwrap();
    // Public attachment supplies a real socket authority rather than creating
    // capture or reaching into the producer's command queue.
    let viewer = server.attach(&id, &Host).unwrap();
    viewer.take_control().unwrap();
    viewer.resize(1920, 1080, 2000).unwrap();
    loop {
        let control = received.recv().await.unwrap();
        if matches!(
            decode_frame(&control).unwrap().frame,
            Frame::Desktop(Message::Size {
                width: 1920,
                height: 1080,
                ..
            })
        ) {
            break;
        }
    }
    drop(media);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while node.preparations.lock().unwrap().len() < 2 {
            node.prepared.notified().await;
        }
    })
    .await
    .unwrap();
    let restored = node.preparations.lock().unwrap()[1].size;
    server.stop(id, "owner").await.unwrap();
    server.configure(false);
    server.stopped().await;
    assert_eq!(
        (restored.width, restored.height),
        (1920, 1080),
        "node restart reverted the admitted viewer resize"
    );
    assert_eq!(
        (
            restored.canvas_width,
            restored.canvas_height,
            restored.backing_scale
        ),
        (960.0, 540.0, 2.0)
    );
}

fn video(sequence: u64) -> Bytes {
    let mut wire = Vec::new();
    infraternal_protocol::encode_frame_into(
        &Frame::Desktop(Message::Video {
            sequence,
            capture_ns: 1,
            keyframe: true,
            bytes: &[7; 100],
        }),
        &mut wire,
    )
    .unwrap();
    Bytes::from(wire)
}
#[tokio::test]
async fn source_restart_receives_the_server_video_floor_and_continues_live_media() {
    let (first, rx) = mpsc::channel(4);
    let (second, second_rx) = mpsc::channel(4);
    let (controls, mut received) = mpsc::channel(8);
    let node = Arc::new(Node {
        lane: Arc::new(Lane {
            media: tokio::sync::Mutex::new(rx),
            controls: controls.clone(),
        }),
        second_lane: Some(Arc::new(Lane {
            media: tokio::sync::Mutex::new(second_rx),
            controls,
        })),
        floors: Mutex::new(Vec::new()),
        opens: AtomicUsize::new(0),
        preparations: Mutex::new(Vec::new()),
        prepared: Notify::new(),
    });
    let server = DesktopServer::new(10);
    server.configure(true);
    let id = server
        .start(
            node.clone(),
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
            },
            Delivery::Reliable,
        )
        .await
        .unwrap();
    received.recv().await.unwrap();
    received.recv().await.unwrap();
    let mut viewer = server.attach(&id, &Host).unwrap();
    first.send(video(41)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), viewer.next())
            .await
            .unwrap()
            .unwrap()
            .sequence,
        41
    );
    drop(first);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while node.preparations.lock().unwrap().len() < 2 {
            node.prepared.notified().await;
        }
    })
    .await
    .unwrap();
    let floor = node.floors.lock().unwrap()[1];
    second.send(video(floor + 1)).await.unwrap();
    let resumed = tokio::time::timeout(std::time::Duration::from_secs(1), viewer.next()).await;
    server.stop(id, "owner").await.unwrap();
    server.configure(false);
    server.stopped().await;
    assert_eq!(
        floor, 41,
        "node process replacement lost the server-held sequence high water"
    );
    assert_eq!(resumed.unwrap().unwrap().sequence, 42);
}
