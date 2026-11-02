//! Exercises the production relay loop and its admission boundary with bounded transport fixtures [D104,D208,D232].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use bytes::Bytes;
use infraternal_plugin_api::{
    Operation,
    streams::{NodeHost, WireLane, WireStreamDef},
};
use infraternal_plugin_desktop::{
    relay,
    session::{AccessRules, Session},
};
use infraternal_protocol::{
    Frame, decode_frame,
    desktop::{Delivery, Input, Message},
    encode_frame_into,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, mpsc};

struct Owner;
impl AccessRules for Owner {
    fn may_view(&self, user: &str, _host: &str, owner: &str) -> bool {
        user == owner
    }
    fn may_control(&self, user: &str, _host: &str, owner: &str) -> bool {
        user == owner
    }
}
struct Host;
impl NodeHost for Host {
    fn id(&self) -> &'static str {
        "fixture-mac"
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
    fn call<'a>(
        &'a self,
        _action: &'a str,
        _input: &'a [u8],
    ) -> Operation<'a, Result<Vec<u8>, ()>> {
        Box::pin(async { Err(()) })
    }
    fn open<'a>(
        &'a self,
        _definition: &'static WireStreamDef,
        _opening: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>> {
        Box::pin(async { Err(()) })
    }
}
struct Lane {
    media: Mutex<mpsc::Receiver<Bytes>>,
    control: mpsc::Sender<Bytes>,
    retired: AtomicBool,
}
impl WireLane for Lane {
    fn stream_id(&self) -> u32 {
        2
    }
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>> {
        Box::pin(async { self.media.lock().await.recv().await.ok_or(()) })
    }
    fn send<'a>(&'a self, frame: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            self.control
                .send(Bytes::copy_from_slice(frame))
                .await
                .map_err(|_| ())
        })
    }
    fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }
}
#[tokio::test]
async fn relay_retains_video_after_viewer_drop_and_releases_input_on_stop() {
    let (session, mut commands) = Session::new(
        [146; 16],
        "fixture-mac".into(),
        "owner".into(),
        Arc::new(Owner),
    );
    let (media, packets) = mpsc::channel(1);
    let (control, mut replies) = mpsc::channel(8);
    let lane = Arc::new(Lane {
        media: Mutex::new(packets),
        control,
        retired: AtomicBool::new(false),
    });
    let mut viewer = session.attach("owner".into()).unwrap();
    viewer.take_control().unwrap();
    let retained = session.clone();
    let lease = lane.clone();
    let task = tokio::spawn(async move {
        relay::run(
            retained,
            Arc::new(Host),
            lease,
            Delivery::Reliable,
            &mut commands,
        )
        .await
    });
    let first = replies.recv().await.unwrap();
    assert_eq!(
        decode_frame(&first).unwrap().frame,
        Frame::Desktop(Message::Input(Input::Control { active: false }))
    );
    let repair = replies.recv().await.unwrap();
    assert_eq!(
        decode_frame(&repair).unwrap().frame,
        Frame::Desktop(Message::Repair { last_sequence: 0 })
    );
    let visible = replies.recv().await.unwrap();
    assert_eq!(
        decode_frame(&visible).unwrap().frame,
        Frame::Desktop(Message::Input(Input::Control { active: true })),
        "a reconnect restores an idle controller's visible state without replaying input"
    );
    let mut wire = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Video {
            sequence: 1,
            capture_ns: 2,
            keyframe: true,
            bytes: b"fixture",
        }),
        &mut wire,
    )
    .unwrap();
    media.send(Bytes::from(wire)).await.unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), viewer.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.bytes.as_ref(), b"fixture");
    drop(viewer);
    assert_eq!(
        session.retained_bytes(),
        7,
        "viewer drop ended server-held capture"
    );
    session.close();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
        Ok(())
    );
    let release = replies.recv().await.unwrap();
    assert_eq!(
        decode_frame(&release).unwrap().frame,
        Frame::Desktop(Message::Input(Input::Control { active: false }))
    );
    assert!(lane.retired.load(Ordering::Relaxed));
    assert_eq!(session.retained_bytes(), 0);
}
