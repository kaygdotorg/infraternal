//! Checks socket authority withdrawal and bounded native ingress across viewer lifetimes [D198,D208].
use super::*;
use crate::socket_authority::SocketAuthority;
use infraternal_plugin_api::{Operation, streams::Authority};
struct Host(Arc<SocketAuthority>, std::sync::atomic::AtomicBool);
impl SocketHost for Host {
    fn user_id(&self) -> &'static str {
        "owner"
    }
    fn token_hash(&self) -> &'static str {
        "fixture"
    }
    fn authority(&self) -> Arc<dyn Authority> {
        self.0.clone()
    }
    fn retire(&self) {
        self.0.withdraw();
    }
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            if !self.1.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(());
            }
            operation.await
        })
    }
    fn fresh(&self, _now: i64) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async { self.0.permits() })
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
}
#[tokio::test]
async fn socket_drop_withdraws_before_the_last_host_reference_disappears() {
    let host: Arc<Host> = Arc::new_cyclic(|weak| {
        Host(
            SocketAuthority::admitted(weak.clone()),
            std::sync::atomic::AtomicBool::new(true),
        )
    });
    let authority = host.0.clone();
    let socket = SocketPlugins::new(PluginRuntime::new(vec![], "server"), host.clone());
    assert!(authority.permits());
    drop(socket);
    assert!(
        !authority.permits(),
        "retained host reference kept a dropped login authorized"
    );
    authority.cancelled().await;
    assert!(!host.live().await);
}

#[tokio::test]
async fn forwarding_checks_the_originating_host_without_retaining_it() {
    let host: Arc<Host> = Arc::new_cyclic(|weak| {
        Host(
            SocketAuthority::admitted(weak.clone()),
            std::sync::atomic::AtomicBool::new(true),
        )
    });
    let authority = host.0.clone();
    let polled = std::sync::atomic::AtomicBool::new(false);
    host.1.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(authority.permits());
    assert_eq!(
        authority
            .authorized(Box::pin(async {
                polled.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }))
            .await,
        Err(())
    );
    assert!(!polled.load(std::sync::atomic::Ordering::Relaxed));
    assert_eq!(Arc::strong_count(&host), 1);
    let weak = Arc::downgrade(&host);
    drop(host);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        authority.authorized(Box::pin(async { Ok(()) })).await,
        Err(())
    );
}

#[cfg(feature = "desktop")]
pub(crate) struct NativeEcho(pub(crate) usize);
#[cfg(feature = "desktop")]
impl Plugin for NativeEcho {
    fn descriptor(&self) -> &'static infraternal_plugin_api::PluginDescriptor {
        &infraternal_plugin_desktop::server_manifest::DESCRIPTOR
    }
    fn run(
        &self,
        _: Arc<dyn SocketHost>,
        mut requests: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        replies: ReplySender,
        _: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let length = self.0;
        Box::pin(async move {
            while let Some(wire) = requests.recv().await {
                let decoded = decode_muxed_frame(&wire).unwrap();
                let mut output = Vec::new();
                let body = vec![7; length];
                encode_muxed_frame_into(
                    decoded.stream_id,
                    &Frame::Desktop(infraternal_protocol::desktop::Message::Video {
                        sequence: 1,
                        capture_ns: 1,
                        keyframe: true,
                        bytes: &body,
                    }),
                    &mut output,
                )
                .unwrap();
                if replies
                    .send_and_wait(bytes::Bytes::from(output))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    }
}
#[cfg(feature = "desktop")]
#[tokio::test]
async fn native_ingress_preserves_a_valid_small_command_burst_before_worker_poll() {
    use infraternal_protocol::desktop::{Delivery, Message};
    let host: Arc<Host> = Arc::new_cyclic(|weak| {
        Host(
            SocketAuthority::admitted(weak.clone()),
            std::sync::atomic::AtomicBool::new(true),
        )
    });
    let runtime = PluginRuntime::new(vec![Arc::new(NativeEcho(8))], "server");
    runtime.set_enabled("desktop", true).await.unwrap();
    let mut socket = SocketPlugins::new(runtime, host);
    socket.set_peer_capabilities(8);
    let mut encode = Vec::new();
    let mut opening = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Desktop(Message::Attach {
            session_id: &[3; 16],
            delivery: Delivery::Reliable,
        }),
        &mut opening,
    )
    .unwrap();
    assert!(matches!(
        socket.dispatch(&bytes::Bytes::from(opening), &mut encode),
        Dispatch::Queued
    ));
    let reply = socket.recv().await.unwrap();
    assert!(socket.accept(reply, &mut encode).is_some());
    // A single socket read can already contain all these canonical small
    // commands. The plugin task has not been polled between admissions.
    for index in 0..16 {
        let mut command = Vec::new();
        encode_muxed_frame_into(
            1,
            &Frame::Desktop(Message::Size {
                width: 640 + index * 2,
                height: 480,
                density_milli: 1000,
            }),
            &mut command,
        )
        .unwrap();
        assert!(
            matches!(
                socket.dispatch(&bytes::Bytes::from(command), &mut encode),
                Dispatch::Queued
            ),
            "canonical native command {index} retired the stream at generic socket ingress"
        );
    }
    for _ in 0..16 {
        let reply = socket.recv().await.unwrap();
        assert!(socket.accept(reply, &mut encode).is_some());
    }
    assert!(!socket.native[&1].closed);
    let bound = socket.entries[0].requests.max_capacity();
    assert_eq!(
        bound,
        infraternal_plugin_desktop::server_manifest::DESCRIPTOR
            .streams
            .iter()
            .find_map(|definition| definition.wire)
            .unwrap()
            .max_streams
    );
    let mut command = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Desktop(Message::Size {
            width: 640,
            height: 480,
            density_milli: 1000,
        }),
        &mut command,
    )
    .unwrap();
    let command = bytes::Bytes::from(command);
    for _ in 0..bound {
        assert!(matches!(
            socket.dispatch(&command, &mut encode),
            Dispatch::Queued
        ));
    }
    assert!(matches!(
        socket.dispatch(&command, &mut encode),
        Dispatch::Refused(_)
    ));
}

#[cfg(feature = "desktop")]
#[tokio::test]
async fn declared_native_streams_require_negotiation_preserve_bulk_bytes_and_withdraw() {
    use infraternal_protocol::desktop::{Delivery, Message};
    let host: Arc<Host> = Arc::new_cyclic(|weak| {
        Host(
            SocketAuthority::admitted(weak.clone()),
            std::sync::atomic::AtomicBool::new(true),
        )
    });
    let runtime = PluginRuntime::new(vec![Arc::new(NativeEcho(100 * 1024))], "server");
    runtime.set_enabled("desktop", true).await.unwrap();
    let mut socket = SocketPlugins::new(runtime.clone(), host);
    let mut opening = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Desktop(Message::Attach {
            session_id: &[3; 16],
            delivery: Delivery::Reliable,
        }),
        &mut opening,
    )
    .unwrap();
    let opening = bytes::Bytes::from(opening);
    let mut encode = Vec::new();
    assert!(matches!(
        socket.dispatch(&opening, &mut encode),
        Dispatch::Refused(_)
    ));
    socket.set_peer_capabilities(8);
    assert!(matches!(
        socket.dispatch(&opening, &mut encode),
        Dispatch::Queued
    ));
    assert!(socket.owns_stream(1));
    let reply = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv())
        .await
        .unwrap()
        .unwrap();
    let wire = socket.accept(reply, &mut encode).unwrap();
    assert!(wire.len() > 64 * 1024);
    assert!(
        matches!(decode_muxed_frame(&wire).unwrap().frame, Frame::Desktop(Message::Video { bytes, .. }) if bytes.len() == 100 * 1024)
    );
    drop(wire);
    runtime.set_enabled("desktop", false).await.unwrap();
    let withdrawal = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv())
        .await
        .unwrap()
        .unwrap();
    let closed = socket.accept(withdrawal, &mut encode).unwrap();
    assert!(matches!(
        decode_muxed_frame(&closed).unwrap().frame,
        Frame::Close { .. }
    ));
    assert!(matches!(
        socket.dispatch(&opening, &mut encode),
        Dispatch::Refused(_)
    ));
}

#[cfg(feature = "desktop")]
struct WindowNode(std::sync::atomic::AtomicBool);
#[cfg(feature = "desktop")]
impl infraternal_plugin_api::streams::NodeHost for WindowNode {
    fn id(&self) -> &'static str {
        "window-node"
    }
    fn owner_id(&self) -> &'static str {
        "owner"
    }
    fn permits(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            if self.permits() {
                operation.await
            } else {
                Err(())
            }
        })
    }
    fn call<'a>(&'a self, _: &'a str, input: &'a [u8]) -> Operation<'a, Result<Vec<u8>, ()>> {
        Box::pin(async move {
            let input: serde_json::Value = serde_json::from_slice(input).unwrap();
            Ok(serde_json::to_vec(&serde_json::json!({"session_id":input["session_id"]})).unwrap())
        })
    }
    fn open<'a>(
        &'a self,
        _: &'static infraternal_plugin_api::streams::WireStreamDef,
        _: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn infraternal_plugin_api::streams::WireLane>, ()>> {
        Box::pin(async move {
            let mut wire = Vec::new();
            infraternal_protocol::encode_frame_into(
                &Frame::Desktop(infraternal_protocol::desktop::Message::Video {
                    sequence: 1,
                    capture_ns: 1,
                    keyframe: true,
                    bytes: &[7; 100],
                }),
                &mut wire,
            )
            .unwrap();
            Ok(Arc::new(WindowLane(tokio::sync::Mutex::new(Some(
                bytes::Bytes::from(wire),
            ))))
                as Arc<dyn infraternal_plugin_api::streams::WireLane>)
        })
    }
}
#[cfg(feature = "desktop")]
struct WindowLane(tokio::sync::Mutex<Option<bytes::Bytes>>);
#[cfg(feature = "desktop")]
impl infraternal_plugin_api::streams::WireLane for WindowLane {
    fn stream_id(&self) -> u32 {
        2
    }
    fn receive(&self) -> Operation<'_, Result<bytes::Bytes, ()>> {
        Box::pin(async move {
            if let Some(wire) = self.0.lock().await.take() {
                Ok(wire)
            } else {
                std::future::pending().await
            }
        })
    }
    fn send<'a>(&'a self, _: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async { Ok(()) })
    }
    fn retire(&self) {}
}
#[cfg(feature = "desktop")]
#[tokio::test]
async fn queued_viewer_video_is_withdrawn_when_its_host_access_ends() {
    use infraternal_plugin_desktop::{
        protocol::{Size, Start, Target},
        server::DesktopServer,
    };
    use infraternal_protocol::desktop::{Delivery, Message};
    let host: Arc<Host> = Arc::new_cyclic(|weak| {
        Host(
            SocketAuthority::admitted(weak.clone()),
            std::sync::atomic::AtomicBool::new(true),
        )
    });
    let desktop = Arc::new(DesktopServer::new(10));
    let runtime = PluginRuntime::new(vec![desktop.clone()], "server");
    runtime.set_enabled("desktop", true).await.unwrap();
    let node = Arc::new(WindowNode(std::sync::atomic::AtomicBool::new(true)));
    let id = desktop
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
    let mut socket = SocketPlugins::new(runtime.clone(), host);
    socket.set_peer_capabilities(8);
    let mut opening = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Desktop(Message::Attach {
            session_id: &id,
            delivery: Delivery::Reliable,
        }),
        &mut opening,
    )
    .unwrap();
    let mut encode = Vec::new();
    assert!(matches!(
        socket.dispatch(&bytes::Bytes::from(opening), &mut encode),
        Dispatch::Queued
    ));
    let video = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv())
        .await
        .unwrap()
        .unwrap();
    node.0.store(false, std::sync::atomic::Ordering::Release);
    assert!(
        socket.accept(video, &mut encode).is_none(),
        "retained video crossed withdrawn host access"
    );
    runtime.set_enabled("desktop", false).await.unwrap();
}

#[cfg(feature = "desktop")]
#[tokio::test]
async fn private_event_withdrawal_generation_cannot_collide_with_public_native_stream() {
    use infraternal_protocol::desktop::{Delivery, Message};
    let host: Arc<Host> = Arc::new_cyclic(|weak| {
        Host(
            SocketAuthority::admitted(weak.clone()),
            std::sync::atomic::AtomicBool::new(true),
        )
    });
    let runtime = PluginRuntime::new(vec![Arc::new(NativeEcho(100 * 1024))], "server");
    runtime.set_enabled("desktop", true).await.unwrap();
    let mut socket = SocketPlugins::new(runtime, host);
    socket.set_peer_capabilities(8);
    let mut encode = Vec::new();
    let mut opening = Vec::new();
    encode_muxed_frame_into(
        3,
        &Frame::Desktop(Message::Attach {
            session_id: &[1; 16],
            delivery: Delivery::Reliable,
        }),
        &mut opening,
    )
    .unwrap();
    assert!(matches!(
        socket.dispatch(&bytes::Bytes::from(opening), &mut encode),
        Dispatch::Queued
    ));
    // Subscription generations are a private routing namespace. Its odd
    // withdrawal packet can have the same numeric header as a public wire lane.
    socket.entries[0].registry[0].store((1_u64 << 32) | 0x4d, std::sync::atomic::Ordering::Release);
    let mut event = Vec::new();
    encode_muxed_frame_into(
        3,
        &Frame::Event {
            sub_id: 77,
            event_json: b"{}",
        },
        &mut event,
    )
    .unwrap();
    let withdrawal = SocketReply::Withdrawal(infraternal_plugin_api::PluginReply {
        plugin_id: "desktop",
        epoch: socket.entries[0].reply_epoch,
        wire: bytes::Bytes::from(event),
        authority: None,
    });
    let delivered = socket
        .accept(withdrawal, &mut encode)
        .expect("public native identity consumed a private subscription generation");
    let decoded = decode_muxed_frame(&delivered).unwrap();
    assert_eq!(decoded.stream_id, 0);
    assert!(matches!(decoded.frame, Frame::Event { sub_id: 77, .. }));
}

#[cfg(feature = "desktop")]
#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep two viewer admissions, refusal and sibling control in one ordered scenario.
async fn duplicate_native_opening_retires_only_that_viewer_and_keeps_its_sibling() {
    use infraternal_plugin_desktop::{
        protocol::{Size, Start, Target},
        server::DesktopServer,
    };
    use infraternal_protocol::desktop::{Delivery, Message};
    let host: Arc<Host> = Arc::new_cyclic(|weak| {
        Host(
            SocketAuthority::admitted(weak.clone()),
            std::sync::atomic::AtomicBool::new(true),
        )
    });
    let desktop = Arc::new(DesktopServer::new(10));
    let runtime = PluginRuntime::new(vec![desktop.clone()], "server");
    runtime.set_enabled("desktop", true).await.unwrap();
    let node = Arc::new(WindowNode(std::sync::atomic::AtomicBool::new(true)));
    let id = desktop
        .start(
            node,
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
    let mut socket = SocketPlugins::new(runtime.clone(), host);
    socket.set_peer_capabilities(8);
    let mut encode = Vec::new();
    let mut first = bytes::Bytes::new();
    for stream in [1, 3] {
        let mut opening = Vec::new();
        encode_muxed_frame_into(
            stream,
            &Frame::Desktop(Message::Attach {
                session_id: &id,
                delivery: Delivery::Reliable,
            }),
            &mut opening,
        )
        .unwrap();
        let opening = bytes::Bytes::from(opening);
        if stream == 1 {
            first = opening.clone();
        }
        assert!(matches!(
            socket.dispatch(&opening, &mut encode),
            Dispatch::Queued
        ));
        let video = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv())
            .await
            .unwrap()
            .unwrap();
        let video = socket.accept(video, &mut encode).unwrap();
        assert_eq!(decode_muxed_frame(&video).unwrap().stream_id, stream);
        drop(video);
    }
    assert!(
        matches!(socket.dispatch(&first, &mut encode), Dispatch::Refused(_)),
        "duplicate opening reached and retired the whole viewer worker"
    );
    assert_eq!(socket.active_streams(), 1);
    let mut control = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Call {
            call_id: 7,
            action_id: "desktop.session.control",
            input_json: br#"{"stream_id":3}"#,
        },
        &mut control,
    )
    .unwrap();
    assert!(matches!(
        socket.dispatch(&bytes::Bytes::from(control), &mut encode),
        Dispatch::Queued
    ));
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let reply = socket.recv().await.unwrap();
            if let Some(wire) = socket.accept(reply, &mut encode)
                && let Frame::Result { call_id: 7, ok, .. } =
                    decode_muxed_frame(&wire).unwrap().frame
            {
                assert!(
                    ok,
                    "duplicate opening withdrew the sibling's current viewer access"
                );
                break;
            }
        }
    })
    .await
    .unwrap();
    runtime.set_enabled("desktop", false).await.unwrap();
}

#[cfg(feature = "desktop")]
async fn echo_socket(payload: usize) -> SocketPlugins {
    let host: Arc<Host> = Arc::new_cyclic(|weak| {
        Host(
            SocketAuthority::admitted(weak.clone()),
            std::sync::atomic::AtomicBool::new(true),
        )
    });
    let runtime = PluginRuntime::new(vec![Arc::new(NativeEcho(payload))], "server");
    runtime.set_enabled("desktop", true).await.unwrap();
    let mut socket = SocketPlugins::new(runtime, host);
    socket.set_peer_capabilities(8);
    let mut opening = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Desktop(infraternal_protocol::desktop::Message::Attach {
            session_id: &[1; 16],
            delivery: infraternal_protocol::desktop::Delivery::Reliable,
        }),
        &mut opening,
    )
    .unwrap();
    assert!(matches!(
        socket.dispatch(&bytes::Bytes::from(opening), &mut Vec::new()),
        Dispatch::Queued
    ));
    socket
}
#[cfg(feature = "desktop")]
#[tokio::test]
async fn native_viewer_accepts_valid_two_mebibyte_access_units_with_the_frozen_protocol_bound() {
    let mut socket = echo_socket(2 * 1024 * 1024).await;
    let reply = socket.recv().await.unwrap();
    let video = socket
        .accept(reply, &mut Vec::new())
        .expect("valid access unit below frozen MAX_FRAME_LEN was silently discarded");
    assert!(
        matches!(decode_muxed_frame(&video).unwrap().frame, Frame::Desktop(infraternal_protocol::desktop::Message::Video { bytes, .. }) if bytes.len() == 2 * 1024 * 1024)
    );
}
#[cfg(feature = "desktop")]
#[tokio::test]
async fn native_viewer_wrong_reply_direction_closes_only_its_reserved_stream() {
    let mut socket = echo_socket(100).await;
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Desktop(infraternal_protocol::desktop::Message::Size {
            width: 960,
            height: 600,
            density_milli: 2000,
        }),
        &mut wire,
    )
    .unwrap();
    let reply = SocketReply::Plugin(infraternal_plugin_api::PluginReply {
        plugin_id: "desktop",
        epoch: socket.entries[0].reply_epoch,
        wire: bytes::Bytes::from(wire),
        authority: None,
    });
    let close = socket
        .accept(reply, &mut Vec::new())
        .expect("wrong-direction reply must retire its viewer explicitly");
    assert!(matches!(
        decode_muxed_frame(&close).unwrap().frame,
        Frame::Close { .. }
    ));
    assert_eq!(socket.active_streams(), 0);
    assert!(!socket.entries[0].requests.is_closed());
}
