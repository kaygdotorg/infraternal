//! Independent review of the generic plugin host lifecycle and routing [D198, #108].
#![allow(clippy::expect_used, clippy::unwrap_used)] // Review fixtures fail immediately.
use bytes::Bytes;
use infraternal_plugin_api::{
    ActionDef, Effect, Operation, Permission, Plugin, PluginDescriptor, ReplySender, RoleDef,
    SocketHost, SubscriptionRegistry,
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use infraternal_server::plugins::{Dispatch, PluginRuntime, SocketPlugins};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

const ACTIONS: &[ActionDef] = &[ActionDef {
    target: infraternal_plugin_api::Target::Node,
    dry_run: infraternal_plugin_api::DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
    id: "probe.wait",
    summary: "Wait",
    instructions: &[],
    input: infraternal_plugin_api::SchemaRef("Empty"),
    output: infraternal_plugin_api::SchemaRef("Empty"),
    permission: Permission::One("authenticated"),
    effect: Effect::Read,
}];
const ROLES: &[RoleDef] = &[RoleDef {
    id: "server",
    requires: &["server"],
    default_enabled: true,
}];
static PROBE: PluginDescriptor = PluginDescriptor {
    defaults: &[],
    dependencies: &[],
    can_enable_components: &[],
    events: &[],
    streams: &[],
    id: "probe",
    api: 1,
    actions: ACTIONS,
    topics: &["probe"],
    settings: Some(infraternal_plugin_api::SchemaRef("{}")),
    roles: ROLES,
    max_frame_len: 64 * 1024,
    unavailable: br#"{"error":"probe unavailable"}"#,
    unavailable_event: br#"{"type":"error","error":"probe unavailable"}"#,
};
#[derive(Clone, Copy)]
enum Mode {
    /// The worker ends after its first request, as Mesh does on a 1 s reply timeout.
    ExitAfterFirst,
    /// The worker holds every request, as a slow database call does.
    Hold,
    /// A completed call is queued before the worker returns normally.
    AnswerFirst,
}
struct Probe {
    descriptor: &'static PluginDescriptor,
    mode: Mode,
}
impl Plugin for Probe {
    fn descriptor(&self) -> &'static PluginDescriptor {
        self.descriptor
    }
    fn run(
        &self,
        _host: Arc<dyn SocketHost>,
        mut requests: mpsc::Receiver<Bytes>,
        replies: ReplySender,
        _registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let mode = self.mode;
        Box::pin(async move {
            let first = requests.recv().await;
            if matches!(mode, Mode::Hold) {
                std::future::pending::<()>().await;
            } else if matches!(mode, Mode::AnswerFirst) {
                let first = first.unwrap();
                let Frame::Call { call_id, .. } = decode_muxed_frame(&first).unwrap().frame else {
                    panic!("expected call");
                };
                replies
                    .send(wire(&Frame::Result {
                        call_id,
                        ok: true,
                        json: b"{}",
                    }))
                    .await
                    .unwrap();
            }
        })
    }
}
struct Host;
impl SocketHost for Host {
    fn user_id(&self) -> &'static str {
        "owner"
    }
    fn token_hash(&self) -> &'static str {
        "hash"
    }
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        operation
    }
    fn fresh(&self, _now: i64) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
}

fn wire(frame: &Frame<'_>) -> Bytes {
    let mut encoded = Vec::new();
    encode_muxed_frame_into(0, frame, &mut encoded).unwrap();
    Bytes::from(encoded)
}
fn socket(plugins: Vec<Arc<dyn Plugin>>) -> (PluginRuntime, SocketPlugins) {
    let runtime = PluginRuntime::new(plugins, "server");
    let socket = SocketPlugins::new(runtime.clone(), Arc::new(Host));
    (runtime, socket)
}
/// Collect every frame the host would write to the browser within `wait`.
async fn delivered(socket: &mut SocketPlugins, wait: Duration) -> Vec<Bytes> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Some(reply)) = tokio::time::timeout_at(deadline, socket.recv()).await {
        let mut encode = Vec::new();
        if let Some(bytes) = socket.accept(reply, &mut encode) {
            out.push(bytes);
        }
    }
    out
}

/// A view whose worker ended must receive a final event; otherwise it hangs silently.
#[tokio::test]
async fn review_exited_worker_ends_its_subscriptions() {
    let (_runtime, mut socket) = socket(vec![Arc::new(Probe {
        descriptor: &PROBE,
        mode: Mode::ExitAfterFirst,
    })]);
    let mut encode = Vec::new();
    let subscribe = wire(&Frame::Subscribe {
        sub_id: 7,
        filter_json: br#"{"topic":"probe"}"#,
    });
    assert!(matches!(
        socket.dispatch(&subscribe, &mut encode),
        Dispatch::Queued
    ));
    let frames = delivered(&mut socket, Duration::from_millis(500)).await;
    assert!(
        frames.iter().any(|frame| matches!(
            decode_muxed_frame(frame).unwrap().frame,
            Frame::Event { sub_id: 7, .. }
        )),
        "worker exited, but subscription 7 got no final event: {frames:?}"
    );
}

/// Positive control: disabling ends a view without ending the socket (D199).
#[tokio::test]
async fn review_disable_withdraws_view_and_keeps_socket() {
    let (runtime, mut socket) = socket(vec![Arc::new(Probe {
        descriptor: &PROBE,
        mode: Mode::Hold,
    })]);
    let mut encode = Vec::new();
    let subscribe = wire(&Frame::Subscribe {
        sub_id: 3,
        filter_json: br#"{"topic":"probe"}"#,
    });
    assert!(matches!(
        socket.dispatch(&subscribe, &mut encode),
        Dispatch::Queued
    ));
    tokio::task::yield_now().await;
    assert_eq!(runtime.active_workers("probe"), 1);
    runtime.set_enabled("probe", false).await.unwrap();
    assert_eq!(runtime.active_workers("probe"), 0);
    let frames = delivered(&mut socket, Duration::from_millis(200)).await;
    assert_eq!(frames.len(), 1, "exactly one final event");
    assert!(matches!(
        decode_muxed_frame(&frames[0]).unwrap().frame,
        Frame::Event { sub_id: 3, .. }
    ));
    runtime.set_enabled("probe", true).await.unwrap();
    assert_eq!(runtime.active_workers("probe"), 0, "enable stays lazy");
    assert!(matches!(
        socket.dispatch(&subscribe, &mut encode),
        Dispatch::Queued
    ));
}
/// Disabling a plugin must answer a call it accepted; the browser otherwise waits forever.
#[tokio::test]
async fn review_disable_answers_inflight_call() {
    let (runtime, mut socket) = socket(vec![Arc::new(Probe {
        descriptor: &PROBE,
        mode: Mode::Hold,
    })]);
    let mut encode = Vec::new();
    let call = wire(&Frame::Call {
        call_id: 9,
        action_id: "probe.wait",
        input_json: b"{}",
    });
    assert!(matches!(
        socket.dispatch(&call, &mut encode),
        Dispatch::Queued
    ));
    tokio::task::yield_now().await;
    runtime.set_enabled("probe", false).await.unwrap();
    assert_eq!(
        runtime.active_workers("probe"),
        0,
        "abort and join on disable"
    );
    let frames = delivered(&mut socket, Duration::from_millis(500)).await;
    assert!(
        frames.iter().any(|frame| matches!(
            decode_muxed_frame(frame).unwrap().frame,
            Frame::Result {
                call_id: 9,
                ok: false,
                ..
            }
        )),
        "call 9 was accepted, then the plugin was disabled; no Result was delivered: {frames:?}"
    );
}

#[tokio::test]
async fn review_reenable_preserves_cancelled_calls_until_delivery() {
    let (runtime, mut socket) = socket(vec![Arc::new(Probe {
        descriptor: &PROBE,
        mode: Mode::Hold,
    })]);
    let mut encode = Vec::new();
    let request = |call_id| {
        wire(&Frame::Call {
            call_id,
            action_id: "probe.wait",
            input_json: b"{}",
        })
    };
    assert!(matches!(
        socket.dispatch(&request(21), &mut encode),
        Dispatch::Queued
    ));
    runtime.set_enabled("probe", false).await.unwrap();
    runtime.set_enabled("probe", true).await.unwrap();
    assert!(matches!(
        socket.dispatch(&request(22), &mut encode),
        Dispatch::Queued
    ));
    let ended = delivered(&mut socket, Duration::from_millis(100)).await;
    assert_eq!(ended.len(), 1);
    assert!(matches!(
        decode_muxed_frame(&ended[0]).unwrap().frame,
        Frame::Result {
            call_id: 21,
            ok: false,
            ..
        }
    ));
    runtime.set_enabled("probe", false).await.unwrap();
    let ended = delivered(&mut socket, Duration::from_millis(100)).await;
    assert_eq!(ended.len(), 1);
    assert!(matches!(
        decode_muxed_frame(&ended[0]).unwrap().frame,
        Frame::Result {
            call_id: 22,
            ok: false,
            ..
        }
    ));
}

#[tokio::test]
async fn review_completed_call_survives_normal_worker_exit() {
    let (_runtime, mut socket) = socket(vec![Arc::new(Probe {
        descriptor: &PROBE,
        mode: Mode::AnswerFirst,
    })]);
    assert!(matches!(
        socket.dispatch(
            &wire(&Frame::Call {
                call_id: 31,
                action_id: "probe.wait",
                input_json: b"{}"
            }),
            &mut Vec::new()
        ),
        Dispatch::Queued
    ));
    tokio::task::yield_now().await;
    let frames = delivered(&mut socket, Duration::from_millis(100)).await;
    assert_eq!(frames.len(), 1);
    assert!(matches!(
        decode_muxed_frame(&frames[0]).unwrap().frame,
        Frame::Result {
            call_id: 31,
            ok: true,
            ..
        }
    ));
}
static OTHER: PluginDescriptor = PluginDescriptor {
    defaults: &[],
    dependencies: &[],
    can_enable_components: &[],
    events: &[],
    streams: &[],
    id: "other",
    api: 1,
    actions: &[],
    topics: &["other"],
    settings: Some(infraternal_plugin_api::SchemaRef("{}")),
    roles: ROLES,
    max_frame_len: 64 * 1024,
    unavailable: br#"{"error":"other unavailable"}"#,
    unavailable_event: br#"{"type":"error","error":"other unavailable"}"#,
};

/// Undeclared topics belong to the core (for example `auth.recovery`), not to a plugin.
#[tokio::test]
async fn review_undeclared_topic_is_left_to_the_core() {
    let core = wire(&Frame::Subscribe {
        sub_id: 45,
        filter_json: br#"{"topic":"auth.recovery"}"#,
    });
    let (_runtime, mut single) = socket(vec![Arc::new(Probe {
        descriptor: &PROBE,
        mode: Mode::Hold,
    })]);
    let mut encode = Vec::new();
    let single_result = match single.dispatch(&core, &mut encode) {
        Dispatch::Unhandled => "unhandled",
        Dispatch::Queued => "queued to the plugin",
        Dispatch::Refused(_) => "refused",
    };
    let (_runtime, mut multiple) = socket(vec![
        Arc::new(Probe {
            descriptor: &PROBE,
            mode: Mode::Hold,
        }),
        Arc::new(Probe {
            descriptor: &OTHER,
            mode: Mode::Hold,
        }),
    ]);
    let multiple_result = match multiple.dispatch(&core, &mut encode) {
        Dispatch::Unhandled => "unhandled",
        Dispatch::Queued => "queued to a plugin",
        Dispatch::Refused(_) => "refused",
    };
    assert_eq!(
        (single_result, multiple_result),
        ("unhandled", "unhandled"),
        "a core topic must fall through to the core dispatcher"
    );
}

static CLAIMS_CORE: PluginDescriptor = PluginDescriptor {
    defaults: &[],
    dependencies: &[],
    can_enable_components: &[],
    events: &[],
    streams: &[],
    id: "core-claim",
    topics: &["auth.recovery"],
    ..OTHER
};
#[tokio::test]
async fn review_core_topic_remains_core_owned_even_when_declared() {
    let (_runtime, mut socket) = socket(vec![Arc::new(Probe {
        descriptor: &CLAIMS_CORE,
        mode: Mode::Hold,
    })]);
    let core = wire(&Frame::Subscribe {
        sub_id: 45,
        filter_json: br#"{"topic":"auth.recovery"}"#,
    });
    assert!(matches!(
        socket.dispatch(&core, &mut Vec::new()),
        Dispatch::Unhandled
    ));
    let (_runtime, mut empty) = self::socket(vec![]);
    assert!(matches!(
        empty.dispatch(&core, &mut Vec::new()),
        Dispatch::Unhandled
    ));
}
