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
    id: "probe.wait",
    summary: "Wait",
    instructions: &[],
    input: "Empty",
    output: "Empty",
    permission: Permission::One("authenticated"),
    effect: Effect::Read,
}];
const ROLES: &[RoleDef] = &[RoleDef {
    id: "server",
    requires: &["server"],
    default_enabled: true,
}];
static PROBE: PluginDescriptor = PluginDescriptor {
    id: "probe",
    api: 1,
    actions: ACTIONS,
    topics: &["probe"],
    settings: "{}",
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
        _replies: ReplySender,
        _registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let mode = self.mode;
        Box::pin(async move {
            let _first = requests.recv().await;
            if matches!(mode, Mode::Hold) {
                std::future::pending::<()>().await;
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
