//! Hosts idle-free layout subscriptions on the existing authorized control stream [16,183,198].
use crate::store::Store;
use bytes::Bytes;
use infraternal_plugin_api::{
    ActionDef, DefaultValue, Dependency, DryRun, Effect, Operation, Permission, Plugin,
    PluginDescriptor, ReplySender, RoleDef, SchemaRef, SettingDefault, SocketHost,
    SubscriptionRegistry, Target, subscription_current,
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::mpsc;

const APPLY: ActionDef = ActionDef {
    id: "canvas.layout.apply",
    summary: "Edit your canvas layout",
    instructions: &[
        "Subscribe to canvas.layout for its canonical revision.",
        "Send one intent with a unique op_id and base_revision.",
        "Retry the identical request after a lost response; apply committed events in revision order.",
    ],
    input: SchemaRef("canvas.layout.apply"),
    output: SchemaRef("canvas.layout.revision"),
    permission: Permission::One("authenticated"),
    effect: Effect::Write,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
};
const INITIALIZE: ActionDef = ActionDef {
    id: "canvas.layout.initialize",
    summary: "Recover a device's local canvas",
    instructions: &[
        "Keep the original local v1 document until this call succeeds.",
        "Send the document once with a unique op_id; retry the identical input if needed.",
        "Subscribe to canvas.layout; a differing local layout appears in recovered views.",
    ],
    input: SchemaRef("canvas.layout.initialize"),
    output: SchemaRef("canvas.layout.revision"),
    ..APPLY
};
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "canvas",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[APPLY, INITIALIZE],
    topics: &["canvas.layout"],
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":true}},"additionalProperties":false}"#,
    )),
    defaults: &[SettingDefault {
        id: "enabled",
        value: DefaultValue::Bool(true),
    }],
    roles: &[RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: true,
    }],
    dependencies: &[Dependency::ExistingServer],
    events: &[],
    streams: &[],
    can_enable_components: &[],
    max_frame_len: 64 * 1024,
    unavailable: br#"{"error":"canvas unavailable"}"#,
    unavailable_event: br#"{"type":"error","error":"canvas unavailable"}"#,
};
/// Metadata construction starts no task; workers exist only for active sockets.
pub struct CanvasPlugin(pub Store);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    topic: String,
}
#[derive(Clone)]
struct Subscription {
    id: u32,
    generation: u32,
    revision: Option<i64>,
}
impl Plugin for CanvasPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    #[allow(clippy::too_many_lines)]
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        mut requests: mpsc::Receiver<Bytes>,
        replies: ReplySender,
        registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let store = self.0.clone();
        Box::pin(async move {
            // Subscribe before the first read; coalesced notices cannot lose a commit.
            let mut changes = store.changes();
            let mut subscriptions = Vec::<Subscription>::new();
            loop {
                subscriptions.retain(|s| subscription_current(&registry, s.id, s.generation));
                let result = tokio::select! {
                    request = requests.recv() => {
                        let Some(request) = request else { break; };
                        let Ok(decoded) = decode_muxed_frame(&request) else { break; };
                        match decoded.frame {
                            Frame::Call { call_id,action_id,input_json } => host.authorized(Box::pin(async {
                                let result = match action_id {
                                    "canvas.layout.apply" => store.apply(host.user_id(),input_json).await,
                                    "canvas.layout.initialize" => store.initialize(host.user_id(),input_json).await,
                                    _ => Err(crate::store::Error),
                                };
                                let ok = result.is_ok();
                                let output = result.map_or_else(|_| json!({"error":"invalid canvas operation"}),|revision| json!({"revision":revision}));
                                let json = serde_json::to_vec(&output).map_err(|_|())?;
                                send(&replies,0,Frame::Result {call_id,ok,json:&json}).await
                            })).await,
                            Frame::Subscribe { sub_id,filter_json } => {
                                let generation = decoded.stream_id >> 1;
                                let valid = filter_json.len() <= 1024 && serde_json::from_slice::<Filter>(filter_json).is_ok_and(|f| f.topic == "canvas.layout");
                                if valid && subscription_current(&registry,sub_id,generation) {
                                    subscriptions.retain(|s| s.id != sub_id);
                                    subscriptions.push(Subscription{id:sub_id,generation,revision:None});
                                    host.authorized(Box::pin(publish(&store,host.user_id(),&replies,&registry,&mut subscriptions))).await
                                } else {
                                    host.authorized(Box::pin(send(&replies,generation<<1,Frame::Event{sub_id,event_json:br#"{"type":"error","error":"invalid canvas operation"}"#}))).await
                                }
                            }
                            _ => Ok(()),
                        }
                    }
                    notice = changes.changed(), if !subscriptions.is_empty() => {
                        if notice.is_err() { break; }
                        host.authorized(Box::pin(publish(&store,host.user_id(),&replies,&registry,&mut subscriptions))).await
                    }
                };
                if result.is_err() {
                    break;
                }
            }
        })
    }
}
async fn publish(
    store: &Store,
    account: &str,
    replies: &ReplySender,
    registry: &SubscriptionRegistry,
    subscriptions: &mut [Subscription],
) -> Result<(), ()> {
    for sub in subscriptions {
        for event in store.events(account, sub.revision).await.map_err(|_| ())? {
            if !subscription_current(registry, sub.id, sub.generation) {
                break;
            }
            let json = serde_json::to_vec(&event).map_err(|_| ())?;
            send(
                replies,
                sub.generation << 1,
                Frame::Event {
                    sub_id: sub.id,
                    event_json: &json,
                },
            )
            .await?;
            sub.revision = event.get("revision").and_then(Value::as_i64);
        }
    }
    Ok(())
}
async fn send(replies: &ReplySender, stream: u32, frame: Frame<'_>) -> Result<(), ()> {
    let mut wire = Vec::new();
    encode_muxed_frame_into(stream, &frame, &mut wire).map_err(|_| ())?;
    if wire.len() > DESCRIPTOR.max_frame_len {
        return Err(());
    }
    replies.send(Bytes::from(wire)).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_declares_server_only_actions_and_strict_subscription() {
        assert!(DESCRIPTOR.validate().is_ok());
        assert_eq!(DESCRIPTOR.actions.len(), 2);
        assert_eq!(DESCRIPTOR.topics, ["canvas.layout"]);
        assert!(
            serde_json::from_str::<Filter>(r#"{"topic":"canvas.layout","account":"other"}"#)
                .is_err()
        );
    }
}
