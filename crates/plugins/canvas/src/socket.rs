//! Hosts idle-free layout subscriptions on the existing authorized control stream [16,183,198].
use crate::store::{LayoutStore, Refusal};
use bytes::Bytes;
use infraternal_plugin_api::{
    ActionDef, DefaultValue, Dependency, DryRun, Effect, Operation, Permission, Plugin,
    PluginDescriptor, ReplySender, RoleDef, SchemaRef, SettingDefault, SocketHost,
    SubscriptionRegistry, Target, subscription_current,
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use serde::Deserialize;
use serde_json::Value;
use std::borrow::Cow;
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
    api_scope: None,
    fresh_passkey: false,
};
const INITIALIZE: ActionDef = ActionDef {
    id: "canvas.layout.initialize",
    summary: "Recover a device's local canvas",
    instructions: &[
        "Keep the original local v1 document until this call succeeds.",
        "Send the document once with a unique op_id; retry the identical input if needed.",
        "Subscribe to canvas.layout; missing targets merge into the shared layout.",
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
pub struct CanvasPlugin(pub Arc<dyn LayoutStore>);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    topic: String,
}
/// Borrow ordinary lifetime labels; JSON escapes need owned decoding, never a second document tree.
#[derive(Deserialize)]
struct SessionBinding<'a> {
    #[serde(default, borrow)]
    session_incarnation: Cow<'a, str>,
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
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        mut requests: mpsc::Receiver<Bytes>,
        replies: ReplySender,
        registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let store = Arc::clone(&self.0);
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
                                // Admission precedes receipts too: an old session must not learn or replay a result.
                                if let Some(incarnation) = host.session_incarnation() {
                                    let binding = serde_json::from_slice::<SessionBinding<'_>>(input_json).ok();
                                    if binding.as_ref().map(|v| v.session_incarnation.as_ref()) != Some(incarnation) {
                                        // Refusals before storage admission still need a safe diagnostic, never the binding itself.
                                        tracing::warn!(intent = "unbound", initialize = action_id == "canvas.layout.initialize", input_bytes = input_json.len(), reason = "layout_session_changed", "canvas layout refused");
                                        return send(&replies, 0, Frame::Result { call_id, ok: false, json: br#"{"error":"layout session changed","reason":"layout_session_changed"}"# }).await;
                                    }
                                }
                                let result = match action_id {
                                    "canvas.layout.apply" | "canvas.layout.initialize" => store.call(action_id=="canvas.layout.initialize",host.user_id(),input_json).await,
                                    _=>Err(Refusal::InvalidRequest),
                                };
                                let mut output = Vec::new();
                                let (ok, json) = result_json(result, &mut output)?;
                                send(&replies,0,Frame::Result {call_id,ok,json}).await
                            })).await,
                            Frame::Subscribe { sub_id,filter_json } => {
                                let generation = decoded.stream_id >> 1;
                                let valid = filter_json.len() <= 1024 && serde_json::from_slice::<Filter>(filter_json).is_ok_and(|f| f.topic == "canvas.layout");
                                if valid && subscription_current(&registry,sub_id,generation) {
                                    subscriptions.retain(|s| s.id != sub_id);
                                    subscriptions.push(Subscription{id:sub_id,generation,revision:None});
                                    host.authorized(Box::pin(publish(store.as_ref(),host.user_id(),&replies,&registry,&mut subscriptions))).await
                                } else {
                                    host.authorized(Box::pin(send(&replies,generation<<1,Frame::Event{sub_id,event_json:br#"{"type":"error","error":"invalid canvas operation"}"#}))).await
                                }
                            }
                            _ => Ok(()),
                        }
                    }
                    notice = changes.changed(), if !subscriptions.is_empty() => {
                        if notice.is_err() { break; }
                        host.authorized(Box::pin(publish(store.as_ref(),host.user_id(),&replies,&registry,&mut subscriptions))).await
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
    store: &dyn LayoutStore,
    account: &str,
    replies: &ReplySender,
    registry: &SubscriptionRegistry,
    subscriptions: &mut [Subscription],
) -> Result<(), ()> {
    for sub in subscriptions {
        for event in store.events(account, sub.revision).await? {
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

/// Encodes a revision or a fixed public refusal, never internal storage errors or caller text.
fn result_json(result: Result<i64, Refusal>, output: &mut Vec<u8>) -> Result<(bool, &[u8]), ()> {
    match result {
        Ok(revision) => {
            output.extend_from_slice(b"{\"revision\":");
            serde_json::to_writer(&mut *output, &revision).map_err(|_| ())?;
            output.push(b'}');
            Ok((true, output))
        }
        Err(refusal) => {
            let (reason, error) = refusal.public();
            serde_json::to_writer(
                &mut *output,
                &serde_json::json!({"error": error, "reason": reason}),
            )
            .map_err(|_| ())?;
            Ok((false, output))
        }
    }
}

/// Checks shared metadata, authenticated label parsing and compact result encoding.
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
    #[test]
    fn session_binding_accepts_json_string_escapes() {
        assert!(
            serde_json::from_slice::<SessionBinding<'_>>(
                br#"{"session_incarnation":"\u0041AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            )
            .is_ok()
        );
    }
    #[test]
    fn ordinary_session_binding_borrows_and_escaped_binding_decodes_identically() {
        let plain = serde_json::from_slice::<SessionBinding<'_>>(
            br#"{"session_incarnation":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap();
        let escaped = serde_json::from_slice::<SessionBinding<'_>>(
            br#"{"session_incarnation":"\u0041AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap();
        assert!(matches!(plain.session_incarnation, Cow::Borrowed(_)));
        assert_eq!(plain.session_incarnation, escaped.session_incarnation);
    }
    /// Keeps successful receipts compatible and checks the safe refusal wire fields.
    #[test]
    fn result_json_preserves_both_wire_shapes() {
        let mut output = Vec::new();
        let (ok, json) = result_json(Ok(9), &mut output).unwrap();
        assert!(ok);
        assert_eq!(json, br#"{"revision":9}"#);
        output.clear();
        let (ok, json) = result_json(Err(Refusal::InvalidRequest), &mut output).unwrap();
        assert!(!ok);
        assert_eq!(
            json,
            br#"{"error":"The layout request is invalid.","reason":"invalid_request"}"#
        );
    }
}
