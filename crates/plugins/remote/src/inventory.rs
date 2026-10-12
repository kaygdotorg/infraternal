//! Lists admitted terminal hosts through their existing authority source, with bounded mux replies and idle-free invalidation [16][198], #194.
use bytes::Bytes;
use infraternal_plugin_api::{
    ActionDef, Dependency, DryRun, Effect, Operation, Permission, Plugin, PluginDescriptor,
    ReplySender, RoleDef, SchemaRef, SocketHost, SubscriptionRegistry, subscription_current,
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// Public read action; the source repeats the terminal admission account filter.
pub const LIST: ActionDef = ActionDef {
    id: "remote.host.list",
    summary: "List admitted hosts",
    instructions: &[
        "Sign in to the existing server.",
        "Read admitted hosts, including offline machines.",
        "Continue with next until the account's inventory is complete.",
    ],
    input: SchemaRef("remote.host.list"),
    output: SchemaRef("remote.host.inventory"),
    target: infraternal_plugin_api::Target::Global,
    effect: Effect::Read,
    permission: Permission::One("authenticated"),
    dry_run: DryRun::Unsupported,
    opens: None,
};
/// Inventory remains readable when transport is unavailable; disabling this feature cancels all its socket work.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "remote-inventory",
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":true}},"additionalProperties":false}"#,
    )),
    defaults: &[infraternal_plugin_api::SettingDefault {
        id: "enabled",
        value: infraternal_plugin_api::DefaultValue::Bool(true),
    }],
    actions: &[LIST],
    topics: &["remote.hosts"],
    roles: &[RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: true,
    }],
    dependencies: &[Dependency::ExistingServer],
    max_frame_len: 64 * 1024,
    unavailable: br#"{"error":"action unavailable"}"#,
    unavailable_event: br#"{"type":"error","error":"action unavailable"}"#,
    ..super::DESCRIPTOR
};
/// Coalesced post-commit invalidations; no timer or retained task.
#[derive(Clone)]
pub struct Changes(watch::Sender<()>);
impl Default for Changes {
    fn default() -> Self {
        Self(watch::channel(()).0)
    }
}
impl Changes {
    /// Wake readers only after a visible change has committed.
    pub fn publish(&self) {
        self.0.send_replace(());
    }
    /// Subscribe before reading to avoid missing concurrent admission or removal.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.0.subscribe()
    }
}
/// Bounded input to the account inventory; cursors convey position, never account identity.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    pub after: Option<String>,
}
/// Reject arrays, unknown fields and unbounded cursors before any storage access.
#[must_use]
pub fn decode_list(input: &[u8]) -> Option<ListRequest> {
    if input.len() > 1024 || input.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return None;
    }
    let request: ListRequest = serde_json::from_slice(input).ok()?;
    if request.after.as_ref().is_some_and(|after| {
        after.len() != 36
            || !after.bytes().enumerate().all(|(offset, byte)| {
                if matches!(offset, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                }
            })
    }) {
        return None;
    }
    Some(request)
}
/// Existing server records and live transport registry, supplied without exposing credentials.
pub trait Inventory: Send + Sync {
    fn list<'a>(
        &'a self,
        account: &'a str,
        after: Option<&'a str>,
    ) -> Operation<'a, Result<Value, ()>>;
    fn changes(&self) -> watch::Receiver<()>;
    fn observe(
        &self,
        channel: Arc<dyn infraternal_plugin_api::node_channel::NodeChannel>,
    ) -> Operation<'_, ()>;
}
/// One bounded socket worker per connection; terminal dispatch never awaits a database read.
pub struct InventoryPlugin(pub Arc<dyn Inventory>);
impl Plugin for InventoryPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn node_connected(
        &self,
        channel: Arc<dyn infraternal_plugin_api::node_channel::NodeChannel>,
    ) -> Option<Operation<'static, ()>> {
        if channel.is_server() {
            return None;
        }
        let source = self.0.clone();
        Some(Box::pin(async move {
            source.observe(channel).await;
        }))
    }
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        mut requests: mpsc::Receiver<Bytes>,
        replies: ReplySender,
        registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let source = self.0.clone();
        Box::pin(async move {
            let mut changes = source.changes();
            let mut subscriptions = Vec::<(u32, u32)>::new();
            loop {
                subscriptions
                    .retain(|(id, generation)| subscription_current(&registry, *id, *generation));
                let result = tokio::select! {
                    request = requests.recv() => {
                        let Some(request) = request else { break; };
                        let Ok(decoded) = decode_muxed_frame(&request) else { break; };
                        match decoded.frame {
                            Frame::Call { call_id, action_id, input_json } => {
                                let input = decode_list(input_json);
                                let after = input.as_ref().and_then(|request| request.after.as_deref());
                                let mut output = Err(());
                                if action_id == LIST.id && input.is_some() {
                                    let read = host.authorized(Box::pin(async { output = source.list(host.user_id(), after).await; Ok(()) })).await;
                                    if read.is_err() { break; }
                                }
                                send(&replies, Frame::Result { call_id, ok: output.is_ok(), json: & serde_json::to_vec(&output.unwrap_or_else(|()| json!({"error":"inventory unavailable"})) ).unwrap_or_default() }).await
                            }
                            Frame::Subscribe { sub_id, .. } => {
                                let generation = decoded.stream_id >> 1;
                                if subscription_current(&registry, sub_id, generation) {
                                    subscriptions.retain(|(id, _)| *id != sub_id);
                                    subscriptions.push((sub_id, generation));
                                    send(&replies, Frame::Event { sub_id, event_json: br#"{"type":"changed"}"# }).await
                                } else { Ok(()) }
                            }
                            _ => Ok(()),
                        }
                    }
                    notice = changes.changed(), if !subscriptions.is_empty() => {
                        if notice.is_err() { break; }
                        host.authorized(Box::pin(async {
                            for (id, generation) in &subscriptions {
                                if subscription_current(&registry, *id, *generation) {
                                    send(&replies, Frame::Event { sub_id: *id, event_json: br#"{"type":"changed"}"# }).await?;
                                }
                            }
                            Ok(())
                        })).await
                    }
                };
                if result.is_err() {
                    break;
                }
            }
        })
    }
}
async fn send(replies: &ReplySender, frame: Frame<'_>) -> Result<(), ()> {
    let mut wire = Vec::new();
    encode_muxed_frame_into(0, &frame, &mut wire).map_err(|_| ())?;
    if wire.len() > DESCRIPTOR.max_frame_len {
        return Err(());
    }
    replies.send(Bytes::from(wire)).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn list_input_refuses_parallel_authority_and_noncanonical_cursors() {
        assert!(decode_list(b"{}").is_some());
        assert!(decode_list(br#"{"after":"00000000-0000-0000-0000-000000000042"}"#).is_some());
        for invalid in [
            br#"{"account":"other"}"#.as_slice(),
            b"[]",
            br#"{"after":"wrong"}"#,
            br#"{"after":4}"#,
            br#"{"after":"AAAAAAAA-0000-0000-0000-000000000042"}"#,
        ] {
            assert!(decode_list(invalid).is_none());
        }
        assert!(decode_list(&[b' '; 1025]).is_none());
    }
}
