//! Adapts declared release actions and the `release.update` topic to the host's
//! cancellable, authenticated socket lifecycle [16,198]; #211 S3.
use crate::{
    descriptor::{DESCRIPTOR, UPDATE_STATUS, UPDATE_TOPIC},
    service::ReleaseService,
};
use bytes::Bytes;
use infraternal_plugin_api::{
    Operation, Plugin, PluginDescriptor, ReplySender, SocketHost, SubscriptionRegistry,
    subscription_current,
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Construction binds existing state and starts no timers, sockets or requests.
#[derive(Clone)]
pub struct ReleasePlugin(pub ReleaseService);

/// A subscription filter; only `{"topic":"release.update"}` is accepted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    topic: String,
}

/// One live `release.update` subscription and the last state it was sent, so an
/// unrelated wake-up (another server's updater in the same process) sends nothing.
struct Subscription {
    id: u32,
    generation: u32,
    sent: Option<Vec<u8>>,
}

impl Plugin for ReleasePlugin {
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
        let service = self.0.clone();
        Box::pin(async move {
            // Subscribe before the first read so no state change is missed. The watch
            // only wakes this worker while it has subscriptions: an idle socket costs nothing.
            let mut changes = crate::update::changes();
            let mut subscriptions = Vec::<Subscription>::new();
            loop {
                subscriptions.retain(|s| subscription_current(&registry, s.id, s.generation));
                let result = tokio::select! {
                    wire = requests.recv() => {
                        let Some(wire) = wire else { break };
                        let Ok(decoded) = decode_muxed_frame(&wire) else { break };
                        match decoded.frame {
                            Frame::Call { call_id, action_id, input_json } => {
                                host.authorized(Box::pin(async {
                                    let (ok, value) = match service
                                        .call(action_id, input_json, Some(host.as_ref()))
                                        .await
                                    {
                                        Ok(value) => (true, value),
                                        Err(error) => (false, serde_json::json!({"error":error})),
                                    };
                                    let json = serde_json::to_vec(&value).map_err(|_| ())?;
                                    send(&replies, 0, Frame::Result { call_id, ok, json: &json }).await
                                }))
                                .await
                            }
                            Frame::Subscribe { sub_id, filter_json } => {
                                let generation = decoded.stream_id >> 1;
                                let valid = filter_json.len() <= 1024
                                    && serde_json::from_slice::<Filter>(filter_json)
                                        .is_ok_and(|f| f.topic == UPDATE_TOPIC);
                                if valid && subscription_current(&registry, sub_id, generation) {
                                    subscriptions.retain(|s| s.id != sub_id);
                                    subscriptions.push(Subscription { id: sub_id, generation, sent: None });
                                    host.authorized(Box::pin(publish(&service, host.as_ref(), &replies, &registry, &mut subscriptions))).await
                                } else {
                                    host.authorized(Box::pin(send(&replies, generation << 1, Frame::Event {
                                        sub_id,
                                        event_json: br#"{"type":"error","error":"invalid release subscription"}"#,
                                    }))).await
                                }
                            }
                            _ => Ok(()),
                        }
                    }
                    notice = changes.changed(), if !subscriptions.is_empty() => {
                        if notice.is_err() { break; }
                        host.authorized(Box::pin(publish(&service, host.as_ref(), &replies, &registry, &mut subscriptions))).await
                    }
                };
                if result.is_err() {
                    break;
                }
            }
        })
    }
}

/// Send the current update state to every subscription that has not seen it yet.
/// The state goes through the same owner check as `release.update.status`; a refusal
/// is sent as an error event instead.
async fn publish(
    service: &ReleaseService,
    host: &dyn SocketHost,
    replies: &ReplySender,
    registry: &SubscriptionRegistry,
    subscriptions: &mut [Subscription],
) -> Result<(), ()> {
    let event = match service.call(UPDATE_STATUS.id, b"{}", Some(host)).await {
        Ok(update) => serde_json::json!({"type":"update","update":update}),
        Err(error) => serde_json::json!({"type":"error","error":error}),
    };
    let json = serde_json::to_vec(&event).map_err(|_| ())?;
    for sub in subscriptions {
        if sub.sent.as_deref() == Some(json.as_slice())
            || !subscription_current(registry, sub.id, sub.generation)
        {
            continue;
        }
        send(
            replies,
            sub.generation << 1,
            Frame::Event {
                sub_id: sub.id,
                event_json: &json,
            },
        )
        .await?;
        sub.sent = Some(json.clone());
    }
    Ok(())
}

/// Encode one frame on `stream` and queue it, refusing frames over the declared bound.
async fn send(replies: &ReplySender, stream: u32, frame: Frame<'_>) -> Result<(), ()> {
    let mut wire = Vec::with_capacity(256);
    encode_muxed_frame_into(stream, &frame, &mut wire).map_err(|_| ())?;
    if wire.len() > DESCRIPTOR.max_frame_len {
        return Err(());
    }
    replies.send(Bytes::from(wire)).await.map_err(|_| ())
}
