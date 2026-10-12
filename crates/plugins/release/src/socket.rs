//! Adapts declared release actions to the host's cancellable, authenticated socket lifecycle [16,198].
use crate::{descriptor::DESCRIPTOR, service::ReleaseService};
use bytes::Bytes;
use infraternal_plugin_api::{
    Operation, Plugin, PluginDescriptor, ReplySender, SocketHost, SubscriptionRegistry,
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Construction binds existing state and starts no timers, sockets or requests.
#[derive(Clone)]
pub struct ReleasePlugin(pub ReleaseService);
impl Plugin for ReleasePlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        mut requests: mpsc::Receiver<Bytes>,
        replies: ReplySender,
        _registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let service = self.0.clone();
        Box::pin(async move {
            while let Some(wire) = requests.recv().await {
                let result = host
                    .authorized(Box::pin(async {
                        let decoded = decode_muxed_frame(&wire).map_err(|_| ())?;
                        let Frame::Call {
                            call_id,
                            action_id,
                            input_json,
                        } = decoded.frame
                        else {
                            return Err(());
                        };
                        let (ok, value) = match service
                            .call(action_id, input_json, Some(host.as_ref()))
                            .await
                        {
                            Ok(value) => (true, value),
                            Err(error) => (false, serde_json::json!({"error":error})),
                        };
                        let json = serde_json::to_vec(&value).map_err(|_| ())?;
                        let mut encoded = Vec::with_capacity(json.len() + 32);
                        encode_muxed_frame_into(
                            0,
                            &Frame::Result {
                                call_id,
                                ok,
                                json: &json,
                            },
                            &mut encoded,
                        )
                        .map_err(|_| ())?;
                        replies.send(Bytes::from(encoded)).await.map_err(|_| ())
                    }))
                    .await;
                if result.is_err() {
                    break;
                }
            }
        })
    }
}
