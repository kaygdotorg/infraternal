//! Adapts an already-bound channel to compiled plugin wire directions without feature-specific dispatch [D198,D232].
use crate::{channel::Channel, transport::Receive};
use infraternal_plugin_api::{
    Operation,
    streams::{DatagramLane, WireLane, WireStreamDef},
};
use std::sync::Arc;
use tokio::sync::{Mutex, watch};

/// Direction is local to the authenticated lane, never selected by packet data.
#[derive(Clone, Copy)]
pub enum Side {
    Requester,
    Provider,
}

/// Exactly one bounded parser survives cancelled reads. Construction starts no
/// task or timer; dropping the last lease retires only this native writer.
pub struct Lane<C: Channel> {
    channel: C,
    receive: Mutex<Receive>,
    definition: &'static WireStreamDef,
    side: Side,
    datagrams: Option<Arc<dyn DatagramLane>>,
    retired: watch::Sender<bool>,
}
impl<C: Channel> Lane<C> {
    /// The caller must have checked peer capability, host admission and binding.
    /// # Errors
    /// Refuses invalid metadata, mux/control channels, and unpaired datagrams.
    pub fn new(
        channel: C,
        definition: &'static WireStreamDef,
        side: Side,
        datagrams: Option<Arc<dyn DatagramLane>>,
    ) -> Result<Self, &'static str> {
        Self::with_receive(channel, definition, side, datagrams, Receive::default())
    }
    /// Retain opening-read suffix and deadline state when dispatch selects a
    /// compiled provider after reading its complete authenticated opening.
    /// # Errors
    /// Refuses the same metadata and binding violations as `new`.
    pub fn with_receive(
        channel: C,
        definition: &'static WireStreamDef,
        side: Side,
        datagrams: Option<Arc<dyn DatagramLane>>,
        receive: Receive,
    ) -> Result<Self, &'static str> {
        definition.validate()?;
        if channel
            .native_stream_id()
            .is_none_or(|id| id == 0 || id & 1 != 0)
            || datagrams.is_some() && definition.datagram_tag.is_none()
        {
            return Err("The plugin wire lane is unavailable.");
        }
        let retired = watch::channel(false).0;
        let datagrams = datagrams.map(|inner| {
            Arc::new(Datagrams {
                inner,
                retired: retired.subscribe(),
            }) as Arc<dyn DatagramLane>
        });
        Ok(Self {
            channel,
            receive: Mutex::new(receive),
            definition,
            side,
            datagrams,
            retired,
        })
    }
    fn accepts(&self, packet: &[u8], incoming: bool) -> bool {
        let Ok(frame) = infraternal_protocol::decode_frame(packet) else {
            return false;
        };
        let tags = match (self.side, incoming) {
            (Side::Requester, true) | (Side::Provider, false) => self.definition.replies,
            _ => self.definition.requests,
        };
        // The shared decoder already validated the canonical length varint.
        let tag = packet
            .iter()
            .position(|byte| byte & 0x80 == 0)
            .and_then(|last| packet.get(last + 1));
        frame.wire_len == packet.len() && tag.is_some_and(|tag| tags.contains(tag))
    }
}
impl<C: Channel> Drop for Lane<C> {
    fn drop(&mut self) {
        self.retire();
    }
}
impl<C: Channel> WireLane for Lane<C> {
    fn stream_id(&self) -> u32 {
        self.channel.native_stream_id().unwrap_or(0)
    }
    fn receive(&self) -> Operation<'_, Result<bytes::Bytes, ()>> {
        Box::pin(async {
            let mut retired = self.retired.subscribe();
            if *retired.borrow() {
                return Err(());
            }
            let packet = tokio::select! { biased;
                _ = retired.changed() => return Err(()),
                packet = async { self.receive.lock().await.next_wire(&self.channel).await } => packet,
            };
            let Ok(packet) = packet else {
                self.retire();
                return Err(());
            };
            if !self.accepts(&packet, true) {
                self.retire();
                return Err(());
            }
            Ok(packet)
        })
    }
    fn send<'a>(&'a self, packet: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            let mut retired = self.retired.subscribe();
            if *retired.borrow() || !self.accepts(packet, false) {
                return Err(());
            }
            let mut write = Write {
                lane: self,
                complete: false,
            };
            let result = tokio::select! { biased;
                _ = retired.changed() => Err(()),
                result = self.channel.write(packet) => result.map_err(|_| ()),
            };
            write.complete = result.is_ok();
            result
        })
    }
    fn retire(&self) {
        self.retired.send_replace(true);
        if let Some(datagrams) = &self.datagrams {
            datagrams.retire();
        }
        self.channel.retire();
    }
    fn datagrams(&self) -> Option<Arc<dyn DatagramLane>> {
        self.datagrams.clone()
    }
}

// Cancellation can happen after bytes entered QUIC. Seal all handles before a
// replacement operation can append another frame to that incomplete prefix.
struct Write<'a, C: Channel> {
    lane: &'a Lane<C>,
    complete: bool,
}
impl<C: Channel> Drop for Write<'_, C> {
    fn drop(&mut self) {
        if !self.complete {
            self.lane.retire();
        }
    }
}

// A cloned datagram handle must not outlive its reliable lane's admission.
// The withdrawal signal contains no connection, task or bearer material.
struct Datagrams {
    inner: Arc<dyn DatagramLane>,
    retired: watch::Receiver<bool>,
}
impl DatagramLane for Datagrams {
    fn retire(&self) {
        self.inner.retire();
    }
    fn receive(&self) -> Operation<'_, Result<bytes::Bytes, ()>> {
        Box::pin(async {
            let mut retired = self.retired.clone();
            if *retired.borrow() {
                return Err(());
            }
            tokio::select! { biased;
                _ = retired.changed() => Err(()),
                result = self.inner.receive() => result,
            }
        })
    }
    fn send<'a>(&'a self, packet: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            let mut retired = self.retired.clone();
            if *retired.borrow() {
                return Err(());
            }
            tokio::select! { biased;
                _ = retired.changed() => Err(()),
                result = self.inner.send(packet) => result,
            }
        })
    }
    fn max_payload(&self) -> Option<usize> {
        if *self.retired.borrow() {
            None
        } else {
            self.inner.max_payload()
        }
    }
}
