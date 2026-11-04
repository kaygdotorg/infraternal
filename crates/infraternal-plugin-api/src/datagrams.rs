//! Demultiplexes unreliable packets only into already-admitted plugin lanes [D198,D232].
use crate::streams::WireStreamDef;
use bytes::Bytes;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};

/// The 16-byte id of the session a datagram belongs to.
type Identity = [u8; 16];
/// Reads the session id out of a complete datagram, or `None` if the packet is not valid.
type Decoder = fn(&[u8]) -> Option<Identity>;
/// One plugin's datagram registration: its stream definition, its packet decoder and the
/// lanes (one per session) currently admitted, each with its admission ticket and queue.
struct Provider {
    definition: &'static WireStreamDef,
    decode: Decoder,
    maximum: usize,
    lanes: HashMap<Identity, (u64, mpsc::Sender<Bytes>)>,
}
/// The hub's shared state: providers by capability bit, the next admission ticket and the
/// total number of admitted lanes.
struct State {
    providers: HashMap<u64, Provider>,
    next_ticket: u64,
    count: usize,
}
/// The hub's lock-protected state plus a watch channel that publishes the lane count.
struct Inner {
    state: Mutex<State>,
    active: watch::Sender<usize>,
}
/// Routes the datagrams of one connection to the plugin lanes that were admitted for them.
///
/// A lane is registered with [`DatagramHub::register`] after its reliable stream is bound, and
/// the transport feeds every incoming packet to [`DatagramHub::push`]. A packet for a session
/// that has no lane is dropped; packets never create routes. Clones share the same hub.
///
/// Construction owns metadata only. The enclosing transport starts its sole datagram reader
/// on the first registration and joins it when the last lane retires.
#[derive(Clone)]
pub struct DatagramHub(Arc<Inner>);
/// An empty hub with no providers.
impl Default for DatagramHub {
    fn default() -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State {
                providers: HashMap::new(),
                next_ticket: 1,
                count: 0,
            }),
            active: watch::channel(0).0,
        }))
    }
}
/// Why [`DatagramHub::register`] refused a lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The stream definition is invalid or has no datagram decoder, its datagram tag clashes
    /// with another plugin's, or the hub's lock is poisoned.
    Invalid,
    /// A lane for this session id is already registered.
    Duplicate,
    /// The hub, or this plugin's stream definition, is at its lane limit.
    Limit,
}
/// The receiving end of one admitted datagram lane.
///
/// Admission, not packet contents, chooses this UUID and capability. Call
/// [`DatagramReceiver::receive`] to get the next packet for the session. Dropping the lease
/// withdraws its exact generation before releasing queued packets.
pub struct DatagramReceiver {
    hub: DatagramHub,
    capability: u64,
    identity: Identity,
    ticket: u64,
    receive: mpsc::Receiver<Bytes>,
}
/// A handle that can withdraw one lane without owning its queue, from synchronous code.
///
/// It retains no queued payloads and cannot withdraw a replacement lane registered later with
/// the same session id, because it matches the lane's admission ticket. Get one from
/// [`DatagramReceiver::retirement`].
pub struct DatagramRetirement {
    hub: DatagramHub,
    capability: u64,
    identity: Identity,
    ticket: u64,
}
impl DatagramHub {
    /// A watch on how many lanes are admitted right now, so the transport can start its
    /// datagram reader with the first lane and stop it after the last.
    #[must_use]
    pub fn active(&self) -> watch::Receiver<usize> {
        self.0.active.subscribe()
    }
    /// Admits a datagram lane for the session `identity` and returns the receiver of its packets.
    ///
    /// The caller must first establish host authority and reliable stream binding. `definition`
    /// must declare a datagram tag and decoder, and `identity` is the session id the decoder will
    /// find in that session's packets. Each lane queues at most four packets.
    ///
    /// # Errors
    /// Refuses undeclared datagrams, duplicate identities and bounded capacity.
    pub fn register(
        &self,
        definition: &'static WireStreamDef,
        identity: Identity,
    ) -> Result<DatagramReceiver, AdmissionError> {
        definition.validate().map_err(|_| AdmissionError::Invalid)?;
        let decode = definition
            .datagram_identity
            .ok_or(AdmissionError::Invalid)?;
        let mut state = self.0.state.lock().map_err(|_| AdmissionError::Invalid)?;
        if state.count >= crate::channel::MAX_TERMINAL_STREAMS || definition.max_streams == 0 {
            return Err(AdmissionError::Limit);
        }
        // Capability bits alone do not disambiguate a packet on the shared
        // connection. Reject tag aliases before installing any route.
        if state.providers.values().any(|provider| {
            provider.definition.capability != definition.capability
                && provider.definition.datagram_tag == definition.datagram_tag
        }) {
            return Err(AdmissionError::Invalid);
        }
        let ticket = state.next_ticket;
        state.next_ticket = ticket.checked_add(1).ok_or(AdmissionError::Limit)?;
        let provider = state
            .providers
            .entry(definition.capability)
            .or_insert_with(|| Provider {
                definition,
                decode,
                maximum: definition.max_streams,
                lanes: HashMap::new(),
            });
        if !std::ptr::eq(provider.definition, definition) {
            return Err(AdmissionError::Invalid);
        }
        if provider.lanes.contains_key(&identity) {
            return Err(AdmissionError::Duplicate);
        }
        if provider.lanes.len() >= provider.maximum {
            return Err(AdmissionError::Limit);
        }
        let (send, receive) = mpsc::channel(4);
        provider.lanes.insert(identity, (ticket, send));
        state.count += 1;
        self.0.active.send_replace(state.count);
        Ok(DatagramReceiver {
            hub: self.clone(),
            capability: definition.capability,
            identity,
            ticket,
            receive,
        })
    }
    /// A compiled decoder validates the entire packet before UUID lookup. A full
    /// four-packet lane drops this unreliable packet; frame loss detection repairs
    /// it. No packet can allocate a route or displace another lane's traffic.
    pub fn push(&self, packet: Bytes) {
        let Ok(state) = self.0.state.lock() else {
            return;
        };
        for provider in state.providers.values() {
            if let Some(identity) = (provider.decode)(&packet)
                && let Some((_, send)) = provider.lanes.get(&identity)
            {
                let _ = send.try_send(packet);
                // Definitions have disjoint datagram tags, validated at discovery.
                return;
            }
        }
    }
}
impl DatagramReceiver {
    /// A handle that withdraws this lane, for code that cannot own the receiver.
    #[must_use]
    pub fn retirement(&self) -> DatagramRetirement {
        DatagramRetirement {
            hub: self.hub.clone(),
            capability: self.capability,
            identity: self.identity,
            ticket: self.ticket,
        }
    }
    /// Waits for the next packet of this session. Returns `None` once the lane is withdrawn
    /// and its queue is empty.
    pub async fn receive(&mut self) -> Option<Bytes> {
        self.receive.recv().await
    }
}
impl Drop for DatagramReceiver {
    fn drop(&mut self) {
        self.retirement().retire();
    }
}
impl DatagramRetirement {
    /// Release route capacity immediately. Ticket matching makes repeated calls
    /// and a late predecessor drop harmless to a fresh reliable writer.
    pub fn retire(&self) {
        let Ok(mut state) = self.hub.0.state.lock() else {
            return;
        };
        let Some(provider) = state.providers.get_mut(&self.capability) else {
            return;
        };
        if provider
            .lanes
            .get(&self.identity)
            .is_some_and(|(ticket, _)| *ticket == self.ticket)
        {
            provider.lanes.remove(&self.identity);
            let empty = provider.lanes.is_empty();
            if empty {
                state.providers.remove(&self.capability);
            }
            state.count -= 1;
            self.hub.0.active.send_replace(state.count);
        }
    }
}

#[cfg(test)]
#[path = "datagrams_tests.rs"]
mod tests;
