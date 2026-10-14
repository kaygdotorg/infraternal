//! Demultiplexes unreliable packets only into already-admitted plugin lanes [D198,D232].
use crate::streams::WireStreamDef;
use bytes::Bytes;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};

type Identity = [u8; 16];
type Decoder = fn(&[u8]) -> Option<Identity>;
struct Provider {
    definition: &'static WireStreamDef,
    decode: Decoder,
    maximum: usize,
    lanes: HashMap<Identity, (u64, mpsc::Sender<Bytes>)>,
}
struct State {
    providers: HashMap<u64, Provider>,
    next_ticket: u64,
    count: usize,
}
struct Inner {
    state: Mutex<State>,
    active: watch::Sender<usize>,
}
/// Construction owns metadata only. The enclosing transport starts its sole
/// datagram reader on the first registration and joins it when the last retires.
#[derive(Clone)]
pub struct DatagramHub(Arc<Inner>);
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Invalid,
    Duplicate,
    Limit,
}
/// Admission, not packet contents, chooses this UUID and capability. Dropping
/// the lease withdraws its exact generation before releasing queued packets.
pub struct DatagramReceiver {
    hub: DatagramHub,
    capability: u64,
    identity: Identity,
    ticket: u64,
    receive: mpsc::Receiver<Bytes>,
}
/// Detached synchronous withdrawal for one route generation. It retains no
/// queued payloads and cannot withdraw a replacement with the same identity.
pub struct DatagramRetirement {
    hub: DatagramHub,
    capability: u64,
    identity: Identity,
    ticket: u64,
}
impl DatagramHub {
    #[must_use]
    pub fn active(&self) -> watch::Receiver<usize> {
        self.0.active.subscribe()
    }
    /// The caller must first establish host authority and reliable stream binding.
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
    #[must_use]
    pub fn retirement(&self) -> DatagramRetirement {
        DatagramRetirement {
            hub: self.hub.clone(),
            capability: self.capability,
            identity: self.identity,
            ticket: self.ticket,
        }
    }
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
