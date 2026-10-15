//! Declares bounded plugin wire lanes without feature-specific core dispatch [D16,D198,D232].
#[cfg(any(test, feature = "native-wire"))]
use crate::Operation;
#[cfg(any(test, feature = "native-wire"))]
use bytes::Bytes;
#[cfg(any(test, feature = "native-wire"))]
use std::sync::Arc;

/// An allocation-free, complete-packet identity decoder compiled by its provider.
pub type DatagramIdentity = fn(&[u8]) -> Option<[u8; 16]>;

/// Both sides must advertise the same capability before a native lane opens.
/// Tags are the frozen protocol type bytes, never an untrusted plugin name.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct WireStreamDef {
    /// Native leg-B capability; it cannot alias reserved transport bits.
    pub capability: u64,
    /// Explicit leg-A projection. None means this declaration opens no browser lane.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_capability: Option<u64>,
    pub opening_tag: u8,
    /// Compiled complete-opening decoder. Hosts use this immutable identity
    /// before admitting a correlated datagram lane; packet data creates no route.
    #[serde(skip)]
    pub opening_identity: Option<DatagramIdentity>,
    pub requests: &'static [u8],
    pub replies: &'static [u8],
    pub max_streams: usize,
    pub datagram_tag: Option<u8>,
    /// Compiled, allocation-free decoder for unreliable packet ownership.
    /// Transport admission never interprets feature-specific packet fields.
    #[serde(skip)]
    pub datagram_identity: Option<DatagramIdentity>,
}

impl WireStreamDef {
    /// Browser admission and advertisement must use the same declared identity;
    /// native providers continue to negotiate `capability` independently.
    #[must_use]
    pub const fn browser_capability(&self) -> u64 {
        match self.browser_capability {
            Some(capability) => capability,
            None => 0,
        }
    }

    /// Validate immutable declarations before any transport admission.
    /// # Errors
    /// Refuses ambiguous capability, direction or datagram ownership metadata.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.capability < crate::channel::MIN_NATIVE_STREAM_CAPABILITY
            || self.capability.count_ones() != 1
            || self
                .browser_capability
                .is_some_and(|cap| cap < 8 || cap.count_ones() != 1)
            || self.max_streams == 0
            || self.max_streams > crate::channel::MAX_TERMINAL_STREAMS
            || !self.requests.contains(&self.opening_tag)
            || self.datagram_tag.is_some() != self.datagram_identity.is_some()
            || self.opening_tag < 0x40
            || self
                .requests
                .iter()
                .chain(self.replies)
                .any(|tag| *tag < 0x40)
            || self.datagram_tag.is_some_and(|tag| {
                tag < 0x40 || self.requests.contains(&tag) || self.replies.contains(&tag)
            })
            || self.requests.is_empty()
            || self.replies.is_empty()
            || self
                .requests
                .iter()
                .enumerate()
                .any(|(index, tag)| self.requests[..index].contains(tag))
            || self
                .replies
                .iter()
                .enumerate()
                .any(|(index, tag)| self.replies[..index].contains(tag))
        {
            Err("The plugin stream definition is unavailable.")
        } else {
            Ok(())
        }
    }
}

/// One already-bound reliable lane. Implementations preserve partial reads;
/// cancelling a partial write retires this lane before it can be reused.
/// The enclosing authenticated connection is retained by its host lease.
#[cfg(any(test, feature = "native-wire"))]
pub trait WireLane: Send + Sync {
    fn stream_id(&self) -> u32;
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>>;
    fn send<'a>(&'a self, frame: &'a [u8]) -> Operation<'a, Result<(), ()>>;
    fn retire(&self);
    /// A demultiplexed unreliable lane shares this admitted connection. No fallback
    /// is selected when the explicit delivery candidate is unsupported.
    fn datagrams(&self) -> Option<Arc<dyn DatagramLane>> {
        None
    }
}

/// A compiled node provider receives only complete openings on already-admitted
/// native lanes. Session preparation remains an explicit control operation;
/// the provider must refuse unknown identities without creating native work.
#[cfg(any(test, feature = "native-wire"))]
pub trait WireProvider: Send + Sync {
    fn serve(
        &self,
        definition: &'static WireStreamDef,
        opening: Bytes,
        lane: Arc<dyn WireLane>,
    ) -> Operation<'static, Result<(), ()>>;
}

/// Immutable compiled routing metadata and its owner. Discovery validates
/// declarations before capabilities are advertised; packet data selects no code.
#[cfg(any(test, feature = "native-wire"))]
pub struct WireProviderEntry {
    pub definition: &'static WireStreamDef,
    pub provider: Arc<dyn WireProvider>,
}

/// The host resolves immutable identity through its existing access/admission
/// path. A plugin cannot acquire another user's host by supplying wire IDs.
/// This interface does not create a node, server, listener or certificate.
#[cfg(any(test, feature = "native-wire"))]
pub trait NodeHost: Send + Sync {
    fn id(&self) -> &str;
    fn owner_id(&self) -> &str;
    fn permits(&self) -> bool;
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>>;
    fn call<'a>(&'a self, action: &'a str, input: &'a [u8]) -> Operation<'a, Result<Vec<u8>, ()>>;
    /// Native lanes use the existing never-reused writer allocator and binding.
    /// Implementations refuse unsupported capabilities before opening anything.
    fn open<'a>(
        &'a self,
        definition: &'static WireStreamDef,
        opening: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>>;
}

/// Datagram queues belong to a bound reliable lane and retire with its lease.
/// The transport invokes the compiled identity decoder before queue admission;
/// each consumer receives only packets for its already-authorized stream.
#[cfg(any(test, feature = "native-wire"))]
pub trait DatagramLane: Send + Sync {
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>>;
    fn send<'a>(&'a self, packet: &'a [u8]) -> Operation<'a, Result<(), ()>>;
    fn max_payload(&self) -> Option<usize>;
    /// Withdraw the exact admission generation even while inert clones remain.
    /// Stateless adapters need no registration cleanup.
    fn retire(&self) {}
}

/// A per-socket authority projection belongs to exactly one admitted viewer.
/// The host watchdog withdraws it on logout, expiry, revocation or socket drop.
/// It contains no bearer material and checks do not perform database I/O.
#[cfg(any(test, feature = "native-wire"))]
pub trait Authority: Send + Sync {
    fn permits(&self) -> bool;
    /// Guard actual forwarding through the host's existing login checks. Socket
    /// projections override this with a weak host lease so session retention
    /// cannot create a cycle through the server's plugin runtime.
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            if !self.permits() {
                return Err(());
            }
            tokio::select! { biased;
                () = self.cancelled() => Err(()),
                result = operation => { if self.permits() { result } else { Err(()) } },
            }
        })
    }
    /// An event/deadline waiter cancels a pending native write on authority loss.
    /// Implementations subscribe before checking liveness to avoid missed wakes.
    fn cancelled(&self) -> Operation<'_, ()>;
}
/// Existing adapters that have no viewer authority fail closed on stream admission.
#[cfg(any(test, feature = "native-wire"))]
pub struct Denied;
#[cfg(any(test, feature = "native-wire"))]
impl Authority for Denied {
    fn permits(&self) -> bool {
        false
    }
    fn cancelled(&self) -> Operation<'_, ()> {
        Box::pin(async {})
    }
}

#[cfg(test)]
#[path = "streams_tests.rs"]
mod tests;
