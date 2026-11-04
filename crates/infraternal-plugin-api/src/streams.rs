//! Declares bounded plugin wire lanes without feature-specific core dispatch [D16,D198,D232].
#[cfg(any(test, feature = "native-wire"))]
use crate::Operation;
#[cfg(any(test, feature = "native-wire"))]
use bytes::Bytes;
#[cfg(any(test, feature = "native-wire"))]
use std::sync::Arc;

/// Reads the 16-byte session id from a complete packet, or returns `None` if the packet is
/// not valid. It is compiled by the plugin that owns the packet format and must not allocate.
pub type DatagramIdentity = fn(&[u8]) -> Option<[u8; 16]>;

/// A plugin's declaration of the wire lanes it serves: which capability bit gates them, which
/// frame tags may travel each way, and how many lanes may be open at once.
///
/// Both sides must advertise the same capability before a native lane opens. Tags are the
/// frozen protocol type bytes, never an untrusted plugin name. Call [`WireStreamDef::validate`]
/// before admitting anything.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct WireStreamDef {
    /// Native leg-B capability; it cannot alias reserved transport bits.
    pub capability: u64,
    /// Explicit leg-A projection. None means this declaration opens no browser lane.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_capability: Option<u64>,
    /// Tag of the first frame a viewer sends to open a lane. It must be one of `requests`.
    pub opening_tag: u8,
    /// Compiled complete-opening decoder. Hosts use this immutable identity
    /// before admitting a correlated datagram lane; packet data creates no route.
    #[serde(skip)]
    pub opening_identity: Option<DatagramIdentity>,
    /// Frame tags the viewer may send on this lane. Unique, each at least `0x40`.
    pub requests: &'static [u8],
    /// Frame tags the host may send on this lane. Unique, each at least `0x40`.
    pub replies: &'static [u8],
    /// How many lanes of this kind may be open at once, from 1 up to the terminal stream limit.
    pub max_streams: usize,
    /// Tag of this lane's datagrams, if it uses them. It must be at least `0x40` and not appear
    /// in `requests` or `replies`. Set exactly when `datagram_identity` is set.
    pub datagram_tag: Option<u8>,
    /// Compiled, allocation-free decoder for unreliable packet ownership.
    /// Transport admission never interprets feature-specific packet fields.
    #[serde(skip)]
    pub datagram_identity: Option<DatagramIdentity>,
}

impl WireStreamDef {
    /// The capability bit browsers use for this lane, or `0` when it opens no browser lane.
    ///
    /// Browser admission and advertisement must use the same declared identity;
    /// native providers continue to negotiate `capability` independently.
    #[must_use]
    pub const fn browser_capability(&self) -> u64 {
        match self.browser_capability {
            Some(capability) => capability,
            None => 0,
        }
    }

    /// Checks the declaration before any transport admission.
    ///
    /// It must have a single-bit native capability above the reserved transport bits, a
    /// single-bit browser capability if any, a lane limit in range, an opening tag among the
    /// requests, non-empty request and reply lists of unique tags from `0x40`, and a datagram tag
    /// (if any) that is distinct from them and comes with a decoder.
    ///
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

/// One already-bound reliable lane between a viewer and a plugin on this host.
///
/// Implementations preserve partial reads;
/// cancelling a partial write retires this lane before it can be reused.
/// The enclosing authenticated connection is retained by its host lease.
#[cfg(any(test, feature = "native-wire"))]
pub trait WireLane: Send + Sync {
    /// The id of this lane on its connection.
    fn stream_id(&self) -> u32;
    /// Waits for the next piece of data from the viewer. `Err` means the lane failed or closed.
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>>;
    /// Sends `frame` to the viewer. `Err` means it could not be sent; the lane is then unusable.
    fn send<'a>(&'a self, frame: &'a [u8]) -> Operation<'a, Result<(), ()>>;
    /// Closes the lane and frees its slot.
    fn retire(&self);
    /// A demultiplexed unreliable lane shares this admitted connection. No fallback
    /// is selected when the explicit delivery candidate is unsupported.
    fn datagrams(&self) -> Option<Arc<dyn DatagramLane>> {
        None
    }
}

/// The code of a plugin that serves wire lanes on a node.
///
/// A compiled node provider receives only complete openings on already-admitted
/// native lanes. Session preparation remains an explicit control operation;
/// the provider must refuse unknown identities without creating native work.
#[cfg(any(test, feature = "native-wire"))]
pub trait WireProvider: Send + Sync {
    /// Serves one lane until it ends. `opening` is the complete first frame the viewer sent and
    /// `lane` carries the rest. Returns `Err` when the opening is refused or the lane fails.
    fn serve(
        &self,
        definition: &'static WireStreamDef,
        opening: Bytes,
        lane: Arc<dyn WireLane>,
    ) -> Operation<'static, Result<(), ()>>;
}

/// A [`WireStreamDef`] paired with the [`WireProvider`] that serves it.
///
/// Immutable compiled routing metadata and its owner. Discovery validates
/// declarations before capabilities are advertised; packet data selects no code.
#[cfg(any(test, feature = "native-wire"))]
pub struct WireProviderEntry {
    /// The lane declaration.
    pub definition: &'static WireStreamDef,
    /// The code that serves lanes opened under `definition`.
    pub provider: Arc<dyn WireProvider>,
}

/// What a plugin can ask of the host it runs on.
///
/// The host resolves immutable identity through its existing access/admission
/// path. A plugin cannot acquire another user's host by supplying wire IDs.
/// This interface does not create a node, server, listener or certificate.
#[cfg(any(test, feature = "native-wire"))]
pub trait NodeHost: Send + Sync {
    /// The host's id.
    fn id(&self) -> &str;
    /// The id of the account that owns the host.
    fn owner_id(&self) -> &str;
    /// True while access to this host is still permitted.
    fn permits(&self) -> bool;
    /// Runs `operation`, but cancels it and returns `Err` if access ends first. Use it around
    /// every write that forwards viewer data.
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>>;
    /// Runs the named host action with `input` and returns its output. `Err` means the action
    /// was refused or failed.
    fn call<'a>(&'a self, action: &'a str, input: &'a [u8]) -> Operation<'a, Result<Vec<u8>, ()>>;
    /// Native lanes use the existing never-reused writer allocator and binding.
    /// Implementations refuse unsupported capabilities before opening anything.
    fn open<'a>(
        &'a self,
        definition: &'static WireStreamDef,
        opening: &'a [u8],
    ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>>;
}

/// The unreliable (datagram) side of a [`WireLane`].
///
/// Datagram queues belong to a bound reliable lane and retire with its lease.
/// The transport invokes the compiled identity decoder before queue admission;
/// each consumer receives only packets for its already-authorized stream.
#[cfg(any(test, feature = "native-wire"))]
pub trait DatagramLane: Send + Sync {
    /// Waits for the next datagram of this session. `Err` means the lane is closed.
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>>;
    /// Sends one datagram. `Err` if it could not be sent, for example when it is too large.
    fn send<'a>(&'a self, packet: &'a [u8]) -> Operation<'a, Result<(), ()>>;
    /// The largest datagram that can be sent now, or `None` when datagrams are unavailable.
    fn max_payload(&self) -> Option<usize>;
    /// Withdraw the exact admission generation even while inert clones remain.
    /// Stateless adapters need no registration cleanup.
    fn retire(&self) {}
}

/// Whether one admitted viewer may still use the host.
///
/// A per-socket authority projection belongs to exactly one admitted viewer.
/// The host watchdog withdraws it on logout, expiry, revocation or socket drop.
/// It contains no bearer material and checks do not perform database I/O.
#[cfg(any(test, feature = "native-wire"))]
pub trait Authority: Send + Sync {
    /// True while the viewer's access is valid. It never touches the database.
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
/// An [`Authority`] that never permits anything. Existing adapters that have no viewer
/// authority use it, so stream admission fails closed.
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
