//! Selects a compiled native provider only after enrolled binding and complete opening validation; unknown UUIDs cannot create capture [D198,D232].
use crate::{
    channel::Channel,
    daemon,
    remote_native::NativeChannel,
    remote_quic::BoundStream,
    transport::Receive,
    wire::{Lane, Side},
};
use infraternal_plugin_api::streams::{WireLane, WireProviderEntry};
use infraternal_plugin_remote::wire_datagrams::NativeDatagrams;
use std::{io, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// One compiled native provider and its stream budget. `capacity` holds one
/// permit per concurrent stream the provider's definition allows.
struct Route {
    entry: WireProviderEntry,
    capacity: Arc<Semaphore>,
}
/// Per-connection provider reservations complement the shared terminal/native
/// connection limit. Inert retained lane clones cannot retain these permits.
pub(crate) struct Routes(Vec<Route>);
impl Routes {
    /// Builds the route table from the compiled provider entries.
    ///
    /// Each definition is validated first. Fails with an error if a definition is
    /// invalid or if two entries share a capability bit or an opening tag, because
    /// either would make routing ambiguous.
    pub(crate) fn new(entries: Vec<WireProviderEntry>) -> io::Result<Self> {
        let mut routes: Vec<Route> = Vec::with_capacity(entries.len());
        for entry in entries {
            entry.definition.validate().map_err(io::Error::other)?;
            if routes.iter().any(|route| {
                route.entry.definition.capability == entry.definition.capability
                    || route.entry.definition.opening_tag == entry.definition.opening_tag
            }) {
                return Err(io::Error::other("Native provider routes are ambiguous."));
            }
            routes.push(Route {
                capacity: Arc::new(Semaphore::new(entry.definition.max_streams)),
                entry,
            });
        }
        Ok(Self(routes))
    }
    /// The union of every route's capability bits: what this connection can offer
    /// the peer during negotiation.
    pub(crate) fn capabilities(&self) -> u64 {
        self.0
            .iter()
            .fold(0, |caps, route| caps | route.entry.definition.capability)
    }
}

/// Test helper that serves one stream with standby priming switched off.
#[cfg(test)]
pub(crate) async fn serve(
    bound: BoundStream,
    providers: Arc<Routes>,
    capabilities: u64,
    datagrams: Arc<NativeDatagrams>,
    state: Option<PathBuf>,
) -> io::Result<()> {
    serve_negotiated(bound, providers, capabilities, datagrams, state, false).await
}
/// Native classification preserves negotiated standby intent on the terminal path.
pub(crate) async fn serve_negotiated(
    bound: BoundStream,
    providers: Arc<Routes>,
    capabilities: u64,
    datagrams: Arc<NativeDatagrams>,
    state: Option<PathBuf>,
    allow_priming: bool,
) -> io::Result<()> {
    let channel = NativeChannel::terminal(bound)?;
    let mut retire = Retire(Some(&channel));
    let mut receive = Receive::default();
    let opening = tokio::time::timeout(Duration::from_secs(5), receive.next_wire(&channel))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    let frame = infraternal_protocol::decode_frame(&opening).map_err(io::Error::other)?;
    if matches!(frame.frame, infraternal_protocol::Frame::AttachTerm { .. })
        || allow_priming
            && matches!(
                frame.frame,
                infraternal_protocol::Frame::Call {
                    call_id: 0,
                    action_id: "transport.prime",
                    input_json: b"{}"
                }
            )
    {
        return daemon::run_bound_terminal_opened_mode(
            &channel,
            state,
            receive,
            Some(opening),
            allow_priming,
        )
        .await;
    }
    let tag = opening
        .iter()
        .position(|byte| byte & 0x80 == 0)
        .and_then(|last| opening.get(last + 1))
        .ok_or(io::ErrorKind::InvalidData)?;
    let route = providers
        .0
        .iter()
        .find(|route| {
            route.entry.definition.opening_tag == *tag
                && capabilities & route.entry.definition.capability
                    == route.entry.definition.capability
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Compiled native provider is unavailable.",
            )
        })?;
    // Refuse before provider work and datagram route allocation. Holding the
    // owned permit across serve makes cancellation release exactly this slot.
    let _capacity = route.capacity.clone().try_acquire_owned().map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "Native provider capacity is exhausted.",
        )
    })?;
    let entry = &route.entry;
    let identity = entry
        .definition
        .opening_identity
        .map(|decode| decode(&opening).ok_or(io::ErrorKind::InvalidData))
        .transpose()?;
    let datagrams = match (entry.definition.datagram_tag, identity) {
        (Some(_), Some(identity)) => datagrams_available(&datagrams, entry.definition, identity),
        _ => None,
    };
    // Reliable media remains valid when the negotiated transport has no
    // datagram payload budget. No packet can create its own datagram route.
    retire.0 = None;
    drop(retire);
    let lane: Arc<dyn WireLane> = Arc::new(
        Lane::with_receive(
            channel,
            entry.definition,
            Side::Provider,
            datagrams,
            receive,
        )
        .map_err(io::Error::other)?,
    );
    let _retire = RetireLane(Arc::clone(&lane));
    entry
        .provider
        .serve(entry.definition, opening, lane)
        .await
        .map_err(|()| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Native provider refused the prepared session.",
            )
        })
}
/// Admits a datagram route for this stream's identity, or `None` if the
/// transport has no datagram budget. Reliable streams still work without it.
fn datagrams_available(
    datagrams: &Arc<NativeDatagrams>,
    definition: &'static infraternal_plugin_api::streams::WireStreamDef,
    identity: [u8; 16],
) -> Option<Arc<dyn infraternal_plugin_api::streams::DatagramLane>> {
    datagrams.admit(definition, identity).ok()
}
/// Guard that retires the channel on drop unless disarmed (set to `None`) once
/// the stream has been handed to a provider. Covers every early-error return.
struct Retire<'a>(Option<&'a NativeChannel>);
impl Drop for Retire<'_> {
    fn drop(&mut self) {
        if let Some(channel) = self.0 {
            channel.retire();
        }
    }
}
/// Guard that retires the provider's lane when serving ends or is cancelled.
struct RetireLane(Arc<dyn WireLane>);
impl Drop for RetireLane {
    fn drop(&mut self) {
        self.0.retire();
    }
}
