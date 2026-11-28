//! Select connected UDP sends and open the corresponding Mac routing socket.

use super::underlay::UnderlayAnnouncer;

#[cfg(test)]
pub(super) use infraternal_mesh_node::engine::runtime::walks::{changed_peers, installed_by_key};

/// Run the portable worker with the Mac routing socket and subnet route implementation.
#[cfg(test)]
pub(super) async fn run_worker(
    commands: tokio::sync::mpsc::UnboundedReceiver<super::WorkerCommand>,
    state: super::RuntimeState,
) {
    infraternal_mesh_node::engine::runtime::run_worker(commands, state).await;
}

/// Whether connected per-endpoint sends (S) are on in this process: on by default (owner,
/// 2026-11-21, after J1108 qualified them on #260), off with `GOTATUN_BENCH_MAC_CONNECTED=0`.
///
/// This one answer drives both halves of S: the node passes it to the engine's socket factory
/// (`bind_udp` in the node module), and the worker starts the route listener with it, so an
/// engine with connected sockets always has a listener that restales them on a network change. Where the
/// engine cannot prove the shared port safe (macOS 27 shows a program only its own sockets),
/// it keeps `sendto` by itself, and the listener then only announces.
pub(super) fn mac_connected_sends_enabled() -> bool {
    connected_sends_switch_is_on(std::env::var_os("GOTATUN_BENCH_MAC_CONNECTED").as_deref())
}

/// Read the switch without changing the process environment: only `0` (spaces around it
/// ignored, as the engine's own reader does) turns S off; unset or any other value leaves it on.
fn connected_sends_switch_is_on(value: Option<&std::ffi::OsStr>) -> bool {
    value.and_then(std::ffi::OsStr::to_str).map(str::trim) != Some("0")
}

/// Start the route listener only when the Mac connected-send path needs immediate announcements.
///
/// The disabled mode leaves the listener absent, so route events cannot trigger extra
/// keepalives. A missing utun also leaves the listener absent.
pub(super) fn start_underlay_listener(
    utun: Option<&str>,
    connected_sends_enabled: bool,
) -> Option<UnderlayAnnouncer> {
    if connected_sends_enabled {
        utun.map(UnderlayAnnouncer::start)
    } else {
        None
    }
}

#[cfg(test)]
use infraternal_mesh_node::engine::runtime::{announce_underlay, announce_underlay_on_route_event};

#[cfg(test)]
mod tests {
    //! Order of route-change recovery, independent of sockets or eligible `WireGuard` sessions.

    use super::{
        announce_underlay, announce_underlay_on_route_event, connected_sends_switch_is_on,
        mac_connected_sends_enabled, start_underlay_listener,
    };
    use std::{
        cell::Cell,
        ffi::OsStr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// The first operation in the keepalive walk must see explicit invalidation, even if the
    /// walk finds no live sessions and sends nothing that might mark an endpoint stale.
    #[tokio::test]
    async fn invalidates_sources_before_walking_live_sessions() {
        let invalidated = Cell::new(false);
        let sessions = announce_underlay(
            || invalidated.set(true),
            async || {
                assert!(
                    invalidated.get(),
                    "live-session walk ran before invalidation"
                );
                0
            },
        )
        .await;
        assert_eq!(sessions, 0);
    }

    /// S is on by default and `0` is the kill switch (J1108). With S on the listener announces
    /// live sessions on route events; with it off it stays quiet.
    #[tokio::test]
    async fn connected_sends_gates_the_route_listener_and_keepalives() {
        assert!(connected_sends_switch_is_on(None), "on by default");
        assert!(connected_sends_switch_is_on(Some(OsStr::new("1"))));
        assert!(!connected_sends_switch_is_on(Some(OsStr::new("0"))));
        assert!(!connected_sends_switch_is_on(Some(OsStr::new(" 0 "))));

        let enabled = mac_connected_sends_enabled();
        let mut listener = start_underlay_listener(Some("lo0"), enabled);
        let listening = listener
            .as_ref()
            .is_some_and(super::super::underlay::UnderlayAnnouncer::is_listening);
        let invalidations = AtomicUsize::new(0);
        let requests = AtomicUsize::new(0);
        let result = announce_underlay_on_route_event(
            listener.as_mut(),
            || {
                invalidations.fetch_add(1, Ordering::SeqCst);
            },
            async || {
                requests.fetch_add(1, Ordering::SeqCst);
                1
            },
        )
        .await;

        let invalidation_count = invalidations.load(Ordering::SeqCst);
        let request_count = requests.load(Ordering::SeqCst);
        if enabled {
            assert!(
                listening && result == Some(1) && invalidation_count == 1 && request_count == 1,
                "S on must start a listener and announce a route event: \
                 listening={listening}, result={result:?}, \
                 invalidations={invalidation_count}, requests={request_count}",
            );
        } else {
            assert!(
                !listening && result.is_none() && invalidation_count == 0 && request_count == 0,
                "S off must not start a listener or handle a route event: \
                 listening={listening}, result={result:?}, \
                 invalidations={invalidation_count}, requests={request_count}",
            );
        }
    }
}
