//! Serves bounded native terminal relays for one authenticated server connection; cancellation retires every shim socket [215], #129, #201.
use crate::{remote_native::NativeChannel, remote_quic::BindingConnection};
use infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS;
use std::{io, path::PathBuf, time::Duration};
use tokio::task::JoinSet;

/// How long a newly opened terminal stream may wait for a relay to end when the
/// link already runs the most terminals ([`MAX_TERMINAL_STREAMS`]).
const RELEASE_WAIT: Duration = Duration::from_secs(1);

/// Joins relays until one more terminal fits, for at most [`RELEASE_WAIT`].
/// Returns `false` when the link still runs its most terminals, so the new
/// stream must be refused.
///
/// The wait matters on a full link whose terminals are being replaced: the reset
/// of the old stream and the opening of its replacement travel on separate QUIC
/// streams, in no promised order, so the replacement can arrive while the old
/// relay is still ending (#562).
///
/// # Errors
/// A relay task that panicked, as the serving loop treats it.
async fn room_for_terminal(terminals: &mut JoinSet<io::Result<()>>) -> io::Result<bool> {
    let released = tokio::time::timeout(RELEASE_WAIT, async {
        while terminals.len() >= MAX_TERMINAL_STREAMS {
            let Some(result) = terminals.join_next().await else {
                break;
            };
            // A relay's own error has already retired its channel.
            let _ = result.map_err(io::Error::other)?;
        }
        Ok::<(), io::Error>(())
    })
    .await;
    match released {
        Ok(joined) => joined.map(|()| true),
        Err(_) => Ok(false),
    }
}

/// Accept binding progress once and retain it across completed relay jobs.
/// The caller already checked mTLS, uid and negotiated native capabilities.
pub(super) async fn serve(
    binding: &BindingConnection,
    state: PathBuf,
    allow_priming: bool,
    #[cfg(any(test, feature = "native-streams"))] providers: std::sync::Arc<
        crate::native_dispatch::Routes,
    >,
    #[cfg(any(test, feature = "native-streams"))] capabilities: u64,
    #[cfg(any(test, feature = "native-streams"))] datagrams: std::sync::Arc<
        infraternal_plugin_remote::wire_datagrams::NativeDatagrams,
    >,
) -> io::Result<()> {
    let mut terminals = JoinSet::new();
    loop {
        let next = crate::remote_quic::accept_bound(binding);
        tokio::pin!(next);
        loop {
            tokio::select! {
                terminal = &mut next => {
                    let bound = terminal?;
                    if !room_for_terminal(&mut terminals).await? {
                        crate::channel::Channel::retire(&NativeChannel::terminal(bound)?);
                        break;
                    }
                    let state = state.clone();
                    #[cfg(any(test, feature = "native-streams"))]
                    let providers = providers.clone();
                    #[cfg(any(test, feature = "native-streams"))]
                    let datagrams = datagrams.clone();
                    terminals.spawn(async move {
                        #[cfg(not(any(test, feature = "native-streams")))]
                        let terminals_only = true;
                        #[cfg(any(test, feature = "native-streams"))]
                        let terminals_only = providers.capabilities() == 0;
                        if terminals_only {
                            // Metadata-only builds retain the existing borrowed terminal reader.
                            let channel = NativeChannel::terminal(bound)?;
                            if allow_priming { return crate::daemon::run_negotiated_bound_terminal(&channel, Some(state)).await; }
                            return crate::daemon::run_bound_terminal(&channel, Some(state)).await;
                        }
                        #[cfg(any(test, feature = "native-streams"))]
                        return crate::native_dispatch::serve_negotiated(bound, providers, capabilities, datagrams, Some(state), allow_priming).await;
                        #[cfg(not(any(test, feature = "native-streams")))]
                        unreachable!("terminal-only branch returns above")
                    });
                    break;
                }
                result = terminals.join_next(), if !terminals.is_empty() => {
                    // A malformed writer retires its own channel via its relay
                    // guard. A task panic is a supervisor failure, never ignored.
                    let _ = result.ok_or(io::ErrorKind::BrokenPipe)?.map_err(io::Error::other)?;
                }
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! The serving loop at the per-link terminal bound, over real QUIC (#562).
    use super::*;
    use crate::{channel::Channel, remote_native_tests::Pair, remote_quic, transport::Receive};
    use std::{os::unix::fs::DirBuilderExt, sync::Arc};

    /// Open the server's side of one terminal stream bound to `writer`.
    async fn open(server: &BindingConnection, writer: u32) -> NativeChannel {
        NativeChannel::terminal(remote_quic::open_bound(server, writer).await.unwrap()).unwrap()
    }

    /// A full link replaces one terminal and the new stream arrives before the old
    /// stream's reset: the agent must serve it once the old relay ends, and refuse
    /// only a stream that really is one too many.
    #[tokio::test]
    async fn a_replacement_that_overtakes_its_predecessors_reset_is_served() {
        let pair = Pair::new().await;
        let (host, server) = (pair.binding(false), pair.binding(true));
        let state = crate::test_state_root()
            .join("pn")
            .join(&uuid::Uuid::new_v4().simple().to_string()[..8]);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&state)
            .unwrap();
        let serving = serve(
            &host,
            state.clone(),
            false,
            Arc::new(crate::native_dispatch::Routes::new(Vec::new()).unwrap()),
            0,
            infraternal_plugin_remote::wire_datagrams::NativeDatagrams::new(pair.client.clone()),
        );
        let replacing = async {
            // Relays wait for their first frame, so a silent stream stays served.
            let mut open_streams = Vec::new();
            let bound = u32::try_from(MAX_TERMINAL_STREAMS).unwrap();
            for index in 1..=bound {
                open_streams.push(open(&server, 2 * index).await);
            }
            let replacement = open(&server, 2 * (bound + 1)).await;
            let mut receive = Receive::default();
            // sleep: let the agent accept the replacement before the reset is sent.
            tokio::time::sleep(Duration::from_millis(100)).await;
            open_streams.pop().unwrap().retire();
            assert!(
                tokio::time::timeout(RELEASE_WAIT + Duration::from_millis(500), {
                    receive.next(&replacement)
                })
                .await
                .is_err(),
                "the agent refused the replacement stream"
            );
            // With no relay ending, one more is still refused after the wait.
            let extra = open(&server, 2 * (bound + 2)).await;
            let mut receive = Receive::default();
            let refused =
                tokio::time::timeout(RELEASE_WAIT + Duration::from_secs(2), receive.next(&extra))
                    .await;
            assert!(
                matches!(refused, Ok(Err(_))),
                "a stream past the bound must be refused"
            );
        };
        tokio::select! {
            result = serving => panic!("serving ended: {result:?}"),
            () = replacing => {}
        }
        std::fs::remove_dir_all(state).unwrap();
    }
}
