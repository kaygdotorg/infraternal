//! Serves bounded native terminal relays for one authenticated server connection; cancellation retires every shim socket [215], #129, #201.
use crate::{remote_native::NativeChannel, remote_quic::BindingConnection};
use std::{io, path::PathBuf};
use tokio::task::JoinSet;

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
                    if terminals.len() >= infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS {
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
