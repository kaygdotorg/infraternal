//! Supervises bounded native relays, retaining partial binding progress across completed terminal jobs [215], #129.
use crate::{daemon, remote_native::NativeChannel, remote_quic::BindingConnection};
use std::{io, path::PathBuf};
use tokio::task::JoinSet;

/// Accept binding progress once and retain it across completed relay jobs.
/// The caller already checked mTLS, uid and negotiated native capabilities.
pub(super) async fn serve(
    binding: &BindingConnection,
    state: PathBuf,
    allow_priming: bool,
) -> io::Result<()> {
    let mut terminals = JoinSet::new();
    loop {
        let next = crate::remote_quic::accept_bound(binding);
        tokio::pin!(next);
        loop {
            tokio::select! {
                terminal = &mut next => {
                    let channel = NativeChannel::terminal(terminal?)?;
                    if terminals.len() >= crate::sessions::MAX_SESSIONS {
                        crate::channel::Channel::retire(&channel);
                        break;
                    }
                    let state = state.clone();
                    terminals.spawn(async move {
                        if allow_priming {
                            daemon::run_negotiated_bound_terminal(&channel, Some(state)).await
                        } else {
                            daemon::run_bound_terminal(&channel, Some(state)).await
                        }
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
