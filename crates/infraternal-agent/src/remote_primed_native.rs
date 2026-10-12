//! Owns bounded native standby relays independently of control activation; cancellation retires every shim socket [215], #129.
use crate::{daemon, remote_native::NativeChannel, remote_quic::BindingConnection};
use std::{io, path::PathBuf};
use tokio::task::{JoinHandle, JoinSet};

/// Only parked paths allocate this owned task. Its children never outlive the link.
pub(super) struct Service {
    task: JoinHandle<io::Result<()>>,
}

struct Retire(quinn::Connection);
impl Drop for Retire {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"");
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Service {
    pub(super) fn start(
        connection: quinn::Connection,
        binding: BindingConnection,
        state: PathBuf,
    ) -> Self {
        // Capture the guard before spawning: abort may drop an unpolled future.
        let retire = Retire(connection);
        let task = tokio::spawn(async move {
            // Closure, cancellation and panic all retire the owned transport.
            let _retire = retire;
            serve(&binding, state, true).await
        });
        Self { task }
    }
}

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
                    if terminals.len() >= infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS {
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

#[cfg(test)]
mod tests {
    //! Cancellation of the parked supervisor retires its owned real QUIC transport.
    use super::*;

    #[tokio::test]
    async fn dropping_parked_service_retires_transport() {
        let pair = crate::remote_native_tests::Pair::new().await;
        let service = Service::start(pair.client.clone(), pair.binding(false), PathBuf::new());
        // The task may be cancelled before its first poll; ownership must still
        // retire the connection rather than rely on executing the async body.
        drop(service);
        tokio::time::timeout(std::time::Duration::from_secs(2), pair.client.closed())
            .await
            .unwrap();
    }
}
