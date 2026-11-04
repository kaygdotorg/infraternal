//! Launches the D255 shim-owned shell and bridges SSH pipes through the existing terminal dispatcher.
//!
//! This is the program that runs on the target host as the SSH command. It
//! starts (or reattaches to) a terminal session owned by the shim, never a
//! shell of its own, then copies bytes between the SSH pipes and the terminal
//! dispatcher over a private socket pair, without parsing them. Before the
//! first dispatcher bytes it writes one `SESSION <uuid>` line, in the same
//! write, which tells the other side the session exists. It accepts no command
//! or identity from its arguments: [`Options::decode`] allows exactly two shapes.

use infraternal_agent::{
    daemon,
    sessions::{self, Manager},
    transport::Socket,
};
use infraternal_plugin_api::channel::Channel;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use std::{io, os::fd::AsRawFd, path::PathBuf};

/// Only the authenticated internal startup shapes may enter the session bridge.
pub struct Options {
    /// Private state directory of the infraternal agent on this host.
    state: PathBuf,
    /// Existing session to reattach to; `None` launches a new one.
    session: Option<uuid::Uuid>,
}

impl Options {
    /// Decode the exact launcher shape before any filesystem or process work.
    ///
    /// Accepts `--state <dir>` or `--state <dir> --session <uuid>` and nothing
    /// else. Returns `None` for any other arguments or an invalid session id.
    #[must_use]
    pub fn decode(arguments: &[std::ffi::OsString]) -> Option<Self> {
        let (state, session) = match arguments {
            [flag, state] if flag == "--state" => (state, None),
            [flag, state, option, id] if flag == "--state" && option == "--session" => {
                (state, Some(uuid::Uuid::parse_str(id.to_str()?).ok()?))
            }
            _ => return None,
        };
        Some(Self {
            state: state.into(),
            session,
        })
    }

    /// Enter the same authenticated dispatcher as the installed executable.
    /// # Errors
    /// Returns runtime, private-state, shim admission or bridge failures.
    pub fn run(self) -> io::Result<()> {
        run(self.state, self.session)
    }

    /// Attach only the original session, without retaining node action workers.
    /// # Errors
    /// Returns runtime, private-state, shim admission or bridge failures.
    pub fn run_image(self) -> io::Result<()> {
        run_mode(self.state, self.session, daemon::run_session_image)
    }
}

/// Internal authenticated SSH command; all protocol output goes to its pipe.
/// No public shell, arbitrary command or login identity is accepted from argv.
///
/// With `session` set it reattaches and serves terminal actions only; without it
/// a new session is launched and plugin control is kept (#230). Blocks until the
/// bridge ends.
/// # Errors
/// Returns runtime, private-state, shim admission or authenticated bridge failures.
pub fn run(state: PathBuf, session: Option<uuid::Uuid>) -> io::Result<()> {
    // Retry reattaches a published session while the failed attempt's
    // infraternal agent may still hold the runtime lifetime lock, which plugin
    // control takes. A reattach serves terminal actions only, through the same
    // dispatcher instance; a new bridge keeps plugin control (#230). One
    // closure keeps one bridge instance for both shapes [243].
    let reattach = session.is_some();
    run_mode(
        state,
        session,
        async move |socket: &Socket, state, uid, session: sessions::Session| {
            drop(session);
            if reattach {
                daemon::run_authenticated_terminal(socket, state, uid).await
            } else {
                daemon::run_authenticated(socket, state, uid).await
            }
        },
    )
}

/// Run [`bridge`] to completion on a small single-thread runtime, serving the
/// session with `serve` (the dispatcher entry point to use).
fn run_mode<F>(state: PathBuf, session: Option<uuid::Uuid>, serve: F) -> io::Result<()>
where
    F: for<'a> AsyncFnOnce(&'a Socket, Option<PathBuf>, u32, sessions::Session) -> io::Result<()>
        + 'static,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    infraternal_agent::block_on_io(&runtime, Box::pin(bridge(state, session, serve)))
}
/// Obtain the session (reattach to `existing`, or launch one under the system
/// or user manager according to the effective uid), then run the dispatcher and
/// the pipe relay together. Ends when either one ends.
async fn bridge<F>(state: PathBuf, existing: Option<uuid::Uuid>, serve: F) -> io::Result<()>
where
    F: for<'a> AsyncFnOnce(&'a Socket, Option<PathBuf>, u32, sessions::Session) -> io::Result<()>,
{
    let state = sessions::state(Some(state))?;
    let uid = nix::unistd::Uid::effective().as_raw();
    let exe = std::env::current_exe()?;
    let session = if let Some(id) = existing {
        // This is an authenticated rendezvous lookup, never process adoption.
        // The server supplies only the original person's published session id.
        sessions::connect(sessions::rendezvous(&state, *id.as_bytes()), *id.as_bytes()).await?
    } else {
        // Both image entrypoints are called only after Check::parse and
        // authorize_mode proved the applicable managed scope. Do not probe
        // again or silently detach if that manager has since withdrawn.
        let manager = if uid == 0 {
            Manager::System
        } else {
            Manager::User
        };
        sessions::launch(&exe, &state, manager, uid, 80, 24).await?
    };
    let pipes = crate::stdio::Stdio::inherited()?;
    let session_id = session.id;
    // The daemon discovers this exact shim through its ordinary authenticated
    // rendezvous. Neither this bridge nor SSH starts a shell outside the shim.
    // The image-only dispatcher consumes this authenticated session directly;
    // full builds keep ordinary namespace discovery after dropping its data peer.
    // The dispatcher runs on the same socket channel type as the embedded
    // infraternal agent; a private socketpair relays the SSH pipes to it.
    // One more local copy on a temporary link buys one shared dispatcher
    // instance instead of a second one specialised for pipes (D243, #189).
    let (relay, dispatch) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .map_err(io::Error::from)?;
    let socket = Socket::inherited(dispatch.as_raw_fd())?;
    let relay = tokio::net::UnixStream::from_std(relay.into())?;
    tokio::select! {
        // Choose the future type before constructing this async state. A
        // branch containing both dispatchers also retains their drop paths.
        result = serve(&socket, Some(state), uid, session) => result,
        result = relay_pipes(&pipes, relay, session_id) => result,
    }
}

/// Copy both directions until either side closes; frames pass through unparsed.
async fn relay_pipes(
    pipes: &crate::stdio::Stdio,
    socket: tokio::net::UnixStream,
    session: [u8; 16],
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let (mut from, mut to) = socket.into_split();
    let inbound = async {
        let mut bytes = vec![0; 16 * 1024];
        loop {
            let count = pipes.read(&mut bytes).await?;
            if count == 0 {
                return Ok(());
            }
            to.write_all(&bytes[..count]).await?;
        }
    };
    let outbound = relay_output(pipes, &mut from, session);
    tokio::select! {
        result = inbound => result,
        result = outbound => result,
    }
}

/// Copy dispatcher output to the SSH pipe. The first write is prefixed with the
/// `SESSION <uuid>` line, so a session is announced only once the dispatcher
/// actually produced output; if it produces none, nothing is published.
async fn relay_output(
    pipes: &impl Channel,
    from: &mut (impl tokio::io::AsyncRead + Unpin),
    session: [u8; 16],
) -> io::Result<()> {
    use tokio::io::AsyncReadExt;
    // Publish only when the dispatcher can greet. Combining its first bytes
    // with the receipt avoids exposing a browser route whose actor still waits
    // for Hello; the receive loop must keep answering control probes meanwhile.
    let mut bytes = format!("SESSION {}\n", uuid::Uuid::from_bytes(session)).into_bytes();
    let mut prefix = bytes.len();
    bytes.resize(prefix + 16 * 1024, 0);
    loop {
        let count = from.read(&mut bytes[prefix..]).await?;
        if count == 0 {
            return Ok(());
        }
        pipes.write(&bytes[..prefix + count]).await?;
        prefix = 0;
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Fixture failures retain their direct assertion site."
)]
mod tests {
    //! A published SSH session must carry its dispatcher greeting in the same first write.
    use super::*;

    #[derive(Default)]
    struct Recording(std::sync::Mutex<Vec<Vec<u8>>>);
    impl Channel for Recording {
        fn read(&self, _: &mut [u8]) -> impl std::future::Future<Output = io::Result<usize>> {
            std::future::ready(Ok(0))
        }
        fn write(&self, bytes: &[u8]) -> impl std::future::Future<Output = io::Result<()>> {
            self.0.lock().unwrap().push(bytes.to_vec());
            std::future::ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn publication_and_dispatcher_greeting_share_the_first_write() {
        let pipes = Recording::default();
        let mut hello = b"dispatcher hello".as_slice();
        relay_output(&pipes, &mut hello, [7; 16]).await.unwrap();
        let expected = format!(
            "SESSION {}\ndispatcher hello",
            uuid::Uuid::from_bytes([7; 16])
        );
        assert_eq!(*pipes.0.lock().unwrap(), vec![expected.into_bytes()]);
    }

    #[tokio::test]
    async fn failed_dispatcher_does_not_publish_a_session() {
        let pipes = Recording::default();
        relay_output(&pipes, &mut b"".as_slice(), [7; 16])
            .await
            .unwrap();
        assert!(pipes.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn publication_prefix_preserves_every_dispatcher_byte_across_reads() {
        let pipes = Recording::default();
        let output: Vec<u8> = (0..=255).cycle().take(40_000).collect();
        relay_output(&pipes, &mut output.as_slice(), [7; 16])
            .await
            .unwrap();
        let mut expected = format!("SESSION {}\n", uuid::Uuid::from_bytes([7; 16])).into_bytes();
        expected.extend_from_slice(&output);
        let actual: Vec<u8> = pipes.0.lock().unwrap().iter().flatten().copied().collect();
        assert_eq!(actual, expected);
    }
}
