//! Launches the D255 shim-owned shell and bridges SSH pipes through the existing terminal dispatcher.

use infraternal_agent::{
    daemon,
    sessions::{self, Manager},
    transport::Socket,
};
use infraternal_plugin_api::channel::Channel;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use std::{io, os::fd::AsRawFd, path::PathBuf, process::ExitCode};

/// Internal authenticated SSH command; all protocol output goes to its pipe.
/// No public shell, arbitrary command or login identity is accepted from argv.
pub fn run(state: PathBuf, session: Option<uuid::Uuid>) -> ExitCode {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|runtime| runtime.block_on(bridge(state, session)));
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
async fn bridge(state: PathBuf, existing: Option<uuid::Uuid>) -> io::Result<()> {
    let state = sessions::state(Some(state))?;
    let uid = nix::unistd::Uid::effective().as_raw();
    let exe = std::env::current_exe()?;
    let session = if let Some(id) = existing {
        // This is an authenticated rendezvous lookup, never process adoption.
        // The server supplies only the original person's published session id.
        sessions::connect(sessions::rendezvous(&state, *id.as_bytes()), *id.as_bytes()).await?
    } else {
        sessions::launch(&exe, &state, Manager::detect().await, uid, 80, 24).await?
    };
    let pipes = infraternal_plugin_ssh::stdio::Stdio::inherited()?;
    pipes
        .write(format!("SESSION {}\n", uuid::Uuid::from_bytes(session.id)).as_bytes())
        .await?;
    // The daemon discovers this exact shim through its ordinary authenticated
    // rendezvous. Neither this bridge nor SSH starts a shell outside the shim.
    drop(session);
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
        result = daemon::run_authenticated(&socket, Some(state), uid) => result,
        result = relay_pipes(&pipes, relay) => result,
    }
}

/// Copy both directions until either side closes; frames pass through unparsed.
async fn relay_pipes(
    pipes: &infraternal_plugin_ssh::stdio::Stdio,
    socket: tokio::net::UnixStream,
) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let outbound = async {
        let mut bytes = vec![0; 16 * 1024];
        loop {
            let count = from.read(&mut bytes).await?;
            if count == 0 {
                return Ok(());
            }
            pipes.write(&bytes[..count]).await?;
        }
    };
    tokio::select! {
        result = inbound => result,
        result = outbound => result,
    }
}
