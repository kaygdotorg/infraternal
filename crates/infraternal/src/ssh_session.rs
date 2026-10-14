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
        .and_then(|runtime| {
            infraternal_agent::block_on_io(&runtime, Box::pin(bridge(state, session)))
        });
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
    let session_id = session.id;
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
        result = relay_pipes(&pipes, relay, session_id) => result,
    }
}

/// Copy both directions until either side closes; frames pass through unparsed.
async fn relay_pipes(
    pipes: &infraternal_plugin_ssh::stdio::Stdio,
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
