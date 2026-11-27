//! Hands an owned TCP socket to OpenSSH with small-write latency disabled before key exchange (#190).

use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use std::{
    io::{self, IoSlice},
    net::{TcpStream, ToSocketAddrs},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

// A closed parent must surface as EPIPE, never as SIGPIPE. macOS has no
// MSG_NOSIGNAL; there the Rust runtime's ignored SIGPIPE (set before main,
// never reset by this binary) gives the same result.
#[cfg(target_os = "linux")]
/// Send flags that suppress SIGPIPE on a closed peer (Linux).
const NO_SIGPIPE: MsgFlags = MsgFlags::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
/// No send flag on macOS: the runtime ignores SIGPIPE instead.
const NO_SIGPIPE: MsgFlags = MsgFlags::empty();

/// This private helper receives only the configured public endpoint.
/// OpenSSH retains host-key verification, authentication and connection ownership.
/// # Errors
/// Refuses empty endpoints, failed DNS/connect, socket setup or descriptor delivery.
pub fn handoff(host: &str, port: u16, channel: &impl AsRawFd) -> io::Result<()> {
    handoff_with_diagnostic(host, port, channel).map_err(|(error, _)| error)
}

/// Hand off the socket and classify a failed dial without exposing resolver or OS text.
/// # Errors
/// Returns the local error and a fixed diagnostic for the invoking SSH client.
pub fn handoff_with_diagnostic(
    host: &str,
    port: u16,
    channel: &impl AsRawFd,
) -> Result<(), (io::Error, &'static str)> {
    let stream = connect(host, port)?;
    let descriptors = [stream.as_raw_fd()];
    let sent = sendmsg::<()>(
        channel.as_raw_fd(),
        &[IoSlice::new(b".")],
        &[ControlMessage::ScmRights(&descriptors)],
        NO_SIGPIPE,
        None,
    )
    .map_err(|error| (io::Error::from(error), "Socket handoff failed"))?;
    if sent != 1 {
        return Err((io::ErrorKind::WriteZero.into(), "Socket handoff failed"));
    }
    // SCM_RIGHTS transfers a kernel reference. Closing this helper's copy
    // leaves exactly the parent's socket; no relay or helper remains running.
    Ok(())
}

/// Resolve before dialing so a resolver failure cannot be mistaken for a TCP refusal.
fn connect(host: &str, port: u16) -> Result<TcpStream, (io::Error, &'static str)> {
    if host.is_empty() || port == 0 {
        return Err((io::ErrorKind::InvalidInput.into(), "Invalid endpoint"));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut failure = io::Error::from(io::ErrorKind::AddrNotAvailable);
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| (error, "Could not resolve hostname"))?;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((io::ErrorKind::TimedOut.into(), "Connection timed out"));
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .map_err(|error| (error, "Socket setup failed"))?;
                return Ok(stream);
            }
            Err(error) => failure = error,
        }
    }
    let diagnostic = match failure.kind() {
        io::ErrorKind::ConnectionRefused => "Connection refused",
        io::ErrorKind::TimedOut => "Connection timed out",
        _ => "Connection failed",
    };
    Err((failure, diagnostic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{ControlMessageOwned, recv, recvmsg};
    use std::{
        io::{IoSliceMut, Write},
        net::TcpListener,
        os::unix::net::UnixStream,
    };

    #[test]
    fn connected_socket_has_nodelay_before_any_application_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stream = connect("127.0.0.1", address.port()).unwrap();
        assert!(stream.nodelay().unwrap());
        assert_eq!(stream.peer_addr().unwrap(), address);
    }

    #[test]
    fn descriptor_delivery_keeps_the_exact_peer_after_helper_copy_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        handoff("127.0.0.1", address.port(), &sender).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        accepted.write_all(b"peer-proof").unwrap();
        let mut byte = [0; 1];
        let mut vectors = [IoSliceMut::new(&mut byte)];
        let mut ancillary = nix::cmsg_space!([std::os::fd::RawFd; 1]);
        let message = recvmsg::<()>(
            receiver.as_raw_fd(),
            &mut vectors,
            Some(&mut ancillary),
            MsgFlags::empty(),
        )
        .unwrap();
        let mut descriptors = Vec::new();
        for control in message.cmsgs().unwrap() {
            if let ControlMessageOwned::ScmRights(received) = control {
                descriptors.extend(received);
            }
        }
        let peers: Vec<_> = descriptors
            .iter()
            .map(|fd| {
                let mut proof = [0; 10];
                let count = recv(*fd, &mut proof, MsgFlags::empty());
                (count, proof)
            })
            .collect();
        for fd in descriptors {
            nix::unistd::close(fd).unwrap();
        }
        assert_eq!(byte, *b".");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0.as_ref().unwrap(), &10);
        assert_eq!(peers[0].1, *b"peer-proof");
    }

    #[test]
    fn invalid_endpoint_cannot_send_a_descriptor() {
        let (sender, _) = UnixStream::pair().unwrap();
        assert_eq!(
            handoff("", 22, &sender).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            handoff("127.0.0.1", 0, &sender).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
