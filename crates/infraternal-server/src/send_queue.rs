//! Keeps the kernel's unsent data for each browser connection small, so backpressure reaches the
//! server's own queues in time [#146].
//!
//! A socket normally accepts writes until its send buffer holds megabytes (the kernel grows it
//! with the congestion window and the memory limits). Behind a slow link that buffer is a hidden
//! queue: the server's write returns as soon as the kernel takes the bytes, so the server sees
//! no delay, its frame backlog and pressure signals never trigger, and video sits in the buffer
//! for seconds (measured on #146: 1.7 s at 3 Mbit/s). `TCP_NOTSENT_LOWAT` caps only the *unsent*
//! part of that buffer (bytes the link has not yet been given to carry): the socket stops being
//! writable while more than [`UNSENT_LOWAT`] bytes wait. Data already in flight does not count,
//! so a fast or distant link still fills its pipe. Writes then wait inside the server, where an
//! App Windows viewer can skip stale frames, measure its link and ask the encoder to slow down,
//! and where a terminal's key presses are not stuck behind a flood.
//!
//! One browser connection (`/v1/ws`) carries terminals and App Windows together, so the option
//! is set when the connection is accepted, on both the plain and the TLS listener. Hosts behind
//! a reverse proxy bound only the server-to-proxy leg this way; the proxy's own socket needs the
//! same bound (`net.ipv4.tcp_notsent_lowat`).
use axum_server::accept::Accept;
use std::{future::Ready, io};
use tokio::net::TcpStream;

/// The most unsent bytes a browser connection's kernel buffer holds before writes wait.
///
/// 32 KiB is about 85 ms of a 3 Mbit/s link and a few small frames of any link; the measurements
/// behind it are on #146 (J1167).
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNSENT_LOWAT: u32 = 32 * 1024;

/// Caps the unsent data in `socket`'s kernel buffer at [`UNSENT_LOWAT`] bytes.
///
/// Only Linux has the option; elsewhere this does nothing. A failure is logged and ignored: the
/// connection still works, with the old, deeper buffering.
pub(crate) fn bound_unsent_queue(socket: &TcpStream) {
    #[cfg(target_os = "linux")]
    if let Err(error) = socket2::SockRef::from(socket).set_tcp_notsent_lowat(UNSENT_LOWAT) {
        tracing::warn!(%error, "could not set TCP_NOTSENT_LOWAT on accepted server socket");
    }
    #[cfg(not(target_os = "linux"))]
    let _ = socket;
}

/// The socket setup every accepted browser connection gets: `TCP_NODELAY` (an acknowledgement and
/// the output it follows are separate small writes, and Nagle would delay the second until the
/// peer's delayed ACK) and the [`UNSENT_LOWAT`] bound. Use it as the inner acceptor under TLS.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SocketAdmission;

impl<S> Accept<TcpStream, S> for SocketAdmission {
    type Stream = TcpStream;
    type Service = S;
    type Future = Ready<io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        bound_unsent_queue(&stream);
        std::future::ready(stream.set_nodelay(true).and(Ok((stream, service))))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! A real accepted socket reports the bound; nothing is faked.
    use super::*;
    use axum_server::accept::Accept;

    /// The acceptor both listeners use sets `TCP_NODELAY` and `TCP_NOTSENT_LOWAT` before any bytes move.
    #[tokio::test]
    async fn accepted_sockets_have_nodelay_and_a_bounded_unsent_queue() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let _peer = tokio::net::TcpStream::connect(address).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        assert_eq!(
            socket2::SockRef::from(&socket).tcp_notsent_lowat().unwrap(),
            0,
            "the kernel default is no bound"
        );
        let (socket, ()) = SocketAdmission.accept(socket, ()).await.unwrap();
        assert!(socket.nodelay().unwrap());
        assert_eq!(
            socket2::SockRef::from(&socket).tcp_notsent_lowat().unwrap(),
            UNSENT_LOWAT
        );
    }
}
