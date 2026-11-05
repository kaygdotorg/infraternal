//! Measure request responsiveness with a deliberately stalled file writer (D351).
//!
//! Call from a current-thread test runtime or the benchmark harness, passing an
//! actual infraternal agent request. The writer announces readiness after its
//! first write and waits on a channel until the request completes. This creates
//! deterministic overlap without a sleep or a functional-test latency bound.
//! Dropping the request releases the writer too. No periodic task runs at idle.
use std::{
    future::Future,
    io,
    io::Write,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};

/// Return a request's result and monotonic response time while a file write is held.
///
/// The caller owns the fresh path and removes it after the run. Functional tests
/// assert completion and contents; only performance runs judge the elapsed time.
/// # Errors
/// Returns file creation/write errors, a failed request, or a writer task failure.
pub async fn during_slow_write<T>(
    path: PathBuf,
    request: impl Future<Output = io::Result<T>>,
) -> io::Result<(T, Duration)> {
    let (release, held) = mpsc::channel::<()>();
    let (started, ready) = tokio::sync::oneshot::channel();
    let writer = tokio::task::spawn_blocking(move || -> io::Result<()> {
        let mut file = std::fs::File::create_new(path)?;
        file.write_all(b"pending")?;
        let _ = started.send(());
        // Channel disconnection also releases a cancelled measurement.
        let _ = held.recv();
        file.write_all(b"-complete")?;
        file.sync_all()
    });
    if ready.await.is_err() {
        writer.await.map_err(io::Error::other)??;
        return Err(io::Error::other("writer ended before announcing readiness"));
    }
    let start = Instant::now();
    let answer = request.await;
    let elapsed = start.elapsed();
    drop(release);
    writer.await.map_err(io::Error::other)??;
    Ok((answer?, elapsed))
}

/// Measure a correlated Pong from the real Linux dispatcher during a held write.
///
/// Use a fresh private state directory. The caller removes the directory after
/// the run. This uses the ordinary authenticated channel, parser and writer.
/// # Errors
/// Returns admission, framing, file or channel errors, without a timing bound.
#[cfg(target_os = "linux")]
pub async fn agent_ping_under_slow_write(state: PathBuf) -> io::Result<Duration> {
    use crate::transport::{Receive, Socket, Transmit};
    use infraternal_protocol::Frame;
    use std::os::fd::AsRawFd;
    let (host_fd, peer_fd) = std::os::unix::net::UnixStream::pair()?;
    let host = Socket::inherited(host_fd.as_raw_fd())?;
    let peer = Socket::inherited(peer_fd.as_raw_fd())?;
    drop((host_fd, peer_fd));
    let host_state = state.clone();
    let mut daemons = tokio::task::JoinSet::new();
    daemons.spawn(async move {
        crate::daemon::run_authenticated_terminal(
            &host,
            Some(host_state),
            nix::unistd::Uid::effective().as_raw(),
        )
        .await
    });
    let result = async {
        let mut tx = Transmit::default();
        let mut rx = Receive::default();
        tx.send(
            &peer,
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "runtime probe",
            },
        )
        .await?;
        if !matches!(rx.next(&peer).await?.frame, Frame::Hello { version: 1, .. }) {
            return Err(io::Error::other("missing probe greeting"));
        }
        let ((), elapsed) = during_slow_write(state.join("lag-probe.write"), async {
            tx.send(
                &peer,
                0,
                &Frame::Ping {
                    nonce: 73,
                    sent_us: 0,
                },
            )
            .await?;
            loop {
                let reply = rx.next(&peer).await?;
                if reply.stream_id == 0
                    && matches!(
                        reply.frame,
                        Frame::Pong {
                            nonce: 73,
                            sent_us: 0
                        }
                    )
                {
                    return Ok(());
                }
            }
        })
        .await?;
        Ok(elapsed)
    }
    .await;
    daemons.abort_all();
    while daemons.join_next().await.is_some() {}
    result
}
