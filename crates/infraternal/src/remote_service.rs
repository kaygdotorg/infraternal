//! Turns any enrolled server-link completion into a service failure without waiting indefinitely for background work [128], #225.
use std::io;

/// Joining without running is handled separately by the caller. A running
/// service has no successful completion: the manager must recover any return.
pub(crate) fn stopped(runtime: tokio::runtime::Runtime, result: io::Result<()>) -> io::Result<()> {
    // A detached blocking task cannot be cancelled by Tokio. Waiting for it
    // here would conceal a dead link from the service manager indefinitely.
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    result?;
    Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "Infraternal agent server link stopped unexpectedly",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_link_return_is_a_service_failure() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(stopped(runtime, Ok(())).is_err());
    }

    #[test]
    fn link_failure_does_not_wait_forever_for_blocking_work() {
        let (release, wait) = std::sync::mpsc::channel();
        let (ready, started) = std::sync::mpsc::channel();
        let (finished, completion) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.spawn_blocking(move || {
                ready.send(()).unwrap();
                let _ = wait.recv();
            });
            started.recv().unwrap();
            let result = stopped(runtime, Err(io::ErrorKind::BrokenPipe.into()));
            finished.send(result.map_err(|error| error.kind())).unwrap();
        });
        let result = completion.recv_timeout(std::time::Duration::from_secs(5));
        // Always release the fixture thread, including on a regression failure.
        release.send(()).unwrap();
        thread.join().unwrap();
        assert_eq!(result.unwrap(), Err(io::ErrorKind::BrokenPipe));
    }
}
