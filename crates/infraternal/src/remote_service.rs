//! Turns any enrolled server-link completion into a service failure without waiting indefinitely for background work [128], #225.
use std::io;

/// Run the link at the current-thread runtime boundary, then release it even if
/// polling panics. No partially updated link state resumes after unwinding.
/// Spawning this future would instantiate unused schedulers.
pub(crate) fn run(
    runtime: tokio::runtime::Runtime,
    link: impl std::future::Future<Output = io::Result<()>>,
) -> io::Result<()> {
    // Share the reactor poll loop with the other process entrypoints [243].
    // This one startup allocation replaces the caller's box; panic fencing
    // and bounded shutdown remain owned by this service.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        infraternal_agent::block_on_io(&runtime, Box::pin(link))
    }))
    .unwrap_or_else(|_| {
        Err(io::Error::other(
            "Infraternal agent server link task ended unexpectedly",
        ))
    });
    stopped(runtime, result)
}

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
    fn polling_panic_reaches_bounded_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let (ready, started) = std::sync::mpsc::channel();
        runtime.spawn_blocking(move || {
            ready.send(()).unwrap();
            let _ = wait.recv();
        });
        started.recv().unwrap();
        let (finished, completion) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = run(runtime, async { panic!("fixture polling failure") });
            finished.send(result.map_err(|error| error.kind())).unwrap();
        });
        let result = completion.recv_timeout(std::time::Duration::from_secs(5));
        release.send(()).unwrap();
        thread.join().unwrap();
        assert_eq!(result.unwrap(), Err(io::ErrorKind::Other));
    }

    #[test]
    fn successful_link_return_is_a_service_failure() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(run(runtime, async { Ok(()) }).is_err());
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
            let result = run(runtime, async { Err(io::ErrorKind::BrokenPipe.into()) });
            finished.send(result.map_err(|error| error.kind())).unwrap();
        });
        let result = completion.recv_timeout(std::time::Duration::from_secs(5));
        // Always release the fixture thread, including on a regression failure.
        release.send(()).unwrap();
        thread.join().unwrap();
        assert_eq!(result.unwrap(), Err(io::ErrorKind::BrokenPipe));
    }
}
