//! Runs on each managed host and owns its local PTY and engine work [9][13][18].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod channel;
pub mod daemon;
pub mod relay;
pub mod remote_quic;
pub mod remote_tls;
pub mod sessions;
pub mod transport;

/// Run the standalone inherited-fd daemon after synchronous CLI dispatch [9][13].
/// Its shim children exec the synchronous hidden CLI arm before they fork; the
/// host daemon's current-thread reactor never runs inside those shim processes.
/// # Errors
/// Returns reactor initialization or trusted leg-B protocol/IO failures.
pub fn run_embedded(fd: i32, state: Option<std::path::PathBuf>) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(daemon::run(fd, state))
}
