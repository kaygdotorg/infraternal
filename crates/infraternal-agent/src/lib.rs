//! Runs on each managed host and owns its local PTY and engine work [9][13][18].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod channel;
pub mod cli;
#[cfg(target_os = "linux")]
pub mod daemon;
#[cfg(not(target_os = "linux"))]
pub use control as daemon;
#[path = "daemon_portable.rs"]
pub mod control;
mod daemon_writer;
#[cfg(target_os = "linux")]
mod lifecycle;
#[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
mod native_dispatch;
pub mod plugin_control;
pub mod plugins;
// Shim census exists only on the local terminal platform; portable control has no PTYs.
#[cfg(target_os = "linux")]
mod process_exits;
pub mod relay;
#[cfg(feature = "remote")]
pub mod remote_client;
#[cfg(feature = "remote")]
pub mod remote_cursor;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::remote_native;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::remote_quic;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::remote_renewal;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::remote_tls;
#[cfg(target_os = "linux")]
pub mod sessions;
pub mod transport;
#[cfg(any(test, feature = "native-streams"))]
pub mod wire;

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

#[cfg(all(test, feature = "remote", target_os = "linux"))]
mod transport_diagnostics;

#[cfg(all(test, feature = "remote", target_os = "linux"))]
#[path = "remote_native_tests.rs"]
mod remote_native_tests;

#[cfg(all(test, target_os = "linux"))]
mod process_exits_tests;
