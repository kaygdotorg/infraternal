//! Runs on each managed host and owns its local PTY and engine work [9][13][18].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod channel;
pub mod cli;
pub mod daemon;
mod lifecycle;
mod login_auth;
mod login_binary;
mod login_records;
pub mod logins;
pub mod plugin_control;
pub mod plugins;
mod process_exits;
pub mod relay;
#[cfg(feature = "remote")]
pub mod remote_client;
#[cfg(feature = "remote")]
pub mod remote_cursor;
#[cfg(feature = "remote")]
pub mod remote_websocket;
mod rootless_sessions;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::remote_native;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::remote_quic;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::remote_renewal;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::remote_tls;
#[cfg(target_os = "linux")]
pub mod automation;
pub mod sessions;
pub mod startup_guard;
pub mod transport;

/// Resolve the per-job root used by tests that bind local socket fixtures.
/// The configured root keeps socket names short while `HOME` stays absolute
/// for tests that validate account paths. Standalone runs retain their cache fallback.
#[cfg(test)]
pub(crate) fn test_state_root() -> std::path::PathBuf {
    let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
        || {
            std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME for test scratch"))
                .join(".cache/codex-scratch/remote-agents")
        },
        std::path::PathBuf::from,
    );
    std::fs::create_dir_all(&root).expect("prepare isolated test state root");
    root
}

/// Run the standalone inherited-fd daemon after synchronous CLI dispatch [9][13].
/// Its shim children exec the synchronous hidden CLI arm before they fork; the
/// host daemon's current-thread reactor never runs inside those shim processes.
/// # Errors
/// Returns reactor initialization or trusted leg-B protocol/IO failures.
pub fn run_embedded(fd: i32, state: Option<std::path::PathBuf>) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    block_on_io(&runtime, Box::pin(daemon::run(fd, state)))
}

/// Share the reactor poll loop across process entrypoints (D243, #189).
/// Type erasure allocates once per reactor, never per terminal frame; the
/// configured runtime retains its existing scheduling and unwind behavior.
/// # Errors
/// Returns the operation's IO error unchanged.
#[inline(never)]
pub fn block_on_io(
    runtime: &tokio::runtime::Runtime,
    operation: std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + '_>>,
) -> std::io::Result<()> {
    runtime.block_on(operation)
}

#[cfg(all(test, feature = "remote"))]
mod transport_diagnostics;

#[cfg(all(test, feature = "remote"))]
#[path = "remote_native_tests.rs"]
mod remote_native_tests;

#[cfg(all(test, target_os = "linux"))]
mod process_exits_tests;
