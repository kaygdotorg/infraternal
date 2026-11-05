//! Runs on each managed host and owns its local PTY and engine work [9][13][18].
//!
//! Benchmark probes are deliberately absent from the normal library, including
//! release builds. The release exclusion check compiles a consumer against it.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod channel;
pub mod cli;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod daemon;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use control as daemon;
#[path = "daemon_portable.rs"]
pub mod control;
mod daemon_writer;
/// Admit bounded durable work before moving it off the async runtime.
mod durable_io;
/// Hold real saves until unrelated reactor work proves it can still run.
#[cfg(test)]
mod durable_tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod lifecycle;
mod login_auth;
mod login_binary;
mod login_records;
pub mod logins;
#[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
mod native_dispatch;
pub mod plugin_control;
pub mod plugins;
// Shim census exists only on the local terminal platform; portable control has no PTYs.
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
// Session automation authenticates callers by walking /proc ancestry; it has
// no macOS process-tree check yet, so it stays Linux-only (#328).
#[cfg(target_os = "linux")]
pub mod automation;
pub mod sessions;
pub mod startup_guard;
pub mod transport;
#[cfg(any(test, feature = "native-streams"))]
pub mod wire;

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

#[cfg(all(test, feature = "remote", target_os = "linux"))]
mod transport_diagnostics;

#[cfg(all(test, feature = "remote", target_os = "linux"))]
#[path = "remote_native_tests.rs"]
mod remote_native_tests;

#[cfg(all(test, target_os = "linux"))]
mod process_exits_tests;

/// Test and benchmark measurements with an injected slow file writer (D351).
#[cfg(any(test, feature = "bench-probes"))]
pub mod runtime_probe;
/// Functional coverage for the optional responsiveness helper.
#[cfg(test)]
mod runtime_probe_tests;
