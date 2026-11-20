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
/// Resolve bounded direct scheduler executables and file arguments (D367).
mod access_command;
/// Fingerprints of an account's access files at grant, compared on revoke (D356).
pub mod access_files;
/// Observe future system-account work without stopping it (D367).
mod access_jobs;
/// Conservative inspection of current and legacy polkit policy.
mod access_polkit;
/// Host policy checks for accounts that can exercise root authority.
mod access_privilege;
/// Read typed systemd lifecycle commands without losing argument boundaries.
mod access_units;
/// Kernel permission checks for bounded system-job targets.
mod access_write;
/// Kernel UID observations that verify session shutdown and report leftovers.
mod account_processes;
#[path = "daemon_portable.rs"]
pub mod control;
mod daemon_writer;
/// Admit bounded durable work before moving it off the async runtime.
mod durable_io;
/// Hold real saves until unrelated reactor work proves it can still run.
#[cfg(test)]
mod durable_tests;
/// Keep binaries that systemd starts executable under `SELinux` (#401).
pub mod exec_label;
/// The host OS named in the infraternal agent's link Hello, and the server's reader for it.
pub mod host_os;
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
/// The rootless infraternal agent's control actions for its own root upgrade (D376).
#[cfg(all(feature = "remote", target_os = "linux"))]
pub mod privilege_agent;
/// Becoming root once with the person's password for a root upgrade (D376).
#[cfg(all(feature = "remote", target_os = "linux"))]
pub mod privilege_elevate;
/// The short-lived root relay that runs a root upgrade's install steps (D376).
#[cfg(all(feature = "remote", target_os = "linux"))]
pub mod privilege_relay_host;
/// The root infraternal agent retiring the rootless install it replaced (D376).
#[cfg(all(feature = "remote", target_os = "linux"))]
pub mod privilege_take_over;
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
pub mod shutdown;
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
    run_embedded_with_mesh_state(fd, state, None)
}

/// Run the inherited-fd daemon with an independent mesh state path when the server owns it.
///
/// `state` still controls sessions and the other plugins. `mesh_state` changes only the Mesh
/// node's files, so an embedded server can keep its mesh identity durable without making its
/// live sessions durable.
/// # Errors
/// Returns reactor initialization or trusted leg-B protocol/IO failures.
pub fn run_embedded_with_mesh_state(
    fd: i32,
    state: Option<std::path::PathBuf>,
    mesh_state: Option<std::path::PathBuf>,
) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Components' host state goes when this daemon ends, by return or SIGTERM (#221).
    block_on_io(
        &runtime,
        Box::pin(shutdown::run_then_stop(daemon::run_with_mesh_state(
            fd, state, mesh_state,
        ))),
    )
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
