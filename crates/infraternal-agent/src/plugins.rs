//! Builds the static compiled plugin registry shared by embedded and remote infraternal agent runners [D198].

use infraternal_plugin_api::{PluginDescriptor, PluginError, PluginRegistry};

/// One node registry survives authenticated transport replacement; owned
/// asynchronous operations never hold this lock while waiting on native I/O.
pub type SharedRegistry = std::sync::Arc<std::sync::Mutex<PluginRegistry>>;

const DESCRIPTORS: &[&PluginDescriptor] = &[
    #[cfg(feature = "plugin-host-facts")]
    &infraternal_plugin_host_facts::DESCRIPTOR,
    #[cfg(feature = "remote")]
    &infraternal_plugin_remote::DESCRIPTOR,
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    &infraternal_plugin_mesh::node_actions::DESCRIPTOR,
    #[cfg(all(feature = "desktop", target_os = "macos"))]
    &infraternal_plugin_desktop::source_manifest::DESCRIPTOR,
];
#[cfg(all(feature = "remote", target_os = "linux"))]
pub(crate) type Installation = infraternal_plugin_remote::uninstall::Context;
#[cfg(not(all(feature = "remote", target_os = "linux")))]
pub(crate) type Installation = ();

/// Host role bound to one infraternal agent process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    /// The server's own host.
    Embedded,
    /// A separately managed host.
    Remote,
}

/// Descriptors compiled into this infraternal agent binary, for server-side authorization.
#[must_use]
pub const fn descriptors() -> &'static [&'static PluginDescriptor] {
    DESCRIPTORS
}

/// Creates the enabled-by-default registry for an infraternal agent execution context.
/// # Errors
/// Returns an error if the compiled plugin descriptors conflict with the plugin API.
pub fn registry(mode: ExecutionMode) -> Result<PluginRegistry, PluginError> {
    registry_at(mode, None, None)
}

// Even an empty build keeps the same fallible factory contract as builds with
// registered plugins; feature selection must not change its caller's API.
#[cfg_attr(
    not(any(
        feature = "plugin-host-facts",
        feature = "remote",
        all(feature = "mesh", target_os = "linux")
    )),
    allow(
        clippy::unnecessary_wraps,
        reason = "Keep the fallible registry API identical when every optional component is compiled out."
    )
)]
pub(crate) fn registry_at(
    mode: ExecutionMode,
    state: Option<&std::path::Path>,
    installation: Option<&Installation>,
) -> Result<PluginRegistry, PluginError> {
    #[cfg(any(
        feature = "plugin-host-facts",
        feature = "remote",
        all(feature = "mesh", target_os = "linux"),
        all(feature = "desktop", target_os = "macos")
    ))]
    let mut registry = PluginRegistry::default();
    #[cfg(not(any(
        feature = "plugin-host-facts",
        feature = "remote",
        all(feature = "mesh", target_os = "linux"),
        all(feature = "desktop", target_os = "macos")
    )))]
    let registry = PluginRegistry::default();
    #[cfg(feature = "plugin-host-facts")]
    {
        use infraternal_plugin_host_facts::AgentMode;
        let facts_mode = match mode {
            ExecutionMode::Embedded => AgentMode::Embedded,
            ExecutionMode::Remote => AgentMode::Remote,
        };
        registry.register(Box::new(
            infraternal_plugin_host_facts::HostFactsPlugin::new(facts_mode),
        ))?;
    }
    #[cfg(not(feature = "plugin-host-facts"))]
    let _ = mode;
    #[cfg(all(feature = "remote", target_os = "linux"))]
    if mode == ExecutionMode::Remote
        && let Some(context) = installation
    {
        let home = std::env::var_os("HOME").map_or_else(|| "/".into(), std::path::PathBuf::from);
        if let Ok(plugin) = infraternal_plugin_remote::uninstall::UninstallPlugin::new(
            context.clone(),
            home,
            nix::unistd::Uid::effective().as_raw(),
            KERNEL,
        ) {
            registry.register(Box::new(plugin))?;
        }
    }
    #[cfg(all(feature = "desktop", target_os = "macos"))]
    {
        let home = std::env::var_os("HOME").ok_or(PluginError::Rejected)?;
        let runtime = std::path::PathBuf::from(home).join(".cache/infraternal/desktop-source");
        let executable = std::env::current_exe().map_err(|_| PluginError::Rejected)?;
        let helper = executable
            .parent()
            .ok_or(PluginError::Rejected)?
            .join("infraternal-desktop-helper");
        // Construction retains trusted metadata only; desktop.up is the explicit
        // per-node component switch, and known Attach is the sole capture opener.
        registry.register(Box::new(
            infraternal_plugin_desktop::source::SourceBridge::new(
                runtime,
                helper,
                infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS,
            ),
        ))?;
    }
    #[cfg(not(all(feature = "remote", target_os = "linux")))]
    let _ = installation;
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    registry.register(Box::new(state.map_or_else(
        infraternal_plugin_mesh::node_actions::MeshNodePlugin::default,
        infraternal_plugin_mesh::node_actions::MeshNodePlugin::new,
    )))?;
    #[cfg(not(all(feature = "mesh", target_os = "linux")))]
    let _ = state;
    Ok(registry)
}

/// Kernel objects an installation leaves outside its files, for host uninstall (D273, #235).
///
/// The mesh interface and its packet filter belong to the kernel, not to the
/// daemon process, so stopping the service keeps them (by design across
/// restarts). Only the root infraternal agent can create them; a rootless
/// installation has none. Ownership is this installation's mesh state record,
/// never the shared name or marker: see `Node::plan_retirement`.
#[cfg(all(feature = "remote", target_os = "linux"))]
pub const KERNEL: infraternal_plugin_remote::uninstall::Kernel =
    infraternal_plugin_remote::uninstall::Kernel {
        inspect: inspect_kernel_state,
        retire: retire_kernel_state,
    };
// The uninstall callback keeps its fallible signature even without kernel roles.
#[cfg(all(feature = "remote", target_os = "linux"))]
#[cfg_attr(not(feature = "mesh"), allow(clippy::unnecessary_wraps))]
fn inspect_kernel_state(state: &std::path::Path) -> std::io::Result<Vec<&'static str>> {
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    if nix::unistd::Uid::effective().is_root() {
        return infraternal_plugin_mesh::node::Node::plan_retirement(state)
            .map(|plan| plan.left().to_vec());
    }
    let _ = state;
    Ok(Vec::new())
}
#[cfg(all(feature = "remote", target_os = "linux"))]
#[cfg_attr(not(feature = "mesh"), allow(clippy::unnecessary_wraps))]
fn retire_kernel_state(state: &std::path::Path) -> std::io::Result<Vec<&'static str>> {
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    if nix::unistd::Uid::effective().is_root() {
        return infraternal_plugin_mesh::node::Node::retire(state);
    }
    let _ = state;
    Ok(Vec::new())
}

/// Exact private handoff decoder shared with parser fuzzing; parsing grants no authority.
#[cfg(all(feature = "remote", target_os = "linux"))]
pub use infraternal_plugin_remote::uninstall::decode_request as decode_uninstall_request;
