//! Builds the static compiled plugin registry shared by embedded and remote infraternal agent runners [D198].

use infraternal_plugin_api::{PluginDescriptor, PluginError, PluginRegistry};

const DESCRIPTORS: &[&PluginDescriptor] = &[
    #[cfg(feature = "plugin-host-facts")]
    &infraternal_plugin_host_facts::DESCRIPTOR,
    #[cfg(feature = "remote")]
    &infraternal_plugin_remote::DESCRIPTOR,
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    &infraternal_plugin_mesh::node_actions::DESCRIPTOR,
];
#[cfg(feature = "remote")]
pub(crate) type Installation = infraternal_plugin_remote::uninstall::Context;
#[cfg(not(feature = "remote"))]
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
        all(feature = "mesh", target_os = "linux")
    ))]
    let mut registry = PluginRegistry::default();
    #[cfg(not(any(
        feature = "plugin-host-facts",
        feature = "remote",
        all(feature = "mesh", target_os = "linux")
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
    #[cfg(feature = "remote")]
    if mode == ExecutionMode::Remote
        && let Some(context) = installation
    {
        let home = std::env::var_os("HOME").map_or_else(|| "/".into(), std::path::PathBuf::from);
        if let Ok(plugin) = infraternal_plugin_remote::uninstall::UninstallPlugin::new(
            context.clone(),
            home,
            nix::unistd::Uid::effective().as_raw(),
        ) {
            registry.register(Box::new(plugin))?;
        }
    }
    #[cfg(not(feature = "remote"))]
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

/// Remove kernel objects a stopped infraternal agent leaves behind, for host uninstall (D273, #235).
///
/// The mesh interface and its packet filter belong to the kernel, not to the
/// daemon process, so stopping the service keeps them (by design across
/// restarts). Only the root infraternal agent can create them; a rootless
/// installation has none to remove.
/// # Errors
/// Reports a kernel cleanup failure, or an interface or table with our name that we do not own.
pub fn retire_kernel_state(state: &std::path::Path) -> std::io::Result<()> {
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    if nix::unistd::Uid::effective().is_root() {
        return infraternal_plugin_mesh::node::Node::retire(state);
    }
    let _ = state;
    Ok(())
}

/// Exact private handoff decoder shared with parser fuzzing; parsing grants no authority.
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::uninstall::decode_request as decode_uninstall_request;
