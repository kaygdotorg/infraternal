//! Builds the static compiled plugin registry shared by embedded and remote agent runners [D198].

use infraternal_plugin_api::{PluginDescriptor, PluginError, PluginRegistry};

const DESCRIPTORS: &[&PluginDescriptor] = &[
    #[cfg(feature = "plugin-host-facts")]
    &infraternal_plugin_host_facts::DESCRIPTOR,
    #[cfg(feature = "remote")]
    &infraternal_plugin_remote::DESCRIPTOR,
];
#[cfg(feature = "remote")]
pub(crate) type Installation = infraternal_plugin_remote::uninstall::Context;
#[cfg(not(feature = "remote"))]
pub(crate) type Installation = ();

/// Host role bound to one agent process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    /// The server's own host.
    Embedded,
    /// A separately managed host.
    Remote,
}

/// Descriptors compiled into this infraternal agent binary, for server-side authorization.
#[must_use]
pub fn descriptors() -> &'static [&'static PluginDescriptor] {
    DESCRIPTORS
}

/// Creates the enabled-by-default registry for an agent execution context.
/// # Errors
/// Returns an error if the compiled plugin descriptors conflict with the plugin API.
pub fn registry(mode: ExecutionMode) -> Result<PluginRegistry, PluginError> {
    registry_with_installation(mode, None)
}

pub(crate) fn registry_with_installation(
    mode: ExecutionMode,
    installation: Option<&Installation>,
) -> Result<PluginRegistry, PluginError> {
    #[cfg(any(feature = "plugin-host-facts", feature = "remote"))]
    let mut registry = PluginRegistry::default();
    #[cfg(not(any(feature = "plugin-host-facts", feature = "remote")))]
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
    Ok(registry)
}

/// Exact private handoff decoder shared with parser fuzzing; parsing grants no authority.
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::uninstall::decode_request as decode_uninstall_request;
