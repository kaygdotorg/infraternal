//! Builds the static compiled plugin registry shared by embedded and remote agent runners [D198].

use infraternal_plugin_api::{PluginDescriptor, PluginError, PluginRegistry};

#[cfg(feature = "plugin-host-facts")]
const DESCRIPTORS: &[&PluginDescriptor] = &[&infraternal_plugin_host_facts::DESCRIPTOR];
#[cfg(not(feature = "plugin-host-facts"))]
const DESCRIPTORS: &[&PluginDescriptor] = &[];

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
    #[cfg(feature = "plugin-host-facts")]
    let mut registry = PluginRegistry::default();
    #[cfg(not(feature = "plugin-host-facts"))]
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
    Ok(registry)
}
