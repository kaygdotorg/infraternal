//! Declares the owner-approved publication command for CLI, JSON, and skill adapters [D303, D314, #281].

use infraternal_plugin_api::{ActionDefinition, PluginDefinition};

/// Stable plugin owner used by the shared action registry.
pub const ID: &str = "proxy";

/// Build the proxy command table.
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(ID, "Publish a service through the node proxy.", Vec::<ActionDefinition>::new())
}
