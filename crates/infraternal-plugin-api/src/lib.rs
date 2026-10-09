//! Defines the stable interface used by compiled first-party plugin crates [15][16].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::collections::HashSet;

/// Major version implemented by this plugin API crate.
pub const API_VERSION: u16 = 1;
/// Maximum encoded input or output accepted by one plugin action.
pub const MAX_ACTION_BYTES: usize = 8 * 1024;

/// The requested permission scope for an action, shared by server adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The action applies to the authenticated infraternal agent host.
    Host,
}

/// Whether an action reads or changes plugin state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Reads state without changing it.
    Read,
    /// Changes plugin settings or state.
    Write,
}

/// One action published by a plugin and used for generic call routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionDef {
    /// Stable `<plugin>.<noun>.<verb>` identifier.
    pub id: &'static str,
    /// Plain-language one-line purpose.
    pub summary: &'static str,
    /// JSON Schema document for the action input.
    pub input_schema: &'static str,
    /// JSON Schema document for the action output.
    pub output_schema: &'static str,
    /// Authorization scope.
    pub target: Target,
    /// Read or write behavior.
    pub effect: Effect,
    /// Permission that enables the action.
    pub permission: &'static str,
}

/// UI-editable settings and the action used to apply them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettingsDef {
    /// JSON Schema document for settings.
    pub schema: &'static str,
    /// JSON settings applied when the plugin is first registered.
    pub defaults: &'static str,
    /// Action that updates this plugin's settings.
    pub configure_action: &'static str,
}

/// Static metadata every compiled plugin declares for generated adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginDescriptor {
    /// Unique lowercase plugin id.
    pub id: &'static str,
    /// Plugin API major version.
    pub api: u16,
    /// Declared actions handled by the plugin.
    pub actions: &'static [ActionDef],
    /// Settings schema, defaults, and configure action.
    pub settings: SettingsDef,
    /// Runtime roles that must be enabled before this plugin can run.
    pub role_dependencies: &'static [&'static str],
}

/// A plugin implementation that can be routed without feature-specific agent code.
pub trait AgentPlugin: Send {
    /// Static action and settings metadata.
    fn descriptor(&self) -> &'static PluginDescriptor;
    /// Validate and execute one declared action.
    fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError>;
}

/// A bounded registry that dispatches actions only to declared plugin handlers.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Box<dyn AgentPlugin>>,
    action_ids: HashSet<&'static str>,
    plugin_ids: HashSet<&'static str>,
}

impl PluginRegistry {
    /// Registers one plugin whose descriptor is internally consistent.
    /// # Errors
    /// Rejects unsupported API versions, duplicate ids, or actions outside the plugin namespace.
    pub fn register(&mut self, plugin: Box<dyn AgentPlugin>) -> Result<(), PluginError> {
        let descriptor = plugin.descriptor();
        if descriptor.api != API_VERSION
            || self.plugin_ids.contains(descriptor.id)
            || descriptor.actions.iter().any(|action| {
                !action.id.starts_with(&format!("{}.", descriptor.id))
                    || self.action_ids.contains(action.id)
            })
            || !descriptor
                .actions
                .iter()
                .any(|action| action.id == descriptor.settings.configure_action)
        {
            return Err(PluginError::InvalidDescriptor);
        }
        self.plugin_ids.insert(descriptor.id);
        self.action_ids
            .extend(descriptor.actions.iter().map(|action| action.id));
        self.plugins.push(plugin);
        Ok(())
    }

    /// Executes one declared action while bounding both directions of its JSON body.
    /// # Errors
    /// Returns a bounded error for an unknown action, oversized message, or plugin rejection.
    pub fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        if input.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        let plugin = self.plugins.iter_mut().find(|plugin| {
            plugin
                .descriptor()
                .actions
                .iter()
                .any(|action| action.id == action_id)
        });
        let Some(plugin) = plugin else {
            return Err(PluginError::UnknownAction);
        };
        let output = plugin.call(action_id, input)?;
        if output.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        Ok(output)
    }
}

/// Fixed-size plugin call failures safe to return over the control protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginError {
    /// No registered plugin declared the requested action.
    UnknownAction,
    /// A descriptor conflicts with the current API or registry.
    InvalidDescriptor,
    /// Input or output exceeds the API bound.
    MessageTooLarge,
    /// The plugin rejected a validly routed action.
    Rejected,
}

#[cfg(test)]
mod tests;
