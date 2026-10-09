//! Declares compiled plugin actions, defaults and node lifecycle without owning their transports [15][16][198].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::{future::Future, pin::Pin};

/// Matches this crate's major version; descriptors are checked before discovery.
pub const API_VERSION: u16 = 0;

/// Stable name for a serialized shape supplied by the owning plugin's schema catalog.
#[derive(Clone, Copy, Debug)]
pub struct SchemaRef(pub &'static str);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Global,
    Node,
    Host,
    Session,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Read,
    Write,
    Destructive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DryRun {
    Unsupported,
    Supported,
    Required,
}

/// One description supplies help, skills and adapter labels; instructions are ordered steps [16][202].
#[derive(Clone, Copy, Debug)]
pub struct ActionDef {
    pub id: &'static str,
    pub summary: &'static str,
    pub instructions: &'static [&'static str],
    pub input: SchemaRef,
    pub output: SchemaRef,
    pub target: Target,
    pub effect: Effect,
    pub permission: &'static str,
    pub dry_run: DryRun,
    pub opens: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct EventDef {
    pub id: &'static str,
    pub schema: SchemaRef,
}
#[derive(Clone, Copy, Debug)]
pub struct StreamDef {
    pub id: &'static str,
    pub schema: SchemaRef,
    pub resumable: bool,
}
#[derive(Clone, Copy, Debug)]
pub enum DefaultValue {
    Bool(bool),
    Unsigned(u64),
    Text(&'static str),
}
#[derive(Clone, Copy, Debug)]
pub struct SettingDefault {
    pub id: &'static str,
    pub value: DefaultValue,
}

/// A confirmed server is a prerequisite, never an implicit node component [201].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dependency {
    ExistingServer,
    Component(&'static str),
}

/// Static data has no I/O or background work. Core discovers this through its compiled catalog.
#[derive(Clone, Copy, Debug)]
pub struct PluginDescriptor {
    pub id: &'static str,
    pub api: u16,
    pub actions: &'static [ActionDef],
    pub events: &'static [EventDef],
    pub streams: &'static [StreamDef],
    pub settings: Option<SchemaRef>,
    pub defaults: &'static [SettingDefault],
    pub dependencies: &'static [Dependency],
    pub can_enable_components: &'static [&'static str],
}
impl PluginDescriptor {
    /// Check declaration invariants before exposing a plugin through any adapter.
    /// # Errors
    /// Refuses incompatible versions, duplicate actions, missing instructions,
    /// destructive calls without a required dry run, or implicit server creation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.api != API_VERSION || self.id.is_empty() {
            return Err("The plugin definition is unavailable.");
        }
        if self.can_enable_components.contains(&"server")
            || self.dependencies.contains(&Dependency::Component("server"))
        {
            return Err("A node component cannot create a server.");
        }
        for (index, action) in self.actions.iter().enumerate() {
            if !action.id.starts_with(self.id)
                || action.id.as_bytes().get(self.id.len()) != Some(&b'.')
                || self.actions[..index]
                    .iter()
                    .any(|other| other.id == action.id)
                || action.summary.is_empty()
                || action.instructions.is_empty()
                || action.instructions.iter().any(|step| step.is_empty())
                || action.input.0.is_empty()
                || action.output.0.is_empty()
                || action.permission.is_empty()
                || action.effect == Effect::Destructive && action.dry_run != DryRun::Required
            {
                return Err("The plugin action definition is unavailable.");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginState {
    On,
    Stopping,
    Off,
}
impl PluginState {
    /// Shared plain state labels for human adapters [202].
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::On => "On",
            Self::Stopping => "Stopping",
            Self::Off => "Off",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginStatus {
    pub state: PluginState,
    pub active_work: usize,
}

/// Trusted core authorizes control calls before invoking a node's plugin.
/// Disable returns only after owned work, sockets and timers have retired [198].
pub trait Plugin: Send + Sync {
    fn descriptor(&self) -> &'static PluginDescriptor;
    fn status(&self) -> PluginStatus;
    fn set_enabled(&self, enabled: bool) -> PluginOperation<'_, ()>;
}

/// Control failures contain fixed public text, never transport data or login material.
pub type PluginOperation<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, &'static str>> + Send + 'a>>;

#[cfg(test)]
mod tests {
    use super::*;
    const ACTION: ActionDef = ActionDef {
        id: "fixture.read",
        summary: "Read status",
        instructions: &["Read the current status."],
        input: SchemaRef("fixture.empty"),
        output: SchemaRef("fixture.status"),
        target: Target::Node,
        effect: Effect::Read,
        permission: "fixture.read",
        dry_run: DryRun::Unsupported,
        opens: None,
    };
    const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
        id: "fixture",
        api: API_VERSION,
        actions: &[ACTION],
        events: &[],
        streams: &[],
        settings: None,
        defaults: &[],
        dependencies: &[Dependency::ExistingServer],
        can_enable_components: &["ssh"],
    };
    #[test]
    fn component_declarations_cannot_create_servers() {
        assert!(DESCRIPTOR.validate().is_ok());
        let invalid = PluginDescriptor {
            can_enable_components: &["server"],
            ..DESCRIPTOR
        };
        assert!(invalid.validate().is_err());
        let invalid = PluginDescriptor {
            dependencies: &[Dependency::Component("server")],
            ..DESCRIPTOR
        };
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn destructive_actions_require_a_dry_run_and_every_action_has_instructions() {
        const DESTRUCTIVE: [ActionDef; 1] = [ActionDef {
            effect: Effect::Destructive,
            ..ACTION
        }];
        const MISSING: [ActionDef; 1] = [ActionDef {
            instructions: &[],
            ..ACTION
        }];
        const REQUIRED: [ActionDef; 1] = [ActionDef {
            effect: Effect::Destructive,
            dry_run: DryRun::Required,
            ..ACTION
        }];
        assert!(
            PluginDescriptor {
                actions: &DESTRUCTIVE,
                ..DESCRIPTOR
            }
            .validate()
            .is_err()
        );
        assert!(
            PluginDescriptor {
                actions: &MISSING,
                ..DESCRIPTOR
            }
            .validate()
            .is_err()
        );
        assert!(
            PluginDescriptor {
                actions: &REQUIRED,
                ..DESCRIPTOR
            }
            .validate()
            .is_ok()
        );
    }
}
