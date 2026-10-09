//! Defines the stable interface used by compiled first-party plugin crates [15][16].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod action;

pub use action::{
    ActionAvailability, ActionDefinition, ActionExample, ActionRegistry, JsonSchema,
    JsonSchemaType, PluginDefinition, RegisteredAction, RegistryError, SafetyNotes,
};
