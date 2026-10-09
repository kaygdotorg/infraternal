//! Serializable action contracts shared by plugin adapters, including CLI help and generated skills.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

/// JSON Schema types used for action input and output contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonSchemaType {
    /// A JSON string.
    String,
    /// A JSON integer.
    Integer,
    /// A JSON number.
    Number,
    /// A JSON boolean.
    Boolean,
    /// A JSON object.
    Object,
    /// A JSON array.
    Array,
}

/// A small JSON Schema document with stable, ordered object properties.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JsonSchema {
    /// The JSON Schema type.
    #[serde(rename = "type")]
    pub schema_type: JsonSchemaType,
    /// Human-readable explanation of the value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Object fields, ordered by field name during serialization.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Self>,
    /// Required object fields.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// Array item schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<Self>>,
    /// Whether object properties outside properties are allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_properties: Option<bool>,
}

impl JsonSchema {
    /// Create a string schema with a description.
    #[must_use]
    pub fn string(description: impl Into<String>) -> Self {
        Self::scalar(JsonSchemaType::String, description)
    }

    /// Create an integer schema with a description.
    #[must_use]
    pub fn integer(description: impl Into<String>) -> Self {
        Self::scalar(JsonSchemaType::Integer, description)
    }

    /// Create a number schema with a description.
    #[must_use]
    pub fn number(description: impl Into<String>) -> Self {
        Self::scalar(JsonSchemaType::Number, description)
    }

    /// Create a boolean schema with a description.
    #[must_use]
    pub fn boolean(description: impl Into<String>) -> Self {
        Self::scalar(JsonSchemaType::Boolean, description)
    }

    /// Create an object schema with strict additional-property handling.
    #[must_use]
    pub fn object(
        properties: impl IntoIterator<Item = (String, Self)>,
        required: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            schema_type: JsonSchemaType::Object,
            description: None,
            properties: properties.into_iter().collect(),
            required: required.into_iter().collect(),
            items: None,
            additional_properties: Some(false),
        }
    }

    /// Create an empty object schema.
    #[must_use]
    pub fn empty_object() -> Self {
        Self::object(std::iter::empty(), std::iter::empty())
    }

    /// Create the stable result schema used for action state and next-step output.
    #[must_use]
    pub fn command_result() -> Self {
        Self::object(
            [
                (
                    "schema_version".to_owned(),
                    Self::integer("Version of the CLI JSON result contract."),
                ),
                ("command".to_owned(), Self::string("Executed command path.")),
                (
                    "state".to_owned(),
                    Self::string("Plain machine-readable command state."),
                ),
                ("message".to_owned(), Self::string("Short result summary.")),
                (
                    "next_step".to_owned(),
                    Self::string("Optional recommended follow-up action."),
                ),
            ],
            [
                "schema_version".to_owned(),
                "command".to_owned(),
                "state".to_owned(),
                "message".to_owned(),
            ],
        )
    }

    /// Create an array schema for repeated values.
    #[must_use]
    pub fn array(items: Self, description: impl Into<String>) -> Self {
        Self {
            schema_type: JsonSchemaType::Array,
            description: Some(description.into()),
            properties: BTreeMap::new(),
            required: Vec::new(),
            items: Some(Box::new(items)),
            additional_properties: None,
        }
    }

    /// Add a value-level description to any schema type.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    fn scalar(schema_type: JsonSchemaType, description: impl Into<String>) -> Self {
        Self {
            schema_type,
            description: Some(description.into()),
            properties: BTreeMap::new(),
            required: Vec::new(),
            items: None,
            additional_properties: None,
        }
    }

    fn validate(&self) -> Result<(), RegistryError> {
        match self.schema_type {
            JsonSchemaType::Object => {
                if self.items.is_some() {
                    return Err(RegistryError::InvalidSchema(
                        "object schemas cannot declare array items".to_owned(),
                    ));
                }
                for field in &self.required {
                    if !self.properties.contains_key(field) {
                        return Err(RegistryError::InvalidSchema(format!(
                            "required field {field} is not declared"
                        )));
                    }
                }
                for schema in self.properties.values() {
                    schema.validate()?;
                }
            }
            JsonSchemaType::Array => {
                if !self.properties.is_empty() || !self.required.is_empty() {
                    return Err(RegistryError::InvalidSchema(
                        "array schemas cannot declare object properties".to_owned(),
                    ));
                }
                self.items
                    .as_deref()
                    .ok_or_else(|| {
                        RegistryError::InvalidSchema(
                            "array schemas must declare an item schema".to_owned(),
                        )
                    })?
                    .validate()?;
            }
            JsonSchemaType::String
            | JsonSchemaType::Integer
            | JsonSchemaType::Number
            | JsonSchemaType::Boolean => {
                if !self.properties.is_empty()
                    || !self.required.is_empty()
                    || self.items.is_some()
                    || self.additional_properties.is_some()
                {
                    return Err(RegistryError::InvalidSchema(
                        "scalar schemas cannot declare object or array fields".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Runtime availability for the action handler behind a CLI action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionAvailability {
    /// This action has an implementation in the current build.
    Available,
    /// The command is present as a placeholder for a future component.
    NotAvailableYet,
}

/// Example invocation and its user-facing result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionExample {
    /// Example command line without the executable name.
    pub invocation: String,
    /// Short explanation of the example.
    pub description: String,
}

/// Safety guidance shown in skills and available to other adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SafetyNotes {
    /// Whether this action can remove data, access, or running services.
    pub destructive: bool,
    /// Whether a dry run should be performed before the action.
    pub dry_run_first: bool,
    /// Additional concise safety notes.
    pub notes: Vec<String>,
}

/// Complete action metadata consumed by every presentation adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionDefinition {
    /// Command path, for example server features.
    pub command: Vec<String>,
    /// Concise command description used by help and skills.
    pub description: String,
    /// Situations where the command is useful.
    pub when_to_use: String,
    /// Ordered steps for using the command.
    pub instructions: Vec<String>,
    /// JSON Schema for command input.
    pub input_schema: JsonSchema,
    /// JSON Schema for the command's stable output.
    pub output_schema: JsonSchema,
    /// Concrete examples for help and skill adapters.
    pub examples: Vec<ActionExample>,
    /// Safety notes for destructive and dry-run-sensitive actions.
    pub safety: SafetyNotes,
    /// Whether the action has a working handler in this build.
    pub availability: ActionAvailability,
    /// Whether the action appears in user-facing help and skill listings.
    pub visible: bool,
}

impl ActionDefinition {
    /// Create a visible action with no examples and no special safety guidance.
    #[must_use]
    pub fn new(
        command: impl IntoIterator<Item = impl Into<String>>,
        description: impl Into<String>,
        when_to_use: impl Into<String>,
        instructions: impl IntoIterator<Item = impl Into<String>>,
        input_schema: JsonSchema,
        output_schema: JsonSchema,
    ) -> Self {
        Self {
            command: command.into_iter().map(Into::into).collect(),
            description: description.into(),
            when_to_use: when_to_use.into(),
            instructions: instructions.into_iter().map(Into::into).collect(),
            input_schema,
            output_schema,
            examples: Vec::new(),
            safety: SafetyNotes::default(),
            availability: ActionAvailability::Available,
            visible: true,
        }
    }

    /// Attach a command-line example.
    #[must_use]
    pub fn with_example(
        mut self,
        invocation: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.examples.push(ActionExample {
            invocation: invocation.into(),
            description: description.into(),
        });
        self
    }

    /// Mark an action as a visible placeholder for an unimplemented component.
    #[must_use]
    pub const fn not_available_yet(mut self) -> Self {
        self.availability = ActionAvailability::NotAvailableYet;
        self
    }

    /// Keep an action registered for internal execution without displaying it.
    #[must_use]
    pub const fn hidden(mut self) -> Self {
        self.visible = false;
        self
    }

    /// Add explicit safety guidance.
    #[must_use]
    pub fn with_safety(mut self, safety: SafetyNotes) -> Self {
        self.safety = safety;
        self
    }

    fn validate(&self, plugin_id: &str) -> Result<(), RegistryError> {
        if self.command.is_empty()
            || self.command.iter().any(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(RegistryError::InvalidAction(format!(
                "plugin {plugin_id} declares an invalid command path"
            )));
        }
        if self.description.trim().is_empty() {
            return Err(RegistryError::InvalidAction(format!(
                "action {} has no description",
                self.command.join(" ")
            )));
        }
        if self.when_to_use.trim().is_empty() {
            return Err(RegistryError::InvalidAction(format!(
                "action {} has no usage guidance",
                self.command.join(" ")
            )));
        }
        if self.instructions.is_empty()
            || self
                .instructions
                .iter()
                .any(|instruction| instruction.trim().is_empty())
        {
            return Err(RegistryError::InvalidAction(format!(
                "action {} must have non-empty instructions",
                self.command.join(" ")
            )));
        }
        self.input_schema.validate()?;
        self.output_schema.validate()?;
        Ok(())
    }
}

/// A plugin and the actions it registers into an adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginDefinition {
    /// Stable plugin identifier.
    pub id: String,
    /// Short plugin description used in generated help groups.
    pub description: String,
    /// Actions declared by this plugin.
    pub actions: Vec<ActionDefinition>,
}

impl PluginDefinition {
    /// Create a plugin descriptor with its action list.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        actions: impl IntoIterator<Item = ActionDefinition>,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            actions: actions.into_iter().collect(),
        }
    }
}

/// A registered action paired with its declaring plugin.
#[derive(Clone, Copy, Debug)]
pub struct RegisteredAction<'a> {
    /// Plugin that declared the action.
    pub plugin: &'a PluginDefinition,
    /// Action metadata supplied by that plugin.
    pub action: &'a ActionDefinition,
}

/// Validated set of actions from the plugins enabled in one build.
#[derive(Clone, Debug, Default)]
pub struct ActionRegistry {
    plugins: Vec<PluginDefinition>,
}

impl ActionRegistry {
    /// Validate and register the enabled plugin definitions.
    ///
    /// # Errors
    ///
    /// Returns an error when a plugin has incomplete metadata, a schema is invalid,
    /// or two plugins declare the same identifier or command path.
    pub fn new(plugins: Vec<PluginDefinition>) -> Result<Self, RegistryError> {
        let mut plugin_ids = std::collections::BTreeSet::new();
        let mut commands = std::collections::BTreeSet::new();
        for plugin in &plugins {
            if plugin.id.trim().is_empty() || !plugin_ids.insert(plugin.id.as_str()) {
                return Err(RegistryError::DuplicatePlugin(plugin.id.clone()));
            }
            if plugin.description.trim().is_empty() {
                return Err(RegistryError::InvalidAction(format!(
                    "plugin {} has no description",
                    plugin.id
                )));
            }
            for action in &plugin.actions {
                action.validate(&plugin.id)?;
                if !commands.insert(action.command.join(" ")) {
                    return Err(RegistryError::DuplicateCommand(action.command.join(" ")));
                }
            }
        }
        Ok(Self { plugins })
    }

    /// Iterate through registered actions in plugin declaration order.
    pub fn actions(&self) -> impl Iterator<Item = RegisteredAction<'_>> {
        self.plugins.iter().flat_map(|plugin| {
            plugin
                .actions
                .iter()
                .map(move |action| RegisteredAction { plugin, action })
        })
    }

    /// Find an action by its exact command path.
    #[must_use]
    pub fn find(&self, command: &[&str]) -> Option<RegisteredAction<'_>> {
        self.actions().find(|registered| {
            registered.action.command.len() == command.len()
                && registered
                    .action
                    .command
                    .iter()
                    .zip(command)
                    .all(|(actual, expected)| actual == *expected)
        })
    }

    /// Iterate through plugins registered in this build.
    pub fn plugins(&self) -> impl Iterator<Item = &PluginDefinition> {
        self.plugins.iter()
    }
}

/// Error reported when a plugin declares ambiguous or incomplete action metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// A plugin identifier was empty or repeated.
    DuplicatePlugin(String),
    /// Two actions use the same command path.
    DuplicateCommand(String),
    /// An action or plugin is missing required metadata.
    InvalidAction(String),
    /// A JSON Schema declaration is internally inconsistent.
    InvalidSchema(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicatePlugin(plugin) => {
                write!(formatter, "duplicate or empty plugin {plugin}")
            }
            Self::DuplicateCommand(command) => write!(formatter, "duplicate command {command}"),
            Self::InvalidAction(message) | Self::InvalidSchema(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for RegistryError {}

#[cfg(test)]
mod tests {
    //! Checks validation and lookup behavior for plugin action contracts.

    use super::{ActionDefinition, ActionRegistry, JsonSchema, PluginDefinition, RegistryError};

    fn sample_action(command: &[&str]) -> ActionDefinition {
        ActionDefinition::new(
            command.iter().copied(),
            "Report current state.",
            "Use this command to inspect state.",
            ["Read the current state."],
            JsonSchema::empty_object(),
            JsonSchema::empty_object(),
        )
    }

    #[test]
    fn registry_keeps_plugin_ownership_and_exact_command_paths() {
        let registry = ActionRegistry::new(vec![PluginDefinition::new(
            "state",
            "State commands.",
            [
                sample_action(&["status"]),
                sample_action(&["server", "features"]),
            ],
        )])
        .expect("valid registry");

        let action = registry
            .find(&["server", "features"])
            .expect("registered command");
        assert_eq!(action.plugin.id, "state");
        assert_eq!(action.action.description, "Report current state.");
        assert!(registry.find(&["server"]).is_none());
    }

    #[test]
    fn registry_rejects_missing_action_guidance_and_command_collisions() {
        let mut missing_instructions = sample_action(&["status"]);
        missing_instructions.instructions.clear();
        let missing = ActionRegistry::new(vec![PluginDefinition::new(
            "state",
            "State commands.",
            [missing_instructions],
        )]);
        assert!(matches!(missing, Err(RegistryError::InvalidAction(_))));

        let duplicate = ActionRegistry::new(vec![PluginDefinition::new(
            "state",
            "State commands.",
            [sample_action(&["status"]), sample_action(&["status"])],
        )]);
        assert_eq!(
            duplicate.expect_err("duplicate path is rejected"),
            RegistryError::DuplicateCommand("status".to_owned())
        );
    }

    #[test]
    fn registry_rejects_inconsistent_json_schemas() {
        let invalid_schema = JsonSchema::object(
            [("name".to_owned(), JsonSchema::string("Node name."))],
            ["missing".to_owned()],
        );
        let action = ActionDefinition::new(
            ["status"],
            "Report current state.",
            "Use this command to inspect state.",
            ["Read the current state."],
            invalid_schema,
            JsonSchema::empty_object(),
        );
        let registry = ActionRegistry::new(vec![PluginDefinition::new(
            "state",
            "State commands.",
            [action],
        )]);
        assert!(matches!(registry, Err(RegistryError::InvalidSchema(_))));
    }

    #[test]
    fn command_result_schema_has_required_stable_fields_and_optional_next_step() {
        let schema = JsonSchema::command_result();
        assert_eq!(schema.schema_type, super::JsonSchemaType::Object);
        assert_eq!(
            schema.required,
            ["schema_version", "command", "state", "message"]
        );
        assert!(schema.properties.contains_key("next_step"));
        assert_eq!(schema.additional_properties, Some(false));
    }
}
