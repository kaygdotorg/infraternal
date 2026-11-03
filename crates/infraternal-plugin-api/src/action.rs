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
        Self::scalar(JsonSchemaType::String, description.into())
    }

    /// Create an integer schema with a description.
    #[must_use]
    pub fn integer(description: impl Into<String>) -> Self {
        Self::scalar(JsonSchemaType::Integer, description.into())
    }

    /// Create a number schema with a description.
    #[must_use]
    pub fn number(description: impl Into<String>) -> Self {
        Self::scalar(JsonSchemaType::Number, description.into())
    }

    /// Create a boolean schema with a description.
    #[must_use]
    pub fn boolean(description: impl Into<String>) -> Self {
        Self::scalar(JsonSchemaType::Boolean, description.into())
    }

    /// Create an object schema with strict additional-property handling.
    #[must_use]
    pub fn object(
        properties: impl IntoIterator<Item = (String, Self)>,
        required: impl IntoIterator<Item = String>,
    ) -> Self {
        Self::object_fields(
            properties.into_iter().collect(),
            required.into_iter().collect(),
        )
    }

    // Metadata stays off the terminal data path. Normalize iterator shapes
    // before ordered-map insertion so LTO shares the constructor across every
    // field-array length; required fields retain their original order [243].
    #[inline(never)]
    fn object_fields(properties: Vec<(String, Self)>, required: Vec<String>) -> Self {
        Self {
            schema_type: JsonSchemaType::Object,
            description: None,
            properties: properties.into_iter().collect(),
            required,
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
        Self::command_result_with(Self::empty_object())
    }

    /// Create the stable result envelope with an action-specific typed data object.
    #[must_use]
    pub fn command_result_with(data: Self) -> Self {
        Self::object(
            [
                (
                    "schema_version".to_owned(),
                    Self::integer("Version of the CLI JSON result contract."),
                ),
                ("command".to_owned(), Self::string("Executed command path.")),
                (
                    "ok".to_owned(),
                    Self::boolean("True when the command did what was asked; matches exit code 0."),
                ),
                (
                    "state".to_owned(),
                    Self::string("Plain machine-readable command state."),
                ),
                ("message".to_owned(), Self::string("Short result summary.")),
                (
                    "next".to_owned(),
                    Self::array(
                        Self::string("A command or action that fits this state."),
                        "Recommended follow-ups, at most three; empty when nothing is needed.",
                    ),
                ),
                (
                    "next_step".to_owned(),
                    Self::string("First entry of `next`, kept for readers of the first envelope."),
                ),
                (
                    "details".to_owned(),
                    Self::string("Technical detail associated with a failed command."),
                ),
                (
                    "error".to_owned(),
                    Self::object(
                        [
                            (
                                "code".to_owned(),
                                Self::string(
                                    "Stable error code such as usage, not_found or unreachable.",
                                ),
                            ),
                            (
                                "argument".to_owned(),
                                Self::string("Name of the argument at fault, never its value."),
                            ),
                            (
                                "detail".to_owned(),
                                Self::string("What went wrong, in plain words."),
                            ),
                        ],
                        ["code".to_owned()],
                    ),
                ),
                ("data".to_owned(), data),
            ],
            [
                "schema_version".to_owned(),
                "command".to_owned(),
                "ok".to_owned(),
                "state".to_owned(),
                "message".to_owned(),
                "next".to_owned(),
                "data".to_owned(),
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

    // Share scalar initialization across types and call sites [243].
    #[inline(never)]
    fn scalar(schema_type: JsonSchemaType, description: String) -> Self {
        Self {
            schema_type,
            description: Some(description),
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

/// Scope against which the authorization permission is evaluated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTarget {
    /// The action applies to the server or local node as a whole.
    Global,
    /// The action applies to one managed host.
    Host,
    /// The action applies to one active session.
    Session,
}

/// Kind of state change an action can perform.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionEffect {
    /// The action only reads state.
    Read,
    /// The action changes state without removing existing data or access.
    Write,
    /// The action can remove data, access, or running services.
    Destructive,
}

/// Dry-run support declared by an action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRun {
    /// The action cannot produce a meaningful preview.
    Unsupported,
    /// The action can produce a preview before it runs.
    Supported,
    /// The action requires a preview before it runs.
    Required,
}

/// A single permission or any of the declared management alternatives [187].
/// Single permissions retain the existing CLI metadata's JSON string shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ActionPermission {
    /// Require this permission.
    One(String),
    /// Accept any one of these permissions, without inventing a new role.
    Any { any: Vec<String> },
}

impl ActionPermission {
    fn valid(&self) -> bool {
        match self {
            Self::One(permission) => !permission.trim().is_empty(),
            Self::Any { any } => {
                !any.is_empty() && any.iter().all(|permission| !permission.trim().is_empty())
            }
        }
    }
}

/// Authorization and effect contract shared by every adapter for an action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionContract {
    /// Scope against which the permission is evaluated.
    pub target: ActionTarget,
    /// State effect of the action.
    pub effect: ActionEffect,
    /// Permission name granted by roles.
    pub permission: ActionPermission,
    /// Whether a dry run is available or required.
    pub dry_run: DryRun,
}

impl ActionContract {
    /// Declare the authorization scope, effect, permission, and dry-run policy.
    #[must_use]
    pub fn new(
        target: ActionTarget,
        effect: ActionEffect,
        permission: impl Into<String>,
        dry_run: DryRun,
    ) -> Self {
        Self {
            target,
            effect,
            permission: ActionPermission::One(permission.into()),
            dry_run,
        }
    }
}

/// Runtime binding for the CLI adapter; command paths remain data in the registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliHandler {
    /// Report the action's declared unavailable state.
    Unavailable,
    /// Dispatch a declared node action over its local same-uid socket.
    NodeComponent,
    /// Run saved-session automation with caller-session authority.
    Sessions,
    /// Inspect the local node and registered components.
    Status,
    /// List or render generated command skills.
    Skill,
    /// Sign this CLI device into a server through fresh passkey approval.
    SignIn,
    /// Adapt one shared hosted action to the API-key HTTP or bootstrap WebSocket transport.
    HostedAction,
    /// Run the configured server in the foreground.
    ServerRun,
    /// Create and start a server service.
    ServerInit,
    /// Explain the migration from the hidden legacy server install command.
    ServerInstallCompatibility,
    /// Read the one-time server setup capability.
    ServerSetupToken,
    /// Execute a declared plugin action against an existing private server.
    ServerPlugin,
    /// Run the agent process inherited by the server.
    EmbeddedAgent,
    /// Run the internal session shim process.
    SessionShim,
    /// Check the compiled provider’s locked, dump-excluded key heap.
    KeyMemoryCheck,
    /// Enroll or reconnect an existing remote node.
    RemoteAgent,
    /// Request a CA-preserving server replacement.
    ServerRestart,
    /// Remove a host using fresh administrator proof.
    RemoveHost,
    /// Answer a private SSH authentication prompt.
    SshAskpass,
    /// Start the SSH shell through the owned session shim.
    SshSession,
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
    /// Permission and effect metadata shared with non-CLI adapters.
    #[serde(flatten)]
    pub contract: ActionContract,
    /// Inputs that still parse but are left out of help because they are for scripts and tests.
    #[serde(skip)]
    pub cli_hidden_inputs: Vec<String>,
    /// Original hosted descriptor, retaining schema references and any-of permissions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosted: Option<crate::ActionDef>,
    /// Named input dependencies checked before a CLI handler runs.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub cli_requires: BTreeMap<String, String>,
    /// Ordered positional CLI inputs; other inputs remain named options.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cli_positionals: Vec<String>,
    /// CLI implementation selected by this registered action.
    #[serde(skip)]
    pub cli_handler: CliHandler,
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
        contract: ActionContract,
    ) -> Self {
        Self::from_fields(
            command.into_iter().map(Into::into).collect(),
            description.into(),
            when_to_use.into(),
            instructions.into_iter().map(Into::into).collect(),
            input_schema,
            output_schema,
            contract,
        )
    }

    // Keep one action envelope constructor after the generic string/iterator
    // conversion. Handler defaults and metadata are identical for every plugin;
    // duplicating their initialization at each declaration only costs code [243].
    #[inline(never)]
    fn from_fields(
        command: Vec<String>,
        description: String,
        when_to_use: String,
        instructions: Vec<String>,
        input_schema: JsonSchema,
        output_schema: JsonSchema,
        contract: ActionContract,
    ) -> Self {
        Self {
            command,
            description,
            when_to_use,
            instructions,
            input_schema,
            output_schema,
            examples: Vec::new(),
            safety: SafetyNotes::default(),
            availability: ActionAvailability::Available,
            visible: true,
            contract,
            hosted: None,
            cli_handler: CliHandler::Unavailable,
            cli_positionals: Vec::new(),
            cli_requires: BTreeMap::new(),
            cli_hidden_inputs: Vec::new(),
        }
    }

    /// Bind the registered action to its CLI implementation.
    #[must_use]
    pub const fn with_cli_handler(mut self, handler: CliHandler) -> Self {
        self.cli_handler = handler;
        self
    }

    /// Preserve an operator command's positional arguments in generated adapters.
    #[must_use]
    pub fn with_cli_positionals(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.cli_positionals = names.into_iter().map(Into::into).collect();
        self
    }

    /// Keep these inputs accepted for scripts while hiding them from help and generated skills.
    #[must_use]
    pub fn with_cli_hidden_inputs(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.cli_hidden_inputs = names.into_iter().map(Into::into).collect();
        self
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

    /// Whether people and AI agents should be told about this command: it works and is not internal.
    /// Placeholders for components that are not built yet are neither listed nor callable (D299 C5).
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.visible && self.availability == ActionAvailability::Available
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
        // Internal host routes use a reserved prefix and never appear in public help.
        let allows_internal_underscores =
            !self.visible && self.command.len() == 1 && self.command[0].starts_with("__");
        if self.command.is_empty()
            || self.command.iter().any(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'-'
                            || (allows_internal_underscores && byte == b'_')
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
        if !self.contract.permission.valid() {
            return Err(RegistryError::InvalidAction(format!(
                "action {} has no permission name",
                self.command.join(" ")
            )));
        }
        if self.contract.effect == ActionEffect::Destructive
            && self.contract.dry_run != DryRun::Required
        {
            return Err(RegistryError::InvalidAction(format!(
                "destructive action {} must require a dry run",
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
    /// Descriptions of command groups below the plugin's own, keyed by the space-joined path
    /// such as `server release`, so help never shows a group with no words.
    pub groups: Vec<(String, String)>,
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
            groups: Vec::new(),
        }
    }

    /// Describe a command group (the path of words before its commands) for help.
    #[must_use]
    pub fn with_group(mut self, path: impl Into<String>, description: impl Into<String>) -> Self {
        self.groups.push((path.into(), description.into()));
        self
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

    use super::{
        ActionContract, ActionDefinition, ActionEffect, ActionRegistry, ActionTarget, DryRun,
        JsonSchema, PluginDefinition, RegistryError,
    };

    fn sample_action(command: &[&str]) -> ActionDefinition {
        ActionDefinition::new(
            command.iter().copied(),
            "Report current state.",
            "Use this command to inspect state.",
            ["Read the current state."],
            JsonSchema::empty_object(),
            JsonSchema::empty_object(),
            ActionContract::new(
                ActionTarget::Global,
                ActionEffect::Read,
                "state.inspect",
                DryRun::Unsupported,
            ),
        )
    }

    #[test]
    fn any_of_permissions_are_machine_readable_and_empty_authority_is_rejected() {
        for alternatives in [Vec::new(), vec!["state.read".to_owned(), " ".to_owned()]] {
            let mut action = sample_action(&["status"]);
            action.contract.permission = super::ActionPermission::Any { any: alternatives };
            let registry = ActionRegistry::new(vec![PluginDefinition::new(
                "state",
                "State commands.",
                [action],
            )]);
            assert!(matches!(registry, Err(RegistryError::InvalidAction(_))));
        }
        let permission = super::ActionPermission::Any {
            any: vec!["state.read".to_owned(), "state.manage".to_owned()],
        };
        assert_eq!(
            serde_json::to_value(permission).expect("permission JSON"),
            serde_json::json!({"any": ["state.read", "state.manage"]})
        );
        assert_eq!(
            serde_json::to_value(super::ActionPermission::One("state.read".to_owned()))
                .expect("legacy permission JSON"),
            serde_json::json!("state.read")
        );
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
    fn only_hidden_internal_routes_may_use_the_reserved_prefix() {
        let internal = sample_action(&["__shim"]).hidden();
        let registry = ActionRegistry::new(vec![PluginDefinition::new(
            "cli",
            "Core commands.",
            [internal],
        )]);
        assert!(registry.is_ok());

        let public = sample_action(&["__shim"]);
        let registry = ActionRegistry::new(vec![PluginDefinition::new(
            "cli",
            "Core commands.",
            [public],
        )]);
        assert!(matches!(registry, Err(RegistryError::InvalidAction(_))));
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
            ActionContract::new(
                ActionTarget::Global,
                ActionEffect::Read,
                "state.inspect",
                DryRun::Unsupported,
            ),
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
            [
                "schema_version",
                "command",
                "ok",
                "state",
                "message",
                "next",
                "data"
            ]
        );
        assert!(schema.properties.contains_key("next_step"));
        assert!(schema.properties.contains_key("error"));
        assert!(schema.properties.contains_key("details"));
        assert_eq!(
            schema.properties["data"].schema_type,
            super::JsonSchemaType::Object
        );
        assert_eq!(schema.additional_properties, Some(false));
    }

    #[test]
    fn command_result_schema_keeps_action_data_typed_inside_stable_envelope() {
        let schema = JsonSchema::command_result_with(JsonSchema::object(
            [("role".to_owned(), JsonSchema::string("Current node role."))],
            ["role".to_owned()],
        ));
        assert_eq!(
            schema.properties["data"].schema_type,
            super::JsonSchemaType::Object
        );
        assert_eq!(schema.properties["data"].required, ["role"]);
        assert!(schema.properties["data"].properties.contains_key("role"));
    }
}
