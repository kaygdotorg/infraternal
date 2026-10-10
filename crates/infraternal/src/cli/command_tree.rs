//! Derives the public Clap command tree and argument parsers from registered actions.

use std::fmt::Write as _;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use infraternal_plugin_api::{
    ActionDefinition, ActionRegistry, JsonSchema, JsonSchemaType, PluginDefinition,
};

/// A leaf command selected from the generated command tree.
pub struct SelectedCommand<'a> {
    /// Command path without the executable name.
    pub path: Vec<String>,
    /// Matches containing the selected action's input values.
    pub matches: &'a ArgMatches,
}

/// Build help and argument parsing from the actions enabled in this binary.
#[must_use]
pub fn build(registry: &ActionRegistry) -> Command {
    let mut root = Command::new("infraternal")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Manage infraternal servers and node components.")
        .disable_help_subcommand(true)
        .arg(
            Arg::new("json")
                .long("json")
                .help("Print the stable versioned JSON result envelope.")
                .action(ArgAction::SetTrue)
                .global(true),
        );
    let tree = command_tree(registry);
    for child in &tree.children {
        root = root.subcommand(build_node(child));
    }
    root
}

/// Find the deepest selected subcommand and return its path and input matches.
#[must_use]
pub fn selected(matches: &ArgMatches) -> SelectedCommand<'_> {
    let mut path = Vec::new();
    let mut selected = matches;
    while let Some((name, submatches)) = selected.subcommand() {
        path.push(name.to_owned());
        selected = submatches;
    }
    SelectedCommand {
        path,
        matches: selected,
    }
}

struct CommandNode<'a> {
    name: String,
    plugin_description: Option<String>,
    action: Option<&'a ActionDefinition>,
    children: Vec<CommandNode<'a>>,
}

impl CommandNode<'_> {
    fn child_mut(&mut self, name: &str) -> &mut Self {
        let index = self
            .children
            .iter()
            .position(|child| child.name == name)
            .unwrap_or_else(|| {
                self.children.push(Self {
                    name: name.to_owned(),
                    plugin_description: None,
                    action: None,
                    children: Vec::new(),
                });
                self.children.len() - 1
            });
        &mut self.children[index]
    }

    fn has_visible_action(&self) -> bool {
        self.action.is_some_and(|action| action.visible)
            || self.children.iter().any(Self::has_visible_action)
    }
}

fn command_tree(registry: &ActionRegistry) -> CommandNode<'_> {
    let mut root = CommandNode {
        name: "infraternal".to_owned(),
        plugin_description: None,
        action: None,
        children: Vec::new(),
    };
    for plugin in registry.plugins() {
        for action in &plugin.actions {
            insert_action(&mut root, plugin, action);
        }
    }
    root
}

fn insert_action<'a>(
    root: &mut CommandNode<'a>,
    plugin: &'a PluginDefinition,
    action: &'a ActionDefinition,
) {
    let Some((first, remainder)) = action.command.split_first() else {
        return;
    };
    let mut node = root.child_mut(first);
    if node.plugin_description.is_none() {
        node.plugin_description = Some(plugin.description.clone());
    }
    for part in remainder {
        node = node.child_mut(part);
    }
    node.action = Some(action);
}

fn build_node(node: &CommandNode<'_>) -> Command {
    let mut command = Command::new(node.name.clone());
    if let Some(action) = node.action {
        if action.visible {
            command = command
                .about(action.description.clone())
                .long_about(long_about(action));
        } else if let Some(description) = &node.plugin_description {
            command = command.about(description.clone());
        }
        for (name, schema) in &action.input_schema.properties {
            if action.command == ["skill"] && name == "command" {
                continue;
            }
            command = command.arg(input_argument(
                name,
                schema,
                action
                    .input_schema
                    .required
                    .iter()
                    .any(|field| field == name),
                action.visible,
            ));
        }
        if action.command == ["skill"] {
            command = command.arg(
                Arg::new("command")
                    .value_name("COMMAND")
                    .help("Command path to print, such as `status` or `mesh up`.")
                    .index(1)
                    .num_args(1..)
                    .action(ArgAction::Append),
            );
        }
    } else if let Some(description) = &node.plugin_description {
        command = command.about(description.clone());
    }
    if !node.has_visible_action() {
        command = command.hide(true);
    }
    for child in &node.children {
        command = command.subcommand(build_node(child));
    }
    command
}

fn long_about(action: &ActionDefinition) -> String {
    let mut about = format!(
        "{}\n\nWhen to use:\n{}\n\nSteps:",
        action.description, action.when_to_use
    );
    for (index, instruction) in action.instructions.iter().enumerate() {
        let _ = write!(about, "\n{}. {instruction}", index + 1);
    }
    if !action.examples.is_empty() {
        about.push_str("\n\nExamples:");
        for example in &action.examples {
            let _ = write!(about, "\n  {}  {}", example.invocation, example.description);
        }
    }
    if action.safety.destructive || action.safety.dry_run_first || !action.safety.notes.is_empty() {
        about.push_str("\n\nSafety:");
        if action.safety.destructive {
            about.push_str("\n  This command can change or remove existing state.");
        }
        if action.safety.dry_run_first {
            about.push_str("\n  Review a dry run before applying the change.");
        }
        for note in &action.safety.notes {
            let _ = write!(about, "\n  {note}");
        }
    }
    about
}

fn input_argument(name: &str, schema: &JsonSchema, required: bool, visible: bool) -> Arg {
    let long_name = name.replace('_', "-");
    let mut argument = Arg::new(name.to_owned())
        .long(long_name)
        .help(
            schema
                .description
                .clone()
                .unwrap_or_else(|| "Command input.".to_owned()),
        )
        .required(required)
        .hide(!visible);
    argument = match schema.schema_type {
        JsonSchemaType::Boolean => argument.action(ArgAction::SetTrue),
        JsonSchemaType::Integer => argument
            .value_name("INTEGER")
            .value_parser(value_parser!(i64))
            .action(ArgAction::Set),
        JsonSchemaType::Number => argument
            .value_name("NUMBER")
            .value_parser(value_parser!(f64))
            .action(ArgAction::Set),
        JsonSchemaType::Array => argument
            .value_name("VALUE")
            .action(ArgAction::Append)
            .num_args(1),
        JsonSchemaType::String | JsonSchemaType::Object => argument
            .value_name(name.to_ascii_uppercase())
            .action(ArgAction::Set),
    };
    argument
}

#[cfg(test)]
mod tests {
    //! Checks that help and parsing use the enabled registry's descriptions and inputs.

    use super::{build, selected};
    use crate::cli::actions::registry;

    #[test]
    fn root_help_uses_registered_descriptions_and_long_action_guidance() {
        let registry = registry().expect("action registry");
        let mut help_command = build(&registry);
        let help = help_command.render_long_help().to_string();
        assert!(help.contains("Show this node's role and running components."));
        assert!(help.contains("Start the configured node components."));
        assert!(!help.contains("server install"));
        let up_help = build(&registry)
            .try_get_matches_from(["infraternal", "up", "--help"])
            .expect_err("help is an early exit");
        assert!(
            up_help
                .to_string()
                .contains("Start the node components when lifecycle management is available.")
        );
    }

    #[test]
    fn hidden_session_shim_parser_uses_the_registered_input_schema() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "__shim",
                "--session",
                "0123456789abcdef0123456789abcdef",
                "--uid",
                "1000",
                "--cols",
                "80",
            ])
            .expect("registered hidden session shim command");
        let command = selected(&matches);
        assert_eq!(command.path, ["__shim"]);
        assert_eq!(command.matches.get_one::<i64>("uid"), Some(&1000));
        assert_eq!(command.matches.get_one::<i64>("cols"), Some(&80));
        assert!(
            !build(&registry)
                .render_long_help()
                .to_string()
                .contains("__shim")
        );
    }

    #[test]
    #[cfg(feature = "plugin-mesh")]
    fn parser_uses_plugin_inputs_and_accepts_json_after_a_leaf_command() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from(["infraternal", "mesh", "up", "--ssh", "--json"])
            .expect("registered mesh command and options");
        let command = selected(&matches);
        assert_eq!(command.path, ["mesh", "up"]);
        assert!(matches.get_flag("json"));
        assert!(command.matches.get_flag("ssh"));
    }

    #[test]
    fn skill_parser_accepts_a_multi_part_command_and_write_directory() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from(["infraternal", "skill", "server", "init", "--json"])
            .expect("skill command path and global JSON option");
        let command = selected(&matches);
        assert_eq!(command.path, ["skill"]);
        assert_eq!(
            command
                .matches
                .get_many::<String>("command")
                .map(|values| { values.map(String::as_str).collect::<Vec<_>>() }),
            Some(vec!["server", "init"])
        );
        assert!(matches.get_flag("json"));

        let matches = build(&registry)
            .try_get_matches_from(["infraternal", "skill", "--write", "./skills"])
            .expect("skill output directory option");
        assert_eq!(
            selected(&matches)
                .matches
                .get_one::<String>("write")
                .map(String::as_str),
            Some("./skills")
        );
    }

    #[test]
    #[cfg(feature = "plugin-server")]
    fn server_init_parses_confirmation_plan_and_server_configuration() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "server",
                "init",
                "--listen",
                "127.0.0.1:7443",
                "--dry-run",
                "--json",
            ])
            .expect("server init command and options");
        let command = selected(&matches);
        assert_eq!(command.path, ["server", "init"]);
        assert!(command.matches.get_flag("dry_run"));
        assert_eq!(
            command
                .matches
                .get_one::<String>("listen")
                .map(String::as_str),
            Some("127.0.0.1:7443")
        );
    }

    #[cfg(not(feature = "plugin-mesh"))]
    #[test]
    fn compiled_out_plugin_has_no_help_or_parse_path() {
        let registry = registry().expect("action registry");
        let help = build(&registry).render_long_help().to_string();
        assert!(!help.contains("mesh"));
        assert!(
            build(&registry)
                .try_get_matches_from(["infraternal", "mesh", "up"])
                .is_err()
        );
    }
}
