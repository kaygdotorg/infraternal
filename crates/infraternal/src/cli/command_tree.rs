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
        .version(format!(
            "{} ({})",
            infraternal_plugin_api::VERSION,
            infraternal_plugin_api::release_version::channel(infraternal_plugin_api::VERSION)
                .unwrap_or("unknown")
        ))
        .bin_name("infraternal")
        .about("Run and manage infraternal on this machine.")
        .disable_help_subcommand(true)
        .arg(
            Arg::new("json")
                .long("json")
                .help("Print the stable JSON result envelope.")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("server_override")
                .long("server")
                .help("Use the signed-in server for this action.")
                .action(ArgAction::Set)
                .global(true),
        );
    let tree = command_tree(registry);
    for child in &tree.children {
        root = root.subcommand(build_node(child, &[]));
    }
    if let Some(action) = registry
        .plugins()
        .flat_map(|plugin| &plugin.actions)
        .find(|action| action.visible && action.command == ["server", "init"])
    {
        root = root.after_help(format!(
            "Server setup:\n  {}  {}",
            action.command.join(" "),
            action.description,
        ));
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
    group_description: Option<String>,
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
                    group_description: None,
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
        group_description: None,
        action: None,
        children: Vec::new(),
    };
    for plugin in registry.plugins() {
        for action in &plugin.actions {
            insert_action(&mut root, plugin, action);
        }
        for (path, description) in &plugin.groups {
            let mut node = &mut root;
            for part in path.split(' ') {
                node = node.child_mut(part);
            }
            node.group_description = Some(description.clone());
        }
    }
    root
}

fn insert_action<'a>(
    root: &mut CommandNode<'a>,
    plugin: &'a PluginDefinition,
    action: &'a ActionDefinition,
) {
    // A placeholder for a component that is not built yet is neither shown nor parsed:
    // typing it is an unknown command, like any typo (D299 C5).
    if action.availability == infraternal_plugin_api::ActionAvailability::NotAvailableYet {
        return;
    }
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

/// `inherited` are the options of the ancestors that every subcommand also accepts, wherever they
/// are typed. A subcommand that does not declare one still accepts it, but hides it from its help:
/// listing options it ignores would invite people to pass them.
fn build_node(node: &CommandNode<'_>, inherited: &[Arg]) -> Command {
    let mut command = Command::new(node.name.clone());
    let mut shared: Vec<Arg> = Vec::new();
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
            // `remove-host` uses the root server override for the same HTTPS origin. Keeping a
            // second generated `--server` here would collide with the shared global option.
            if action.command == ["remove-host"] && name == "server" {
                continue;
            }
            let mut argument = input_argument(
                name,
                schema,
                action
                    .input_schema
                    .required
                    .iter()
                    .any(|field| field == name),
                action.visible && !action.cli_hidden_inputs.contains(name),
            );
            if action.command == ["remove-host"] && name == "host" {
                argument = argument.requires("server_override");
            }
            if let Some(required) = action.cli_requires.get(name) {
                argument = argument.requires(required.clone());
            }
            if let Some(index) = action
                .cli_positionals
                .iter()
                .position(|field| field == name)
            {
                argument = argument.long(None::<&str>).index(index + 1);
            } else if !node.children.is_empty() && !action.input_schema.required.contains(name) {
                // Inherited server/node coordinates work before or after an operator subcommand.
                let mut heading = node.name.clone();
                if let Some(first) = heading.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                argument = argument
                    .global(true)
                    .help_heading(format!("{heading} options"));
                shared.push(hidden_inherited_arg(&argument));
            }
            if action.command == ["sessions", "new"] && name == "command" {
                argument = argument.num_args(1..).last(true);
            }
            command = command.arg(argument);
        }
        if action.command == ["skill"] {
            command = command.arg(
                Arg::new("command")
                    .value_name("COMMAND")
                    .help("The command to print, such as `status` or `mesh peers`.")
                    .index(1)
                    .num_args(1..)
                    .action(ArgAction::Append),
            );
        }
    } else if let Some(description) = node
        .group_description
        .as_ref()
        .or(node.plugin_description.as_ref())
    {
        command = command.about(description.clone());
    }
    if !node.has_visible_action() {
        command = command.hide(true);
    }
    for arg in inherited {
        if !command
            .get_arguments()
            .any(|own| own.get_id() == arg.get_id())
        {
            command = command.arg(hidden_inherited_arg(arg));
        }
    }
    let mut passed: Vec<Arg> = inherited
        .iter()
        .filter(|arg| !shared.iter().any(|own| own.get_id() == arg.get_id()))
        .map(hidden_inherited_arg)
        .collect();
    passed.extend(shared);
    for child in &node.children {
        command = command.subcommand(build_node(child, &passed));
    }
    command
}

/// Descendants only need to consume an inherited switch and its value; repeating the full argument
/// metadata at each tree level needlessly retains its clone and validation machinery in the binary.
fn hidden_inherited_arg(argument: &Arg) -> Arg {
    let mut hidden = Arg::new(argument.get_id().clone())
        .action(argument.get_action().clone())
        .hide(true);
    if let Some(long) = argument.get_long() {
        hidden = hidden.long(long.to_owned());
    }
    if let Some(short) = argument.get_short() {
        hidden = hidden.short(short);
    }
    hidden
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
    fn sign_in_accepts_a_server_as_its_positional_argument() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from(["infraternal", "sign-in", "https://mesh.example.org"])
            .expect("sign-in server positional");
        let selected = selected(&matches);
        assert_eq!(selected.path, ["sign-in"]);
        assert_eq!(
            selected
                .matches
                .get_one::<String>("server")
                .map(String::as_str),
            Some("https://mesh.example.org")
        );
    }

    #[cfg(all(feature = "remote", target_os = "linux"))]
    #[test]
    fn up_accepts_a_server_as_its_positional_argument() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from(["infraternal", "up", "https://mesh.example.org"])
            .expect("up server positional");
        let selected = selected(&matches);
        assert_eq!(selected.path, ["up"]);
        assert_eq!(
            selected
                .matches
                .get_one::<String>("server")
                .map(String::as_str),
            Some("https://mesh.example.org")
        );
    }

    #[test]
    fn sign_in_accepts_repeated_additional_scopes() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "sign-in",
                "https://mesh.example.org",
                "--scope",
                "hosts:write",
                "--scope",
                "terminal:connect",
            ])
            .expect("repeated scope options");
        let selected = selected(&matches);
        assert_eq!(
            selected
                .matches
                .get_many::<String>("scope")
                .expect("scope values")
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["hosts:write", "terminal:connect"]
        );
    }

    /// Hosted command syntax preserves the shared action identity and server selection.
    #[test]
    #[cfg(feature = "remote")]
    fn server_action_commands_use_the_shared_action_definitions() {
        let registry = registry().expect("action registry");
        for (path, action_id, example_argument) in [
            (&["hosts", "list"][..], "remote.host.list", None),
            (
                &["hosts", "add"][..],
                "ssh.start",
                Some("operator@host.example"),
            ),
            (
                &["hosts", "remove"][..],
                "remote.host.remove",
                Some("00000000-0000-0000-0000-000000000001"),
            ),
            (
                &["hosts", "forget"][..],
                "remote.host.forget",
                Some("00000000-0000-0000-0000-000000000001"),
            ),
            (&["sessions", "list"][..], "sessions.list", None),
        ] {
            let mut args = vec!["infraternal", "--server", "https://mesh.example.org"];
            args.extend_from_slice(path);
            args.push("--json");
            if let Some(argument) = example_argument {
                args.push(argument);
            }
            let matches = build(&registry)
                .try_get_matches_from(args)
                .unwrap_or_else(|error| panic!("parse {}: {error}", path.join(" ")));
            let selected = selected(&matches);
            assert_eq!(selected.path, path);
            assert_eq!(
                selected
                    .matches
                    .get_one::<String>("server_override")
                    .map(String::as_str),
                Some("https://mesh.example.org")
            );
            let hosted = registry
                .find(path)
                .and_then(|registered| registered.action.hosted.as_ref())
                .unwrap_or_else(|| {
                    panic!("{} must carry its shared hosted definition", path.join(" "))
                });
            assert_eq!(hosted.id, action_id);
            // D333: inside its scope a key needs no further tap, removal included.
            assert!(!hosted.fresh_passkey, "{action_id}");
        }

        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "--server",
                "https://mesh.example.org",
                "status",
                "--json",
            ])
            .expect("server status command");
        let hosted = registry
            .find(&["status"])
            .and_then(|registered| registered.action.hosted.as_ref())
            .expect("status uses the shared core action");
        assert_eq!(selected(&matches).path, ["status"]);
        assert_eq!(hosted.id, "server.status");
        assert!(!hosted.fresh_passkey);
    }

    /// Forget shares the hosted dry-run and explicit-confirmation flags (D369).
    #[test]
    #[cfg(feature = "remote")]
    fn hosts_forget_takes_dry_run_and_yes_flags() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "hosts",
                "forget",
                "00000000-0000-0000-0000-000000000001",
                "--dry-run",
                "--yes",
            ])
            .expect("hosts forget");
        let command = selected(&matches);
        assert_eq!(command.path, ["hosts", "forget"]);
        assert!(command.matches.get_flag("dry_run"));
        assert!(command.matches.get_flag("yes"));
    }

    /// D333 keeps the dry run of a key-driven removal: `--dry-run` reaches the shared input.
    #[test]
    #[cfg(feature = "remote")]
    fn hosts_remove_takes_a_dry_run_flag() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "hosts",
                "remove",
                "00000000-0000-0000-0000-000000000001",
                "--dry-run",
            ])
            .expect("hosts remove --dry-run");
        let command = selected(&matches);
        assert_eq!(command.path, ["hosts", "remove"]);
        assert!(command.matches.get_flag("dry_run"));
    }

    /// D28: removal always shows its dry run first; `--yes` skips only the question, for
    /// scripts that reviewed it already.
    #[test]
    #[cfg(feature = "remote")]
    fn hosts_remove_takes_a_yes_flag() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "hosts",
                "remove",
                "00000000-0000-0000-0000-000000000001",
                "--yes",
            ])
            .expect("hosts remove --yes");
        let command = selected(&matches);
        assert!(command.matches.get_flag("yes"));
        assert!(!command.matches.get_flag("dry_run"));
    }

    #[test]
    fn every_command_in_the_tree_takes_json() {
        // D299: no command is exempt, hidden internal ones included.
        fn walk(command: &clap::Command, path: &str, missing: &mut Vec<String>) {
            if !command
                .get_arguments()
                .any(|argument| argument.get_id() == "json")
            {
                missing.push(path.to_owned());
            }
            for child in command.get_subcommands() {
                walk(child, &format!("{path} {}", child.get_name()), missing);
            }
        }
        let registry = registry().expect("action registry");
        let mut root = build(&registry);
        root.build();
        let mut missing = Vec::new();
        walk(&root, "infraternal", &mut missing);
        assert!(missing.is_empty(), "commands without --json: {missing:?}");
    }

    #[test]
    fn public_help_is_plain_words() {
        // D299: no "plugin actions", no empty group, no internal vocabulary, one style.
        const INTERNAL: [&str; 8] = [
            "plugin",
            "capability",
            "descriptor",
            "uid",
            "runtime directory",
            "stdin",
            "described by",
            "action json",
        ];
        fn words(text: &str, what: &str, problems: &mut Vec<String>) {
            let lower = text.to_ascii_lowercase();
            for word in INTERNAL {
                if lower.contains(word) {
                    problems.push(format!("{what}: internal word `{word}` in {text:?}"));
                }
            }
            if !text.chars().next().is_some_and(char::is_uppercase) || !text.ends_with('.') {
                problems.push(format!("{what}: not a capitalised sentence: {text:?}"));
            }
        }
        fn walk(command: &clap::Command, path: &str, problems: &mut Vec<String>) {
            if command.is_hide_set() {
                return;
            }
            let about = command
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            if about.is_empty() {
                problems.push(format!("{path}: no description"));
            } else {
                words(&about, path, problems);
            }
            for argument in command.get_arguments() {
                if argument.is_hide_set()
                    || argument.get_id() == "help"
                    || argument.get_id() == "version"
                {
                    continue;
                }
                let help = argument
                    .get_help()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                words(&help, &format!("{path} --{}", argument.get_id()), problems);
            }
            for child in command.get_subcommands() {
                walk(child, &format!("{path} {}", child.get_name()), problems);
            }
        }
        let registry = registry().expect("action registry");
        let mut root = build(&registry);
        root.build();
        let mut problems = Vec::new();
        walk(&root, "infraternal", &mut problems);
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    #[test]
    fn root_help_uses_registered_descriptions_and_long_action_guidance() {
        let registry = registry().expect("action registry");
        let mut help_command = build(&registry);
        let help = help_command.render_long_help().to_string();
        assert!(help.contains("Show what infraternal runs on this machine."));
        assert!(!help.contains("server install"));
        let status_help = build(&registry)
            .try_get_matches_from(["infraternal", "status", "--help"])
            .expect_err("help is an early exit");
        assert!(status_help.to_string().contains("Steps:"));
    }

    #[test]
    fn root_help_lines_fit_80_columns() {
        // The parser does not wrap help in this build, so the descriptions must be short enough.
        let registry = registry().expect("action registry");
        let help = build(&registry).render_help().to_string();
        for line in help.lines() {
            assert!(
                line.chars().count() <= 80,
                "{} columns: {line}",
                line.chars().count()
            );
        }
    }

    #[test]
    fn unbuilt_placeholders_are_neither_shown_nor_parsed() {
        // D299 C5: `up`, `relay`, `mesh list` and friends only say "not available yet".
        let registry = registry().expect("action registry");
        let help = build(&registry).render_long_help().to_string();
        for placeholder in ["relay", "backup", "release", "host "] {
            assert!(
                !help.contains(&format!("\n  {placeholder}")),
                "{placeholder}: {help}"
            );
        }
        for command in [["up"], ["relay"], ["release"]] {
            assert!(
                build(&registry)
                    .try_get_matches_from(std::iter::once("infraternal").chain(command))
                    .is_err(),
                "{command:?}"
            );
        }
        // The builds that keep the declarations (feature `placeholders`) still hide them.
        #[cfg(feature = "placeholders")]
        assert!(
            registry
                .actions()
                .any(|a| !a.action.is_public() && a.action.visible)
        );
    }

    #[cfg(all(feature = "ssh", feature = "remote"))]
    #[test]
    fn hidden_ssh_session_action_parses_existing_session_rendezvous() {
        let registry = registry().expect("action registry");
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "__ssh-session",
                "--state",
                "private-state",
                "--session",
                id,
            ])
            .expect("registered SSH session bridge inputs");
        let selected = selected(&matches);
        assert_eq!(selected.path, ["__ssh-session"]);
        assert_eq!(
            selected
                .matches
                .get_one::<String>("session")
                .map(String::as_str),
            Some(id)
        );
        assert!(
            !build(&registry)
                .render_long_help()
                .to_string()
                .contains("__ssh-session")
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
    #[cfg(all(feature = "plugin-mesh", target_os = "linux"))]
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
    #[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
    fn parser_uses_macos_mesh_service_input_and_accepts_json_after_a_leaf_command() {
        let registry = registry().expect("action registry");
        let matches = build(&registry)
            .try_get_matches_from(["infraternal", "mesh", "up", "--system-service", "--json"])
            .expect("registered Mac system service input");
        let command = selected(&matches);
        assert_eq!(command.path, ["mesh", "up"]);
        assert!(matches.get_flag("json"));
        assert!(command.matches.get_flag("system_service"));
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

    /// Resolve the actual packaging recipe independently of this test binary's
    /// features: an accidental role dependency must not silently disable its test.
    #[test]
    fn packaged_node_dependency_closure_omits_server_storage_and_release() {
        let output = std::process::Command::new("cargo")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "tree",
                "--offline",
                "--locked",
                "--color",
                "never",
                "-p",
                "infraternal",
                "--no-default-features",
                "--features",
                "plugin-host-facts,remote,ssh",
                "--edges",
                "normal",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ])
            .output()
            .expect("resolve the packaged node dependency closure without building");
        assert!(
            output.status.success(),
            "node dependency resolution failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let dependencies = String::from_utf8(output.stdout).expect("UTF-8 dependency names");
        for forbidden in [
            "infraternal-server",
            "sqlx",
            "libsqlite3-sys",
            "infraternal-plugin-release",
        ] {
            let prefix = format!("{forbidden} ");
            assert!(
                !dependencies.lines().any(|line| line.starts_with(&prefix)),
                "packaged node retains forbidden dependency {forbidden}"
            );
        }
    }

    #[cfg(not(feature = "plugin-server"))]
    #[test]
    fn node_build_omits_and_refuses_server_commands() {
        let registry = registry().expect("node action registry");
        assert!(build(&registry).find_subcommand("server").is_none());
        for command in [&["server"][..], &["server", "init"], &["server", "restart"]] {
            assert!(registry.find(command).is_none());
            let arguments = std::iter::once("infraternal").chain(command.iter().copied());
            let error = build(&registry)
                .try_get_matches_from(arguments)
                .unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        }
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

#[cfg(all(test, feature = "remote"))]
mod backmerge_tests {
    //! Keeps deployed transport invocations on the metadata-driven command path.

    use super::{build, selected};
    use crate::cli::actions::registry;
    use infraternal_plugin_api::CliHandler;

    #[cfg(feature = "plugin-server")]
    #[test]
    fn restart_inherits_private_state_before_or_after_the_command() {
        let registry = registry().unwrap();
        for args in [
            vec![
                "infraternal",
                "server",
                "--data",
                "/private/server",
                "restart",
                "--binary",
                "/verified/replacement",
                "--json",
            ],
            vec![
                "infraternal",
                "server",
                "restart",
                "--data",
                "/private/server",
                "--binary",
                "/verified/replacement",
                "--json",
            ],
        ] {
            let matches = build(&registry).try_get_matches_from(args).unwrap();
            let command = selected(&matches);
            assert_eq!(command.path, ["server", "restart"]);
            assert_eq!(
                command.matches.get_one::<String>("data").unwrap(),
                "/private/server"
            );
            assert_eq!(
                registry
                    .find(&["server", "restart"])
                    .unwrap()
                    .action
                    .cli_handler,
                CliHandler::ServerRestart
            );
        }
    }

    #[test]
    fn removal_and_retention_inputs_keep_the_production_runtime_bindings() {
        let registry = registry().unwrap();
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "remove-host",
                "00000000-0000-0000-0000-000000000001",
                "--server",
                "https://localhost",
                "--finish",
                "--retain",
                "--json",
            ])
            .unwrap();
        assert_eq!(selected(&matches).path, ["remove-host"]);
        assert_eq!(
            selected(&matches)
                .matches
                .get_one::<String>("server_override")
                .map(String::as_str),
            Some("https://localhost")
        );
        assert_eq!(
            registry.find(&["remove-host"]).unwrap().action.cli_handler,
            CliHandler::RemoveHost
        );
        let missing_server = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "remove-host",
                "00000000-0000-0000-0000-000000000001",
            ])
            .expect_err("host removal still requires a server address");
        assert_eq!(
            missing_server.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let matches = build(&registry)
            .try_get_matches_from([
                "infraternal",
                "__shim",
                "--session",
                "00000000000000000000000000000001",
                "--uid",
                "1000",
                "--exit-retention-ms",
                "700",
                "--readiness",
            ])
            .unwrap();
        assert_eq!(
            selected(&matches)
                .matches
                .get_one::<i64>("exit_retention_ms"),
            Some(&700)
        );
        assert!(selected(&matches).matches.get_flag("readiness"));
    }
}
