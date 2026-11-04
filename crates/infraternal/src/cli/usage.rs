//! Turns a command-line parse failure into the shared result: it names the argument at fault, never its value (#239, D299).
//!
//! Clap's own text is right for people at a terminal. A script or an AI tool that
//! passed `--json` needs the same facts in the envelope: which command, which argument,
//! what to do. Values are never echoed: a mistyped argument can hold a URL, a path or a
//! secret, and the error must be safe to log.

use clap::{
    Command,
    error::{ContextKind, ContextValue, ErrorKind},
};
use serde_json::{Value, json};

use super::output::{CommandResult, CommandState};

/// The deepest command path the typed words reach, e.g. `["server", "restart"]`.
/// Options and their values are skipped; a word that is not a subcommand is skipped too.
fn command_path(root: &Command, args: &[String]) -> Vec<String> {
    let mut path = Vec::new();
    let mut current = root;
    for word in args {
        if word.starts_with('-') {
            continue;
        }
        if let Some(next) = current.find_subcommand(word) {
            path.push(word.clone());
            current = next;
        }
    }
    path
}

/// An option or placeholder name such as `--server` or `<HOST>`, with any value placeholder removed.
/// Anything else (a typed value, a path, a URL) is dropped.
fn argument_name(raw: &str) -> Option<String> {
    let first = raw.split_whitespace().next()?;
    let first = first.split('=').next()?;
    let is_option = first.starts_with('-') && first.len() > 1;
    let is_placeholder = first.starts_with('<') && first.ends_with('>');
    (is_option || is_placeholder).then(|| first.to_owned())
}

/// Collects the strings clap attached to a parse error under `kind`, whatever shape it used
/// (one string, several, or styled text). Returns an empty list when the error has none.
fn context_strings(error: &clap::Error, kind: ContextKind) -> Vec<String> {
    match error.get(kind) {
        Some(ContextValue::String(value)) => vec![value.clone()],
        Some(ContextValue::Strings(values)) => values.clone(),
        Some(ContextValue::StyledStr(value)) => vec![value.to_string()],
        Some(ContextValue::StyledStrs(values)) => values.iter().map(ToString::to_string).collect(),
        _ => Vec::new(),
    }
}

/// The envelope for `--help` or `--version` under `--json`: the text a person would have read.
///
/// `args` are the typed words without the program name; they pick which command's help this is.
/// The result is `Ready`, with the text under `help` (or `version` for `--version`).
#[must_use]
pub fn help_result(root: &Command, args: &[String], error: &clap::Error) -> CommandResult<Value> {
    let path = command_path(root, args);
    let command = if path.is_empty() {
        "infraternal".to_owned()
    } else {
        path.join(" ")
    };
    let is_version = error.kind() == ErrorKind::DisplayVersion;
    let text = error.to_string();
    CommandResult::new(
        command,
        CommandState::Ready,
        if is_version {
            "The version of this build."
        } else {
            "Help for this command."
        },
        if is_version {
            json!({ "version": text.trim_end() })
        } else {
            json!({ "help": text.trim_end() })
        },
    )
}

/// Build the envelope for a parse failure of the typed `args` (without the program name).
///
/// The result is `Refused` and carries a plain sentence naming the command and the argument at
/// fault (never the value typed), the argument under the `usage` key, and a next step that
/// points at `<command> --help`.
#[must_use]
pub fn result(root: &Command, args: &[String], error: &clap::Error) -> CommandResult<Value> {
    let path = command_path(root, args);
    let shown = if path.is_empty() {
        "infraternal".to_owned()
    } else {
        format!("infraternal {}", path.join(" "))
    };
    let names: Vec<String> = context_strings(error, ContextKind::InvalidArg)
        .iter()
        .filter_map(|raw| argument_name(raw))
        .collect();
    let argument = names.first().cloned();
    let message = match error.kind() {
        ErrorKind::UnknownArgument => match &argument {
            Some(name) => format!("{shown} has no option {name}."),
            None => format!("{shown} was given an argument it does not accept."),
        },
        ErrorKind::InvalidSubcommand => format!("{shown} has no command in this position."),
        ErrorKind::MissingRequiredArgument => {
            format!("{shown} needs {}.", names.join(" and "))
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => match &argument {
            Some(name) => format!("The value given for {name} is not valid."),
            None => "A value given on the command line is not valid.".to_owned(),
        },
        ErrorKind::ArgumentConflict => match &argument {
            Some(name) => format!("{name} cannot be combined with the other options given."),
            None => "Some options given cannot be combined.".to_owned(),
        },
        _ => "The command line is not valid.".to_owned(),
    };
    CommandResult::new(
        if path.is_empty() {
            "infraternal".to_owned()
        } else {
            path.join(" ")
        },
        CommandState::Refused,
        message,
        json!({}),
    )
    .with_argument("usage", argument)
    .with_next_step(format!("{shown} --help"))
}

#[cfg(test)]
mod tests {
    //! Usage errors name the argument and never echo a value.

    use clap::{Arg, ArgAction, Command};

    use super::result;

    fn tree() -> Command {
        Command::new("infraternal").subcommand(
            Command::new("remove-host")
                .arg(Arg::new("server").long("server").required(true))
                .arg(Arg::new("host").required(true))
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
        )
    }

    fn fail(args: &[&str]) -> (Vec<String>, clap::Error) {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let error = tree()
            .try_get_matches_from(std::iter::once("infraternal".to_owned()).chain(args.clone()))
            .expect_err("invalid arguments");
        (args, error)
    }

    #[test]
    fn an_unknown_option_is_named_without_its_value() {
        let (args, error) = fail(&["remove-host", "--bogus=hunter2", "x", "--server", "y"]);
        let result = result(&tree(), &args, &error);
        let json = serde_json::to_string(&result).expect("serialize");
        assert!(json.contains("\"argument\":\"--bogus\""), "{json}");
        assert!(!json.contains("hunter2"), "{json}");
        assert_eq!(result.command, "remove-host");
        assert!(!result.ok);
    }

    #[test]
    fn missing_arguments_are_listed_by_name() {
        let (args, error) = fail(&["remove-host"]);
        let result = result(&tree(), &args, &error);
        assert!(result.message.contains("--server"), "{}", result.message);
        assert!(result.message.contains("<host>") || result.message.contains("<HOST>"));
    }

    #[test]
    fn a_wrong_command_names_only_a_plain_word() {
        let (args, error) = fail(&["https://user:pw@example.test/x"]);
        let json = serde_json::to_string(&result(&tree(), &args, &error)).expect("serialize");
        assert!(!json.contains("pw@"), "{json}");
    }
}
