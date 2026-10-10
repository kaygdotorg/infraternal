//! Renders AI agent skill instructions directly from compiled public action definitions [16,202].
use clap::{Arg, ArgMatches, Command};
use std::process::ExitCode;

pub(crate) fn command() -> Command {
    Command::new("skill")
        .about("Read AI agent instructions for compiled node actions")
        .arg(Arg::new("action").help("Action id or component id; omit to list compiled actions"))
}
pub(crate) fn run(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let selected = matches.get_one::<String>("action");
    let actions: Vec<_> = infraternal_agent::plugins::descriptors()
        .iter()
        .flat_map(|descriptor| descriptor.actions)
        .filter(|action| {
            selected.is_none_or(|selected| {
                action.id == selected
                    || action
                        .id
                        .strip_prefix(selected.as_str())
                        .is_some_and(|suffix| suffix.starts_with('.'))
            })
        })
        .collect();
    if actions.is_empty() {
        return crate::output::refuse(
            json_output,
            "skill",
            "No compiled action matches.",
            "Run infraternal skill to list the compiled actions.",
            2,
        );
    }
    if json_output {
        println!("{}", serde_json::json!({"actions":actions}));
    } else if selected.is_none() {
        println!("AI agent skills");
        for action in actions {
            println!("  {:<24}  {}", action.id, action.summary);
        }
        println!("\n  Next  Run infraternal skill <action> for its instructions.");
    } else {
        for action in actions {
            println!(
                "---\nname: {}\ndescription: {}\n---\n\n{}\n",
                action.id.replace('.', "-"),
                action.summary,
                action.help()
            );
        }
    }
    ExitCode::SUCCESS
}
