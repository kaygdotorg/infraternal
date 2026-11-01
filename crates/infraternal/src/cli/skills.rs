//! Renders and writes command skills from the registered action contracts.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

use infraternal_plugin_api::{ActionDefinition, ActionRegistry, JsonSchema, JsonSchemaType};
use serde::Serialize;

/// A visible command and its concise description for `infraternal skill`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SkillCommand {
    /// Command path without the executable name.
    pub command: String,
    /// Concise description shared with CLI help.
    pub description: String,
}

/// Return every visible action in the registration order used by CLI help.
#[must_use]
pub fn commands(registry: &ActionRegistry) -> Vec<SkillCommand> {
    registry
        .actions()
        .filter(|registered| registered.action.is_public())
        .map(|registered| SkillCommand {
            command: registered.action.command.join(" "),
            description: registered.action.description.clone(),
        })
        .collect()
}

/// Render one complete Markdown skill from the action's canonical metadata.
///
/// # Errors
///
/// Returns an error if the action metadata cannot be serialized as JSON.
pub fn render_action(action: &ActionDefinition) -> Result<String, serde_json::Error> {
    let name = format!("infraternal-{}", file_stem(&action.command));
    let mut output = format!(
        "---\nname: {name}\ndescription: {}\n---\n\n# `infraternal {}`\n\n## When to use\n\n{}\n\n## Steps\n",
        serde_json::to_string(&action.description)?,
        action.command.join(" "),
        action.when_to_use
    );
    for (index, instruction) in action.instructions.iter().enumerate() {
        let _ = write!(output, "\n{}. {instruction}", index + 1);
    }

    output.push_str("\n\n## Inputs\n");
    render_inputs(&mut output, &action.input_schema, &action.cli_hidden_inputs);

    output.push_str("\n\n## Outputs and JSON shape\n\n```json\n");
    output.push_str(&serde_json::to_string_pretty(&action.output_schema)?);
    output.push_str("\n```\n");

    if let Some(hosted) = &action.hosted {
        output.push_str("\n## Hosted action contract\n\n```json\n");
        output.push_str(&serde_json::to_string_pretty(hosted)?);
        output.push_str("\n```\n");
    }

    output.push_str("\n## Examples\n");
    if action.examples.is_empty() {
        output.push_str("\nNo examples are registered.\n");
    } else {
        for example in &action.examples {
            let _ = write!(
                output,
                "\n- `infraternal {}` — {}",
                example.invocation, example.description
            );
        }
        output.push('\n');
    }

    output.push_str("\n## Safety\n");
    if !action.safety.destructive && !action.safety.dry_run_first && action.safety.notes.is_empty()
    {
        output.push_str("\nNo destructive operation is declared.\n");
    } else {
        if action.safety.destructive {
            output.push_str("\n- This command can remove data, access, or running services.");
        }
        if action.safety.dry_run_first {
            output.push_str("\n- Review a dry run before applying the change.");
        }
        for note in &action.safety.notes {
            let _ = write!(output, "\n- {note}");
        }
        output.push('\n');
    }
    Ok(output)
}

/// Write one Markdown file per visible action and return the file names.
///
/// Temporary files are created next to their destination so each replacement
/// is atomic on the destination filesystem. Duplicate sanitized names fail
/// before any output file is written.
///
/// # Errors
///
/// Returns an error when the directory cannot be created, an action schema
/// cannot be serialized, filenames collide, or a file cannot be replaced.
pub fn write_all(registry: &ActionRegistry, directory: &Path) -> io::Result<Vec<String>> {
    let skills = registry
        .actions()
        .filter(|registered| registered.action.is_public())
        .map(|registered| {
            let file_name = format!("infraternal-{}.md", file_stem(&registered.action.command));
            (file_name, registered.action)
        })
        .collect::<Vec<_>>();
    let mut unique_names = BTreeSet::new();
    if skills
        .iter()
        .any(|(file_name, _)| !unique_names.insert(file_name.clone()))
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "registered commands produce duplicate skill filenames",
        ));
    }

    fs::create_dir_all(directory)?;
    let mut written = Vec::with_capacity(skills.len());
    for (index, (file_name, action)) in skills.into_iter().enumerate() {
        let markdown = render_action(action).map_err(io::Error::other)?;
        let destination = directory.join(&file_name);
        write_atomic(&destination, markdown.as_bytes(), index)?;
        written.push(file_name);
    }
    Ok(written)
}

fn file_stem(command: &[String]) -> String {
    command
        .join("-")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn render_inputs(output: &mut String, schema: &JsonSchema, hidden: &[String]) {
    let mut visible = schema
        .properties
        .iter()
        .filter(|(name, _)| !hidden.iter().any(|hidden| hidden == *name))
        .peekable();
    if visible.peek().is_none() {
        output.push_str("\nNo inputs.\n");
        return;
    }
    for (name, property) in visible {
        let required = schema.required.iter().any(|field| field == name);
        let position = if name == "command" && property.schema_type == JsonSchemaType::Array {
            "positional"
        } else {
            "option"
        };
        let description = property.description.as_deref().unwrap_or("No description.");
        let value_type = schema_type(property);
        let _ = write!(
            output,
            "\n- `{name}` ({position}, {value_type}, {}): {description}",
            if required { "required" } else { "optional" }
        );
    }
    output.push('\n');
}

fn schema_type(schema: &JsonSchema) -> String {
    match schema.schema_type {
        JsonSchemaType::Array => schema.items.as_deref().map_or_else(
            || "array".to_owned(),
            |item| format!("array of {}", schema_type(item)),
        ),
        JsonSchemaType::String => "string".to_owned(),
        JsonSchemaType::Integer => "integer".to_owned(),
        JsonSchemaType::Number => "number".to_owned(),
        JsonSchemaType::Boolean => "boolean".to_owned(),
        JsonSchemaType::Object => "object".to_owned(),
    }
}

fn write_atomic(destination: &Path, bytes: &[u8], index: usize) -> io::Result<()> {
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("skill.md");
    let temporary =
        destination.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), index));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Confirms generated skills reflect visible action metadata and write safely.

    use std::{fs, path::PathBuf};

    #[cfg(feature = "plugin-server")]
    use super::render_action;
    use super::{commands, write_all};
    use crate::cli::actions::registry;

    #[test]
    #[cfg(feature = "plugin-server")]
    fn generated_skill_contains_front_matter_inputs_outputs_and_safety() {
        let registry = registry().expect("registered action metadata");
        let action = registry
            .find(&["server", "init"])
            .expect("server init action")
            .action;
        let skill = render_action(action).expect("render server init skill");
        assert!(skill.starts_with("---\nname: infraternal-server-init\n"));
        assert!(skill.contains("## When to use"));
        assert!(skill.contains("## Steps"));
        assert!(skill.contains("Review a dry run before applying the change."));
        assert!(skill.contains("--dry-run"));
        assert!(skill.contains("schema_version"));
    }

    #[test]
    fn writing_skills_creates_one_file_per_visible_action() {
        let registry = registry().expect("registered action metadata");
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(std::env::temp_dir, PathBuf::from)
            .join(format!("skill-generation-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&target);
        let files = write_all(&registry, &target).expect("write generated skills");
        let visible = commands(&registry);
        assert_eq!(files.len(), visible.len());
        assert!(files.contains(&"infraternal-status.md".to_owned()));
        #[cfg(feature = "plugin-agent")]
        assert!(!files.contains(&"infraternal-agent.md".to_owned()));
        #[cfg(feature = "plugin-agent")]
        {
            // Placeholders are not written (D299 C5); a working agent command is.
            assert!(!files.contains(&"infraternal-agent-up.md".to_owned()));
            assert!(!files.contains(&"infraternal-up.md".to_owned()));
        }
        #[cfg(feature = "remote")]
        assert!(files.contains(&"infraternal-agent-join.md".to_owned()));
        for file in files {
            assert!(fs::read_to_string(target.join(file)).is_ok());
        }
        fs::remove_dir_all(target).expect("remove generated skill files");
    }
}
