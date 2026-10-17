//! Renders stable command results as readable terminal text or versioned JSON.

use std::fmt::Write as _;

use serde::Serialize;

/// Versioned envelope shared by every public command's JSON output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommandResult<T> {
    /// Version of the stable CLI result contract.
    pub schema_version: u32,
    /// Executed command path without the executable name.
    pub command: String,
    /// Plain machine-readable state.
    pub state: CommandState,
    /// Short sentence describing the result.
    pub message: String,
    /// Recommended follow-up action, when one is useful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
    /// Technical detail for a failure, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Action-specific typed output data.
    pub data: T,
}

impl<T> CommandResult<T> {
    /// Create a result using the current stable CLI envelope version.
    #[must_use]
    pub fn new(
        command: impl Into<String>,
        state: CommandState,
        message: impl Into<String>,
        data: T,
    ) -> Self {
        Self {
            schema_version: 1,
            command: command.into(),
            state,
            message: message.into(),
            next_step: None,
            details: None,
            data,
        }
    }

    /// Attach a recommended follow-up action.
    #[must_use]
    pub fn with_next_step(mut self, next_step: impl Into<String>) -> Self {
        self.next_step = Some(next_step.into());
        self
    }

    /// Attach technical detail while keeping the short sentence user-facing.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Stable state values used by pretty output and JSON consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandState {
    /// The requested operation completed or a healthy state was found.
    Ready,
    /// The requested service or component is currently active.
    Running,
    /// The requested service or component is stopped.
    Stopped,
    /// This build does not yet provide the command handler.
    Unavailable,
    /// The command failed.
    Failed,
    /// A truthful state cannot be established from available runtime data.
    Unknown,
}

impl CommandState {
    const fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Running => "Running",
            Self::Stopped => "Stopped",
            Self::Unavailable => "Unavailable",
            Self::Failed => "Failed",
            Self::Unknown => "Unknown",
        }
    }

    const fn color(self) -> &'static str {
        match self {
            Self::Ready | Self::Running => "\u{1b}[32m",
            Self::Stopped | Self::Unknown => "\u{1b}[36m",
            Self::Unavailable => "\u{1b}[33m",
            Self::Failed => "\u{1b}[31m",
        }
    }
}

/// Formatting controls supplied by the output destination and test snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenderOptions {
    /// Whether stdout is connected to a terminal.
    pub terminal: bool,
    /// Whether ANSI color is allowed.
    pub color: bool,
    /// Maximum rendered line width in terminal columns.
    pub width: usize,
}

impl RenderOptions {
    /// Detect terminal width and disable color outside a TTY or with `NO_COLOR`.
    #[must_use]
    pub fn detect(terminal: bool) -> Self {
        let width = std::env::var("COLUMNS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|width| (40..=240).contains(width))
            .unwrap_or(80);
        Self {
            terminal,
            color: terminal && std::env::var_os("NO_COLOR").is_none(),
            width,
        }
    }

    fn usable_width(self) -> usize {
        self.width.max(40)
    }
}

/// Serialize CLI output, including action-specific compatibility fields, with a trailing newline.
pub fn render_json<T: Serialize>(result: &T) -> Result<String, serde_json::Error> {
    let mut output = serde_json::to_string_pretty(result)?;
    output.push('\n');
    Ok(output)
}

/// Render a command result as organized, width-aware terminal text.
pub fn render_pretty<T: Serialize>(
    result: &CommandResult<T>,
    options: RenderOptions,
) -> Result<String, serde_json::Error> {
    let data = serde_json::to_value(&result.data)?;
    let width = options.usable_width();
    let mut output = String::new();
    let title = format!("Infraternal {}", result.command);
    let _ = writeln!(output, "{title}");
    output.push('\n');
    output.push_str("Overview\n");
    let state = result.state.label();
    let rendered_state = if options.terminal && options.color {
        format!("{}{}\u{1b}[0m", result.state.color(), state)
    } else {
        state.to_owned()
    };
    render_key_value(&mut output, "State", &rendered_state, 2, 9, width);
    render_key_value(&mut output, "Summary", &result.message, 2, 9, width);

    render_data(&mut output, &data, options);

    if let Some(details) = &result.details {
        output.push('\n');
        output.push_str("Technical details\n");
        render_wrapped(&mut output, details, 2, width);
    }
    if let Some(next_step) = &result.next_step {
        output.push('\n');
        output.push_str("Next step\n");
        render_wrapped(&mut output, next_step, 2, width);
    }
    Ok(output)
}

fn render_data(output: &mut String, data: &serde_json::Value, options: RenderOptions) {
    let Some(fields) = data.as_object() else {
        output.push('\n');
        output.push_str("Data\n");
        render_wrapped(output, &scalar_text(data), 2, options.usable_width());
        return;
    };

    let scalars = fields
        .iter()
        .filter(|(_, value)| {
            !value.is_object() && !value.is_array() && !is_empty_pretty_value(value)
        })
        .collect::<Vec<_>>();
    if !scalars.is_empty() {
        output.push('\n');
        output.push_str("Details\n");
        let label_width = scalars
            .iter()
            .map(|(key, _)| humanize(key).chars().count())
            .max()
            .unwrap_or(8)
            .min(22);
        for (key, value) in scalars {
            render_key_value(
                output,
                &humanize(key),
                &scalar_text(value),
                2,
                label_width,
                options.usable_width(),
            );
        }
    }

    for (key, value) in fields.iter().filter(|(_, value)| {
        (value.is_object() || value.is_array()) && !is_empty_pretty_value(value)
    }) {
        output.push('\n');
        output.push_str(&humanize(key));
        output.push('\n');
        if let Some(items) = value.as_array() {
            if let Some(rows) = object_rows(items) {
                render_table(output, &rows, 2, options.usable_width());
            } else {
                for item in items {
                    if !is_empty_pretty_value(item) {
                        render_wrapped(output, &scalar_text(item), 2, options.usable_width());
                    }
                }
            }
        } else if let Some(nested) = value.as_object() {
            let label_width = nested
                .iter()
                .filter(|(_, value)| !is_empty_pretty_value(value))
                .map(|(key, _)| key)
                .map(|key| humanize(key).chars().count())
                .max()
                .unwrap_or(8)
                .min(22);
            for (nested_key, nested_value) in nested
                .iter()
                .filter(|(_, value)| !is_empty_pretty_value(value))
            {
                render_key_value(
                    output,
                    &humanize(nested_key),
                    &scalar_text(nested_value),
                    2,
                    label_width,
                    options.usable_width(),
                );
            }
        }
    }
}

/// Empty containers and blank strings have no useful human representation.
/// Keep them in JSON, but omit their labels in the human renderer.
fn is_empty_pretty_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => value.trim().is_empty(),
        serde_json::Value::Array(items) => {
            items.is_empty() || items.iter().all(is_empty_pretty_value)
        }
        serde_json::Value::Object(fields) => {
            fields.is_empty() || fields.values().all(is_empty_pretty_value)
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

fn object_rows(items: &[serde_json::Value]) -> Option<Vec<Vec<String>>> {
    if items.is_empty() || items.iter().any(|item| !item.is_object()) {
        return None;
    }
    let visible_rows = items
        .iter()
        .filter_map(serde_json::Value::as_object)
        .filter(|fields| {
            !fields.is_empty() && fields.values().any(|value| !is_empty_pretty_value(value))
        })
        .collect::<Vec<_>>();
    if visible_rows.is_empty() {
        return None;
    }
    let mut columns = std::collections::BTreeSet::new();
    for fields in &visible_rows {
        columns.extend(
            fields
                .iter()
                .filter(|(_, value)| !is_empty_pretty_value(value))
                .map(|(key, _)| key.clone()),
        );
    }
    if columns.is_empty() {
        return None;
    }
    // Identity first: a table reads "name, state, then the facts about it".
    let mut columns = columns.into_iter().collect::<Vec<_>>();
    columns.sort_by_key(|key| match key.as_str() {
        "name" => 0,
        "state" => 1,
        _ => 2,
    });
    let mut rows = Vec::with_capacity(visible_rows.len() + 1);
    rows.push(columns.iter().map(|key| humanize(key)).collect());
    for fields in visible_rows {
        rows.push(
            columns
                .iter()
                .map(|key| fields.get(key).map_or_else(String::new, scalar_text))
                .collect(),
        );
    }
    Some(rows)
}

fn render_table(output: &mut String, rows: &[Vec<String>], indent: usize, width: usize) {
    let column_count = rows.first().map_or(0, Vec::len);
    if column_count == 0 {
        return;
    }
    let gap = 2;
    let available = width
        .saturating_sub(indent + gap * (column_count - 1))
        .max(column_count);
    let mut widths = (0..column_count)
        .map(|column| {
            rows.iter()
                .filter_map(|row| row.get(column))
                .map(|cell| cell.chars().count())
                .max()
                .unwrap_or(1)
                .max(1)
        })
        .collect::<Vec<_>>();
    // Only when the table is too wide, narrow the widest column first, so
    // short columns never wrap and the long text takes the slack.
    while widths.iter().sum::<usize>() > available {
        let Some(widest) = widths
            .iter()
            .enumerate()
            .max_by_key(|(_, width)| **width)
            .map(|(index, _)| index)
        else {
            break;
        };
        if widths[widest] <= 1 {
            break;
        }
        widths[widest] -= 1;
    }
    for row in rows {
        let wrapped = row
            .iter()
            .enumerate()
            .map(|(index, value)| wrap_words(value, widths[index]))
            .collect::<Vec<_>>();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        for line in 0..height {
            write_indent(output, indent);
            for (column, column_width) in widths.iter().enumerate() {
                let value = wrapped
                    .get(column)
                    .and_then(|lines| lines.get(line))
                    .map_or("", String::as_str);
                output.push_str(value);
                if column + 1 != column_count {
                    let padding = column_width.saturating_sub(value.chars().count()) + gap;
                    output.push_str(&" ".repeat(padding));
                }
            }
            output.push('\n');
        }
    }
}

fn render_key_value(
    output: &mut String,
    label: &str,
    value: &str,
    indent: usize,
    label_width: usize,
    width: usize,
) {
    let value_indent = indent + label_width + 2;
    let label_length = label.chars().count();
    if label_length > label_width || value_indent >= width {
        write_indent(output, indent);
        output.push_str(label);
        output.push('\n');
        render_wrapped(output, value, indent + 2, width);
        return;
    }
    write_indent(output, indent);
    output.push_str(label);
    output.push_str(&" ".repeat(label_width - label_length + 2));
    let wrapped = wrap_words(value, width.saturating_sub(value_indent).max(1));
    if let Some(first) = wrapped.first() {
        output.push_str(first);
    }
    output.push('\n');
    for line in wrapped.iter().skip(1) {
        write_indent(output, value_indent);
        output.push_str(line);
        output.push('\n');
    }
}

fn render_wrapped(output: &mut String, value: &str, indent: usize, width: usize) {
    let available = width.saturating_sub(indent).max(1);
    let wrapped = wrap_words(value, available);
    for line in wrapped {
        write_indent(output, indent);
        output.push_str(&line);
        output.push('\n');
    }
}

fn wrap_words(value: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in value.split_whitespace() {
        let word_length = word.chars().count();
        if !line.is_empty() && line.chars().count() + 1 + word_length > width {
            lines.push(std::mem::take(&mut line));
        }
        if word_length > width {
            let mut chars = word.chars();
            while chars.clone().count() > width {
                line.extend(chars.by_ref().take(width));
                lines.push(std::mem::take(&mut line));
            }
            line.extend(chars);
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn write_indent(output: &mut String, indent: usize) {
    output.push_str(&" ".repeat(indent));
}

fn humanize(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut uppercase_next = true;
    for character in value.chars() {
        if character == '_' || character == '-' {
            output.push(' ');
            uppercase_next = true;
        } else if uppercase_next {
            output.extend(character.to_uppercase());
            uppercase_next = false;
        } else {
            output.push(character);
        }
    }
    output
}

fn scalar_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "None".to_owned(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            serde_json::to_string(value).unwrap_or_else(|_| "(unreadable value)".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    //! Snapshots pretty output, terminal color, wrapping, and the stable JSON envelope.

    use infraternal_plugin_api::{JsonSchema, JsonSchemaType};
    use serde_json::json;

    use super::{CommandResult, CommandState, RenderOptions, render_json, render_pretty};

    fn status() -> CommandResult<serde_json::Value> {
        CommandResult::new(
            "status",
            CommandState::Ready,
            "The server is running and this node is connected.",
            json!({
                "role": "managed node",
                "components": [
                    {"name": "server", "state": "running"},
                    {"name": "mesh", "state": "stopped"}
                ]
            }),
        )
        .with_next_step("Run infraternal mesh up when this node needs mesh connectivity.")
    }

    #[test]
    fn non_terminal_pretty_snapshot_has_aligned_details_and_table() {
        let output = render_pretty(
            &status(),
            RenderOptions {
                terminal: false,
                color: false,
                width: 80,
            },
        )
        .expect("render status");
        assert_eq!(
            output,
            concat!(
                "Infraternal status\n\n",
                "Overview\n",
                "  State      Ready\n",
                "  Summary    The server is running and this node is connected.\n\n",
                "Details\n",
                "  Role  managed node\n\n",
                "Components\n",
                "  Name    State\n",
                "  server  running\n",
                "  mesh    stopped\n\n",
                "Next step\n",
                "  Run infraternal mesh up when this node needs mesh connectivity.\n"
            )
        );
    }

    #[test]
    fn terminal_snapshot_uses_color_but_still_wraps_to_the_requested_width() {
        let mut result = status();
        result.message =
            "This sentence is deliberately long enough to wrap across a narrow terminal."
                .to_owned();
        let output = render_pretty(
            &result,
            RenderOptions {
                terminal: true,
                color: true,
                width: 52,
            },
        )
        .expect("render status");
        assert_eq!(
            output,
            concat!(
                "Infraternal status\n\n",
                "Overview\n",
                "  State      \u{1b}[32mReady\u{1b}[0m\n",
                "  Summary    This sentence is deliberately long\n",
                "             enough to wrap across a narrow\n",
                "             terminal.\n\n",
                "Details\n",
                "  Role  managed node\n\n",
                "Components\n",
                "  Name    State\n",
                "  server  running\n",
                "  mesh    stopped\n\n",
                "Next step\n",
                "  Run infraternal mesh up when this node needs mesh\n",
                "  connectivity.\n"
            )
        );
    }

    #[test]
    fn pretty_snapshot_omits_empty_skill_write_sections() {
        let result = CommandResult::new(
            "skill",
            CommandState::Ready,
            "Wrote 1 command skill files.",
            json!({
                "commands": [],
                "skill": "",
                "files": ["infraternal-status.md"]
            }),
        )
        .with_next_step("Open a generated Markdown file to review its command contract.");
        let output = render_pretty(
            &result,
            RenderOptions {
                terminal: false,
                color: false,
                width: 80,
            },
        )
        .expect("render skill write result");

        assert_eq!(
            output,
            concat!(
                "Infraternal skill\n\n",
                "Overview\n",
                "  State      Ready\n",
                "  Summary    Wrote 1 command skill files.\n\n",
                "Files\n",
                "  infraternal-status.md\n\n",
                "Next step\n",
                "  Open a generated Markdown file to review its command contract.\n"
            )
        );
        let json_output = render_json(&result).expect("render JSON skill write result");
        assert!(json_output.contains("\"commands\": []"));
        assert!(json_output.contains("\"skill\": \"\""));
    }

    #[test]
    fn pretty_tables_omit_empty_columns_and_rows() {
        let result = CommandResult::new(
            "status",
            CommandState::Ready,
            "Components were inspected.",
            json!({
                "components": [
                    {"name": "mesh", "state": "running", "details": ""},
                    {}
                ]
            }),
        );
        let output = render_pretty(
            &result,
            RenderOptions {
                terminal: false,
                color: false,
                width: 80,
            },
        )
        .expect("render status");

        assert!(!output.contains("Details"), "empty column: {output}");
        assert!(!output.contains("  \n"), "empty row: {output}");
    }

    #[test]
    fn json_snapshot_has_stable_versioned_fields_and_omits_absent_details() {
        let mut result = CommandResult::new(
            "mesh up",
            CommandState::Unavailable,
            "Mesh connectivity is not available yet.",
            json!({"ssh": false}),
        )
        .with_next_step("Check infraternal skill mesh up for current instructions.");
        assert_eq!(
            render_json(&result).expect("serialize result"),
            "{\n  \"schema_version\": 1,\n  \"command\": \"mesh up\",\n  \"state\": \"unavailable\",\n  \"message\": \"Mesh connectivity is not available yet.\",\n  \"next_step\": \"Check infraternal skill mesh up for current instructions.\",\n  \"data\": {\n    \"ssh\": false\n  }\n}\n"
        );
        result.details = Some("No component manager is registered.".to_owned());
        let json = render_json(&result).expect("serialize result with details");
        assert!(json.contains("\"details\": \"No component manager is registered.\""));
    }

    #[test]
    fn registered_action_output_schemas_accept_typed_json_envelopes() {
        let registry = crate::cli::actions::registry().expect("action metadata");
        for registered in registry.actions() {
            let command = registered.action.command.join(" ");
            let data = sample_data(&command);
            let result = CommandResult::new(
                command.clone(),
                CommandState::Ready,
                "Schema fixture result.",
                data,
            );
            let value = serde_json::to_value(result).expect("serialize command result");
            assert!(
                matches_schema(&registered.action.output_schema, &value),
                "result for `{command}` must conform to its registered output schema: {value}"
            );
        }
    }

    fn sample_data(command: &str) -> serde_json::Value {
        match command {
            "status" => json!({
                "role": "node",
                "components": [{"name": "server", "state": "Stopped"}]
            }),
            "up" => json!({"started": []}),
            "skill" => json!({
                "commands": [{"command": "status", "description": "Show status."}],
                "skill": "# Status skill",
                "files": ["infraternal-status.md"]
            }),
            "server" => json!({
                "listen": "127.0.0.1:7443",
                "public_origin": "https://localhost:7443"
            }),
            "server init" | "server install" => json!({
                "service": "infraternal-server.service",
                "enabled": true,
                "dry_run": false
            }),
            "server features" => json!({
                "features": [{"name": "mesh", "state": "disabled"}]
            }),
            "server setup-token" => json!({"token": "synthetic-test-value"}),
            _ => json!({}),
        }
    }

    fn matches_schema(schema: &JsonSchema, value: &serde_json::Value) -> bool {
        match schema.schema_type {
            JsonSchemaType::String => value.is_string(),
            JsonSchemaType::Integer => value.as_i64().is_some(),
            JsonSchemaType::Number => value.is_number(),
            JsonSchemaType::Boolean => value.is_boolean(),
            JsonSchemaType::Array => value.as_array().is_some_and(|items| {
                schema.items.as_deref().is_some_and(|item_schema| {
                    items.iter().all(|item| matches_schema(item_schema, item))
                })
            }),
            JsonSchemaType::Object => value.as_object().is_some_and(|object| {
                let has_required = schema.required.iter().all(|key| object.contains_key(key));
                let has_allowed_keys = schema.additional_properties != Some(false)
                    || object.keys().all(|key| schema.properties.contains_key(key));
                let has_valid_values = object.iter().all(|(key, value)| {
                    // Only declared fields have value constraints; extra fields follow the schema policy.
                    match schema.properties.get(key) {
                        Some(property) => matches_schema(property, value),
                        None => schema.additional_properties != Some(false),
                    }
                });
                has_required && has_allowed_keys && has_valid_values
            }),
        }
    }
}
