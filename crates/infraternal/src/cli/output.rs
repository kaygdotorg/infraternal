//! One output style and one JSON envelope for every command (#239, D202, D299, D303).
//!
//! A result is rendered one of two ways from the same [`CommandResult`]:
//!
//! - Text for people: the answer first, in plain words; then short aligned
//!   blocks; then `Why` (only for failures) and `Next` (only when a follow-up is
//!   true for this state). Colour and the state mark appear only on a terminal.
//!   Failures go to standard error so a script's standard output stays empty.
//! - JSON for scripts and AI tools: one single-line envelope per result, with the
//!   same fields for every command, including usage errors. Fields are only ever
//!   added within `schema_version` 1; removing or renaming one bumps the version.

use std::{
    io::{self, IsTerminal, Write},
    process::ExitCode,
};

use infraternal_plugin_api::present;
use serde::Serialize;

/// Widest line a table or paragraph uses, however wide the terminal is: long lines are hard to scan.
const MAX_WIDTH: usize = 100;
/// Narrowest layout the renderer still tries to keep readable.
const MIN_WIDTH: usize = 40;

/// What went wrong, for scripts: a stable code, the argument at fault (never its value), and a sentence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ErrorInfo {
    /// Stable machine-readable code such as `usage`, `not_found` or `unreachable`.
    pub code: String,
    /// Name of the argument at fault, e.g. `--server`; never the value that was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argument: Option<String>,
    /// The failure in plain words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Versioned envelope shared by every command's JSON output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommandResult<T> {
    /// Version of the stable CLI result contract.
    pub schema_version: u32,
    /// Executed command path without the executable name.
    pub command: String,
    /// True when the command did what was asked; always agrees with exit code 0.
    pub ok: bool,
    /// Plain machine-readable state.
    pub state: CommandState,
    /// Short sentence describing the result.
    pub message: String,
    /// Follow-ups that are true for this state; at most three, empty when nothing is needed.
    pub next: Vec<String>,
    /// First entry of `next`; kept so readers of the first envelope keep working.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
    /// Technical detail for a failure, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Present exactly when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    /// Action-specific typed output data.
    pub data: T,
    /// Aligned text that replaces the generic rendering of `data` for people; never serialized.
    #[serde(skip)]
    pub body: Option<String>,
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
            ok: state.is_ok(),
            state,
            message: message.into(),
            next: Vec::new(),
            next_step: None,
            details: None,
            error: None,
            data,
            body: None,
        }
    }

    /// Add a follow-up command or action. Callers add only follow-ups that are true now.
    #[must_use]
    pub fn with_next_step(mut self, next_step: impl Into<String>) -> Self {
        let next_step = next_step.into();
        if self.next.is_empty() {
            self.next_step = Some(next_step.clone());
        }
        self.next.push(next_step);
        self
    }

    /// Attach technical detail while keeping the short sentence user-facing.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Give the failure its own stable code, finer than the exit code (for example `component_down`).
    #[must_use]
    pub fn with_error_code(mut self, code: &str) -> Self {
        self.error = Some(ErrorInfo {
            code: code.to_owned(),
            argument: None,
            detail: Some(self.details.clone().unwrap_or_else(|| self.message.clone())),
        });
        self
    }

    /// Name the argument at fault in a usage error; the value is never recorded.
    #[must_use]
    pub fn with_argument(mut self, code: &str, argument: Option<String>) -> Self {
        self.error = Some(ErrorInfo {
            code: code.to_owned(),
            argument,
            detail: Some(self.details.clone().unwrap_or_else(|| self.message.clone())),
        });
        self
    }

    /// Give people this text instead of the generic rendering of `data`.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        let body = body.into();
        self.body = (!body.trim().is_empty()).then_some(body);
        self
    }
}

/// Stable state values used by text output and JSON consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandState {
    /// The requested operation completed or a healthy state was found.
    Ready,
    /// The requested service or component is currently active.
    Running,
    /// The service is restarting repeatedly and is unavailable.
    Restarting,
    /// The requested service or component is stopped.
    Stopped,
    /// The command waits for a step that only a person can take (a passkey, a confirmation).
    #[cfg_attr(
        not(any(feature = "remote", feature = "plugin-agent")),
        allow(dead_code)
    )]
    Pending,
    /// This build does not provide the command handler.
    Unavailable,
    /// The command was understood and refused: not allowed, or its inputs were not accepted.
    Refused,
    /// The command failed.
    Failed,
    /// A truthful state cannot be established from available runtime data.
    Unknown,
}

impl CommandState {
    /// States that describe a command which did not do what was asked.
    const fn is_ok(self) -> bool {
        !matches!(
            self,
            Self::Unavailable | Self::Refused | Self::Failed | Self::Restarting
        )
    }

    /// One mark per state, shown only on a terminal and always beside a word.
    const fn mark(self) -> &'static str {
        match self {
            Self::Ready | Self::Running => "●",
            Self::Stopped => "○",
            Self::Pending | Self::Unavailable | Self::Unknown => "!",
            Self::Refused | Self::Failed | Self::Restarting => "✕",
        }
    }

    const fn color(self) -> &'static str {
        match self {
            Self::Ready | Self::Running => "\u{1b}[32m",
            Self::Stopped | Self::Unknown => "\u{1b}[36m",
            Self::Pending | Self::Unavailable => "\u{1b}[33m",
            Self::Refused | Self::Failed | Self::Restarting => "\u{1b}[31m",
        }
    }
}

/// How a command ended (D303). A shell reports 130 for SIGINT termination; `error_code` is what
/// the envelope says.
///
/// 0 done · 1 failed · 2 the command line is wrong · 3 not allowed · 4 not found ·
/// 5 off or unreachable · 6 partly done · 130 interrupted by Ctrl-C, terminated by SIGINT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    /// Done, or the state that was asked about was found.
    Ok,
    /// The operation failed.
    Failed,
    /// The command line is wrong.
    Usage,
    /// The request was understood and refused: wrong account, missing proof.
    #[allow(dead_code)]
    // Used by the server, agent and remote commands, which a minimal build leaves out.
    NotAllowed,
    /// What the command was asked about does not exist.
    #[allow(dead_code)] // Used by the server commands, which a minimal build leaves out.
    NotFound,
    /// A component or the thing to talk to is off or does not answer.
    Unreachable,
    /// Some of the work was done and some was not.
    #[allow(dead_code)]
    // The remote operation may have succeeded, but the client cannot confirm or finish it.
    Partial,
    /// Stopped by the person (Ctrl-C); `--json` runs print the `interrupted` envelope, then re-raise SIGINT.
    Interrupted,
}

impl Exit {
    /// Process exit status.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Usage => 2,
            Self::NotAllowed => 3,
            Self::NotFound => 4,
            Self::Unreachable => 5,
            Self::Partial => 6,
            Self::Interrupted => 130,
        }
    }

    /// Stable error code for the envelope's `error.code`.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Usage => "usage",
            Self::NotAllowed => "not_allowed",
            Self::NotFound => "not_found",
            Self::Unreachable => "unreachable",
            Self::Partial => "partial",
            Self::Interrupted => "interrupted",
        }
    }
}

/// The single line a `--json` run prints when Ctrl-C ends it, rendered ahead of time because
/// the signal handler may only copy bytes (see `infraternal_shim::exit_on_interrupt`).
#[must_use]
pub fn interrupted_notice(command: &str) -> Vec<u8> {
    let (message, next) = if command == "sign-in" {
        (
            "Sign-in stopped before it finished; the server may have issued a key.",
            Some(
                "Check the server's device keys and revoke a matching device key before retrying sign-in.",
            ),
        )
    } else {
        ("Stopped before it finished.", None)
    };
    let mut result = CommandResult::new(
        command,
        CommandState::Stopped,
        message,
        serde_json::json!({}),
    );
    if let Some(next) = next {
        result = result.with_next_step(next);
    }
    result.ok = false;
    result.error = Some(ErrorInfo {
        code: Exit::Interrupted.error_code().to_owned(),
        argument: None,
        detail: Some(message.to_owned()),
    });
    render_json(&result).unwrap_or_default().into_bytes()
}

/// Formatting controls supplied by the output destination and test snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenderOptions {
    /// Whether the destination is a terminal.
    pub terminal: bool,
    /// Whether ANSI color is allowed.
    pub color: bool,
    /// Maximum rendered line width in terminal columns.
    pub width: usize,
}

impl RenderOptions {
    /// Width comes from the terminal, then `$COLUMNS`, then 80.
    ///
    /// A dumb terminal (`TERM=dumb`, as in an editor's shell buffer) cannot show escapes or the
    /// state marks, so it is treated like a pipe. Colour is also off when `NO_COLOR` is set to a
    /// non-empty value; an empty one is ignored, which is what the convention says and what the
    /// parser's own messages already do, so the two halves of the binary agree.
    #[must_use]
    pub fn detect(terminal: bool) -> Self {
        let terminal = terminal && std::env::var_os("TERM").is_none_or(|term| term != "dumb");
        let width = infraternal_shim::stdout_columns()
            .map(usize::from)
            .or_else(|| {
                std::env::var("COLUMNS")
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or(80);
        Self {
            terminal,
            color: terminal && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty()),
            width,
        }
    }

    /// Layout width after the readability bounds.
    #[must_use]
    pub fn usable_width(self) -> usize {
        self.width.clamp(MIN_WIDTH, MAX_WIDTH)
    }
}

/// Serialize a result as one line, with a trailing newline. Single lines let a stream of
/// results (progress, pages) be read line by line.
///
/// # Errors
///
/// Returns an error when the value cannot be serialized.
pub fn render_json<T: Serialize>(result: &T) -> Result<String, serde_json::Error> {
    let mut output = serde_json::to_string(result)?;
    output.push('\n');
    Ok(output)
}

/// Render a result as text for people.
///
/// # Errors
///
/// Returns an error when `data` cannot be converted for the generic renderer.
pub fn render_pretty<T: Serialize>(
    result: &CommandResult<T>,
    options: RenderOptions,
) -> Result<String, serde_json::Error> {
    let width = options.usable_width();
    let mut sections: Vec<String> = Vec::new();

    let headline = if options.terminal {
        let mark = if options.color {
            format!("{}{}\u{1b}[0m", result.state.color(), result.state.mark())
        } else {
            result.state.mark().to_owned()
        };
        // The mark takes two columns of the first line.
        let mut lines = present::wrap(&result.message, width.saturating_sub(2));
        lines[0] = format!("{mark} {}", lines[0]);
        for line in lines.iter_mut().skip(1) {
            line.insert_str(0, "  ");
        }
        lines.join("\n") + "\n"
    } else {
        present::wrap(&result.message, width).join("\n") + "\n"
    };
    sections.push(headline);

    if let Some(body) = &result.body {
        sections.push(body.clone());
    } else {
        let data = serde_json::to_value(&result.data)?;
        sections.extend(render_data(&data, options));
    }

    let mut closing: Vec<(&str, String)> = Vec::new();
    if let Some(details) = &result.details {
        closing.push(("Why", details.clone()));
    }
    for (index, next) in result.next.iter().enumerate() {
        closing.push((if index == 0 { "Next" } else { "" }, next.clone()));
    }
    let closing = present::pairs(&closing, 0, width);
    if !closing.is_empty() {
        sections.push(closing);
    }
    Ok(sections
        .iter()
        .map(|section| section.trim_end_matches('\n'))
        .collect::<Vec<_>>()
        .join("\n\n")
        + "\n")
}

/// Text for results that have no hand-made body: values in `data`, shown as short aligned blocks.
fn render_data(data: &serde_json::Value, options: RenderOptions) -> Vec<String> {
    let width = options.usable_width();
    let Some(fields) = data.as_object() else {
        return if is_empty_value(data) {
            Vec::new()
        } else {
            vec![present::wrap(&scalar_text(data), width).join("\n") + "\n"]
        };
    };
    let mut sections = Vec::new();
    let scalars: Vec<(String, String)> = fields
        .iter()
        .filter(|(_, value)| !value.is_object() && !value.is_array() && !is_empty_value(value))
        .map(|(key, value)| (humanize(key), scalar_text(value)))
        .collect();
    if !scalars.is_empty() {
        let rows: Vec<(&str, String)> = scalars
            .iter()
            .map(|(label, value)| (label.as_str(), value.clone()))
            .collect();
        sections.push(present::pairs(&rows, 0, width));
    }
    let structured: Vec<_> = fields
        .iter()
        .filter(|(_, value)| (value.is_object() || value.is_array()) && !is_empty_value(value))
        .collect();
    // A heading only helps when it tells blocks apart.
    let headings = structured.len() + usize::from(!scalars.is_empty()) > 1;
    for (key, value) in structured {
        let mut block = if headings {
            format!("{}\n", humanize(key))
        } else {
            String::new()
        };
        let indent = if headings { 2 } else { 0 };
        if let Some(items) = value.as_array() {
            if let Some((header, rows)) = object_rows(items) {
                let tint = |column: usize, text: &str| {
                    (options.color && header[column] == "state")
                        .then(|| state_tint(text))
                        .flatten()
                };
                let labels: Vec<String> = header.iter().map(|key| humanize(key)).collect();
                let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
                block.push_str(&present::table(&labels, &rows, indent, width, Some(&tint)));
            } else {
                for item in items.iter().filter(|item| !is_empty_value(item)) {
                    for line in present::wrap(&scalar_text(item), width.saturating_sub(indent)) {
                        block.push_str(&" ".repeat(indent));
                        block.push_str(&line);
                        block.push('\n');
                    }
                }
            }
        } else if let Some(nested) = value.as_object() {
            let rows: Vec<(String, String)> = nested
                .iter()
                .filter(|(_, value)| !is_empty_value(value))
                .map(|(key, value)| (humanize(key), scalar_text(value)))
                .collect();
            let rows: Vec<(&str, String)> = rows
                .iter()
                .map(|(label, value)| (label.as_str(), value.clone()))
                .collect();
            block.push_str(&present::pairs(&rows, indent, width));
        }
        sections.push(block);
    }
    sections
}

/// Terminal tint for a state word in a table column.
pub fn state_tint(text: &str) -> Option<&'static str> {
    match text.to_ascii_lowercase().as_str() {
        "running" | "ready" | "on" | "active" => Some("\u{1b}[32m"),
        "failed" | "refused" => Some("\u{1b}[31m"),
        "stopped" | "unknown" | "off" => Some("\u{1b}[36m"),
        _ => None,
    }
}

/// Empty containers and blank strings have no useful human representation.
/// Keep them in JSON, but omit their labels in the human renderer.
fn is_empty_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => value.trim().is_empty(),
        serde_json::Value::Array(items) => items.is_empty() || items.iter().all(is_empty_value),
        serde_json::Value::Object(fields) => {
            fields.is_empty() || fields.values().all(is_empty_value)
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

/// Columns (keys, `name` first) and rows for an array of flat objects.
fn object_rows(items: &[serde_json::Value]) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    if items.is_empty() || items.iter().any(|item| !item.is_object()) {
        return None;
    }
    let visible: Vec<_> = items
        .iter()
        .filter_map(serde_json::Value::as_object)
        .filter(|fields| fields.values().any(|value| !is_empty_value(value)))
        .collect();
    let mut columns: Vec<String> = Vec::new();
    for fields in &visible {
        for (key, value) in *fields {
            if !is_empty_value(value) && !columns.contains(key) {
                columns.push(key.clone());
            }
        }
    }
    if columns.is_empty() {
        return None;
    }
    if let Some(at) = columns
        .iter()
        .position(|key| key == "name" || key == "command")
    {
        let first = columns.remove(at);
        columns.insert(0, first);
    }
    let rows = visible
        .iter()
        .map(|fields| {
            columns
                .iter()
                .map(|key| fields.get(key).map_or_else(String::new, scalar_text))
                .collect()
        })
        .collect();
    Some((columns, rows))
}

/// A label for a JSON key: `state_detail` reads as `Detail`, `peer_count` as `Peer count`.
fn humanize(value: &str) -> String {
    let value = value.strip_prefix("state_").unwrap_or(value);
    let mut output = String::with_capacity(value.len());
    for (index, character) in value.chars().enumerate() {
        if character == '_' || character == '-' {
            output.push(' ');
        } else if index == 0 {
            output.extend(character.to_uppercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn scalar_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "none".to_owned(),
        serde_json::Value::Bool(true) => "yes".to_owned(),
        serde_json::Value::Bool(false) => "no".to_owned(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            serde_json::to_string(value).unwrap_or_else(|_| "(unreadable value)".to_owned())
        }
    }
}

/// Finish a command: stamp `ok` and `error` from how it ended, print it, and return the exit code.
///
/// Failures go to standard error in text mode, so a script that reads standard output
/// sees nothing; in JSON mode every result, failure or not, is one line on standard output.
pub fn emit<T: Serialize>(result: CommandResult<T>, json: bool, exit: Exit) -> ExitCode {
    emit_to(result, json, exit, exit != Exit::Ok)
}

/// Like [`emit`], with the destination for text output chosen by the caller.
/// A report that is information even when the exit code is not zero (a stopped node) uses standard output.
pub fn emit_to<T: Serialize>(
    mut result: CommandResult<T>,
    json: bool,
    exit: Exit,
    to_stderr: bool,
) -> ExitCode {
    result.ok = exit == Exit::Ok;
    if exit != Exit::Ok && result.error.is_none() {
        result.error = Some(ErrorInfo {
            code: exit.error_code().to_owned(),
            argument: None,
            detail: result
                .details
                .clone()
                .or_else(|| Some(result.message.clone())),
        });
    }
    print(&result, json, to_stderr && !json);
    ExitCode::from(exit.code())
}

/// Print a result without deciding the exit code (streams of progress records, tests).
pub fn print<T: Serialize>(result: &CommandResult<T>, json: bool, to_stderr: bool) {
    print_with_phase(result, json, to_stderr, true);
}

/// Write a progress record without marking the command's final result as written.
/// This keeps the interrupt handler free to emit the final interrupted envelope later.
pub fn print_progress<T: Serialize>(result: &CommandResult<T>, json: bool, to_stderr: bool) {
    print_with_phase(result, json, to_stderr, false);
}

fn print_with_phase<T: Serialize>(
    result: &CommandResult<T>,
    json: bool,
    to_stderr: bool,
    final_output: bool,
) {
    let terminal = if to_stderr {
        io::stderr().is_terminal()
    } else {
        io::stdout().is_terminal()
    };
    let rendered = if json {
        render_json(result)
    } else {
        render_pretty(result, RenderOptions::detect(terminal))
    };
    write_rendered(rendered, to_stderr, final_output);
}

/// Shares formatting-error and destination handling for every rendered result.
pub fn write_output(output: Result<String, serde_json::Error>, to_stderr: bool) {
    write_rendered(output, to_stderr, true);
}

fn write_rendered(output: Result<String, serde_json::Error>, to_stderr: bool, final_output: bool) {
    let rendered = match output {
        Ok(output) => output,
        Err(error) => {
            eprintln!("The result could not be formatted.\nWhy  {error}");
            return;
        }
    };
    if final_output {
        infraternal_shim::begin_final_output();
    }
    let write_result = if to_stderr {
        io::stderr().write_all(rendered.as_bytes())
    } else {
        io::stdout().write_all(rendered.as_bytes())
    };
    // A closed pipe (for example `| head`) is the reader's choice, not an error to report.
    if let Err(error) = write_result
        && error.kind() != io::ErrorKind::BrokenPipe
    {
        eprintln!("The result could not be written.\nWhy  {error}");
    }
    if final_output {
        infraternal_shim::finish_final_output();
    }
}

#[cfg(test)]
mod tests {
    //! Snapshots text output, terminal colour, wrapping, and the stable JSON envelope.

    use infraternal_plugin_api::{JsonSchema, JsonSchemaType};
    use serde_json::json;

    use super::{
        CommandResult, CommandState, Exit, RenderOptions, emit_to, render_json, render_pretty,
    };

    const PLAIN: RenderOptions = RenderOptions {
        terminal: false,
        color: false,
        width: 80,
    };

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
        .with_next_step("infraternal mesh up")
    }

    #[test]
    fn plain_text_answers_first_then_aligned_blocks_then_next() {
        let output = render_pretty(&status(), PLAIN).expect("render status");
        assert_eq!(
            output,
            concat!(
                "The server is running and this node is connected.\n\n",
                "Role  managed node\n\n",
                "Components\n",
                "  NAME    STATE\n",
                "  server  running\n",
                "  mesh    stopped\n\n",
                "Next  infraternal mesh up\n"
            )
        );
    }

    #[test]
    fn terminal_output_has_a_mark_and_colour_and_wraps_to_the_width() {
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
        assert!(
            output.starts_with(
                "\u{1b}[32m●\u{1b}[0m This sentence is deliberately long enough to wrap\n  across"
            ),
            "{output:?}"
        );
        assert!(output.contains("\u{1b}[32mrunning\u{1b}[0m"), "{output:?}");
        // The mark stays with NO_COLOR; plain output has neither mark nor colour.
        let marked = render_pretty(
            &result,
            RenderOptions {
                terminal: true,
                color: false,
                width: 80,
            },
        )
        .expect("render status");
        assert!(marked.starts_with("● This sentence"), "{marked:?}");
        assert!(!marked.contains('\u{1b}'), "{marked:?}");
        assert!(!render_pretty(&result, PLAIN).expect("plain").contains('●'));
    }

    #[test]
    fn a_failure_says_why_and_what_to_do() {
        let result = CommandResult::new(
            "mesh peers",
            CommandState::Failed,
            "The infraternal agent on this machine is not answering.",
            json!({}),
        )
        .with_details("No socket in the runtime directory.")
        .with_next_step("infraternal agent run");
        assert_eq!(
            render_pretty(&result, PLAIN).expect("render failure"),
            concat!(
                "The infraternal agent on this machine is not answering.\n\n",
                "Why   No socket in the runtime directory.\n",
                "Next  infraternal agent run\n"
            )
        );
    }

    #[test]
    fn a_body_replaces_the_generic_rendering_of_data() {
        let result = status().with_body("custom block\n");
        let output = render_pretty(&result, PLAIN).expect("render body");
        assert!(output.contains("custom block"));
        assert!(!output.contains("Components"));
    }

    #[test]
    fn tables_omit_empty_columns_and_rows_and_single_rows_have_no_header() {
        let result = CommandResult::new(
            "status",
            CommandState::Ready,
            "Components were inspected.",
            json!({"components": [{"name": "mesh", "state": "running", "details": ""}, {}]}),
        );
        let output = render_pretty(&result, PLAIN).expect("render status");
        assert_eq!(output, "Components were inspected.\n\nmesh  running\n");
    }

    #[test]
    fn json_is_one_line_with_stable_fields_and_omits_absent_ones() {
        let result = CommandResult::new(
            "mesh up",
            CommandState::Unavailable,
            "Mesh connectivity is not available yet.",
            json!({"ssh": false}),
        )
        .with_next_step("infraternal skill mesh up");
        assert_eq!(
            render_json(&result).expect("serialize result"),
            concat!(
                "{\"schema_version\":1,\"command\":\"mesh up\",\"ok\":false,",
                "\"state\":\"unavailable\",\"message\":\"Mesh connectivity is not available yet.\",",
                "\"next\":[\"infraternal skill mesh up\"],",
                "\"next_step\":\"infraternal skill mesh up\",\"data\":{\"ssh\":false}}\n"
            )
        );
    }

    #[test]
    fn exit_codes_follow_d303() {
        use super::Exit::{
            Failed, Interrupted, NotAllowed, NotFound, Ok, Partial, Unreachable, Usage,
        };
        let codes: Vec<u8> = [
            Ok,
            Failed,
            Usage,
            NotAllowed,
            NotFound,
            Unreachable,
            Partial,
            Interrupted,
        ]
        .iter()
        .map(|exit| exit.code())
        .collect();
        assert_eq!(codes, [0, 1, 2, 3, 4, 5, 6, 130]);
    }

    #[test]
    fn interrupted_sign_in_warns_that_the_server_key_may_need_revocation() {
        let notice = super::interrupted_notice("sign-in");
        let result: serde_json::Value =
            serde_json::from_slice(&notice).expect("interrupted JSON envelope");

        assert_eq!(result["error"]["code"], "interrupted");
        assert!(
            result["message"]
                .as_str()
                .expect("message")
                .contains("may have issued a key")
        );
        assert!(
            result["next_step"]
                .as_str()
                .expect("next step")
                .contains("revoke a matching device key")
        );
    }

    #[test]
    fn finishing_a_command_stamps_ok_and_the_error_from_the_exit() {
        let failed = CommandResult::new("x", CommandState::Failed, "It broke.", json!({}))
            .with_details("because");
        let exit = emit_to(failed, true, Exit::Failed, false);
        assert_eq!(
            format!("{exit:?}"),
            format!("{:?}", std::process::ExitCode::from(1))
        );
        let mut done = CommandResult::new("x", CommandState::Ready, "Done.", json!({}));
        done.ok = false;
        let exit = emit_to(done, true, Exit::Ok, false);
        assert_eq!(
            format!("{exit:?}"),
            format!("{:?}", std::process::ExitCode::SUCCESS)
        );
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
