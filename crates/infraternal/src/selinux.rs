//! Keeps the updater's boot pointer executable for systemd on `SELinux` hosts (#211).
//!
//! On enforcing `SELinux` hosts (such as EL-family servers), files created under
//! `/var/lib/infraternal` inherit `var_lib_t`. systemd refuses to execute a
//! service entrypoint with `var_lib_t` (203/EXEC, Permission denied), so a
//! unit starting `<data>/updates/current/infraternal` cannot cold-start unless
//! `<data>/updates(/.*)?` carries an executable file context (`bin_t`).
//!
//! Both `infraternal server init --system` and `infraternal server update adopt`
//! call [`plan_for_host`] before touching units and [`apply_on_host`] before
//! writing or reloading the systemd unit:
//!
//! 1. Detect whether `SELinux` is active (`/sys/fs/selinux/enforce` exists, or
//!    `getenforce` prints anything other than `Disabled`). Non-SELinux hosts
//!    return `Ok(None)` and run no extra commands.
//! 2. Resolve `semanage` and `restorecon` from fixed, root-owned system paths
//!    ([`crate::trusted_program::trusted_program`], never `PATH`). If
//!    `semanage` is missing, refuse with a message naming
//!    `policycoreutils-python-utils` instead of producing a unit systemd cannot
//!    start.
//! 3. Check `semanage fcontext -l -C` so the persistent `bin_t` rule for
//!    `<data>/updates(/.*)?` is added only when not already present.
//! 4. Ensure `<data>/updates` exists (0700) and run `restorecon -R <data>/updates`
//!    so the folder and any staged releases inherit `bin_t`.

use crate::trusted_program::{ToolError, trusted_program};
use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Kernel selinuxfs flag present whenever `SELinux` is enabled (enforcing or permissive).
const ENFORCE_PATH: &str = "/sys/fs/selinux/enforce";

/// `SELinux` file type that lets systemd execute the server binary from `<data>/updates`.
const EXEC_TYPE: &str = "bin_t";

/// Package that provides `semanage` on EL-family and Fedora hosts.
pub(crate) const SEMANAGE_PACKAGE: &str = "policycoreutils-python-utils";

/// Package that provides `restorecon` on `SELinux` hosts.
const RESTORECON_PACKAGE: &str = "policycoreutils";

/// Fixed, root-owned candidate paths for `getenforce` (never resolved via `PATH`).
const GETENFORCE_CANDIDATES: &[&str] = &[
    "/usr/sbin/getenforce",
    "/sbin/getenforce",
    "/usr/bin/getenforce",
    "/bin/getenforce",
];

/// Fixed, root-owned candidate paths for `semanage` (never resolved via `PATH`).
const SEMANAGE_CANDIDATES: &[&str] = &[
    "/usr/sbin/semanage",
    "/sbin/semanage",
    "/usr/bin/semanage",
    "/bin/semanage",
];

/// Fixed, root-owned candidate paths for `restorecon` (never resolved via `PATH`).
const RESTORECON_CANDIDATES: &[&str] = &[
    "/usr/sbin/restorecon",
    "/sbin/restorecon",
    "/usr/bin/restorecon",
    "/bin/restorecon",
];

/// Captured result of running one `SELinux` helper command.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct CommandOutput {
    /// Whether the command exited with status 0.
    pub(crate) success: bool,
    /// Captured standard output (lossily decoded UTF-8).
    pub(crate) stdout: String,
    /// Captured standard error (lossily decoded UTF-8).
    pub(crate) stderr: String,
}

/// System seam for `SELinux` detection, tool lookup and command execution.
///
/// Production uses [`HostEnvironment`]; unit tests substitute a fake
/// environment so detection, idempotency, missing-tool refusal and dry-run
/// output run on any Linux host without `SELinux` installed.
pub(crate) trait Environment {
    /// Whether `/sys/fs/selinux/enforce` exists on this host.
    fn enforce_file_exists(&self) -> bool;

    /// Resolve the first existing root-owned candidate binary.
    fn find_tool(&self, candidates: &[&str]) -> Result<PathBuf, ToolError>;

    /// Run `program` with `args` and return its exit status and output.
    fn run(&mut self, program: &Path, args: &[&str]) -> io::Result<CommandOutput>;

    /// Ensure `<data>/updates` exists with private `0700` permissions before `restorecon`.
    fn ensure_updates_dir(&mut self, path: &Path) -> io::Result<()>;
}

/// Real Linux host implementation of [`Environment`].
struct HostEnvironment;

impl Environment for HostEnvironment {
    fn enforce_file_exists(&self) -> bool {
        Path::new(ENFORCE_PATH).exists()
    }

    fn find_tool(&self, candidates: &[&str]) -> Result<PathBuf, ToolError> {
        trusted_program(candidates, 0)
    }

    fn run(&mut self, program: &Path, args: &[&str]) -> io::Result<CommandOutput> {
        let mut command = Command::new(program);
        infraternal_shim::prepare_child(&mut command);
        command.stdin(Stdio::null());
        command.args(args);
        let output = command.output()?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn ensure_updates_dir(&mut self, path: &Path) -> io::Result<()> {
        crate::install_paths::create_private_dir(path)
    }
}

/// Errors returned while planning or applying `SELinux` file-context labels.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub(crate) enum SelinuxError {
    /// The updates directory path is not valid UTF-8 or contains control characters.
    #[error("the updates folder {} cannot be represented in an SELinux file-context rule", .0.display())]
    InvalidPath(PathBuf),
    /// `SELinux` is active, but `semanage` is not installed.
    #[error(
        "SELinux is active on this host, but semanage is not installed, so {} cannot be labeled \
         executable ({EXEC_TYPE}) for systemd; install {SEMANAGE_PACKAGE} and try again",
        updates_dir.display()
    )]
    MissingSemanage {
        /// The `<data>/updates` directory that needs the persistent label.
        updates_dir: PathBuf,
    },
    /// `SELinux` is active, but `restorecon` is not installed.
    #[error(
        "SELinux is active on this host, but restorecon is not installed, so {} cannot be \
         relabeled ({EXEC_TYPE}) for systemd; install {RESTORECON_PACKAGE} and try again",
        updates_dir.display()
    )]
    MissingRestorecon {
        /// The `<data>/updates` directory that needs relabeling.
        updates_dir: PathBuf,
    },
    /// A candidate `SELinux` tool is not safely owned and protected by root.
    #[error(
        "refusing to run {tool} because it or a parent directory is writable by non-root users"
    )]
    UntrustedTool {
        /// Human-readable name of the refused binary.
        tool: &'static str,
    },
    /// Creating `<data>/updates` before `restorecon` failed.
    #[error("could not create {} before running restorecon: {detail}", path.display())]
    UpdatesDir {
        /// Path of the updates directory.
        path: PathBuf,
        /// Underlying OS error text.
        detail: String,
    },
    /// An `SELinux` management command exited non-zero or failed to start.
    #[error("{command} failed: {detail}")]
    CommandFailed {
        /// Command summary without secrets.
        command: String,
        /// Captured stderr or OS error detail.
        detail: String,
    },
}

impl SelinuxError {
    /// Actionable next step for CLI refusal envelopes.
    pub(crate) fn next_step(&self) -> String {
        match self {
            Self::MissingSemanage { .. } => {
                format!("Install {SEMANAGE_PACKAGE} (for semanage) and run this command again.")
            }
            Self::MissingRestorecon { .. } => {
                format!("Install {RESTORECON_PACKAGE} (for restorecon) and run this command again.")
            }
            Self::UntrustedTool { tool } => {
                format!("Fix ownership and permissions on {tool}, then run this command again.")
            }
            Self::InvalidPath(_) => {
                "Choose a data folder path made of plain UTF-8 characters without control characters."
                    .to_owned()
            }
            Self::UpdatesDir { .. } | Self::CommandFailed { .. } => {
                "Check the host's SELinux policy and permissions, then run this command again."
                    .to_owned()
            }
        }
    }
}

/// Planned `SELinux` labeling work for `<data>/updates`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct LabelPlan {
    /// Resolved trusted path to `semanage`.
    semanage: PathBuf,
    /// Resolved trusted path to `restorecon`.
    restorecon: PathBuf,
    /// `<data>/updates` directory to create (if missing) and relabel.
    updates_dir: PathBuf,
    /// Regex pattern passed to `semanage fcontext`, e.g. `/var/lib/infraternal/updates(/.*)?`.
    pattern: String,
    /// Whether `semanage fcontext -a -t bin_t <pattern>` must be run (`false` when already present).
    add_rule: bool,
}

impl LabelPlan {
    /// Human-readable commands that [`Self::apply`] will execute, for `--dry-run` output.
    pub(crate) fn dry_run_commands(&self) -> Vec<String> {
        let mut commands = Vec::with_capacity(2);
        if self.add_rule {
            commands.push(format!(
                "semanage fcontext -a -t {EXEC_TYPE} {}",
                shell_quote(&self.pattern)
            ));
        }
        commands.push(format!(
            "restorecon -R {}",
            shell_quote(&self.updates_dir.to_string_lossy())
        ));
        commands
    }

    /// Apply the planned persistent fcontext rule (if missing) and relabel `<data>/updates`.
    pub(crate) fn apply(&self, env: &mut impl Environment) -> Result<(), SelinuxError> {
        if self.add_rule {
            let args = ["fcontext", "-a", "-t", EXEC_TYPE, self.pattern.as_str()];
            let output =
                env.run(&self.semanage, &args)
                    .map_err(|error| SelinuxError::CommandFailed {
                        command: format!(
                            "semanage fcontext -a -t {EXEC_TYPE} {}",
                            shell_quote(&self.pattern)
                        ),
                        detail: error.to_string(),
                    })?;
            if !output.success {
                return Err(SelinuxError::CommandFailed {
                    command: format!(
                        "semanage fcontext -a -t {EXEC_TYPE} {}",
                        shell_quote(&self.pattern)
                    ),
                    detail: command_detail(&output),
                });
            }
        }
        env.ensure_updates_dir(&self.updates_dir)
            .map_err(|error| SelinuxError::UpdatesDir {
                path: self.updates_dir.clone(),
                detail: error.to_string(),
            })?;
        let updates_str = self
            .updates_dir
            .to_str()
            .ok_or_else(|| SelinuxError::InvalidPath(self.updates_dir.clone()))?;
        let restore_args = ["-R", updates_str];
        let output = env.run(&self.restorecon, &restore_args).map_err(|error| {
            SelinuxError::CommandFailed {
                command: format!("restorecon -R {}", shell_quote(updates_str)),
                detail: error.to_string(),
            }
        })?;
        if !output.success {
            return Err(SelinuxError::CommandFailed {
                command: format!("restorecon -R {}", shell_quote(updates_str)),
                detail: command_detail(&output),
            });
        }
        Ok(())
    }
}

/// Detect whether `SELinux` is active on this host.
///
/// Returns `true` when `/sys/fs/selinux/enforce` exists, or when `getenforce`
/// succeeds and prints anything other than `Disabled` (case-insensitive).
pub(crate) fn is_selinux_active(env: &mut impl Environment) -> bool {
    if env.enforce_file_exists() {
        return true;
    }
    let Ok(getenforce) = env.find_tool(GETENFORCE_CANDIDATES) else {
        return false;
    };
    let Ok(output) = env.run(&getenforce, &[]) else {
        return false;
    };
    if !output.success {
        return false;
    }
    let mode = output.stdout.trim();
    !mode.is_empty() && !mode.eq_ignore_ascii_case("disabled")
}

/// Build the `semanage fcontext` regex for `<data>/updates(/.*)?`.
///
/// Regex metacharacters in `updates_dir` are escaped so paths containing `.`
/// or `+` match literally while standard paths like `/var/lib/infraternal/updates`
/// produce `/var/lib/infraternal/updates(/.*)?` verbatim.
pub(crate) fn updates_fcontext_pattern(updates_dir: &Path) -> Result<String, SelinuxError> {
    let raw = updates_dir
        .to_str()
        .ok_or_else(|| SelinuxError::InvalidPath(updates_dir.to_owned()))?;
    if raw.is_empty() || raw.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(SelinuxError::InvalidPath(updates_dir.to_owned()));
    }
    let trimmed = raw.trim_end_matches('/');
    let mut escaped = String::with_capacity(trimmed.len() + 7);
    for ch in trimmed.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped.push_str("(/.*)?");
    Ok(escaped)
}

/// Whether `semanage fcontext -l -C` output already contains the exact `all files`
/// rule mapping `pattern` to `label_type` (for example `bin_t`).
pub(crate) fn has_exact_fcontext_rule(
    locallist_output: &str,
    pattern: &str,
    label_type: &str,
) -> bool {
    for line in locallist_output.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(pattern) else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((file_type, context)) = rest.trim().rsplit_once(char::is_whitespace) else {
            continue;
        };
        if file_type.trim() == "all files" && context.split(':').nth(2) == Some(label_type) {
            return true;
        }
    }
    false
}

/// Plan the `SELinux` labeling commands for `<data>/updates` against `env`.
///
/// Returns `Ok(None)` on non-SELinux hosts so callers perform no extra work.
/// On `SELinux` hosts, refuses immediately if `semanage` or `restorecon` is
/// missing or untrusted. In `dry_run` mode, a failed `semanage fcontext -l -C`
/// (such as when an unprivileged user inspects a `--dry-run` plan) conservatively
/// plans `semanage fcontext -a` instead of aborting.
pub(crate) fn plan_updates_exec(
    data: &Path,
    env: &mut impl Environment,
    dry_run: bool,
) -> Result<Option<LabelPlan>, SelinuxError> {
    if !is_selinux_active(env) {
        return Ok(None);
    }
    let updates_dir = data.join("updates");
    let pattern = updates_fcontext_pattern(&updates_dir)?;
    let semanage = match env.find_tool(SEMANAGE_CANDIDATES) {
        Ok(path) => path,
        Err(ToolError::Missing) => return Err(SelinuxError::MissingSemanage { updates_dir }),
        Err(ToolError::Untrusted) => return Err(SelinuxError::UntrustedTool { tool: "semanage" }),
    };
    let restorecon = match env.find_tool(RESTORECON_CANDIDATES) {
        Ok(path) => path,
        Err(ToolError::Missing) => return Err(SelinuxError::MissingRestorecon { updates_dir }),
        Err(ToolError::Untrusted) => {
            return Err(SelinuxError::UntrustedTool { tool: "restorecon" });
        }
    };
    let add_rule = match env.run(&semanage, &["fcontext", "-l", "-C"]) {
        Ok(output) if output.success => {
            !has_exact_fcontext_rule(&output.stdout, &pattern, EXEC_TYPE)
        }
        Ok(_) | Err(_) if dry_run => true,
        Ok(output) => {
            return Err(SelinuxError::CommandFailed {
                command: "semanage fcontext -l -C".to_owned(),
                detail: command_detail(&output),
            });
        }
        Err(error) => {
            return Err(SelinuxError::CommandFailed {
                command: "semanage fcontext -l -C".to_owned(),
                detail: error.to_string(),
            });
        }
    };
    Ok(Some(LabelPlan {
        semanage,
        restorecon,
        updates_dir,
        pattern,
        add_rule,
    }))
}

/// Plan `SELinux` labeling for `<data>/updates` on the real host.
pub(crate) fn plan_for_host(data: &Path, dry_run: bool) -> Result<Option<LabelPlan>, SelinuxError> {
    let mut env = HostEnvironment;
    plan_updates_exec(data, &mut env, dry_run)
}

/// Apply a planned `SELinux` label update on the real host.
pub(crate) fn apply_on_host(plan: &LabelPlan) -> Result<(), SelinuxError> {
    let mut env = HostEnvironment;
    plan.apply(&mut env)
}

/// Construct a [`LabelPlan`] directly for caller dry-run unit tests.
#[cfg(test)]
pub(crate) fn plan_for_tests(data: &Path, add_rule: bool) -> LabelPlan {
    let updates_dir = data.join("updates");
    let pattern = updates_fcontext_pattern(&updates_dir).expect("valid test path");
    LabelPlan {
        semanage: PathBuf::from("/usr/sbin/semanage"),
        restorecon: PathBuf::from("/usr/sbin/restorecon"),
        updates_dir,
        pattern,
        add_rule,
    }
}

/// Quote `value` for human-readable shell command output when it contains shell metacharacters.
fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_.-:@".contains(&byte));
    if safe {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if matches!(ch, '"' | '\\' | '$' | '`') {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Summarize a failed command's stderr (or stdout) in one trimmed line.
fn command_detail(output: &CommandOutput) -> String {
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_owned();
    }
    let stdout = output.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_owned();
    }
    "command exited with a non-zero status".to_owned()
}

/// Unit tests for `SELinux` detection, command planning and idempotency.
#[cfg(test)]
#[path = "selinux_tests.rs"]
mod tests;
