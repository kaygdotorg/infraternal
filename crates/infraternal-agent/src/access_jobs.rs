//! D367 observes system jobs that can write as a revoked account later.
//! System cron and the system manager's effective service identities are read,
//! including dormant services, timers and transient units. Nothing is stopped,
//! edited or deleted. Unknown inventory is reported, never treated as empty.
//!
//! Root-job coverage is deliberately bounded to a cron command's direct target,
//! a service's ExecStart target/direct interpreter script, and its fragment and
//! drop-ins, with their writable parent directories. It does not trace libraries,
//! sourced files or arbitrary executable-input graphs. Shell expansion and
//! wrappers we cannot resolve fail closed as privileged instead of being ignored.
use nix::unistd::User;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

/// One bounded observation of future account work.
#[derive(Default)]
pub(crate) struct Observation {
    /// Printable source names only; command arguments may contain credentials.
    pub(crate) jobs: Vec<String>,
    /// False on unavailable, malformed or over-budget inventory.
    pub(crate) complete: bool,
    /// A root job has a writable or unresolvable direct input (D367).
    pub(crate) privileged: bool,
    /// Direct root-job inputs pending the single kernel permission query.
    root_inputs: Vec<(String, Vec<PathBuf>)>,
    /// Aggregate path budget, charged before retaining any root-job candidate.
    input_paths: usize,
    /// Aggregate pathname bytes, also bounding the downgraded child's argv.
    input_bytes: usize,
}

impl Observation {
    /// Start a complete empty inventory before observing each scheduler source.
    pub(crate) fn empty() -> Self {
        Self {
            complete: true,
            ..Self::default()
        }
    }
}

/// Read a small ordinary cron file without following a link or blocking on a device.
fn cron_text(path: &Path) -> Option<String> {
    let file = fs::File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(65537).read_to_string(&mut text).ok()?;
    (text.len() <= 65536).then_some(text)
}

/// Parse only cron's schedule and account columns. Command text is never exposed.
fn cron_accounts(text: &str) -> Option<Vec<(usize, &str)>> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let columns: Vec<_> = line.split_ascii_whitespace().collect();
        if columns.first().is_some_and(|word| word.contains('=')) || columns.get(1) == Some(&"=") {
            continue;
        }
        let user_column = if line.starts_with('@') { 1 } else { 5 };
        if columns.len() <= user_column + 1 {
            return None;
        }
        found.push((index + 1, columns[user_column]));
    }
    Some(found)
}

/// Keep report text bounded and printable; dropping a name invalidates completeness.
fn add(observed: &mut Observation, name: &str) {
    if observed.jobs.len() >= 64 {
        observed.complete = false;
        return;
    }
    observed.jobs.push(
        name.chars()
            .take(200)
            .map(|c| {
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '\u{fffd}'
                }
            })
            .collect(),
    );
}

/// Preserve the command tail exactly; normalizing whitespace can change a
/// quoted executable path and inspect a different file from the scheduler.
fn after_columns(mut line: &str, count: usize) -> Option<&str> {
    for _ in 0..count {
        line = line.trim_start_matches(|c: char| c.is_ascii_whitespace());
        let end = line.find(|c: char| c.is_ascii_whitespace())?;
        line = &line[end..];
    }
    Some(line.trim_start_matches(|c: char| c.is_ascii_whitespace()))
}

/// Direct command targets only: no shell expansion, sourcing or recursive
/// executable-input graph. Ambiguous shell constructs fail closed for that job.
fn command_targets(command: &str) -> Option<Vec<PathBuf>> {
    if command.contains('\\')
        || command.len() > 4096
        || command.chars().any(|c| "$;|&<>`()\n%".contains(c))
    {
        return None;
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escape = false;
    for c in command.chars() {
        if escape {
            word.push(c);
            escape = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escape = true;
            continue;
        }
        if Some(c) == quote {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if quote.is_none() && c.is_ascii_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if quote.is_some() || escape {
        return None;
    }
    if !word.is_empty() {
        words.push(word);
    }
    let first = words.first()?;
    if !first.starts_with('/') {
        return None;
    }
    let mut paths = vec![PathBuf::from(first)];
    let name = Path::new(first).file_name()?.to_str()?;
    if matches!(
        name,
        "sh" | "bash" | "dash" | "zsh" | "python" | "python3" | "perl" | "ruby" | "node"
    ) {
        let script = words.get(1)?;
        if script == "-c" {
            return command_targets(&words.get(2..)?.join(" "));
        }
        if !script.starts_with('/') {
            return None;
        }
        paths.push(PathBuf::from(script));
    } else if matches!(name, "env" | "sudo" | "doas" | "runuser" | "su") {
        // These wrappers select another executable or identity. We do not
        // interpret their argument languages and cannot prove the job safe.
        return None;
    }
    Some(paths)
}

/// Collect a root job's direct targets and unit files. Parents and resolved
/// symlink targets matter too: replacing a path can change what root executes.
fn root_job(observed: &mut Observation, name: String, inputs: Option<Vec<PathBuf>>) {
    let Some(inputs) = inputs else {
        observed.privileged = true;
        add(observed, &format!("Root-run job: {name} (target unknown)"));
        return;
    };
    let mut paths = BTreeSet::new();
    for input in inputs {
        let Ok(canonical) = fs::canonicalize(&input) else {
            observed.privileged = true;
            add(
                observed,
                &format!("Root-run job: {name} (target unavailable)"),
            );
            return;
        };
        for path in [input, canonical] {
            for (depth, parent) in path.ancestors().enumerate() {
                if depth >= 64 {
                    observed.privileged = true;
                    add(
                        observed,
                        &format!("Root-run job: {name} (path depth unknown)"),
                    );
                    return;
                }
                paths.insert(parent.to_owned());
            }
        }
    }
    if observed.root_inputs.len() >= 1024 {
        observed.complete = false;
        return;
    }
    let bytes: usize = paths.iter().map(|path| path.as_os_str().len()).sum();
    if observed.input_paths + paths.len() > 4096 || observed.input_bytes + bytes > 128 * 1024 {
        observed.privileged = true;
        add(
            observed,
            &format!("Root-run job: {name} (input budget exceeded)"),
        );
        return;
    }
    observed.input_paths += paths.len();
    observed.input_bytes += bytes;
    observed
        .root_inputs
        .push((name, paths.into_iter().collect()));
}

/// Check all direct root inputs in one downgraded child. The kernel accounts
/// for group permissions and ACLs. Unknown access marks each candidate job.
fn root_writes(account: &User, observed: &mut Observation) {
    let candidates = std::mem::take(&mut observed.root_inputs);
    let paths: Vec<_> = candidates
        .iter()
        .flat_map(|(_, paths)| paths.iter().cloned())
        .collect();
    let writable = crate::access_write::writable(account, &paths);
    let mut offset = 0;
    for (name, paths) in candidates {
        if writable.as_ref().is_none_or(|indices| {
            (offset..offset + paths.len()).any(|index| indices.contains(&index))
        }) {
            observed.privileged = true;
            add(
                observed,
                &format!("Root-run job: {name} (input writable or not checked)"),
            );
        }
        offset += paths.len();
    }
}

/// Observe both system cron sources. Missing files are absent, other errors unknown.
fn cron(account: &User, observed: &mut Observation) {
    let mut paths = vec![std::path::PathBuf::from("/etc/crontab")];
    match fs::read_dir("/etc/cron.d") {
        Ok(entries) => {
            for (index, entry) in entries.take(257).enumerate() {
                if index >= 256 {
                    observed.complete = false;
                    break;
                }
                let Ok(entry) = entry else {
                    observed.complete = false;
                    continue;
                };
                if paths.len() > 256 {
                    observed.complete = false;
                    break;
                }
                // Cron ignores dotted backup files and hidden editor files.
                if entry.file_name().to_str().is_none_or(|name| {
                    name.is_empty()
                        || !name
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                }) {
                    continue;
                }
                paths.push(entry.path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => observed.complete = false,
    }
    let uid = account.uid.to_string();
    let mut remaining: usize = 1024 * 1024;
    for path in paths {
        if fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        let Some(text) = cron_text(&path) else {
            observed.complete = false;
            continue;
        };
        let Some(left) = remaining.checked_sub(text.len()) else {
            observed.complete = false;
            break;
        };
        remaining = left;
        let Some(entries) = cron_accounts(&text) else {
            observed.complete = false;
            continue;
        };
        for (line, user) in entries {
            if matches!(user, "root" | "0") {
                let source = text.lines().nth(line - 1).unwrap_or_default().trim();
                let start = if source.starts_with('@') { 2 } else { 6 };
                let command = after_columns(source, start);
                root_job(
                    observed,
                    format!("{}:{line}", path.display()),
                    command.and_then(command_targets),
                );
            }
            if user == account.name || user == uid {
                add(observed, &format!("{}:{line}", path.display()));
            }
        }
    }
}

/// Read root's user crontab from both standard cron implementations. These
/// have no user column; missing spools are absent, read/parse errors unknown.
fn root_crontab(observed: &mut Observation) {
    for path in ["/var/spool/cron/crontabs/root", "/var/spool/cron/root"] {
        let path = Path::new(path);
        if fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        let Some(text) = cron_text(path) else {
            observed.complete = false;
            continue;
        };
        for (line, command) in text.lines().enumerate() {
            let command = command.trim();
            if command.is_empty()
                || command.starts_with('#')
                || command
                    .split_ascii_whitespace()
                    .next()
                    .is_some_and(|word| word.contains('='))
            {
                continue;
            }
            let start = if command.starts_with('@') { 1 } else { 5 };
            let target = after_columns(command, start);
            root_job(
                observed,
                format!("{}:{}", path.display(), line + 1),
                target.and_then(command_targets),
            );
        }
    }
}

/// Parse manager properties in blocks, preserving empty default identities.
fn unit_properties(text: &str) -> Option<Vec<BTreeMap<&str, String>>> {
    let mut units = Vec::new();
    for block in text.trim().split("\n\n") {
        let mut fields: BTreeMap<&str, String> = BTreeMap::new();
        for line in block.lines() {
            let (name, value) = line.split_once('=')?;
            // Oneshot services expose one ExecStart line per command. Keep
            // every direct target without invalidating unrelated unit names.
            if let Some(previous) = fields.get_mut(name) {
                if name != "ExecStart" {
                    return None;
                }
                previous.push(' ');
                previous.push_str(value);
            } else {
                fields.insert(name, value.to_owned());
            }
        }
        let id = fields.get("Id")?;
        if Path::new(id)
            .extension()
            .is_some_and(|extension| extension == "timer")
        {
            fields.entry("User").or_default();
        }
        if !fields.contains_key("User") {
            return None;
        }
        units.push(fields);
    }
    Some(units)
}

/// Ask systemd for installed and live units, then inspect their effective User
/// property in one bounded query. Template definitions are not jobs until they
/// have an instance; instantiated and transient services are in the live list.
fn system_units(account: &User, observed: &mut Observation) {
    let mut names = BTreeSet::new();
    for list in ["list-unit-files", "list-units"] {
        let Some(output) = crate::access_privilege::host_output(
            "systemctl",
            &[
                list,
                "--all",
                "--type=service",
                "--type=timer",
                "--plain",
                "--no-legend",
                "--no-pager",
            ],
        ) else {
            observed.complete = false;
            return;
        };
        for line in output.lines() {
            let Some(name) = line.split_ascii_whitespace().next() else {
                continue;
            };
            if !Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "service" || extension == "timer")
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-.@\\:".contains(&c))
            {
                observed.complete = false;
                return;
            }
            if !name.contains("@.") {
                names.insert(name.to_owned());
            }
            if names.len() > 1024 {
                observed.complete = false;
                return;
            }
        }
    }
    if names.is_empty() {
        observed.complete = false;
        return;
    }
    let mut args = vec![
        "show",
        "--no-pager",
        "--property=Id,User,Triggers,ExecStart,FragmentPath,DropInPaths,LoadState",
        "--",
    ];
    args.extend(names.iter().map(String::as_str));
    let Some(output) = crate::access_privilege::host_output("systemctl", &args) else {
        observed.complete = false;
        return;
    };
    let Some(units) = unit_properties(&output) else {
        observed.complete = false;
        return;
    };
    let uid = account.uid.to_string();
    let matching: BTreeSet<_> = units
        .iter()
        .filter(|unit| unit["User"] == account.name || unit["User"] == uid)
        .map(|unit| unit["Id"].as_str())
        .collect();
    for unit in &units {
        let name = unit["Id"].as_str();
        if matching.contains(name)
            || unit.get("Triggers").is_some_and(|triggers| {
                triggers
                    .split_ascii_whitespace()
                    .any(|target| matching.contains(target))
            })
        {
            add(observed, &format!("system unit {name}"));
        }
        if matches!(unit["User"].as_str(), "" | "root" | "0")
            && unit.get("LoadState").map(String::as_str) != Some("masked")
        {
            let mut inputs = Vec::new();
            let fragment = unit
                .get("FragmentPath")
                .map(String::as_str)
                .unwrap_or_default();
            let dropins = unit
                .get("DropInPaths")
                .map(String::as_str)
                .unwrap_or_default();
            if !fragment.is_empty() {
                inputs.push(PathBuf::from(fragment));
            }
            inputs.extend(dropins.split_ascii_whitespace().map(PathBuf::from));
            let mut valid = !fragment.is_empty();
            if let Some(exec) = unit.get("ExecStart").filter(|exec| !exec.is_empty()) {
                for part in exec.split("argv[]=").skip(1) {
                    let Some(command) = part.split(" ;").next() else {
                        valid = false;
                        continue;
                    };
                    match command_targets(command) {
                        Some(paths) => inputs.extend(paths),
                        None => valid = false,
                    }
                }
                if !exec.contains("argv[]=") {
                    valid = false;
                }
            }
            // A transient root unit has no fragment; its direct ExecStart is
            // still inspectable, but any missing effective inputs fail closed.
            root_job(
                observed,
                format!("system unit {name}"),
                valid.then_some(inputs),
            );
        }
        if unit["User"].contains('%') {
            observed.complete = false;
        }
    }
}

/// Inventory future system work once after session teardown. Uncertainty and
/// any listed job both prevent a clean report, even if no PID currently exists.
pub(crate) fn inspect(account: &User) -> Observation {
    let mut observed = Observation::empty();
    cron(account, &mut observed);
    root_crontab(&mut observed);
    system_units(account, &mut observed);
    root_writes(account, &mut observed);
    if !observed.complete {
        if observed.jobs.len() >= 64 {
            observed.jobs.pop();
        }
        add(
            &mut observed,
            "System jobs: inventory could not be fully checked",
        );
    }
    observed
}

#[cfg(test)]
mod tests {
    //! Scheduler columns must not confuse usernames with command text.
    use super::*;

    /// Both standard and macro schedules retain the account column.
    #[test]
    fn cron_user_columns_and_unknown_lines() {
        let entries =
            cron_accounts("PATH=/bin\n0 1 * * * alice /bin/true\n@reboot 1002 /bin/true\n")
                .unwrap();
        assert_eq!(entries, vec![(2, "alice"), (3, "1002")]);
        assert!(cron_accounts("* * * broken").is_none());
    }

    /// Direct interpreter scripts are checked; shell graphs are unknown.
    #[test]
    fn direct_root_command_targets_are_bounded() {
        assert_eq!(
            command_targets("/bin/sh /home/alice/task").unwrap(),
            vec![PathBuf::from("/bin/sh"), PathBuf::from("/home/alice/task")]
        );
        assert!(command_targets("/bin/sh -c '$TARGET'").is_none());
        assert!(command_targets("cd / && run-parts /etc/cron.daily").is_none());
        assert!(command_targets("/usr/bin/env python3 /home/alice/task").is_none());
    }

    /// Effective empty User means root; incomplete manager blocks are unknown.
    #[test]
    fn manager_blocks_preserve_user_and_timer_target() {
        let units = unit_properties(
            "User=42\nId=job.service\nTriggers=\n\nUser=\nId=job.timer\nTriggers=job.service\n",
        )
        .unwrap();
        assert_eq!(units[0]["User"], "42");
        assert_eq!(units[1]["Triggers"], "job.service");
        assert!(unit_properties("Id=job.service\n").is_none());
    }

    /// Real managers repeat `ExecStart` for oneshot commands. Preserve both
    /// commands and later account jobs; ambiguous identity fields stay unknown.
    #[test]
    fn repeated_oneshot_commands_preserve_inventory() {
        let units = unit_properties(
            "User=\nId=root.service\nExecStart={ argv[]=/bin/true ; }\nExecStart={ argv[]=/home/alice/task ; }\n\nUser=alice\nId=account.service\n",
        ).unwrap();
        assert!(units[0]["ExecStart"].contains("/bin/true"));
        assert!(units[0]["ExecStart"].contains("/home/alice/task"));
        assert_eq!(units[1]["User"], "alice");
        assert!(unit_properties("User=root\nUser=alice\nId=job.service\n").is_none());
    }
}
