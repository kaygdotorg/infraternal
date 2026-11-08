//! D367 observes system jobs that can write as a revoked account later.
//! System cron and the system manager's effective service identities are read,
//! including dormant services, timers and transient units. Nothing is stopped,
//! edited or deleted. Unknown inventory is reported, never treated as empty.
use nix::unistd::User;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read as _,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

/// One bounded observation of future account work.
#[derive(Default)]
pub(crate) struct Observation {
    /// Printable source names only; command arguments may contain credentials.
    pub(crate) jobs: Vec<String>,
    /// False on unavailable, malformed or over-budget inventory.
    pub(crate) complete: bool,
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

/// Observe both system cron sources. Missing files are absent, other errors unknown.
fn cron(account: &User, observed: &mut Observation) {
    let mut paths = vec![std::path::PathBuf::from("/etc/crontab")];
    match fs::read_dir("/etc/cron.d") {
        Ok(entries) => {
            for entry in entries.take(257) {
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
        let Some(entries) = cron_accounts(&text) else {
            observed.complete = false;
            continue;
        };
        for (line, user) in entries {
            if user == account.name || user == uid {
                add(observed, &format!("{}:{line}", path.display()));
            }
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
    let mut args = vec!["show", "--no-pager", "--property=Id,User,Triggers", "--"];
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
    system_units(account, &mut observed);
    if !observed.complete {
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
