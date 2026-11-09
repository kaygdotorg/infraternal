//! Read systemd's effective executable paths and argument vectors for root jobs.
//! `systemctl show` renders argv as whitespace-separated text, losing boundaries
//! and making `@`'s substituted argv[0] look like the executable. D-Bus keeps
//! those fields separate and has already parsed every unit prefix and Exec line.
//!
//! The manager still expands `$NAME` and `${NAME}` when it starts a command.
//! This module performs the same expansion from the manager's environment, the
//! unit's `Environment=` and its `EnvironmentFile=` files, which also count as
//! the unit's inputs: an account that can edit one can change what root runs.
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Variables the manager sets itself when it runs a command. Their values are
/// a process id, a terminal type, a result keyword or a random id, never a
/// file name, so they expand to plain data here. Any other variable that the
/// unit and the manager leave unset may be a runtime path (for example
/// `$STATE_DIRECTORY`), so a command using it stays unknown.
const MANAGER_DATA: &[&str] = &[
    "MAINPID",
    "MANAGERPID",
    "SERVICE_RESULT",
    "EXIT_CODE",
    "EXIT_STATUS",
    "TERM",
    "INVOCATION_ID",
];

/// All lifecycle commands that systemd can execute for a service. Extended
/// properties retain privilege flags, so `+` and `!` also count on User= units.
const COMMANDS: &[&str] = &[
    "ExecConditionEx",
    "ExecStartPreEx",
    "ExecStartEx",
    "ExecStartPostEx",
    "ExecReloadEx",
    "ExecStopEx",
    "ExecStopPostEx",
];

/// Retain known files even when an executable cannot be resolved. Otherwise an
/// unknown shell command could hide an account-writable service fragment.
pub(crate) struct Inputs {
    /// Direct files and executable inputs whose paths are known.
    pub(crate) paths: Vec<PathBuf>,
    /// False if any command or execution context remains unprovable.
    pub(crate) complete: bool,
}

/// Encode a validated unit id using systemd's D-Bus object-path escaping.
fn object_path(name: &str) -> String {
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() {
            path.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(path, "_{byte:02x}");
        }
    }
    path
}

/// Read the manager's own environment once per scan. Every service inherits
/// it, including the default `PATH`. `None` means the manager did not answer.
pub(crate) fn manager_environment() -> Option<Vec<String>> {
    let output = crate::access_privilege::host_output(
        "busctl",
        &[
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "Environment",
        ],
    )?;
    let reply: Value = serde_json::from_str(&output).ok()?;
    if reply.get("type")?.as_str()? != "as" {
        return None;
    }
    reply
        .get("data")?
        .as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect()
}

/// Return direct root command inputs, or unknown on a failed or unfamiliar
/// manager reply. No job is started and no command text is copied to a report.
/// `manager` is [`manager_environment`]'s answer, shared by every unit.
pub(crate) fn inputs(name: &str, root: bool, manager: &[String]) -> Option<Inputs> {
    let path = object_path(name);
    let output = crate::access_privilege::host_output(
        "busctl",
        &[
            "--json=short",
            "call",
            "org.freedesktop.systemd1",
            &path,
            "org.freedesktop.DBus.Properties",
            "GetAll",
            "s",
            "",
        ],
    )?;
    parse(&output, root, name.ends_with(".service"), manager)
}

/// Parse an `EnvironmentFile=` the way the manager does for the simple forms:
/// `KEY=value` lines, `#` and `;` comments, and values wrapped whole in one
/// kind of quote. Escapes, continuations, embedded quotes and `$` return
/// `None`, because a different reading could yield a different path.
fn environment_file(text: &str) -> Option<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        let key = key.trim_end();
        if key.is_empty()
            || key.bytes().next().is_some_and(|c| c.is_ascii_digit())
            || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return None;
        }
        let value = value.trim_start();
        let value = match value.as_bytes() {
            [quote @ (b'"' | b'\''), inner @ .., last] if last == quote => {
                std::str::from_utf8(inner).ok()?
            }
            _ => value,
        };
        if value.contains(['"', '\'', '\\', '$', '`']) {
            return None;
        }
        pairs.push((key.to_owned(), value.to_owned()));
    }
    Some(pairs)
}

/// Read every `EnvironmentFile=` of a unit, in order. A missing file adds
/// nothing (the manager skips an optional one and refuses to start without a
/// required one); any other failure is unknown. Returns the files' variables.
fn environment_files(files: &[(String, bool)]) -> Option<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for (path, _optional) in files {
        let path = Path::new(path);
        if !path.is_absolute() {
            return None;
        }
        match std::fs::metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
            Ok(meta) if !meta.is_file() || meta.len() > 65536 => return None,
            Ok(_) => {}
        }
        let text = std::fs::read_to_string(path).ok()?;
        pairs.extend(environment_file(&text)?);
    }
    Some(pairs)
}

/// Expand variables in one command's arguments as the manager does: a word
/// that is exactly `$NAME` becomes the value split at whitespace (an empty
/// value removes the word), `${NAME}` anywhere becomes the value, and `$$`
/// is a literal `$`. A `$` left in a word after this is shell text, which the
/// resolver treats as unknown. argv[0] is passed through unchanged.
fn expand(argv: &[String], environment: &BTreeMap<String, String>) -> Option<Vec<String>> {
    let value = |name: &str| -> Option<String> {
        if name.bytes().next().is_none_or(|c| c.is_ascii_digit())
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return None;
        }
        match environment.get(name) {
            Some(value) => Some(value.clone()),
            None if MANAGER_DATA.contains(&name) => Some(String::new()),
            None => None,
        }
    };
    let mut out = Vec::with_capacity(argv.len());
    for (index, word) in argv.iter().enumerate() {
        if index == 0 {
            out.push(word.clone());
            continue;
        }
        if let Some(name) = word.strip_prefix('$')
            && !name.starts_with(['{', '$'])
        {
            out.extend(value(name)?.split_whitespace().map(str::to_owned));
            continue;
        }
        let mut expanded = String::with_capacity(word.len());
        let mut rest = word.as_str();
        while let Some(at) = rest.find('$') {
            expanded.push_str(&rest[..at]);
            rest = &rest[at + 1..];
            if let Some(after) = rest.strip_prefix('$') {
                expanded.push('$');
                rest = after;
            } else if let Some(after) = rest.strip_prefix('{') {
                let (name, after) = after.split_once('}')?;
                expanded.push_str(&value(name)?);
                rest = after;
            } else {
                expanded.push('$');
            }
        }
        expanded.push_str(rest);
        out.push(expanded);
    }
    Some(out)
}

/// Validate typed properties before resolving arguments. Unsupported namespaces
/// and variables we cannot expand remain unknown; host paths would be misleading.
/// `manager` is the manager's own environment, which every unit inherits.
fn parse(output: &str, root: bool, service: bool, manager: &[String]) -> Option<Inputs> {
    let reply: Value = serde_json::from_str(output).ok()?;
    if reply.get("type")?.as_str()? != "a{sv}" {
        return None;
    }
    let data = reply.get("data")?.as_array()?;
    if data.len() != 1 {
        return None;
    }
    let fields = data.first()?.as_object()?;
    // Future executable properties must not quietly become unchecked root
    // commands. Legacy properties mirror the extended vectors used below.
    let mut complete = true;
    for (name, property) in fields {
        if name.starts_with("Exec")
            && property.get("type")?.as_str()?.starts_with("a(sas")
            && !COMMANDS
                .iter()
                .any(|known| name == *known || Some(name.as_str()) == known.strip_suffix("Ex"))
        {
            complete = false;
        }
    }
    let string = |name: &str| fields.get(name)?.get("data")?.as_str();
    // The unit's environment files are inputs whatever their contents.
    let files: Vec<(String, bool)> = match fields.get("EnvironmentFiles") {
        None => Vec::new(),
        Some(property) => {
            if property.get("type")?.as_str()? != "a(sb)" {
                return None;
            }
            property
                .get("data")?
                .as_array()?
                .iter()
                .map(|entry| Some((entry.get(0)?.as_str()?.to_owned(), entry.get(1)?.as_bool()?)))
                .collect::<Option<_>>()?
        }
    };
    // Later sources win, as in the manager: its own environment, then
    // Environment=, then each EnvironmentFile= in order.
    let environment: Option<BTreeMap<String, String>> = (|| {
        let unit: Vec<&str> = match fields.get("Environment") {
            None => Vec::new(),
            Some(property) => property
                .get("data")?
                .as_array()?
                .iter()
                .map(Value::as_str)
                .collect::<Option<_>>()?,
        };
        let mut environment = BTreeMap::new();
        for entry in manager.iter().map(String::as_str).chain(unit) {
            let (key, value) = entry.split_once('=')?;
            environment.insert(key.to_owned(), value.to_owned());
        }
        environment.extend(environment_files(&files)?);
        Some(environment)
    })();
    let commands = |setting: &str| -> Option<Vec<PathBuf>> {
        let environment = environment.as_ref()?;
        let directory = if service {
            string("WorkingDirectory")?
        } else {
            ""
        };
        let directory = if directory.is_empty() {
            Path::new("/")
        } else {
            Path::new(directory)
        };
        let search: Vec<&str> = environment
            .get("PATH")
            .map(String::as_str)
            .into_iter()
            .collect();
        let context = crate::access_command::Context::new(vec![directory.to_owned()], &search)?;
        let user = if service { string("User")? } else { "" };
        if service && root != matches!(user, "" | "root" | "0") {
            return None;
        }
        let mut paths = Vec::new();
        let property = fields.get(setting)?;
        if property.get("type")?.as_str()? != "a(sasasttttuii)" {
            return None;
        }
        for command in property.get("data")?.as_array()? {
            let command = command.as_array()?;
            let executable = command.first()?.as_str()?;
            let argv: Vec<String> = command
                .get(1)?
                .as_array()?
                .iter()
                .map(|word| word.as_str().map(str::to_owned))
                .collect::<Option<_>>()?;
            let flags: Vec<&str> = command
                .get(2)?
                .as_array()?
                .iter()
                .map(Value::as_str)
                .collect::<Option<_>>()?;
            if flags.iter().any(|flag| {
                !matches!(
                    *flag,
                    "ignore-failure" | "privileged" | "no-setuid" | "ambient" | "no-env-expand"
                )
            }) {
                return None;
            }
            if root
                || flags
                    .iter()
                    .any(|flag| matches!(*flag, "privileged" | "no-setuid" | "ambient"))
            {
                if !matches!(string("RootDirectory")?, "" | "/") || !string("RootImage")?.is_empty()
                {
                    return None;
                }
                // Host path probes cannot prove the identity of an executable
                // replaced by a service-specific mount or extension image.
                for property in [
                    "BindPaths",
                    "BindReadOnlyPaths",
                    "TemporaryFileSystem",
                    "MountImages",
                    "ExtensionImages",
                    "ExtensionDirectories",
                ] {
                    if let Some(value) = fields.get(property)
                        && !value.get("data")?.as_array()?.is_empty()
                    {
                        return None;
                    }
                }
                let argv = if flags.contains(&"no-env-expand") {
                    argv
                } else {
                    expand(&argv, environment)?
                };
                paths.extend(crate::access_command::arguments(
                    executable, &argv, &context,
                )?);
            }
        }
        Some(paths)
    };
    let mut paths = Vec::new();
    for setting in COMMANDS.iter().filter(|_| service) {
        match commands(setting) {
            Some(inputs) => paths.extend(inputs),
            None => complete = false,
        }
    }
    if root || !complete || !paths.is_empty() {
        let fragment = string("FragmentPath")?;
        if fragment.is_empty() {
            return None;
        }
        paths.push(PathBuf::from(fragment));
        paths.extend(files.iter().map(|(path, _)| PathBuf::from(path)));
        paths.extend(
            fields
                .get("DropInPaths")?
                .get("data")?
                .as_array()?
                .iter()
                .map(|path| path.as_str().map(PathBuf::from))
                .collect::<Option<Vec<_>>>()?,
        );
    }
    Some(Inputs { paths, complete })
}

#[cfg(test)]
mod tests {
    //! Typed manager output must preserve executables and lifecycle commands.
    use super::*;

    /// Build a small real D-Bus-shaped property reply without manager metadata.
    fn reply(setting: &str, path: &str, argv: &[&str]) -> String {
        let mut fields = serde_json::Map::new();
        fields.insert(
            "FragmentPath".into(),
            serde_json::json!({"type":"s", "data":"/usr/lib/systemd/system/job.service"}),
        );
        fields.insert(
            "DropInPaths".into(),
            serde_json::json!({"type":"as", "data":[]}),
        );
        for name in ["WorkingDirectory", "RootDirectory", "RootImage", "User"] {
            fields.insert(name.into(), serde_json::json!({"type":"s", "data":""}));
        }
        for name in COMMANDS {
            fields.insert(
                (*name).into(),
                serde_json::json!({"type":"a(sasasttttuii)", "data":[]}),
            );
        }
        fields[setting]["data"] = serde_json::json!([[path, argv, [], 0, 0, 0, 0, 0, 0, 0]]);
        serde_json::json!({"type":"a{sv}", "data":[fields]}).to_string()
    }

    /// Every lifecycle field matters, and @ cannot hide the executable in argv0.
    #[test]
    fn manager_executable_and_all_lifecycle_inputs_are_retained() {
        for setting in COMMANDS {
            let paths = parse(
                &reply(setting, "/home/alice/task", &["/bin/true"]),
                true,
                true,
                &[],
            )
            .unwrap();
            assert!(paths.complete);
            assert!(
                paths.paths.contains(&PathBuf::from("/home/alice/task")),
                "{setting}"
            );
        }
        let paths = parse(
            &reply("ExecStartEx", "/bin/sh", &["/bin/sh", "/home/alice/a b"]),
            true,
            true,
            &[],
        )
        .unwrap();
        assert!(paths.complete);
        assert!(paths.paths.contains(&PathBuf::from("/home/alice/a b")));
        assert_eq!(
            object_path("job@one.service"),
            "/org/freedesktop/systemd1/unit/job_40one_2eservice"
        );
        assert!(parse("{}", true, true, &[]).is_none());
    }
    /// Turn string literals into an owned argument vector.
    fn words(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    /// Expansion mirrors the manager; runtime paths and defaults stay unknown.
    #[test]
    fn manager_variables_expand_like_the_manager() {
        let environment: BTreeMap<String, String> = [
            ("JOB".to_owned(), "/srv/job".to_owned()),
            ("OPTS".to_owned(), "-a  -b".to_owned()),
            ("EMPTY".to_owned(), String::new()),
        ]
        .into();
        assert_eq!(
            expand(
                &words(&["sh", "${JOB}", "$OPTS", "$EMPTY", "--pid=${MAINPID}"]),
                &environment
            )
            .unwrap(),
            words(&["sh", "/srv/job", "-a", "-b", "--pid="])
        );
        assert!(expand(&words(&["sh", "$STATE_DIRECTORY"]), &environment).is_none());
        assert!(expand(&words(&["sh", "${JOB:-/x}"]), &environment).is_none());
        assert_eq!(
            expand(&words(&["sh", "-c", "echo $$x"]), &environment).unwrap()[2],
            "echo $x"
        );
    }

    /// Plain environment files parse; anything a different reader could
    /// split differently is unknown.
    #[test]
    fn environment_files_parse_only_unambiguous_lines() {
        assert_eq!(
            environment_file("# c\n; c\nSSHD_OPTS=\nA = \"x y\"\n").unwrap(),
            vec![
                ("SSHD_OPTS".to_owned(), String::new()),
                ("A".to_owned(), "x y".to_owned())
            ]
        );
        for text in ["export A=1\n", "A=\"x\\\"y\"\n", "A=$B\n", "A=x\\\n"] {
            assert!(environment_file(text).is_none(), "{text:?}");
        }
    }

    /// `Environment=` feeds expansion, and every `EnvironmentFile=` is an input.
    #[test]
    fn unit_environment_reaches_commands_and_inputs() {
        let mut reply: Value =
            serde_json::from_str(&reply("ExecStartEx", "/bin/sh", &["/bin/sh", "${JOB}"])).unwrap();
        let fields = reply["data"][0].as_object_mut().unwrap();
        fields.insert(
            "Environment".into(),
            serde_json::json!({"type":"as", "data":["JOB=/home/alice/task"]}),
        );
        fields.insert(
            "EnvironmentFiles".into(),
            serde_json::json!({"type":"a(sb)", "data":[["/nonexistent/ifrv-env", true]]}),
        );
        let inputs = parse(&reply.to_string(), true, true, &[]).unwrap();
        assert!(inputs.complete);
        assert!(inputs.paths.contains(&PathBuf::from("/home/alice/task")));
        assert!(
            inputs
                .paths
                .contains(&PathBuf::from("/nonexistent/ifrv-env"))
        );
    }
}
