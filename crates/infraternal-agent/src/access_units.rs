//! Read systemd's effective executable paths and argument vectors for root jobs.
//! `systemctl show` renders argv as whitespace-separated text, losing boundaries
//! and making `@`'s substituted argv[0] look like the executable. D-Bus keeps
//! those fields separate and has already parsed every unit prefix and Exec line.
use serde_json::Value;
use std::path::{Path, PathBuf};

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

/// Return direct root command inputs, or unknown on a failed or unfamiliar
/// manager reply. No job is started and no command text is copied to a report.
pub(crate) fn inputs(name: &str, root: bool) -> Option<Inputs> {
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
    parse(&output, root, name.ends_with(".service"))
}

/// Validate typed properties before resolving arguments. Unsupported namespaces
/// and environment expansion remain unknown; host paths would be misleading.
fn parse(output: &str, root: bool, service: bool) -> Option<Inputs> {
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
    let commands = |setting: &str| -> Option<Vec<PathBuf>> {
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
        let context = crate::access_command::Context::new(vec![directory.to_owned()], &[])?;
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
        )
        .unwrap();
        assert!(paths.complete);
        assert!(paths.paths.contains(&PathBuf::from("/home/alice/a b")));
        assert_eq!(
            object_path("job@one.service"),
            "/org/freedesktop/systemd1/unit/job_40one_2eservice"
        );
        assert!(parse("{}", true, true).is_none());
    }
}
