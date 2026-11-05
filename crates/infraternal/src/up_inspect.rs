//! Reads kernel executable identities and manager-resolved services before host installation (#338).
//!
//! Unit-file text is not a command: prefixes, environment substitution and escapes
//! belong to systemd. We ask its manager for the executable and conservatively
//! refuse commands whose resolved identity cannot be inspected unambiguously.
use super::{SERVICE_NAME, refused};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs, io,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
};

/// Recognize supported executable names and renamed links to this exact running image.
fn install_image(path: &Path, metadata: &fs::Metadata, current: &fs::Metadata) -> bool {
    let name = path.file_name().unwrap_or_default().as_encoded_bytes();
    let name = name.strip_suffix(b" (deleted)").unwrap_or(name);
    name == b"infra"
        || name.starts_with(b"infraternal")
        || name.starts_with(b"memfd:infraternal")
        || (metadata.dev(), metadata.ino()) == (current.dev(), current.ino())
}

/// Refuse a running server or infraternal agent using its kernel image, never its chosen argv[0].
pub(super) fn running_install(recovery: &super::journal::Snapshot) -> io::Result<()> {
    processes(Path::new("/proc"), recovery)
}

/// Inspect a process namespace; a pinned executable plus a second stat detects exec races.
fn processes(root: &Path, recovery: &super::journal::Snapshot) -> io::Result<()> {
    let current = fs::metadata("/proc/self/exe")?;
    for process in fs::read_dir(root)? {
        let process = process?;
        if !process
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let executable = process.path().join("exe");
        let image = match fs::File::open(&executable) {
            Ok(image) => image,
            // Exited processes and kernel threads have no executable to classify.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(refused(
                    "Could not inspect a running executable. Retry sudo infraternal up with permission to inspect this host's processes.",
                ));
            }
        };
        let metadata = image.metadata()?;
        let path = match fs::read_link(&executable) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !install_image(&path, &metadata, &current) {
            continue;
        }
        let arguments = match fs::read(process.path().join("cmdline")) {
            Ok(arguments) => arguments,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let after = match fs::metadata(&executable) {
            Ok(after) => after,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if (metadata.dev(), metadata.ino()) != (after.dev(), after.ino()) {
            return Err(refused(
                "A running executable changed during inspection. Retry infraternal up after the other installation finishes.",
            ));
        }
        match command(&arguments) {
            Some(b"server") => {
                return Err(refused(
                    "An infraternal server is running on this host. Use its embedded infraternal agent; run infraternal up on a different host.",
                ));
            }
            Some(b"agent")
                if recovery.created.iter().any(|entry| {
                    entry.path.ends_with("var/lib/infraternal/bin/infraternal")
                        && entry.identity == (metadata.dev(), metadata.ino())
                        && recovery.owns(&entry.path)
                }) => {}
            Some(b"agent") => {
                return Err(refused(
                    "An infraternal agent is already running on this host. Manage the existing service instead of running infraternal up.",
                ));
            }
            None => {
                return Err(refused(
                    "Could not resolve a running infraternal command. Inspect the existing process before retrying infraternal up.",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Read the host subcommand only after the kernel executable has established CLI identity.
pub(super) fn command(arguments: &[u8]) -> Option<&[u8]> {
    let word = arguments
        .split(|byte| *byte == 0)
        .skip(1)
        .find(|word| !word.is_empty() && *word != b"--json")?;
    // An unknown leading option may take arguments before the host subcommand.
    // Do not treat that option as proof that this executable is not a server.
    (!word.starts_with(b"-")).then_some(word)
}

/// Explain which installed unit needs inspection without printing its arguments or environment.
fn unresolved(unit: &OsStr) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "Could not resolve the command for service {} through systemd. Inspect that service or restore manager access before retrying infraternal up.",
            unit.to_string_lossy()
        ),
    )
}

/// Read a manager property with locale-stable formatting and no inherited terminal input.
fn manager(systemctl: &Path, arguments: &[&OsStr]) -> io::Result<String> {
    let output = Command::new(systemctl)
        .args(arguments)
        .env_clear()
        .env("PATH", super::super::HELPER_PATH)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(refused(
            "Could not inspect systemd services. Restore manager access before retrying infraternal up.",
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| refused("The service manager returned an unreadable command. Inspect its configuration before retrying infraternal up."))
}

/// Include generated and transient services as well as the unit files visible on disk.
fn manager_units(systemctl: &Path, units: &mut BTreeSet<OsString>) -> io::Result<()> {
    for list in ["list-unit-files", "list-units"] {
        let output = manager(
            systemctl,
            &[
                OsStr::new(list),
                OsStr::new("--type=service"),
                OsStr::new("--all"),
                OsStr::new("--no-legend"),
                OsStr::new("--no-pager"),
                OsStr::new("--plain"),
                OsStr::new("--full"),
            ],
        )?;
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            let name = line
                .split_whitespace()
                .next()
                .ok_or_else(|| unresolved(OsStr::new("unknown")))?;
            if !name.ends_with(".service") || name.contains('/') {
                return Err(unresolved(OsStr::new(name)));
            }
            units.insert(OsString::from(name));
        }
    }
    Ok(())
}

/// Inspect only the manager's resolved path field; its human-readable argv is deliberately unused.
///
/// Accept a narrow, unambiguous serialization of absolute executable paths. Other
/// output is a refusal, not a second implementation of unit-file syntax. Any service
/// invoking this CLI is refused because argv[0] overrides make the formatted argv
/// unsuitable for proving that an installed command cannot launch a server.
fn resolved_service(unit: &OsStr, output: &str) -> io::Result<()> {
    let mut states = output
        .lines()
        .filter_map(|line| line.strip_prefix("LoadState="));
    let state = states.next().ok_or_else(|| unresolved(unit))?;
    if states.next().is_some() {
        return Err(unresolved(unit));
    }
    match state {
        "loaded" => {}
        _ => return Err(unresolved(unit)),
    }
    let commands = output
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
        .ok_or_else(|| unresolved(unit))?;
    let current = fs::metadata("/proc/self/exe")?;
    let mut count = 0;
    for record in commands.split("{ path=").skip(1) {
        let path = record
            .split_once(" ; ")
            .map(|(path, _)| path)
            .ok_or_else(|| unresolved(unit))?;
        if !path.starts_with('/')
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._+-:@".contains(&byte))
        {
            return Err(unresolved(unit));
        }
        let path = Path::new(path);
        let metadata = fs::metadata(path).map_err(|_| unresolved(unit))?;
        if !metadata.is_file() {
            return Err(unresolved(unit));
        }
        if install_image(path, &metadata, &current) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Service {} invokes infraternal. Use its existing server or infraternal agent; inspect that service before retrying infraternal up on a fresh host.",
                    unit.to_string_lossy()
                ),
            ));
        }
        count += 1;
    }
    if count == 0 {
        return Err(unresolved(unit));
    }
    Ok(())
}

/// Resolve installed services through the manager, including custom unit and data paths.
pub(super) fn installed_services(
    root: &Path,
    systemctl: &Path,
    recovery: &super::journal::Snapshot,
) -> io::Result<()> {
    let mut units = BTreeSet::new();
    for relative in [
        "etc/systemd/system",
        "run/systemd/system",
        "usr/lib/systemd/system",
        "lib/systemd/system",
    ] {
        let entries = match fs::read_dir(root.join(relative)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            if recovery.owns(&entry.path()) {
                continue;
            }
            if entry.file_name() == SERVICE_NAME {
                return Err(refused(
                    "An infraternal agent service is already installed. Manage that service instead of running infraternal up.",
                ));
            }
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "service")
            {
                units.insert(entry.file_name());
            }
        }
    }
    if root == Path::new("/") {
        manager_units(systemctl, &mut units)?;
    }
    for unit in units {
        if unit == SERVICE_NAME && recovery.owns(&root.join("etc/systemd/system").join(&unit)) {
            continue;
        }
        if unit == SERVICE_NAME {
            return Err(refused(
                "An infraternal agent service is already known to systemd. Manage that service instead of running infraternal up.",
            ));
        }
        let output = manager(
            systemctl,
            &[
                OsStr::new("show"),
                OsStr::new("--no-pager"),
                OsStr::new("--property=LoadState"),
                OsStr::new("--property=ExecStart"),
                OsStr::new("--"),
                &unit,
            ],
        )
        .map_err(|_| unresolved(&unit))?;
        resolved_service(&unit, &output)?;
    }
    Ok(())
}

/// Kernel identity controls ensure an argv[0] override neither hides nor invents a host daemon.
#[cfg(test)]
mod tests {
    use super::*;

    /// A private proc-shaped directory exercises actual executable descriptors and inode comparison.
    #[test]
    fn kernel_image_identifies_overridden_argv_zero() {
        let root = std::env::temp_dir().join(format!("up-proc-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("123")).unwrap();
        std::os::unix::fs::symlink("/proc/self/exe", root.join("123/exe")).unwrap();
        fs::write(
            root.join("123/cmdline"),
            b"harmless\0--json\0server\0--data\0/srv/private\0",
        )
        .unwrap();
        assert!(
            processes(&root, &super::super::journal::Snapshot::default())
                .unwrap_err()
                .to_string()
                .contains("server is running")
        );
        fs::write(root.join("123/cmdline"), b"harmless\0ssh\0host\0server\0").unwrap();
        processes(&root, &super::super::journal::Snapshot::default()).unwrap();
        fs::write(
            root.join("123/cmdline"),
            b"harmless\0--unknown-output\0value\0server\0",
        )
        .unwrap();
        assert!(
            processes(&root, &super::super::journal::Snapshot::default())
                .unwrap_err()
                .to_string()
                .contains("Could not resolve")
        );
        fs::remove_file(root.join("123/exe")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/true", root.join("123/exe")).unwrap();
        fs::write(root.join("123/cmdline"), b"infraternal\0server\0").unwrap();
        processes(&root, &super::super::journal::Snapshot::default()).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    /// Manager path identity catches renamed executables and refuses missing or ambiguous commands.
    #[test]
    fn manager_resolves_executable_without_trusting_argv() {
        let unit = OsStr::new("custom.service");
        let image = std::env::current_exe().unwrap();
        assert!(
            resolved_service(
                unit,
                &format!(
                    "LoadState=loaded\nExecStart={{ path={} ; argv[]=harmless server ; }}\n",
                    image.display()
                )
            )
            .is_err()
        );
        resolved_service(
            unit,
            "LoadState=loaded\nExecStart={ path=/usr/bin/true ; argv[]=infra server ; }\n",
        )
        .unwrap();
        for value in [
            "",
            "LoadState=not-found\n",
            "LoadState=loaded\nExecStart=\n",
            "LoadState=loaded\nExecStart={ path=/opt/missing ; argv[]=server ; }\n",
        ] {
            assert!(resolved_service(unit, value).is_err());
        }
    }
}
