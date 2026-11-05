//! Reads kernel executable identities and manager-resolved services before host installation (#338).
//!
//! Unit-file text is not a command: prefixes, environment substitution and escapes
//! belong to systemd. We ask its manager for executable identities, skip inert
//! stock units, and refuse identified CLI images or unresolved references to them.
use super::{SERVICE_NAME, refused};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs, io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
};

/// Recognize the two CLI spellings and the named binaries distributed with an installation.
fn image_name(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().as_encoded_bytes();
    let name = name.strip_suffix(b" (deleted)").unwrap_or(name);
    name == b"infra" || name.starts_with(b"infraternal") || name.starts_with(b"memfd:infraternal")
}

/// One pinned known build; hashes are lazy and reused across a host scan.
struct KnownImage {
    /// Keep the inode alive even if an upgrade replaces its pathname.
    file: fs::File,
    /// Size avoids hashing unrelated programs; device/inode is the cheap identity check.
    metadata: fs::Metadata,
    /// Hash only when a differently named file has the same byte length.
    digest: Option<[u8; 32]>,
}

/// Compare against at most four locally known builds, without scanning arbitrary directories.
/// A renamed foreign build with no known local reference cannot be identified this way.
/// Dynamic shell commands and external scripts still need runtime process inspection.
struct KnownImages(
    /// Bounded set of pinned descriptors and their reusable identity hashes.
    Vec<KnownImage>,
);

impl KnownImages {
    /// Pin this executable and the usual installed copies once per inspection pass.
    fn new() -> io::Result<Self> {
        let mut images = Vec::new();
        for path in [
            "/proc/self/exe",
            "/usr/local/bin/infraternal",
            "/var/lib/infraternal/bin/infraternal",
            "/usr/bin/infraternal",
        ] {
            let file = match fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NONBLOCK)
                .open(path)
            {
                Ok(file) => file,
                Err(error) if path == "/proc/self/exe" => return Err(error),
                Err(_) => continue,
            };
            let metadata = file.metadata()?;
            if metadata.is_file()
                && !images.iter().any(|image: &KnownImage| {
                    (image.metadata.dev(), image.metadata.ino()) == (metadata.dev(), metadata.ino())
                })
            {
                images.push(KnownImage {
                    file,
                    metadata,
                    digest: None,
                });
            }
        }
        Ok(Self(images))
    }

    /// Names and inodes are cheap; hash only size-matched unknown executable descriptors.
    fn matches(&mut self, path: &Path, file: &mut fs::File) -> io::Result<bool> {
        use std::io::{Seek, SeekFrom};
        let metadata = file.metadata()?;
        if image_name(path)
            || fs::canonicalize(path).is_ok_and(|canonical| image_name(&canonical))
            || self.0.iter().any(|image| {
                (metadata.dev(), metadata.ino()) == (image.metadata.dev(), image.metadata.ino())
            })
        {
            return Ok(true);
        }
        let mut digest = None;
        for image in self
            .0
            .iter_mut()
            .filter(|image| image.metadata.len() == metadata.len())
        {
            if image.digest.is_none() {
                image.file.seek(SeekFrom::Start(0))?;
                image.digest = Some(super::hash_stream(&mut image.file, None)?);
            }
            if digest.is_none() {
                file.seek(SeekFrom::Start(0))?;
                digest = Some(super::hash_stream(file, None)?);
            }
            if digest == image.digest {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Refuse a running server or infraternal agent using its kernel image, never its chosen argv[0].
pub(super) fn running_install(recovery: &super::journal::Snapshot) -> io::Result<()> {
    processes(Path::new("/proc"), recovery)
}

/// Inspect a process namespace; a pinned executable plus a second stat detects exec races.
fn processes(root: &Path, recovery: &super::journal::Snapshot) -> io::Result<()> {
    let mut images = KnownImages::new()?;
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
        let mut image = match fs::File::open(&executable) {
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
        if !images.matches(&path, &mut image)? {
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

/// Recognize whole program or path components without interpreting unit-file commands.
/// Keep punctuation inside basenames so infrastructure and my-infra-helper are
/// unrelated. Strip one leading systemd ignore-failure sigil from a bare token;
/// this preserves the unresolved -infra command hint without matching /opt/-infra.
fn mentions_install(value: &str) -> bool {
    value
        .split(|character: char| {
            character.is_whitespace() || "\"';|&()={}[]:@+!".contains(character)
        })
        .any(|word| {
            Path::new(word.strip_prefix('-').unwrap_or(word))
                .components()
                .any(|component| {
                    matches!(
                        component.as_os_str().to_str(),
                        Some("infra" | "infraternal")
                    )
                })
        })
}

/// Report an installed command without exposing its arguments or environment values.
fn installed(unit: &OsStr) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "Service {} invokes infraternal. Use its existing server or infraternal agent; inspect that service before retrying infraternal up on a fresh host.",
            unit.to_string_lossy()
        ),
    )
}

/// Search bare executables on systemd's configured or compiled-in path.
/// Environment PATH belongs to the child process and cannot change this lookup.
fn search_path<'a>(output: &'a str, default: &'a str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix("ExecSearchPath="))
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
}

/// Resolve a manager path or bare executable name using only absolute search directories.
fn executable_path(program: &str, search: &str) -> Option<std::path::PathBuf> {
    let program = Path::new(program);
    if program.is_absolute() {
        return Some(program.to_owned());
    }
    if program.components().count() != 1 {
        return None;
    }
    std::env::split_paths(search)
        .filter(|path| path.is_absolute())
        .map(|path| path.join(program))
        .find(|path| {
            fs::metadata(path)
                .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
        })
}

/// Read the default compiled into systemd once per scan, with the documented standard path as fallback.
fn default_search_path() -> String {
    let candidates = ["/usr/bin/systemd-path", "/bin/systemd-path"];
    if let Ok(tool) = super::super::trusted_tool(&candidates, super::super::Failure::NoSystemd)
        && let Ok(value) = manager(&tool, &[OsStr::new("search-binaries-default")])
        && !value.trim().is_empty()
    {
        return value.trim().to_owned();
    }
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned()
}

/// Inspect literal arguments of a small explicit set of exec wrappers.
/// env, shells, nice, setpriv, ionice, chrt, taskset and stdbuf may launch another
/// program. Recognize its distributed name or an absolute known-build identity.
/// This is a conservative scan, not shell evaluation or wrapper option parsing;
/// dynamic commands and external scripts still need runtime process inspection.
fn wrapper_mentions_install(
    program: &str,
    arguments: &str,
    images: &mut KnownImages,
) -> io::Result<bool> {
    let wrapper = Path::new(program).file_name().unwrap_or_default();
    if ![
        "env", "sh", "bash", "dash", "zsh", "ksh", "fish", "nice", "setpriv", "ionice", "chrt",
        "taskset", "stdbuf",
    ]
    .iter()
    .any(|name| wrapper == OsStr::new(name))
    {
        return Ok(false);
    }
    for word in arguments
        .split(|character: char| character.is_whitespace() || "\"';|&()=".contains(character))
    {
        let path = Path::new(word);
        if image_name(path) {
            return Ok(true);
        }
        if path.is_absolute()
            && let Ok(mut file) = fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NONBLOCK)
                .open(path)
            && file.metadata()?.is_file()
            && images.matches(path, &mut file)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Ignore inert stock units and classify executable identity rather than every resolution failure.
/// Only unresolved commands mentioning infraternal refuse; missing unrelated programs do not.
fn resolved_service(
    unit: &OsStr,
    output: &str,
    default: &str,
    images: &mut KnownImages,
) -> io::Result<()> {
    let relevant = mentions_install(&unit.to_string_lossy()) || mentions_install(output);
    let state = output
        .lines()
        .find_map(|line| line.strip_prefix("LoadState="));
    match state {
        Some("masked" | "not-found") => return Ok(()),
        Some("loaded") => {}
        _ => {
            return if relevant {
                Err(unresolved(unit))
            } else {
                Ok(())
            };
        }
    }
    // Bare names use the manager's exec search path, independently of the child environment.
    let search = search_path(output, default);
    let commands = output
        .lines()
        .filter_map(|line| {
            [
                "ExecStart=",
                "ExecStartPre=",
                "ExecStartPost=",
                "ExecCondition=",
            ]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        })
        .collect::<Vec<_>>()
        .join("\n");
    for record in commands.split("{ path=").skip(1) {
        let Some((program, arguments)) = record.split_once(" ; ") else {
            if relevant {
                return Err(unresolved(unit));
            }
            continue;
        };
        if image_name(Path::new(program)) || wrapper_mentions_install(program, arguments, images)? {
            return Err(installed(unit));
        }
        let Some(path) = executable_path(program, search) else {
            if relevant {
                return Err(unresolved(unit));
            }
            continue;
        };
        let mut image = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(image) if image.metadata()?.is_file() => image,
            _ if relevant => return Err(unresolved(unit)),
            _ => continue,
        };
        if images.matches(&path, &mut image)? {
            return Err(installed(unit));
        }
    }
    if !commands.is_empty() && !commands.contains("{ path=") && relevant {
        return Err(unresolved(unit));
    }
    Ok(())
}

/// Inspect only an unresolved unit's text for identity hints; never parse commands from it.
fn unit_mentions_install(root: &Path, unit: &OsStr) -> bool {
    if mentions_install(&unit.to_string_lossy()) {
        return true;
    }
    [
        "etc/systemd/system",
        "run/systemd/system",
        "usr/lib/systemd/system",
        "lib/systemd/system",
    ]
    .iter()
    .any(|directory| {
        use std::io::Read as _;
        let Ok(file) = fs::File::open(root.join(directory).join(unit)) else {
            return false;
        };
        let mut bytes = Vec::new();
        file.take(1024 * 1024).read_to_end(&mut bytes).is_ok()
            && mentions_install(&String::from_utf8_lossy(&bytes))
    })
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
    let default_search = default_search_path();
    let mut images = KnownImages::new()?;
    for unit in units {
        if unit.as_encoded_bytes().ends_with(b"@.service") {
            continue;
        }
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
                OsStr::new("--property=ExecStartPre"),
                OsStr::new("--property=ExecStartPost"),
                OsStr::new("--property=ExecCondition"),
                OsStr::new("--property=ExecSearchPath"),
                OsStr::new("--"),
                &unit,
            ],
        );
        match output {
            Ok(output) => resolved_service(&unit, &output, &default_search, &mut images)?,
            Err(_) if unit_mentions_install(root, &unit) => return Err(unresolved(&unit)),
            Err(_) => {}
        }
    }
    Ok(())
}

/// Kernel identity controls ensure an argv[0] override neither hides nor invents a host daemon.
#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise manager classification with the standard executable search directories.
    fn resolved_service(unit: &OsStr, output: &str) -> io::Result<()> {
        super::resolved_service(
            unit,
            output,
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            &mut KnownImages::new()?,
        )
    }

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

    /// Manager identity catches renamed links without mistaking unrelated argument text for an executable.
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
            resolved_service(unit, value).unwrap();
        }
    }
    /// Ordinary manager states and unrelated missing programs cannot block a fresh host.
    #[test]
    fn stock_service_states_and_search_names_are_accepted() {
        for value in [
            "LoadState=masked\n",
            "LoadState=not-found\n",
            "LoadState=loaded\nExecStart=\n",
            "LoadState=loaded\nExecStart={ path=true ; argv[]=true ; }\n",
            "LoadState=loaded\nExecStart={ path=unrelated-missing-command ; argv[]=unrelated-missing-command ; }\n",
        ] {
            assert!(
                resolved_service(OsStr::new("stock.service"), value).is_ok(),
                "stock command refused: {value}"
            );
        }
    }

    /// Remove only units created by this real-manager probe and refresh their manager state.
    struct UserUnits {
        /// Unique unit files under the current user's manager runtime directory.
        paths: Vec<std::path::PathBuf>,
    }
    impl Drop for UserUnits {
        /// Cleanup also runs when a manager assertion fails.
        fn drop(&mut self) {
            for path in &self.paths {
                let _ = fs::remove_file(path);
            }
            let _ = Command::new("/usr/bin/systemctl")
                .args(["--user", "daemon-reload"])
                .status();
        }
    }

    /// Real systemd output must accept stock states and search bare commands without false refusal.
    #[test]
    #[ignore = "requires a live systemd user manager; run explicitly as its ordinary user"]
    fn real_user_manager_accepts_stock_and_bare_commands() {
        let runtime =
            std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").expect("user runtime"));
        let units = runtime.join("systemd/user");
        fs::create_dir_all(&units).unwrap();
        let prefix = format!("j198-{}", uuid::Uuid::new_v4());
        let fixture = crate::restart_binary::fixture::Directory::new();
        let visible = fixture.0.join("etc/systemd/system");
        fs::create_dir_all(&visible).unwrap();
        let mut guard = UserUnits { paths: Vec::new() };
        for (suffix, contents) in [
            ("bare.service", "[Service]\nType=oneshot\nExecStart=true\n"),
            (
                "empty.service",
                "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStartPre=/usr/bin/true\n",
            ),
            ("template@.service", "[Service]\nExecStart=/usr/bin/true\n"),
        ] {
            let name = format!("{prefix}-{suffix}");
            let path = units.join(&name);
            fs::write(&path, contents).unwrap();
            guard.paths.push(path.clone());
            std::os::unix::fs::symlink(&path, visible.join(name)).unwrap();
        }
        let masked = units.join(format!("{prefix}-masked.service"));
        std::os::unix::fs::symlink("/dev/null", &masked).unwrap();
        guard.paths.push(masked.clone());
        std::os::unix::fs::symlink(&masked, visible.join(masked.file_name().unwrap())).unwrap();
        fs::write(
            visible.join(format!("{prefix}-not-found.service")),
            b"[Unit]\n",
        )
        .unwrap();
        assert!(
            Command::new("/usr/bin/systemctl")
                .args(["--user", "daemon-reload"])
                .status()
                .unwrap()
                .success()
        );
        let manager = fixture.0.join("systemctl");
        crate::test_executable::write(
            &manager,
            format!(
                "#!/bin/sh\nexport XDG_RUNTIME_DIR='{}'\nexport DBUS_SESSION_BUS_ADDRESS='unix:path={}/bus'\nexec /usr/bin/systemctl --user \"$@\"\n",
                runtime.display(),
                runtime.display()
            ),
            0o700,
        );
        let result = installed_services(
            &fixture.0,
            &manager,
            &super::super::journal::Snapshot::default(),
        );
        println!("real user manager stock commands: {result:?}");
        assert!(
            result.is_ok(),
            "normal user manager commands refused: {result:?}"
        );
    }

    /// The manager's executable search is independent of the environment passed to the child.
    #[test]
    fn manager_search_path_ignores_unit_environment() {
        let fixture = crate::restart_binary::fixture::Directory::new();
        let directory = fixture.0.join("private binaries");
        fs::create_dir(&directory).unwrap();
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), directory.join("python3"))
            .unwrap();
        let hidden = "LoadState=loaded\nEnvironment=PATH=/nonexistent\nExecStart={ path=python3 ; argv[]=python3 server ; }\n";
        assert!(
            super::resolved_service(
                OsStr::new("custom.service"),
                hidden,
                directory.to_str().unwrap(),
                &mut KnownImages::new().unwrap(),
            )
            .is_err(),
            "child PATH hid the manager's inode alias"
        );
        let unrelated = format!(
            "LoadState=loaded\nEnvironment=\"PATH={}\"\nExecStart={{ path=python3 ; argv[]=python3 server ; }}\n",
            directory.display()
        );
        assert!(
            super::resolved_service(
                OsStr::new("custom.service"),
                &unrelated,
                "/usr/bin:/bin",
                &mut KnownImages::new().unwrap(),
            )
            .is_ok(),
            "child PATH invented an installed executable"
        );
        let explicit = format!(
            "LoadState=loaded\nEnvironment=PATH=/nonexistent\nExecSearchPath={}\nExecStart={{ path=python3 ; argv[]=python3 server ; }}\n",
            directory.display()
        );
        assert!(resolved_service(OsStr::new("custom.service"), &explicit).is_err());
    }

    /// Common literal exec wrappers must expose named binaries and renamed inode aliases.
    #[test]
    fn scheduling_and_privilege_wrappers_expose_installs() {
        let fixture = crate::restart_binary::fixture::Directory::new();
        let alias = fixture.0.join("control");
        fs::hard_link(std::env::current_exe().unwrap(), &alias).unwrap();
        for (wrapper, options) in [
            ("nice", "-n5"),
            ("setpriv", "--reuid=0"),
            ("ionice", "-c3"),
            ("chrt", "-f 1"),
            ("taskset", "-c 0"),
            ("stdbuf", "-oL"),
        ] {
            for image in ["/opt/infra", alias.to_str().unwrap()] {
                let value = format!(
                    "LoadState=loaded\nExecStart={{ path=/usr/bin/{wrapper} ; argv[]=/usr/bin/{wrapper} {options} {image} server ; }}\n"
                );
                assert!(
                    resolved_service(OsStr::new("custom.service"), &value).is_err(),
                    "wrapper {wrapper} hid {image}"
                );
            }
            let benign = format!(
                "LoadState=loaded\nExecStart={{ path=/usr/bin/{wrapper} ; argv[]=/usr/bin/{wrapper} {options} /usr/bin/true ; }}\n"
            );
            resolved_service(OsStr::new("custom.service"), &benign).unwrap();
        }
    }

    /// Unrelated infrastructure text cannot make an unresolved command look like our program.
    #[test]
    fn unresolved_references_require_whole_program_components() {
        for value in [
            "LoadState=loaded\nExecStart={ path=/opt/infrastructure-tools/missing ; argv[]=missing --x ; }\n",
            "LoadState=loaded\nEnvironment=LABEL=infrastructure\nExecStart={ path=/opt/missing ; argv[]=missing ; }\n",
            "LoadState=error\nDescription=an infrasonic monitor\n",
            "LoadState=loaded\nExecStart={ path=/opt/my-infra-helper/missing ; argv[]=missing ; }\n",
            "LoadState=loaded\nExecStart={ path=/opt/-infra/missing ; argv[]=missing ; }\n",
        ] {
            assert!(
                resolved_service(OsStr::new("stock.service"), value).is_ok(),
                "unrelated text refused: {value}"
            );
        }
        for value in [
            "LoadState=loaded\nExecStart={ path=/srv/infra/missing ; argv[]=missing ; }\n",
            "LoadState=loaded\nExecStart={ path=/srv/infraternal/missing ; argv[]=missing ; }\n",
            "LoadState=error\nExecStart=infra server\n",
            "LoadState=error\nExecStart=-infra server\n",
            "LoadState=error\nExecStart=/opt/infraternal server\n",
        ] {
            assert!(
                resolved_service(OsStr::new("custom.service"), value).is_err(),
                "literal reference missed: {value}"
            );
        }
    }
    /// Stopped wrappers and secondary startup commands cannot conceal our executable.
    #[test]
    fn indirect_service_commands_are_refused() {
        for value in [
            "LoadState=loaded\nExecStart={ path=/usr/bin/env ; argv[]=/usr/bin/env infra server ; }\n",
            "LoadState=loaded\nExecStart={ path=/bin/sh ; argv[]=/bin/sh -c exec /opt/infra server ; }\n",
            "LoadState=loaded\nExecStart={ path=/usr/bin/true ; argv[]=true ; }\nExecStartPre={ path=/opt/infra ; argv[]=infra server ; }\n",
            "LoadState=loaded\nExecStart={ path=/usr/bin/true ; argv[]=true ; }\nExecStartPost={ path=/opt/infraternal ; argv[]=infraternal server ; }\n",
        ] {
            assert!(
                resolved_service(OsStr::new("custom.service"), value).is_err(),
                "hidden install accepted: {value}"
            );
        }
        let fixture = crate::restart_binary::fixture::Directory::new();
        let named = fixture.0.join("infraternal-old");
        fs::write(&named, b"different fixture build").unwrap();
        let alias = fixture.0.join("ctl");
        std::os::unix::fs::symlink(&named, &alias).unwrap();
        assert!(
            resolved_service(
                OsStr::new("custom.service"),
                &format!(
                    "LoadState=loaded\nExecStart={{ path={} ; argv[]=ctl server ; }}\n",
                    alias.display()
                )
            )
            .is_err()
        );
    }

    /// Real manager serialization must expose direct, wrapped and secondary infraternal commands.
    #[test]
    #[ignore = "requires a live systemd user manager; run explicitly as its ordinary user"]
    fn real_user_manager_refuses_stopped_installs() {
        let runtime =
            std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").expect("user runtime"));
        let units = runtime.join("systemd/user");
        fs::create_dir_all(&units).unwrap();
        let name = format!("j198-{}.service", uuid::Uuid::new_v4());
        let path = units.join(&name);
        let _guard = UserUnits {
            paths: vec![path.clone()],
        };
        let fixture = crate::restart_binary::fixture::Directory::new();
        let visible = fixture.0.join("etc/systemd/system");
        fs::create_dir_all(&visible).unwrap();
        std::os::unix::fs::symlink(&path, visible.join(&name)).unwrap();
        let manager = fixture.0.join("systemctl");
        crate::test_executable::write(
            &manager,
            format!(
                "#!/bin/sh\nexport XDG_RUNTIME_DIR='{}'\nexport DBUS_SESSION_BUS_ADDRESS='unix:path={}/bus'\nexec /usr/bin/systemctl --user \"$@\"\n",
                runtime.display(),
                runtime.display()
            ),
            0o700,
        );
        for (index, (body, refuse)) in [
            ("ExecStart=/usr/bin/true", false),
            (
                "ExecStart=@/opt/infraternal harmless server --data /srv/private",
                true,
            ),
            ("ExecStart=/opt/infra \\x73erver --data /srv/private", true),
            (
                "Environment=MODE=server\nExecStart=/opt/infra ${MODE} --data /srv/private",
                true,
            ),
            ("ExecStart=infra server", true),
            ("ExecStart=-infra server", true),
            ("ExecStart=/opt/infra \\\n server --data /srv/private", true),
            ("ExecStart=/usr/bin/env infra server", true),
            ("ExecStart=/bin/sh -c \"exec /opt/infra server\"", true),
            (
                "ExecStartPre=/opt/infra server\nExecStart=/usr/bin/true",
                true,
            ),
            (
                "ExecStart=/usr/bin/true\nExecStartPost=/opt/infraternal server",
                true,
            ),
            ("ExecStart=/usr/bin/true", false),
        ]
        .into_iter()
        .enumerate()
        {
            fs::write(&path, format!("[Service]\nType=oneshot\n{body}\n")).unwrap();
            assert!(
                Command::new("/usr/bin/systemctl")
                    .args(["--user", "daemon-reload"])
                    .status()
                    .unwrap()
                    .success()
            );
            let result = installed_services(
                &fixture.0,
                &manager,
                &super::super::journal::Snapshot::default(),
            );
            println!(
                "real user manager form {index}: refused={}",
                result.is_err()
            );
            assert_eq!(result.is_err(), refuse, "manager form {index}: {result:?}");
        }
    }
    /// A byte-identical copy retains CLI identity even when its inode and name change.
    #[test]
    fn renamed_copy_of_known_build_is_detected() {
        let fixture = crate::restart_binary::fixture::Directory::new();
        let copy = fixture.0.join("control");
        fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
        let namespace = fixture.0.join("proc/123");
        fs::create_dir_all(&namespace).unwrap();
        std::os::unix::fs::symlink(&copy, namespace.join("exe")).unwrap();
        fs::write(namespace.join("cmdline"), b"harmless\0server\0").unwrap();
        assert!(
            processes(
                &fixture.0.join("proc"),
                &super::super::journal::Snapshot::default()
            )
            .is_err(),
            "renamed copy of running build was missed"
        );
        assert!(
            resolved_service(
                OsStr::new("custom.service"),
                &format!(
                    "LoadState=loaded\nExecStart={{ path={} ; argv[]=control server ; }}\n",
                    copy.display()
                )
            )
            .is_err(),
            "renamed installed copy was missed"
        );
    }
}
