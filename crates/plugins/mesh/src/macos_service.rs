//! Owns launchd lifecycle and the fixed, root-owned system Mesh service.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const LABEL: &str = "org.infraternal.mesh";
const PLIST: &str = "/Library/LaunchDaemons/org.infraternal.mesh.plist";
const PLIST_DIRECTORY: &str = "/Library/LaunchDaemons";
const LAUNCHCTL: &str = "/bin/launchctl";
const SUDO: &str = "/usr/bin/sudo";
const DATA_DIRECTORY: &str = "/var/lib/infraternal/agent";
/// The system service's mesh state directory; `agent join` clears it when no `--state` is given.
pub const STATE_DIRECTORY: &str = "/var/lib/infraternal/state";

/// Public launchd state; it contains no enrollment or key material.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Status {
    /// Whether launchd currently has the system job loaded.
    pub loaded: bool,
    /// Whether launchd reports a live service process.
    pub running: bool,
    /// The service process identifier when running.
    pub pid: Option<u32>,
}

/// Handle `mesh up|down|status` without accepting caller-selected paths or commands.
///
/// Ordinary `up` and `down` calls require an already installed root-owned CLI,
/// try the fixed operation through noninteractive sudo first, and prompt only
/// when sudoers does not already authorize it. The privileged branch accepts
/// only the current action and uses fixed paths.
/// # Errors
/// Refuses an unsafe executable, failed administrator authorization or launchd error.
pub fn control(
    action: &str,
    system_service: bool,
    executable: &Path,
) -> io::Result<Option<Status>> {
    if system_service {
        require_root()?;
        let executable = trusted_executable(executable)?;
        match action {
            "up" => install(&executable)?,
            "down" => stop()?,
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        }
        return Ok(None);
    }
    match action {
        "status" => status().map(Some),
        "up" | "down" => {
            let executable = trusted_executable(executable)?;
            elevate(action, &executable)?;
            status().map(Some)
        }
        _ => Err(io::ErrorKind::InvalidInput.into()),
    }
}

fn elevate(action: &str, executable: &Path) -> io::Result<()> {
    let run_operation = || {
        Command::new(SUDO)
            .args(["-n", "--"])
            .arg(executable)
            .args(["mesh", action, "--system-service"])
            .status()
    };
    let is_authorized = || {
        Command::new(SUDO)
            .args(["-n", "-l", "--"])
            .arg(executable)
            .args(["mesh", action, "--system-service"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };
    run_privileged_operation(run_operation, is_authorized, || {
        Command::new(SUDO).arg("-v").status()
    })
}

fn run_privileged_operation(
    mut operation: impl FnMut() -> io::Result<std::process::ExitStatus>,
    mut is_authorized: impl FnMut() -> io::Result<std::process::ExitStatus>,
    mut prompt: impl FnMut() -> io::Result<std::process::ExitStatus>,
) -> io::Result<()> {
    if operation()?.success() {
        return Ok(());
    }
    // The fixed command may have failed after sudo authorized it. Do not prompt
    // for a service or launchd failure; only prompt when sudo -n -l denies it.
    if is_authorized()?.success() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if !prompt()?.success() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if operation()?.success() {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

fn require_root() -> io::Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

fn trusted_executable(path: &Path) -> io::Result<PathBuf> {
    let path = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !trusted_binary_metadata(
        metadata.uid(),
        metadata.mode(),
        metadata.file_type().is_file(),
    ) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(path)
}

fn trusted_binary_metadata(uid: u32, mode: u32, regular_file: bool) -> bool {
    uid == 0 && regular_file && mode & 0o022 == 0
}

fn install(executable: &Path) -> io::Result<()> {
    require_root()?;
    ensure_root_directory(DATA_DIRECTORY, true)?;
    ensure_root_directory(STATE_DIRECTORY, true)?;
    ensure_plist_directory()?;
    let plist = render_plist(executable)?;
    write_plist(&plist)?;
    let target = format!("system/{LABEL}");
    launchctl_checked(&["enable".into(), target.clone()])?;
    if !status()?.loaded {
        launchctl_checked(&["bootstrap".into(), "system".into(), PLIST.into()])?;
    }
    launchctl_checked(&["kickstart".into(), "-k".into(), target])?;
    Ok(())
}

fn stop() -> io::Result<()> {
    require_root()?;
    let target = format!("system/{LABEL}");
    launchctl_checked(&["disable".into(), target.clone()])?;
    if status()?.loaded {
        launchctl_checked(&["bootout".into(), target])?;
    }
    Ok(())
}

fn status() -> io::Result<Status> {
    let target = format!("system/{LABEL}");
    let output = launchctl(&["print".into(), target])?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if reason.contains("could not find service") || reason.contains("service not found") {
            return Ok(Status::default());
        }
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let running = listing.lines().any(|line| line.trim() == "state = running");
    let pid = listing.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .and_then(|pid| pid.parse().ok())
    });
    Ok(Status {
        loaded: true,
        running,
        pid,
    })
}

fn launchctl(arguments: &[String]) -> io::Result<Output> {
    Command::new(LAUNCHCTL).args(arguments).output()
}

fn launchctl_checked(arguments: &[String]) -> io::Result<()> {
    checked_launchctl(launchctl(arguments)?)
}

fn checked_launchctl(output: Output) -> io::Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other("launchctl operation failed"))
    }
}

fn ensure_root_directory(path: &str, create: bool) -> io::Result<()> {
    let path = Path::new(path);
    if create && !path.exists() {
        fs::create_dir_all(path)?;
    }
    let canonical = fs::canonicalize(path)?;
    for parent in canonical.ancestors() {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let metadata = fs::symlink_metadata(&canonical)?;
    if metadata.mode() & 0o077 != 0 {
        fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn ensure_plist_directory() -> io::Result<()> {
    let path = Path::new(PLIST_DIRECTORY);
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn write_plist(contents: &str) -> io::Result<()> {
    let path = Path::new(PLIST);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            require_owned_plist(&metadata)?;
            if fs::read_to_string(path)? == contents {
                return Ok(());
            }
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = path.with_file_name(format!("org.infraternal.mesh.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(PLIST_DIRECTORY)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn require_owned_plist(metadata: &Metadata) -> io::Result<()> {
    if metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

fn render_plist(executable: &Path) -> io::Result<String> {
    if !executable.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let executable = xml_escape(&executable.to_string_lossy());
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>{LABEL}</string>\n\
         <key>ProgramArguments</key><array>\n\
         <string>{executable}</string><string>agent</string><string>run</string>\n\
         <string>--data</string><string>{DATA_DIRECTORY}</string>\n\
         <string>--state</string><string>{STATE_DIRECTORY}</string>\n\
         </array>\n\
         <key>RunAtLoad</key><true/>\n\
         <key>KeepAlive</key><true/>\n\
         <key>ThrottleInterval</key><integer>5</integer>\n\
         <key>ProcessType</key><string>Background</string>\n\
         <key>StandardOutPath</key><string>/dev/null</string>\n\
         <key>StandardErrorPath</key><string>/dev/null</string>\n\
         </dict></plist>\n"
    ))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::{checked_launchctl, render_plist, trusted_binary_metadata};
    use std::path::Path;
    use std::{os::unix::process::ExitStatusExt, process::Output};

    #[test]
    fn launchctl_nonzero_exit_is_not_reported_as_success() {
        let output = Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: b"launchctl refused the operation".to_vec(),
        };
        assert_eq!(
            checked_launchctl(output)
                .expect_err("failed launchctl mutation must fail")
                .kind(),
            std::io::ErrorKind::Other
        );
    }

    #[test]
    fn launch_daemon_uses_fixed_root_agent_arguments() {
        let plist = render_plist(Path::new("/var/lib/infraternal/bin/infraternal"))
            .expect("render launch daemon plist");
        for value in [
            "org.infraternal.mesh",
            "/var/lib/infraternal/bin/infraternal",
            "agent",
            "run",
            "--data",
            "/var/lib/infraternal/agent",
            "--state",
            "/var/lib/infraternal/state",
            "<true/>",
        ] {
            assert!(plist.contains(value), "missing {value:?} in {plist}");
        }
        assert!(!plist.contains("--fd"));
    }

    #[test]
    fn launch_daemon_escapes_executable_path_for_xml() {
        let plist = render_plist(Path::new("/var/lib/infraternal/bin/a&b"))
            .expect("render launch daemon plist");
        assert!(plist.contains("a&amp;b"));
        assert!(!plist.contains("a&b"));
    }

    #[test]
    fn elevation_requires_a_root_owned_non_writable_regular_binary() {
        assert!(trusted_binary_metadata(0, 0o100_755, true));
        assert!(!trusted_binary_metadata(0, 0o100_775, true));
        assert!(!trusted_binary_metadata(501, 0o100_755, true));
        assert!(!trusted_binary_metadata(0, 0o120_777, false));
    }

    #[test]
    fn an_authorized_noninteractive_operation_skips_the_password_prompt() {
        let mut operations = 0;
        let mut authorization_checks = 0;
        let mut prompts = 0;
        super::run_privileged_operation(
            || {
                operations += 1;
                Ok(std::process::ExitStatus::from_raw(0))
            },
            || {
                authorization_checks += 1;
                Ok(std::process::ExitStatus::from_raw(0))
            },
            || {
                prompts += 1;
                Ok(std::process::ExitStatus::from_raw(0))
            },
        )
        .expect("the noninteractive operation is already authorized");

        assert_eq!(operations, 1);
        assert_eq!(authorization_checks, 0);
        assert_eq!(prompts, 0);
    }

    #[test]
    fn a_failed_authorized_operation_does_not_prompt_or_retry() {
        let mut operations = 0;
        let mut authorization_checks = 0;
        let mut prompts = 0;
        let result = super::run_privileged_operation(
            || {
                operations += 1;
                Ok(std::process::ExitStatus::from_raw(256))
            },
            || {
                authorization_checks += 1;
                Ok(std::process::ExitStatus::from_raw(0))
            },
            || {
                prompts += 1;
                Ok(std::process::ExitStatus::from_raw(0))
            },
        );

        assert_eq!(
            result
                .expect_err("service failure remains a failure")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(operations, 1);
        assert_eq!(authorization_checks, 1);
        assert_eq!(prompts, 0);
    }

    #[test]
    fn a_denied_noninteractive_operation_prompts_then_retries_once() {
        let mut statuses = [
            std::process::ExitStatus::from_raw(256),
            std::process::ExitStatus::from_raw(0),
        ]
        .into_iter();
        let mut operations = 0;
        let mut authorization_checks = 0;
        let mut prompts = 0;
        super::run_privileged_operation(
            || {
                operations += 1;
                Ok(statuses.next().expect("one first call and one retry"))
            },
            || {
                authorization_checks += 1;
                Ok(std::process::ExitStatus::from_raw(256))
            },
            || {
                prompts += 1;
                Ok(std::process::ExitStatus::from_raw(0))
            },
        )
        .expect("the prompted retry succeeds");

        assert_eq!(operations, 2);
        assert_eq!(authorization_checks, 1);
        assert_eq!(prompts, 1);
    }
}
