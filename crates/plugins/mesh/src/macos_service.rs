//! Owns launchd lifecycle and the fixed, root-owned system Mesh service.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
};

use crate::macos_user_mode::{self as names, legacy};
use infraternal_plugin_api::elevation_prompt::ElevationPrompt;

/// The system service's launchd label.
pub const LABEL: &str = names::DAEMON_LABEL;
/// The system service's property list.
pub const PLIST: &str = names::DAEMON_PLIST;

/// One launchd job and property list a root-mode install can have: the current names, or the
/// ones a build before the move to `kayg.infraternal` wrote (#580).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Daemon {
    /// The launchd label.
    label: &'static str,
    /// The property list path.
    plist: &'static str,
}

/// The names this build writes.
const CURRENT: Daemon = Daemon {
    label: LABEL,
    plist: PLIST,
};
/// The names older builds wrote. They are only ever stopped and removed, never written.
const LEGACY: Daemon = Daemon {
    label: legacy::DAEMON_LABEL,
    plist: legacy::DAEMON_PLIST,
};
const PLIST_DIRECTORY: &str = "/Library/LaunchDaemons";
const LAUNCHCTL: &str = "/bin/launchctl";
const SUDO: &str = "/usr/bin/sudo";
const DATA_DIRECTORY: &str = "/var/lib/infraternal/agent";
/// The system service's mesh state directory.
pub const STATE_DIRECTORY: &str = "/var/lib/infraternal/state";
/// Data directory of device-approved system installs (D395).
pub const MACHINE_BASE: &str = "/Library/Application Support/infraternal";
/// Root-owned binary published by the device-approved installer.
pub const MACHINE_BINARY: &str = "/Library/Application Support/infraternal/bin/infraternal";
/// Private enrollment for the device-approved system service.
pub const MACHINE_DATA: &str = "/Library/Application Support/infraternal/agent";
/// Mesh and local control state for the device-approved system service.
pub const MACHINE_STATE: &str = "/Library/Application Support/infraternal/state";
/// Records the host and whether its installer created the short PATH alias.
pub const MACHINE_OWNER: &str = ".machine-owner";
/// Canonical PATH link for a device-approved root install.
const MACHINE_LINK: &str = "/usr/local/bin/infraternal";
/// Private child entry used only by the authenticated uninstall handler.
const REMOVE_HANDOFF: &str = "--macos-remove-after-reply";
/// Private system state that survives replacement of the machine directory.
const LIFECYCLE_DIRECTORY: &str = "/Library/Application Support/.infraternal-lifecycle";

/// Holds the system-wide lock until publication, rollback or retirement finishes.
pub struct MachineLock {
    /// Keep the locked descriptor open, including while launchctl runs.
    _file: File,
}

impl MachineLock {
    /// Serialize launchd and machine path changes across root helpers.
    ///
    /// # Errors
    /// Refuses unsafe filesystem ownership or an unavailable lock.
    pub fn acquire() -> io::Result<Self> {
        require_root()?;
        let directory = Path::new(LIFECYCLE_DIRECTORY);
        let parent = directory.parent().ok_or(io::ErrorKind::InvalidInput)?;
        require_root_directories(parent)?;
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(directory.join("lock"))?;
        require_owned_plist(&file.metadata()?)?;
        // Keep this inode across runs. Unlinking a live lock would let another
        // helper open a second inode and enter while the first still owns it.
        file.lock()?;
        Ok(Self { _file: file })
    }

    /// Publish or stop the fixed launchd service while holding the lifecycle lock.
    ///
    /// # Errors
    /// Refuses an unsafe executable or failed launchd operation.
    pub fn set_service(&self, action: &str, executable: &Path) -> io::Result<()> {
        let executable = trusted_executable(executable)?;
        match action {
            "up" => install(&executable),
            "down" => stop(),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
}

/// Publish the ownership receipt before launchd can accept any removal request.
///
/// # Errors
/// Refuses another receipt at the same name or an incomplete disk write.
pub fn record_installation(host: &str, alias_created: bool) -> io::Result<()> {
    require_root()?;
    if !valid_host(host) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let receipt = Path::new(MACHINE_BASE).join(MACHINE_OWNER);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(receipt)?;
    writeln!(file, "{host} {}", u8::from(alias_created))?;
    file.sync_all()
}

/// Inspect the exact device-approved install before any destructive action.
///
/// # Errors
/// Refuses a foreign, altered or unsafe install, or a different host identity.
pub fn validate_installation(host: &str) -> io::Result<bool> {
    let (_, alias_created) = installed_identity(host)?;
    let binary = trusted_executable(Path::new(MACHINE_BINARY))?;
    if binary != Path::new(MACHINE_BINARY) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if owned_machine_plist()?.is_none() {
        return Err(io::ErrorKind::NotFound.into());
    }
    Ok(alias_created)
}

/// Read the recorded enrollment and its directory identity, independent of cleanup progress.
fn installed_identity(host: &str) -> io::Result<((u64, u64), bool)> {
    if !valid_host(host) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let base = Path::new(MACHINE_BASE);
    require_root_directories(base)?;
    let metadata = fs::symlink_metadata(base)?;
    let receipt = base.join(MACHINE_OWNER);
    require_owned_plist(&fs::symlink_metadata(&receipt)?)?;
    let mut contents = String::new();
    File::open(receipt)?
        .take(36)
        .read_to_string(&mut contents)?;
    let alias = receipt_alias(&contents, host).ok_or(io::ErrorKind::PermissionDenied)?;
    Ok(((metadata.dev(), metadata.ino()), alias))
}

/// Find the install's property list, under the current or the old name, and check it.
///
/// `None` is an already retired step. A plist that is not exactly what this code renders for
/// the machine binary under that name is refused, so a foreign file is never adopted.
fn owned_machine_plist() -> io::Result<Option<Daemon>> {
    ensure_plist_directory()?;
    for daemon in [CURRENT, LEGACY] {
        let plist = Path::new(daemon.plist);
        match fs::symlink_metadata(plist) {
            Ok(metadata) => require_owned_plist(&metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        let expected = render_plist_for(daemon.label, Path::new(MACHINE_BINARY))?;
        let mut actual = String::new();
        File::open(plist)?
            .take(expected.len() as u64 + 1)
            .read_to_string(&mut actual)?;
        if actual != expected {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        return Ok(Some(daemon));
    }
    Ok(None)
}

/// Read alias ownership only from a receipt for the exact enrolled host.
fn receipt_alias(receipt: &str, host: &str) -> Option<bool> {
    let (recorded, alias) = receipt.split_once(' ')?;
    if recorded != host {
        return None;
    }
    match alias {
        "1\n" => Some(true),
        "0\n" => Some(false),
        _ => None,
    }
}

/// Start an independent child that waits for the accepted reply before stopping launchd.
///
/// The service manager reaps the service's process group on bootout. A new
/// process group lets this child finish removing the stopped installation.
///
/// # Errors
/// Refuses an unowned installation or a child that cannot be started.
pub fn prepare_removal(host: &str) -> io::Result<Child> {
    validate_installation(host)?;
    Command::new(MACHINE_BINARY)
        .arg(REMOVE_HANDOFF)
        .arg(host)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Handle a checked local removal or an authenticated after-reply child invocation.
#[must_use]
pub fn remove_if_requested() -> Option<std::process::ExitCode> {
    let mut arguments = std::env::args_os().skip(1);
    let action = arguments.next()?;
    let waits = action == REMOVE_HANDOFF;
    if !waits && action != "--bootstrap-uninstall" {
        return None;
    }
    let Some(host) = arguments
        .next()
        .and_then(|arg| arg.into_string().ok())
        .filter(|host| valid_host(host) && arguments.next().is_none())
    else {
        return Some(std::process::ExitCode::FAILURE);
    };
    if waits {
        let mut armed = [0];
        if std::io::stdin().read_exact(&mut armed).is_err() || armed != [1] {
            return Some(std::process::ExitCode::FAILURE);
        }
    }
    Some(match remove_installation(&host) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "Could not remove the owned infraternal installation ({:?}).",
                error.kind()
            );
            std::process::ExitCode::FAILURE
        }
    })
}

/// Accept the same lowercase UUID form used in removal receipts.
fn valid_host(host: &str) -> bool {
    host.len() == 32
        && host
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Stop the live utun owner before retiring only the approved install's files.
fn remove_installation(host: &str) -> io::Result<()> {
    let _lock = MachineLock::acquire()?;
    if !valid_host(host) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let lifecycle = Path::new(LIFECYCLE_DIRECTORY);
    let retired = lifecycle.join(host);
    match fs::symlink_metadata(&retired) {
        // Only the verified rename below can publish this host-specific name.
        // Its receipt may already be gone after an interrupted directory walk.
        Ok(metadata) if metadata.is_dir() && metadata.uid() == 0 => {
            return fs::remove_dir_all(retired);
        }
        Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let identity = installed_identity(host)?;
    let verify = || -> io::Result<()> {
        if installed_identity(host)? == identity {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    };
    let binary = Path::new(MACHINE_BINARY);
    let owned = owned_machine_plist()?;
    if trusted_executable(binary)? != binary
        || (owned.is_none() && (status_of(CURRENT)?.loaded || status_of(LEGACY)?.loaded))
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    verify()?;
    stop()?;
    verify()?;
    remove_command_links(identity.1)?;
    verify()?;
    if let Some(daemon) = owned_machine_plist()? {
        fs::remove_file(daemon.plist)?;
        File::open(PLIST_DIRECTORY)?.sync_all()?;
    }
    verify()?;
    // Keep the receipt at the live path until every shared resource is gone.
    // Once renamed, deletion can resume without touching any replacement.
    let base = Path::new(MACHINE_BASE);
    fs::rename(base, &retired)?;
    File::open(lifecycle)?.sync_all()?;
    File::open(base.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()?;
    fs::remove_dir_all(retired)
}

/// Remove owned links in their trusted PATH directory and tolerate completed unlinks.
fn remove_command_links(alias_created: bool) -> io::Result<()> {
    let link = Path::new(MACHINE_LINK);
    let parent = link.parent().ok_or(io::ErrorKind::InvalidInput)?;
    match require_root_directories(parent) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    }
    let present = match fs::symlink_metadata(link) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && fs::read_link(link)? == Path::new(MACHINE_BINARY) =>
        {
            true
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if alias_created {
        infraternal_plugin_api::cli_alias::remove(link, 0)?;
    }
    if present {
        fs::remove_file(link)?;
    }
    File::open(parent)?.sync_all()
}

/// The mesh state an `agent join` into `data` must forget, if any (#265, J162 F4).
///
/// A join replaces the enrolment in `data` only. The service's state belongs to
/// the service's enrolment, so it is forgotten only when the join wrote the
/// service's own data directory. A join into another directory (a test
/// identity, say) forgets only an explicit `--state` of its own, never the
/// service's. When this skips a join that did re-enrol the service (an unusual
/// spelling of its path), the enrolment binding catches the mismatch at the
/// service's next start, so skipping is the safe side.
#[must_use]
pub fn join_state_to_forget(data: &Path, state: Option<&Path>) -> Option<PathBuf> {
    let service_state = Path::new(STATE_DIRECTORY);
    let target = state.unwrap_or(service_state);
    if same_directory(data, Path::new(DATA_DIRECTORY)) || !same_directory(target, service_state) {
        Some(target.to_path_buf())
    } else {
        None
    }
}

/// Compare directories after resolving links (`/var` is `/private/var` on macOS).
fn same_directory(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left.components().eq(right.components()),
    }
}

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
    json_output: bool,
) -> io::Result<Option<Status>> {
    if system_service {
        MachineLock::acquire()?.set_service(action, executable)?;
        return Ok(None);
    }
    match action {
        "status" => status().map(Some),
        "up" | "down" => {
            let executable = trusted_executable(executable)?;
            elevate(action, &executable, json_output)?;
            status().map(Some)
        }
        _ => Err(io::ErrorKind::InvalidInput.into()),
    }
}

/// Select the elevation explanation for a privileged macOS mesh service action.
fn elevation_prompt_for_action(action: &str) -> Option<ElevationPrompt> {
    match action {
        "up" => Some(ElevationPrompt::MacosMeshServiceUp),
        "down" => Some(ElevationPrompt::MacosMeshServiceDown),
        _ => None,
    }
}

fn elevate(action: &str, executable: &Path, json_output: bool) -> io::Result<()> {
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
        if let Some(prompt) = elevation_prompt_for_action(action) {
            prompt.print_to_stderr(json_output);
        }
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

/// Require a root-owned executable whose directory and loaded libraries are trusted.
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
    require_root_directories(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
    // A root-owned file can still make dyld load a user's library (J162 F2, #265).
    crate::macos_image::check_file(&path)?;
    Ok(path)
}

/// Verify each component of an absolute directory without following symlinks.
fn require_root_directories(path: &Path) -> io::Result<()> {
    for parent in path.ancestors() {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(())
}

fn trusted_binary_metadata(uid: u32, mode: u32, regular_file: bool) -> bool {
    uid == 0 && regular_file && mode & 0o022 == 0
}

/// Enable the trusted system service and add the short CLI name beside its image.
fn install(executable: &Path) -> io::Result<()> {
    require_root()?;
    if !infraternal_plugin_api::cli_alias::install(executable, 0)? {
        eprintln!("infraternal: skipped infra; an existing path belongs to another command.");
    }
    let (data, state) = service_paths(executable);
    ensure_root_directory(data, true)?;
    ensure_root_directory(state, true)?;
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

/// Stops the system Mesh service, under either name, and removes its managed DNS resolver files.
fn stop() -> io::Result<()> {
    require_root()?;
    #[cfg(feature = "mesh-dns")]
    crate::dns_integration::DnsIntegration::default().remove()?;
    stop_job(CURRENT)?;
    // A job of an older build is stopped only when it is there; nothing is disabled for a
    // label that was never installed.
    if status_of(LEGACY)?.loaded {
        stop_job(LEGACY)?;
    }
    Ok(())
}

/// Disable and unload one launchd job.
fn stop_job(daemon: Daemon) -> io::Result<()> {
    let target = format!("system/{}", daemon.label);
    launchctl_checked(&["disable".into(), target.clone()])?;
    if status_of(daemon)?.loaded {
        launchctl_checked(&["bootout".into(), target])?;
    }
    Ok(())
}

/// What launchd reports for the current service name.
fn status() -> io::Result<Status> {
    status_of(CURRENT)
}

/// What launchd reports for one job.
fn status_of(daemon: Daemon) -> io::Result<Status> {
    let target = format!("system/{}", daemon.label);
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

/// Runs `launchctl` and turns a non-zero exit status into an I/O error.
fn launchctl_checked(arguments: &[String]) -> io::Result<()> {
    checked_launchctl(&launchctl(arguments)?)
}

/// Converts a `launchctl` command result into `Ok(())` when it succeeded.
fn checked_launchctl(output: &Output) -> io::Result<()> {
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

/// Write the current service's property list atomically; an identical one already there is fine.
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
    let temporary = path.with_file_name(format!("{LABEL}.{}.tmp", std::process::id()));
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

/// Keep manually configured legacy services on their original paths.
fn service_paths(executable: &Path) -> (&'static str, &'static str) {
    if executable == Path::new(MACHINE_BINARY) {
        (MACHINE_DATA, MACHINE_STATE)
    } else {
        (DATA_DIRECTORY, STATE_DIRECTORY)
    }
}

/// Describe the launchd job using fixed platform paths.
///
/// `ProcessType` is `Interactive` on purpose (#554): the kernel coalesces the timers of every
/// other class, so an 8.33 ms pacing timer fired at 34-41 ms (and 91 ms under `Background`)
/// on a real M1, which stretched pacing, deadlines and keepalives. `Interactive` measured 10.5 ms.
fn render_plist(executable: &Path) -> io::Result<String> {
    render_plist_for(LABEL, executable)
}

/// [`render_plist`] under `label`, so a root-mode install of an older build can be recognised.
fn render_plist_for(label: &str, executable: &Path) -> io::Result<String> {
    if !executable.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let (data, state) = service_paths(executable);
    let executable = xml_escape(&executable.to_string_lossy());
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>{label}</string>\n\
         <key>ProgramArguments</key><array>\n\
         <string>{executable}</string><string>agent</string><string>run</string>\n\
         <string>--data</string><string>{data}</string>\n\
         <string>--state</string><string>{state}</string>\n\
         </array>\n\
         <key>RunAtLoad</key><true/>\n\
         <key>KeepAlive</key><true/>\n\
         <key>ThrottleInterval</key><integer>5</integer>\n\
         <key>ProcessType</key><string>Interactive</string>\n\
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

/// Exercise launchd arguments, privileged checks and installation receipts.
#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "launchd unit tests panic on unexpected plist or command failures."
    )]
    use super::{
        CURRENT, DATA_DIRECTORY, LABEL, LEGACY, MACHINE_BINARY, STATE_DIRECTORY, checked_launchctl,
        join_state_to_forget, render_plist, render_plist_for, trusted_binary_metadata,
    };
    use std::path::Path;

    /// Fresh installs use Apple data paths while legacy launchd jobs remain valid.
    #[test]
    fn approved_install_renders_its_own_launchd_paths() {
        let managed = render_plist(Path::new(super::MACHINE_BINARY)).unwrap();
        assert!(managed.contains(super::MACHINE_DATA));
        assert!(managed.contains(super::MACHINE_STATE));
        assert!(!managed.contains(STATE_DIRECTORY));
        let legacy = render_plist(Path::new("/usr/local/bin/infraternal")).unwrap();
        assert!(legacy.contains(DATA_DIRECTORY));
        assert!(legacy.contains(STATE_DIRECTORY));
    }

    /// #554: the job runs as `Interactive` so the kernel does not coalesce its short timers.
    #[test]
    fn plist_runs_the_agent_as_an_interactive_process() {
        let plist = render_plist(Path::new(super::MACHINE_BINARY)).unwrap();
        assert!(plist.contains("<key>ProcessType</key><string>Interactive</string>"));
        assert!(!plist.contains("<string>Background</string>"));
        assert_eq!(plist.matches("<key>ProcessType</key>").count(), 1);
    }

    /// A stale removal request cannot claim the new install or its PATH alias.
    #[test]
    fn uninstall_receipt_is_scoped_to_the_enrolled_host() {
        let host = "cccccccccccccccccccccccccccccccc";
        let previous = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            super::receipt_alias(&format!("{host} 1\n"), host),
            Some(true)
        );
        assert_eq!(
            super::receipt_alias(&format!("{host} 0\n"), host),
            Some(false)
        );
        assert_eq!(super::receipt_alias(&format!("{previous} 1\n"), host), None);
        assert_eq!(
            super::receipt_alias(&format!("{host} 1\nextra"), host),
            None
        );
    }

    /// J162 F4: a join for another data directory leaves the service's mesh state alone.
    #[test]
    fn agent_join_forgets_the_service_state_only_for_the_service_enrolment() {
        let service = Path::new(STATE_DIRECTORY);
        assert_eq!(
            join_state_to_forget(Path::new(DATA_DIRECTORY), None).as_deref(),
            Some(service)
        );
        assert_eq!(
            join_state_to_forget(Path::new("/var/lib/infraternal/agent/"), None).as_deref(),
            Some(service)
        );
        assert_eq!(
            join_state_to_forget(Path::new(DATA_DIRECTORY), Some(service)).as_deref(),
            Some(service)
        );
        assert_eq!(join_state_to_forget(Path::new("/tmp/x"), None), None);
        assert_eq!(
            join_state_to_forget(Path::new("/tmp/x"), Some(service)),
            None
        );
        // A join with its own state directory still forgets that one.
        assert_eq!(
            join_state_to_forget(Path::new("/tmp/x"), Some(Path::new("/tmp/x-state"))).as_deref(),
            Some(Path::new("/tmp/x-state"))
        );
    }
    use std::{os::unix::process::ExitStatusExt, process::Output};

    /// A non-zero `launchctl` exit status must be reported as an I/O error.
    #[test]
    fn launchctl_nonzero_exit_is_not_reported_as_success() {
        let output = Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: b"launchctl refused the operation".to_vec(),
        };
        assert_eq!(
            checked_launchctl(&output)
                .expect_err("failed launchctl mutation must fail")
                .kind(),
            std::io::ErrorKind::Other
        );
    }

    /// The property list runs the fixed root agent command line, under the current label.
    #[test]
    fn launch_daemon_uses_fixed_root_agent_arguments() {
        let plist = render_plist(Path::new("/var/lib/infraternal/bin/infraternal"))
            .expect("render launch daemon plist");
        for value in [
            "kayg.infraternal.mesh",
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

    /// A root-mode install of a build before #580 differs from a new one only in its label, so
    /// it is recognised (and removed) under its own name, never adopted under the new one.
    #[test]
    fn an_old_root_install_differs_only_in_its_label() {
        let binary = Path::new(MACHINE_BINARY);
        let old = render_plist_for(LEGACY.label, binary).expect("render old plist");
        let new = render_plist(binary).expect("render new plist");
        assert_ne!(old, new);
        assert_eq!(old.replace(LEGACY.label, LABEL), new);
        assert_ne!(CURRENT, LEGACY);
        assert!(CURRENT.plist.contains(CURRENT.label) && LEGACY.plist.contains(LEGACY.label));
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

    #[test]
    fn elevation_prompt_maps_up_and_down_actions() {
        use infraternal_plugin_api::elevation_prompt::ElevationPrompt;
        assert_eq!(
            super::elevation_prompt_for_action("up"),
            Some(ElevationPrompt::MacosMeshServiceUp)
        );
        assert_eq!(
            super::elevation_prompt_for_action("down"),
            Some(ElevationPrompt::MacosMeshServiceDown)
        );
        assert_eq!(super::elevation_prompt_for_action("status"), None);
    }
}
