//! Hands removal of exactly a bootstrap-owned installation to a bounded independent service [17][198], #87.
use infraternal_plugin_api::{ActionReply, AgentPlugin, PluginDescriptor, PluginError};
use serde::{Deserialize, Serialize};
use std::{
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::Command,
};

/// Trusted local coordinates; an action request never supplies filesystem paths.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub host: String,
    pub uid: u32,
    pub data: PathBuf,
    pub sessions: PathBuf,
}
struct Layout {
    base: PathBuf,
    launcher: PathBuf,
    unit: PathBuf,
    wanted: PathBuf,
    user: bool,
    /// The account this installation runs as; selects its user service manager.
    uid: u32,
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
/// The one directory infraternal setup installs into for this account.
fn base_dir(home: &Path, uid: u32) -> PathBuf {
    if uid == 0 {
        PathBuf::from("/var/lib/infraternal")
    } else {
        home.join(".local/share/infraternal")
    }
}
/// This account's bootstrap installation for `host`, for an uninstall the
/// owner runs by hand on the machine (#235). Nothing here is trusted: cleanup
/// revalidates the layout and requires `.bootstrap-owner` to name `host`.
#[must_use]
pub fn installation(host: &str, home: &Path, uid: u32) -> Context {
    let base = base_dir(home, uid);
    Context {
        host: host.into(),
        uid,
        data: base.join("state"),
        sessions: base.join("sessions"),
    }
}
fn layout(context: &Context, home: &Path, uid: u32) -> io::Result<Layout> {
    if context.uid != uid
        || context.host.len() != 32
        || !context
            .host
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !home.is_absolute()
    {
        return Err(denied());
    }
    let user = uid != 0;
    let base = base_dir(home, uid);
    if context.data != base.join("state") || context.sessions != base.join("sessions") {
        return Err(denied());
    }
    let unit = if user {
        home.join(".config/systemd/user/infraternal-agent.service")
    } else {
        PathBuf::from("/etc/systemd/system/infraternal-agent.service")
    };
    let wanted = unit
        .parent()
        .ok_or_else(denied)?
        .join(if user {
            "default.target.wants"
        } else {
            "multi-user.target.wants"
        })
        .join("infraternal-agent.service");
    Ok(Layout {
        base,
        launcher: if user {
            home.join(".local/bin/infraternal")
        } else {
            "/usr/local/bin/infraternal".into()
        },
        unit,
        wanted,
        user,
        uid,
    })
}
pub(crate) fn public_file(path: &Path, uid: u32, max: u64) -> io::Result<String> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.len() > max
    {
        return Err(denied());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let actual = file.metadata()?;
    if actual.ino() != metadata.ino() || actual.dev() != metadata.dev() {
        return Err(denied());
    }
    let mut bytes = String::new();
    Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_string(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| denied())? > max {
        return Err(denied());
    }
    Ok(bytes)
}
/// Revalidate every owned artifact before handing off or removing any of them.
/// # Errors
/// Refuses arbitrary layouts, another uid/host, symlinks or unrelated units/launchers.
pub fn validate(context: &Context, home: &Path, uid: u32) -> io::Result<()> {
    validate_artifacts(context, home, uid, true)
}
fn validate_artifacts(context: &Context, home: &Path, uid: u32, unlocked: bool) -> io::Result<()> {
    let paths = layout(context, home, uid)?;
    let base = std::fs::symlink_metadata(&paths.base)?;
    // Only root's /var/lib/infraternal may also be 0711: `infraternal up` lays
    // it out so others reach `bin/` without listing it (#263). Nothing makes a
    // rootless base 0711, so it stays exactly 0700 (J145 P3-4).
    let private = match base.mode() & 0o777 {
        0o700 => true,
        0o711 => uid == 0,
        _ => false,
    };
    if !base.is_dir() || base.uid() != uid || !private {
        return Err(denied());
    }
    if public_file(&paths.base.join(".bootstrap-owner"), uid, 64)?.trim() != context.host {
        return Err(denied());
    }
    if unlocked {
        match std::fs::symlink_metadata(paths.base.join(".bootstrap-lock")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(denied()),
        }
    }
    let unit = public_file(&paths.unit, uid, 4096)?;
    if !unit
        .lines()
        .any(|line| line == format!("# infraternal bootstrap {}", context.host))
        || !unit.lines().any(|line| line == "KillMode=process")
        || !unit.lines().any(|line| line == format!("ExecStart=\"{0}/bin/current\" agent --data \"{0}/state\" --state \"{0}/sessions\" run", paths.base.display()))
    {
        return Err(denied());
    }
    if std::fs::read_link(&paths.launcher)? != paths.base.join("bin/current")
        || std::fs::read_link(paths.base.join("bin/current"))? != paths.base.join("bin/live")
    {
        return Err(denied());
    }
    match std::fs::read_link(&paths.wanted) {
        Ok(target)
            if target == paths.unit || target == Path::new("../infraternal-agent.service") => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(denied()),
    }
    Ok(())
}

/// Kernel objects an installation leaves outside its files (the mesh
/// interface and packet filter), handled by the build that owns them (#235).
///
/// Both functions take the installation's public state directory and return
/// the names of objects with our name that this installation did not create:
/// those are left in place and reported, never a reason to fail.
#[derive(Clone, Copy)]
pub struct Kernel {
    /// Decide ownership of every object, changing nothing.
    pub inspect: fn(&Path) -> io::Result<Vec<&'static str>>,
    /// Delete the objects this installation created.
    pub retire: fn(&Path) -> io::Result<Vec<&'static str>>,
}
impl Kernel {
    /// A build or account that never creates kernel objects.
    pub const NONE: Self = Self {
        inspect: |_| Ok(Vec::new()),
        retire: |_| Ok(Vec::new()),
    };
}
pub use crate::left_line;

/// Enabled only for a checked managed remote installation, without an idle task.
pub struct UninstallPlugin {
    context: Context,
    home: PathBuf,
    uid: u32,
    kernel: Kernel,
    // The service manager's transient-unit launcher. Tests substitute an inert
    // program so a handoff never starts a real unit on the build host.
    launcher: &'static str,
}
impl UninstallPlugin {
    /// # Errors
    /// Refuses a foreground or unrelated installation before registering its handler.
    pub fn new(context: Context, home: PathBuf, uid: u32, kernel: Kernel) -> io::Result<Self> {
        // The service starts while bootstrap still holds its publication lock.
        // Register the owned handler now; every call and cleanup rechecks the
        // lock, so installation must finish before any removal is accepted.
        validate_artifacts(&context, &home, uid, false)?;
        Ok(Self {
            context,
            home,
            uid,
            kernel,
            launcher: "systemd-run",
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// An exact host identity and dry-run choice, without filesystem input.
pub struct Request {
    host: String,
    dry_run: bool,
}
/// Decode the same bounded object used by the authenticated uninstall handler.
/// # Errors
/// Refuses positional input, foreign fields, duplicate keys and invalid host identities.
pub fn decode_request(input: &[u8]) -> Result<Request, PluginError> {
    if input.len() > infraternal_plugin_api::MAX_ACTION_BYTES
        || input.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(PluginError::Rejected);
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| PluginError::Rejected)?;
    if request.host.len() != 32
        || !request
            .host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PluginError::Rejected);
    }
    Ok(request)
}
impl AgentPlugin for UninstallPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &crate::NODE_DESCRIPTOR
    }
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::Rejected)
    }
    fn call_with_reply(&mut self, action: &str, input: &[u8]) -> Result<ActionReply, PluginError> {
        let request = decode_request(input)?;
        if action != crate::UNINSTALL.id || request.host != self.context.host {
            return Err(PluginError::Rejected);
        }
        validate(&self.context, &self.home, self.uid).map_err(|_| PluginError::Rejected)?;
        // Decide every kernel object before accepting, so the server can say
        // which ones stay, and a failed query refuses with nothing changed.
        let left =
            (self.kernel.inspect)(&self.context.sessions).map_err(|_| PluginError::Rejected)?;
        if request.dry_run {
            return Ok(ActionReply {
                json: reply(r#"{"state":"ready","owned":true,"left":["#, &left),
                after_write: None,
            });
        }
        let plan = serde_json::to_vec(&self.context).map_err(|_| PluginError::Rejected)?;
        let armed = plan_path(&self.home, self.uid);
        let staged = armed.with_file_name(STAGED);
        // A plan left by an earlier attempt is replaced, never followed.
        for path in [&staged, &armed] {
            match std::fs::remove_file(path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    return Err(PluginError::Rejected);
                }
                _ => {}
            }
        }
        write_plan(&staged, &plan).map_err(|_| PluginError::Rejected)?;
        // Disarm on every exit below that does not hand the reply over.
        let handoff = Handoff {
            staged,
            armed,
            pending: true,
        };
        // The helper runs as a separate transient service so it survives this
        // daemon's stop. It starts before the reply so a launch failure is
        // reported instead of "accepted" (#235), but waits until the reply is
        // written and the plan armed, so it cannot stop this daemon first.
        // No stdin pipe and no wait for the unit itself: both need the
        // manager's bus, which hosts without a per-user bus lack. Starting a
        // unit needs only the manager's private socket.
        let mut command = std::process::Command::new(self.launcher);
        infraternal_shim::prepare_child(&mut command);
        if self.uid != 0 {
            command.arg("--user");
        }
        command
            .args(["--quiet", "--collect", "--property=RuntimeMaxSec=30"])
            .arg(std::env::current_exe().map_err(|_| PluginError::Rejected)?)
            .arg("--bootstrap-uninstall")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if !launched(&mut command) {
            drop(handoff);
            return Ok(ActionReply {
                json: br#"{"state":"failed","cleanup":"not-started"}"#.to_vec(),
                after_write: None,
            });
        }
        let mut handoff = handoff;
        Ok(ActionReply {
            json: reply(r#"{"state":"accepted","cleanup":"pending","left":["#, &left),
            after_write: Some(Box::new(move || handoff.arm())),
        })
    }
}
/// A reply object ending in the names of kernel objects left in place.
///
/// The names are fixed identifiers from the kernel hooks (no quotes or
/// escapes), so they are written directly rather than through a JSON value.
fn reply(head: &str, left: &[&str]) -> Vec<u8> {
    let mut json = head.as_bytes().to_vec();
    for (index, name) in left.iter().enumerate() {
        if index > 0 {
            json.push(b',');
        }
        json.push(b'"');
        json.extend(name.bytes().filter(|byte| *byte != b'"' && *byte != b'\\'));
        json.push(b'"');
    }
    json.extend(b"]}");
    json
}
/// Run the transient-unit launcher to completion within a bound.
///
/// It returns once the manager has queued the unit, normally in milliseconds;
/// a launcher still running after the bound is killed and counts as failed.
fn launched(command: &mut std::process::Command) -> bool {
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}
/// The private plan file the helper consumes, inside the installation it removes.
const PLAN: &str = ".uninstall-plan";
/// The plan before the reply that accepts it is written; the helper ignores it.
const STAGED: &str = ".uninstall-plan.staged";
fn plan_path(home: &Path, uid: u32) -> PathBuf {
    base_dir(home, uid).join(PLAN)
}
fn write_plan(path: &Path, plan: &[u8]) -> io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    // A plan left by a crash between writing and starting is replaced, never followed.
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    // The helper accepts only a private regular file; never inherit a mode.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(plan)?;
    file.sync_all()
}
/// Wait for, read and consume the plan the infraternal agent left for its uninstall helper.
///
/// The helper starts before the agent's reply is written; the agent arms the
/// plan only after that write. An unarmed plan is never read, and a reply
/// that never went out leaves the helper with nothing to do (#235).
/// # Errors
/// Refuses a missing, foreign, shared-writable, oversized or malformed plan.
pub fn take_plan(home: &Path, uid: u32) -> io::Result<Context> {
    let path = plan_path(home, uid);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while matches!(std::fs::symlink_metadata(&path), Err(ref error) if error.kind() == io::ErrorKind::NotFound)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    let body = public_file(&path, uid, 8192);
    // Consume it whatever it holds: one accepted request starts one cleanup.
    let _ = std::fs::remove_file(&path);
    serde_json::from_str(&body?).map_err(|_| denied())
}
/// The staged plan of a started helper, owned until the reply is written.
///
/// Arming renames it to the name the helper waits for. Dropping it unarmed
/// (the launch failed, or the reply write failed) removes it, so nothing can
/// act on a request the server never saw accepted.
struct Handoff {
    staged: PathBuf,
    armed: PathBuf,
    pending: bool,
}
impl Handoff {
    fn arm(&mut self) {
        if std::fs::rename(&self.staged, &self.armed).is_ok() {
            self.pending = false;
        }
    }
}
impl Drop for Handoff {
    fn drop(&mut self) {
        if self.pending {
            let _ = std::fs::remove_file(&self.staged);
        }
    }
}
async fn shim_frame(
    peer: &mut (impl tokio::io::AsyncRead + Unpin),
) -> io::Result<infraternal_shim::frame::Frame> {
    let length = peer.read_u32_le().await? as usize;
    if length == 0 || length > infraternal_shim::frame::MAX_FRAME {
        return Err(denied());
    }
    let mut body = vec![0; length];
    peer.read_exact(&mut body).await?;
    infraternal_shim::frame::Frame::decode(&body)
}
async fn retire_shim(path: &Path, uid: u32) -> io::Result<()> {
    use infraternal_shim::frame::Frame;
    let mut peer = UnixStream::connect(path).await?;
    if peer.peer_cred()?.uid() != uid {
        return Err(denied());
    }
    let Frame::Hello { head, session, .. } = shim_frame(&mut peer).await? else {
        return Err(denied());
    };
    let mut expected = String::with_capacity(32);
    for byte in session {
        use std::fmt::Write;
        write!(&mut expected, "{byte:02x}").map_err(|_| denied())?;
    }
    if path.file_stem().and_then(|s| s.to_str()) != Some(expected.as_str()) {
        return Err(denied());
    }
    peer.write_all(&Frame::Attach(0).encode()?).await?;
    peer.write_all(&Frame::ReadFrom(head).encode()?).await?;
    peer.write_all(&Frame::Signal(9).encode()?).await?;
    let (mut reader, mut writer) = peer.into_split();
    // A foreground application has its own process group. After retiring it,
    // signal the restored shell as well, within the caller's existing deadline.
    let mut signals = tokio::time::interval(Duration::from_millis(100));
    signals.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    signals.tick().await;
    loop {
        let pending = shim_frame(&mut reader);
        tokio::pin!(pending);
        // Keep the same read future across ticks: cancelling a partial frame
        // would discard bytes and corrupt the authenticated socket decoder.
        let frame = loop {
            tokio::select! {
                frame = &mut pending => break frame?,
                _ = signals.tick() => writer.write_all(&Frame::Signal(9).encode()?).await?,
            }
        };
        match frame {
            Frame::Exited(..) => {
                writer.write_all(&Frame::ExitAck.encode()?).await?;
                return Ok(());
            }
            Frame::Output(..)
            | Frame::Snapshot(..)
            | Frame::SnapshotWithFlags(..)
            | Frame::InputAck(..) => {}
            _ => return Err(denied()),
        }
    }
}
/// The runtime directory `systemctl --user` needs to reach this account's
/// service manager, when the caller's session did not provide one.
///
/// A login without a systemd user session (an SSH server that does not run
/// `pam_systemd`, `su`, a cron job) has no `XDG_RUNTIME_DIR`, and `systemctl
/// --user` then fails even though the account's manager runs (linger keeps it
/// up for the installed service). The by-hand uninstall Remove hands out was
/// refused there with a bare "permission denied" (#305 F-C). Only the
/// account's own `/run/user/<uid>`, a real directory it owns, is used.
fn user_manager_runtime(uid: u32, current: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    if current.is_some_and(|value| !value.is_empty()) {
        return None;
    }
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let metadata = std::fs::symlink_metadata(&runtime).ok()?;
    (metadata.is_dir() && metadata.uid() == uid).then_some(runtime)
}
async fn manager(paths: &Layout, args: &[&str]) -> io::Result<()> {
    // Unit tests build complete fixture installations under the build
    // account; they must never reach that account's real service manager.
    if cfg!(test) {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let mut command = Command::new("systemctl");
    infraternal_shim::prepare_child(command.as_std_mut());
    if paths.user {
        command.arg("--user");
        if let Some(runtime) =
            user_manager_runtime(paths.uid, std::env::var_os("XDG_RUNTIME_DIR").as_deref())
        {
            command.env("XDG_RUNTIME_DIR", runtime);
        }
    }
    let status = command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    if !status.success() {
        // Say what failed: "permission denied" read as a refusal of ownership.
        return Err(io::Error::other(format!(
            "the service manager refused `systemctl{} {}`",
            if paths.user { " --user" } else { "" },
            args.join(" ")
        )));
    }
    Ok(())
}
/// Execute the private plan only in the independent helper, revalidating ownership.
///
/// Order (#235): ownership of every file and kernel object is decided before
/// anything is stopped, so a refusal leaves a working installation. Kernel
/// objects outlive the daemon process, so they are removed once the service
/// has stopped and before any file goes. An object with our name that this
/// installation did not create stays and is reported, never a failure.
/// Returns one report line per object left in place.
/// # Errors
/// Leaves unrelated artifacts untouched and refuses incomplete shell retirement, manager or kernel failure.
pub async fn cleanup(
    context: &Context,
    home: &Path,
    uid: u32,
    kernel: Kernel,
) -> io::Result<Vec<String>> {
    let paths = layout(context, home, uid)?;
    // Held until return: a re-add of this host meanwhile is refused with
    // "Setup is already running" instead of racing the removal (#235).
    let _setup = setup_guard(&paths.base).await?;
    validate(context, home, uid)?;
    (kernel.inspect)(&context.sessions)?;
    let sockets = context.sessions.join("sessions");
    if sockets.exists() {
        let metadata = std::fs::symlink_metadata(&sockets)?;
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(denied());
        }
        let entries = std::fs::read_dir(&sockets)?.collect::<Result<Vec<_>, _>>()?;
        if entries.len() > 128 {
            return Err(denied());
        }
        for entry in entries {
            let path = entry.path();
            if path.extension().is_some_and(|s| s == "sock") {
                tokio::time::timeout(Duration::from_secs(2), retire_shim(&path, uid))
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            }
        }
    }
    manager(&paths, &["disable", "--now", "infraternal-agent.service"]).await?;
    // Recheck after manager calls; never unlink a replacement made during stop.
    validate(context, home, uid)?;
    let report: Vec<String> = (kernel.retire)(&context.sessions)?
        .into_iter()
        .map(left_line)
        .collect();
    std::fs::remove_file(&paths.unit)?;
    infraternal_plugin_api::cli_alias::remove(&paths.launcher, uid)?;
    std::fs::remove_file(&paths.launcher)?;
    manager(&paths, &["daemon-reload"]).await?;
    remove_files(&paths.base).map(|left| report.into_iter().chain(left).collect())
}
/// Take the lock every infraternal setup command takes first (an exclusive
/// `flock` on the base's parent directory, see the ssh plugin's
/// `setup_guard.sh`), waiting a bounded time for a running setup step.
///
/// While it is held, setup admits no new attempt on this account (exit 73,
/// "Setup is already running on this host"). Setup holds it only for one
/// command, so the wait is short; a longer one refuses with nothing changed.
async fn setup_guard(base: &Path) -> io::Result<nix::fcntl::Flock<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = base.parent().ok_or_else(denied)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(parent)?;
        match nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(guard) => return Ok(guard),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err((_, error)) => return Err(error.into()),
        }
    }
}
/// Remove what infraternal setup and its infraternal agent put in `base`, then
/// `base` itself when nothing else is in it.
///
/// The rootless base is `~/.local/share/infraternal`, which is also where the
/// server keeps its CA (`ca`) and a joined node its data (`agent`) on the
/// same account. Those are not this installation's: they stay, and so does
/// the base that holds them (#235). `.bootstrap-owner` goes either way, so a
/// re-add never meets this installation's identity again.
fn remove_files(base: &Path) -> io::Result<Vec<String>> {
    for directory in ["bin", "state", "sessions"] {
        // Removes a symlink itself, never its target.
        match std::fs::remove_dir_all(base.join(directory)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    for file in [".bootstrap-ready", PLAN, STAGED, ".bootstrap-owner"] {
        match std::fs::remove_file(base.join(file)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    match std::fs::remove_dir(base) {
        Ok(()) => Ok(Vec::new()),
        Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(vec![format!(
            "Left {} because it holds files infraternal setup didn't create.",
            base.display()
        )]),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #305 F-C: the by-hand uninstall must reach the account's user manager from a
    /// login with no systemd user session (no `XDG_RUNTIME_DIR`), using only that
    /// account's own runtime directory, and must keep a session's own value.
    #[test]
    fn a_login_without_a_user_session_still_reaches_its_own_service_manager() {
        let uid = nix::unistd::Uid::effective().as_raw();
        let own = PathBuf::from(format!("/run/user/{uid}"));
        if std::fs::symlink_metadata(&own).is_ok_and(|m| m.is_dir() && m.uid() == uid) {
            assert_eq!(user_manager_runtime(uid, None), Some(own.clone()));
            assert_eq!(
                user_manager_runtime(uid, Some(std::ffi::OsStr::new(""))),
                Some(own)
            );
        }
        assert_eq!(
            user_manager_runtime(uid, Some(std::ffi::OsStr::new("/run/user/elsewhere"))),
            None
        );
        // Never another account's directory.
        assert_eq!(user_manager_runtime(uid.wrapping_add(7919), None), None);
    }
    /// A complete rootless bootstrap layout under a private fixture home.
    fn installation(name: &str, locked: bool) -> Option<(PathBuf, Context, u32)> {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let uid = nix::unistd::Uid::effective().as_raw();
        if uid == 0 {
            return None;
        } // Root's frozen layout cannot be redirected to a fixture.
        let home = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/a87/{name}{}",
            std::process::id()
        ));
        let base = home.join(".local/share/infraternal");
        let context = Context {
            host: "00000000000000000000000000000001".into(),
            uid,
            data: base.join("state"),
            sessions: base.join("sessions"),
        };
        let paths = layout(&context, &home, uid).unwrap();
        for path in [
            base.join("bin"),
            paths.unit.parent().unwrap().to_owned(),
            paths.launcher.parent().unwrap().to_owned(),
        ] {
            std::fs::create_dir_all(path).unwrap();
        }
        if locked {
            std::fs::create_dir_all(base.join(".bootstrap-lock")).unwrap();
        }
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(base.join(".bootstrap-owner"), &context.host).unwrap();
        std::fs::write(&paths.unit,format!("# infraternal bootstrap {}\nKillMode=process\nExecStart=\"{}/bin/current\" agent --data \"{}/state\" --state \"{}/sessions\" run\n",context.host,base.display(),base.display(),base.display())).unwrap();
        for file in [base.join(".bootstrap-owner"), paths.unit.clone()] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        symlink(base.join("bin/current"), &paths.launcher).unwrap();
        symlink(base.join("bin/live"), base.join("bin/current")).unwrap();
        Some((home, context, uid))
    }
    #[test]
    fn bootstrap_lock_delays_uninstall_without_omitting_its_handler() {
        let Some((home, context, uid)) = installation("n", true) else {
            return;
        };
        let base = context.data.parent().unwrap().to_owned();
        let mut plugin = UninstallPlugin::new(context.clone(), home.clone(), uid, Kernel::NONE);
        let registered = plugin.is_ok();
        if let Ok(plugin) = &mut plugin {
            let input =
                serde_json::to_vec(&serde_json::json!({"host":context.host,"dry_run":true}))
                    .unwrap();
            assert!(plugin.call_with_reply(crate::UNINSTALL.id, &input).is_err());
            std::fs::remove_dir(base.join(".bootstrap-lock")).unwrap();
            assert!(plugin.call_with_reply(crate::UNINSTALL.id, &input).is_ok());
        }
        std::fs::remove_dir_all(home).unwrap();
        assert!(
            registered,
            "the service starts before bootstrap removes its lock"
        );
    }
    /// #235: the plugin worker is a plain OS thread with no async runtime. The
    /// accepted handoff used to start its launcher through the runtime's process
    /// driver there, panicking with "there is no reactor running" and killing the
    /// worker, so removal never uninstalled anything.
    #[test]
    fn accepted_handoff_runs_on_a_thread_without_an_async_runtime() {
        let Some((home, context, uid)) = installation("h", false) else {
            return;
        };
        let mut plugin =
            UninstallPlugin::new(context.clone(), home.clone(), uid, Kernel::NONE).unwrap();
        plugin.launcher = "true";
        let input =
            serde_json::to_vec(&serde_json::json!({"host":context.host,"dry_run":false})).unwrap();
        let plan = plan_path(&home, uid);
        let observed = plan.with_file_name(STAGED);
        let armed = plan.clone();
        let worker = std::thread::spawn(move || {
            // An unwritten reply is dropped: its plan must not survive it.
            let unwritten = plugin.call_with_reply(crate::UNINSTALL.id, &input).unwrap();
            // Until the reply is written the helper has nothing to follow.
            assert!(observed.exists() && !armed.exists());
            drop(unwritten);
            assert!(!observed.exists(), "a dropped reply left its plan");
            // The reply writer runs this after a successful write; it must not
            // need a runtime either.
            let reply = plugin.call_with_reply(crate::UNINSTALL.id, &input).unwrap();
            reply.after_write.unwrap()();
            reply.json
        })
        .join();
        let taken = take_plan(&home, uid);
        let consumed = !plan.exists();
        std::fs::remove_dir_all(home).unwrap();
        let json = worker.expect("the uninstall handoff panicked off the async runtime");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&json).unwrap(),
            serde_json::json!({"state":"accepted","cleanup":"pending","left":[]})
        );
        // The helper finds exactly the plan for this installation, once.
        assert_eq!(taken.unwrap().host, context.host);
        assert!(consumed);
    }
    /// Break-it review (#235): planted files at the plan path are replaced, never
    /// followed, and the helper refuses a plan that is not a private regular file.
    #[test]
    fn review_planted_plan_is_never_followed() {
        use std::os::unix::fs::symlink;
        let Some((home, context, uid)) = installation("p", false) else {
            return;
        };
        let plan = plan_path(&home, uid);
        let victim = home.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        symlink(&victim, &plan).unwrap();
        // The helper refuses a symlinked plan and removes only the link.
        let refused = take_plan(&home, uid).is_err();
        let kept = std::fs::read(&victim).unwrap() == b"keep";
        symlink(&victim, &plan).unwrap();
        // The infraternal agent replaces a planted link without writing through it.
        write_plan(&plan, &serde_json::to_vec(&context).unwrap()).unwrap();
        let untouched = std::fs::read(&victim).unwrap() == b"keep";
        let regular = std::fs::symlink_metadata(&plan).unwrap().is_file();
        std::fs::remove_dir_all(&home).unwrap();
        assert!(refused && kept && untouched && regular);
    }
    /// Break-it review (#235): the launcher runs after the reply already said
    /// "accepted". When it then fails (no user manager, a refused unit), the plan
    /// must not stay behind in the installation as a standing order.
    #[test]
    fn review_failed_launcher_leaves_no_plan() {
        let Some((home, context, uid)) = installation("f", false) else {
            return;
        };
        let mut plugin =
            UninstallPlugin::new(context.clone(), home.clone(), uid, Kernel::NONE).unwrap();
        plugin.launcher = "false";
        let input =
            serde_json::to_vec(&serde_json::json!({"host":context.host,"dry_run":false})).unwrap();
        let reply = plugin.call_with_reply(crate::UNINSTALL.id, &input).unwrap();
        // Fix (#235): the launcher runs before the reply, so its failure is
        // the reply: never "accepted", and nothing left to arm.
        let plan = plan_path(&home, uid);
        let left = plan.exists() || plan.with_file_name(STAGED).exists();
        std::fs::remove_dir_all(&home).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&reply.json).unwrap()["state"],
            "failed"
        );
        assert!(reply.after_write.is_none());
        assert!(!left, "a failed launcher left its uninstall plan behind");
    }
    /// #235: while setup holds its lock on this account, uninstall waits a
    /// bounded time and then refuses with nothing changed; while uninstall
    /// holds it, setup's own `flock -n` admission fails (its exit 73).
    #[tokio::test]
    async fn uninstall_and_setup_exclude_each_other() {
        let Some((home, context, uid)) = installation("l", false) else {
            return;
        };
        let parent = context.data.parent().unwrap().parent().unwrap().to_owned();
        let held = nix::fcntl::Flock::lock(
            std::fs::File::open(&parent).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, error)| error)
        .unwrap();
        let started = std::time::Instant::now();
        let refused = cleanup(&context, &home, uid, Kernel::NONE).await;
        let waited = started.elapsed();
        let intact = validate(&context, &home, uid).is_ok();
        drop(held);
        let guard = setup_guard(context.data.parent().unwrap()).await.unwrap();
        let setup = std::process::Command::new("flock")
            .arg("-n")
            .arg(&parent)
            .arg("true")
            .status()
            .unwrap();
        drop(guard);
        std::fs::remove_dir_all(&home).unwrap();
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(waited >= Duration::from_secs(5) && intact);
        assert!(!setup.success(), "setup was admitted during uninstall");
    }
    /// #235: kernel ownership is decided before the service is stopped; a
    /// failed check leaves a working installation, not a stopped one.
    #[tokio::test]
    async fn a_failed_kernel_check_stops_cleanup_before_the_service() {
        let Some((home, context, uid)) = installation("k", false) else {
            return;
        };
        let refused = Kernel {
            inspect: |_| Err(io::ErrorKind::ConnectionRefused.into()),
            retire: |_| Ok(Vec::new()),
        };
        let checked = cleanup(&context, &home, uid, refused).await;
        // With the check passing, cleanup goes on to the service manager.
        let reached = cleanup(&context, &home, uid, Kernel::NONE).await;
        let intact = validate(&context, &home, uid).is_ok();
        std::fs::remove_dir_all(&home).unwrap();
        assert_eq!(
            checked.unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert_eq!(reached.unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert!(intact, "a refused check changed the installation");
    }
    #[tokio::test]
    async fn retirement_signals_the_shell_after_its_foreground_job_exits() {
        use infraternal_shim::frame::Frame;
        let directory = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(format!(".cache/codex-scratch/a87/r{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("00000000000000000000000000000001.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut session = [0; 16];
            session[15] = 1;
            peer.write_all(
                &Frame::Hello {
                    version: 1,
                    caps: 0,
                    session,
                    pid: 1,
                    cols: 80,
                    rows: 24,
                    created: 0,
                    head: 0,
                    start: 0,
                }
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();
            assert!(matches!(
                shim_frame(&mut peer).await.unwrap(),
                Frame::Attach(0)
            ));
            assert!(matches!(
                shim_frame(&mut peer).await.unwrap(),
                Frame::ReadFrom(0)
            ));
            assert!(matches!(
                shim_frame(&mut peer).await.unwrap(),
                Frame::Signal(9)
            ));
            // The first signal retires an application, leaving its login shell.
            assert!(matches!(
                shim_frame(&mut peer).await.unwrap(),
                Frame::Signal(9)
            ));
            let exit = Frame::Exited(0, 0).encode().unwrap();
            peer.write_all(&exit[..2]).await.unwrap();
            assert!(matches!(
                shim_frame(&mut peer).await.unwrap(),
                Frame::Signal(9)
            ));
            peer.write_all(&exit[2..]).await.unwrap();
            assert!(matches!(
                shim_frame(&mut peer).await.unwrap(),
                Frame::ExitAck
            ));
        });
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            retire_shim(&path, nix::unistd::Uid::effective().as_raw()),
        )
        .await;
        server.abort();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        assert!(result.is_ok_and(|r| r.is_ok()));
    }
    /// #235: the server's CA and a joined node's data can share the rootless
    /// base; uninstall removes only setup's own entries and keeps the rest.
    #[test]
    fn a_traversable_rootless_base_is_refused() {
        // J145 P3-4: 0711 is accepted only for root's /var/lib/infraternal.
        use std::os::unix::fs::PermissionsExt;
        let Some((home, context, uid)) = installation("rootless-711", false) else {
            return;
        };
        let base = home.join(".local/share/infraternal");
        assert!(
            validate(&context, &home, uid).is_ok(),
            "the 0700 fixture is valid"
        );
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o711)).unwrap();
        assert!(
            validate(&context, &home, uid).is_err(),
            "a 0711 rootless base"
        );
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn file_removal_keeps_what_setup_did_not_create() {
        let Some((home, context, _)) = installation("c", false) else {
            return;
        };
        let base = context.data.parent().unwrap().to_owned();
        std::fs::create_dir_all(base.join("ca")).unwrap();
        std::fs::write(base.join("ca/key"), b"keep").unwrap();
        std::fs::create_dir_all(context.sessions.join("sessions")).unwrap();
        let kept = remove_files(&base).unwrap();
        let ca = std::fs::read(base.join("ca/key")).ok();
        let gone = ["bin", "sessions", ".bootstrap-owner"]
            .iter()
            .all(|entry| !base.join(entry).exists());
        // Without foreign entries the base itself goes.
        std::fs::remove_dir_all(base.join("ca")).unwrap();
        let empty = remove_files(&base).unwrap();
        let removed = !base.exists();
        std::fs::remove_dir_all(&home).unwrap();
        assert_eq!(ca.as_deref(), Some(&b"keep"[..]));
        assert!(gone, "setup's own entries survived");
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert!(empty.is_empty() && removed);
    }
    /// #235: the command the owner copies names a host; it removes nothing
    /// unless `.bootstrap-owner` names that same host.
    #[tokio::test]
    async fn manual_uninstall_refuses_another_hosts_installation() {
        let Some((home, context, uid)) = installation("m", false) else {
            return;
        };
        let other = super::installation("00000000000000000000000000000002", &home, uid);
        let same = super::installation(&context.host, &home, uid);
        let refused = cleanup(&other, &home, uid, Kernel::NONE).await;
        let intact = validate(&context, &home, uid).is_ok();
        let matches = same.data == context.data && same.sessions == context.sessions;
        std::fs::remove_dir_all(&home).unwrap();
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(intact && matches);
    }
    #[test]
    fn replies_name_the_objects_left_as_valid_json() {
        let json = reply(
            r#"{"state":"accepted","left":["#,
            &["infraternal0", "the IFM_* iptables chains"],
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&json).unwrap(),
            serde_json::json!({"state":"accepted","left":["infraternal0","the IFM_* iptables chains"]})
        );
        assert_eq!(reply(r#"{"left":["#, &[]), br#"{"left":[]}"#);
    }
    #[test]
    fn uninstall_never_accepts_request_selected_paths_or_foreign_identity() {
        let context = Context {
            host: "not-a-host".into(),
            uid: 1000,
            data: "/unrelated/state".into(),
            sessions: "/unrelated/sessions".into(),
        };
        assert!(validate(&context, Path::new("/home/fixture"), 1000).is_err());
    }
}
