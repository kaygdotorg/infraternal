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

/// Whether `base` still contains exactly the committed transaction that asked
/// for cleanup. Any staged transaction makes the old marker stale.
fn committed_transaction_matches(
    base: &Path,
    transaction: uuid::Uuid,
    uid: u32,
) -> io::Result<bool> {
    let stage = base.join(".bootstrap-lock");
    match std::fs::symlink_metadata(stage) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let marker = base.join(".bootstrap-transaction");
    let metadata = match std::fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(denied());
    }
    Ok(public_file(&marker, uid, 33)? == format!("{}\n", transaction.simple()))
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
/// The Linux paths and host used to review native service removal.
pub struct Review {
    /// The bootstrap state and host selected for removal.
    pub context: Context,
    /// The installation root that owns the enrollment and runtime directories.
    pub base: PathBuf,
    /// The files systemd and command discovery use for this installation.
    pub paths: Vec<PathBuf>,
}

/// Find the host marker in this account's installed systemd unit.
///
/// # Errors
/// Rejects an unrelated unit. An unprivileged review of a system install reads
/// the public unit only. The elevated command always validates the private receipt.
pub fn review(home: &Path, uid: u32, caller: u32) -> io::Result<Review> {
    let paths = layout(&installation(&"0".repeat(32), home, uid), home, uid)?;
    let unit = public_file(&paths.unit, uid, 4096)?;
    let host = unit
        .lines()
        .find_map(|line| line.strip_prefix("# infraternal bootstrap "))
        .ok_or_else(denied)?;
    let context = installation(host, home, uid);
    let paths = layout(&context, home, uid)?;
    validate_unit(&unit, &paths, host)?;
    if caller == uid {
        validate(&context, home, uid).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => denied(),
            _ => error,
        })?;
    }
    let mut removal = vec![
        paths.unit,
        paths.launcher.clone(),
        paths.base.join("bin"),
        paths.base.join("sessions"),
    ];
    if paths.wanted.is_symlink() {
        removal.push(paths.wanted);
    }
    let alias = paths.launcher.with_file_name("infra");
    if std::fs::symlink_metadata(&alias).is_ok_and(|metadata| metadata.uid() == uid)
        && std::fs::read_link(&alias).is_ok_and(|target| target == Path::new("infraternal"))
    {
        removal.push(alias);
    }
    if let Ok(Some(cache)) = owned_payload_cache(&paths.base, uid) {
        removal.push(cache);
    }
    Ok(Review {
        context,
        base: paths.base,
        paths: removal,
    })
}

/// Locate only the SSH installer's private, marked public payload cache.
fn owned_payload_cache(base: &Path, uid: u32) -> io::Result<Option<PathBuf>> {
    let cache = base.with_file_name("infraternal.bootstrap-cache");
    let metadata = match std::fs::symlink_metadata(&cache) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o700
        || public_file(&cache.join("owner"), uid, 64)? != "INFRATERNAL_PAYLOAD_CACHE_V1\n"
    {
        return Err(denied());
    }
    for entry in std::fs::read_dir(&cache)? {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        let mode = match entry.file_name().to_str() {
            Some("owner") => 0o600,
            Some("payload") => 0o700,
            _ => return Err(denied()),
        };
        if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o777 != mode {
            return Err(denied());
        }
    }
    Ok(Some(cache))
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
    validate_unit(&unit, &paths, &context.host)?;
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

/// Check systemd's public unit before trusting it to identify a bootstrap installation.
fn validate_unit(unit: &str, paths: &Layout, host: &str) -> io::Result<()> {
    if !unit
        .lines()
        .any(|line| line == format!("# infraternal bootstrap {host}"))
        || !unit.lines().any(|line| line == "KillMode=process")
        || !unit.lines().any(|line| line == format!("ExecStart=\"{0}/bin/current\" agent --data \"{0}/state\" --state \"{0}/sessions\" run", paths.base.display()))
    {
        return Err(denied());
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
pub use crate::{left_line, uninstall_request::decode_request};

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
/// Hang guard for each step of retiring one shim: connecting, its Hello, and
/// the wait for each next frame while it is signalled. The shim is
/// infraternal's own process under the installation's account, so its
/// silence is a hang, not a slow host. A slow but progressing host never
/// refuses an uninstall, and a stuck shim still fails it (D352, #334, #355).
const RETIRE_STEP_HANG: Duration = Duration::from_secs(60);

/// Runs one step of a shim retirement under [`RETIRE_STEP_HANG`].
async fn retire_step<T>(work: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(RETIRE_STEP_HANG, work)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Retires one session's shim for [`cleanup`]. No clock covers the whole
/// retirement: each of its steps is bounded by [`RETIRE_STEP_HANG`], so a
/// slow but progressing host never refuses an uninstall (D352, #355).
async fn retire_session(path: &Path, uid: u32) -> io::Result<()> {
    retire_shim(path, uid).await
}

/// Removes the socket file a gone shim left at `path` (#409).
///
/// Only a socket owned by `uid`, this installation's account, is removed. Any
/// other kind of file there (or another owner) refuses, and stays. A path that
/// is already gone is fine.
fn remove_stale_socket(path: &Path, uid: u32) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        metadata => metadata?,
    };
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(denied());
    }
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Retires the shim at `path`, owned by `uid`: authenticates its Hello, kills
/// its foreground job and then its restored shell (signalling every 100 ms),
/// and acknowledges its exit. Each step is hang-bounded; nothing bounds the
/// whole retirement, which ends when the shim has exited.
async fn retire_shim(path: &Path, uid: u32) -> io::Result<()> {
    use infraternal_shim::frame::Frame;
    let mut peer = match retire_step(UnixStream::connect(path)).await {
        Ok(peer) => peer,
        // A shim listens on its socket for its whole life, so a refused or
        // vanished socket means no shim serves this session any more: its
        // shell went with it. That is the normal state on a root host after
        // the login revocation the removal outbox delivers first, which kills
        // the login's unit outright (D354, #409). The session is retired;
        // only the stale socket file of this installation's account is left.
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            return remove_stale_socket(path, uid);
        }
        Err(error) => return Err(error),
    };
    if peer.peer_cred()?.uid() != uid {
        return Err(denied());
    }
    let Frame::Hello { head, session, .. } = retire_step(shim_frame(&mut peer)).await? else {
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
        // Each frame is progress; only a shim silent for a whole step hangs.
        let frame = retire_step(async {
            loop {
                tokio::select! {
                    frame = &mut pending => break frame,
                    _ = signals.tick() => writer.write_all(&Frame::Signal(9).encode()?).await?,
                }
            }
        })
        .await?;
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
    user_manager_runtime_in(Path::new("/run/user"), uid, current)
}
/// [`user_manager_runtime`] under `root` (`/run/user` outside tests).
fn user_manager_runtime_in(
    root: &Path,
    uid: u32,
    current: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if current.is_some_and(|value| !value.is_empty()) {
        return None;
    }
    let runtime = root.join(uid.to_string());
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
    cleanup_with_state(context, home, uid, kernel, false).await
}

/// Remove the reviewed install, optionally keeping a private copy of its enrollment.
///
/// # Errors
/// Refuses an unowned install, an existing backup, or incomplete service cleanup.
pub async fn cleanup_with_state(
    context: &Context,
    home: &Path,
    uid: u32,
    kernel: Kernel,
    keep_state: bool,
) -> io::Result<Vec<String>> {
    let paths = layout(context, home, uid)?;
    // Held until return: a re-add of this host meanwhile is refused with
    // "Setup is already running" instead of racing the removal (#235).
    let _setup = setup_guard(&paths.base).await?;
    cleanup_locked(context, &paths, home, uid, kernel, true, keep_state).await
}

/// Remove a committed root install only while its transaction still owns the
/// base. Stale abandonment is an idempotent no-op and cannot stop a later install.
/// # Errors
/// Reports validation, manager and file cleanup failures without claiming completion.
pub async fn cleanup_for_promotion(
    context: &Context,
    home: &Path,
    uid: u32,
    transaction: uuid::Uuid,
    kernel: Kernel,
) -> io::Result<bool> {
    let paths = layout(context, home, uid)?;
    // Check the transaction under the same lock that fences setup and cleanup.
    let _setup = setup_guard(&paths.base).await?;
    if !committed_transaction_matches(&paths.base, transaction, uid)? {
        return Ok(false);
    }
    cleanup_locked(context, &paths, home, uid, kernel, false, false).await?;
    Ok(true)
}

/// Run the checked removal while the caller holds the setup lock.
async fn cleanup_locked(
    context: &Context,
    paths: &Layout,
    home: &Path,
    uid: u32,
    kernel: Kernel,
    stop_agent: bool,
    keep_state: bool,
) -> io::Result<Vec<String>> {
    validate(context, home, uid)?;
    let backup = keep_state
        .then(|| infraternal_plugin_api::uninstall_state::destination(&paths.base, &context.host));
    if let Some(path) = &backup {
        infraternal_plugin_api::uninstall_state::check_destination(path)?;
    }
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
                retire_session(&path, uid).await?;
            }
        }
    }
    if stop_agent {
        manager(paths, &["disable", "--now", "infraternal-agent.service"]).await?;
    } else {
        // The abandonment reply travels over this daemon's live link. Disable
        // its unit now, then stop the already-running process after the reply.
        manager(paths, &["disable", "infraternal-agent.service"]).await?;
    }
    // Recheck after manager calls; never unlink a replacement made during stop.
    validate(context, home, uid)?;
    let report: Vec<String> = (kernel.retire)(&context.sessions)?
        .into_iter()
        .map(left_line)
        .collect();
    if let Some(path) = &backup {
        infraternal_plugin_api::uninstall_state::preserve(&context.data, path, uid)?;
    }
    std::fs::remove_file(&paths.unit)?;
    infraternal_plugin_api::cli_alias::remove(&paths.launcher, uid)?;
    std::fs::remove_file(&paths.launcher)?;
    manager(paths, &["daemon-reload"]).await?;
    // A rootful agent may have written mesh SSH's client files (#221); they
    // go with it. Only files infraternal wrote are removed.
    let mut report = report;
    if !paths.user
        && infraternal_plugin_api::mesh_ssh_files::remove_client_files(Path::new("/")).is_err()
    {
        report.push(format!(
            "Left {} and {}; remove them by hand.",
            infraternal_plugin_api::mesh_ssh_files::CONFIG_PATH,
            infraternal_plugin_api::mesh_ssh_files::KNOWN_HOSTS_PATH
        ));
    }
    match owned_payload_cache(&paths.base, uid) {
        Ok(Some(cache)) => {
            if let Err(error) = std::fs::remove_dir_all(&cache) {
                report.push(format!(
                    "Couldn't remove {} ({error}). Remove the cache by hand.",
                    cache.display()
                ));
            }
        }
        Ok(None) => {}
        Err(_) => report.push(format!(
            "Left {} because infraternal could not verify its ownership.",
            paths
                .base
                .with_file_name("infraternal.bootstrap-cache")
                .display()
        )),
    }
    remove_files(&paths.base).map(|left| report.into_iter().chain(left).collect())
}
/// Retire this account's rootless installation after its host was upgraded
/// to the root infraternal agent (D376, #399; J415 R5, R6).
///
/// Run as the account itself (the root agent starts this binary as the
/// account; root never touches these files). Like [`cleanup`], ownership is
/// decided before anything stops, under the setup lock. Unlike it, the
/// running terminals stay: their shims and session sockets are left in
/// place, so the person's own process can adopt them. The user unit is
/// stopped (its `KillMode=process` stops only the agent, never a shim),
/// disabled and removed with the launcher and the agent's state.
///
/// Idempotent: an installation that is already gone is a success, so the
/// server's outbox can ask again after a lost receipt.
/// # Errors
/// Refuses another account's or another host's installation, and reports a
/// service manager or file removal failure; nothing past the failure changes.
pub async fn retire_for_promotion(context: &Context, home: &Path, uid: u32) -> io::Result<()> {
    let paths = layout(context, home, uid)?;
    if !paths.user {
        return Err(denied());
    }
    if !paths.base.join(".bootstrap-owner").exists() && !paths.unit.exists() {
        return Ok(());
    }
    let _setup = setup_guard(&paths.base).await?;
    validate(context, home, uid)?;
    manager(&paths, &["disable", "--now", "infraternal-agent.service"]).await?;
    // Recheck after the manager call; never unlink a replacement made meanwhile.
    validate(context, home, uid)?;
    std::fs::remove_file(&paths.unit)?;
    infraternal_plugin_api::cli_alias::remove(&paths.launcher, uid)?;
    std::fs::remove_file(&paths.launcher)?;
    manager(&paths, &["daemon-reload"]).await?;
    for directory in ["bin", "state"] {
        match std::fs::remove_dir_all(paths.base.join(directory)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    for file in [
        ".bootstrap-ready",
        ".bootstrap-transaction",
        PLAN,
        STAGED,
        ".bootstrap-owner",
    ] {
        match std::fs::remove_file(paths.base.join(file)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

/// Open the install's setup guard file, `<base>.bootstrap-guard`, creating
/// it when missing; every infraternal setup command and the infraternal
/// agent's runtime admission `flock` this one file (see the ssh plugin's
/// `setup_guard.sh`).
///
/// The guard must be something no other local account can open: `flock`
/// needs only a descriptor, so a lock on a world-readable object (the base's
/// parent, `/var/lib` for a root install, before #399 J569 P1-1) let any
/// account block every setup step, rollback and uninstall. So:
/// - the parent must be a real directory owned by this account and not
///   writable by group or others, so nobody else can plant or swap the name;
/// - the file is created exclusively with mode 0600 and opened without
///   following a link;
/// - the opened file must be a regular file owned by this account, mode
///   0600, with one link. Anything else is refused, never repaired.
///
/// The file is never removed (see `setup_guard.sh` for why).
pub(crate) fn open_setup_guard(base: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = base.parent().ok_or_else(denied)?;
    if !private_parent(base) {
        return Err(denied());
    }
    let euid = nix::unistd::Uid::effective().as_raw();
    let mut name = base.file_name().ok_or_else(denied)?.to_os_string();
    name.push(".bootstrap-guard");
    let path = parent.join(name);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != euid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(denied());
    }
    Ok(file)
}

/// Whether `base`'s parent is a real directory owned by this account and not
/// writable by group or others: the only kind setup installs under (its guard
/// refuses any other parent with exit 71), so the only kind with a setup
/// guard file.
pub(crate) fn private_parent(base: &Path) -> bool {
    base.parent()
        .and_then(|parent| std::fs::symlink_metadata(parent).ok())
        .is_some_and(|directory| {
            directory.is_dir()
                && directory.uid() == nix::unistd::Uid::effective().as_raw()
                && directory.mode() & 0o022 == 0
        })
}

/// Take the lock every infraternal setup command takes first (an exclusive
/// `flock` on the install's guard file, [`open_setup_guard`]), waiting a
/// bounded time for a running setup step.
///
/// While it is held, setup admits no new attempt on this account (exit 73,
/// "Setup is already running on this host"). Setup holds it only for one
/// command, so the wait is short; a longer one refuses with nothing changed.
async fn setup_guard(base: &Path) -> io::Result<nix::fcntl::Flock<std::fs::File>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let guard = open_setup_guard(base)?;
        match nix::fcntl::Flock::lock(guard, nix::fcntl::FlockArg::LockExclusiveNonblock) {
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
    for file in [
        ".bootstrap-ready",
        ".bootstrap-transaction",
        PLAN,
        STAGED,
        ".bootstrap-owner",
    ] {
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
    //! Uninstall decides ownership before it stops anything, removes only
    //! what setup created, and retires every shell before it reports done.
    use super::*;

    /// #305 F-C: the by-hand uninstall must reach the account's user manager from a
    /// login with no systemd user session (no `XDG_RUNTIME_DIR`), using only that
    /// account's own runtime directory, and must keep a session's own value. Runs
    /// against a private root, so it asserts on every machine (J257 P3).
    #[test]
    fn a_login_without_a_user_session_still_reaches_its_own_service_manager() {
        use std::os::unix::fs::symlink;
        let uid = nix::unistd::Uid::effective().as_raw();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("run-user-{}-{unique}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        // No directory for this uid: nothing to point at.
        assert_eq!(user_manager_runtime_in(&root, uid, None), None);
        let own = root.join(uid.to_string());
        std::fs::create_dir(&own).unwrap();
        assert_eq!(user_manager_runtime_in(&root, uid, None), Some(own.clone()));
        assert_eq!(
            user_manager_runtime_in(&root, uid, Some(std::ffi::OsStr::new(""))),
            Some(own.clone())
        );
        // A session that has its own value keeps it.
        assert_eq!(
            user_manager_runtime_in(
                &root,
                uid,
                Some(std::ffi::OsStr::new("/run/user/elsewhere"))
            ),
            None
        );
        // Never another account's directory, even one this account created.
        let other = uid.wrapping_add(7919);
        std::fs::create_dir(root.join(other.to_string())).unwrap();
        assert_eq!(user_manager_runtime_in(&root, other, None), None);
        // Never a link standing in for the directory.
        std::fs::remove_dir(&own).unwrap();
        symlink(root.join(other.to_string()), &own).unwrap();
        assert_eq!(user_manager_runtime_in(&root, uid, None), None);
        std::fs::remove_dir_all(&root).unwrap();
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
    /// The system unit must name the fixed system paths, even in an unprivileged preview.
    #[test]
    fn system_review_refuses_user_paths_in_the_installed_unit() {
        let home = Path::new("/root");
        let context = super::installation("00000000000000000000000000000001", home, 0);
        let layout = layout(&context, home, 0).unwrap();
        let unit = format!(
            "# infraternal bootstrap {}\nKillMode=process\nExecStart=\"/var/lib/infraternal/bin/current\" agent --data \"/var/lib/infraternal/state\" --state \"/var/lib/infraternal/sessions\" run\n",
            context.host
        );
        assert!(super::validate_unit(&unit, &layout, &context.host).is_ok());
        let unrelated = unit.replace(
            "/var/lib/infraternal",
            "/home/other/.local/share/infraternal",
        );
        assert!(super::validate_unit(&unrelated, &layout, &context.host).is_err());
    }

    /// Review names only the canonical Linux user installation and refuses an altered launcher.
    #[test]
    fn review_refuses_a_launcher_pointing_outside_the_owned_install() {
        let Some((home, context, uid)) = installation("review", false) else {
            return;
        };
        let plan = super::review(&home, uid, uid).unwrap();
        assert_eq!(plan.context.host, context.host);
        assert!(
            plan.paths
                .contains(&home.join(".config/systemd/user/infraternal-agent.service"))
        );
        let launcher = home.join(".local/bin/infraternal");
        std::fs::remove_file(&launcher).unwrap();
        std::os::unix::fs::symlink("/bin/sh", &launcher).unwrap();
        assert!(super::review(&home, uid, uid).is_err());
        std::fs::remove_dir_all(&home).unwrap();
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
        let base = context.data.parent().unwrap();
        let guard_file = base.with_file_name("infraternal.bootstrap-guard");
        let held = nix::fcntl::Flock::lock(
            open_setup_guard(base).unwrap(),
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
            .arg(&guard_file)
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
    /// A fake shim on a short socket path: answers Hello after `hello`, then
    /// Exited after `exit`, draining the retirement's signals meanwhile.
    fn slow_shim(
        hello: Option<Duration>,
        exit: Duration,
    ) -> (PathBuf, tokio::task::JoinHandle<()>) {
        use infraternal_shim::frame::Frame;
        let directory = nix::unistd::mkdtemp("/tmp/rs-XXXXXX").unwrap();
        let path = directory.join("00000000000000000000000000000001.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let Some(hello) = hello else {
                // A stuck shim: it accepted and never says anything.
                std::future::pending::<()>().await;
                return;
            };
            // sleep: a slow shim on purpose (paused time); retirement must wait it out.
            tokio::time::sleep(hello).await;
            let mut session = [0; 16];
            session[15] = 1;
            let frame = Frame::Hello {
                version: 1,
                caps: 0,
                session,
                pid: 1,
                cols: 80,
                rows: 24,
                created: 0,
                head: 0,
                start: 0,
            };
            peer.write_all(&frame.encode().unwrap()).await.unwrap();
            let (mut reader, mut writer) = peer.into_split();
            let exited = tokio::spawn(async move {
                // sleep: a slow exit on purpose (paused time), while signals keep arriving.
                tokio::time::sleep(exit).await;
                writer
                    .write_all(&Frame::Exited(0, 0).encode().unwrap())
                    .await
                    .unwrap();
            });
            while let Ok(frame) = shim_frame(&mut reader).await {
                if matches!(frame, Frame::ExitAck) {
                    break;
                }
            }
            exited.await.unwrap();
        });
        (path, server)
    }

    /// A slow but progressing shim (Hello after 3 s, exit 3 s later) is still
    /// retired: no clock covers the whole retirement, so a loaded host never
    /// refuses an uninstall (D352, #355). The 2 s whole-retirement limit
    /// refused it.
    #[tokio::test(start_paused = true)]
    async fn slow_but_progressing_shim_retirement_still_completes() {
        let (path, server) = slow_shim(Some(Duration::from_secs(3)), Duration::from_secs(3));
        let retired = retire_shims_at(&path).await;
        server.abort();
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert!(
            retired.is_ok(),
            "a slow shim refused the uninstall: {retired:?}"
        );
    }

    /// A shim that accepts and never says Hello still fails the retirement,
    /// at the step's hang guard.
    #[tokio::test(start_paused = true)]
    async fn a_silent_shim_still_fails_retirement() {
        let (path, server) = slow_shim(None, Duration::ZERO);
        let retired = retire_shims_at(&path).await;
        server.abort();
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert_eq!(
            retired.map_err(|error| error.kind()).err(),
            Some(io::ErrorKind::TimedOut)
        );
    }

    /// A session socket nobody listens on is a session already gone: on a
    /// root host the login revocation that precedes the uninstall kills the
    /// login's unit outright, and its shim never removes its socket (#409).
    /// Retirement removes that stale socket and succeeds, instead of
    /// refusing the whole uninstall with "Connection refused".
    #[tokio::test]
    async fn a_stale_session_socket_counts_as_retired_and_is_removed() {
        let directory = nix::unistd::mkdtemp("/tmp/rs-XXXXXX").unwrap();
        let path = directory.join("00000000000000000000000000000002.sock");
        // Binding and dropping the listener leaves the socket file behind,
        // exactly what a killed shim leaves.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let retired = retire_shims_at(&path).await;
        let left = path.exists();
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(
            retired.is_ok(),
            "a stale socket refused the uninstall: {retired:?}"
        );
        assert!(!left, "the stale socket stayed");
    }

    /// Only a real socket counts as stale: a regular file at a session's
    /// socket path still refuses retirement, and stays.
    #[tokio::test]
    async fn a_regular_file_at_a_session_path_still_refuses() {
        let directory = nix::unistd::mkdtemp("/tmp/rs-XXXXXX").unwrap();
        let path = directory.join("00000000000000000000000000000003.sock");
        std::fs::write(&path, b"not a socket").unwrap();
        let retired = retire_shims_at(&path).await;
        let left = path.exists();
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(retired.is_err());
        assert!(left);
    }

    /// Retires one shim the way `cleanup` does for each session socket.
    async fn retire_shims_at(path: &Path) -> io::Result<()> {
        retire_session(path, nix::unistd::Uid::effective().as_raw()).await
    }

    /// Hang guard for retiring the fake shim below (#334 rule). The test's
    /// claims are orders, enforced by the fake shim: the retirement signals
    /// again after a foreground job exits, and a partly read exit frame
    /// survives a signal tick. A retirement that stopped re-signalling would
    /// hang here, not pass. The product's own numbers live elsewhere: the
    /// 100 ms re-signal interval in `retire_shim` and its per-step hang bound
    /// `RETIRE_STEP_HANG`. A 1 s clock here asserted neither, and failed
    /// under a loaded gate (#355).
    const RETIREMENT_HANG: Duration = Duration::from_secs(60);

    /// Retiring a shim whose foreground job exits first keeps signalling
    /// until the restored shell has exited too, and it acknowledges that
    /// exit even when the exit frame arrives in two parts across a tick.
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
            RETIREMENT_HANG,
            retire_shim(&path, nix::unistd::Uid::effective().as_raw()),
        )
        .await;
        server.abort();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        let retired = result.expect("retirement hung: no exit acknowledged within the hang guard");
        assert!(retired.is_ok(), "retirement failed: {retired:?}");
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

    /// A delayed cleanup for A may finish as a no-op after B has committed, but it cannot claim B's install.
    #[test]
    fn promotion_cleanup_matches_only_its_committed_transaction() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "infraternal-promotion-transaction-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let transaction_a = uuid::Uuid::from_u128(0xa);
        let transaction_b = uuid::Uuid::from_u128(0xb);
        let marker = base.join(".bootstrap-transaction");
        std::fs::write(&marker, format!("{}\n", transaction_b.simple())).unwrap();
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();

        let uid = nix::unistd::geteuid().as_raw();
        assert!(!committed_transaction_matches(&base, transaction_a, uid).unwrap());
        assert!(committed_transaction_matches(&base, transaction_b, uid).unwrap());

        // A remains the last committed transaction while B is staged. A's
        // delayed cleanup must not treat the old marker as authority over B.
        std::fs::write(&marker, format!("{}\n", transaction_a.simple())).unwrap();
        let active = base.join(".bootstrap-lock/transaction");
        std::fs::create_dir_all(active.parent().unwrap()).unwrap();
        std::fs::write(&active, format!("{}\n", transaction_b.simple())).unwrap();
        assert!(!committed_transaction_matches(&base, transaction_a, uid).unwrap());

        std::fs::remove_dir_all(base).unwrap();
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
