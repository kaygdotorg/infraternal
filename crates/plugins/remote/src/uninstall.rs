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
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
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
    let base = if user {
        home.join(".local/share/infraternal")
    } else {
        PathBuf::from("/var/lib/infraternal")
    };
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
    })
}
fn public_file(path: &Path, uid: u32, max: u64) -> io::Result<String> {
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
    if !base.is_dir() || base.uid() != uid || base.mode() & 0o777 != 0o700 {
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

/// Enabled only for a checked managed remote installation, without an idle task.
pub struct UninstallPlugin {
    context: Context,
    home: PathBuf,
    uid: u32,
    // The service manager's transient-unit launcher. Tests substitute an inert
    // program so a handoff never starts a real unit on the build host.
    launcher: &'static str,
}
impl UninstallPlugin {
    /// # Errors
    /// Refuses a foreground or unrelated installation before registering its handler.
    pub fn new(context: Context, home: PathBuf, uid: u32) -> io::Result<Self> {
        // The service starts while bootstrap still holds its publication lock.
        // Register the owned handler now; every call and cleanup rechecks the
        // lock, so installation must finish before any removal is accepted.
        validate_artifacts(&context, &home, uid, false)?;
        Ok(Self {
            context,
            home,
            uid,
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
        if request.dry_run {
            return Ok(ActionReply {
                json: br#"{"state":"ready","owned":true}"#.to_vec(),
                after_write: None,
            });
        }
        let plan = serde_json::to_vec(&self.context).map_err(|_| PluginError::Rejected)?;
        // This runs on the synchronous plugin worker thread, which has no async
        // runtime (#235): start and feed the launcher with blocking process
        // primitives only. Nothing here may depend on an ambient reactor.
        let mut command = std::process::Command::new(self.launcher);
        infraternal_shim::prepare_child(&mut command);
        if self.uid != 0 {
            command.arg("--user");
        }
        // Private stdin is inherited by a separate transient service; it survives
        // the owned daemon's stop. A dropped writer closes it without any plan.
        let mut child = command
            .args([
                "--quiet",
                "--collect",
                "--pipe",
                "--wait",
                "--property=RuntimeMaxSec=30",
            ])
            .arg(std::env::current_exe().map_err(|_| PluginError::Rejected)?)
            .arg("--bootstrap-uninstall")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| PluginError::Rejected)?;
        let Some(stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(PluginError::Rejected);
        };
        let mut handoff = Handoff {
            child: Some(child),
            stdin: Some(stdin),
        };
        Ok(ActionReply {
            json: br#"{"state":"accepted","cleanup":"pending"}"#.to_vec(),
            after_write: Some(Box::new(move || handoff.deliver(&plan))),
        })
    }
}
/// The started launcher and its private plan pipe, owned until the reply is written.
///
/// Dropping it undelivered (the reply write failed) kills and reaps the launcher;
/// the helper then reads end-of-file instead of a plan and removes nothing.
struct Handoff {
    child: Option<std::process::Child>,
    stdin: Option<std::process::ChildStdin>,
}
impl Handoff {
    fn deliver(&mut self, plan: &[u8]) {
        use std::io::Write;
        // The plan is at most 8 KiB, below the kernel's minimum pipe capacity,
        // so this write completes without waiting for the helper to read.
        let Some(mut stdin) = self.stdin.take() else {
            return;
        };
        if stdin.write_all(plan).is_err() {
            return;
        }
        drop(stdin);
        // The launcher waits for the transient unit (at most RuntimeMaxSec);
        // reap it off the caller's thread. If no thread can start, the exited
        // launcher stays unreaped only until the helper stops this process.
        if let Some(mut child) = self.child.take() {
            let _ = std::thread::Builder::new()
                .name("uninstall-handoff".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}
impl Drop for Handoff {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
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
async fn manager(paths: &Layout, args: &[&str]) -> io::Result<()> {
    let mut command = Command::new("systemctl");
    infraternal_shim::prepare_child(command.as_std_mut());
    if paths.user {
        command.arg("--user");
    }
    let status = command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    if !status.success() {
        return Err(denied());
    }
    Ok(())
}
/// Execute the private plan only in the independent helper, revalidating ownership.
///
/// `retire_kernel` runs once the service is stopped and before any file is
/// removed, with the public state directory. It removes kernel objects that
/// outlive the daemon process (the mesh interface and packet filter), which this
/// crate does not own. A failure there stops cleanup with the files intact.
/// # Errors
/// Leaves unrelated artifacts untouched and refuses incomplete shell retirement, manager or kernel failure.
pub async fn cleanup(
    context: &Context,
    home: &Path,
    uid: u32,
    retire_kernel: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    validate(context, home, uid)?;
    let paths = layout(context, home, uid)?;
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
    retire_kernel(&context.sessions)?;
    std::fs::remove_file(&paths.unit)?;
    std::fs::remove_file(&paths.launcher)?;
    manager(&paths, &["daemon-reload"]).await?;
    std::fs::remove_dir_all(&paths.base)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut plugin = UninstallPlugin::new(context.clone(), home.clone(), uid);
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
        let mut plugin = UninstallPlugin::new(context.clone(), home.clone(), uid).unwrap();
        plugin.launcher = "true";
        let input =
            serde_json::to_vec(&serde_json::json!({"host":context.host,"dry_run":false})).unwrap();
        let worker = std::thread::spawn(move || {
            let reply = plugin.call_with_reply(crate::UNINSTALL.id, &input).unwrap();
            // The reply writer runs this after a successful write; it must not
            // need a runtime either, and dropping an unwritten reply is inert.
            reply.after_write.unwrap()();
            reply.json
        })
        .join();
        std::fs::remove_dir_all(home).unwrap();
        let json = worker.expect("the uninstall handoff panicked off the async runtime");
        assert_eq!(json, br#"{"state":"accepted","cleanup":"pending"}"#);
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
