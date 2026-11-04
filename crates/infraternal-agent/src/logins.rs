//! Starts or adopts deterministic person/account login units without an idle infraternal agent timer [D240,D247].
#![forbid(unsafe_code)]

use crate::sessions::Manager;
use nix::unistd::{Uid, User};
use std::{
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

/// Why a rootless host refused a login. A root host never produces either: it switches accounts, or falls back to
/// root when the person has none. The browser must tell these apart from every other `PermissionDenied` (a revoked
/// person, a worker owned by another account), because only these two mean "this server runs without root" (#327).
/// The error carries a type so the daemon never matches on message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootlessRefusal {
    /// The person's name is no account here, and a rootless host cannot fall back to root.
    NoMatchingLogin,
    /// The account exists but is not the one this infraternal agent runs as.
    OtherAccount,
}

impl std::fmt::Display for RootlessRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoMatchingLogin => "preferred account is absent on a rootless host",
            Self::OtherAccount => "rootless host cannot change account",
        })
    }
}

impl std::error::Error for RootlessRefusal {}

impl RootlessRefusal {
    fn denied(self) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, self)
    }

    /// The rootless refusal inside `error`, if it is one.
    pub(crate) fn of(error: &io::Error) -> Option<Self> {
        error.get_ref()?.downcast_ref::<Self>().copied()
    }
}

/// Resolve account names on the host, where its account database is authoritative.
/// # Errors
/// Rootless hosts refuse account switching and absent fallback identities.
pub fn account(preferred: &str) -> io::Result<(User, bool)> {
    if preferred
        .as_bytes()
        .first()
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'_' | b'-'))
        || preferred.len() > 64
        || !preferred
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid account name",
        ));
    }
    // D231 person names may begin with a dash. Such names cannot select a
    // host account; apply the ordinary missing-account fallback instead.
    let user = if preferred.starts_with('-') {
        None
    } else {
        User::from_name(preferred).map_err(io::Error::from)?
    };
    let fallback = user.is_none();
    let user = match user {
        Some(user) => user,
        None if Uid::effective().is_root() => User::from_uid(Uid::from_raw(0))
            .map_err(io::Error::from)?
            .ok_or_else(|| io::Error::other("root account absent"))?,
        None => {
            return Err(RootlessRefusal::NoMatchingLogin.denied());
        }
    };
    if !Uid::effective().is_root() && user.uid != Uid::effective() {
        return Err(RootlessRefusal::OtherAccount.denied());
    }
    Ok((user, fallback))
}

/// The owned person fence travels with a pending durable write, even if its caller drops.
pub(crate) type PersonGuard = nix::fcntl::Flock<std::fs::File>;

/// Hold the launch fence through the shell's durable reservation and readiness.
pub(crate) async fn rootless_launch_guard(
    state: &Path,
    person: uuid::Uuid,
) -> io::Result<PersonGuard> {
    let guard = acquire(state, &format!("{}.person", person.simple())).await?;
    permitted(state, person)?;
    Ok(guard)
}

async fn ready(endpoint: &Path, uid: u32) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut peer = UnixStream::connect(endpoint).await?;
        if peer.peer_cred()?.uid() != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "login worker account differs",
            ));
        }
        peer.write_all(b"?").await?;
        peer.shutdown().await?;
        let mut response = [0];
        peer.read_exact(&mut response).await?;
        if response != *b"R" {
            return Err(io::Error::other("invalid login worker readiness"));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Unit identity is independent of infraternal agent PID or version, so upgrades adopt the same login.
#[must_use]
pub fn name(person: uuid::Uuid, uid: u32) -> String {
    format!("infraternal-login-{}-{uid}", person.simple())
}

/// Open a host login or authenticate its existing worker before launching any terminal.
/// # Errors
/// Returns host manager, account, worker readiness or privilege failures.
/// `None` keeps the inherited own-account login on a rootless host [D18].
/// `state` is the infraternal agent's resolved state directory; see
/// [`runtime_root`] for where person locks and revocation markers live.
#[allow(clippy::too_many_lines)]
pub async fn ensure(
    exe: &Path,
    state: &Path,
    manager: Manager,
    person: uuid::Uuid,
    user: &User,
) -> io::Result<Option<PathBuf>> {
    let name = name(person, user.uid.as_raw());
    let root = runtime_root(state);
    // Serialize every account for a person against revocation. The tombstone
    // survives daemon restarts in the same runtime directory and fails closed.
    let _person = acquire(root, &format!("{}.person", person.simple())).await?;
    permitted(root, person)?;
    if !Uid::effective().is_root() {
        // The daemon already runs in the host-authenticated account context.
        // D18 allows only that account: asking su to authenticate it again
        // requires interactive credentials and breaks rootless terminals.
        if user.uid != Uid::effective() {
            return Err(RootlessRefusal::OtherAccount.denied());
        }
        return Ok(None);
    }
    let image =
        crate::login_binary::accessible(exe, Path::new("/var/cache/infraternal-login-bin")).await?;
    let exe = image.path();
    let _lock = acquire(root, &name).await?;
    let endpoint = root.join(&name).join("login.sock");
    match ready(&endpoint, user.uid.as_raw()).await {
        Ok(()) => {
            if !matches!(manager, Manager::System) {
                cgroup(&endpoint, manager, person, user.uid.as_raw()).await?;
            }
            return Ok(Some(endpoint));
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => return Err(error),
    }
    match manager {
        Manager::System => {}
        Manager::Detached | Manager::User => {
            // The launcher authenticates before releasing ownership. The
            // terminal admission path independently rechecks the returned worker.
            return fallback(exe, root, &name, &endpoint, person, user)
                .await
                .map(Some);
        }
    }
    // Only the system manager reaches this launch path. The exhaustive branch
    // above keeps user-manager/fallback flags out of this future's unit setup.
    let mut command = crate::sessions::isolated(Path::new("systemd-run"));
    command
        .args(
            [
                "--quiet",
                "--collect",
                "--pipe",
                "--service-type=exec",
                "--unit",
            ]
            .as_slice(),
        )
        .arg(&name);
    {
        command
            .arg("-p")
            .arg(format!("User={}", user.name))
            .args(["-p", "PAMName=login"].as_slice());
        let record =
            crate::login_records::identifier(Path::new("/run/infraternal-login-records"), &name)?;
        command
            .arg("-p")
            .arg(format!("UtmpIdentifier={record}"))
            .args(["-p", "UtmpMode=user", "-p", "StandardInput=null"].as_slice())
            .arg("-p")
            .arg(format!(
                "TTYPath=/dev/{}",
                crate::login_records::line(person, &record)
            ));
    }
    command
        .arg("-p")
        .arg(format!("RuntimeDirectory={name}"))
        .args(
            [
                "-p",
                "RuntimeDirectoryMode=0700",
                "-p",
                "KillMode=control-group",
            ]
            .as_slice(),
        )
        .arg("-p")
        .arg(format!("WorkingDirectory={}", user.dir.display()))
        .arg(exe)
        .args(
            [
                "__shim",
                "--login-worker",
                "--login-ready-fd",
                "1",
                "--session",
                &person.simple().to_string(),
                "--uid",
                &user.uid.as_raw().to_string(),
                "--login-socket",
            ]
            .as_slice(),
        )
        .arg(&endpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // The manager's unit-name fence handles racing cold opens. Its second
    // caller may see an exists status, then authenticates the original worker.
    let original = launch_identity(command, user.uid.as_raw()).await?;
    if let Some(mut identity) = original {
        let peer = UnixStream::connect(&endpoint).await?;
        let credentials = peer.peer_cred()?;
        if credentials.uid() != user.uid.as_raw()
            || credentials.pid() != Some(identity.pid)
            || !identity.alive()
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        set_group(&mut identity)?;
        crate::login_auth::remember(person, user.uid.as_raw(), identity);
        // The original announcement is emitted only after account setup,
        // endpoint binding and signal readiness. Socket credentials and the
        // live process pin above authenticate that completed initialization;
        // another readiness exchange cannot add a stronger startup proof.
        // Adoption without an original announcement still takes the loop below.
        return Ok(Some(endpoint));
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ready(&endpoint, user.uid.as_raw()).await {
                Ok(()) => return Ok(Some(endpoint.clone())),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

// The manager passes this root controller's original socket to the exact
// immutable worker executable. The worker transfers its own process inode:
// a dead announcement can never resolve to a later reused numeric PID.
async fn launch_identity(
    mut command: tokio::process::Command,
    uid: u32,
) -> io::Result<Option<crate::login_auth::Identity>> {
    let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    command.stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)));
    let reader = UnixStream::from_std(reader)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut child = command.spawn()?;
        // Command retains configured Stdio after spawn. Release our writer so
        // an unsuccessful launcher produces EOF and takes authenticated adoption.
        drop(command);
        let result = loop {
            reader.readable().await?;
            match reader.try_io(tokio::io::Interest::READABLE, || {
                infraternal_shim::login_ready::receive(&reader)
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => break result,
            }
        };
        let (ready, process) = match result {
            Err(error)
                if error.kind() == io::ErrorKind::UnexpectedEof
                    && !child.wait().await?.success() =>
            {
                // The unit-name fence rejects racing launchers. Authenticate
                // the existing worker through manager MainPID adoption instead.
                return Ok(None);
            }
            result => result?,
        };
        if ready.uid != uid {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let identity = crate::login_auth::Identity {
            pid: ready.pid,
            process: std::sync::Arc::new(process),
            group: PathBuf::new(),
            parent: None,
        };
        if !identity.alive() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Reap only the launcher; the host manager retains the PAM lifetime.
        child.kill().await?;
        Ok(Some(identity))
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Authenticate the worker against its root-created unit before placing the PTY owner in that login scope.
/// # Errors
/// Refuses an account-created replacement endpoint or a malformed kernel cgroup path.
pub(crate) async fn cgroup(
    endpoint: &Path,
    manager: Manager,
    person: uuid::Uuid,
    uid: u32,
) -> io::Result<Option<crate::login_auth::Identity>> {
    let peer = UnixStream::connect(endpoint).await?;
    let credentials = peer.peer_cred()?;
    if credentials.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "login worker account differs",
        ));
    }
    peer.writable().await?;
    let mut peer = peer;
    peer.write_all(b"?").await?;
    peer.shutdown().await?;
    let mut ready = [0];
    peer.read_exact(&mut ready).await?;
    if ready != *b"R" {
        return Err(io::Error::other("invalid login readiness"));
    }
    let pid = credentials
        .pid()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::other("login worker pid absent"))?;
    if let Some(identity) = crate::login_auth::get(person, uid, pid) {
        return Ok(Some(identity));
    }
    let mut identity = crate::login_auth::pin(pid, PathBuf::new())?;
    if !matches!(manager, Manager::System) {
        crate::login_auth::fallback(&mut identity, person, uid, endpoint)?;
        crate::login_auth::remember(person, uid, identity.clone());
        return Ok(Some(identity));
    }
    let unit = format!("{}.service", name(person, uid));
    let mut command = crate::sessions::isolated(Path::new("systemctl"));
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        command
            .args(["show", "--property=MainPID", "--value", &unit].as_slice())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if !output.status.success()
        || output.stdout.len() > 32
        || std::str::from_utf8(&output.stdout)
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok())
            != Some(pid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "login endpoint is not the host login unit",
        ));
    }
    set_group(&mut identity)?;
    crate::login_auth::remember(person, uid, identity.clone());
    Ok(Some(identity))
}

fn set_group(identity: &mut crate::login_auth::Identity) -> io::Result<()> {
    let record = std::fs::read_to_string(identity.path().join("cgroup"))?;
    let path = record
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("host login path needs a unified cgroup"))?;
    if !path.starts_with('/') || path.split('/').any(|part| matches!(part, "." | "..")) {
        return Err(io::Error::other("invalid login cgroup"));
    }
    identity.group = Path::new("/sys/fs/cgroup")
        .join(path.trim_start_matches('/'))
        .join("cgroup.procs");
    if !identity.alive() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    Ok(())
}

/// Directory that holds the person locks, revocation markers and (as root)
/// the login endpoints.
///
/// As root, login units are host-wide service manager objects whose
/// `RuntimeDirectory=` lives under `/run`, so their registry is host-wide too:
/// two root daemons with different state directories still share one login per
/// person and account, and must see the same revocation markers.
///
/// Rootless, the registry belongs to this infraternal agent's state directory,
/// which `sessions::state` has already resolved (an explicit `--state` wins,
/// otherwise `$XDG_RUNTIME_DIR/infraternal`) and validated as private 0700. It
/// never reads the environment again, so an explicit state works without
/// `XDG_RUNTIME_DIR`, and open, revoke and restore always agree on one place.
fn runtime_root(state: &Path) -> &Path {
    if Uid::effective().is_root() {
        Path::new("/run")
    } else {
        state
    }
}

fn permitted(root: &Path, person: uuid::Uuid) -> io::Result<()> {
    let marker = root
        .join("infraternal-login-locks")
        .join(format!("{}.revoked", person.simple()));
    match std::fs::symlink_metadata(marker) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "person's host login access was revoked",
        )),
    }
}

/// Restore access only at the trusted server's explicit authority transition.
/// # Errors
/// Refuses unsafe marker or registry objects; ordinary opens never restore access.
pub async fn restore(state: &Path, person: uuid::Uuid) -> io::Result<()> {
    restore_at(runtime_root(state), person).await
}

/// Serialize access restoration, retaining its fence until directory durability completes.
async fn restore_at(root: &Path, person: uuid::Uuid) -> io::Result<()> {
    let person_guard = acquire(root, &format!("{}.person", person.simple())).await?;
    let root = root.to_owned();
    tokio::task::spawn_blocking(move || {
        let _person = person_guard;
        restore_marker(&root, person)
    })
    .await
    .map_err(io::Error::other)?
}

/// Remove only a validated marker, then make that removal durable before restoring access.
fn restore_marker(root: &Path, person: uuid::Uuid) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let registry = root.join("infraternal-login-locks");
    let marker = registry.join(format!("{}.revoked", person.simple()));
    let metadata = match std::fs::symlink_metadata(&marker) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        result => result?,
    };
    if !metadata.is_file()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe login revocation marker",
        ));
    }
    // Serialize with both open and cleanup. A successful restore removes only
    // this person's validated marker, never a symlink target or another person.
    #[cfg(test)]
    crate::durable_tests::hold(root);
    std::fs::remove_file(marker)?;
    std::fs::File::open(registry)?.sync_all()
}

/// End a person's host logins and refuse later opens, including across daemon restarts.
/// Login access restoration is a separate authority operation and is not implied by reconnect.
/// # Errors
/// Refuses unsafe registry paths or workers, and reports host cleanup failures.
pub async fn revoke(state: &Path, manager: Manager, person: uuid::Uuid) -> io::Result<()> {
    revoke_at(
        runtime_root(state),
        manager,
        person,
        !Uid::effective().is_root(),
    )
    .await
}

/// Save the refusal before shell cleanup, keeping one person fence through both stages.
async fn revoke_at(
    root: &Path,
    manager: Manager,
    person: uuid::Uuid,
    rootless: bool,
) -> io::Result<()> {
    let person_guard = acquire(root, &format!("{}.person", person.simple())).await?;
    let state = root.to_owned();
    // The task owns the fence, so cancellation cannot let a later authority
    // transition overtake the file or directory fsync. Return it for cleanup.
    let person_guard = tokio::task::spawn_blocking(move || {
        revoke_marker(&state, person)?;
        Ok::<_, io::Error>(person_guard)
    })
    .await
    .map_err(io::Error::other)??;
    let registry = root.join("infraternal-login-locks");
    if rootless {
        return crate::rootless_sessions::revoke(root, person, Some(person_guard)).await;
    }
    let prefix = format!("infraternal-login-{}-", person.simple());
    let mut failure = None;
    for entry in std::fs::read_dir(&registry)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(uid) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".lock"))
        else {
            continue;
        };
        let uid = uid.parse::<u32>().map_err(io::Error::other)?;
        let unit = self::name(person, uid);
        let _account = acquire(root, &unit).await?;
        if let Err(error) = stop_login(root, manager, person, uid, &unit).await {
            failure = Some(error);
        }
    }
    crate::login_auth::forget(person);
    failure.map_or(Ok(()), Err)
}

/// Validate and durably publish a person's refusal before any shell is stopped.
fn revoke_marker(root: &Path, person: uuid::Uuid) -> io::Result<()> {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let registry = root.join("infraternal-login-locks");
    let marker = registry.join(format!("{}.revoked", person.simple()));
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(marker)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != Uid::effective().as_raw()
        || meta.mode() & 0o777 != 0o600
        || meta.len() != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe login revocation marker",
        ));
    }
    #[cfg(test)]
    crate::durable_tests::hold(root);
    file.sync_all()?;
    std::fs::File::open(&registry)?.sync_all()?;
    Ok(())
}

async fn request_stop(
    endpoint: &Path,
    uid: u32,
    expected: Option<&crate::login_auth::Identity>,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (mut peer, dedicated) = match UnixStream::connect(endpoint.with_extension("stop")).await
        {
            Ok(peer) => (peer, true),
            Err(error) if crate::sessions::gone(&error) => {
                (UnixStream::connect(endpoint).await?, false)
            }
            Err(error) => return Err(error),
        };
        let credentials = peer.peer_cred()?;
        if credentials.uid() != uid
            || expected.is_some_and(|identity| {
                credentials.pid() != Some(identity.pid) || !identity.alive()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "login stop worker identity differs",
            ));
        }
        peer.write_all(b"!").await?;
        if !dedicated {
            peer.shutdown().await?;
        }
        let mut response = [0];
        peer.read_exact(&mut response).await?;
        if response != *b"S" {
            return Err(io::Error::other("login worker refused stop"));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

async fn stop_login(
    root: &Path,
    manager: Manager,
    person: uuid::Uuid,
    uid: u32,
    unit: &str,
) -> io::Result<()> {
    let endpoint = root.join(unit).join("login.sock");
    let scope = tokio::time::timeout(
        Duration::from_secs(3),
        cgroup(&endpoint, manager, person, uid),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
    let scope = match scope {
        Ok(scope) => scope,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let stopped = request_stop(&endpoint, uid, scope.as_ref()).await;
    if let Some(identity) = &scope
        && !identity.group.as_os_str().is_empty()
    {
        let path = &identity.group;
        // The kernel-backed MainPID check authenticated this exact login scope.
        // Root PTY owners are siblings of the worker, so child cleanup alone
        // cannot retire retained terminal shims immediately on revoked access.
        let kill = path
            .parent()
            .ok_or_else(|| io::Error::other("login cgroup parent absent"))?
            .join("cgroup.kill");
        match std::fs::write(kill, b"1") {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if path.parent().is_some_and(Path::exists) {
                    return Err(io::Error::other(
                        "host login cgroup lacks immediate cleanup",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    if matches!(manager, Manager::System) {
        let unit = format!("{unit}.service");
        let mut show = crate::sessions::isolated(Path::new("systemctl"));
        let output = tokio::time::timeout(
            Duration::from_secs(2),
            show.args(["show", "--property=LoadState", "--value", &unit].as_slice())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let load = std::str::from_utf8(&output.stdout).ok().map(str::trim);
        if output.stdout.len() > 32 || (!output.status.success() && load != Some("not-found")) {
            return Err(io::Error::other("host login unit state unavailable"));
        }
        // Collected transient units leave their private account lock as history.
        // Repeated access removal must not fail merely because cleanup already
        // unloaded that unit; an existing unit still gets an explicit stop.
        if load != Some("not-found") {
            let mut command = crate::sessions::isolated(Path::new("systemctl"));
            let status = tokio::time::timeout(
                Duration::from_secs(5),
                command
                    .args(["stop", &unit].as_slice())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .status(),
            )
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            if !status.success() {
                return Err(io::Error::other("host login unit refused stop"));
            }
        }
    }
    match stopped {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(())
        }
        Err(_) if matches!(manager, Manager::System) && scope.is_some() => Ok(()),
        Err(error) => Err(error),
    }
}

async fn acquire(root: &Path, name: &str) -> io::Result<nix::fcntl::Flock<std::fs::File>> {
    use std::{
        fs::{self, DirBuilder, OpenOptions},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    let directory = root.join("infraternal-login-locks");
    match DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(&directory)?;
    if !meta.is_dir() || meta.uid() != Uid::effective().as_raw() || meta.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe login lock directory",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(directory.join(format!("{name}.lock")))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != Uid::effective().as_raw() || meta.mode() & 0o777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe login lock file",
        ));
    }
    // Kernel locks release on abrupt process exit. A per-login lock prevents a
    // refused stale endpoint check from unlinking a newly listening fallback.
    // Waiting must not occupy Tokio's bounded blocking pool: otherwise many
    // opens behind one person's lock can starve unrelated cleanup. There is no
    // flock readiness descriptor. Only active contention retries, and dropping
    // the future closes its handle immediately; idle logins have no timer.
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut file = file;
        loop {
            match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
                Ok(lock) => return Ok(lock),
                Err((returned, nix::errno::Errno::EWOULDBLOCK)) => {
                    file = returned;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err((_, error)) => return Err(io::Error::from(error)),
            }
        }
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// The utility argv is a public identity binding, shared with fallback adoption checks.
pub(crate) fn fallback_script(
    executable: &str,
    endpoint: &Path,
    person: uuid::Uuid,
    uid: u32,
    controller: u32,
) -> io::Result<String> {
    let endpoint = endpoint
        .to_str()
        .ok_or_else(|| io::Error::other("login endpoint is not UTF-8"))?;
    Ok(format!(
        "exec {} __shim --login-worker --controller-uid {controller} --session {} --uid {uid} --login-socket {}",
        quoted(executable),
        person.simple(),
        quoted(endpoint)
    ))
}

// Pending launch ownership is distinct from the adopted long-lived login.
// Cancellation must let the host login utility run its own session cleanup,
// rather than abruptly abandoning or killing only its PAM-owning parent.
struct PendingLogin(Option<tokio::process::Child>);
impl PendingLogin {
    fn child(&mut self) -> io::Result<&mut tokio::process::Child> {
        self.0
            .as_mut()
            .ok_or_else(|| io::Error::other("pending login already released"))
    }
    fn release(&mut self) -> io::Result<tokio::process::Child> {
        self.0
            .take()
            .ok_or_else(|| io::Error::other("pending login already released"))
    }
}
impl Drop for PendingLogin {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if !matches!(
                    tokio::time::timeout(Duration::from_secs(3), child.wait()).await,
                    Ok(Ok(_))
                ) {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                }
            });
        } else {
            // Startup cancellation normally happens inside the daemon reactor.
            // Still refuse to retain a launcher if shutdown has removed it.
            let _ = child.start_kill();
        }
    }
}

async fn fallback(
    exe: &Path,
    root: &Path,
    name: &str,
    endpoint: &Path,
    person: uuid::Uuid,
    user: &User,
) -> io::Result<PathBuf> {
    use std::{
        fs::{self, DirBuilder, File},
        os::unix::{
            fs::{DirBuilderExt, MetadataExt},
            process::CommandExt,
        },
    };
    let directory = root.join(name);
    match DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {
            let file = File::open(&directory)?;
            if Uid::effective().is_root() {
                nix::unistd::fchown(&file, Some(user.uid), Some(user.gid))
                    .map_err(io::Error::from)?;
            }
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(&directory)?;
    if !meta.is_dir() || meta.uid() != user.uid.as_raw() || meta.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe fallback login directory",
        ));
    }
    match fs::symlink_metadata(endpoint) {
        Ok(meta)
            if std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type())
                && meta.uid() == user.uid.as_raw() =>
        {
            fs::remove_file(endpoint)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe fallback login endpoint",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut command = crate::sessions::isolated(Path::new("su"));
    let executable = exe
        .to_str()
        .ok_or_else(|| io::Error::other("login executable is not UTF-8"))?;
    let script = fallback_script(
        executable,
        endpoint,
        person,
        user.uid.as_raw(),
        Uid::effective().as_raw(),
    )?;
    command
        .args(["--login", "--shell", "/bin/sh", "--command"].as_slice())
        .arg(script)
        .arg("--")
        .arg(&user.name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Host policy decides whether this local login is permitted. Never feed an
    // auth prompt or substitute a bare uid change if su refuses the session.
    // Keep the host login utility out of the daemon's foreground group.
    // The utility still decides how its PAM child/session is established.
    command.as_std_mut().process_group(0);
    let mut pending = PendingLogin(Some(command.spawn()?));
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if pending.child()?.try_wait()?.is_some() {
                return Err(io::Error::other("host login path refused the account"));
            }
            if ready(endpoint, user.uid.as_raw()).await.is_ok() {
                return Ok(endpoint.to_path_buf());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)));
    // Keep utility ownership until identity authentication has completed. A
    // failed pin/parent check must close the newly opened host PAM login too.
    let result = match result {
        Ok(endpoint) => cgroup(&endpoint, Manager::Detached, person, user.uid.as_raw())
            .await
            .map(|_| endpoint),
        Err(error) => Err(error),
    };
    if result.is_ok() {
        let mut child = pending.release()?;
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
    }
    result
}

#[cfg(test)]
mod tests {
    //! Person identity remains distinct even when the OS account is shared.
    use super::*;
    #[tokio::test]
    async fn unsuccessful_launch_releases_writer_and_takes_adoption() {
        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", "exit 1"]);
        assert!(launch_identity(command, 0).await.unwrap().is_none());
    }
    #[tokio::test]
    async fn successful_launcher_without_original_worker_record_is_not_login_success() {
        // Asynchronous unit admission can succeed before PAM or exec refuses.
        // A zero launcher status cannot substitute for the original descriptor.
        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", "exit 0"]);
        assert_eq!(
            launch_identity(command, 0)
                .await
                .err()
                .expect("launcher status substituted for worker identity")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    #[tokio::test]
    async fn fallback_refuses_a_same_account_socket_without_a_host_login_parent() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/rl3/fake-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let endpoint = root.join("login.sock");
        let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = [0];
            peer.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"?");
            peer.write_all(b"R").await.unwrap();
        });
        let result = cgroup(
            &endpoint,
            Manager::Detached,
            uuid::Uuid::new_v4(),
            Uid::effective().as_raw(),
        )
        .await;
        server.abort();
        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(
            result
                .err()
                .expect("fake same-account listener was adopted")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn login_fences_do_not_wait_for_shared_blocking_pool_capacity() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/real-logins")
                .join(format!("lock-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&root).unwrap();
            let (release, held) = std::sync::mpsc::channel();
            let (entered, ready) = tokio::sync::oneshot::channel();
            let blocker = runtime.spawn_blocking(move || {
                entered.send(()).unwrap();
                held.recv().unwrap();
            });
            ready.await.unwrap();
            let result =
                tokio::time::timeout(Duration::from_secs(1), acquire(&root, "independent.person"))
                    .await;
            // Always release the idle fixture thread before asserting, including
            // on the pre-fix failure, so runtime teardown cannot wait forever.
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert!(
                result.is_ok(),
                "an unheld login fence waited behind the shared blocking pool"
            );
            drop(result.unwrap().unwrap());
            std::fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn revoke_waits_for_person_lock_and_refuses_linked_tombstones() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
                ".cache/codex-scratch/rl3/revoke-lock-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let person = uuid::Uuid::new_v4();
            let lock = acquire(&root, &format!("{}.person", person.simple()))
                .await
                .unwrap();
            let path = root.clone();
            let task =
                tokio::spawn(
                    async move { revoke_at(&path, Manager::Detached, person, false).await },
                );
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(permitted(&root, person).is_ok());
            drop(lock);
            task.await.unwrap().unwrap();
            assert!(permitted(&root, person).is_err());
            let target = root.join("fixture");
            std::fs::write(&target, b"fixture").unwrap();
            let other = uuid::Uuid::new_v4();
            std::os::unix::fs::symlink(
                &target,
                root.join("infraternal-login-locks")
                    .join(format!("{}.revoked", other.simple())),
            )
            .unwrap();
            assert!(
                revoke_at(&root, Manager::Detached, other, false)
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(target).unwrap(), b"fixture");
            std::fs::remove_dir_all(root).unwrap();
        });
    }

    #[tokio::test]
    async fn explicit_restoration_clears_only_the_validated_person_marker() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/rl3/restore-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let person = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        revoke_at(&root, Manager::Detached, person, false)
            .await
            .unwrap();
        revoke_at(&root, Manager::Detached, other, false)
            .await
            .unwrap();
        assert!(permitted(&root, person).is_err());
        restore_at(&root, person).await.unwrap();
        permitted(&root, person).unwrap();
        assert!(permitted(&root, other).is_err());
        restore_at(&root, person).await.unwrap();
        let marker = root
            .join("infraternal-login-locks")
            .join(format!("{}.revoked", person.simple()));
        let target = root.join("untouched");
        std::fs::write(&target, b"fixture").unwrap();
        std::os::unix::fs::symlink(&target, &marker).unwrap();
        assert!(restore_at(&root, person).await.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"fixture");
        std::fs::remove_file(marker).unwrap();
        std::fs::write(
            root.join("infraternal-login-locks")
                .join(format!("{}.revoked", person.simple())),
            b"invalid",
        )
        .unwrap();
        assert!(restore_at(&root, person).await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revoke_latches_every_account_and_survives_a_new_open_check() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
                ".cache/codex-scratch/rl3/revoke-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let person = uuid::Uuid::new_v4();
            permitted(&root, person).unwrap();
            revoke_at(&root, Manager::Detached, person, false)
                .await
                .unwrap();
            assert_eq!(
                permitted(&root, person).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(permitted(&root, uuid::Uuid::new_v4()).is_ok());
            // A repeat is idempotent and reads the same persisted tombstone.
            revoke_at(&root, Manager::Detached, person, false)
                .await
                .unwrap();
            std::fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn cancelling_pending_launch_terminates_and_reaps_the_launcher() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut command = tokio::process::Command::new("/bin/sleep");
            command
                .arg("300")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let child = command.spawn().unwrap();
            let pid = child.id().unwrap();
            drop(PendingLogin(Some(child)));
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            let mut gone = false;
            while std::time::Instant::now() < deadline {
                if !Path::new(&format!("/proc/{pid}")).exists() {
                    gone = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            if !gone {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            assert!(gone, "cancelled pending login launcher was retained");
        });
    }

    /// Shadow review #172: a rootless infraternal agent may only open its own
    /// account (D18, contracts/shim.md). Before this branch that worked with no
    /// authentication. Now every person open goes through `su --login` to the
    /// agent's own account. Standard su PAM stacks allow that without a password
    /// only for root (`pam_rootok`), so on such a host every rootless terminal
    /// is refused. The fixture `su` reproduces that refusal without making a
    /// real authentication attempt on the review host.
    #[test]
    fn rootless_self_account_login_does_not_depend_on_su_authentication() {
        const FIXTURE: &str = "INFRATERNAL_SHADOW_ROOTLESS_FIXTURE";
        if Uid::effective().is_root() {
            eprintln!("SKIP rootless fixture: runs only as a non-root account");
            return;
        }
        if std::env::var_os(FIXTURE).is_none() {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
                ".cache/codex-scratch/shadow-real-logins/rootless-{}",
                std::process::id()
            ));
            let bin = root.join("bin");
            // Unix socket paths are short; /run/user/UID is in production.
            let runtime = PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(format!(".cache/srl{}", std::process::id()));
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::create_dir_all(&runtime).unwrap();
            std::fs::set_permissions(
                &runtime,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let su = bin.join("su");
            std::fs::write(
                &su,
                "#!/bin/sh\n# Host policy: non-root su needs a password; stdin is /dev/null.\n\
                 echo 'su: Authentication failure' >&2\nexit 1\n",
            )
            .unwrap();
            std::fs::set_permissions(&su, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();
            let path = format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "logins::tests::rootless_self_account_login_does_not_depend_on_su_authentication",
                    "--nocapture",
                ])
                .env(FIXTURE, "1")
                .env("PATH", path)
                .env("XDG_RUNTIME_DIR", &runtime)
                .output()
                .unwrap();
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&runtime);
            assert!(
                output.status.success(),
                "rootless self-account open failed:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let me = User::from_uid(Uid::effective()).unwrap().unwrap();
            // The server's default preferred account is the person's own name;
            // here it matches the agent's account, the only one it may open.
            let (user, fallback_used) = account(&me.name).unwrap();
            assert!(!fallback_used);
            // Default resolution, as the daemon does without --state.
            let state = crate::sessions::state(None).unwrap();
            let result = ensure(
                &std::env::current_exe().unwrap(),
                &state,
                Manager::Detached,
                uuid::Uuid::new_v4(),
                &user,
            )
            .await;
            assert!(
                result.is_ok(),
                "rootless agent refused its own account: {:?}",
                result.err()
            );
        });
    }

    #[test]
    fn leading_dash_username_uses_missing_account_fallback() {
        let result = account("-missing-infraternal-account");
        if Uid::effective().is_root() {
            let (user, fallback) = result.unwrap();
            assert!(fallback);
            assert!(user.uid.is_root());
        } else {
            // Rootless hosts cannot fall back to root, but username syntax is
            // valid: report the absent account instead of InvalidInput.
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn login_identity_is_stable_and_never_shared_between_people() {
        let person = uuid::Uuid::from_u128(1);
        assert_eq!(name(person, 1000), name(person, 1000));
        assert_ne!(name(person, 1000), name(uuid::Uuid::from_u128(2), 1000));
        assert_ne!(name(person, 1000), name(person, 1001));
        assert!(account("--root").is_err());
        assert!(account("bad/account").is_err());
    }
}

#[cfg(test)]
mod durable_tests {
    //! Held durable writes must leave the shared reactor available to other work.
    use super::*;

    /// Revocation cannot reply before its held marker write finishes.
    #[tokio::test]
    async fn login_durable_writes_leave_the_reactor_responsive() {
        let root = crate::durable_tests::directory();
        let person = uuid::Uuid::new_v4();
        crate::durable_tests::responsive(root.clone(), {
            let root = root.clone();
            async move { revoke_at(&root, Manager::Detached, person, false).await }
        })
        .await
        .unwrap();
        assert!(permitted(&root, person).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Restoring access must leave the reactor free until directory durability completes.
    #[tokio::test]
    async fn restore_durable_write_leaves_the_reactor_responsive() {
        let root = crate::durable_tests::directory();
        let person = uuid::Uuid::new_v4();
        revoke_at(&root, Manager::Detached, person, false)
            .await
            .unwrap();
        crate::durable_tests::responsive(root.clone(), {
            let root = root.clone();
            async move { restore_at(&root, person).await }
        })
        .await
        .unwrap();
        permitted(&root, person).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A later open or restore cannot overtake a cancelled revocation write.
    #[tokio::test]
    async fn cancelled_durable_write_keeps_the_person_fenced() {
        let root = crate::durable_tests::directory();
        let person = uuid::Uuid::new_v4();
        let lock = root
            .join("infraternal-login-locks")
            .join(format!("{}.person.lock", person.simple()));
        crate::durable_tests::cancellation_keeps_fence(
            root.clone(),
            {
                let root = root.clone();
                async move { revoke_at(&root, Manager::Detached, person, false).await }
            },
            lock.clone(),
        )
        .await;
        // Join actual disk completion without the production lock-acquisition
        // deadline: this test checks ordering even on a very busy filesystem.
        drop(
            tokio::task::spawn_blocking(move || {
                nix::fcntl::Flock::lock(
                    std::fs::File::open(lock).unwrap(),
                    nix::fcntl::FlockArg::LockExclusive,
                )
                .unwrap()
            })
            .await
            .unwrap(),
        );
        assert!(permitted(&root, person).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
