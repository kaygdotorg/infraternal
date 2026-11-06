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

/// A worker owns this fence once its durable write starts; cancelled waiters release it.
pub(crate) type PersonGuard = nix::fcntl::Flock<std::fs::File>;

/// The UID of an existing account on this host, for login access checks
/// [D235]. An account the database does not know, or a failed lookup, is `None`.
#[must_use]
pub fn account_uid(name: &str) -> Option<u32> {
    User::from_name(name)
        .ok()
        .flatten()
        .map(|user| user.uid.as_raw())
}

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

/// Positive authority is deliberately process-local: a restarted daemon begins
/// closed until the trusted server resends an authorized login request. Disk
/// marker absence alone is never authority. Bound retained grants across roots.
static AUTHORIZED: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<(PathBuf, uuid::Uuid)>>,
> = std::sync::LazyLock::new(std::sync::Mutex::default);

/// Apply the trusted server's current positive authority without clearing refusals.
/// Call only for a server-authorized open/prepare or an explicit durable restore.
/// No grant survives process exit, so an unconfirmed revocation cannot be lost
/// into implicit permission when the daemon restarts before saving its marker.
pub(crate) fn synchronize(state: &Path, person: uuid::Uuid) -> io::Result<()> {
    synchronize_at(runtime_root(state), person)
}

/// Publish a bounded grant only when neither pending nor persisted refusal exists.
pub(crate) fn synchronize_at(root: &Path, person: uuid::Uuid) -> io::Result<()> {
    not_refused(root, person)?;
    let mut grants = AUTHORIZED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = (root.to_owned(), person);
    if grants.len() >= 10_000 && !grants.contains(&key) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    grants.insert(key);
    Ok(())
}

/// Require a current server grant as well as the absence of every refusal.
fn permitted(root: &Path, person: uuid::Uuid) -> io::Result<()> {
    if !AUTHORIZED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&(root.to_owned(), person))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host login authority has not been synchronized with the server",
        ));
    }
    not_refused(root, person)
}

/// Deny retained revocation intent before consulting the durable authority markers.
fn not_refused(root: &Path, person: uuid::Uuid) -> io::Result<()> {
    if revocations::denied(root, person) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host login revocation is pending or host access is denied",
        ));
    }
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
/// Refuses unsafe marker or registry objects and pending person revocations;
/// ordinary opens never restore access.
/// Returns `WouldBlock` when the durable queue is full, before opening a fence.
pub async fn restore(state: &Path, person: uuid::Uuid) -> io::Result<()> {
    restore_at(runtime_root(state), person).await
}

/// Admit restoration before opening its fence and retain it through an executing sync.
async fn restore_at(root: &Path, person: uuid::Uuid) -> io::Result<()> {
    if revocations::denied(root, person) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host login revocation must finish before restoration",
        ));
    }
    let admission = crate::durable_io::admit()?;
    let person_guard = acquire(root, &format!("{}.person", person.simple())).await?;
    let root = root.to_owned();
    let restored = root.clone();
    admission
        .run(move || {
            let _person = person_guard;
            restore_marker(&root, person)
        })
        .await?
        .0?;
    synchronize_at(&restored, person)
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
/// Denies access in memory before waiting for disk. Errors reach the caller while
/// a bounded owner retries independently of caller lifetime and ordinary saves.
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
    revocations::submit(root, manager, person, rootless).await
}

/// Try one reserved revocation; its owner retains denial and retries any failure.
async fn revoke_once(
    root: &Path,
    manager: Manager,
    person: uuid::Uuid,
    rootless: bool,
) -> io::Result<()> {
    let admission = crate::durable_io::security().await?;
    let person_guard = acquire(root, &format!("{}.person", person.simple())).await?;
    let state = root.to_owned();
    // The bounded revocation owner outlives callers and retains this fence
    // through marker durability, including after a caller has received an error.
    let (person_guard, admission) = admission
        .run(move || {
            revoke_marker(&state, person)?;
            Ok::<_, io::Error>(person_guard)
        })
        .await?;
    let person_guard = person_guard?;
    let registry = root.join("infraternal-login-locks");
    if rootless {
        return crate::rootless_sessions::revoke(root, person, Some(person_guard), admission).await;
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
    save_refusal(root, &format!("{}.revoked", person.simple()))
}

/// Publish a validated refusal inode and sync both it and its registry.
fn save_refusal(root: &Path, name: &str) -> io::Result<()> {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let registry = root.join("infraternal-login-locks");
    let marker = registry.join(name);
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

/// Persist person refusals in a reserved lane while preserving immediate denial.
#[path = "revocations.rs"]
mod revocations;

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

/// Stops one person's host login for account `uid` (`unit`).
///
/// With the system manager, the unit is ended through systemd alone
/// ([`stop_unit`]). The login worker runs as the revoked account, which can
/// freeze or ptrace it, so revocation must not depend on its answers (J261
/// P1/P2, #355). Without a system manager there is no unit and the worker is
/// the only handle: it is authenticated and asked to stop its shells, under
/// short bounds, because its silence is the account's choice, not a slow host.
async fn stop_login(
    root: &Path,
    manager: Manager,
    person: uuid::Uuid,
    uid: u32,
    unit: &str,
) -> io::Result<()> {
    if matches!(manager, Manager::System) {
        return stop_unit(unit).await;
    }
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
    match request_stop(&endpoint, uid, scope.as_ref()).await {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Hang guard for one `systemctl show` query. systemd is a peer whose
/// progress we trust, so this only detects a manager that never answers; a
/// slow host makes the query slow, not wrong (#355).
const SYSTEMD_QUERY_HANG: Duration = Duration::from_secs(60);

/// Hang guard for `systemctl stop`. systemd itself escalates a unit that
/// ignores its stop signal to SIGKILL after the unit's stop timeout (90 s by
/// default), so this stays above that escalation and only detects a manager
/// that never answers (#355).
const UNIT_STOP_HANG: Duration = Duration::from_secs(180);

#[cfg(test)]
thread_local! {
    /// Test-only stand-ins for the `systemctl` program and the cgroup
    /// filesystem root, so `stop_unit` runs against a scripted manager.
    static HOST_UNITS: std::cell::RefCell<Option<(PathBuf, PathBuf)>> =
        const { std::cell::RefCell::new(None) };
}

/// A `systemctl` command, isolated like every host-manager child.
fn systemctl() -> tokio::process::Command {
    #[cfg(test)]
    if let Some((program, _)) = HOST_UNITS.with(|units| units.borrow().clone()) {
        return crate::sessions::isolated(&program);
    }
    crate::sessions::isolated(Path::new("systemctl"))
}

/// Root of the unified cgroup hierarchy that systemd's `ControlGroup` paths
/// are relative to.
fn cgroup_root() -> PathBuf {
    #[cfg(test)]
    if let Some((_, root)) = HOST_UNITS.with(|units| units.borrow().clone()) {
        return root;
    }
    PathBuf::from("/sys/fs/cgroup")
}

/// What systemd reports about one unit.
struct UnitState {
    /// `LoadState`: `not-found` once a transient unit has been collected.
    load: String,
    /// `ActiveState`: `inactive` or `failed` once the unit has stopped.
    active: String,
    /// `ControlGroup`, relative to [`cgroup_root`]; empty when it has none.
    control_group: String,
}

/// Asks systemd for `service`'s load, active and cgroup state.
async fn unit_state(service: &str) -> io::Result<UnitState> {
    let output = tokio::time::timeout(
        SYSTEMD_QUERY_HANG,
        systemctl()
            .args(
                [
                    "show",
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=ControlGroup",
                    service,
                ]
                .as_slice(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let unavailable = || io::Error::other("host login unit state unavailable");
    if output.stdout.len() > 1024 {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| unavailable())?;
    let mut state = UnitState {
        load: String::new(),
        active: String::new(),
        control_group: String::new(),
    };
    for line in text.lines() {
        match line.split_once('=') {
            Some(("LoadState", value)) => value.trim().clone_into(&mut state.load),
            Some(("ActiveState", value)) => value.trim().clone_into(&mut state.active),
            Some(("ControlGroup", value)) => value.trim().clone_into(&mut state.control_group),
            _ => {}
        }
    }
    if state.load.is_empty() || (!output.status.success() && state.load != "not-found") {
        return Err(unavailable());
    }
    Ok(state)
}

/// Ends the host login unit `unit` through systemd alone, then refuses only
/// if systemd still reports it running.
///
/// The cgroup comes from systemd's `ControlGroup` of a unit only root can
/// create, so nothing here depends on the login worker, which runs as the
/// revoked account (J261 P1, #355). `cgroup.kill` ends every process in it at
/// once, the shells, their PTY owners and any `setsid` escapees, before any
/// courtesy, so no exchange the account controls can delay the kill (J261
/// P2). `systemctl stop` then retires the unit and its PAM session.
async fn stop_unit(unit: &str) -> io::Result<()> {
    let service = format!("{unit}.service");
    let state = unit_state(&service).await?;
    // Collected transient units leave their private account lock as history.
    // Repeated access removal must not fail merely because cleanup already
    // unloaded that unit.
    if state.load == "not-found" {
        return Ok(());
    }
    if !state.control_group.is_empty() {
        let group = &state.control_group;
        let parts: Vec<_> = group.split('/').collect();
        if !group.starts_with('/')
            || parts[1..]
                .iter()
                .any(|part| matches!(*part, "" | "." | ".."))
            || parts.last() != Some(&service.as_str())
        {
            return Err(io::Error::other("invalid host login cgroup"));
        }
        let directory = cgroup_root().join(group.trim_start_matches('/'));
        match std::fs::write(directory.join("cgroup.kill"), b"1") {
            Ok(()) => {}
            // The unit's cgroup is already gone: nothing is left to kill.
            Err(error) if error.kind() == io::ErrorKind::NotFound && !directory.exists() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::other(
                    "host login cgroup lacks immediate cleanup",
                ));
            }
            Err(error) => return Err(error),
        }
    }
    let status = tokio::time::timeout(
        UNIT_STOP_HANG,
        systemctl()
            .args(["stop", &service].as_slice())
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
    let after = unit_state(&service).await?;
    if after.load != "not-found" && !matches!(after.active.as_str(), "inactive" | "failed") {
        return Err(io::Error::other("host login unit still running after stop"));
    }
    Ok(())
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

    /// A revoked account that freezes its own login worker (`kill -STOP`)
    /// still loses its shell: with the system manager, revocation kills the
    /// unit's cgroup and stops the unit through systemd without asking the
    /// worker (J261 P1, #355). The worker here accepts and never answers, the
    /// socket-level shape of a stopped process. systemd is a script that
    /// records its calls and reports the unit stopped after `stop`.
    #[tokio::test]
    async fn frozen_login_worker_cannot_keep_a_revoked_shell() {
        use std::os::unix::fs::PermissionsExt as _;
        // Short, so the worker's socket path stays within SUN_LEN.
        let root = nix::unistd::mkdtemp("/tmp/rl-XXXXXX").unwrap();
        let person = uuid::Uuid::new_v4();
        let uid = Uid::effective().as_raw();
        let unit = name(person, uid);
        drop(acquire(&root, &unit).await.unwrap());
        synchronize_at(&root, person).unwrap();
        let endpoint = root.join(&unit).join("login.sock");
        std::fs::create_dir(endpoint.parent().unwrap()).unwrap();
        let worker = tokio::net::UnixListener::bind(&endpoint).unwrap();
        let frozen = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                // Accepted and never read or answered.
                held.push(worker.accept().await.unwrap().0);
            }
        });
        let host = root.join("host");
        let group = format!("/system.slice/{unit}.service");
        let cgroup = host.join("cgroup").join(group.trim_start_matches('/'));
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::write(cgroup.join("cgroup.kill"), b"").unwrap();
        std::fs::write(host.join("active"), "active\n").unwrap();
        std::fs::write(host.join("group"), format!("{group}\n")).unwrap();
        let script = format!(
            "#!/bin/sh\nd='{}'\necho \"$*\" >> \"$d/calls\"\ncase \"$1\" in\n\
             show) printf 'LoadState=loaded\\nActiveState=%s\\nControlGroup=%s\\n' \"$(cat \"$d/active\")\" \"$(cat \"$d/group\")\" ;;\n\
             stop) echo inactive > \"$d/active\"; : > \"$d/group\" ;;\nesac\n",
            host.display()
        );
        let staging = host.join("systemctl.staging");
        std::fs::write(&staging, script).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
        let systemctl = host.join("systemctl");
        // Published by a separate process so no forked sibling holds a writer (ETXTBSY).
        assert!(
            std::process::Command::new("install")
                .args(["-m", "700", "--"])
                .args([&staging, &systemctl])
                .status()
                .unwrap()
                .success()
        );
        HOST_UNITS.with(|units| *units.borrow_mut() = Some((systemctl, host.join("cgroup"))));
        // Hang guard only: a correct revocation never waits on the worker.
        let revoked = tokio::time::timeout(
            Duration::from_secs(300),
            revoke_at(&root, Manager::System, person, false),
        )
        .await
        .expect("revocation hung");
        HOST_UNITS.with(|units| *units.borrow_mut() = None);
        frozen.abort();
        let calls = std::fs::read_to_string(host.join("calls")).unwrap_or_default();
        let killed = std::fs::read(cgroup.join("cgroup.kill")).unwrap();
        assert!(
            revoked.is_ok(),
            "a frozen worker refused the revocation: {revoked:?}; systemctl calls: {calls:?}"
        );
        assert_eq!(killed, b"1", "the unit's cgroup was not killed");
        assert!(
            calls
                .lines()
                .any(|line| line == format!("stop {unit}.service")),
            "the unit was not stopped: {calls:?}"
        );
        assert_eq!(
            permitted(&root, person).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Contended publishers must leave a worker available for refusal markers.
    /// Run explicitly as root in a private fixture; the watchdog only breaks a
    /// deadlock and never supplies an elapsed-time success criterion.
    #[test]
    #[ignore = "root-only publication contention proof; run in a throwaway root clone"]
    fn publisher_contention_does_not_starve_revocation() {
        use std::{fs::File, os::unix::fs::PermissionsExt as _, sync::mpsc};
        assert!(Uid::effective().is_root());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        let root = crate::durable_tests::directory();
        let images = root.join("images");
        let locks = root.join(".images-locks");
        std::fs::create_dir(&locks).unwrap();
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).unwrap();
        let publisher = nix::fcntl::Flock::lock(
            File::open(locks).unwrap(),
            nix::fcntl::FlockArg::LockExclusive,
        )
        .unwrap();
        let (release, wait) = mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            let fired = wait.recv_timeout(Duration::from_secs(30)).is_err();
            drop(publisher);
            fired
        });
        runtime.block_on(async {
            use std::{future::Future as _, task::Context};
            let mut releases = Vec::new();
            let mut blockers = Vec::new();
            for _ in 0..2 {
                let (release, wait) = mpsc::channel();
                let (entered, ready) = tokio::sync::oneshot::channel();
                blockers.push(tokio::task::spawn_blocking(move || {
                    entered.send(()).unwrap();
                    let _ = wait.recv();
                }));
                ready.await.unwrap();
                releases.push(release);
            }
            let mut first = Box::pin(crate::login_binary::accessible(
                Path::new("/bin/true"),
                &images,
            ));
            let mut second = Box::pin(crate::login_binary::accessible(
                Path::new("/bin/true"),
                &images,
            ));
            let mut context = Context::from_waker(std::task::Waker::noop());
            assert!(first.as_mut().poll(&mut context).is_pending());
            assert!(second.as_mut().poll(&mut context).is_pending());
            for release in releases {
                release.send(()).unwrap();
            }
            let person = uuid::Uuid::new_v4();
            revoke_at(&root, Manager::Detached, person, false)
                .await
                .unwrap();
            assert!(permitted(&root, person).is_err());
            let _ = release.send(());
            for blocker in blockers {
                blocker.await.unwrap();
            }
            let (first, second) = tokio::join!(first, second);
            first.unwrap();
            second.unwrap();
        });
        assert!(
            !watchdog.join().unwrap(),
            "publisher waiters starved revocation"
        );
        drop(runtime);
        std::fs::remove_dir_all(root).unwrap();
    }
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

    /// A held person fence delays disk work but cannot delay in-memory denial:
    /// while revocation waits for the lock, the marker is not on disk yet, and
    /// an authorized person's opens are still refused. Opens therefore cannot
    /// win the lock race and pass the check during the wait (J261 P3, #355).
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
            // Authorized, so a refusal below can only come from the revocation.
            synchronize_at(&root, person).unwrap();
            permitted(&root, person).unwrap();
            let lock = acquire(&root, &format!("{}.person", person.simple()))
                .await
                .unwrap();
            let mut task = Box::pin(revoke_at(&root, Manager::Detached, person, false));
            assert!(
                std::future::Future::poll(
                    task.as_mut(),
                    &mut std::task::Context::from_waker(std::task::Waker::noop()),
                )
                .is_pending()
            );
            assert!(
                !root
                    .join("infraternal-login-locks")
                    .join(format!("{}.revoked", person.simple()))
                    .exists(),
                "the marker is written only under the person lock"
            );
            assert_eq!(
                permitted(&root, person).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            drop(lock);
            task.await.unwrap();
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

    /// A current server grant cannot bypass a later durable person refusal.
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
            synchronize_at(&root, person).unwrap();
            permitted(&root, person).unwrap();
            revoke_at(&root, Manager::Detached, person, false)
                .await
                .unwrap();
            assert_eq!(
                permitted(&root, person).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            let unrelated = uuid::Uuid::new_v4();
            synchronize_at(&root, unrelated).unwrap();
            assert!(permitted(&root, unrelated).is_ok());
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
    /// Supply the trusted server grant before calling login admission directly,
    /// matching the daemon's authority synchronization before an ordinary open.
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
            let person = uuid::Uuid::new_v4();
            synchronize(&state, person).unwrap();
            let result = ensure(
                &std::env::current_exe().unwrap(),
                &state,
                Manager::Detached,
                person,
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

    /// A cancelled 1,024-person flood cannot leave a descriptor per queued save.
    /// Two held Tokio workers reproduce the review's saturated shared pool;
    /// all observations happen before either worker is allowed to finish.
    #[cfg(target_os = "linux")]
    #[test]
    fn cancelled_restore_flood_bounds_descriptors() {
        use std::{future::Future as _, sync::mpsc, task::Context};
        const CHILD: &str = "INFRATERNAL_DURABLE_FLOOD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "logins::durable_tests::cancelled_restore_flood_bounds_descriptors",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            eprint!(
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        let root = crate::durable_tests::directory();
        let people: Vec<_> = (0..1024).map(|_| uuid::Uuid::new_v4()).collect();
        let mut releases = Vec::new();
        let mut blockers = Vec::new();
        runtime.block_on(async {
            for _ in 0..2 {
                let (release, wait) = mpsc::channel();
                let (entered, ready) = tokio::sync::oneshot::channel();
                blockers.push(tokio::task::spawn_blocking(move || {
                    entered.send(()).unwrap();
                    wait.recv().unwrap();
                }));
                ready.await.unwrap();
                releases.push(release);
            }
            let mut calls: Vec<_> = people
                .iter()
                .map(|person| Box::pin(restore_at(&root, *person)))
                .collect();
            let mut context = Context::from_waker(std::task::Waker::noop());
            for call in &mut calls {
                let _ = call.as_mut().poll(&mut context);
            }
            let submitted = owned_descriptors(&root);
            drop(calls);
            let cancelled = owned_descriptors(&root);
            let retained = people.iter().filter(|person| {
                let path = root.join("infraternal-login-locks")
                    .join(format!("{}.person.lock", person.simple()));
                std::fs::File::open(path).is_ok_and(|file| matches!(
                    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock),
                    Err((_, nix::errno::Errno::EWOULDBLOCK))
                ))
            }).count();
            for release in releases { release.send(()).unwrap(); }
            for blocker in blockers { blocker.await.unwrap(); }
            eprintln!("flood=1024 submitted_fds={submitted} cancelled_fds={cancelled} retained_fences={retained}");
            assert!(submitted <= 36, "unbounded descriptor admission: {submitted}");
            assert!(cancelled <= 4, "cancelled queue retained descriptors: {cancelled}");
            assert!(retained <= 2, "cancelled queue retained fences: {retained}");
        });
        drop(runtime);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Count only descriptors owned by this flood, excluding concurrent tests.
    #[cfg(target_os = "linux")]
    fn owned_descriptors(root: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .filter(|path| path.starts_with(root))
            .count()
    }

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

/// Exercise revocation saturation, restart denial and durable retry ordering.
#[cfg(test)]
#[path = "revocation_tests.rs"]
mod revocation_tests;
