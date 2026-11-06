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

/// A root infraternal agent on a host without systemd refuses person logins
/// (D354, amending D247). Without systemd's per-login cgroups, revocation
/// cannot prove that every process of a login is gone, and with `su` a revoked
/// person kept their shell alive (J291). Rootless agents and systemd hosts are
/// unaffected. The error carries a type so the daemon never matches on text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NoSystemd;

impl std::fmt::Display for NoSystemd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a root infraternal agent opens person logins only on hosts with systemd")
    }
}

impl std::error::Error for NoSystemd {}

impl NoSystemd {
    /// This refusal as an error.
    fn denied(self) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, self)
    }

    /// Whether `error` is this refusal.
    pub(crate) fn of(error: &io::Error) -> bool {
        matches!(error.get_ref(), Some(inner) if inner.is::<Self>())
    }
}

/// A login whose processes revocation cannot prove gone: an `su` login opened
/// before D354 (or a unit with an account-owned runtime directory and no
/// recorded scope). The person stays denied and the owner keeps retrying,
/// but only the host's administrator can end it, so the revocation says so
/// in plain words, once (J295, #355).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnprovableLogin;

impl std::fmt::Display for UnprovableLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "this person's host login was opened without systemd (by an older infraternal), so \
             its processes can't be proven gone; the person stays denied, but stop that login's \
             processes by hand or restart the host to end it",
        )
    }
}

impl std::error::Error for UnprovableLogin {}

impl UnprovableLogin {
    /// This refusal as an error.
    fn error() -> io::Error {
        io::Error::other(Self)
    }

    /// Whether `error` is this refusal.
    pub(crate) fn of(error: &io::Error) -> bool {
        matches!(error.get_ref(), Some(inner) if inner.is::<Self>())
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
    // Refuses unless the system manager answers (D354); only it reaches below.
    root_login_manager(manager, Manager::probe).await?;
    let image =
        crate::login_binary::accessible(exe, Path::new("/var/cache/infraternal-login-bin")).await?;
    let exe = image.path();
    let _lock = acquire(root, &name).await?;
    let endpoint = root.join(&name).join("login.sock");
    match ready(&endpoint, user.uid.as_raw()).await {
        Ok(()) => {
            remember_scope(root, &name, &endpoint, person, user.uid.as_raw()).await?;
            return Ok(Some(endpoint));
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => return Err(error),
    }
    // Only the system manager reaches this launch path (`root_login_manager`,
    // D354): there is no `su` fallback for root logins any more.
    let bound = runtime_socket(root, &name, &endpoint, user)?;
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
            .args(["-p", "UtmpMode=user"].as_slice())
            .arg("-p")
            .arg(format!(
                "TTYPath=/dev/{}",
                crate::login_records::line(person, &record)
            ));
    }
    // No RuntimeDirectory=: systemd would give that directory to the
    // account, which could then swap the login socket (J295 P1).
    command
        .args(["-p", "KillMode=control-group"].as_slice())
        .arg("-p")
        .arg(format!("WorkingDirectory={}", user.dir.display()))
        .arg(exe)
        .args(
            [
                "__shim",
                "--login-worker",
                "--login-ready-fd",
                "1",
                "--login-listen-fd",
                "0",
                "--session",
                &person.simple().to_string(),
                "--uid",
                &user.uid.as_raw().to_string(),
                "--login-socket",
            ]
            .as_slice(),
        )
        .arg(&endpoint)
        // `--pipe` hands this root-created socket to the worker as its stdin.
        .stdin(Stdio::from(bound))
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
        // Before any shell can run in it: revocation kills this scope (#355).
        record_scope(root, &name, user.uid.as_raw(), &relative_group(&identity)?)?;
        crate::login_auth::remember(person, user.uid.as_raw(), identity);
        // The original announcement is emitted only after account setup,
        // endpoint binding and signal readiness. Socket credentials and the
        // live process pin above authenticate that completed initialization;
        // another readiness exchange cannot add a stronger startup proof.
        // Adoption without an original announcement still takes the loop below.
        return Ok(Some(endpoint));
    }
    let adopted = tokio::time::timeout(Duration::from_secs(10), async {
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
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    // An adopted worker (a racing launch won the unit name) gets its scope
    // recorded too, before this open returns (#355).
    remember_scope(root, &name, &endpoint, person, user.uid.as_raw()).await?;
    Ok(adopted)
}

/// Creates login `name`'s runtime directory and socket as root, for the worker
/// to serve: the directory root-owned and 0755, the socket bound at
/// `endpoint` but not listening (the worker listens, so peers still see its
/// credentials), and owned by the account at 0600 so only root and the
/// account connect. The account can use the socket but can neither replace it
/// nor its directory, so no open can be steered to a decoy (J291, J295 P1,
/// #355). A leftover account-owned directory (an older unit's
/// `RuntimeDirectory=`) and stale sockets are replaced. Called under the
/// unit's lock, so no other launch races it.
fn runtime_socket(
    root: &Path,
    name: &str,
    endpoint: &Path,
    user: &User,
) -> io::Result<std::os::fd::OwnedFd> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, bind, socket};
    use std::os::{
        fd::AsRawFd as _,
        unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    };
    let directory = root.join(name);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(metadata) if metadata.is_dir() && metadata.uid() == 0 => {}
        // Not ours (an older unit's account-owned directory, or not a
        // directory): remove it; this never follows a symlink.
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(&directory)?,
        Ok(_) => std::fs::remove_file(&directory)?,
        Err(error) => return Err(error),
    }
    match std::fs::DirBuilder::new().mode(0o755).create(&directory) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        result => result?,
    }
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
    for stale in [endpoint.to_owned(), endpoint.with_extension("stop")] {
        match std::fs::remove_file(stale) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    let bound = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    bind(
        bound.as_raw_fd(),
        &UnixAddr::new(endpoint).map_err(io::Error::from)?,
    )
    .map_err(io::Error::from)?;
    nix::unistd::chown(endpoint, Some(user.uid), Some(user.gid)).map_err(io::Error::from)?;
    std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o600))?;
    Ok(bound)
}

/// Whether login `unit` still has a runtime directory that its account owns:
/// an `su` login from before D354, or a unit launched with
/// `RuntimeDirectory=`. Its processes cannot be shown gone without a unit or
/// a recorded scope. A root-owned directory is the agent's own, not evidence.
fn account_owned_runtime(root: &Path, unit: &str) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(root.join(unit)).is_ok_and(|metadata| metadata.uid() != 0)
}

/// Removes login `unit`'s root-owned runtime directory once the login is
/// shown gone. An account-owned one is left alone (fail-closed path).
fn remove_runtime(root: &Path, unit: &str) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let directory = root.join(unit);
    match std::fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && metadata.uid() == 0 => {
            std::fs::remove_dir_all(directory)
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// The manager a root revocation stops logins under. A launch's `Detached`
/// may stand for a probe that only timed out, for example right after an
/// agent restart, so it is probed again. `System` and "no system manager" are
/// used as answered (the latter keeps the fail-closed path for logins from
/// before D354). A probe that times out again fails this attempt: the person
/// stays denied and the revocation owner retries (J295 P1, #355).
async fn root_revoke_manager(
    manager: Manager,
    probe: impl std::future::Future<Output = Option<Manager>>,
) -> io::Result<Manager> {
    if matches!(manager, Manager::System) {
        return Ok(manager);
    }
    probe.await.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "the host's service manager did not answer; revocation will retry",
        )
    })
}

/// The manager probe for a root revocation.
#[cfg(not(test))]
fn revoke_probe(_given: Manager) -> impl std::future::Future<Output = Option<Manager>> {
    Manager::probe()
}

/// The manager probe for a root revocation, in tests: the scripted host's
/// answer, or the manager the test passed when it scripts none.
#[cfg(test)]
fn revoke_probe(given: Manager) -> impl std::future::Future<Output = Option<Manager>> {
    std::future::ready(stand_in().map_or(Some(given), |host| host.probe))
}

/// The manager a root agent opens another account's login under: always the
/// system manager.
///
/// A launch gets `Detached` both when the host has no system manager and when
/// the system manager's probe merely timed out (`Manager::resolve` keeps only
/// answers). So a non-`System` manager is probed again here. An answer of
/// `System` is used; an answer that there is none refuses the login with
/// [`NoSystemd`] (D354); a probe that times out again refuses the open, and
/// the server may retry it. No root login ever runs without a unit and a
/// recorded scope that revocation can kill and check (J291 P1, #355).
async fn root_login_manager<F, Fut>(manager: Manager, probe: F) -> io::Result<Manager>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<Manager>>,
{
    if matches!(manager, Manager::System) {
        return Ok(manager);
    }
    match probe().await {
        Some(Manager::System) => Ok(Manager::System),
        Some(_) => Err(NoSystemd.denied()),
        None => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the host's service manager did not answer; host login not opened",
        )),
    }
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
        // A root login outside the system manager is an `su` fallback from
        // before D354. It is never authenticated again: revocation of it fails
        // closed (`stop_login`), and new ones are not opened.
        return Err(NoSystemd.denied());
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
pub async fn revoke(state: &Path, manager: Manager, person: uuid::Uuid) -> io::Result<Revoked> {
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
) -> io::Result<Revoked> {
    revocations::submit(root, manager, person, rootless).await
}

/// What a completed revocation could not guarantee.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Revoked {
    /// Someone else still has access to a host account the person used, so
    /// that account's own background services were left running (D353).
    pub background_may_remain: bool,
}

/// Try one reserved revocation; its owner retains denial and retries any failure.
async fn revoke_once(
    root: &Path,
    manager: Manager,
    person: uuid::Uuid,
    rootless: bool,
) -> io::Result<Revoked> {
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
        // A rootless agent's user manager may be the agent's own (D18): D353
        // applies to root agents only.
        return crate::rootless_sessions::revoke(root, person, Some(person_guard), admission)
            .await
            .map(|()| Revoked::default());
    }
    // The refusal is durable above; now find how this host's logins run. A
    // probe that times out never means "no system manager": that would take
    // the path that cannot see a login's session scope (J295 P1, #355).
    let manager = root_revoke_manager(manager, revoke_probe(manager)).await?;
    let prefix = format!("infraternal-login-{}-", person.simple());
    let mut failure = None;
    let mut revoked = Revoked::default();
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
        match stop_login(root, manager, person, uid, &unit).await {
            Err(error) => failure = Some(error),
            // D353: background services of the account go with its last
            // holder; while others share it, they stay and the result warns.
            Ok(()) if matches!(manager, Manager::System) => {
                if others_share(root, person, uid)? {
                    revoked.background_may_remain = true;
                } else if let Err(error) = stop_user_services(uid).await {
                    failure = Some(error);
                }
            }
            Ok(()) => {}
        }
    }
    crate::login_auth::forget(person);
    failure.map_or(Ok(revoked), Err)
}

/// Whether another person still has access to host account `uid` here, as
/// far as this host can tell from its durable, root-only state: a login lock
/// for that account, without a revocation marker or a pending revocation.
/// The agent never sees other people's grants, and the in-memory grants are
/// empty after a restart, so this errs towards "shared", which stops nothing
/// (D353). Root's account (D231's fallback) is always shared: its user
/// manager belongs to the host's administrator.
fn others_share(root: &Path, person: uuid::Uuid, uid: u32) -> io::Result<bool> {
    if uid == 0 {
        return Ok(true);
    }
    let registry = root.join("infraternal-login-locks");
    let suffix = format!("-{uid}.lock");
    for entry in std::fs::read_dir(&registry)? {
        let name = entry?.file_name();
        let Some(other) = name
            .to_str()
            .and_then(|name| name.strip_prefix("infraternal-login-"))
            .and_then(|rest| rest.strip_suffix(&suffix))
            .and_then(|other| uuid::Uuid::parse_str(other).ok())
        else {
            continue;
        };
        if other == person
            || revocations::denied(root, other)
            || registry
                .join(format!("{}.revoked", other.simple()))
                .exists()
        {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

/// Ends host account `uid`'s own background services, once its last holder
/// is revoked (D353): kills the user manager's cgroup (`user@<uid>.service`,
/// which holds every `systemd-run --user` unit), stops the manager and
/// requires that cgroup to be empty, then turns linger off, and reports
/// success only once linger is verified off and the manager has stayed gone.
/// The account's other, non-infraternal sessions are not touched.
async fn stop_user_services(uid: u32) -> io::Result<()> {
    let name = User::from_uid(Uid::from_raw(uid))
        .map_err(io::Error::from)?
        .ok_or_else(|| io::Error::other("host account absent"))?
        .name;
    let manager = format!("/user.slice/user-{uid}.slice/user@{uid}.service");
    // The account's own services can keep asking logind for linger, and an
    // enable-linger queued before the kill still lands. So the user manager
    // dies first, then linger goes off, then both are checked: linger off and
    // no user manager back (J295 P1, #355). A few rounds absorb a request
    // that was already in flight; one that keeps coming back fails this
    // attempt, and the owner retries.
    for _ in 0..LINGER_ROUNDS {
        kill_cgroup(&manager)?;
        // The cgroup check below decides; a manager that is already gone may
        // make `stop` report failure.
        let _ = tokio::time::timeout(
            UNIT_STOP_HANG,
            systemctl()
                .args(["stop", &format!("user@{uid}.service")].as_slice())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        cgroup_emptied(&manager).await?;
        let linger = tokio::time::timeout(
            SYSTEMD_QUERY_HANG,
            loginctl()
                .args(["disable-linger", &uid.to_string()].as_slice())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if !linger.success() {
            return Err(io::Error::other(
                "host account linger could not be turned off",
            ));
        }
        if !linger_file(&name).exists() && cgroup_empty(&manager)? {
            return Ok(());
        }
    }
    Err(io::Error::other(
        "host account linger or user manager kept coming back; revocation will retry",
    ))
}

/// How many kill, linger-off, verify rounds one revocation attempt makes.
const LINGER_ROUNDS: usize = 5;

/// logind's linger flag for account `name`: a root-owned file whose presence
/// starts the account's user manager at boot.
fn linger_file(name: &str) -> PathBuf {
    #[cfg(test)]
    if let Some(host) = stand_in() {
        return host.linger.join(name);
    }
    Path::new("/var/lib/systemd/linger").join(name)
}

/// Whether cgroup `group` has no process left (or is gone), right now.
fn cgroup_empty(group: &str) -> io::Result<bool> {
    let events = cgroup_root()
        .join(group.trim_start_matches('/'))
        .join("cgroup.events");
    match std::fs::read_to_string(events) {
        Err(error) if cgroup_gone(&error) => Ok(true),
        Err(error) => Err(error),
        Ok(text) => Ok(text.lines().any(|line| line == "populated 0")),
    }
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
/// ([`stop_system_login`]). The login worker runs as the revoked account, which can
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
        return stop_system_login(root, uid, unit).await;
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
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => return Err(error),
    }
    // Without a system manager there is no cgroup to kill or inspect, and
    // the account owns the worker and can delete its sockets: neither a stop
    // confirmation nor a missing socket proves its processes are gone. While
    // the login's root-created runtime directory exists, revocation fails
    // closed (J291 P1, #355; how such hosts get a provable kill is open
    // under D247).
    if root.join(unit).exists() {
        return Err(UnprovableLogin::error());
    }
    Ok(())
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

/// Hang guard for a killed login cgroup to empty. `cgroup.kill` delivers
/// SIGKILL to every member at once, so only a process stuck in the kernel
/// (uninterruptible sleep) can keep it populated; then revocation fails
/// rather than report a login it could not end (#355).
const CGROUP_EMPTY_HANG: Duration = Duration::from_secs(60);

/// Test-only stand-ins for the host: the `systemctl` and `loginctl`
/// programs, the cgroup filesystem root, and the empty-cgroup hang guard.
#[cfg(test)]
#[derive(Clone)]
struct HostStandIn {
    /// Scripted `systemctl`.
    systemctl: PathBuf,
    /// Scripted `loginctl`.
    loginctl: PathBuf,
    /// Stand-in for `/sys/fs/cgroup`.
    cgroups: PathBuf,
    /// Replaces [`CGROUP_EMPTY_HANG`].
    empty_hang: Duration,
    /// The manager probe's answer; `None` is a probe that timed out.
    probe: Option<Manager>,
    /// Stand-in for `/var/lib/systemd/linger`.
    linger: PathBuf,
}

#[cfg(test)]
thread_local! {
    /// The scripted host for `stop_system_login` on this test thread.
    static HOST_UNITS: std::cell::RefCell<Option<HostStandIn>> =
        const { std::cell::RefCell::new(None) };
}

/// The scripted host on this test thread, if any.
#[cfg(test)]
fn stand_in() -> Option<HostStandIn> {
    HOST_UNITS.with(|units| units.borrow().clone())
}

/// A `systemctl` command, isolated like every host-manager child.
fn systemctl() -> tokio::process::Command {
    #[cfg(test)]
    if let Some(host) = stand_in() {
        return crate::sessions::isolated(&host.systemctl);
    }
    crate::sessions::isolated(Path::new("systemctl"))
}

/// A `loginctl` command, isolated like every host-manager child.
fn loginctl() -> tokio::process::Command {
    #[cfg(test)]
    if let Some(host) = stand_in() {
        return crate::sessions::isolated(&host.loginctl);
    }
    crate::sessions::isolated(Path::new("loginctl"))
}

/// Root of the unified cgroup hierarchy that cgroup paths are relative to.
fn cgroup_root() -> PathBuf {
    #[cfg(test)]
    if let Some(host) = stand_in() {
        return host.cgroups;
    }
    PathBuf::from("/sys/fs/cgroup")
}

/// How long a killed cgroup may take to empty before revocation fails.
fn empty_hang() -> Duration {
    #[cfg(test)]
    if let Some(host) = stand_in() {
        return host.empty_hang;
    }
    CGROUP_EMPTY_HANG
}

/// What systemd reports about one unit.
struct UnitState {
    /// `LoadState`: `not-found` once a transient unit has been collected.
    load: String,
    /// `ActiveState`: `inactive` or `failed` once the unit has stopped.
    active: String,
    /// `ControlGroup`, relative to [`cgroup_root`]; empty when it has none.
    control_group: String,
    /// `MainPID`: the login worker while the unit runs, otherwise 0.
    main_pid: i32,
}

/// Asks systemd for `service`'s load, active, cgroup and main process state.
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
                    "--property=MainPID",
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
        main_pid: 0,
    };
    for line in text.lines() {
        match line.split_once('=') {
            Some(("LoadState", value)) => value.trim().clone_into(&mut state.load),
            Some(("ActiveState", value)) => value.trim().clone_into(&mut state.active),
            Some(("ControlGroup", value)) => value.trim().clone_into(&mut state.control_group),
            Some(("MainPID", value)) => state.main_pid = value.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    if state.load.is_empty() || (!output.status.success() && state.load != "not-found") {
        return Err(unavailable());
    }
    Ok(state)
}

/// Whether `group` (a cgroup path relative to the hierarchy root) is one a
/// login of `uid` with unit `service` can own: that unit's own cgroup, or a
/// logind session scope of that account. Absolute, with no empty, `.` or `..`
/// parts: cgroupfs has no symlinks, so nothing else can be reached.
fn login_cgroup(group: &str, uid: u32, service: &str) -> bool {
    let Some(rest) = group.strip_prefix('/') else {
        return false;
    };
    let parts: Vec<_> = rest.split('/').collect();
    if parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
        return false;
    }
    let slice = format!("user-{uid}.slice");
    match parts.as_slice() {
        ["system.slice", unit] => *unit == service,
        ["user.slice", user, scope] => {
            *user == slice
                && scope
                    .strip_prefix("session-")
                    .and_then(|rest| rest.strip_suffix(".scope"))
                    .is_some_and(|id| {
                        !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    })
        }
        _ => false,
    }
}

/// Where the session scope of login `unit` is recorded: the root-only lock
/// registry, next to the unit's lock.
fn scope_record(root: &Path, unit: &str) -> PathBuf {
    root.join("infraternal-login-locks")
        .join(format!("{unit}.scope"))
}

/// How many scopes one login's record keeps. Each launch of the unit adds
/// one; an open fails closed rather than forget one.
const RECORDED_SCOPES: usize = 16;

/// Adds, durably, a cgroup that login `unit` of `uid` lives in to its record.
/// With `PAMName=` that is the logind session scope (`session-N.scope`), not
/// the unit's own cgroup, and it holds the worker, the PTY owners and every
/// descendant. Revocation kills every recorded scope, never trusting anything
/// the login's account can touch (J291, #355). Scopes of earlier launches
/// stay recorded: a process the account left in one is still the revoked
/// person's code, and a new launch must not make revocation forget it (J295).
fn record_scope(root: &Path, unit: &str, uid: u32, group: &str) -> io::Result<()> {
    use std::{fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _};
    if !login_cgroup(group, uid, &format!("{unit}.service")) {
        return Err(io::Error::other("host login is in an unexpected cgroup"));
    }
    let mut groups = recorded_scopes(root, unit, uid)?;
    if groups.iter().any(|recorded| recorded == group) {
        return Ok(());
    }
    if groups.len() >= RECORDED_SCOPES {
        return Err(io::Error::other("host login has too many recorded scopes"));
    }
    groups.push(group.to_owned());
    let record = scope_record(root, unit);
    let staging = record.with_extension("scope.staging");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&staging)?;
    file.write_all(groups.join("\n").as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&staging, &record)?;
    std::fs::File::open(root.join("infraternal-login-locks"))?.sync_all()
}

/// Every cgroup recorded for login `unit` of `uid`; empty when none was.
fn recorded_scopes(root: &Path, unit: &str, uid: u32) -> io::Result<Vec<String>> {
    use std::os::unix::fs::MetadataExt as _;
    let record = scope_record(root, unit);
    let metadata = match std::fs::symlink_metadata(&record) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        result => result?,
    };
    let unsafe_record =
        || io::Error::new(io::ErrorKind::PermissionDenied, "unsafe login scope record");
    if !metadata.is_file() || metadata.uid() != Uid::effective().as_raw() || metadata.len() > 4096 {
        return Err(unsafe_record());
    }
    let text = std::fs::read_to_string(&record)?;
    let service = format!("{unit}.service");
    let groups: Vec<String> = text.lines().map(str::to_owned).collect();
    if groups.is_empty()
        || groups.len() > RECORDED_SCOPES
        || groups
            .iter()
            .any(|group| !login_cgroup(group, uid, &service))
    {
        return Err(unsafe_record());
    }
    Ok(groups)
}

/// The cgroup that process `pid` is in, from the kernel.
fn process_cgroup(pid: i32) -> io::Result<String> {
    let record = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    record
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("host login path needs a unified cgroup"))
}

/// Records the session scope of the worker at `endpoint`, authenticated
/// against the unit's `MainPID`, on every open. An older record never stands
/// in for the live worker's scope (J295 P1, #355): a new launch adds its own.
async fn remember_scope(
    root: &Path,
    unit: &str,
    endpoint: &Path,
    person: uuid::Uuid,
    uid: u32,
) -> io::Result<()> {
    let identity = cgroup(endpoint, Manager::System, person, uid)
        .await?
        .ok_or_else(|| io::Error::other("host login worker absent"))?;
    record_scope(root, unit, uid, &relative_group(&identity)?)
}

/// The cgroup path, relative to the hierarchy root, of an authenticated
/// worker identity.
fn relative_group(identity: &crate::login_auth::Identity) -> io::Result<String> {
    identity
        .group
        .parent()
        .and_then(|group| group.strip_prefix("/sys/fs/cgroup").ok())
        .and_then(Path::to_str)
        .map(|group| format!("/{group}"))
        .ok_or_else(|| io::Error::other("host login cgroup absent"))
}

/// Whether `error` from a cgroup control file means the cgroup is gone or
/// being removed. The kernel answers `ENODEV` for the files of a cgroup that
/// is being torn down while its directory is still visible, and it removes a
/// cgroup only once no process is left in it (#355).
fn cgroup_gone(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(nix::libc::ENODEV)
}

/// Kills every process in cgroup `group` at once. A missing or dying cgroup
/// has no processes left to kill.
fn kill_cgroup(group: &str) -> io::Result<()> {
    let directory = cgroup_root().join(group.trim_start_matches('/'));
    match std::fs::write(directory.join("cgroup.kill"), b"1") {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(nix::libc::ENODEV) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !directory.exists() => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::other(
            "host login cgroup lacks immediate cleanup",
        )),
        Err(error) => Err(error),
    }
}

/// Waits until cgroup `group` has no process left, or is gone. Fails at
/// [`empty_hang`]: a login that cannot be shown empty is not revoked.
async fn cgroup_emptied(group: &str) -> io::Result<()> {
    let events = cgroup_root()
        .join(group.trim_start_matches('/'))
        .join("cgroup.events");
    tokio::time::timeout(empty_hang(), async {
        loop {
            match std::fs::read_to_string(&events) {
                Err(error) if cgroup_gone(&error) => return Ok(()),
                Err(error) => return Err(error),
                Ok(text) if text.lines().any(|line| line == "populated 0") => return Ok(()),
                Ok(_) => {}
            }
            // sleep: poll interval for the kernel's populated flag; the loop ends on that condition.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "host login processes outlived cgroup.kill",
        )
    })?
}

/// Ends host login `unit` of `uid` through root-owned sources only, and
/// reports success only once every process of it is shown gone.
///
/// The login's processes live in its logind session scope, not in the unit's
/// own cgroup: `PAMName=` moves the worker, the PTY owners and every
/// descendant there (J291, #355). So revocation kills every scope recorded at
/// open, the scope the kernel reports for the loaded unit's `MainPID` (a
/// stale record must not hide the current launch, J295), and the unit's own
/// cgroup, before any courtesy. It then stops the unit, terminates the logind
/// sessions, and requires every one of those cgroups to be empty. Nothing the account controls is asked or waited on: it can stop or
/// kill its own worker, and that must neither keep the login alive nor make a
/// revoke report success (J261 P1/P2, J291 P1). A login with no unit and no
/// record, but with its runtime directory still present, cannot be accounted
/// for, so revocation fails closed.
async fn stop_system_login(root: &Path, uid: u32, unit: &str) -> io::Result<()> {
    let service = format!("{unit}.service");
    let recorded = recorded_scopes(root, unit, uid)?;
    let state = unit_state(&service).await?;
    let mut groups = recorded.clone();
    if state.load != "not-found" {
        if !state.control_group.is_empty() {
            if !login_cgroup(&state.control_group, uid, &service) {
                return Err(io::Error::other("invalid host login cgroup"));
            }
            groups.push(state.control_group.clone());
        }
        // The scope the kernel reports for the live unit's MainPID, even with a
        // record: a stale record must not hide the current launch (J295).
        if state.main_pid > 0 {
            let group = process_cgroup(state.main_pid)?;
            if !login_cgroup(&group, uid, &service) {
                return Err(io::Error::other("host login is in an unexpected cgroup"));
            }
            groups.push(group);
        }
    } else if recorded.is_empty() {
        if account_owned_runtime(root, unit) {
            return Err(UnprovableLogin::error());
        }
        return remove_runtime(root, unit);
    }
    groups.sort();
    groups.dedup();
    for group in &groups {
        kill_cgroup(group)?;
    }
    if state.load != "not-found" {
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
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        // Advisory only: once `cgroup.kill` has ended the unit's main process,
        // systemd may collect the transient unit before this stop arrives, and
        // `stop` then exits 5 (not loaded). The checks below decide: both
        // cgroups shown empty, and the unit gone or inactive (#355).
        let _ = status;
    }
    for session in groups.iter().filter_map(|group| {
        group
            .rsplit('/')
            .next()
            .and_then(|scope| scope.strip_prefix("session-"))
            .and_then(|rest| rest.strip_suffix(".scope"))
    }) {
        // Belt and braces after the kill: logind retires the session record.
        // A session that is already gone is not an error.
        let _ = tokio::time::timeout(
            SYSTEMD_QUERY_HANG,
            loginctl()
                .args(["terminate-session", session].as_slice())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await;
    }
    for group in &groups {
        cgroup_emptied(group).await?;
    }
    let after = unit_state(&service).await?;
    if after.load != "not-found" && !matches!(after.active.as_str(), "inactive" | "failed") {
        return Err(io::Error::other("host login unit still running after stop"));
    }
    match std::fs::remove_file(scope_record(root, unit)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    remove_runtime(root, unit)
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

#[cfg(test)]
mod tests {
    //! Person identity remains distinct even when the OS account is shared.
    use super::*;

    /// A root open never takes the `su` fallback on a probe that only timed
    /// out: it probes again, uses an answer as given, and refuses the open if
    /// the manager is still silent (J291 P1, #355).
    #[tokio::test]
    async fn a_timed_out_manager_probe_never_opens_a_fallback_login() {
        let silent = root_login_manager(Manager::Detached, || async { None }).await;
        assert_eq!(
            silent.map_err(|error| error.kind()).err(),
            Some(io::ErrorKind::TimedOut)
        );
        let answered = root_login_manager(Manager::Detached, || async { Some(Manager::System) })
            .await
            .unwrap();
        assert!(matches!(answered, Manager::System));
        let absent = root_login_manager(Manager::Detached, || async { Some(Manager::Detached) })
            .await
            .unwrap_err();
        assert!(
            NoSystemd::of(&absent),
            "a host without systemd refuses root logins (D354): {absent}"
        );
        let system = root_login_manager(Manager::System, || async {
            unreachable!("a system manager is not probed again")
        })
        .await
        .unwrap();
        assert!(matches!(system, Manager::System));
    }

    /// Without a system manager, a login whose runtime directory remains is
    /// never reported revoked, even when its socket is gone: the account can
    /// delete that socket while its shell lives on (J291 unlink, #355).
    #[tokio::test]
    async fn detached_revocation_fails_closed_while_the_login_remains() {
        let (root, person, _, unit) = system_login_fixture().await;
        std::fs::create_dir(root.join(&unit)).unwrap();
        let revoked = revoke_at(&root, Manager::Detached, person, false).await;
        assert!(
            revoked
                .as_ref()
                .is_err_and(|error| error.to_string().contains("can't be proven gone")),
            "an unprovable login must say why: {revoked:?}"
        );
        assert!(
            revoked.is_err(),
            "a login with a deleted socket was reported revoked"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A scripted host for `stop_system_login`: a fake cgroupfs where login
    /// `unit` of `uid` has an empty unit cgroup and its processes in
    /// `session-7.scope`, as `PAMName=` places them on a real host (J291),
    /// plus `systemctl`/`loginctl` scripts that record their calls. Like a
    /// real host, `stop` finds the transient unit already collected after the
    /// kill and exits 5 (not loaded).
    struct ScriptedHost {
        /// Root of the fake host files.
        host: PathBuf,
        /// The fake `session-7.scope` directory.
        scope: PathBuf,
        /// The fake `user@<uid>.service` directory.
        services: PathBuf,
        /// Stops the stand-in kernel thread.
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl ScriptedHost {
        /// Builds the host under `root`. With `dies`, a stand-in kernel empties
        /// the scope once `cgroup.kill` is written; without it the scope stays
        /// populated, like a process in uninterruptible sleep.
        fn new(root: &Path, unit: &str, uid: u32, loaded: bool, dies: bool) -> Self {
            use std::os::unix::fs::PermissionsExt as _;
            let host = root.join("host");
            let cgroups = host.join("cgroup");
            let service = format!("{unit}.service");
            let unit_group = cgroups.join("system.slice").join(&service);
            let scope = cgroups
                .join(format!("user.slice/user-{uid}.slice"))
                .join("session-7.scope");
            let services = cgroups
                .join(format!("user.slice/user-{uid}.slice"))
                .join(format!("user@{uid}.service"));
            for (directory, populated) in [(&unit_group, "0"), (&scope, "1"), (&services, "1")] {
                std::fs::create_dir_all(directory).unwrap();
                std::fs::write(directory.join("cgroup.kill"), b"").unwrap();
                std::fs::write(
                    directory.join("cgroup.events"),
                    format!("populated {populated}\n"),
                )
                .unwrap();
            }
            std::fs::write(
                host.join("load"),
                if loaded { "loaded" } else { "not-found" },
            )
            .unwrap();
            std::fs::write(host.join("active"), "active").unwrap();
            let script = |name: &str, body: &str| {
                let staging = host.join(format!("{name}.staging"));
                std::fs::write(
                    &staging,
                    format!(
                        "#!/bin/sh\nd='{}'\necho \"{name} $*\" >> \"$d/calls\"\n{body}",
                        host.display()
                    ),
                )
                .unwrap();
                std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
                let program = host.join(name);
                // Published by a separate process so no forked sibling holds a writer (ETXTBSY).
                assert!(
                    std::process::Command::new("install")
                        .args(["-m", "700", "--"])
                        .args([&staging, &program])
                        .status()
                        .unwrap()
                        .success()
                );
                program
            };
            let systemctl = script(
                "systemctl",
                &format!(
                    "case \"$1\" in\nshow) printf 'LoadState=%s\\nActiveState=%s\\nControlGroup=/system.slice/{service}\\nMainPID=0\\n' \"$(cat \"$d/load\")\" \"$(cat \"$d/active\")\" ;;\nstop) echo inactive > \"$d/active\"; echo not-found > \"$d/load\"; exit 5 ;;\nesac\n"
                ),
            );
            // disable-linger removes the linger files, except once while
            // `relinger` exists: a queued enable-linger that lands after it.
            let loginctl = script(
                "loginctl",
                "if [ \"$1\" = disable-linger ]; then if [ -e \"$d/relinger\" ]; then rm \"$d/relinger\"; else rm -f \"$d\"/linger/*; fi; fi\nexit 0\n",
            );
            std::fs::create_dir_all(host.join("linger")).unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            if dies {
                let (groups, stop) = (vec![scope.clone(), services.clone()], stop.clone());
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                        for group in &groups {
                            if std::fs::read(group.join("cgroup.kill"))
                                .is_ok_and(|kill| kill == b"1")
                            {
                                std::fs::write(group.join("cgroup.events"), "populated 0\n")
                                    .unwrap();
                            }
                        }
                        // sleep: the stand-in kernel polls for the kill write; the loop ends on it.
                        std::thread::sleep(Duration::from_millis(5));
                    }
                });
            }
            HOST_UNITS.with(|units| {
                *units.borrow_mut() = Some(HostStandIn {
                    systemctl,
                    loginctl,
                    cgroups,
                    empty_hang: Duration::from_secs(2),
                    probe: Some(Manager::System),
                    linger: host.join("linger"),
                });
            });
            Self {
                host,
                scope,
                services,
                stop,
            }
        }

        /// The scripted programs' calls so far.
        fn calls(&self) -> String {
            std::fs::read_to_string(self.host.join("calls")).unwrap_or_default()
        }
    }

    impl Drop for ScriptedHost {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            HOST_UNITS.with(|units| *units.borrow_mut() = None);
        }
    }

    /// A root revocation fixture: a short registry root, a synchronized
    /// person and that person's unit lock for our uid.
    async fn system_login_fixture() -> (PathBuf, uuid::Uuid, u32, String) {
        // Short, so a worker socket path stays within SUN_LEN.
        let root = nix::unistd::mkdtemp("/tmp/rl-XXXXXX").unwrap();
        let person = uuid::Uuid::new_v4();
        let uid = Uid::effective().as_raw();
        let unit = name(person, uid);
        drop(acquire(&root, &unit).await.unwrap());
        synchronize_at(&root, person).unwrap();
        (root, person, uid, unit)
    }

    /// A revoked account that kills (or freezes) its own login worker still
    /// loses every process of its login. They live in the logind session
    /// scope, not the unit's cgroup (J291), so revocation kills the scope
    /// recorded at open, without asking the worker, and reports success only
    /// once the kernel shows the scope empty (J261 P1, J291 P1). The worker
    /// here is frozen: it accepts and never answers.
    #[tokio::test]
    async fn killed_or_frozen_worker_cannot_keep_its_session_scope() {
        let (root, person, uid, unit) = system_login_fixture().await;
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
        let host = ScriptedHost::new(&root, &unit, uid, true, true);
        record_scope(
            &root,
            &unit,
            uid,
            &format!("/user.slice/user-{uid}.slice/session-7.scope"),
        )
        .unwrap();
        // Hang guard only: a correct revocation never waits on the worker.
        let revoked = tokio::time::timeout(
            Duration::from_secs(300),
            revoke_at(&root, Manager::System, person, false),
        )
        .await
        .expect("revocation hung");
        frozen.abort();
        let calls = host.calls();
        assert!(
            revoked.is_ok(),
            "revocation failed: {revoked:?}; calls: {calls:?}"
        );
        assert_eq!(
            std::fs::read(host.scope.join("cgroup.kill")).unwrap(),
            b"1",
            "the login's session scope was not killed; calls: {calls:?}"
        );
        assert!(
            calls
                .lines()
                .any(|line| line == format!("systemctl stop {unit}.service")),
            "{calls:?}"
        );
        assert!(
            calls
                .lines()
                .any(|line| line == "loginctl terminate-session 7"),
            "{calls:?}"
        );
        assert!(
            !scope_record(&root, &unit).exists(),
            "the scope record outlived the login"
        );
        drop(host);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A cgroup that the kernel is removing (control files answer `ENODEV`)
    /// counts as emptied: the kernel removes only cgroups with no process
    /// left. Treating it as an error failed the first attempt of every real
    /// last-holder revocation, as systemd tore down `user@<uid>.service` (#355).
    #[test]
    fn a_dying_cgroup_counts_as_gone() {
        assert!(cgroup_gone(&io::Error::from_raw_os_error(
            nix::libc::ENODEV
        )));
        assert!(cgroup_gone(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(!cgroup_gone(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    /// D353: revoking an account's last holder also ends the account's own
    /// background services (`systemd-run --user` with linger, J291 P2): linger
    /// off, the user manager's cgroup killed and stopped, and shown empty.
    #[tokio::test]
    async fn revoking_the_last_holder_ends_the_accounts_user_services() {
        let (root, person, uid, unit) = system_login_fixture().await;
        let host = ScriptedHost::new(&root, &unit, uid, true, true);
        record_scope(
            &root,
            &unit,
            uid,
            &format!("/user.slice/user-{uid}.slice/session-7.scope"),
        )
        .unwrap();
        let revoked = revoke_at(&root, Manager::System, person, false).await;
        let calls = host.calls();
        assert_eq!(
            revoked.as_ref().ok(),
            Some(&Revoked::default()),
            "{revoked:?}; {calls:?}"
        );
        assert_eq!(
            std::fs::read(host.services.join("cgroup.kill")).unwrap(),
            b"1",
            "{calls:?}"
        );
        assert!(
            calls
                .lines()
                .any(|line| line == format!("loginctl disable-linger {uid}")),
            "{calls:?}"
        );
        assert!(
            calls
                .lines()
                .any(|line| line == format!("systemctl stop user@{uid}.service")),
            "{calls:?}"
        );
        drop(host);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// J295 `lingerloop`: the account's service keeps asking for linger, and
    /// one request lands after `disable-linger`. The revocation reports
    /// success only once linger is verified off (and the user manager stays
    /// gone): it kills first, then disables, then checks, and repeats.
    #[tokio::test]
    async fn a_linger_request_landing_after_disable_never_survives_revocation() {
        let (root, person, uid, unit) = system_login_fixture().await;
        let host = ScriptedHost::new(&root, &unit, uid, true, true);
        let name = User::from_uid(Uid::from_raw(uid)).unwrap().unwrap().name;
        std::fs::write(host.host.join("linger").join(&name), b"").unwrap();
        std::fs::write(host.host.join("relinger"), b"").unwrap();
        record_scope(
            &root,
            &unit,
            uid,
            &format!("/user.slice/user-{uid}.slice/session-7.scope"),
        )
        .unwrap();
        let revoked = revoke_at(&root, Manager::System, person, false).await;
        let calls = host.calls();
        assert!(revoked.is_ok(), "{revoked:?}; {calls:?}");
        assert!(
            !host.host.join("linger").join(&name).exists(),
            "revoked with linger still on: {calls:?}"
        );
        assert_eq!(
            calls.matches("loginctl disable-linger").count(),
            2,
            "{calls:?}"
        );
        drop(host);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// D353: while another person still has the account, its background
    /// services stay, and the revocation says so.
    #[tokio::test]
    async fn revoking_one_of_several_holders_leaves_user_services_and_warns() {
        let (root, person, uid, unit) = system_login_fixture().await;
        drop(
            acquire(&root, &name(uuid::Uuid::new_v4(), uid))
                .await
                .unwrap(),
        );
        let host = ScriptedHost::new(&root, &unit, uid, true, true);
        record_scope(
            &root,
            &unit,
            uid,
            &format!("/user.slice/user-{uid}.slice/session-7.scope"),
        )
        .unwrap();
        let revoked = revoke_at(&root, Manager::System, person, false).await;
        let calls = host.calls();
        assert_eq!(
            revoked.as_ref().ok(),
            Some(&Revoked {
                background_may_remain: true
            }),
            "{revoked:?}; {calls:?}"
        );
        assert_eq!(
            std::fs::read(host.services.join("cgroup.kill")).unwrap(),
            b"",
            "{calls:?}"
        );
        assert!(
            !calls.contains("user@"),
            "a shared account's services were stopped: {calls:?}"
        );
        drop(host);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// J295 `restartslow`: after an agent restart the manager probe stalls,
    /// the launch passes `Detached`, the worker is gone and its unit
    /// collected, but detached children live in the recorded scope. A root
    /// revocation must not take the no-system-manager path on that timeout:
    /// it fails (retryable) and keeps the record, so the next attempt kills
    /// the scope.
    #[tokio::test]
    async fn a_stalled_probe_never_makes_a_root_revocation_skip_the_scope() {
        let (root, person, uid, unit) = system_login_fixture().await;
        let host = ScriptedHost::new(&root, &unit, uid, false, true);
        HOST_UNITS.with(|units| units.borrow_mut().as_mut().unwrap().probe = None);
        record_scope(
            &root,
            &unit,
            uid,
            &format!("/user.slice/user-{uid}.slice/session-7.scope"),
        )
        .unwrap();
        let revoked = revoke_at(&root, Manager::Detached, person, false).await;
        assert_eq!(
            revoked.as_ref().map_err(io::Error::kind).err(),
            Some(io::ErrorKind::TimedOut),
            "{revoked:?}; calls: {:?}",
            host.calls()
        );
        assert!(
            scope_record(&root, &unit).exists(),
            "the record of a live scope was dropped"
        );
        drop(host);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A login's record keeps every scope its launches lived in, without
    /// duplicates (J295 `stale`): a new launch adds its scope and never
    /// replaces one that may still hold the account's processes.
    #[tokio::test]
    async fn scope_records_keep_every_launch() {
        let (root, _, uid, unit) = system_login_fixture().await;
        let old = format!("/user.slice/user-{uid}.slice/session-1029.scope");
        let new = format!("/user.slice/user-{uid}.slice/session-1031.scope");
        record_scope(&root, &unit, uid, &old).unwrap();
        record_scope(&root, &unit, uid, &new).unwrap();
        record_scope(&root, &unit, uid, &old).unwrap();
        assert_eq!(recorded_scopes(&root, &unit, uid).unwrap(), [old, new]);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Revocation kills every recorded scope of a login, not only the first:
    /// a stale record of an earlier launch next to the live one (J295 P1).
    #[tokio::test]
    async fn revocation_kills_every_recorded_scope() {
        let (root, person, uid, unit) = system_login_fixture().await;
        let host = ScriptedHost::new(&root, &unit, uid, true, true);
        let live = host.scope.parent().unwrap().join("session-8.scope");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("cgroup.kill"), b"").unwrap();
        std::fs::write(live.join("cgroup.events"), "populated 0\n").unwrap();
        record_scope(
            &root,
            &unit,
            uid,
            &format!("/user.slice/user-{uid}.slice/session-7.scope"),
        )
        .unwrap();
        record_scope(
            &root,
            &unit,
            uid,
            &format!("/user.slice/user-{uid}.slice/session-8.scope"),
        )
        .unwrap();
        let revoked = revoke_at(&root, Manager::System, person, false).await;
        assert!(revoked.is_ok(), "{revoked:?}; calls: {:?}", host.calls());
        for scope in [&host.scope, &live] {
            assert_eq!(
                std::fs::read(scope.join("cgroup.kill")).unwrap(),
                b"1",
                "{} survived",
                scope.display()
            );
        }
        drop(host);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A session scope that stays populated after `cgroup.kill` (a process in
    /// uninterruptible sleep) fails the revocation: success is reported only
    /// for a login shown gone (J291).
    #[tokio::test]
    async fn revocation_fails_while_the_session_scope_stays_populated() {
        let (root, person, uid, unit) = system_login_fixture().await;
        let host = ScriptedHost::new(&root, &unit, uid, true, false);
        record_scope(
            &root,
            &unit,
            uid,
            &format!("/user.slice/user-{uid}.slice/session-7.scope"),
        )
        .unwrap();
        let revoked = revoke_at(&root, Manager::System, person, false).await;
        assert_eq!(
            revoked.as_ref().map_err(io::Error::kind),
            Err(io::ErrorKind::TimedOut),
            "{revoked:?}; calls: {:?}",
            host.calls()
        );
        assert!(
            scope_record(&root, &unit).exists(),
            "a failed revocation forgot the login"
        );
        // It failed at the populated scope, before going on to the account.
        assert_eq!(
            std::fs::read(host.services.join("cgroup.kill")).unwrap(),
            b"",
            "the revocation went on past a populated session scope"
        );
        drop(host);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A login that left its runtime directory but has neither a unit nor a
    /// recorded scope (an `su` fallback launched when the manager probe timed
    /// out, J291) cannot be shown ended, so revocation fails instead of
    /// reporting success over a live shell.
    #[tokio::test]
    async fn revocation_fails_closed_for_a_login_it_cannot_account_for() {
        let (root, person, uid, unit) = system_login_fixture().await;
        std::fs::create_dir(root.join(&unit)).unwrap();
        let host = ScriptedHost::new(&root, &unit, uid, false, true);
        let revoked = revoke_at(&root, Manager::System, person, false).await;
        assert!(
            revoked
                .as_ref()
                .is_err_and(|error| error.to_string().contains("can't be proven gone")),
            "an unprovable login must say why: {revoked:?}"
        );
        assert!(
            revoked.is_err(),
            "an unaccounted login was reported revoked; calls: {:?}",
            host.calls()
        );
        drop(host);
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
