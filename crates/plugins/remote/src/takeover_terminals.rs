//! Read-only, authenticated terminal records for a finished install's Take over confirmation (D368, #433).
//!
//! Take over may close an old install's open terminals, but only the ones the person reviewed, and only
//! when each is provably this install's. A terminal is identified by its shim, never by a unit name:
//!
//! - the socket under the install's `sessions/` answers with a shim whose kernel peer is root, whose
//!   `Hello` names that socket's session, and whose executable lies under the install's base (the same
//!   proof the holder scan uses);
//! - the shim's cgroup gives its close boundary. Before host login (the layout minipc01 still has) each
//!   shim ran in its own `infraternal-session-<id>.scope`. Since host login (11-01) a terminal's shim
//!   runs in the logind `session-N.scope` of its person's host login, beside that login's worker and
//!   shells. A login boundary counts only when logind's own record names as its leader the infraternal
//!   login worker started by the system manager, so someone's ordinary SSH or console login never does.
//!
//! Inside a boundary every process must belong to one of the reviewed terminals, or the whole offer is
//! refused (73): what Take over closes is exactly what the confirmation lists. Each record carries the
//! close unit, so the shell stops what was authenticated here and nothing it named itself.

use super::{
    kernel_bound, process_identity, read_session_frame, same, session_id, session_sockets,
};
use infraternal_shim::frame::Frame;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use ring::digest::{Context, SHA256};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    time::Duration,
};

/// Where a root agent publishes the login worker images (`logins::LOGIN_IMAGES` in the agent).
const LOGIN_IMAGES: &str = "/var/cache/infraternal-login-bin";

/// A stable process record excludes counters that change while a terminal is idle.
#[derive(Clone, Debug)]
struct Process {
    /// Kernel PID and birth ticks protect against PID reuse.
    pid: i32,
    /// The parent PID, which attributes tty-less background programs to their terminal.
    ppid: i32,
    birth: u64,
    uid: u32,
    /// The short executable name (`comm`), never argv.
    program: String,
    /// The controlling terminal's raw kernel device number, 0 for none.
    tty: u32,
    /// Foreground ownership is read from the PTY's process group, never argv.
    foreground: bool,
    /// The (device, inode) of the file it executes: its identity where a name proves nothing, such as
    /// the login's PAM helper, and bound into the fingerprint so a swapped binary is a change (#433).
    exe: (u64, u64),
}

/// Where a terminal's processes live, and the unit Take over stops to close them.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Boundary {
    /// The old layout: the terminal's own `infraternal-session-<id>.scope`.
    Scope(String),
    /// A host login: logind's `session-<session>.scope` of account `uid`.
    Login { session: String, uid: u32 },
}

impl Boundary {
    /// The system manager unit whose stop closes this boundary.
    fn unit(&self) -> String {
        match self {
            Self::Scope(unit) => unit.clone(),
            Self::Login { session, .. } => format!("session-{session}.scope"),
        }
    }
}

/// One authenticated shim and what its socket and `Hello` proved.
struct Shim {
    socket: fs::Metadata,
    path: PathBuf,
    id: String,
    pid: i32,
    birth: u64,
    created: u64,
    /// The PTY index the shim holds the master side of, when the kernel reports one.
    tty: Option<u32>,
}

/// One terminal's place inside its boundary: the program its row names and how many others run there.
#[derive(Debug, PartialEq, Eq)]
struct Attributed {
    /// Index into the boundary's members of the program named in the row.
    foreground: usize,
    /// Programs on this terminal besides that one (its shell, background jobs), shown as a count (P3-1).
    others: usize,
    /// `/dev/pts/<n>`, which tells rows of the same account and program apart (P3-2).
    tty: Option<u32>,
}

/// Read bounded proc files; incomplete or oversized metadata cannot authorize closing a scope.
fn bounded(path: impl AsRef<Path>) -> Result<String, u8> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| 73)?
        .take(16_385)
        .read_to_string(&mut text)
        .map_err(|_| 73)?;
    if text.len() > 16_384 {
        return Err(73);
    }
    Ok(text)
}

/// Keep public names bounded and printable; hex encoding preserves spaces and punctuation in fixed records.
fn name(value: &str) -> Result<String, u8> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.len() > 64 || value.chars().any(char::is_control) {
        return Err(73);
    }
    Ok(value.into())
}

/// Encode names without allowing their characters to alter shell field boundaries.
fn encoded_name(value: &str) -> Result<String, u8> {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        write!(encoded, "{byte:02x}").map_err(|_| 73)?;
    }
    Ok(encoded)
}

/// The index of `/dev/pts/<n>` for a raw `tty_nr`, or `None` for no terminal or any other device.
/// Unix98 PTY slaves use majors 136–143, each holding 256 minors.
fn pts(tty: u32) -> Option<u32> {
    let major = (tty >> 8) & 0xfff;
    let minor = (tty & 0xff) | ((tty >> 12) & 0xfff00);
    (136..=143)
        .contains(&major)
        .then(|| (major - 136) * 256 + minor)
}

/// Capture a boundary member's identity, its parent, its terminal and whether it leads that
/// terminal's foreground process group.
fn process(pid: i32) -> Result<Process, u8> {
    let stat = bounded(format!("/proc/{pid}/stat"))?;
    let (_, suffix) = stat.rsplit_once(')').ok_or(73)?;
    let fields: Vec<_> = suffix.split_ascii_whitespace().collect();
    let field = |index| fields.get(index).copied().ok_or(73);
    if matches!(field(0)?, "Z" | "X" | "x") {
        return Err(73);
    }
    let birth = field(19)?.parse().map_err(|_| 73)?;
    let tty: u32 = field(4)?.parse::<i32>().map_err(|_| 73)?.cast_unsigned();
    let status = bounded(format!("/proc/{pid}/status"))?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_ascii_whitespace().next())
        .ok_or(73)?
        .parse()
        .map_err(|_| 73)?;
    Ok(Process {
        pid,
        ppid: field(1)?.parse().map_err(|_| 73)?,
        birth,
        uid,
        program: name(&bounded(format!("/proc/{pid}/comm"))?)?,
        tty,
        foreground: tty != 0 && field(5)?.parse::<i32>().map_err(|_| 73)? == pid,
        exe: {
            // `/proc/<pid>/exe` resolves to the executed file even when it was replaced or deleted.
            let file = fs::metadata(format!("/proc/{pid}/exe")).map_err(|_| 73)?;
            (file.dev(), file.ino())
        },
    })
}

/// The (device, inode) of the system manager's own executables that may run the login's PAM helper:
/// `systemd-executor` beside `/proc/1/exe` (systemd 255 and later) and `/proc/1/exe` itself (earlier
/// systemd forks the helper from the manager). Each must be a root-owned regular file nobody else can
/// write. An account cannot make a process run one of these as a long-lived helper of its login, so
/// they identify the real `(sd-pam)` where its name proves nothing (#433 P2-1).
fn executors() -> Vec<(u64, u64)> {
    let Ok(manager) = executable(1) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for path in [manager.with_file_name("systemd-executor"), manager] {
        if let Ok(file) = fs::symlink_metadata(&path)
            && file.is_file()
            && file.uid() == 0
            && file.permissions().mode() & 0o022 == 0
        {
            found.push((file.dev(), file.ino()));
        }
    }
    found
}

/// Find the close boundary for a shim of session `id` from its cgroup v2 path.
///
/// The old layout is the shim's own `infraternal-session-<id>.scope`, nested cgroups included. That
/// scope must be a direct child of `system.slice`: it is the system unit Take over stops, so the
/// processes read and the unit stopped are the same cgroup (#433 P3-4). A host
/// login is exactly `/user.slice/user-<uid>.slice/session-<N>.scope`, the shape the agent itself accepts
/// for a login (`logins::login_cgroup`). Anything else, including another session's scope, is refused.
fn boundary(path: &str, id: &str) -> Result<(PathBuf, Boundary), u8> {
    let parts: Vec<_> = path.strip_prefix('/').ok_or(73)?.split('/').collect();
    if parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
        return Err(73);
    }
    let wanted = format!("infraternal-session-{id}.scope");
    if let ["system.slice", scope, ..] = parts.as_slice()
        && *scope == wanted
    {
        let root: PathBuf = ["/sys/fs/cgroup", "system.slice", scope].iter().collect();
        return Ok((root, Boundary::Scope(wanted)));
    }
    if parts.contains(&wanted.as_str()) {
        return Err(73);
    }
    let ["user.slice", user, scope] = parts.as_slice() else {
        return Err(73);
    };
    let uid = user
        .strip_prefix("user-")
        .and_then(|rest| rest.strip_suffix(".slice"))
        .filter(|uid| !uid.is_empty() && uid.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|uid| uid.parse().ok())
        .ok_or(73)?;
    let session = scope
        .strip_prefix("session-")
        .and_then(|rest| rest.strip_suffix(".scope"))
        .filter(|session| {
            !session.is_empty()
                && session.len() <= 32
                && session.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .ok_or(73)?;
    let root: PathBuf = std::iter::once("/sys/fs/cgroup")
        .chain(parts.iter().copied())
        .collect();
    Ok((
        root,
        Boundary::Login {
            session: session.into(),
            uid,
        },
    ))
}

/// The leader PID that logind recorded for session `session` of account `uid`, from its
/// `/run/systemd/sessions/<session>` record. Only logind (root) writes that file; each key appears once.
fn login_leader(record: &str, session: &str, uid: u32) -> Result<i32, u8> {
    let mut values = BTreeMap::new();
    for line in record.lines() {
        if let Some((key, value)) = line.split_once('=')
            && matches!(key, "UID" | "SCOPE" | "LEADER")
            && values.insert(key, value).is_some()
        {
            return Err(73);
        }
    }
    if values.get("SCOPE") != Some(&format!("session-{session}.scope").as_str())
        || values.get("UID") != Some(&uid.to_string().as_str())
    {
        return Err(73);
    }
    let leader: i32 = values.get("LEADER").ok_or(73)?.parse().map_err(|_| 73)?;
    if leader <= 1 {
        return Err(73);
    }
    Ok(leader)
}

/// The executable a process runs, without the kernel's ` (deleted)` mark for a replaced file.
fn executable(pid: i32) -> Result<PathBuf, u8> {
    use std::os::unix::ffi::OsStrExt as _;
    let target = fs::read_link(format!("/proc/{pid}/exe")).map_err(|_| 73)?;
    let bytes = target.as_os_str().as_bytes();
    let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

/// Whether the logind session's leader is the infraternal login worker: started by the system manager
/// (parent PID 1), running `__shim --login-worker` from a root-owned image in [`LOGIN_IMAGES`] that only
/// root can replace, and a member of that same session. An `sshd` or `login` leader never matches.
fn verified_worker(leader: i32) -> Result<(), u8> {
    let images = fs::symlink_metadata(LOGIN_IMAGES).map_err(|_| 73)?;
    if !images.is_dir() || images.uid() != 0 || images.permissions().mode() & 0o022 != 0 {
        return Err(73);
    }
    let image = executable(leader)?;
    if image.parent() != Some(Path::new(LOGIN_IMAGES)) {
        return Err(73);
    }
    let arguments = bounded(format!("/proc/{leader}/cmdline"))?;
    let mut arguments = arguments.split('\0').skip(1);
    if arguments.next() != Some("__shim") || arguments.next() != Some("--login-worker") {
        return Err(73);
    }
    if process(leader)?.ppid != 1 {
        return Err(73);
    }
    Ok(())
}

/// The PTY index a shim holds the master side of, read from the kernel's `tty-index` in its fdinfo.
/// `None` when it holds none; two different ones are refused.
fn shim_tty(pid: i32) -> Result<Option<u32>, u8> {
    let mut found = None;
    for entry in fs::read_dir(format!("/proc/{pid}/fd")).map_err(|_| 73)? {
        let entry = entry.map_err(|_| 73)?;
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        if target != Path::new("/dev/ptmx") && target != Path::new("/dev/pts/ptmx") {
            continue;
        }
        let info = bounded(format!(
            "/proc/{pid}/fdinfo/{}",
            entry.file_name().to_string_lossy()
        ))?;
        let index = info
            .lines()
            .find_map(|line| line.strip_prefix("tty-index:"))
            .ok_or(73)?
            .trim()
            .parse::<u32>()
            .map_err(|_| 73)?;
        if found.is_some_and(|found| found != index) {
            return Err(73);
        }
        found = Some(index);
    }
    Ok(found)
}

/// Enumerate all descendants too: stopping a scope closes its whole cgroup tree.
fn members(
    path: &Path,
    depth: u8,
    output: &mut Vec<Process>,
    visited: &mut usize,
) -> Result<(), u8> {
    *visited += 1;
    if depth > 8 || *visited > 1024 {
        return Err(73);
    }
    for pid in bounded(path.join("cgroup.procs"))?.split_ascii_whitespace() {
        output.push(process(pid.parse().map_err(|_| 73)?)?);
        if output.len() > 1024 {
            return Err(73);
        }
    }
    for entry in fs::read_dir(path).map_err(|_| 73)? {
        let entry = entry.map_err(|_| 73)?;
        if entry.file_type().map_err(|_| 73)?.is_dir() {
            members(&entry.path(), depth + 1, output, visited)?;
        }
    }
    Ok(())
}

/// Attribute every member of one boundary to the terminals in it.
///
/// `shims` are this install's authenticated shims in the boundary, each with the PTY index it serves.
/// Without a `leader` the boundary is an old-layout scope: it holds exactly one shim, and everything
/// else in it is that terminal's. With a `leader` (the verified login worker) it is a host login: each
/// process belongs to the terminal of its nearest ancestor, itself included, that has a PTY, and that
/// PTY must be one of the shims'. The worker, the shims and systemd's `(sd-pam)` helper are the login
/// itself and belong to no terminal. The helper is recognised by identity, never by name: it runs one
/// of the system manager's `executors` (device and inode), as the login's account, as a tty-less child
/// of the worker born before every other process of the login but the worker, and there is only one. A process under neither the worker nor a shim, a PTY no shim serves,
/// or a tty-less process with no such ancestor is refused (73), because the person could not have seen
/// it in the confirmation.
fn attribute(
    members: &[Process],
    shims: &[(i32, Option<u32>)],
    leader: Option<i32>,
    executors: &[(u64, u64)],
) -> Result<Vec<Attributed>, u8> {
    let index: BTreeMap<_, _> = members
        .iter()
        .enumerate()
        .map(|(at, process)| (process.pid, at))
        .collect();
    if index.len() != members.len()
        || shims.iter().any(|(pid, _)| !index.contains_key(pid))
        || shims.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || leader.is_some_and(|leader| {
            !index.contains_key(&leader) || shims.iter().any(|(pid, _)| *pid == leader)
        })
    {
        return Err(73);
    }
    // `PAMName=` leaves systemd's PAM helper, `(sd-pam)`, in the session scope: the executor process
    // forked right after the worker, which drops to the login's account and never execs (seen on the
    // J311b guest, systemd 257). It is part of the login like the worker itself. The worker is a child
    // subreaper, so a terminal's detached program lands beside it with no tty; only the helper's
    // identity tells them apart (#433 P2-1, J462). Anything on a terminal stays that terminal's.
    let helper = leader.and_then(|leader| {
        let worker = members.iter().find(|process| process.pid == leader)?;
        let earliest = members
            .iter()
            .filter(|process| process.pid != leader)
            .map(|process| process.birth)
            .min()?;
        let mut candidates = members.iter().filter(|process| {
            process.ppid == leader
                && process.tty == 0
                && process.uid == worker.uid
                && process.program == "(sd-pam)"
                && executors.contains(&process.exe)
        });
        let found = candidates.next()?;
        (candidates.next().is_none() && found.birth == earliest).then_some(found.pid)
    });
    let pam_helper = |pid: i32| helper == Some(pid);
    let infrastructure = |pid: i32| {
        leader == Some(pid) || shims.iter().any(|(shim, _)| *shim == pid) || pam_helper(pid)
    };
    // Which terminal each member belongs to, as an index into `shims`.
    let mut owners = vec![None; members.len()];
    if leader.is_none() {
        let [_] = shims else { return Err(73) };
        owners.fill(Some(0));
    } else {
        for (at, process) in members.iter().enumerate() {
            if infrastructure(process.pid) {
                continue;
            }
            let mut current = process;
            let mut tty = None;
            let mut root = process.pid;
            for _ in 0..=members.len() {
                // The worker and shims hold no controlling terminal of their own; never take one from them.
                if tty.is_none() && current.tty != 0 && !infrastructure(current.pid) {
                    tty = Some(current.tty);
                }
                root = current.pid;
                match index.get(&current.ppid) {
                    Some(&parent) if !infrastructure(current.pid) => current = &members[parent],
                    _ => break,
                }
            }
            if !infrastructure(root) {
                return Err(73);
            }
            let tty = pts(tty.ok_or(73)?).ok_or(73)?;
            owners[at] = Some(
                shims
                    .iter()
                    .position(|(_, shim)| *shim == Some(tty))
                    .ok_or(73)?,
            );
        }
    }
    let mut attributed = Vec::with_capacity(shims.len());
    for (terminal, (_, tty)) in shims.iter().enumerate() {
        if leader.is_some() && tty.is_none() {
            return Err(73);
        }
        let on = |at: &usize| owners[*at] == Some(terminal) && !infrastructure(members[*at].pid);
        let foreground = (0..members.len())
            .filter(on)
            .filter(|at| members[*at].foreground)
            .min_by_key(|at| (members[*at].birth, members[*at].pid))
            .ok_or(73)?;
        // Shims and the worker are never counted: they are how the terminal runs, not what runs in it.
        let others = (0..members.len()).filter(on).count() - 1;
        attributed.push(Attributed {
            foreground,
            others,
            tty: tty.or_else(|| pts(members[foreground].tty)),
        });
    }
    Ok(attributed)
}

/// Authenticate the shim behind one bound session socket and find its boundary. The shim's executable
/// must lie under the install's canonical base: a socket name or a scope name alone proves nothing.
fn shim(path: &Path, before: &fs::Metadata, base: &Path) -> Result<(Shim, PathBuf, Boundary), u8> {
    let id = uuid::Uuid::from_bytes(session_id(path)?)
        .simple()
        .to_string();
    let mut stream = UnixStream::connect(path).map_err(|_| 73)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| 73)?;
    let credentials = getsockopt(&stream, PeerCredentials).map_err(|_| 73)?;
    let pid = credentials.pid();
    if pid <= 0 || credentials.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(73);
    }
    let birth = process_identity(pid).map_err(|_| 73)?.0;
    let Frame::Hello {
        version: 1,
        session,
        pid: reported,
        created,
        ..
    } = read_session_frame(&mut stream).map_err(|_| 73)?
    else {
        return Err(73);
    };
    if session != session_id(path)?
        || i32::try_from(reported).ok() != Some(pid)
        || !(1000..=253_402_300_799_999).contains(&created)
    {
        return Err(73);
    }
    if !executable(pid)?.starts_with(base) {
        return Err(73);
    }
    let groups = bounded(format!("/proc/{pid}/cgroup"))?;
    let group = groups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(73)?;
    let (root, boundary) = boundary(group, &id)?;
    let tty = shim_tty(pid)?;
    Ok((
        Shim {
            socket: before.clone(),
            path: path.to_owned(),
            id,
            pid,
            birth,
            created,
            tty,
        },
        root,
        boundary,
    ))
}

/// One digest of a boundary and every process in it, bound into each of its records: any process
/// starting, ending, or changing account, program, executable, terminal, foreground or parent invalidates the
/// confirmation. A shim's parent is left out: a shim is bound by its pid and birth, and on a host login
/// its parent is the old agent, which Take over stops before it compares the records again (the shim is
/// then reparented, #433 e2e L1).
fn members_digest(
    root: &Path,
    inode: u64,
    processes: &[Process],
    shims: &[i32],
    leader: Option<i32>,
) -> ring::digest::Digest {
    let mut hash = Context::new(&SHA256);
    hash.update(&inode.to_be_bytes());
    hash.update(root.as_os_str().as_encoded_bytes());
    hash.update(&[0]);
    for process in processes {
        let parent = if shims.contains(&process.pid) {
            0
        } else {
            process.ppid
        };
        hash.update(&process.pid.to_be_bytes());
        hash.update(&parent.to_be_bytes());
        hash.update(&process.birth.to_be_bytes());
        hash.update(&process.uid.to_be_bytes());
        hash.update(&process.tty.to_be_bytes());
        hash.update(&process.exe.0.to_be_bytes());
        hash.update(&process.exe.1.to_be_bytes());
        hash.update(process.program.as_bytes());
        hash.update(&[
            0,
            u8::from(process.foreground),
            u8::from(leader == Some(process.pid)),
        ]);
    }
    hash.finish()
}

/// The records of one boundary: every member is read once, attributed, and bound into each record's
/// fingerprint, so any process starting, ending or changing there invalidates the confirmation.
fn boundary_records(
    root: &Path,
    boundary: &Boundary,
    mut shims: Vec<Shim>,
) -> Result<Vec<String>, u8> {
    shims.sort_by_key(|shim| shim.pid);
    let leader = match boundary {
        Boundary::Scope(_) => None,
        Boundary::Login { session, uid } => {
            let leader = login_leader(
                &bounded(format!("/run/systemd/sessions/{session}"))?,
                session,
                *uid,
            )?;
            verified_worker(leader)?;
            Some(leader)
        }
    };
    let scope_metadata = fs::metadata(root).map_err(|_| 73)?;
    let mut processes = Vec::new();
    let mut visited = 0;
    members(root, 0, &mut processes, &mut visited)?;
    processes.sort_by_key(|process| process.pid);
    for shim in &shims {
        if !processes
            .iter()
            .any(|process| process.pid == shim.pid && process.birth == shim.birth)
        {
            return Err(73);
        }
    }
    let pairs: Vec<_> = shims.iter().map(|shim| (shim.pid, shim.tty)).collect();
    let executors = if leader.is_some() {
        executors()
    } else {
        Vec::new()
    };
    let attributed = attribute(&processes, &pairs, leader, &executors)?;
    let unit = boundary.unit();
    let shim_pids: Vec<_> = shims.iter().map(|shim| shim.pid).collect();
    let members_hash = members_digest(root, scope_metadata.ino(), &processes, &shim_pids, leader);
    let mut records = Vec::with_capacity(shims.len());
    for (shim, place) in shims.iter().zip(attributed) {
        let foreground = &processes[place.foreground];
        let account = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(foreground.uid))
            .map_err(|_| 73)?
            .ok_or(73)?
            .name;
        let account = name(&account)?;
        let tty = place
            .tty
            .map_or_else(|| "-".to_owned(), |tty| format!("pts/{tty}"));
        let mut hash = Context::new(&SHA256);
        for number in [
            shim.socket.dev(),
            shim.socket.ino(),
            u64::from(shim.socket.uid()),
            u64::try_from(shim.pid).map_err(|_| 73)?,
            shim.birth,
            shim.created,
        ] {
            hash.update(&number.to_be_bytes());
        }
        hash.update(unit.as_bytes());
        hash.update(&[0]);
        hash.update(members_hash.as_ref());
        if process_identity(shim.pid).map_err(|_| 73)?.0 != shim.birth
            || !same(
                &shim.socket,
                &fs::symlink_metadata(&shim.path).map_err(|_| 73)?,
            )
        {
            return Err(73);
        }
        let mut fingerprint = String::with_capacity(64);
        for byte in hash.finish().as_ref() {
            write!(fingerprint, "{byte:02x}").map_err(|_| 73)?;
        }
        // Hello dates sessions in milliseconds; the public confirmation uses Unix seconds.
        let since = shim.created / 1000;
        records.push(format!(
            "{},{},{},{since},{},{},{unit},{fingerprint}",
            shim.id,
            encoded_name(&account)?,
            encoded_name(&foreground.program)?,
            encoded_name(&tty)?,
            place.others,
        ));
    }
    Ok(records)
}

/// Report only bound endpoints, in canonical id order, or refuse the whole offer if any cannot be
/// attributed. Each record is `<id>,<account>,<program>,<since>,<tty>,<others>,<unit>,<fingerprint>`,
/// with names hex-encoded. No input is sent to a terminal and nothing is stopped by this read-only mode.
pub(super) fn records(runtime: &File, base: &Path) -> Result<String, u8> {
    let base = fs::canonicalize(base).map_err(|_| 73)?;
    let mut groups: BTreeMap<PathBuf, (Boundary, Vec<Shim>)> = BTreeMap::new();
    for (path, metadata) in session_sockets(runtime)? {
        if !kernel_bound(&[(path.clone(), metadata.clone())]).ok_or(73)? {
            continue;
        }
        let (shim, root, boundary) = shim(&path, &metadata, &base)?;
        let group = groups
            .entry(root)
            .or_insert_with(|| (boundary.clone(), Vec::new()));
        if group.0 != boundary {
            return Err(73);
        }
        group.1.push(shim);
        if groups.values().map(|group| group.1.len()).sum::<usize>() > 1024 {
            return Err(73);
        }
    }
    let mut records = Vec::new();
    for (root, (boundary, shims)) in groups {
        records.extend(boundary_records(&root, &boundary, shims)?);
    }
    records.sort();
    if records
        .windows(2)
        .any(|pair| pair[0].split(',').next() == pair[1].split(',').next())
    {
        return Err(73);
    }
    Ok(records.join(" "))
}

/// Unit tests for the boundary, logind record and attribution rules (both terminal layouts).
#[cfg(test)]
#[path = "takeover_terminals_tests.rs"]
mod tests;
