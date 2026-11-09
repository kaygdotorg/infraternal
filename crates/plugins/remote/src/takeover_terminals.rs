//! Read-only, authenticated terminal records for a finished install's Take over confirmation (D368).
//! Only the endpoint's own shim and its exact session scope establish ownership; names alone never do.

use super::{
    kernel_bound, process_identity, read_session_frame, same, session_id, session_sockets,
};
use infraternal_shim::frame::Frame;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use ring::digest::{Context, SHA256};
use std::{
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::{Path, PathBuf},
    time::Duration,
};

/// A stable process record excludes counters that change while a terminal is idle.
struct Process {
    /// Kernel PID and birth ticks protect against PID reuse.
    pid: i32,
    birth: u64,
    /// Foreground ownership is read from the PTY's process group, never argv.
    uid: u32,
    program: String,
    foreground: bool,
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

/// Capture a scope member's identity and whether it leads the terminal's foreground process group.
fn process(pid: i32) -> Result<Process, u8> {
    let stat = bounded(format!("/proc/{pid}/stat"))?;
    let (_, suffix) = stat.rsplit_once(')').ok_or(73)?;
    let fields: Vec<_> = suffix.split_ascii_whitespace().collect();
    let field = |index| fields.get(index).copied().ok_or(73);
    if matches!(field(0)?, "Z" | "X" | "x") {
        return Err(73);
    }
    let birth = field(19)?.parse().map_err(|_| 73)?;
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
        birth,
        uid,
        program: name(&bounded(format!("/proc/{pid}/comm"))?)?,
        foreground: field(4)? != "0" && field(5)?.parse::<i32>().map_err(|_| 73)? == pid,
    })
}

/// Find the authenticated shim's cgroup v2 scope. Nested scope membership remains inside the same close boundary.
fn scope(pid: i32, id: &str) -> Result<PathBuf, u8> {
    let groups = bounded(format!("/proc/{pid}/cgroup"))?;
    let path = groups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(73)?;
    let wanted = format!("infraternal-session-{id}.scope");
    let mut root = PathBuf::from("/sys/fs/cgroup");
    for component in Path::new(path).components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(part) => {
                root.push(part);
                if part == wanted.as_str() {
                    return Ok(root);
                }
            }
            _ => return Err(73),
        }
    }
    Err(73)
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

/// Bind the displayed account/program/date to the socket inode, shim, scope inode and every scope member.
fn terminal(path: &Path, before: &fs::Metadata) -> Result<String, u8> {
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
    let scope = scope(pid, &id)?;
    let scope_metadata = fs::metadata(&scope).map_err(|_| 73)?;
    let mut processes = Vec::new();
    let mut visited = 0;
    members(&scope, 0, &mut processes, &mut visited)?;
    processes.sort_by_key(|process| process.pid);
    if !processes
        .iter()
        .any(|process| process.pid == pid && process.birth == birth)
    {
        return Err(73);
    }
    let foreground = processes
        .iter()
        .filter(|process| process.foreground)
        .min_by_key(|process| (process.birth, process.pid))
        .ok_or(73)?;
    let account = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(foreground.uid))
        .map_err(|_| 73)?
        .ok_or(73)?
        .name;
    let account = name(&account)?;
    let mut hash = Context::new(&SHA256);
    for number in [
        before.dev(),
        before.ino(),
        u64::from(before.uid()),
        u64::try_from(pid).map_err(|_| 73)?,
        birth,
        created,
        scope_metadata.ino(),
    ] {
        hash.update(&number.to_be_bytes());
    }
    hash.update(scope.as_os_str().as_encoded_bytes());
    hash.update(&[0]);
    for process in &processes {
        hash.update(&process.pid.to_be_bytes());
        hash.update(&process.birth.to_be_bytes());
        hash.update(&process.uid.to_be_bytes());
        hash.update(process.program.as_bytes());
        hash.update(&[0, u8::from(process.foreground)]);
    }
    if process_identity(pid).map_err(|_| 73)?.0 != birth
        || !same(before, &fs::symlink_metadata(path).map_err(|_| 73)?)
    {
        return Err(73);
    }
    let mut fingerprint = String::with_capacity(64);
    for byte in hash.finish().as_ref() {
        write!(fingerprint, "{byte:02x}").map_err(|_| 73)?;
    }
    // Hello dates sessions in milliseconds; the public confirmation uses Unix seconds.
    let since = created / 1000;
    Ok(format!(
        "{id},{},{},{since},{fingerprint}",
        encoded_name(&account)?,
        encoded_name(&foreground.program)?
    ))
}

/// Report only bound endpoints, in canonical id order, or refuse the whole offer if any cannot be attributed.
/// No input is sent to a terminal and no scope is stopped by this read-only mode.
pub(super) fn records(runtime: &File) -> Result<String, u8> {
    let mut records = Vec::new();
    for (path, metadata) in session_sockets(runtime)? {
        if !kernel_bound(&[(path.clone(), metadata.clone())]).ok_or(73)? {
            continue;
        }
        records.push(terminal(&path, &metadata)?);
        if records.len() > 1024 {
            return Err(73);
        }
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

#[cfg(test)]
#[path = "takeover_terminals_tests.rs"]
mod tests;
