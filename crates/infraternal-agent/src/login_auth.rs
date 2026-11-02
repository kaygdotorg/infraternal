//! Caches manager-validated login identities with pinned kernel process directories [D240,D247].
#![forbid(unsafe_code)]
use std::{
    collections::HashMap,
    fs::File,
    io,
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

/// A pinned process directory cannot resolve to a later process that reuses its numeric PID.
#[derive(Clone)]
pub(crate) struct Identity {
    pub(crate) group: PathBuf,
    pub(crate) pid: i32,
    pub(crate) process: Arc<File>,
    pub(crate) parent: Option<Box<Self>>,
}
impl Identity {
    /// The magic descriptor link follows the pinned inode, rather than a fresh /proc/PID lookup.
    pub(crate) fn path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.process.as_raw_fd()
        ))
    }
    pub(crate) fn alive(&self) -> bool {
        self.record().is_ok_and(|(pid, parent)| {
            pid == self.pid
                && self
                    .parent
                    .as_ref()
                    .is_none_or(|pin| pin.pid == parent && pin.alive())
        })
    }
    /// Parse the original live process and its kernel parent, including comm names containing spaces.
    pub(crate) fn record(&self) -> io::Result<(i32, i32)> {
        let stat = std::fs::read_to_string(self.path().join("stat"))?;
        let pid = stat
            .split_once(' ')
            .and_then(|(pid, _)| pid.parse::<i32>().ok());
        let mut fields = stat
            .rsplit_once(") ")
            .map(|(_, tail)| tail.split_whitespace())
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let state = fields.next();
        let parent = fields.next().and_then(|value| value.parse::<i32>().ok());
        match (pid, state, parent) {
            (Some(pid), Some(state), Some(parent))
                if pid == self.pid
                    && parent >= 0
                    && state.len() == 1
                    && !matches!(state, "Z" | "X" | "x") =>
            {
                Ok((pid, parent))
            }
            _ => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        }
    }
}
type Key = (uuid::Uuid, u32);
static CACHE: OnceLock<Mutex<HashMap<Key, Identity>>> = OnceLock::new();

/// Reuse only the exact live process previously authenticated by the system manager.
pub(crate) fn get(person: uuid::Uuid, uid: u32, pid: i32) -> Option<Identity> {
    let mut cache = CACHE.get_or_init(Mutex::default).lock().ok()?;
    let key = (person, uid);
    let identity = cache.get(&key)?;
    if identity.pid == pid && identity.alive() {
        Some(identity.clone())
    } else {
        cache.remove(&key);
        None
    }
}
/// Bound retained descriptors and heap use; overflow simply takes the authenticated slow path.
pub(crate) fn remember(person: uuid::Uuid, uid: u32, identity: Identity) {
    if let Ok(mut cache) = CACHE.get_or_init(Mutex::default).lock() {
        if cache.len() >= 256 {
            // Reclaim retired logins only on admission, never from an idle timer.
            cache.retain(|_, old| old.alive());
        }
        if cache.len() < 256 || cache.contains_key(&(person, uid)) {
            cache.insert((person, uid), identity);
        }
    }
}
/// Explicit access removal evicts identities; opened handles retain their pin until launch completes.
pub(crate) fn forget(person: uuid::Uuid) {
    if let Ok(mut cache) = CACHE.get_or_init(Mutex::default).lock() {
        cache.retain(|(owner, _), _| *owner != person);
    }
}
/// Pin before manager authentication; validating the live pinned process after that query
/// prevents a replaced numeric process path from entering the cache.
pub(crate) fn pin(pid: i32, group: PathBuf) -> io::Result<Identity> {
    let identity = Identity {
        group,
        pid,
        process: Arc::new(File::open(format!("/proc/{pid}"))?),
        parent: None,
    };
    if !identity.alive() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    Ok(identity)
}

fn bounded(path: &std::path::Path) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    File::open(path)?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(bytes)
}

/// Authenticate an adopted fallback against its original privileged host login utility.
/// The root-owned su parent holds PAM open while its account worker lives. Its
/// exact public argv binds that login to one person/account/endpoint; a same-uid
/// socket alone never proves that the host opened a login.
pub(crate) fn fallback(
    worker: &mut Identity,
    person: uuid::Uuid,
    uid: u32,
    endpoint: &std::path::Path,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
    let (_, parent_pid) = worker.record()?;
    if parent_pid <= 1 {
        return Err(denied());
    }
    let parent = pin(parent_pid, PathBuf::new())?;
    let status = bounded(&parent.path().join("status"))?;
    let status = std::str::from_utf8(&status).map_err(|_| denied())?;
    let owners: Vec<u32> = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or_else(denied)?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| denied())?;
    let controller = nix::unistd::Uid::effective().as_raw();
    if owners.len() != 4 || owners[0] != controller || owners[1..].iter().any(|uid| *uid != 0) {
        return Err(denied());
    }
    // Read through the pinned original process. Refuse a host policy that
    // prevents authenticating its privileged utility instead of reverting to
    // UID-only adoption or granting process-inspection capabilities.
    let image = File::open(parent.path().join("exe"))?.metadata()?;
    let host_su = std::fs::metadata("/usr/bin/su").or_else(|_| std::fs::metadata("/bin/su"))?;
    if image.uid() != 0
        || image.mode() & 0o022 != 0
        || (image.dev(), image.ino()) != (host_su.dev(), host_su.ino())
    {
        return Err(denied());
    }
    let bytes = bounded(&parent.path().join("cmdline"))?;
    let arguments: Vec<_> = bytes.split(|byte| *byte == 0).collect();
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map_err(io::Error::from)?
        .ok_or_else(denied)?;
    if arguments.len() != 9
        || !arguments[8].is_empty()
        || arguments[1..5] != [b"--login".as_slice(), b"--shell", b"/bin/sh", b"--command"]
        || arguments[6] != b"--"
        || arguments[7] != user.name.as_bytes()
    {
        return Err(denied());
    }
    let script = std::str::from_utf8(arguments[5]).map_err(|_| denied())?;
    let encoded = script
        .strip_prefix("exec ")
        .and_then(|text| text.split_once(" __shim "))
        .map(|(exe, _)| exe)
        .ok_or_else(denied)?;
    let executable = encoded
        .strip_prefix('\'')
        .and_then(|text| text.strip_suffix('\''))
        .ok_or_else(denied)?
        .replace("'\"'\"'", "'");
    if script != crate::logins::fallback_script(&executable, endpoint, person, uid, controller)? {
        return Err(denied());
    }
    if controller == 0 {
        let path = std::path::Path::new(&executable);
        if path.parent() != Some(std::path::Path::new("/var/cache/infraternal-login-bin")) {
            return Err(denied());
        }
        let directory = std::fs::symlink_metadata(path.parent().ok_or_else(denied)?)?;
        let image = std::fs::symlink_metadata(path)?;
        if !directory.is_dir()
            || directory.uid() != 0
            || directory.mode() & 0o022 != 0
            || !image.is_file()
            || image.uid() != 0
            || image.mode() & 0o7777 != 0o555
        {
            return Err(denied());
        }
    }
    worker.parent = Some(Box::new(parent));
    if !worker.alive() {
        return Err(denied());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    //! Exercise real kernel process-directory lifetime rather than a timestamp approximation.
    use super::*;
    #[test]
    fn dead_process_pin_never_becomes_a_fresh_numeric_lookup() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let id = pin(i32::try_from(child.id()).unwrap(), PathBuf::new()).unwrap();
        assert!(id.alive());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!id.alive());
        assert!(std::fs::read_to_string(id.path().join("stat")).is_err());
    }
    #[test]
    fn cache_requires_person_account_pid_and_live_pin() {
        let person = uuid::Uuid::new_v4();
        let uid = nix::unistd::Uid::effective().as_raw();
        let pid = i32::try_from(std::process::id()).unwrap();
        remember(person, uid, pin(pid, PathBuf::from("/trusted")).unwrap());
        assert!(get(uuid::Uuid::new_v4(), uid, pid).is_none());
        assert!(get(person, uid.wrapping_add(1), pid).is_none());
        assert_eq!(
            get(person, uid, pid).unwrap().group,
            PathBuf::from("/trusted")
        );
        assert!(get(person, uid, pid.wrapping_add(1)).is_none());
    }
}
