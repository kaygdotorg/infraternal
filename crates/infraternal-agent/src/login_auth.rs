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
    /// True while the pinned process is still the same live process, and (when a
    /// parent pin exists) is still a child of that exact parent, recursively.
    /// Zombie and dead states count as not alive. Any read error counts as not alive.
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
/// Cache key: the person (as a UUID) and the host account's numeric uid.
type Key = (uuid::Uuid, u32);
/// Process-wide cache of authenticated login identities, shared by all
/// requests. Bounded to 256 entries by `remember`.
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
