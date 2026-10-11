//! Tracks authenticated surviving shims and attached windows without per-session descriptors or idle timers [D13,D178], #151.

use crate::sessions::Session;
use infraternal_plugin_api::admission::NodeContext;
use std::{collections::HashMap, fs, io, path::PathBuf};

struct Live {
    path: PathBuf,
    process: PathBuf,
    birth_ticks: u64,
}

impl Live {
    fn alive(&self) -> bool {
        // A proc inode can change on cache eviction. The kernel birth clock is
        // stable across that change; a new PID incarnation cannot borrow the
        // recorded lifetime. process_birth_ticks excludes zombies; /proc/PID/exe
        // is unavailable for same-UID children after startup disables dumpability.
        // These checks run on control reads and retirement events, with no idle timer.
        self.path.exists()
            && birth(&self.process).is_ok_and(|value| value == Some(self.birth_ticks))
    }
}

fn birth(process: &std::path::Path) -> io::Result<Option<u64>> {
    use std::io::Read;
    let mut record = Vec::with_capacity(512);
    fs::File::open(process.join("stat"))?
        .take(4097)
        .read_to_end(&mut record)?;
    Ok(crate::sessions::process_birth_ticks(&record))
}

#[derive(Default)]
pub(crate) struct Registry(HashMap<[u8; 16], Live>);

impl Registry {
    pub(crate) fn insert(&mut self, session: &Session) -> io::Result<()> {
        let process = PathBuf::from(format!("/proc/{}", session.pid));
        let birth_ticks = match birth(&process) {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let live = Live {
            path: session.path.clone(),
            process,
            birth_ticks,
        };
        if live.alive() {
            self.0.insert(session.id, live);
        }
        Ok(())
    }

    pub(crate) fn refresh(&mut self) {
        self.0.retain(|_, live| live.alive());
    }
    pub(crate) fn get(&self, id: &[u8; 16]) -> Option<&PathBuf> {
        self.0.get(id).map(|live| &live.path)
    }
    pub(crate) fn context(&self) -> NodeContext {
        #[cfg(feature = "plugin-host-facts")]
        let background = self
            .0
            .values()
            .filter(|live| !windows::attached(&live.path))
            .count();
        #[cfg(not(feature = "plugin-host-facts"))]
        let background = 0;
        NodeContext {
            session_count: self.0.len(),
            background_session_count: background,
        }
    }
}

#[cfg(feature = "plugin-host-facts")]
pub(crate) mod windows {
    //! Counts window ownership even while credit starvation disconnects its local shim link.
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{Mutex, MutexGuard, OnceLock},
    };
    fn entries() -> MutexGuard<'static, HashMap<PathBuf, usize>> {
        static WINDOWS: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();
        WINDOWS
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(super) fn attached(path: &Path) -> bool {
        entries().contains_key(path)
    }
    pub(crate) struct Attachment(PathBuf);
    impl Attachment {
        pub(crate) fn new(path: PathBuf) -> Self {
            *entries().entry(path.clone()).or_default() += 1;
            Self(path)
        }
    }
    impl Drop for Attachment {
        fn drop(&mut self) {
            let mut entries = entries();
            if let Some(count) = entries.get_mut(&self.0) {
                *count -= 1;
                if *count == 0 {
                    entries.remove(&self.0);
                }
            }
        }
    }
}

#[cfg(all(test, feature = "plugin-host-facts"))]
mod tests {
    //! Reference counts preserve background truth across multiple windows; stale process identities never count.
    use super::*;

    #[tokio::test]
    async fn window_ownership_and_process_identity_bound_live_counts() {
        let path = PathBuf::from("../../target").join(format!("l{}", uuid::Uuid::new_v4()));
        fs::write(&path, b"").unwrap();
        let (peer, _remote) = tokio::net::UnixStream::pair().unwrap();
        let session = Session {
            id: [151; 16],
            path: path.clone(),
            peer,
            head: 0,
            pid: std::process::id(),
            caps: 0,
            supports_owner: false,
        };
        let mut registry = Registry::default();
        registry.insert(&session).unwrap();
        assert_eq!(
            registry.context(),
            NodeContext {
                session_count: 1,
                background_session_count: 1
            }
        );
        let first = windows::Attachment::new(path.clone());
        let second = windows::Attachment::new(path.clone());
        assert_eq!(registry.context().background_session_count, 0);
        drop(first);
        assert_eq!(registry.context().background_session_count, 0);
        drop(second);
        assert_eq!(registry.context().background_session_count, 1);
        registry.0.get_mut(&session.id).unwrap().birth_ticks = 0;
        registry.refresh();
        assert_eq!(registry.context(), NodeContext::default());
        registry.insert(&session).unwrap();
        fs::remove_file(path).unwrap();
        registry.refresh();
        assert_eq!(registry.context(), NodeContext::default());
    }

    #[tokio::test]
    async fn directory_inode_changes_do_not_retire_the_same_process() {
        let root = PathBuf::from("../../target").join(format!("identity-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("socket");
        fs::write(&path, b"").unwrap();
        let (peer, _remote) = tokio::net::UnixStream::pair().unwrap();
        let session = Session {
            id: [150; 16],
            path,
            peer,
            head: 0,
            pid: std::process::id(),
            caps: 0,
            supports_owner: false,
        };
        let mut registry = Registry::default();
        registry.insert(&session).unwrap();
        let view = root.join("process");
        fs::create_dir(&view).unwrap();
        // Kernel proc directory inodes can be recreated. Preserve the exact
        // process birth record and executable while presenting a fresh inode;
        // this models eviction without changing host caches or adding load.
        fs::write(view.join("stat"), fs::read("/proc/self/stat").unwrap()).unwrap();
        std::os::unix::fs::symlink("/proc/self/exe", view.join("exe")).unwrap();
        registry.0.get_mut(&session.id).unwrap().process = view;
        registry.refresh();
        let count = registry.context().session_count;
        fs::remove_dir_all(root).unwrap();
        assert_eq!(
            count, 1,
            "the same live process must survive proc inode recreation"
        );
    }
    #[test]
    fn process_birth_parser_handles_command_bytes_and_numeric_bounds() {
        use crate::sessions::process_birth_ticks;
        let record = |name: &[u8], state: &str, tick: &str| {
            let mut bytes = b"17 (".to_vec();
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(format!(") {state} {}{tick}\n", "0 ".repeat(18)).as_bytes());
            bytes
        };
        assert_eq!(
            process_birth_ticks(&record(b"name ) ( \xff", "S", "42")),
            Some(42)
        );
        assert_eq!(
            process_birth_ticks(&record(b"shim", "R", "18446744073709551615")),
            Some(u64::MAX)
        );
        for tick in ["-1", "+1", "1.0", "18446744073709551616"] {
            assert_eq!(process_birth_ticks(&record(b"shim", "R", tick)), None);
        }
        for state in ["Z", "X", "x", "12"] {
            assert_eq!(process_birth_ticks(&record(b"shim", state, "42")), None);
        }
        assert_eq!(process_birth_ticks(b"17 (shim) S 0"), None);
        let mut padded = record(b"shim", "S", "42");
        padded.resize(4096, b' ');
        assert_eq!(process_birth_ticks(&padded), Some(42));
        padded.push(b' ');
        assert_eq!(process_birth_ticks(&padded), None);
    }
}
