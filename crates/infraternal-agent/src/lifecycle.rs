//! Tracks authenticated surviving shims and attached windows without per-session descriptors or idle timers [D13,D178], #151.

use crate::sessions::Session;
use infraternal_plugin_api::admission::NodeContext;
use std::{collections::HashMap, fs, io, os::unix::fs::MetadataExt, path::PathBuf};

struct Live {
    path: PathBuf,
    process: PathBuf,
    birth_inode: u64,
}

impl Live {
    fn alive(&self) -> bool {
        // proc directory identity changes on PID reuse; exe disappears for a
        // zombie. Socket existence alone cannot distinguish an abruptly stopped
        // shim from its stale rendezvous. These checks run on control reads only.
        self.path.exists()
            && fs::metadata(&self.process).is_ok_and(|meta| meta.ino() == self.birth_inode)
            && self.process.join("exe").exists()
    }
}

#[derive(Default)]
pub(crate) struct Registry(HashMap<[u8; 16], Live>);

impl Registry {
    pub(crate) fn insert(&mut self, session: &Session) -> io::Result<()> {
        let process = PathBuf::from(format!("/proc/{}", session.pid));
        let meta = match fs::metadata(&process) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let live = Live {
            path: session.path.clone(),
            process,
            birth_inode: meta.ino(),
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
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/session-bounds")
            .join(format!("l{}", uuid::Uuid::new_v4()));
        fs::write(&path, b"").unwrap();
        let (peer, _remote) = tokio::net::UnixStream::pair().unwrap();
        let session = Session {
            id: [151; 16],
            path: path.clone(),
            peer,
            head: 0,
            pid: std::process::id(),
            caps: 0,
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
        registry.0.get_mut(&session.id).unwrap().birth_inode = 0;
        registry.refresh();
        assert_eq!(registry.context(), NodeContext::default());
        registry.insert(&session).unwrap();
        fs::remove_file(path).unwrap();
        registry.refresh();
        assert_eq!(registry.context(), NodeContext::default());
    }
}
