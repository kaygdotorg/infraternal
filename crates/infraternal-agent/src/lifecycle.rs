//! Tracks authenticated surviving shims and attached windows with one shared process-exit readiness source and no idle timers [D13,D178,D217], #151/#154.

use crate::sessions::Session;
use infraternal_plugin_api::admission::NodeContext;
#[cfg(target_os = "linux")]
use std::fs;
use std::{collections::HashMap, io, path::PathBuf};

struct Live {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    process: PathBuf,
    #[cfg(target_os = "macos")]
    pid: u32,
    birth_ticks: u64,
}

impl Live {
    #[cfg(target_os = "linux")]
    fn alive(&self) -> bool {
        // A proc inode can change on cache eviction. The kernel birth clock is
        // stable across that change; a new PID incarnation cannot borrow the
        // recorded lifetime; the birth parser also excludes dead states. Check
        // the executable link without following it: CA protection makes live
        // shims non-dumpable, denying ptrace-gated /proc/<pid>/exe traversal.
        // Lifecycle events recheck this identity; no task or timer runs per shim.
        self.path.exists()
            && birth(&self.process).is_ok_and(|value| value == Some(self.birth_ticks))
            && fs::symlink_metadata(self.process.join("exe"))
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
    }

    // macOS identifies one PID lifetime by its kernel start time (microseconds,
    // proc_pidinfo); zombies report no identity, as dead states do on Linux.
    #[cfg(target_os = "macos")]
    fn alive(&self) -> bool {
        self.path.exists()
            && infraternal_shim::process_start(self.pid)
                .is_ok_and(|value| value == Some(self.birth_ticks))
    }
}

#[cfg(target_os = "linux")]
fn birth(process: &std::path::Path) -> io::Result<Option<u64>> {
    use std::io::Read;
    let mut record = Vec::with_capacity(512);
    fs::File::open(process.join("stat"))?
        .take(4097)
        .read_to_end(&mut record)?;
    Ok(crate::sessions::process_birth_ticks(&record))
}

#[derive(Default)]
pub(crate) struct Registry(HashMap<[u8; 16], Live>, crate::process_exits::ProcessExits);

impl Registry {
    pub(crate) fn insert(&mut self, session: &Session) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        let process = PathBuf::from(format!("/proc/{}", session.pid));
        #[cfg(target_os = "linux")]
        let identity = birth(&process);
        #[cfg(target_os = "macos")]
        let identity = infraternal_shim::process_start(session.pid);
        let birth_ticks = match identity {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let live = Live {
            path: session.path.clone(),
            #[cfg(target_os = "linux")]
            process,
            #[cfg(target_os = "macos")]
            pid: session.pid,
            birth_ticks,
        };
        // Authenticate lifetime across pidfd/kqueue registration: PID reuse
        // between the Hello, birth read and kernel registration cannot claim an
        // old session ID. A death during registration is already readable.
        if !self.1.watch(session.id, session.pid)? {
            return Ok(());
        }
        if !live.alive() {
            self.1.retain(|id| *id != session.id);
            return Ok(());
        }
        self.0.insert(session.id, live);
        Ok(())
    }

    /// Removes shims whose process identity or rendezvous path has disappeared.
    pub(crate) fn refresh(&mut self) {
        self.0.retain(|_, live| live.alive());
        self.1.retain(|id| self.0.contains_key(id));
    }

    /// One shared readiness future, cancelled safely at each dispatcher event.
    pub(crate) async fn changed(&self) -> io::Result<Vec<[u8; 16]>> {
        self.1.changed().await
    }

    /// Remove registered lifetimes reported dead even if their PID has since been reused.
    pub(crate) fn exited(&mut self, ids: &[[u8; 16]]) {
        for id in ids {
            self.0.remove(id);
        }
        self.1.retain(|id| self.0.contains_key(id));
    }

    /// Stable live-session snapshot for the server and plugin context.
    pub(crate) fn session_ids(&self) -> Vec<[u8; 16]> {
        let mut ids: Vec<_> = self.0.keys().copied().collect();
        ids.sort_unstable();
        ids
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

// These fixtures read /proc identities and executable links.
#[cfg(all(test, feature = "plugin-host-facts", target_os = "linux"))]
mod tests {
    //! Reference counts preserve background truth across multiple windows; stale process identities never count.
    use super::*;

    #[tokio::test]
    async fn nondumpable_process_keeps_its_authenticated_lifetime() {
        use std::{io::Read as _, process::Stdio};
        const CASE: &str = "lifecycle::tests::nondumpable_process_keeps_its_authenticated_lifetime";
        const FIXTURE: &str = "INFRATERNAL_LIFETIME_FIXTURE";
        if let Some(ready) = std::env::var_os(FIXTURE) {
            // Protection changes only in this disposable process. Keep it alive
            // on private stdin until the parent has inspected its registry.
            nix::sys::prctl::set_dumpable(false).unwrap();
            fs::write(ready, b"ready").unwrap();
            let _ = std::io::stdin().read_exact(&mut [0]);
            return;
        }
        let root =
            PathBuf::from("../../target").join(format!("nondumpable-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let ready = root.join("ready");
        let path = root.join("socket");
        fs::write(&path, b"").unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        infraternal_shim::prepare_child(&mut command);
        let mut child = command
            .args(["--exact", CASE])
            .env(FIXTURE, &ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let ready_observed = ready.exists();
        let image = PathBuf::from(format!("/proc/{}/exe", child.id()));
        let followed_image_denied = fs::metadata(&image)
            .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied);
        let image_link_exists =
            fs::symlink_metadata(&image).is_ok_and(|metadata| metadata.file_type().is_symlink());
        let (peer, _remote) = tokio::net::UnixStream::pair().unwrap();
        let session = Session {
            id: [154; 16],
            path,
            peer,
            head: 0,
            size: (80, 24),
            pid: child.id(),
            caps: 0,
            supports_owner: false,
        };
        let mut registry = Registry::default();
        let inserted = registry.insert(&session);
        registry.refresh();
        let count = registry.context().session_count;
        // Always release/reap the fixture before assertions, including the red
        // regression path. No protected process outlives this test.
        drop(child.stdin.take());
        let status = child.wait().unwrap();
        fs::remove_dir_all(root).unwrap();
        assert!(ready_observed && status.success());
        // A privileged runner may follow the link; the lifetime contract holds
        // under either ptrace policy without weakening process protection.
        assert!(image_link_exists);
        println!("protected_lifetime: followed_image_denied={followed_image_denied}");
        inserted.unwrap();
        assert_eq!(count, 1, "a protected live process must remain counted");
    }

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
            size: (80, 24),
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
            size: (80, 24),
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
