//! Runs each Traefik child in its own cgroup v2 leaf, so a stop kills everything it forked
//! [#281, D336, docs/design/proxy-containment.md option 1].
//!
//! The leaf is a child of the infraternal agent's own cgroup, named
//! `proxy-<dev>-<ino>-<n>`, from the device and inode of the supervisor's private lock
//! directory, so the mixed and public supervisors never touch each other's leaves, two agents in
//! one cgroup whose lock directories share an inode on different filesystems don't either, and
//! the same supervisor finds its leaves again after a crash. The child joins its leaf in the pre-exec hook, before it can
//! exec or fork, and stopping it writes `cgroup.kill`, which kills every member at once.
//!
//! Invariants:
//! - No controller is enabled in the leaf (`subtree_control` of the agent's cgroup stays
//!   untouched), so cgroup v2's "no internal processes" rule never applies and the agent itself
//!   stays where its init system put it. The measured cost is ~16 µs to create, ~11 µs to
//!   remove, and nothing in steady state (#281, J164).
//! - Rootful, the leaf belongs to root, so the child (dedicated account, no `CAP_SYS_ADMIN`)
//!   can't move out of it. Rootless, the child runs as the agent's own user, who owns the
//!   tree: an ordinary fork is contained, but a compromised child could write itself into
//!   the parent cgroup. The design note accepts that until option 2.
//! - Where no usable delegation exists, detection returns the reason, and the supervisor
//!   keeps the pidfd-verified lock-holder reaper (J159). Status output says which applies.

use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const LEAF_PREFIX: &str = "proxy-";
/// Bounds a stop: after `cgroup.kill` the kernel only has to deliver SIGKILL.
const EMPTY_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounds the cgroups a (rootless, compromised) child may have made inside its leaf that a stop
/// removes; past it the stop fails closed instead of walking an unbounded tree.
const MAX_NESTED_CGROUPS: usize = 4096;
/// The agent's cgroup when the last leaf was made, for a restart whose cgroup moved (an init
/// system without systemd can start the next agent elsewhere).
const RECORD_NAME: &str = ".traefik-cgroup";

/// How the Traefik children of this infraternal agent are contained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Containment {
    /// Rootful: each child runs in its own root-owned leaf and is stopped with `cgroup.kill`.
    Cgroup,
    /// Rootless: the same, but the child runs as the agent's user, who owns the leaf, so a
    /// compromised child could move itself out (#281, J172 P3-2).
    CgroupRootless,
    /// No usable cgroup delegation; children are reaped through their pidfd as before.
    Fallback(&'static str),
}

impl Containment {
    /// One line for status output, written for the person reading it.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Cgroup => "each Traefik process runs in its own cgroup; stopping it stops everything it started".to_owned(),
            Self::CgroupRootless => "each Traefik process runs in its own cgroup, so stopping it also stops what it forks; a compromised Traefik running as your user could still move out of it".to_owned(),
            Self::Fallback(reason) => format!(
                "limited: {reason}; a process Traefik forks may outlive it"
            ),
        }
    }

    /// Stable machine-readable form for JSON.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Cgroup => "cgroup",
            Self::CgroupRootless => "cgroup-rootless",
            Self::Fallback(_) => "fallback",
        }
    }
}

/// The delegated cgroup that proxy leaves are created under, scoped to one supervisor.
#[derive(Debug)]
pub struct ProxyCgroups {
    base: PathBuf,
    tag: String,
    record: PathBuf,
    next: AtomicU64,
}

/// One child's leaf. Holds `cgroup.procs` open for the pre-exec join.
#[derive(Debug)]
pub struct Leaf {
    path: PathBuf,
    procs: File,
}

/// How this process contains its Traefik children. Detected once: the answer changes only
/// when the infraternal agent's unit changes, which restarts the agent.
#[must_use]
pub fn containment() -> Containment {
    match own_base() {
        Ok(_) => Containment::contained(),
        Err(reason) => Containment::Fallback(reason),
    }
}

impl Containment {
    /// The contained variant for this process: rootful or rootless.
    #[must_use]
    pub fn contained() -> Self {
        if nix::unistd::Uid::effective().is_root() {
            Self::Cgroup
        } else {
            Self::CgroupRootless
        }
    }
}

fn own_base() -> Result<&'static Path, &'static str> {
    static BASE: std::sync::OnceLock<Result<PathBuf, &'static str>> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        if !cfg!(target_os = "linux") {
            return Err("cgroups exist only on Linux");
        }
        let own = fs::read_to_string("/proc/self/cgroup")
            .map_err(|_| "this system has no cgroup information")?;
        let base = own_cgroup(&own).ok_or("this system does not use cgroup v2 alone")?;
        check_base(&base)?;
        Ok(base)
    })
    .as_ref()
    .map(PathBuf::as_path)
    .map_err(|reason| *reason)
}

fn check_base(base: &Path) -> Result<(), &'static str> {
    // The root cgroup has no cgroup.kill (or cgroup.events) on any kernel, so it must be named
    // before the kernel check below gives a false reason (#281, J172 P3-3).
    if base == Path::new(CGROUP_ROOT) {
        return Err("the infraternal agent runs in the root cgroup");
    }
    if !base.join("cgroup.kill").exists() {
        return Err("the kernel is older than Linux 5.14 (no cgroup.kill)");
    }
    let metadata = fs::metadata(base).map_err(|_| "the agent's cgroup is unreadable")?;
    let euid = nix::unistd::Uid::effective().as_raw();
    if euid == 0 {
        // Under systemd, only a unit marked `Delegate=yes` may manage its own subtree; the
        // system manager tags such a cgroup. Without systemd the agent's cgroup is its own.
        if Path::new("/run/systemd/system").exists() && !delegated(base) {
            return Err("the infraternal agent's unit lacks Delegate=yes");
        }
    } else if metadata.uid() != euid
        || nix::unistd::access(base, nix::unistd::AccessFlags::W_OK).is_err()
        || nix::unistd::access(&base.join("cgroup.procs"), nix::unistd::AccessFlags::W_OK).is_err()
    {
        // The user manager delegates its whole tree to the user but tags nothing, so
        // ownership is the test. A login session's scope belongs to root and fails here.
        return Err("the infraternal agent does not run in a user service it owns");
    }
    Ok(())
}

impl ProxyCgroups {
    /// Use this process's own cgroup for the leaves of the supervisor owning `lock_directory`.
    ///
    /// # Errors
    /// Returns the reason, in words for status output, when containment is unavailable.
    pub fn detect(lock_directory: &Path) -> Result<Self, &'static str> {
        Self::at(own_base()?.to_owned(), lock_directory)
    }

    /// Use `base` (an absolute path under the cgroup v2 mount) for this supervisor's leaves.
    ///
    /// # Errors
    /// Returns the reason when `base` can't hold proxy leaves.
    pub fn at(base: PathBuf, lock_directory: &Path) -> Result<Self, &'static str> {
        check_base(&base)?;
        let lock =
            fs::metadata(lock_directory).map_err(|_| "the proxy state directory is unreadable")?;
        Ok(Self {
            base,
            tag: format!("{LEAF_PREFIX}{:x}-{:x}-", lock.dev(), lock.ino()),
            record: lock_directory.join(RECORD_NAME),
            next: AtomicU64::new(0),
        })
    }

    /// Kill and remove every leaf this supervisor left behind, here and where the last agent
    /// ran. Call it while holding the supervisor lock, before the first child starts.
    ///
    /// # Errors
    /// Returns an error when a leftover leaf can't be emptied or removed; starting a child
    /// then would race the orphan for its listeners.
    pub fn adopt_orphans(&self) -> io::Result<usize> {
        let mut bases = vec![self.base.clone()];
        if let Some(previous) = fs::read_to_string(&self.record)
            .ok()
            .and_then(|recorded| valid_recorded_base(recorded.trim()))
            && previous != self.base
        {
            bases.push(previous);
        }
        let mut stopped = 0;
        for base in bases {
            let Ok(entries) = fs::read_dir(&base) else {
                continue;
            };
            for entry in entries.flatten() {
                let is_ours = entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(&self.tag));
                if is_ours && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    kill_and_remove(&entry.path())?;
                    stopped += 1;
                }
            }
        }
        Ok(stopped)
    }

    /// Make a fresh leaf for the next child.
    ///
    /// # Errors
    /// Returns operating-system errors from creating or opening the leaf.
    pub fn create_leaf(&self) -> io::Result<Leaf> {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let path = self.base.join(format!("{}{n}", self.tag));
        if path.exists() {
            // A leaf of this name outlived an earlier stop; it is ours, so it goes first.
            kill_and_remove(&path)?;
        }
        fs::create_dir(&path)?;
        let procs = OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_CLOEXEC)
            .open(path.join("cgroup.procs"))
            .inspect_err(|_| {
                let _ = fs::remove_dir(&path);
            })?;
        // Best effort: the record only helps when the next agent starts in another cgroup.
        // Owner-only, in the agent-only lock directory; rewritten only when it changes.
        let base = self.base.as_os_str().as_encoded_bytes();
        if fs::read(&self.record).ok().as_deref() != Some(base) {
            let _ = crate::config::write_config_atomic(&self.record, base);
        }
        Ok(Leaf { path, procs })
    }
}

impl Leaf {
    /// `cgroup.procs` of this leaf, for the child's pre-exec join.
    #[must_use]
    pub const fn procs(&self) -> &File {
        &self.procs
    }

    /// Kill every member of the leaf at once.
    ///
    /// # Errors
    /// Returns the write error; the caller then falls back to killing the direct child.
    pub fn kill(&self) -> io::Result<()> {
        fs::write(self.path.join("cgroup.kill"), "1")
    }

    /// Wait until the leaf is empty, then remove it.
    ///
    /// # Errors
    /// Returns `TimedOut` when members remain, or the removal error.
    pub fn remove(&self) -> io::Result<()> {
        kill_and_remove(&self.path)
    }

    /// The leaf's path, for tests and diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn kill_and_remove(leaf: &Path) -> io::Result<()> {
    // Idempotent: killing an empty leaf is a no-op, and a racing member gets it too.
    fs::write(leaf.join("cgroup.kill"), "1")?;
    let deadline = Instant::now() + EMPTY_TIMEOUT;
    let mut pause = Duration::from_micros(50);
    while !is_empty(leaf)? {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("proxy cgroup {} did not empty after kill", leaf.display()),
            ));
        }
        thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(5));
    }
    // A rootless child owns its leaf and can make cgroups inside it. `cgroup.kill` and
    // `populated` cover the whole subtree, so they are empty now, but rmdir of a cgroup with
    // children fails with EBUSY, which would block every later start (#281, J172 P3-1). Remove
    // them deepest first: a breadth-first listing reversed puts every child before its parent.
    let mut nested = Vec::new();
    let mut next = 0;
    let mut current = leaf.to_owned();
    loop {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if nested.len() == MAX_NESTED_CGROUPS {
                    return Err(io::Error::other(format!(
                        "proxy cgroup {} holds too many nested cgroups to remove",
                        leaf.display()
                    )));
                }
                nested.push(entry.path());
            }
        }
        let Some(child) = nested.get(next) else {
            break;
        };
        current.clone_from(child);
        next += 1;
    }
    for directory in nested
        .iter()
        .rev()
        .map(PathBuf::as_path)
        .chain(std::iter::once(leaf))
    {
        if let Err(error) = fs::remove_dir(directory)
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(error);
        }
    }
    Ok(())
}

fn is_empty(leaf: &Path) -> io::Result<bool> {
    match fs::read_to_string(leaf.join("cgroup.events")) {
        Ok(events) => Ok(events.lines().any(|line| line == "populated 0")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

// The single `0::` line of a cgroup-v2-only system; a hybrid system has more lines and is
// treated as unavailable rather than guessed at.
fn own_cgroup(proc_self_cgroup: &str) -> Option<PathBuf> {
    let mut lines = proc_self_cgroup.lines().filter(|line| !line.is_empty());
    let relative = lines.next()?.strip_prefix("0::")?;
    if lines.next().is_some() {
        return None;
    }
    valid_recorded_base(&format!("{CGROUP_ROOT}{relative}"))
}

// Only an absolute path inside the cgroup mount, with no `..` or empty segment, is used. The
// mount itself is valid: an agent outside systemd can run in the root cgroup (`0::/`).
fn valid_recorded_base(path: &str) -> Option<PathBuf> {
    let rest = path.strip_prefix(CGROUP_ROOT)?;
    let clean = rest.is_empty()
        || rest == "/"
        || (rest.starts_with('/')
            && rest
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != ".."));
    clean.then(|| PathBuf::from(path.trim_end_matches('/')))
}

fn delegated(base: &Path) -> bool {
    ["trusted.delegate", "user.delegate"].iter().any(|name| {
        xattr::get(base, name)
            .ok()
            .flatten()
            .is_some_and(|value| value == b"1")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_pure_cgroup_v2_line_names_the_agent_cgroup() {
        assert_eq!(
            own_cgroup("0::/system.slice/infraternal.service\n"),
            Some(PathBuf::from(
                "/sys/fs/cgroup/system.slice/infraternal.service"
            ))
        );
        assert_eq!(own_cgroup("0::/\n"), Some(PathBuf::from("/sys/fs/cgroup")));
        assert_eq!(own_cgroup("12:pids:/x\n0::/x\n"), None);
        assert_eq!(own_cgroup("1:name=systemd:/x\n"), None);
        assert_eq!(own_cgroup("0::/a/../b\n"), None);
    }

    #[test]
    fn a_recorded_base_outside_the_cgroup_mount_is_ignored() {
        assert_eq!(valid_recorded_base("/etc"), None);
        assert_eq!(valid_recorded_base("/sys/fs/cgroupx/a"), None);
        assert_eq!(valid_recorded_base("/sys/fs/cgroup/a//b"), None);
        assert_eq!(
            valid_recorded_base("/sys/fs/cgroup/a/b"),
            Some(PathBuf::from("/sys/fs/cgroup/a/b"))
        );
    }

    #[test]
    fn status_names_the_fallback_reason() {
        let text =
            Containment::Fallback("the infraternal agent's unit lacks Delegate=yes").describe();
        assert!(text.contains("Delegate=yes"), "{text}");
        assert_eq!(Containment::Cgroup.kind(), "cgroup");
        let rootless = Containment::CgroupRootless.describe();
        assert!(!rootless.contains("stops everything"), "{rootless}");
        assert_eq!(Containment::CgroupRootless.kind(), "cgroup-rootless");
    }
}
