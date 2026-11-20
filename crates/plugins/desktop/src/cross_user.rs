//! Admission of the console user's desktop helper by a root infraternal agent (D203 C2, #146).
//!
//! A Mac enrolled with `infraternal up` runs its infraternal agent as a root
//! `LaunchDaemon`. macOS grants screen capture and input to an app in the
//! logged-in person's session, so the root agent never captures. Each source
//! leg starts a one-shot helper as **the console user** (the owner of
//! `/dev/console`) inside that user's GUI login, and talks to it over one
//! private Unix socket. A rootless agent, already in the person's login, keeps
//! the same-user path and never uses this module.
//!
//! **The boundary, in order** (see `source_ipc::Helper::start`):
//!
//! 1. *Who is at the screen.* [`console_user`] reads the owner of
//!    `/dev/console`. Root means only the login window shows, and then
//!    nothing starts: no capture with nobody logged in.
//! 2. *Where the socket lives.* Root owns the base folder
//!    `/private/var/run/ifd` with mode 0711: others may pass through it but
//!    not list, add, rename or remove anything ([`prepare_base`]). Each leg
//!    gets a fresh `<32 hex>` folder that root creates with mode 0700 and then
//!    hands to the console user ([`hand_over`]). The socket path stays near 60
//!    bytes, well inside Darwin's 104-byte limit. Folders a killed daemon
//!    left behind are removed when the root agent starts ([`sweep_base`]).
//! 3. *How it starts.* The agent's launcher (the shim's `__desktop-user`
//!    entry) places the helper in the user's GUI login and drops to the
//!    user. The helper gets a one-time [`Token`] on its standard input pipe:
//!    never on disk, in argv or in the environment.
//! 4. *Before any frame is parsed.* The socket file must be owned by the
//!    console uid. The kernel's peer uid must be the console uid. The peer's
//!    code signature, read by audit token, must be the helper's identifier
//!    signed by the agent's own signer ([`VerifyPeer`]). The first 32 bytes
//!    the helper sends must equal the token, compared in constant time.
//! 5. *While it runs.* [`ConsoleWatch`] checks the console owner once a
//!    second (one `stat`). When the person at the screen changes (fast user
//!    switching, logout), the leg ends and its helper is retired. The next
//!    attach starts a helper for the new console user. With nobody at the
//!    screen, a leg waits idle ([`someone_at_screen`]) rather than failing in
//!    a loop.
//!
//! **What the helper can and cannot do.** It runs with the console user's
//! rights only and can see what that user can see. It never receives the
//! agent's enrollment key, server link or any root file. Root sends it the
//! bounded desktop commands and reads back window lists, geometry and encoded
//! video through the strict frame parser, which bounds every length before it
//! allocates.
//!
//! **How others are refused.** A different local user fails the peer uid
//! check and cannot open the 0700 folder. Another process of the console
//! user that binds the socket first does not have the token, and its code
//! signature does not match. That process cannot collect the token from the
//! real helper either: in this mode the helper admits only uid 0 as its
//! client. What remains is the person's own login. Code injected into their
//! signed helper (which the hardened runtime blocks) could feed root bad
//! frames, and the frame parser is the defence there. It could also show the
//! viewer that person's own screen, which they can already do.
use std::{
    fs, io,
    os::{
        fd::BorrowedFd,
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};

/// The root agent's base folder for per-leg helper folders.
pub const BASE: &str = "/private/var/run/ifd";
/// The device whose owner is the person at the screen.
const CONSOLE: &str = "/dev/console";
/// How often a running leg checks that the same person is at the screen.
const CONSOLE_CHECK: Duration = Duration::from_secs(1);

/// Builds the start of the command that places a program in a user's GUI
/// login as that user (the shim's `__desktop-user` entry). The component
/// appends the helper program and its arguments.
pub type Launch = Arc<dyn Fn(u32) -> io::Result<Command> + Send + Sync>;
/// Checks the code signature of the process on the other end of a connected
/// socket; `PermissionDenied` when it is not our helper.
pub type VerifyPeer = Arc<dyn Fn(BorrowedFd<'_>) -> io::Result<()> + Send + Sync>;

/// How a root agent starts and admits the console user's helper. The agent
/// builds it from the shim's entry and code-identity check, so this crate
/// needs no platform code of its own.
#[derive(Clone)]
pub struct CrossUser {
    /// Starts the placement command for a uid.
    pub launch: Launch,
    /// Checks a connected helper's code signature.
    pub verify: VerifyPeer,
    /// The capture app's executable, passed to the helper.
    pub companion: PathBuf,
}

impl CrossUser {
    /// Bundles the launcher, the peer check and the capture app path.
    #[must_use]
    pub fn new(launch: Launch, verify: VerifyPeer, companion: PathBuf) -> Self {
        Self {
            launch,
            verify,
            companion,
        }
    }
}

/// The person at the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleUser {
    /// Their uid.
    pub uid: u32,
    /// Their primary gid, for the per-leg folder.
    pub gid: u32,
}

/// The console user, or `None` when only the login window shows (root owns
/// the console) or the account cannot be read.
#[must_use]
pub fn console_user() -> Option<ConsoleUser> {
    let uid = fs::metadata(CONSOLE).ok()?.uid();
    if uid == 0 {
        return None;
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()?;
    Some(ConsoleUser {
        uid,
        gid: user.gid.as_raw(),
    })
}

/// Makes sure the base folder exists as root's, mode 0711, and refuses one
/// that is a symlink, someone else's, or writable by group or others.
///
/// # Errors
/// Refuses an unsafe existing folder; it is not repaired.
pub fn prepare_base(base: &Path) -> io::Result<()> {
    match fs::symlink_metadata(base) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::DirBuilder::new().mode(0o711).create(base) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let metadata = fs::symlink_metadata(base)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "The desktop helper base folder is not private to the agent.",
        ));
    }
    Ok(())
}

/// Removes per-leg folders that a previous root agent left behind in `base`.
///
/// Each leg removes its own folder when it ends, but a daemon that is killed
/// (or restarted by launchd) cannot. Call once when the root agent starts,
/// before any leg exists: every folder in `base` is then stale. Only names in
/// the per-leg shape (32 lowercase hex digits) are touched, and
/// `remove_dir_all` never follows a link inside them. A missing base is fine.
///
/// # Errors
/// Refuses an unsafe base folder; passes on removal errors.
pub fn sweep_base(base: &Path) -> io::Result<usize> {
    match fs::symlink_metadata(base) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
        Ok(_) => prepare_base(base)?,
    }
    let mut removed = 0;
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        let name = entry.file_name();
        let leg = name.to_str().is_some_and(|name| {
            name.len() == 32
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if leg && entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Gives a freshly created per-leg folder to the console user. The base
/// folder is root's and closed to others, so nobody can swap the entry
/// between creation and this call; `lchown` never follows a link anyway.
///
/// # Errors
/// Passes on the ownership change's error.
pub fn hand_over(folder: &Path, user: ConsoleUser) -> io::Result<()> {
    std::os::unix::fs::lchown(folder, Some(user.uid), Some(user.gid))
}

/// The helper's one-time proof that the agent started it.
pub struct Token([u8; 32]);

impl Token {
    /// Number of bytes the helper sends back first.
    pub const LEN: usize = 32;

    /// Thirty-two bytes from the kernel's random source.
    ///
    /// # Errors
    /// Fails when the random source cannot be read.
    pub fn random() -> io::Result<Self> {
        use std::io::Read as _;
        let mut bytes = [0_u8; Self::LEN];
        fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// The bytes to hand to the helper.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compares `presented` with the token in constant time.
    #[must_use]
    pub fn matches(&self, presented: &[u8; 32]) -> bool {
        self.0
            .iter()
            .zip(presented)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    }
}

/// Resolves once someone is at the screen (checked once a second).
///
/// A leg that would start with nobody logged in waits here instead of failing
/// at once: an immediate failure makes the server prepare and attach again in
/// a tight loop (measured about 18 times a second on the Mac VM). Nothing is
/// started while it waits. Cancellation-safe; the caller selects it against
/// its own stop signal.
pub async fn someone_at_screen() {
    loop {
        if console_user().is_some() {
            return;
        }
        tokio::time::sleep(CONSOLE_CHECK).await;
    }
}

/// Watches that the person at the screen stays the one a leg's helper runs
/// as. A same-user leg never changes.
pub struct ConsoleWatch {
    /// The uid the helper runs as, and the timer between checks.
    watched: Option<(u32, tokio::time::Interval)>,
}

impl ConsoleWatch {
    /// A watch for a helper running as `uid`; `None` watches nothing.
    #[must_use]
    pub fn new(uid: Option<u32>) -> Self {
        Self {
            watched: uid.map(|uid| {
                let mut timer = tokio::time::interval(CONSOLE_CHECK);
                timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                (uid, timer)
            }),
        }
    }

    /// Resolves once the console belongs to someone else (or nobody). Never
    /// resolves for a same-user leg. Cancellation-safe: a dropped call loses
    /// at most one check.
    pub async fn changed(&mut self) {
        let Some((uid, timer)) = self.watched.as_mut() else {
            return std::future::pending().await;
        };
        loop {
            timer.tick().await;
            if console_user().map(|user| user.uid) != Some(*uid) {
                return;
            }
        }
    }
}

#[cfg(test)]
/// Token comparison, base-folder safety and the console watch.
mod tests {
    use super::*;

    /// Equal tokens match; a single flipped bit does not.
    #[test]
    fn token_matches_only_its_own_bytes() {
        let token = Token::random().unwrap();
        let mut presented = *token.bytes();
        assert!(token.matches(&presented));
        presented[31] ^= 1;
        assert!(!token.matches(&presented));
        assert_ne!(Token::random().unwrap().bytes(), token.bytes());
    }

    /// The base folder is created closed to listing and writing by others,
    /// and an existing folder others can write is refused, not repaired.
    #[test]
    fn base_folder_is_private_and_never_repaired() {
        use std::os::unix::fs::PermissionsExt;
        let parent = nix::unistd::mkdtemp("/tmp/ifd-base-XXXXXX").unwrap();
        let base = parent.join("ifd");
        prepare_base(&base).unwrap();
        assert_eq!(fs::metadata(&base).unwrap().mode() & 0o777, 0o711);
        prepare_base(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o733)).unwrap();
        let refused = prepare_base(&base);
        fs::remove_dir_all(&parent).unwrap();
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    /// The startup sweep removes only stale per-leg folders.
    #[test]
    fn sweep_removes_only_leg_folders() {
        let parent = nix::unistd::mkdtemp("/tmp/ifd-sweep-XXXXXX").unwrap();
        let base = parent.join("ifd");
        assert_eq!(sweep_base(&base).unwrap(), 0, "a missing base is fine");
        prepare_base(&base).unwrap();
        let leg = base.join("0123456789abcdef0123456789abcdef");
        fs::create_dir(&leg).unwrap();
        fs::write(leg.join("desktop.sock"), b"").unwrap();
        fs::create_dir(base.join("keep")).unwrap();
        let removed = sweep_base(&base).unwrap();
        let kept = base.join("keep").exists();
        fs::remove_dir_all(&parent).unwrap();
        assert_eq!(removed, 1);
        assert!(kept, "a folder not in the per-leg shape was removed");
    }

    /// A same-user leg's watch never fires.
    #[tokio::test(start_paused = true)]
    async fn same_user_watch_never_fires() {
        let mut watch = ConsoleWatch::new(None);
        let fired = tokio::time::timeout(Duration::from_secs(5), watch.changed()).await;
        assert!(fired.is_err());
    }

    /// A watch for a uid that is not at the console fires at its first check.
    #[tokio::test(start_paused = true)]
    async fn watch_fires_when_someone_else_is_at_the_screen() {
        let mut watch = ConsoleWatch::new(Some(u32::MAX - 7));
        tokio::time::timeout(Duration::from_secs(5), watch.changed())
            .await
            .unwrap();
    }
}
