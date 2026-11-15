//! Finds the mesh firewall tools (nft and the iptables-nft frontends) at fixed, root-owned paths [D384, D386], #265, #483.
//!
//! The mesh runs these tools as root, so a tool is only used when it sits at one of a short,
//! fixed list of entry points and every hop of its symlink chain passes an ownership check.
//! `PATH` is never searched: an environment variable must not be able to choose a program that
//! root runs.
//!
//! Where it looks, in order, for each tool ([`FIXED_DIRECTORIES`]):
//! 1. the distribution directories `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`;
//! 2. the Nix system profile (`/run/current-system/sw/bin`), the default profile
//!    (`/nix/var/nix/profiles/default/bin`, production's shape, #483), the system profile link
//!    and root's own profiles (`~/.nix-profile/bin`, `~/.local/state/nix/profile/bin`);
//! 3. or, instead of all of these, one explicitly configured path.
//!
//! The Nix store is never scanned by name. On a multi-user Nix host any local user can
//! `nix-store --add` a directory called `nftables-999999.0.0` through the daemon socket; the
//! result is root-owned and read-only, so its name and owner say nothing about who asked for it
//! (J589 on #483, J592 on #265). A store path is used only when a root-owned profile link points
//! at it.
//!
//! A candidate is trusted when [`Lookup::chain`] can walk it one component at a time from `/`:
//! every directory passed is owned by root and not group- or world-writable (only `/nix/store`
//! and `/nix/var/nix/profiles/per-user` may be sticky instead), every symlink is owned by root,
//! and the end is a root-owned regular file that is executable and not group- or
//! world-writable. Checking only the two ends of the chain would miss an intermediate link that
//! someone else could repoint, such as a profile generation. This is the same rule as
//! `host_firewall::trusted_chain` (J591, #483); both should share this module once both merge.
//!
//! The lookup happens at run time, not at install time. A Nix store path pinned at install time
//! goes stale after a profile upgrade and garbage collection. The last trusted path is cached per
//! tool and re-walked before each use.
//!
//! The command is run through the found path, not its resolved target: `iptables-nft` and its
//! siblings are symlinks to one multi-call binary that picks its behaviour from `argv[0]`. Every
//! hop of that path is root-controlled, so only root can change what it runs between the check
//! and the exec.
use std::{
    collections::VecDeque,
    ffi::OsString,
    fmt, io,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

/// Test and test-support builds may trust these exact paths only after the privileged runner
/// verified them on the host; it passes them as a `:`-separated list.
#[cfg(any(test, feature = "test-support"))]
const TEST_ROOT_OWNED_TOOLS_ENV: &str = "INFRATERNA_TEST_ROOT_OWNED_NFT";

/// The fixed entry points searched when no path is configured, in order of preference.
///
/// Each is a place only root can repoint: distribution directories and the Nix system, default
/// and root profiles. The list matches J591's `host_firewall` nft candidates (#483).
const FIXED_DIRECTORIES: [&str; 9] = [
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/run/current-system/sw/bin",
    "/nix/var/nix/profiles/default/bin",
    "/nix/var/nix/profiles/system/sw/bin",
    "/root/.nix-profile/bin",
    "/root/.local/state/nix/profile/bin",
];

/// Root-owned directories that may be group- or world-writable because they are sticky.
///
/// In a sticky directory nobody but the owner of an entry (or root) can rename or remove it, and
/// the walk requires every entry it passes to be root-owned, so an entry another user created
/// there is refused. Only these two are exempt: the store (`1775 root:nixbld`) and the per-user
/// profile root, which older Nix installs create as `1777`. Any other sticky directory, such as
/// `/tmp`, is refused.
const STICKY_TRUSTED_DIRECTORIES: [&str; 2] = ["/nix/store", "/nix/var/nix/profiles/per-user"];

/// The most symlinks one candidate may pass through, as the kernel limits it.
const MAX_SYMLINK_HOPS: usize = 40;

/// One firewall program the mesh may run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tool {
    /// The nftables frontend, used by the default backend and required by kernel `WireGuard`.
    Nft,
    /// The IPv4 iptables frontend over `nf_tables`, used to inspect owned chains.
    IptablesNft,
    /// The IPv4 atomic restore frontend, used to change owned chains.
    IptablesNftRestore,
    /// The IPv6 iptables frontend over `nf_tables`, used to inspect owned chains.
    Ip6tablesNft,
    /// The IPv6 atomic restore frontend, used to change owned chains.
    Ip6tablesNftRestore,
}

impl Tool {
    /// Every tool, in cache order.
    const ALL: [Self; 5] = [
        Self::Nft,
        Self::IptablesNft,
        Self::IptablesNftRestore,
        Self::Ip6tablesNft,
        Self::Ip6tablesNftRestore,
    ];

    /// The executable's file name.
    pub(crate) const fn binary(self) -> &'static str {
        match self {
            Self::Nft => "nft",
            Self::IptablesNft => "iptables-nft",
            Self::IptablesNftRestore => "iptables-nft-restore",
            Self::Ip6tablesNft => "ip6tables-nft",
            Self::Ip6tablesNftRestore => "ip6tables-nft-restore",
        }
    }

    /// The slot this tool uses in the process cache.
    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|tool| *tool == self)
            .unwrap_or_default()
    }
}

/// A tool that no fixed place provided as a trusted executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Missing(pub(crate) Tool);

impl fmt::Display for Missing {
    /// Names the tool and every place searched, so an operator knows what to install where.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} was not found as a root-owned executable in {}",
            self.0.binary(),
            searched_places()
        )
    }
}

impl From<Missing> for io::Error {
    fn from(missing: Missing) -> Self {
        Self::new(io::ErrorKind::NotFound, missing.to_string())
    }
}

/// The searched directories as one sentence fragment.
pub(crate) fn searched_places() -> String {
    FIXED_DIRECTORIES.join(", ")
}

/// Where and how to look; the real system uses `/` and root, tests use a private tree.
pub(crate) struct Lookup {
    /// The directory treated as `/` when building candidate paths. Its strict ancestors are
    /// the test's own scratch directories and are not checked; on the real host it is `/`,
    /// which has none, so every hop is checked.
    root: PathBuf,
    /// The uid that must own every directory, link and file on the chain.
    owner: u32,
    /// Exact paths the privileged test runner already verified on the host.
    host_verified: Vec<PathBuf>,
}

impl Lookup {
    /// The real host: tools under `/`, owned by root.
    pub(crate) fn system() -> Self {
        #[cfg(any(test, feature = "test-support"))]
        let host_verified = std::env::var(TEST_ROOT_OWNED_TOOLS_ENV)
            .map(|paths| {
                paths
                    .split(':')
                    .filter(|path| path.starts_with('/'))
                    .map(PathBuf::from)
                    .collect()
            })
            .unwrap_or_default();
        #[cfg(not(any(test, feature = "test-support")))]
        let host_verified = Vec::new();
        Self {
            root: PathBuf::from("/"),
            owner: 0,
            host_verified,
        }
    }

    /// A private tree owned by `owner`, for tests that cannot create root-owned files.
    #[cfg(test)]
    fn under(root: &Path, owner: u32) -> Self {
        Self {
            root: root.to_path_buf(),
            owner,
            host_verified: Vec::new(),
        }
    }

    /// Find the first trusted path for `tool`: the configured path alone when one is given,
    /// otherwise the fixed entry points in order.
    ///
    /// An entry point that exists but fails the walk is skipped, never run; a later trusted
    /// entry point can still be used, because each of them is equally root-controlled.
    ///
    /// # Errors
    /// Returns [`Missing`] when no searched place holds a trusted executable.
    pub(crate) fn find(&self, tool: Tool, configured: Option<&Path>) -> Result<PathBuf, Missing> {
        match configured {
            Some(path) => self.trusted(path).then(|| path.to_owned()),
            None => FIXED_DIRECTORIES
                .iter()
                .map(|directory| self.place(directory).join(tool.binary()))
                .find(|candidate| self.trusted(candidate)),
        }
        .ok_or(Missing(tool))
    }

    /// Map an absolute host path into this lookup's root.
    fn place(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// Whether `path` is a tool only the trusted owner could have put or changed there.
    pub(crate) fn trusted(&self, path: &Path) -> bool {
        self.host_verified.iter().any(|verified| verified == path) || self.chain(path).is_some()
    }

    /// Walk `candidate` one component at a time from `/` and return its final target when every
    /// hop is controlled by the owner, or `None` at the first hop that is not.
    ///
    /// `current` never contains a symlink, so `..` is resolved by dropping its last component.
    /// Absolute link targets restart the walk at `/`; relative ones continue from the link's
    /// directory. At most [`MAX_SYMLINK_HOPS`] links are followed.
    fn chain(&self, candidate: &Path) -> Option<PathBuf> {
        /// A path's components, keeping `..` and dropping `.` and the root.
        fn components(path: &Path) -> impl DoubleEndedIterator<Item = OsString> + '_ {
            path.components().filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_owned()),
                Component::ParentDir => Some(OsString::from("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            })
        }

        if !candidate.is_absolute() {
            return None;
        }
        let mut current = PathBuf::from("/");
        if !self.trusted_directory(&current, &std::fs::metadata(&current).ok()?) {
            return None;
        }
        let mut pending = components(candidate).collect::<VecDeque<_>>();
        let mut hops = 0;
        while let Some(name) = pending.pop_front() {
            if name == ".." {
                current.pop();
                continue;
            }
            let next = current.join(&name);
            let metadata = std::fs::symlink_metadata(&next).ok()?;
            if metadata.file_type().is_symlink() {
                hops += 1;
                if metadata.uid() != self.owner || hops > MAX_SYMLINK_HOPS {
                    return None;
                }
                let target = std::fs::read_link(&next).ok()?;
                if target.is_absolute() {
                    current = PathBuf::from("/");
                }
                for component in components(&target).rev() {
                    pending.push_front(component);
                }
                continue;
            }
            if metadata.is_dir() {
                if !self.trusted_directory(&next, &metadata) {
                    return None;
                }
                current = next;
                continue;
            }
            let mode = metadata.mode();
            return (pending.is_empty()
                && metadata.is_file()
                && metadata.uid() == self.owner
                && mode & 0o022 == 0
                && mode & 0o111 != 0)
                .then_some(next);
        }
        // The chain ended on a directory, not an executable.
        None
    }

    /// Whether a directory on the chain is the owner's and not writable by anyone else.
    ///
    /// The strict ancestors of a test tree's root are the test's own scratch directories and
    /// are not judged. On the real host the root is `/`, so every directory is.
    fn trusted_directory(&self, path: &Path, metadata: &std::fs::Metadata) -> bool {
        if path != self.root && self.root.starts_with(path) {
            return true;
        }
        let mode = metadata.mode();
        metadata.is_dir()
            && metadata.uid() == self.owner
            && (mode & 0o022 == 0
                || (mode & 0o1000 != 0
                    && STICKY_TRUSTED_DIRECTORIES
                        .iter()
                        .any(|sticky| path == self.place(sticky))))
    }
}

/// The last trusted path per tool, re-checked before each use.
static CACHE: Mutex<[Option<PathBuf>; 5]> = Mutex::new([None, None, None, None, None]);

/// Find `tool` on this host, reusing the last trusted path while it still passes the check.
///
/// # Errors
/// Returns [`Missing`] naming the tool and every place searched.
pub(crate) fn find(tool: Tool) -> Result<PathBuf, Missing> {
    #[cfg(test)]
    if HIDDEN_FOR_TEST.with(std::cell::Cell::get) {
        return Err(Missing(tool));
    }
    let lookup = Lookup::system();
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = &mut cache[tool.index()];
    if let Some(path) = slot.as_ref().filter(|path| lookup.trusted(path)) {
        return Ok(path.clone());
    }
    let found = lookup.find(tool, None);
    *slot = found.as_ref().ok().cloned();
    found
}

// Namespace tests prove what a node does on a host with no firewall tool at all.
#[cfg(test)]
std::thread_local! {
    /// Whether [`find`] reports every tool missing on this test thread.
    static HIDDEN_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A test-only guard under which [`find`] finds no tool on the current thread.
///
/// The privileged test runner marks the host's root-owned nft and iptables-nft
/// as trusted, so a namespace test would otherwise always find them. Install
/// this to model a host without any of them, for example a `GotaTun` node
/// whose optional kernel guard cannot be installed. Dropping it restores the
/// normal lookup. The process-wide cache is left alone, so later lookups on
/// other threads are unaffected.
#[cfg(test)]
pub(crate) struct HiddenToolsForTest {
    /// Whether tools were already hidden when this guard was installed.
    previous: bool,
}

#[cfg(test)]
impl HiddenToolsForTest {
    /// Hide every firewall tool from [`find`] on this thread until the guard is dropped.
    #[must_use]
    pub(crate) fn install() -> Self {
        Self {
            previous: HIDDEN_FOR_TEST.with(|hidden| hidden.replace(true)),
        }
    }
}

#[cfg(test)]
impl Drop for HiddenToolsForTest {
    /// Restore the lookup this thread had before the guard.
    fn drop(&mut self) {
        HIDDEN_FOR_TEST.with(|hidden| hidden.set(self.previous));
    }
}

/// Lookup order, hop-by-hop trust checks and missing-tool messages, over private trees.
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::{Lookup, Missing, Tool, searched_places};
    use std::{
        os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink},
        path::{Path, PathBuf},
    };

    /// A private, owner-only tree removed when the test ends.
    struct Tree(PathBuf);

    impl Tree {
        /// Create an empty tree under the test's temporary directory.
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "ifm-tools-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            // A leftover tree from an earlier run with the same pid must not leak into this one.
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("test fixture");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("test fixture");
            Self(root)
        }

        /// Create `relative` and every missing directory above it as mode 0755.
        ///
        /// Each mode is set explicitly, so a group-writable umask (002 on some build hosts)
        /// cannot make a fixture fail the ownership check for the wrong reason (J592 P3).
        fn dir(&self, relative: &str) -> PathBuf {
            let mut path = self.0.clone();
            for part in Path::new(relative).components() {
                path.push(part);
                if !path.exists() {
                    std::fs::DirBuilder::new()
                        .mode(0o755)
                        .create(&path)
                        .expect("test fixture");
                }
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                    .expect("test fixture");
            }
            path
        }

        /// Write an executable file with `mode` at `relative`, creating its directories.
        fn tool(&self, relative: &str, mode: u32) -> PathBuf {
            let path = self.0.join(relative);
            self.dir(
                path.parent()
                    .and_then(|parent| parent.strip_prefix(&self.0).ok())
                    .and_then(Path::to_str)
                    .expect("fixture parent"),
            );
            std::fs::write(&path, "#!/bin/sh\n").expect("test fixture");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("test fixture");
            path
        }

        /// Make `relative` a symlink to `target`, creating its directory.
        fn link(&self, relative: &str, target: &Path) -> PathBuf {
            let path = self.0.join(relative);
            self.dir(
                path.parent()
                    .and_then(|parent| parent.strip_prefix(&self.0).ok())
                    .and_then(Path::to_str)
                    .expect("fixture parent"),
            );
            symlink(target, &path).expect("test fixture");
            path
        }

        /// The uid that owns this tree: the test's own effective uid.
        fn owner(&self) -> u32 {
            std::fs::metadata(&self.0).expect("test fixture").uid()
        }

        /// A lookup over this tree that trusts files owned by the test's own uid.
        fn lookup(&self) -> Lookup {
            Lookup::under(&self.0, self.owner())
        }

        /// Set `relative`'s mode exactly.
        fn chmod(&self, relative: &str, mode: u32) {
            std::fs::set_permissions(self.0.join(relative), std::fs::Permissions::from_mode(mode))
                .expect("test fixture");
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Store entry for one package version with a fixed 32-character hash.
    fn store(hash: char, name: &str) -> String {
        format!("nix/store/{}-{name}", hash.to_string().repeat(32))
    }

    /// A Nix profile link into the store (production's shape, #483) is found and kept as the
    /// link, and a distribution path is preferred to it.
    #[test]
    fn fixed_directories_are_searched_in_order_and_links_are_kept() {
        let tree = Tree::new();
        let target = tree.tool(&format!("{}/bin/nft", store('a', "nftables-1.1.7")), 0o555);
        tree.chmod("nix/store", 0o1775);
        let profile = tree.link("nix/var/nix/profiles/default/bin/nft", &target);
        assert_eq!(tree.lookup().find(Tool::Nft, None), Ok(profile));

        let distro = tree.tool("usr/sbin/nft", 0o755);
        assert_eq!(tree.lookup().find(Tool::Nft, None), Ok(distro));
    }

    /// Production's full chain: `profiles/default -> per-user/root/profile -> profile-N-link ->
    /// store`. Every intermediate hop counts: a group-writable directory or a link in the middle
    /// refuses the tool, which checking only the two ends of the chain missed (J592 P3).
    #[test]
    fn every_intermediate_hop_of_a_profile_chain_is_checked() {
        let tree = Tree::new();
        let package = store('b', "nftables-1.1.7");
        tree.tool(&format!("{package}/bin/nft"), 0o555);
        tree.chmod("nix/store", 0o1775);
        tree.link(
            "nix/var/nix/profiles/per-user/root/profile-3-link",
            &tree.0.join(&package),
        );
        tree.link(
            "nix/var/nix/profiles/per-user/root/profile",
            Path::new("profile-3-link"),
        );
        tree.chmod("nix/var/nix/profiles/per-user", 0o1777);
        tree.link(
            "nix/var/nix/profiles/default",
            Path::new("per-user/root/profile"),
        );
        let entry = tree.0.join("nix/var/nix/profiles/default/bin/nft");
        assert_eq!(tree.lookup().find(Tool::Nft, None), Ok(entry.clone()));

        tree.chmod("nix/var/nix/profiles/per-user/root", 0o775);
        assert!(
            !tree.lookup().trusted(&entry),
            "a group-writable directory in the middle lets others repoint the generation"
        );
        tree.chmod("nix/var/nix/profiles/per-user/root", 0o755);
        tree.chmod(&format!("{package}/bin"), 0o775);
        assert!(
            !tree.lookup().trusted(&entry),
            "a group-writable target directory lets others swap the tool"
        );
    }

    /// The iptables-nft frontends of both families are found through their own names in a
    /// profile, because the multi-call binary dispatches on `argv[0]`.
    #[test]
    fn ipv4_and_ipv6_frontends_are_found_through_their_own_names() {
        let tree = Tree::new();
        let bin = format!("{}/bin", store('e', "iptables-1.8.11"));
        let multi = tree.tool(&format!("{bin}/xtables-nft-multi"), 0o555);
        tree.chmod("nix/store", 0o1775);
        for tool in [
            Tool::IptablesNft,
            Tool::IptablesNftRestore,
            Tool::Ip6tablesNft,
            Tool::Ip6tablesNftRestore,
        ] {
            tree.link(
                &format!("{bin}/{}", tool.binary()),
                Path::new("xtables-nft-multi"),
            );
            let link = tree.link(
                &format!("root/.nix-profile/bin/{}", tool.binary()),
                &tree.0.join(&bin).join(tool.binary()),
            );
            assert_eq!(tree.lookup().find(tool, None), Ok(link), "{tool:?}");
        }
        assert!(multi.exists());
    }

    /// A missing tool names itself and every place searched, and never a store pattern.
    #[test]
    fn a_missing_tool_names_every_searched_place() {
        let tree = Tree::new();
        let missing = tree.lookup().find(Tool::Ip6tablesNftRestore, None);
        assert_eq!(missing, Err(Missing(Tool::Ip6tablesNftRestore)));
        let message = missing.expect_err("no tool in an empty tree").to_string();
        for place in [
            "ip6tables-nft-restore was not found",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/run/current-system/sw/bin",
            "/nix/var/nix/profiles/default/bin",
            "/root/.nix-profile/bin",
        ] {
            assert!(message.contains(place), "missing {place}: {message}");
        }
        assert!(!searched_places().contains("/nix/store"));
    }

    /// Writable, non-executable or wrongly owned files are refused, as is a writable directory;
    /// only the two listed sticky directories may be shared.
    #[test]
    fn untrusted_files_and_directories_are_refused() {
        let tree = Tree::new();
        let lookup = tree.lookup();
        let writable = tree.tool("usr/sbin/nft", 0o775);
        assert!(!lookup.trusted(&writable));
        let plain = tree.tool("usr/bin/nft", 0o644);
        assert!(!lookup.trusted(&plain));
        assert_eq!(lookup.find(Tool::Nft, None), Err(Missing(Tool::Nft)));

        let nft = tree.tool("nix/var/nix/profiles/default/bin/nft", 0o755);
        assert!(lookup.trusted(&nft));
        tree.chmod("nix/var/nix/profiles/default/bin", 0o777);
        assert!(
            !lookup.trusted(&nft),
            "a world-writable directory lets others swap the tool"
        );
        tree.chmod("nix/var/nix/profiles/default/bin", 0o1777);
        assert!(
            !lookup.trusted(&nft),
            "only /nix/store and the per-user profile root may be sticky and shared"
        );
        tree.chmod("nix/var/nix/profiles/default/bin", 0o755);

        let stranger = Lookup::under(&tree.0, tree.owner() + 1);
        assert!(!stranger.trusted(&nft), "another owner's file is refused");
        assert!(
            !lookup.trusted(Path::new("usr/sbin/nft")),
            "relative paths are refused"
        );
        let directory = tree.dir("nix/var/nix/profiles/default/bin/nft-dir");
        assert!(!lookup.trusted(&directory), "a directory is not a tool");
    }

    /// An explicitly configured path is the only one checked, and it must pass the same walk.
    #[test]
    fn a_configured_path_replaces_the_fixed_list() {
        let tree = Tree::new();
        tree.tool("usr/sbin/nft", 0o755);
        let configured = tree.tool("opt/firewall/nft", 0o755);
        assert_eq!(
            tree.lookup().find(Tool::Nft, Some(&configured)),
            Ok(configured.clone())
        );
        tree.chmod("opt/firewall", 0o777);
        assert_eq!(
            tree.lookup().find(Tool::Nft, Some(&configured)),
            Err(Missing(Tool::Nft)),
            "an unsafe configured path never falls back to the fixed list"
        );
    }

    /// Host-verified paths from the privileged runner are trusted exactly, and nothing else is.
    #[test]
    fn host_verified_paths_are_trusted_only_exactly() {
        let lookup = Lookup {
            root: PathBuf::from("/nonexistent-ifm-root"),
            owner: 0,
            host_verified: vec![PathBuf::from("/usr/sbin/nft")],
        };
        assert!(lookup.trusted(Path::new("/usr/sbin/nft")));
        assert!(!lookup.trusted(Path::new("/tmp/not-nft")));
    }

    /// J592 review (P1, security, D384, #265): a store entry's name says nothing about who asked
    /// for it. On a multi-user Nix host any local user can `nix-store --add` a directory named
    /// `nftables-999999.0.0` (or `iptables-999999.0.0`) through the world-writable daemon
    /// socket; the result is root-owned and read-only, so it passes every ownership check, and
    /// its version sorts first. A host with no fixed-path tool (production's shape, #483) would
    /// then run it as root. The lookup must only trust fixed, root-owned entry points (system
    /// and root profiles, the distribution directories, an explicit path), never a name match.
    #[test]
    fn review_j592_lookup_never_selects_a_store_path_by_its_name() {
        let tree = Tree::new();
        tree.tool(
            &format!("{}/bin/nft", store('f', "nftables-999999.0.0")),
            0o555,
        );
        for tool in [
            Tool::IptablesNft,
            Tool::IptablesNftRestore,
            Tool::Ip6tablesNft,
            Tool::Ip6tablesNftRestore,
        ] {
            tree.tool(
                &format!(
                    "{}/bin/{}",
                    store('9', "iptables-999999.0.0"),
                    tool.binary()
                ),
                0o555,
            );
        }
        // Pin every fixture directory to 0755: under a group-writable umask the ownership
        // check alone would refuse the store and this test would pass for the wrong reason.
        for entry in ["nix", "nix/store"]
            .into_iter()
            .map(|relative| tree.0.join(relative))
            .chain(
                std::fs::read_dir(tree.0.join("nix/store"))
                    .expect("fixture store")
                    .flat_map(|entry| {
                        let path = entry.expect("fixture entry").path();
                        [path.join("bin"), path]
                    }),
            )
        {
            std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755))
                .expect("test fixture");
        }
        for tool in [
            Tool::Nft,
            Tool::IptablesNft,
            Tool::IptablesNftRestore,
            Tool::Ip6tablesNft,
            Tool::Ip6tablesNftRestore,
        ] {
            assert_eq!(
                tree.lookup().find(tool, None),
                Err(Missing(tool)),
                "{tool:?}: a store path nobody linked from a root profile was chosen by name"
            );
        }
    }

    /// J592 review (P1, security, D384, #265), real Nix daemon: an unprivileged user plants
    /// `nftables-999999.0.0/bin/nft` and `iptables-999999.0.0/bin/iptables-nft-restore` with
    /// `nix-store --add`. The store scan must not offer either to run as root. The planted paths
    /// are removed with `nix-store --delete` afterwards. Reports SKIP without a Nix daemon. The
    /// store scan is gone, so this now asserts the replacement API never reaches the planted path.
    #[test]
    fn review_j592_store_scan_never_offers_a_user_added_tool() {
        use std::process::Command;

        /// Deletes the planted store paths even when the assertion fails.
        struct Planted(Vec<PathBuf>, PathBuf);
        impl Drop for Planted {
            fn drop(&mut self) {
                for path in &self.0 {
                    let _ = Command::new(&self.1).arg("--delete").arg(path).output();
                }
            }
        }

        let nix_store = PathBuf::from("/nix/var/nix/profiles/default/bin/nix-store");
        if !nix_store.exists() || !Path::new("/nix/var/nix/daemon-socket/socket").exists() {
            eprintln!("SKIP: no multi-user Nix daemon on this host");
            return;
        }
        let scratch = Tree::new();
        let mut planted = Planted(Vec::new(), nix_store.clone());
        let mut offered = Vec::new();
        for (package, tool) in [
            ("nftables-999999.0.0", Tool::Nft),
            ("iptables-999999.0.0", Tool::IptablesNftRestore),
        ] {
            let program = scratch.tool(&format!("{package}/bin/{}", tool.binary()), 0o755);
            std::fs::write(
                &program,
                "#!/bin/sh\necho j592-not-a-firewall-tool >&2\nexit 1\n",
            )
            .expect("test fixture");
            let added = Command::new(&nix_store)
                .arg("--add")
                .arg(scratch.0.join(package))
                .output()
                .expect("run nix-store --add as the unprivileged test user");
            assert!(added.status.success(), "{added:?}");
            let store_path = PathBuf::from(String::from_utf8_lossy(&added.stdout).trim());
            planted.0.push(store_path.clone());
            let path = store_path.join("bin").join(tool.binary());
            let metadata = std::fs::metadata(&path).expect("planted tool");
            let lookup = super::Lookup::system();
            let found = lookup.find(tool, None);
            eprintln!(
                "PLANTED {} uid={} mode={:o} found={found:?}",
                path.display(),
                metadata.uid(),
                metadata.mode() & 0o7777,
            );
            // The walk alone would accept the planted path if it were ever offered: the store
            // makes it root-owned. The defence is that no searched place leads to it.
            if found.as_ref().is_ok_and(|found| {
                std::fs::canonicalize(found).is_ok_and(|real| real.starts_with(&store_path))
            }) || searched_places().contains("/nix/store")
            {
                offered.push(path);
            }
        }
        assert!(
            offered.is_empty(),
            "the lookup offers store paths an unprivileged user added, to run as root: {offered:?}"
        );
    }
}
