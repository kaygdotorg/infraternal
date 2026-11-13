//! Finds the mesh firewall tools (nft and the iptables-nft frontends) at fixed, root-owned paths [D384, D386], #265, #483.
//!
//! The mesh runs these tools as root, so a tool is only used when it sits at one of a short,
//! fixed list of places and passes an ownership check. `PATH` is never searched: an environment
//! variable must not be able to choose a program that root runs.
//!
//! Where it looks, in order, for each tool:
//! 1. the distribution directories `/usr/sbin` and `/usr/bin`;
//! 2. the Nix system and root profiles (`/run/current-system/sw/bin`,
//!    `/nix/var/nix/profiles/{system/sw,default}/bin`, root's `~/.nix-profile/bin` and
//!    `~/.local/state/nix/profile/bin`);
//! 3. the Nix store itself, `/nix/store/<hash>-<package>-<version>/bin/<tool>`, newest version
//!    first. This covers hosts whose firewall runs a store path that no profile links, which is
//!    how production's nftables is installed (#483).
//!
//! A path is trusted when the link and its target are owned by root, the target is a regular
//! executable file that only root can change, and every directory above both the link and the
//! target is owned by root and not writable by others (a sticky directory such as `/nix/store`,
//! mode 1775, is allowed because others cannot replace root's entries in it).
//!
//! The lookup happens at run time, not at install time. A Nix store path pinned at install time
//! goes stale after a profile upgrade and garbage collection, and a pin in the service unit would
//! not reach hosts installed by `infraternal up`, older units, or the server. The last trusted path
//! is cached per tool and re-checked before each use, so the store is only scanned when nothing
//! cheaper is found.
//!
//! The command is run through the found path, not its resolved target: `iptables-nft` and its
//! siblings are symlinks to one multi-call binary that picks its behaviour from `argv[0]`.
use std::{
    cmp::Ordering,
    fmt, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Test and test-support builds may trust these exact paths only after the privileged runner
/// verified them on the host; it passes them as a `:`-separated list.
#[cfg(any(test, feature = "test-support"))]
const TEST_ROOT_OWNED_TOOLS_ENV: &str = "INFRATERNA_TEST_ROOT_OWNED_NFT";

/// Fixed directories searched before the Nix store, in order of preference.
const FIXED_DIRECTORIES: [&str; 7] = [
    "/usr/sbin",
    "/usr/bin",
    "/run/current-system/sw/bin",
    "/nix/var/nix/profiles/system/sw/bin",
    "/nix/var/nix/profiles/default/bin",
    "/root/.nix-profile/bin",
    "/root/.local/state/nix/profile/bin",
];

/// The store pattern searched last; `<package>` is the tool's Nix package name.
const STORE_PATTERN: &str = "/nix/store/*-<package>-<version>/bin";

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

    /// The Nix package name whose store path ships the executable.
    const fn package(self) -> &'static str {
        match self {
            Self::Nft => "nftables",
            _ => "iptables",
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
            searched_places(self.0.package())
        )
    }
}

impl From<Missing> for io::Error {
    fn from(missing: Missing) -> Self {
        Self::new(io::ErrorKind::NotFound, missing.to_string())
    }
}

/// The searched directories as one sentence fragment; `package` fills the store pattern.
pub(crate) fn searched_places(package: &str) -> String {
    format!(
        "{} or {}",
        FIXED_DIRECTORIES.join(", "),
        STORE_PATTERN.replace("<package>", package)
    )
}

/// Where and how to look; the real system uses `/` and root, tests use a private tree.
pub(crate) struct Lookup {
    /// The directory treated as `/` when building candidate paths.
    root: PathBuf,
    /// The uid that must own the tool and its link.
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

    /// Find the first trusted path for `tool`, checking the fixed directories before the store.
    ///
    /// # Errors
    /// Returns [`Missing`] when no searched place holds a trusted executable.
    pub(crate) fn find(&self, tool: Tool) -> Result<PathBuf, Missing> {
        FIXED_DIRECTORIES
            .iter()
            .map(|directory| self.place(directory).join(tool.binary()))
            .chain(self.store_candidates(tool))
            .find(|candidate| self.trusted(candidate))
            .ok_or(Missing(tool))
    }

    /// Map an absolute host path into this lookup's root.
    fn place(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// Store paths that may hold `tool`, newest package version first.
    ///
    /// Only entries named `<hash>-<package>-<digit>…` count, so a different package whose name
    /// merely contains the package's (for example a language binding) is never picked.
    fn store_candidates(&self, tool: Tool) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(self.place("/nix/store")) else {
            return Vec::new();
        };
        let prefix = format!("{}-", tool.package());
        let mut found: Vec<(String, PathBuf)> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let (hash, rest) = name.split_once('-')?;
                let version = rest.strip_prefix(&prefix)?;
                (hash.len() == 32 && version.starts_with(|c: char| c.is_ascii_digit())).then(|| {
                    (
                        version.to_owned(),
                        entry.path().join("bin").join(tool.binary()),
                    )
                })
            })
            .collect();
        found.sort_by(|(left, left_path), (right, right_path)| {
            compare_versions(right, left).then_with(|| left_path.cmp(right_path))
        });
        found.into_iter().map(|(_, path)| path).collect()
    }

    /// Whether `path` is a tool only the trusted owner could have put or changed there.
    pub(crate) fn trusted(&self, path: &Path) -> bool {
        if self.host_verified.iter().any(|verified| verified == path) {
            return true;
        }
        if !path.is_absolute() {
            return false;
        }
        let (Ok(link), Ok(target), Ok(canonical)) = (
            std::fs::symlink_metadata(path),
            std::fs::metadata(path),
            std::fs::canonicalize(path),
        ) else {
            return false;
        };
        link.uid() == self.owner
            && target.uid() == self.owner
            && target.is_file()
            && target.mode() & 0o111 != 0
            && target.mode() & 0o022 == 0
            && path
                .parent()
                .is_some_and(|parent| self.trusted_directories(parent))
            && canonical
                .parent()
                .is_some_and(|parent| self.trusted_directories(parent))
    }

    /// Every directory from `directory` up to `/` is owned by root or the owner and not
    /// replaceable by anyone else.
    fn trusted_directories(&self, directory: &Path) -> bool {
        directory.ancestors().all(|ancestor| {
            std::fs::metadata(ancestor).is_ok_and(|metadata| {
                metadata.is_dir()
                    && (metadata.uid() == 0 || metadata.uid() == self.owner)
                    && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0)
            })
        })
    }
}

/// Compare two version strings by their numeric and text runs, so `1.1.10` sorts above `1.1.7`.
fn compare_versions(left: &str, right: &str) -> Ordering {
    /// Split a version into alternating digit and non-digit runs.
    fn runs(version: &str) -> impl Iterator<Item = &str> {
        let mut rest = version;
        std::iter::from_fn(move || {
            let first = rest.chars().next()?;
            let digits = first.is_ascii_digit();
            let end = rest
                .find(|c: char| c.is_ascii_digit() != digits)
                .unwrap_or(rest.len());
            let (run, tail) = rest.split_at(end);
            rest = tail;
            Some(run)
        })
    }
    let mut left_runs = runs(left);
    let mut right_runs = runs(right);
    loop {
        match (left_runs.next(), right_runs.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => {
                let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                    (Ok(a), Ok(b)) => a.cmp(&b),
                    _ => a.cmp(b),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    }
}

/// The last trusted path per tool, re-checked before each use.
static CACHE: Mutex<[Option<PathBuf>; 5]> = Mutex::new([None, None, None, None, None]);

/// Find `tool` on this host, reusing the last trusted path while it still passes the check.
///
/// # Errors
/// Returns [`Missing`] naming the tool and every place searched.
pub(crate) fn find(tool: Tool) -> Result<PathBuf, Missing> {
    let lookup = Lookup::system();
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = &mut cache[tool.index()];
    if let Some(path) = slot.as_ref().filter(|path| lookup.trusted(path)) {
        return Ok(path.clone());
    }
    let found = lookup.find(tool);
    *slot = found.as_ref().ok().cloned();
    found
}

/// Lookup order, Nix store selection, trust checks and missing-tool messages, over private trees.
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::{Lookup, Missing, Tool, compare_versions, searched_places};
    use std::{
        cmp::Ordering,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
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

        /// Write an executable file with `mode` at `relative`, creating its directories.
        fn tool(&self, relative: &str, mode: u32) -> PathBuf {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("test fixture");
            std::fs::write(&path, "#!/bin/sh\n").expect("test fixture");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("test fixture");
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

    /// A host whose only nft is in the Nix store (production's shape, #483) gets that exact path.
    #[test]
    fn a_nix_store_only_nft_is_found_at_its_exact_store_path() {
        let tree = Tree::new();
        let nft = tree.tool(&format!("{}/bin/nft", store('a', "nftables-1.1.7")), 0o755);
        assert_eq!(tree.lookup().find(Tool::Nft), Ok(nft));
    }

    /// The newest store version wins, and look-alike packages such as language bindings never do.
    #[test]
    fn the_store_prefers_the_newest_version_of_the_exact_package() {
        let tree = Tree::new();
        tree.tool(&format!("{}/bin/nft", store('a', "nftables-1.1.7")), 0o755);
        let newest = tree.tool(&format!("{}/bin/nft", store('b', "nftables-1.1.10")), 0o755);
        tree.tool(
            &format!("{}/bin/nft", store('c', "python3.12-nftables-9.9.9")),
            0o755,
        );
        tree.tool(&format!("{}/bin/nft", store('d', "nftables-doc")), 0o755);
        assert_eq!(tree.lookup().find(Tool::Nft), Ok(newest));
    }

    /// A distribution path is preferred to the store, and a Nix profile link to the store is used
    /// through the link itself.
    #[test]
    fn fixed_directories_come_before_the_store_and_links_are_kept() {
        let tree = Tree::new();
        let target = tree.tool(&format!("{}/bin/nft", store('a', "nftables-1.1.7")), 0o755);
        let profile = tree.0.join("nix/var/nix/profiles/default/bin");
        std::fs::create_dir_all(&profile).expect("test fixture");
        symlink(&target, profile.join("nft")).expect("test fixture");
        assert_eq!(tree.lookup().find(Tool::Nft), Ok(profile.join("nft")));

        let distro = tree.tool("usr/sbin/nft", 0o755);
        assert_eq!(tree.lookup().find(Tool::Nft), Ok(distro));
    }

    /// The iptables-nft frontends of both families come from the store's iptables package, run
    /// through their own names (the multi-call binary dispatches on `argv[0]`).
    #[test]
    fn ipv4_and_ipv6_frontends_are_found_through_their_own_names() {
        let tree = Tree::new();
        let bin = store('e', "iptables-1.8.11");
        let multi = tree.tool(&format!("{bin}/bin/xtables-nft-multi"), 0o755);
        for tool in [
            Tool::IptablesNft,
            Tool::IptablesNftRestore,
            Tool::Ip6tablesNft,
            Tool::Ip6tablesNftRestore,
        ] {
            let link = tree.0.join(&bin).join("bin").join(tool.binary());
            symlink(&multi, &link).expect("test fixture");
            assert_eq!(tree.lookup().find(tool), Ok(link), "{tool:?}");
        }
    }

    /// A missing tool names itself and every place searched, including the store pattern.
    #[test]
    fn a_missing_tool_names_every_searched_place() {
        let tree = Tree::new();
        let missing = tree.lookup().find(Tool::Ip6tablesNftRestore);
        assert_eq!(missing, Err(Missing(Tool::Ip6tablesNftRestore)));
        let message = missing.expect_err("no tool in an empty tree").to_string();
        for place in [
            "ip6tables-nft-restore was not found",
            "/usr/sbin",
            "/usr/bin",
            "/run/current-system/sw/bin",
            "/root/.nix-profile/bin",
            "/nix/store/*-iptables-<version>/bin",
        ] {
            assert!(message.contains(place), "missing {place}: {message}");
        }
        assert!(searched_places("nftables").ends_with("/nix/store/*-nftables-<version>/bin"));
    }

    /// Writable, non-executable or wrongly owned files are refused, as is a writable directory.
    #[test]
    fn untrusted_files_and_directories_are_refused() {
        let tree = Tree::new();
        let lookup = tree.lookup();
        let writable = tree.tool("usr/sbin/nft", 0o775);
        assert!(!lookup.trusted(&writable));
        let plain = tree.tool("usr/bin/nft", 0o644);
        assert!(!lookup.trusted(&plain));
        assert_eq!(lookup.find(Tool::Nft), Err(Missing(Tool::Nft)));

        let open = tree.0.join("nix/var/nix/profiles/default/bin");
        let nft = tree.tool("nix/var/nix/profiles/default/bin/nft", 0o755);
        assert!(lookup.trusted(&nft));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))
            .expect("test fixture");
        assert!(
            !lookup.trusted(&nft),
            "a world-writable directory lets others swap the tool"
        );
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777))
            .expect("test fixture");
        assert!(
            lookup.trusted(&nft),
            "a sticky directory keeps entries with their owners"
        );

        let stranger = Lookup::under(&tree.0, tree.owner() + 1);
        assert!(!stranger.trusted(&nft), "another owner's file is refused");
        assert!(
            !lookup.trusted(Path::new("usr/sbin/nft")),
            "relative paths are refused"
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

    /// Numeric runs compare as numbers; text runs as text.
    #[test]
    fn versions_compare_by_number() {
        assert_eq!(compare_versions("1.1.10", "1.1.7"), Ordering::Greater);
        assert_eq!(compare_versions("1.8.11", "1.8.11"), Ordering::Equal);
        assert_eq!(compare_versions("1.1", "1.1.1"), Ordering::Less);
    }
}
