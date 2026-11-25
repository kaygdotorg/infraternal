//! Where `server init` puts the server's folders, following each operating system's standard [D395, #516].
//!
//! Every default here is absolute and comes only from the values in
//! [`Environment`], never from the current directory: a service is installed
//! once and must find the same folders forever.
//!
//! # The server's data folder
//!
//! The server keeps one folder (`--data`). It holds the database
//! (`infraternal.sqlite`), sockets, the identity and trust files: databases and
//! state, in D395's words. It cannot be split yet, so the whole folder maps to
//! D395's *state* location, with no extra suffix, matching the Linux system
//! path that already exists. On a Linux system with an infraternal agent in
//! the shared base, the server gets its own 0700 `server/` child.
//!
//! | Platform        | Data folder                                          |
//! |-----------------|------------------------------------------------------|
//! | Linux, per user | `$XDG_STATE_HOME/infraternal`, else `~/.local/state/infraternal` |
//! | Linux, system   | `/var/lib/infraternal` (D229)                        |
//! | macOS, per user | `~/Library/Application Support/infraternal`          |
//! | macOS, system   | `/Library/Application Support/infraternal`           |
//!
//! D395 puts binaries and data in `$XDG_DATA_HOME/infraternal` on Linux per user,
//! which is where the server's remote CA already defaults
//! (`infraternal-server`'s `remote_startup::default_ca_dir`). macOS has a single
//! Application Support folder for both, as D395 says.
//!
//! # Existing installs
//!
//! [`resolve_server_init`] reports the folders recorded in the unit it would
//! overwrite, so a custom web root is kept and a re-run plans the same unit.
//! When that unit's data folder is not the default above and no `--data` was
//! given, `server init` then moves it there with `install_move` (owner,
//! 2026-11-15: "change for existing installs too"), which also rewrites the
//! unit. An explicit `--data` keeps any folder where it is.
//!
//! # Not routed through here (yet)
//!
//! - `remote_startup::default_ca_dir` applies the same XDG rule to
//!   `$XDG_DATA_HOME`, but it lives in the `infraternal-server` crate, which this
//!   binary crate depends on, not the other way round. Sharing it needs a small
//!   common crate; that belongs to the follow-up that moves the infraternal
//!   agents onto D395 paths.
//! - `exec_label`'s `/var/lib/infraternal/bin/` is not a default to resolve but
//!   the fixed system install prefix whose files get an executable `SELinux`
//!   label (D17). It is a policy match, so it stays a constant there.

use std::{
    env,
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};

/// The Linux system base shared by the server and infraternal agent.
pub(super) const LINUX_SYSTEM_BASE: &str = "/var/lib/infraternal";

/// The standard private server child when the Linux system base is shared.
pub(super) const LINUX_COMBINED_SERVER: &str = "/var/lib/infraternal/server";

/// Why a folder could not be chosen; the text says what to pass instead.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PathError(String);

/// Whether the install belongs to one user or to the whole machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A per-user service.
    User,
    /// A machine-wide service.
    System,
}

/// The operating-system family whose folder conventions apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// XDG Base Directory for users, FHS for the system.
    Linux,
    /// `~/Library` and `/Library`.
    MacOs,
}

/// The facts the defaults come from, as plain values so tests never depend on the real environment.
///
/// Every host fact a default reads is a field here: `detect` fills them from
/// the machine, and tests set them directly. A test that builds this struct
/// by hand therefore never sees the host's real `/var/lib/infraternal`.
#[derive(Debug, Clone)]
pub struct Environment {
    /// Which convention to follow.
    pub os: Os,
    /// Whether the process runs as root (effective user id 0).
    pub is_root: bool,
    /// `$XDG_STATE_HOME`, only when it is set, non-empty and absolute.
    pub xdg_state_home: Option<PathBuf>,
    /// `$HOME`, when set and non-empty.
    pub home: Option<PathBuf>,
    /// The folder holding the running binary, where a release bundle keeps `web/`.
    pub binary_dir: Option<PathBuf>,
    /// The Linux system base a machine-wide server defaults to: [`LINUX_SYSTEM_BASE`]
    /// on a real machine. A debug-only test hook may point `detect` elsewhere so
    /// the CLI integration tests reason about a fixture, never the real base.
    pub linux_system_base: PathBuf,
    /// Whether an infraternal agent's state already sits in `linux_system_base`,
    /// so a new machine-wide server takes the private `server/` child (see
    /// `system_base_has_agent_state`). `detect` reads it from disk; tests set it.
    pub agent_in_system_base: bool,
}

impl Environment {
    /// Read the real process environment, the effective user and the running binary's location.
    #[must_use]
    pub fn detect() -> Self {
        let mut environment = Self::from_lookup(
            if cfg!(target_os = "macos") {
                Os::MacOs
            } else {
                Os::Linux
            },
            nix::unistd::Uid::effective().is_root(),
            |name| env::var_os(name),
            env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_owned)),
        );
        // Debug builds let the CLI integration tests point the system base at a
        // fixture, mirroring `INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR`. Release
        // builds always use the real base.
        #[cfg(debug_assertions)]
        if let Some(base) = env::var_os("INFRATERNAL_TEST_LINUX_SYSTEM_BASE") {
            environment.linux_system_base = PathBuf::from(base);
        }
        environment.agent_in_system_base = environment.os == Os::Linux
            && system_base_has_agent_state(&environment.linux_system_base);
        environment
    }

    /// Build an environment from a variable lookup, applying the XDG rules once.
    ///
    /// The XDG Base Directory specification says a relative path in an `XDG_*`
    /// variable is invalid and must be ignored, and an empty one counts as
    /// unset, so both fall back to the `$HOME` default.
    pub fn from_lookup(
        os: Os,
        is_root: bool,
        lookup: impl Fn(&str) -> Option<OsString>,
        binary_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            os,
            is_root,
            xdg_state_home: lookup("XDG_STATE_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute()),
            home: lookup("HOME")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from),
            binary_dir,
            linux_system_base: PathBuf::from(LINUX_SYSTEM_BASE),
            // Only `detect` looks at the disk; a built value starts with no agent state.
            agent_in_system_base: false,
        }
    }

    /// `$HOME` when it is set and absolute; a relative one would depend on the cwd.
    fn absolute_home(&self) -> Result<&Path, PathError> {
        self.home
            .as_deref()
            .filter(|home| home.is_absolute())
            .ok_or_else(|| {
                PathError(
                    "cannot find a home folder for the default location; pass --data <absolute path>"
                        .to_owned(),
                )
            })
    }
}

/// Refuse a machine-wide install from a non-root process before anything is planned.
///
/// A dry run only prints the plan, so it is allowed without root. Root without
/// `--system` keeps the existing behaviour: a per-user service for root.
pub fn check_scope(
    scope: Scope,
    dry_run: bool,
    environment: &Environment,
) -> Result<(), PathError> {
    if scope == Scope::System && !dry_run && !environment.is_root {
        return Err(PathError(
            "--system installs a machine-wide service and needs root; run it with sudo, \
             or leave out --system for a per-user service (--dry-run previews without root)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// The server's default data folder for a fresh install in this scope (see the module table).
pub fn server_data_dir(scope: Scope, environment: &Environment) -> Result<PathBuf, PathError> {
    match (environment.os, scope) {
        (Os::Linux, Scope::System) => Ok(if environment.agent_in_system_base {
            environment.linux_system_base.join("server")
        } else {
            environment.linux_system_base.clone()
        }),
        (Os::Linux, Scope::User) => Ok(match &environment.xdg_state_home {
            Some(state) => state.join("infraternal"),
            None => environment
                .absolute_home()?
                .join(".local/state/infraternal"),
        }),
        (Os::MacOs, Scope::System) => Ok(PathBuf::from("/Library/Application Support/infraternal")),
        (Os::MacOs, Scope::User) => Ok(environment
            .absolute_home()?
            .join("Library/Application Support/infraternal")),
    }
}

/// Whether an infraternal agent already keeps state in the Linux system base.
///
/// A new machine-wide server then takes the private `server/` child, so the two
/// do not share one folder. A binary directory can also be part of a
/// server-only release, so this looks for agent state or ownership markers,
/// not for the binary itself. Only [`Environment::detect`] calls this; the
/// result is stored on the environment so tests never read the real base.
fn system_base_has_agent_state(base: &Path) -> bool {
    [
        "agent",
        "state",
        "sessions",
        ".bootstrap-owner",
        ".bootstrap-lock",
        ".promotion-transaction",
        "host-firewall-agent.json",
    ]
    .iter()
    .any(|name| {
        std::fs::symlink_metadata(base.join(name))
            .is_ok_and(|entry| entry.is_dir() || entry.is_file())
    })
}

/// The release bundle's `web/` folder beside the running binary, when it exists.
#[must_use]
pub fn bundled_web_root(environment: &Environment) -> Option<PathBuf> {
    environment
        .binary_dir
        .as_ref()
        .map(|dir| dir.join("web"))
        .filter(|dir| dir.is_dir())
}

/// What `server init` found already installed, read before it chooses folders.
#[derive(Debug, Clone, Default)]
pub struct Installed {
    /// The unit init would overwrite (same scope and name), when one exists.
    pub unit: Option<infraternal_status::RecordedServer>,
    /// The data folder of any installed system server unit, the readers' rule
    /// (`infraternal_status::server_data_directory`). Only used for `--system`.
    pub system_data: Option<PathBuf>,
    /// Whether a system server unit named like this one exists, whatever it records.
    pub system_unit: bool,
}

/// A note for root running `server init` without `--system` while a system server unit exists.
///
/// Root without `--system` still installs a per-user service for root (kept
/// behaviour), which is rarely what a root login means and leaves two servers.
/// The text names the system install and the flag; it is printed, never fatal.
#[must_use]
pub fn root_user_scope_warning(
    scope: Scope,
    installed: &Installed,
    environment: &Environment,
) -> Option<String> {
    let system_unit = installed.system_data.is_some() || installed.system_unit;
    (scope == Scope::User && environment.is_root && system_unit).then(|| {
        "warning: a system-wide infraternal server is already installed on this machine, \
         and you are root without --system, so this installs a second per-user service for root; \
         pass --system to manage the system install instead"
            .to_owned()
    })
}

/// The folders `server init` will write into the unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFolders {
    /// The absolute `--data` folder.
    pub data: PathBuf,
    /// The absolute `--web-root` folder, or `None` to leave the flag out of the unit.
    pub web_root: Option<PathBuf>,
}

/// Choose `server init`'s data and web folders, in this order:
///
/// 1. an explicit `--data` / `--web-root`, which must be absolute;
/// 2. what the existing unit records, so a re-run writes the same unit text and
///    a custom folder is never orphaned, even with `--force`;
/// 3. for `--system` data only, the folder an installed system server records
///    under another name (what init used before #516);
/// 4. the fresh-install defaults: [`server_data_dir`], and the bundled `web/`
///    beside the binary.
///
/// An existing unit without `--web-root` keeps that shape: adding the flag
/// would change the unit text and turn a no-op re-run into a conflict. With no
/// bundle and no flag the unit has no `--web-root`, as before.
pub fn resolve_server_init(
    scope: Scope,
    data: Option<&Path>,
    web_root: Option<&Path>,
    installed: &Installed,
    environment: &Environment,
) -> Result<ServerFolders, PathError> {
    let recorded = installed.unit.as_ref();
    // A hand-edited unit with a relative folder cannot be reproduced: its
    // meaning depends on the directory systemd happened to use. Replacing it
    // silently would move the server's data, so refuse and say what to do.
    if let Some((flag, value)) = recorded.and_then(|unit| {
        unit.relative.iter().find(|(flag, _)| {
            (flag == "--data" && data.is_none()) || (flag == "--web-root" && web_root.is_none())
        })
    }) {
        return Err(PathError(format!(
            "the installed unit has a relative {flag} {} (a hand edit), so init cannot tell \
             which folder it means and will not replace it; pass {flag} <absolute path> \
             with --force, or fix the unit",
            value.display()
        )));
    }
    let data = match explicit_absolute("--data", data)? {
        Some(path) => path,
        None => match (recorded.and_then(|unit| unit.data.clone()), scope) {
            (Some(path), _) => path,
            (None, Scope::System) => match &installed.system_data {
                Some(path) => path.clone(),
                None => server_data_dir(scope, environment)?,
            },
            (None, Scope::User) => server_data_dir(scope, environment)?,
        },
    };
    let web_root = match explicit_absolute("--web-root", web_root)? {
        Some(path) => Some(path),
        None => match recorded {
            Some(unit) => unit.web_root.clone(),
            None => bundled_web_root(environment),
        },
    };
    Ok(ServerFolders { data, web_root })
}

/// Pass an explicit absolute flag value through; refuse a relative one.
///
/// A relative value is REFUSED rather than resolved against the cwd: the unit
/// would silently freeze whichever directory the shell was in (#516). The
/// error names the absolute path the user most likely meant, so the retry is a
/// copy and paste. Printing the resolved path and carrying on was rejected
/// because an unattended `--yes` run never reads it.
fn explicit_absolute(flag: &str, value: Option<&Path>) -> Result<Option<PathBuf>, PathError> {
    match value {
        None => Ok(None),
        Some(path) if path.is_absolute() => Ok(Some(path.to_owned())),
        Some(path) => Err(PathError(match env::current_dir() {
            Ok(cwd) => format!(
                "{flag} {} is relative; pass an absolute path, for example {flag} {}",
                path.display(),
                cwd.join(path).display()
            ),
            Err(_) => format!(
                "{flag} {} is relative; pass an absolute path",
                path.display()
            ),
        })),
    }
}

/// Create `path` and any missing parents as private (0700) folders.
///
/// Folders that already exist keep their mode: a re-run must not change an
/// install it did not create. The server checks and tightens its own folder
/// at start as well; creating it private here closes the window before that.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

// ---------------------------------------------------------------------------
// The command on PATH [D395]
// ---------------------------------------------------------------------------

/// What publishing the PATH link did, so the install can tell the user.
#[derive(Debug, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The link did not exist and now points at the binary.
    Created(PathBuf),
    /// Our link pointed at an older release and now points at the binary.
    Repointed(PathBuf),
    /// The link already points at the binary.
    Current(PathBuf),
    /// Something else is at the link path; it was not touched.
    Foreign(PathBuf),
    /// No link is made here (macOS per user): add this directory to `PATH`.
    PathAdvice(PathBuf),
}

impl LinkOutcome {
    /// One plain sentence for the install output.
    #[must_use]
    pub fn describe(&self, binary: &Path) -> String {
        match self {
            Self::Created(link) => format!("Linked {} to {}.", link.display(), binary.display()),
            Self::Repointed(link) => {
                format!("Re-pointed {} to {}.", link.display(), binary.display())
            }
            Self::Current(link) => format!("{} already points at this release.", link.display()),
            Self::Foreign(link) => format!(
                "Left {} alone: it is not our link, so `infraternal` on PATH may be another program. \
                 Run {} directly, or move that file aside and install again.",
                link.display(),
                binary.display()
            ),
            Self::PathAdvice(dir) => format!(
                "To run `infraternal` from any shell, add this line to your shell profile: \
                 export PATH=\"{}:$PATH\"",
                dir.display()
            ),
        }
    }
}

/// Where the one `infraternal` link lives, or `None` when no link is made.
///
/// Linux per user is `~/.local/bin/infraternal`; system-wide (either OS) is
/// `/usr/local/bin/infraternal`; macOS per user makes no link and prints the
/// `PATH` line instead [D395].
pub fn path_link(scope: Scope, environment: &Environment) -> Result<Option<PathBuf>, PathError> {
    match (environment.os, scope) {
        (_, Scope::System) => Ok(Some(PathBuf::from("/usr/local/bin/infraternal"))),
        (Os::Linux, Scope::User) => Ok(Some(
            environment.absolute_home()?.join(".local/bin/infraternal"),
        )),
        (Os::MacOs, Scope::User) => Ok(None),
    }
}

/// Where the symlink `link` really points, as an absolute path with `.` and `..` resolved.
///
/// A relative target is taken from the link's own folder, as the kernel does.
/// `..` is resolved lexically, without touching the disk, so a dangling link
/// (its release deleted) still has a target to judge. Lexical resolution can
/// differ from the kernel's only when a component of the target is itself a
/// symlink to elsewhere; then the link is judged by the path it names, which
/// errs on the side of calling it foreign. `None` means it is not a readable link.
fn link_target(link: &Path) -> Option<PathBuf> {
    let target = std::fs::read_link(link).ok()?;
    let joined = if target.is_absolute() {
        target
    } else {
        link.parent()?.join(target)
    };
    let mut normal = PathBuf::new();
    for part in joined.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Some(normal)
}

/// Whether the symlink `link` points at a release of ours.
///
/// Ours means: exactly `binary`, or a file named `infraternal`, `live` or
/// `current` below a folder called `infraternal` (an install folder of any
/// release, old or new). That is how an update recognises the previous
/// release's link and re-points it, while a link to `/usr/bin/other` is foreign.
fn points_at_ours(link: &Path, binary: &Path) -> bool {
    let Some(target) = link_target(link) else {
        return false;
    };
    if target == binary {
        return true;
    }
    let named = target.file_name().is_some_and(|name| {
        ["infraternal", "live", "current"]
            .iter()
            .any(|ours| name == *ours)
    });
    named
        && target.parent().is_some_and(|dir| {
            dir.components()
                .any(|part| part.as_os_str() == "infraternal")
        })
}

/// Point `link` at `binary`: create it, re-point our own older link, never replace anything else.
///
/// A regular file, a directory or a symlink to somewhere not ours is reported
/// as [`LinkOutcome::Foreign`] and left untouched. Re-pointing builds the new
/// symlink beside the old one and renames it over, so `PATH` never sees a gap.
pub fn publish_link(link: &Path, binary: &Path) -> io::Result<LinkOutcome> {
    match std::fs::symlink_metadata(link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if link_target(link).as_deref() == Some(binary) {
                return Ok(LinkOutcome::Current(link.to_owned()));
            }
            if !points_at_ours(link, binary) {
                return Ok(LinkOutcome::Foreign(link.to_owned()));
            }
            // Known window (J719 P3): between the check above and the rename
            // below, someone could replace the link with a file of their own,
            // and the rename would replace that file. Closing it needs an
            // atomic swap (Linux `renameat2(RENAME_EXCHANGE)`, macOS
            // `renamex_np(RENAME_SWAP)`) and a swap back, two OS paths for a
            // race in a folder only its owner (or root) can write. Accepted:
            // PATH readers still see the old or the new link, never neither.
            let parent = link.parent().ok_or(io::ErrorKind::InvalidInput)?;
            let temporary = parent.join(format!(".infraternal.link-{}", std::process::id()));
            let _ = std::fs::remove_file(&temporary);
            std::os::unix::fs::symlink(binary, &temporary)?;
            if let Err(error) = std::fs::rename(&temporary, link) {
                let _ = std::fs::remove_file(&temporary);
                return Err(error);
            }
            Ok(LinkOutcome::Repointed(link.to_owned()))
        }
        Ok(_) => Ok(LinkOutcome::Foreign(link.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = link.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(binary, link)?;
            Ok(LinkOutcome::Created(link.to_owned()))
        }
        Err(error) => Err(error),
    }
}

/// Remove `link` only if it is a symlink to exactly `binary`; report whether it did.
///
/// Uninstall calls this so a link someone re-pointed to another program
/// stays. Unlike publishing, which re-points a link to any older release of
/// ours, removal is exact (D395: "only if it still points at our binary"):
/// a link to another release or a developer checkout belongs to that
/// install. A dangling link to exactly `binary` still counts, because
/// uninstall may delete the binary first.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the uninstall that calls it does not exist on dev yet"
    )
)]
pub fn remove_link(link: &Path, binary: &Path) -> io::Result<bool> {
    if std::fs::symlink_metadata(link).is_ok_and(|meta| meta.file_type().is_symlink())
        && link_target(link).as_deref() == Some(binary)
    {
        std::fs::remove_file(link)?;
        return Ok(true);
    }
    Ok(false)
}

/// What to do about the `PATH` command for an install in `scope` with `binary`.
pub fn link_for_install(
    scope: Scope,
    binary: &Path,
    environment: &Environment,
) -> Result<LinkOutcome, PathError> {
    match path_link(scope, environment)? {
        Some(link) => publish_link(&link, binary)
            .map_err(|error| PathError(format!("could not link {}: {error}", link.display()))),
        None => Ok(LinkOutcome::PathAdvice(
            binary.parent().map_or_else(PathBuf::new, Path::to_owned),
        )),
    }
}

#[cfg(test)]
mod tests {
    //! One test per rule, so each has its own failure. Paths are plain values;
    //! only the bundle and folder-creation tests touch the disk, under the temp dir.

    use super::*;
    use infraternal_status::RecordedServer;
    use std::os::unix::fs::PermissionsExt;

    /// A non-root Linux environment with no bundle beside the binary.
    fn linux() -> Environment {
        Environment {
            os: Os::Linux,
            is_root: false,
            xdg_state_home: None,
            home: Some(PathBuf::from("/home/someone")),
            binary_dir: None,
            linux_system_base: PathBuf::from(LINUX_SYSTEM_BASE),
            agent_in_system_base: false,
        }
    }

    /// The same machine following macOS conventions.
    fn macos() -> Environment {
        Environment {
            os: Os::MacOs,
            ..linux()
        }
    }

    /// Resolve with nothing installed and no flags.
    fn fresh(scope: Scope, environment: &Environment) -> ServerFolders {
        resolve_server_init(scope, None, None, &Installed::default(), environment).unwrap()
    }

    /// A unique scratch folder under the temp dir.
    fn scratch(tag: &str) -> PathBuf {
        env::temp_dir().join(format!("init-{tag}-{}", uuid::Uuid::new_v4()))
    }

    /// The four D395 defaults, with no `/server` suffix anywhere.
    #[test]
    fn fresh_defaults_follow_d395_on_every_platform() {
        assert_eq!(
            fresh(Scope::User, &linux()).data,
            PathBuf::from("/home/someone/.local/state/infraternal")
        );
        assert_eq!(
            fresh(Scope::System, &linux()).data,
            PathBuf::from("/var/lib/infraternal")
        );
        assert_eq!(
            fresh(Scope::User, &macos()).data,
            PathBuf::from("/home/someone/Library/Application Support/infraternal")
        );
        assert_eq!(
            fresh(Scope::System, &macos()).data,
            PathBuf::from("/Library/Application Support/infraternal")
        );
    }

    /// A new install selects the private child only when infraternal agent state exists.
    #[test]
    fn combined_system_default_uses_the_server_child() {
        let base = scratch("combined");
        std::fs::create_dir_all(base.join("bin")).unwrap();
        assert!(!system_base_has_agent_state(&base));
        std::fs::create_dir(base.join("agent")).unwrap();
        assert!(system_base_has_agent_state(&base));
        // With the probe's answer recorded, the default takes the child.
        let combined = Environment {
            linux_system_base: base.clone(),
            agent_in_system_base: true,
            ..linux()
        };
        assert_eq!(
            server_data_dir(Scope::System, &combined).unwrap(),
            base.join("server")
        );
        std::fs::remove_dir(base.join("agent")).unwrap();
        std::fs::create_dir(base.join("server")).unwrap();
        assert!(!system_base_has_agent_state(&base));
        std::fs::remove_dir_all(base).unwrap();
    }

    /// A standalone server may already use the name `server` for its web root.
    #[test]
    fn standalone_system_default_ignores_an_unrelated_server_child() {
        let base = scratch("standalone-web");
        std::fs::create_dir_all(base.join("server")).unwrap();
        std::fs::write(base.join("server/index.html"), "standalone web").unwrap();
        std::fs::write(base.join("infraternal.sqlite"), "standalone data").unwrap();
        let standalone = system_base_has_agent_state(&base);
        std::fs::remove_dir_all(&base).unwrap();
        assert!(!standalone);
    }

    /// An absolute `XDG_STATE_HOME` is honoured; empty or relative ones are ignored (XDG spec).
    #[test]
    fn xdg_state_home_is_honoured_only_when_absolute() {
        let lookup = |value: &'static str| {
            move |name: &str| match name {
                "XDG_STATE_HOME" => Some(OsString::from(value)),
                "HOME" => Some(OsString::from("/home/someone")),
                _ => None,
            }
        };
        let env = Environment::from_lookup(Os::Linux, false, lookup("/srv/xdg"), None);
        assert_eq!(
            fresh(Scope::User, &env).data,
            PathBuf::from("/srv/xdg/infraternal")
        );
        for ignored in ["", "relative/state"] {
            let env = Environment::from_lookup(Os::Linux, false, lookup(ignored), None);
            assert_eq!(env.xdg_state_home, None, "{ignored:?}");
            assert_eq!(
                fresh(Scope::User, &env).data,
                PathBuf::from("/home/someone/.local/state/infraternal"),
                "{ignored:?}"
            );
        }
    }

    /// `detect` reads this process: its OS, its effective user and its `HOME`.
    #[test]
    fn detect_reads_the_running_process() {
        let env = Environment::detect();
        assert_eq!(env.os == Os::MacOs, cfg!(target_os = "macos"));
        assert_eq!(env.is_root, nix::unistd::Uid::effective().is_root());
        assert_eq!(
            env.home,
            env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from)
        );
        assert_eq!(
            env.binary_dir,
            env::current_exe().unwrap().parent().map(Path::to_owned)
        );
        assert!(env.xdg_state_home.as_ref().is_none_or(|p| p.is_absolute()));
    }

    /// No usable home means a refusal that names `--data`.
    #[test]
    fn missing_empty_or_relative_home_is_refused_for_user_data() {
        for home in [None, Some(""), Some("rel")] {
            let env = Environment::from_lookup(
                Os::Linux,
                false,
                |name| {
                    (name == "HOME")
                        .then_some(home.map(OsString::from))
                        .flatten()
                },
                None,
            );
            let error = resolve_server_init(Scope::User, None, None, &Installed::default(), &env)
                .unwrap_err();
            assert!(error.to_string().contains("--data"), "{home:?}");
        }
    }

    /// The web root defaults to the bundle's `web/`, and is left out when there is none.
    #[test]
    fn web_root_is_the_bundle_when_present_and_absent_otherwise() {
        let dir = scratch("bundle");
        std::fs::create_dir_all(&dir).unwrap();
        let mut env = linux();
        env.binary_dir = Some(dir.clone());
        assert_eq!(fresh(Scope::User, &env).web_root, None);
        std::fs::create_dir(dir.join("web")).unwrap();
        assert_eq!(fresh(Scope::User, &env).web_root, Some(dir.join("web")));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A re-run keeps the unit's recorded folders and its shape, even with a bundle present.
    #[test]
    fn an_existing_unit_keeps_its_folders_and_shape() {
        let dir = scratch("keep");
        std::fs::create_dir_all(dir.join("web")).unwrap();
        let mut env = linux();
        env.binary_dir = Some(dir.clone());
        let installed = Installed {
            unit: Some(RecordedServer {
                data: Some("/srv/custom".into()),
                web_root: None,
                relative: Vec::new(),
            }),
            system_data: Some("/srv/elsewhere".into()),
            system_unit: false,
        };
        for scope in [Scope::User, Scope::System] {
            let folders = resolve_server_init(scope, None, None, &installed, &env).unwrap();
            assert_eq!(
                folders,
                ServerFolders {
                    data: "/srv/custom".into(),
                    web_root: None
                }
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `--system` falls back to another system server's folder, as before #516; `--user` does not.
    #[test]
    fn system_scope_reuses_an_installed_system_servers_folder() {
        let installed = Installed {
            unit: None,
            system_data: Some("/srv/state".into()),
            system_unit: false,
        };
        let system = resolve_server_init(Scope::System, None, None, &installed, &linux()).unwrap();
        assert_eq!(system.data, PathBuf::from("/srv/state"));
        let user = resolve_server_init(Scope::User, None, None, &installed, &linux()).unwrap();
        assert_eq!(
            user.data,
            PathBuf::from("/home/someone/.local/state/infraternal")
        );
    }

    /// Explicit flags win over everything recorded.
    #[test]
    fn explicit_flags_win_over_the_recorded_unit() {
        let installed = Installed {
            unit: Some(RecordedServer {
                data: Some("/srv/old".into()),
                web_root: Some("/srv/oldweb".into()),
                relative: Vec::new(),
            }),
            system_data: None,
            system_unit: false,
        };
        let folders = resolve_server_init(
            Scope::User,
            Some(Path::new("/srv/new")),
            Some(Path::new("/srv/newweb")),
            &installed,
            &linux(),
        )
        .unwrap();
        assert_eq!(folders.data, PathBuf::from("/srv/new"));
        assert_eq!(folders.web_root, Some(PathBuf::from("/srv/newweb")));
    }

    /// Relative flag values are refused, and the error names the absolute path to use.
    #[test]
    fn relative_flags_are_refused_with_the_absolute_path_to_use() {
        let cwd = env::current_dir().unwrap();
        let none = Installed::default();
        let error =
            resolve_server_init(Scope::User, Some(Path::new("data")), None, &none, &linux())
                .unwrap_err()
                .to_string();
        assert!(
            error.contains(&format!("--data {}", cwd.join("data").display())),
            "{error}"
        );
        let error =
            resolve_server_init(Scope::User, None, Some(Path::new("./web")), &none, &linux())
                .unwrap_err()
                .to_string();
        assert!(error.contains("--web-root ./web is relative"), "{error}");
        assert!(
            error.contains(&format!("--web-root {}", cwd.join("./web").display())),
            "{error}"
        );
    }

    /// `--system` needs root unless it is a dry run; root without `--system` stays per user.
    #[test]
    fn system_scope_needs_root_except_for_a_dry_run() {
        let user = linux();
        let error = check_scope(Scope::System, false, &user).unwrap_err();
        assert!(error.to_string().contains("needs root"));
        check_scope(Scope::System, true, &user).unwrap();
        check_scope(Scope::User, false, &user).unwrap();
        let root = Environment {
            is_root: true,
            ..linux()
        };
        check_scope(Scope::System, false, &root).unwrap();
        check_scope(Scope::User, false, &root).unwrap();
    }

    /// New folders are created 0700; an existing folder keeps its mode.
    #[test]
    fn created_folders_are_private_and_existing_ones_keep_their_mode() {
        let root = scratch("mode");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let leaf = root.join("a/b");
        create_private_dir(&leaf).unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root.join("a")), 0o700);
        assert_eq!(mode(&leaf), 0o700);
        assert_eq!(mode(&root), 0o755);
        create_private_dir(&leaf).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A relative recorded folder is refused unless the flag is passed explicitly.
    #[test]
    fn a_relative_recorded_folder_is_refused_not_replaced() {
        let installed = Installed {
            unit: Some(RecordedServer {
                relative: vec![("--data".to_owned(), "state".into())],
                ..RecordedServer::default()
            }),
            ..Installed::default()
        };
        let error = resolve_server_init(Scope::User, None, None, &installed, &linux())
            .unwrap_err()
            .to_string();
        assert!(error.contains("relative --data state"), "{error}");
        assert!(error.contains("--force"), "{error}");
        resolve_server_init(
            Scope::User,
            Some(Path::new("/srv/new")),
            None,
            &installed,
            &linux(),
        )
        .unwrap();
    }

    /// Only root, without `--system`, with a system unit present gets the warning.
    #[test]
    fn root_without_system_beside_a_system_unit_is_warned() {
        let installed = Installed {
            system_unit: true,
            ..Installed::default()
        };
        let root = Environment {
            is_root: true,
            ..linux()
        };
        let text = root_user_scope_warning(Scope::User, &installed, &root).unwrap();
        assert!(
            text.contains("system-wide") && text.contains("--system"),
            "{text}"
        );
        assert!(root_user_scope_warning(Scope::System, &installed, &root).is_none());
        assert!(root_user_scope_warning(Scope::User, &installed, &linux()).is_none());
        assert!(root_user_scope_warning(Scope::User, &Installed::default(), &root).is_none());
    }

    /// The link lives at the D395 path for each platform and scope.
    #[test]
    fn the_path_link_follows_d395() {
        assert_eq!(
            path_link(Scope::User, &linux()).unwrap(),
            Some("/home/someone/.local/bin/infraternal".into())
        );
        assert_eq!(
            path_link(Scope::System, &linux()).unwrap(),
            Some("/usr/local/bin/infraternal".into())
        );
        assert_eq!(path_link(Scope::User, &macos()).unwrap(), None);
        assert_eq!(
            path_link(Scope::System, &macos()).unwrap(),
            Some("/usr/local/bin/infraternal".into())
        );
        let advice =
            link_for_install(Scope::User, Path::new("/Users/a/bin/infraternal"), &macos()).unwrap();
        assert_eq!(advice, LinkOutcome::PathAdvice("/Users/a/bin".into()));
        assert!(
            advice
                .describe(Path::new("x"))
                .contains("export PATH=\"/Users/a/bin:$PATH\"")
        );
    }

    /// Create, keep, re-point on update, and never overwrite anything foreign.
    #[test]
    fn the_link_is_created_repointed_and_never_overwrites_foreign_files() {
        let root = scratch("link");
        let releases = root.join("data/infraternal/bin");
        std::fs::create_dir_all(&releases).unwrap();
        let (old, new) = (
            releases.join("infraternal"),
            root.join("data/infraternal/new/infraternal"),
        );
        std::fs::create_dir_all(new.parent().unwrap()).unwrap();
        let link = root.join("bin/infraternal");
        assert_eq!(
            publish_link(&link, &old).unwrap(),
            LinkOutcome::Created(link.clone())
        );
        assert_eq!(
            publish_link(&link, &old).unwrap(),
            LinkOutcome::Current(link.clone())
        );
        assert_eq!(
            publish_link(&link, &new).unwrap(),
            LinkOutcome::Repointed(link.clone())
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), new);

        // A regular file and a link to another program are left exactly as found.
        let file = root.join("bin/other");
        std::fs::write(&file, "mine").unwrap();
        assert_eq!(
            publish_link(&file, &new).unwrap(),
            LinkOutcome::Foreign(file.clone())
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "mine");
        let foreign = root.join("bin/foreign");
        std::os::unix::fs::symlink("/usr/bin/true", &foreign).unwrap();
        assert_eq!(
            publish_link(&foreign, &new).unwrap(),
            LinkOutcome::Foreign(foreign.clone())
        );
        assert_eq!(
            std::fs::read_link(&foreign).unwrap(),
            Path::new("/usr/bin/true")
        );

        // Uninstall removes ours only.
        assert!(!remove_link(&foreign, &new).unwrap());
        assert!(!remove_link(&file, &new).unwrap());
        assert!(remove_link(&link, &new).unwrap());
        assert!(!link.exists() && std::fs::symlink_metadata(&link).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Uninstall removes only a link to exactly this binary, never one to another release (J719 P2).
    #[test]
    fn uninstall_removes_only_a_link_to_this_exact_binary() {
        let root = scratch("unlink");
        let ours = root.join("data/infraternal/bin/infraternal");
        let older = root.join("data/infraternal/old/infraternal");
        let checkout = root.join("src/infraternal/live");
        let link = root.join("bin/infraternal");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        for other in [&older, &checkout] {
            std::os::unix::fs::symlink(other, &link).unwrap();
            assert!(!remove_link(&link, &ours).unwrap(), "{}", other.display());
            assert_eq!(&std::fs::read_link(&link).unwrap(), other);
            std::fs::remove_file(&link).unwrap();
        }
        // Dangling but exact still counts as ours: the binary was removed first.
        std::os::unix::fs::symlink(&ours, &link).unwrap();
        assert!(remove_link(&link, &ours).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Relative targets are normalised (`..` too), and odd things at the link path are handled (J719 P3).
    #[test]
    fn relative_dangling_and_directory_links_are_judged_by_their_real_target() {
        let root = scratch("relink");
        let binary = root.join("data/infraternal/bin/infraternal");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, "elf").unwrap();
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let link = bin.join("infraternal");

        // A relative link through `..` to exactly this binary is current, and uninstall removes it.
        std::os::unix::fs::symlink("../data/infraternal/bin/../bin/infraternal", &link).unwrap();
        assert_eq!(
            publish_link(&link, &binary).unwrap(),
            LinkOutcome::Current(link.clone())
        );
        assert!(remove_link(&link, &binary).unwrap());

        // A relative link to an older release of ours is re-pointed.
        std::os::unix::fs::symlink("../data/infraternal/old/../old/infraternal", &link).unwrap();
        assert_eq!(
            publish_link(&link, &binary).unwrap(),
            LinkOutcome::Repointed(link.clone())
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), binary);
        std::fs::remove_file(&link).unwrap();

        // `..` that leaves the install folder is not ours, even if a name matches.
        std::os::unix::fs::symlink("../data/infraternal/../elsewhere/infraternal", &link).unwrap();
        assert_eq!(
            publish_link(&link, &binary).unwrap(),
            LinkOutcome::Foreign(link.clone())
        );
        std::fs::remove_file(&link).unwrap();

        // A dangling link of ours (its release was deleted) is re-pointed.
        std::os::unix::fs::symlink(root.join("data/infraternal/gone/infraternal"), &link).unwrap();
        assert_eq!(
            publish_link(&link, &binary).unwrap(),
            LinkOutcome::Repointed(link.clone())
        );
        std::fs::remove_file(&link).unwrap();

        // A dangling foreign link stays exactly as it was.
        std::os::unix::fs::symlink("/nonexistent/other-tool", &link).unwrap();
        assert_eq!(
            publish_link(&link, &binary).unwrap(),
            LinkOutcome::Foreign(link.clone())
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("/nonexistent/other-tool")
        );
        assert!(!remove_link(&link, &binary).unwrap());
        std::fs::remove_file(&link).unwrap();

        // A directory at the link path is foreign and survives publish and uninstall.
        std::fs::create_dir(&link).unwrap();
        assert_eq!(
            publish_link(&link, &binary).unwrap(),
            LinkOutcome::Foreign(link.clone())
        );
        assert!(!remove_link(&link, &binary).unwrap());
        assert!(link.is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }
}
