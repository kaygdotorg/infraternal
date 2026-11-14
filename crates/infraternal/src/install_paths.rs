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
//! path that already exists:
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
//! # Existing installs are never moved here
//!
//! The new defaults apply only to a fresh install. [`resolve_server_init`] keeps
//! the folders recorded in the unit it would overwrite, so re-running init
//! leaves the unit byte-for-byte unchanged and never orphans a custom folder.
//! Moving old locations is the updater's job (D395, "moved on the next update").
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
}

impl Environment {
    /// Read the real process environment, the effective user and the running binary's location.
    #[must_use]
    pub fn detect() -> Self {
        Self::from_lookup(
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
        )
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
pub fn check_scope(scope: Scope, dry_run: bool, environment: &Environment) -> Result<(), PathError> {
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
        (Os::Linux, Scope::System) => Ok(PathBuf::from("/var/lib/infraternal")),
        (Os::Linux, Scope::User) => Ok(match &environment.xdg_state_home {
            Some(state) => state.join("infraternal"),
            None => environment
                .absolute_home()?
                .join(".local/state/infraternal"),
        }),
        (Os::MacOs, Scope::System) => {
            Ok(PathBuf::from("/Library/Application Support/infraternal"))
        }
        (Os::MacOs, Scope::User) => Ok(environment
            .absolute_home()?
            .join("Library/Application Support/infraternal")),
    }
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
                |name| (name == "HOME").then_some(home.map(OsString::from)).flatten(),
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
            }),
            system_data: Some("/srv/elsewhere".into()),
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
            }),
            system_data: None,
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
}
