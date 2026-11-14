//! Where an install keeps its files, following each operating system's standard [D395, #516].
//!
//! Every path here is absolute and is derived only from the environment values in
//! [`Environment`], never from the current directory: a service is installed once and
//! must find the same folders forever. Only `server init` uses this module today; a
//! follow-up moves the agents onto it, so keep it small and free of install logic.
//!
//! Layout for the server's state and database:
//! - Linux, per user: `$XDG_STATE_HOME/infraternal/server`, else
//!   `~/.local/state/infraternal/server`.
//! - Linux, system-wide: `/var/lib/infraternal` (D229, D395).
//! - macOS, per user: `~/Library/Application Support/infraternal/server`.
//! - macOS, system-wide: `/Library/Application Support/infraternal/server`.

use std::{
    env,
    path::{Path, PathBuf},
};

/// Why a folder could not be chosen; the text says which flag to pass instead.
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

/// The facts the defaults come from, as plain values so tests never read the real environment.
#[derive(Debug, Clone)]
pub struct Environment {
    /// Which convention to follow.
    pub os: Os,
    /// `$XDG_STATE_HOME`, when set (Linux only).
    pub xdg_state_home: Option<PathBuf>,
    /// `$HOME`, when set.
    pub home: Option<PathBuf>,
    /// The folder holding the running binary, where a release bundle keeps `web/`.
    pub binary_dir: Option<PathBuf>,
}

impl Environment {
    /// Read the real process environment and the running binary's location.
    #[must_use]
    pub fn detect() -> Self {
        Self {
            os: if cfg!(target_os = "macos") {
                Os::MacOs
            } else {
                Os::Linux
            },
            xdg_state_home: env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            home: env::var_os("HOME").map(PathBuf::from),
            binary_dir: env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_owned)),
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

/// The server's default state and database folder for this scope and operating system.
///
/// A relative or empty `$XDG_STATE_HOME` is ignored, as the XDG specification requires.
pub fn server_state_dir(scope: Scope, environment: &Environment) -> Result<PathBuf, PathError> {
    match (environment.os, scope) {
        (Os::Linux, Scope::System) => Ok(PathBuf::from("/var/lib/infraternal")),
        (Os::Linux, Scope::User) => {
            let base = match &environment.xdg_state_home {
                Some(path) if path.is_absolute() => path.clone(),
                _ => environment.absolute_home()?.join(".local/state"),
            };
            Ok(base.join("infraternal/server"))
        }
        (Os::MacOs, Scope::System) => Ok(PathBuf::from(
            "/Library/Application Support/infraternal/server",
        )),
        (Os::MacOs, Scope::User) => Ok(environment
            .absolute_home()?
            .join("Library/Application Support/infraternal/server")),
    }
}

/// The release bundle's `web/` folder beside the running binary, when it exists.
pub fn bundled_web_root(environment: &Environment) -> Result<PathBuf, PathError> {
    environment
        .binary_dir
        .as_ref()
        .map(|dir| dir.join("web"))
        .filter(|dir| dir.is_dir())
        .ok_or_else(|| {
            PathError(
                "no web/ folder beside the infraternal binary; pass --web-root <absolute path>"
                    .to_owned(),
            )
        })
}

/// Resolve `server init`'s data and web folders, as absolute paths.
///
/// An explicit `--data` or `--web-root` must itself be absolute. A relative one is
/// REFUSED rather than resolved against the cwd: the unit would silently freeze
/// whichever directory the shell was in, and refusing costs one retry with a full
/// path. Printing the cwd-resolved path was rejected because an unattended `--yes`
/// run never reads it.
pub fn resolve_server_init(
    scope: Scope,
    data: Option<&Path>,
    web_root: Option<&Path>,
    environment: &Environment,
) -> Result<(PathBuf, PathBuf), PathError> {
    let data = match explicit_absolute("--data", data)? {
        Some(path) => path,
        None => server_state_dir(scope, environment)?,
    };
    let web_root = match explicit_absolute("--web-root", web_root)? {
        Some(path) => path,
        None => bundled_web_root(environment)?,
    };
    Ok((data, web_root))
}

/// Pass an explicit absolute flag value through; refuse a relative one.
fn explicit_absolute(flag: &str, value: Option<&Path>) -> Result<Option<PathBuf>, PathError> {
    match value {
        None => Ok(None),
        Some(path) if path.is_absolute() => Ok(Some(path.to_owned())),
        Some(path) => Err(PathError(format!(
            "{flag} {} is relative; pass an absolute path so the service does not depend on the current directory",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    //! One test per default, so each rule has its own failure.

    use super::*;

    /// A Linux environment whose binary sits in `dir`.
    fn linux(dir: &Path) -> Environment {
        Environment {
            os: Os::Linux,
            xdg_state_home: None,
            home: Some(PathBuf::from("/home/someone")),
            binary_dir: Some(dir.to_owned()),
        }
    }

    /// A temporary release bundle that contains a `web/` folder.
    fn bundle() -> PathBuf {
        let dir = env::temp_dir().join(format!("init-bundle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("web")).unwrap();
        dir
    }

    /// Without `XDG_STATE_HOME`, user state goes under `~/.local/state`.
    #[test]
    fn linux_user_state_defaults_under_home_when_xdg_is_unset() {
        let dir = bundle();
        let (data, _) = resolve_server_init(Scope::User, None, None, &linux(&dir)).unwrap();
        assert_eq!(
            data,
            PathBuf::from("/home/someone/.local/state/infraternal/server")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An absolute `XDG_STATE_HOME` is honoured; a relative one is ignored.
    #[test]
    fn linux_user_state_follows_an_absolute_xdg_state_home_only() {
        let dir = bundle();
        let mut env = linux(&dir);
        env.xdg_state_home = Some(PathBuf::from("/srv/xdg"));
        let (data, _) = resolve_server_init(Scope::User, None, None, &env).unwrap();
        assert_eq!(data, PathBuf::from("/srv/xdg/infraternal/server"));
        env.xdg_state_home = Some(PathBuf::from("relative"));
        let (data, _) = resolve_server_init(Scope::User, None, None, &env).unwrap();
        assert!(data.starts_with("/home/someone/.local/state"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// System state stays at the documented service folder (D229).
    #[test]
    fn linux_system_state_is_the_documented_service_folder() {
        let dir = bundle();
        let (data, _) = resolve_server_init(Scope::System, None, None, &linux(&dir)).unwrap();
        assert_eq!(data, PathBuf::from("/var/lib/infraternal"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// macOS state lives under Application Support, per user and system-wide.
    #[test]
    fn macos_state_lives_under_application_support() {
        let dir = bundle();
        let mut env = linux(&dir);
        env.os = Os::MacOs;
        let (user, _) = resolve_server_init(Scope::User, None, None, &env).unwrap();
        assert_eq!(
            user,
            PathBuf::from("/home/someone/Library/Application Support/infraternal/server")
        );
        let (system, _) = resolve_server_init(Scope::System, None, None, &env).unwrap();
        assert_eq!(
            system,
            PathBuf::from("/Library/Application Support/infraternal/server")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// No usable home means a refusal that names `--data`.
    #[test]
    fn missing_or_relative_home_is_refused_for_user_state() {
        let dir = bundle();
        let mut env = linux(&dir);
        env.home = Some(PathBuf::from("rel"));
        let error = resolve_server_init(Scope::User, None, None, &env).unwrap_err();
        assert!(error.to_string().contains("--data"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The web root defaults to `web/` beside the binary.
    #[test]
    fn web_root_defaults_to_the_folder_beside_the_binary() {
        let dir = bundle();
        let (_, web) = resolve_server_init(Scope::User, None, None, &linux(&dir)).unwrap();
        assert_eq!(web, dir.join("web"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Without a bundled `web/`, init refuses and names `--web-root`.
    #[test]
    fn missing_bundle_web_folder_is_refused_with_the_flag_to_use() {
        let dir = env::temp_dir().join(format!("init-empty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let error = resolve_server_init(Scope::User, None, None, &linux(&dir)).unwrap_err();
        assert!(error.to_string().contains("--web-root"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Relative flag values are refused, never resolved against the cwd.
    #[test]
    fn relative_data_and_web_root_are_refused_not_resolved_against_the_cwd() {
        let dir = bundle();
        let env = linux(&dir);
        let error =
            resolve_server_init(Scope::User, Some(Path::new("data")), None, &env).unwrap_err();
        assert!(error.to_string().contains("--data data is relative"));
        let error =
            resolve_server_init(Scope::User, None, Some(Path::new("./web")), &env).unwrap_err();
        assert!(error.to_string().contains("--web-root ./web is relative"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
