//! Resolves the dedicated system account the rootful Traefik child runs as [#281].
//!
//! The account `infraternal-proxy` and its private group are created once with the host's own
//! account tools, so the IDs come from the distribution's system range and are recorded in
//! `/etc/passwd` and `/etc/group`. A fixed, conventional ID (such as the 65532 `nonroot` user of
//! container images) could be shared with an unrelated workload, which could then trace or signal
//! Traefik and read its credential files. So the identity is refused when:
//!
//! - it is root, or another passwd entry has the same UID;
//! - another group entry has the same GID, or the account's primary group isn't its own group;
//! - any running process other than this agent's own children uses the UID or GID.
//!
//! The process check repeats before every child start. A full file-system scan for files already
//! owned by the IDs is deliberately not done: it costs seconds to minutes on a large host, while
//! IDs allocated fresh by the account tools have no prior files.

use std::{fs, io, process::Command, sync::OnceLock};

/// Name of the dedicated account and its private group.
pub(crate) const PROXY_ACCOUNT: &str = "infraternal-proxy";

static PROXY_IDS: OnceLock<(u32, u32)> = OnceLock::new();
// Serializes first-use creation within this process; another process may still race us,
// which `proxy_ids` resolves by looking the account up again.
static CREATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether the caller can switch to and hand files to a separate proxy account.
#[must_use]
pub(crate) fn rootful() -> bool {
    if !nix::unistd::Uid::effective().is_root() {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        // Root in a user namespace that maps only a few IDs can't switch to or chown files for
        // an account allocated from the host's system range, so it runs rootless.
        maps_system_range("/proc/self/uid_map") && maps_system_range("/proc/self/gid_map")
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Child identity: the dedicated account when rootful, the caller's identity otherwise.
///
/// # Errors
/// Returns an error when the account can't be created or collides with another identity.
pub(crate) fn child_ids() -> io::Result<(u32, u32)> {
    if rootful() {
        proxy_ids()
    } else {
        Ok((
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
        ))
    }
}

/// Group shared by the agent's child-readable files and the child.
///
/// # Errors
/// Returns the same errors as [`child_ids`].
pub(crate) fn child_group() -> io::Result<u32> {
    child_ids().map(|(_, group)| group)
}

/// Refuse to start a rootful child while anything else runs as the proxy account.
///
/// # Errors
/// Returns `PermissionDenied` naming the collision, or a `/proc` read error.
pub(crate) fn verify_unshared() -> io::Result<()> {
    if !rootful() {
        return Ok(());
    }
    let (user, group) = proxy_ids()?;
    let own = std::process::id();
    for entry in fs::read_dir("/proc")? {
        let Some(pid) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own {
            continue;
        }
        // A process can exit between listing and reading; that is not a collision.
        let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        // Our own children run as the account by design; nothing else can become our child.
        if status_parent(&status) == Some(own) {
            continue;
        }
        if status_uses_ids(&status, user, group) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "another process runs as the proxy account; refusing to share its identity",
            ));
        }
    }
    Ok(())
}

fn proxy_ids() -> io::Result<(u32, u32)> {
    if let Some(ids) = PROXY_IDS.get() {
        return Ok(*ids);
    }
    let _creation = CREATION
        .lock()
        .map_err(|_| io::Error::other("proxy account creation is unavailable"))?;
    let ids = if let Some(ids) = lookup()? {
        ids
    } else {
        let created = create_account();
        // A concurrent creator (another agent process) may have won; its account is as good.
        match (lookup()?, created) {
            (Some(ids), _) => ids,
            (None, Err(error)) => return Err(error),
            (None, Ok(())) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "proxy account was not created",
                ));
            }
        }
    };
    let passwd = fs::read_to_string("/etc/passwd")?;
    let groups = fs::read_to_string("/etc/group")?;
    check_unique(&passwd, &groups, ids.0, ids.1)?;
    Ok(*PROXY_IDS.get_or_init(|| ids))
}

fn lookup() -> io::Result<Option<(u32, u32)>> {
    let user = nix::unistd::User::from_name(PROXY_ACCOUNT).map_err(io::Error::from)?;
    let group = nix::unistd::Group::from_name(PROXY_ACCOUNT).map_err(io::Error::from)?;
    match (user, group) {
        (Some(user), Some(group)) => {
            if user.gid != group.gid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "proxy account's primary group is not its own group",
                ));
            }
            Ok(Some((user.uid.as_raw(), group.gid.as_raw())))
        }
        (None, None) => Ok(None),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy account and group exist only partly; refusing to guess",
        )),
    }
}

// The host's own tools allocate an unused ID from its system range and record it.
fn create_account() -> io::Result<()> {
    let nologin = ["/usr/sbin/nologin", "/sbin/nologin"]
        .into_iter()
        .find(|path| fs::metadata(path).is_ok())
        .unwrap_or("/bin/false");
    let run = |program: &str, args: &[&str]| -> io::Result<bool> {
        if fs::metadata(program).is_err() {
            return Ok(false);
        }
        let status = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if status.success() {
            Ok(true)
        } else {
            Err(io::Error::other("creating the proxy account failed"))
        }
    };
    for useradd in ["/usr/sbin/useradd", "/sbin/useradd"] {
        let args = [
            "--system",
            "--user-group",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            nologin,
            PROXY_ACCOUNT,
        ];
        if run(useradd, &args)? {
            return Ok(());
        }
    }
    // BusyBox systems (Alpine) ship adduser/addgroup instead.
    for (addgroup, adduser) in [
        ("/usr/sbin/addgroup", "/usr/sbin/adduser"),
        ("/bin/addgroup", "/bin/adduser"),
    ] {
        if run(addgroup, &["-S", PROXY_ACCOUNT])? {
            let args = [
                "-S",
                "-D",
                "-H",
                "-h",
                "/nonexistent",
                "-s",
                nologin,
                "-G",
                PROXY_ACCOUNT,
                PROXY_ACCOUNT,
            ];
            if run(adduser, &args)? {
                return Ok(());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no account tool is available to create the proxy account",
    ))
}

fn check_unique(passwd: &str, groups: &str, user: u32, group: u32) -> io::Result<()> {
    let ids = |database: &str, field: usize| -> Vec<(String, u32)> {
        database
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let fields: Vec<_> = line.split(':').collect();
                Some((
                    fields.first()?.to_string(),
                    fields.get(field)?.parse().ok()?,
                ))
            })
            .collect()
    };
    let shares = |entries: Vec<(String, u32)>, id: u32| {
        entries
            .iter()
            .any(|(name, entry)| *entry == id && name != PROXY_ACCOUNT)
    };
    if user == 0 || group == 0 || shares(ids(passwd, 2), user) || shares(ids(groups, 2), group) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the proxy account's ID is shared with another account or group",
        ));
    }
    Ok(())
}

fn status_parent(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse().ok())
}

fn status_uses_ids(status: &str, user: u32, group: u32) -> bool {
    status.lines().any(|line| {
        let (field, wanted) = match line.split_once(':') {
            Some(("Uid", values)) => (values, user),
            Some(("Gid" | "Groups", values)) => (values, group),
            _ => return false,
        };
        field
            .split_whitespace()
            .any(|value| value.parse::<u32>() == Ok(wanted))
    })
}

#[cfg(target_os = "linux")]
fn maps_system_range(path: &str) -> bool {
    // Every ID an account tool may allocate lies below 65536.
    fs::read_to_string(path).is_ok_and(|mapping| {
        mapping.lines().any(|line| {
            let mut fields = line.split_whitespace().map(str::parse::<u64>);
            matches!(
                (fields.next(), fields.next(), fields.next()),
                (Some(Ok(0)), Some(Ok(_)), Some(Ok(length))) if length >= 65_536
            )
        })
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "The user namespace subprocess is required to exercise this identity boundary."
    )]

    use super::*;

    #[test]
    fn a_proxy_id_shared_with_another_account_or_group_is_refused() {
        let passwd = "root:x:0:0::/root:/bin/sh\ninfraternal-proxy:x:998:998::/nonexistent:/usr/sbin/nologin\n";
        let groups = "root:x:0:\ninfraternal-proxy:x:998:\n";
        check_unique(passwd, groups, 998, 998).expect("a dedicated identity");
        let nonroot = format!("{passwd}nonroot:x:998:65532::/home/nonroot:/bin/sh\n");
        assert!(check_unique(&nonroot, groups, 998, 998).is_err());
        let shared_group = format!("{groups}docker:x:998:\n");
        assert!(check_unique(passwd, &shared_group, 998, 998).is_err());
        assert!(check_unique(passwd, groups, 0, 998).is_err());
    }

    #[test]
    fn a_process_running_with_the_proxy_ids_is_a_collision() {
        let status = |uid: &str, gid: &str, groups: &str| {
            format!("Name:\tsleep\nUid:\t{uid}\nGid:\t{gid}\nGroups:\t{groups}\n")
        };
        assert!(!status_uses_ids(
            &status("1000 1000 1000 1000", "1000 1000 1000 1000", "27 1000"),
            998,
            998
        ));
        assert!(status_uses_ids(
            &status("1000 998 1000 1000", "1000 1000 1000 1000", ""),
            998,
            998
        ));
        assert!(status_uses_ids(
            &status("1000 1000 1000 1000", "1000 1000 1000 1000", "27 998"),
            998,
            998
        ));
    }

    #[test]
    fn the_agents_own_children_are_not_a_collision() {
        assert_eq!(
            status_parent("Name:\tsleep\nPPid:\t4242\nUid:\t998\t998\t998\t998\n"),
            Some(4242)
        );
        assert_eq!(status_parent("Name:\tsleep\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_rootful_child_runs_as_the_dedicated_account() {
        if !rootful() {
            return;
        }
        let (user, group) = child_ids().expect("resolve the proxy account");
        let account = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(user))
            .expect("read account database")
            .expect("account exists");
        assert_eq!(account.name, PROXY_ACCOUNT);
        assert_eq!(account.gid.as_raw(), group);
        assert_ne!(user, 65_532, "not the shared conventional container ID");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn user_namespace_root_without_a_system_id_range_is_rootless() {
        const PROBE: &str = "INFRATERNAL_PROXY_IDENTITY_USERNS_PROBE";
        if std::env::var_os(PROBE).is_some() {
            assert!(nix::unistd::Uid::effective().is_root());
            assert!(!super::rootful());
            return;
        }

        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--fork"])
            .arg(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "identity::tests::user_namespace_root_without_a_system_id_range_is_rootless",
                "--nocapture",
            ])
            .env(PROBE, "1")
            .status()
            .expect("start user namespace identity probe");
        assert!(
            status.success(),
            "user namespace identity probe failed: {status}"
        );
    }
}
