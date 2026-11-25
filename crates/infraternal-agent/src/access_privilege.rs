//! Ask the host whether an account could rewrite a root-owned access record.
//! A negative answer covers only the checks listed in this module. Unknown
//! results fail closed. Queries run in the access scan's blocking worker,
//! never the reactor.
//!
//! Out of scope (D367, follow-up #437): `pam_cap` grants from
//! `/etc/security/capability.conf`; subordinate-uid mappings, including a range
//! containing host uid 0; and host-wide setuid-root binary auditing. Direct
//! root-job scripts, unit files and their writable parents are checked, but
//! libraries, sourced files and arbitrary root executable-input graphs are not.
//! A negative result establishes none of those routes' absence. The report
//! names completed checks and explicitly says access outside them is uncovered.
#[cfg(not(target_vendor = "apple"))]
use std::ffi::CString;
use std::{io::Read, path::Path, process::Stdio, time::Duration};

use nix::unistd::{Group, Uid, User};
use tokio::io::AsyncReadExt as _;

/// Root-equivalent groups, including common administrative policy groups.
/// sudo, wheel and admin conventionally grant administrative commands; docker
/// can mount the host filesystem in a root container; lxd, incus and incus-admin can start
/// privileged containers with host mounts; libvirt can attach host disks to a
/// guest; disk grants raw host-disk writes. Membership is therefore enough to
/// distrust the account, even when sudo itself explicitly denies all commands.
const ROOT_GROUPS: &[&str] = &[
    "sudo",
    "wheel",
    "admin",
    "docker",
    "lxd",
    "incus",
    "incus-admin",
    "libvirt",
    "disk",
];

/// A sudo listing can contain arbitrarily large policy. Exceeding this bound
/// makes the result unknown, which is privileged, without logging its content.
const OUTPUT_BYTES: u64 = 64 * 1024;

/// A root route and its owner-facing name. The same registry executes policy
/// checks and supplies the completed-check evidence in a negative report.
struct RootCheck {
    /// Plain name displayed in the access report.
    name: &'static str,
    /// True means root authority is present or could not be ruled out.
    inspect: fn(&User, &crate::access_jobs::Observation) -> bool,
}

/// Known root routes, ordered to avoid subprocess work for obvious privilege.
/// Adding a route here also updates report evidence and server requirements.
const ROOT_CHECKS: &[RootCheck] = &[
    RootCheck {
        name: "container sockets",
        inspect: socket_route,
    },
    RootCheck {
        name: "root-run jobs",
        inspect: job_route,
    },
    RootCheck {
        name: "admin groups",
        inspect: root_group_or_unknown,
    },
    RootCheck {
        name: "doas",
        inspect: doas_route,
    },
    RootCheck {
        name: "polkit",
        inspect: polkit_route,
    },
    RootCheck {
        name: "sudo",
        inspect: sudo_route,
    },
];

/// Names of the registered checks. Only a completed negative inspection may
/// attach these as evidence; privileged or rootless reports carry no such claim.
pub(crate) fn check_names() -> Vec<String> {
    ROOT_CHECKS
        .iter()
        .map(|check| check.name.to_owned())
        .collect()
}

/// Query a trusted host tool from the scan's blocking worker. Both pipes and
/// child lifetime are bounded; callers treat missing or ambiguous output as
/// unknown. Host tools see only the system bus and a fixed C locale.
pub(crate) fn host_output(name: &str, args: &[&str]) -> Option<String> {
    let program = crate::logins::account_tool(name)?;
    let mut command = crate::sessions::isolated(&program);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command_output(command)
}

/// Collect a prepared isolated child's small stdout without unbounded pipe or
/// lifetime waits. A successful status and empty diagnostics are required.
pub(crate) fn command_output(mut command: tokio::process::Command) -> Option<String> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    runtime.block_on(async {
        let mut child = command.spawn().ok()?;
        let mut stdout = child.stdout.take()?.take(1024 * 1024 + 1);
        let mut stderr = child.stderr.take()?.take(OUTPUT_BYTES + 1);
        let query = async {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let (a, b, status) = tokio::join!(
                stdout.read_to_end(&mut out),
                stderr.read_to_end(&mut err),
                child.wait()
            );
            match (a, b, status) {
                (Ok(_), Ok(_), Ok(status))
                    if status.success() && err.is_empty() && out.len() <= 1024 * 1024 =>
                {
                    String::from_utf8(out).ok()
                }
                _ => None,
            }
        };
        tokio::time::timeout(Duration::from_secs(5), query)
            .await
            .ok()
            .flatten()
    })
}

/// Inspect the host doas configuration from the registry's account callback.
fn doas_route(_account: &User, _jobs: &crate::access_jobs::Observation) -> bool {
    doas_allows_or_unknown(Path::new("/etc/doas.conf"))
}

/// Run sudo's bounded asynchronous query from the scan's blocking worker.
fn sudo_route(account: &User, _jobs: &crate::access_jobs::Observation) -> bool {
    tokio::runtime::Handle::try_current().map_or(true, |runtime| {
        runtime.block_on(sudo_allows_or_unknown(&account.name))
    })
}

/// Recognize only sudo's explicit C-locale denial with no diagnostics. Some
/// hosts return zero for this denial, others one; every other status or output
/// is unknown or permits a command, and therefore cannot prove lack of power.
fn sudo_denied(user: &str, status: Option<i32>, stdout: &[u8], stderr: &[u8]) -> bool {
    if !matches!(status, Some(0 | 1)) || !stderr.is_empty() {
        return false;
    }
    let Ok(output) = std::str::from_utf8(stdout) else {
        return false;
    };
    let prefix = format!("User {user} is not allowed to run sudo on ");
    output
        .strip_prefix(&prefix)
        .and_then(|host| host.strip_suffix(".\n"))
        .is_some_and(|host| {
            !host.is_empty()
                && host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        })
}

/// Query sudo as real host root, without a password prompt or inherited locale.
/// Both pipes and the entire child lifetime are bounded. Isolated children do
/// not inherit the daemon's control sockets or credentials through descriptors.
async fn sudo_allows_or_unknown(user: &str) -> bool {
    let Some(sudo) = crate::logins::account_tool("sudo") else {
        return true;
    };
    let mut command = crate::sessions::isolated(&sudo);
    command
        .args(["-n", "-l", "-U", user])
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let Ok(mut child) = command.spawn() else {
        return true;
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return true;
    };
    let mut stdout = stdout.take(OUTPUT_BYTES + 1);
    let mut stderr = stderr.take(OUTPUT_BYTES + 1);
    let query = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (out_result, err_result, status) = tokio::join!(
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err),
            child.wait(),
        );
        match (out_result, err_result, status) {
            (Ok(_), Ok(_), Ok(status)) if out.len() as u64 <= OUTPUT_BYTES => {
                !sudo_denied(user, status.code(), &out, &err)
            }
            _ => true,
        }
    };
    tokio::time::timeout(Duration::from_secs(5), query)
        .await
        .unwrap_or(true)
}

/// An absent top-level doas file grants nothing. Read bounded include trees;
/// empty protected children are harmless, active rules and unknown syntax are
/// privileged. This does not duplicate doas's account/command policy engine.
fn doas_allows_or_unknown(path: &Path) -> bool {
    doas_policy(
        path,
        true,
        0,
        &mut usize::try_from(OUTPUT_BYTES).unwrap_or(0),
        &mut std::collections::BTreeSet::new(),
    )
}

/// No symlink following, writable ancestors, include cycles or unbounded input.
/// Only simple include directives and comments can prove policy harmless.
fn doas_policy(
    path: &Path,
    absent_ok: bool,
    depth: usize,
    remaining: &mut usize,
    seen: &mut std::collections::BTreeSet<std::path::PathBuf>,
) -> bool {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    if depth > 8 || seen.len() >= 32 || !seen.insert(path.to_owned()) {
        return true;
    }
    let file = match std::fs::File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if absent_ok && error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    for parent in path.ancestors().skip(1) {
        let Ok(meta) = std::fs::symlink_metadata(parent) else {
            return true;
        };
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return true;
        }
    }
    let Ok(meta) = file.metadata() else {
        return true;
    };
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return true;
    }
    let mut text = String::new();
    if file
        .take((*remaining as u64) + 1)
        .read_to_string(&mut text)
        .is_err()
        || text.len() > *remaining
    {
        return true;
    }
    *remaining -= text.len();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some(include) = line
            .strip_prefix("include ")
            .or_else(|| line.strip_prefix(".include "))
        else {
            return true;
        };
        let include = include.trim();
        let include = if include.starts_with('"') {
            include.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
        } else if include.starts_with('\'') {
            include
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
        } else {
            (!include.chars().any(char::is_whitespace)).then_some(include)
        };
        let Some(include) = include.filter(|s| !s.is_empty() && !s.contains('\\')) else {
            return true;
        };
        let include = Path::new(include);
        if include
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return true;
        }
        let include = if include.is_absolute() {
            include.to_owned()
        } else {
            path.parent().unwrap_or(Path::new("/")).join(include)
        };
        if doas_policy(&include, false, depth + 1, remaining, seen) {
            return true;
        }
    }
    false
}

/// Ask NSS for all account groups, including its primary and supplementary
/// memberships. Missing named groups are harmless; failed lookups are unknown.
fn root_group_or_unknown(account: &User, _jobs: &crate::access_jobs::Observation) -> bool {
    let Some(groups) = account_groups(account) else {
        return true;
    };
    ROOT_GROUPS.iter().any(|name| match Group::from_name(name) {
        Ok(Some(group)) => groups.contains(&group.gid),
        Ok(None) => false,
        Err(_) => true,
    })
}

/// Resolve the complete account group list once before a credential drop.
/// Missing NSS membership is unknown, never an empty group list.
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn account_groups(account: &User) -> Option<Vec<nix::unistd::Gid>> {
    let mut sources = String::new();
    std::fs::File::open("/etc/nsswitch.conf")
        .ok()?
        .take(16385)
        .read_to_string(&mut sources)
        .ok()?;
    if sources.len() > 16384 || !membership_sources_complete(&sources) {
        return None;
    }
    let name = CString::new(account.name.as_bytes()).ok()?;
    nix::unistd::getgrouplist(&name, account.gid).ok()
}

/// macOS keeps group membership in Directory Services, and the `nix` crate has no
/// `getgrouplist` there, so the answer is unknown: callers already treat unknown as
/// the cautious result (#355, D367).
#[cfg(target_vendor = "apple")]
pub(crate) fn account_groups(_account: &User) -> Option<Vec<nix::unistd::Gid>> {
    None
}

/// Use the already completed job inventory, rather than scan host units twice.
fn job_route(_account: &User, jobs: &crate::access_jobs::Observation) -> bool {
    jobs.privileged || !jobs.complete
}

/// Inspect current policy through the registry's common context signature.
fn polkit_route(account: &User, _jobs: &crate::access_jobs::Observation) -> bool {
    crate::access_polkit::privileged(account)
}

/// NSS may return a successful partial list when SSSD/LDAP is unavailable.
/// No portable health query proves a remote initgroups response complete, so
/// any network/unknown provider stays unknown even when local lookup succeeds.
#[cfg(any(not(target_vendor = "apple"), test))]
fn membership_sources_complete(text: &str) -> bool {
    let mut passwd = false;
    let mut group = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some((database, sources)) = line.split_once(':') else {
            continue;
        };
        if !matches!(database.trim(), "passwd" | "group" | "initgroups") {
            continue;
        }
        let mut any = false;
        for source in sources.split_ascii_whitespace() {
            if source.starts_with('[') && source.ends_with(']') {
                continue;
            }
            if !matches!(source, "files" | "systemd") {
                return false;
            }
            any = true;
        }
        if !any {
            return false;
        }
        passwd |= database.trim() == "passwd";
        group |= database.trim() == "group";
    }
    passwd && group
}

/// Probe root container endpoints, irrespective of their group name or ACL.
/// Non-sockets and unavailable permission/group information are unknown.
fn socket_allows_or_unknown(path: &Path, account: &User) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    if !metadata.file_type().is_socket() {
        return true;
    }
    crate::access_write::writable(account, &[path.to_owned()])
        .is_none_or(|indices| !indices.is_empty())
}

/// Default root daemon endpoints; /var/run aliases are checked too. Custom
/// group ownership and named-user ACLs are evaluated by the kernel, not labels.
fn socket_route(account: &User, _jobs: &crate::access_jobs::Observation) -> bool {
    [
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
    ]
    .iter()
    .any(|path| socket_allows_or_unknown(Path::new(path), account))
}

/// Whether root authority is present or cannot be ruled out. Call only from
/// the access scan's blocking worker with a Tokio runtime available. Rootless
/// reports already have their own unverified outcome and never call this.
pub(crate) fn privileged(account: &User, jobs: &crate::access_jobs::Observation) -> bool {
    if account.uid.is_root() || !Uid::effective().is_root() {
        return true;
    }
    ROOT_CHECKS
        .iter()
        .any(|check| (check.inspect)(account, jobs))
}

#[cfg(test)]
mod tests {
    //! Policy output must prove denial rather than merely lack a known grant.
    use super::*;

    /// Retire this fixture directory even when a red assertion unwinds.
    struct RemoveOnDrop(std::path::PathBuf);
    impl Drop for RemoveOnDrop {
        /// Cleanup is best effort during an assertion's panic.
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// incus-admin can administer host containers just as incus can.
    #[test]
    fn incus_administrators_are_root_equivalent() {
        assert!(ROOT_GROUPS.contains(&"incus-admin"));
    }

    /// NSS can return a partial local list while a directory provider is down.
    #[test]
    fn remote_group_membership_is_not_proven_by_local_nss_success() {
        assert!(membership_sources_complete(
            "passwd: files systemd\ngroup: files systemd\n"
        ));
        for source in ["sss", "ldap", "winbind", "nis", "compat"] {
            assert!(!membership_sources_complete(&format!(
                "passwd: files\ngroup: files {source}\n"
            )));
        }
    }

    /// Includes must be read, not treated as a grant merely by their presence.
    #[test]
    #[ignore = "requires real root and protected test policy ownership"]
    fn doas_includes_are_read_and_unknown_children_fail_closed() {
        assert!(Uid::effective().is_root());
        let root = nix::unistd::mkdtemp("/root/rvdoas-XXXXXX").unwrap();
        let _cleanup = RemoveOnDrop(root.clone());
        let top = root.join("doas.conf");
        let child = root.join("included.conf");
        std::fs::write(&top, format!("include {}\n", child.display())).unwrap();
        std::fs::write(&child, "# no grants\n").unwrap();
        assert!(!doas_allows_or_unknown(&top));
        std::fs::write(&child, "permit nobody as root\n").unwrap();
        assert!(doas_allows_or_unknown(&top));
        std::fs::remove_file(child).unwrap();
        assert!(doas_allows_or_unknown(&top));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A custom group, not a conventional name, can control a root socket.
    #[test]
    #[ignore = "requires real root and a local ordinary account"]
    fn custom_socket_group_is_privileged() {
        use std::os::unix::{fs::PermissionsExt as _, net::UnixListener};
        assert!(Uid::effective().is_root());
        let user = User::from_name("nobody").unwrap().unwrap();
        let root = nix::unistd::mkdtemp("/tmp/rvsock-XXXXXX").unwrap();
        let _cleanup = RemoveOnDrop(root.clone());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.join("socket");
        let _socket = UnixListener::bind(&path).unwrap();
        nix::unistd::chown(&path, Some(Uid::from_raw(0)), Some(user.gid)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let result = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                tokio::task::spawn_blocking(move || socket_allows_or_unknown(&path, &user))
                    .await
                    .unwrap()
            });
        std::fs::remove_dir_all(root).unwrap();
        assert!(result);
        assert!(check_names().contains(&"container sockets".to_owned()));
    }

    /// Explicit denial is portable across the two observed exit conventions.
    #[test]
    fn only_explicit_sudo_denial_is_unprivileged() {
        let denied = b"User alice is not allowed to run sudo on host.example.\n";
        for status in [Some(0), Some(1)] {
            assert!(sudo_denied("alice", status, denied, b""));
        }
        for output in [
            &b""[..],
            &b"User alice may run the following commands on host:\n    (ALL) NOPASSWD: ALL\n"[..],
            &b"User alice may run the following commands on host:\n    (root) /usr/bin/id\n"[..],
            &b"User bob is not allowed to run sudo on host.\n"[..],
            &b"User alice is not allowed to run sudo on host.\nextra\n"[..],
        ] {
            assert!(!sudo_denied("alice", Some(0), output, b""));
        }
        assert!(!sudo_denied("alice", Some(2), denied, b""));
        assert!(!sudo_denied("alice", None, denied, b""));
        assert!(!sudo_denied("alice", Some(0), denied, b"policy error"));
    }

    /// Config errors and active doas rules cannot turn into a clean report.
    #[test]
    fn unknown_doas_policy_is_privileged() {
        let root = nix::unistd::mkdtemp("/tmp/rvd-XXXXXX").unwrap();
        let policy = root.join("doas.conf");
        assert!(!doas_allows_or_unknown(&policy));
        std::fs::write(&policy, "permit alice as root\n").unwrap();
        assert!(doas_allows_or_unknown(&policy));
        std::fs::remove_file(&policy).unwrap();
        std::fs::create_dir(&policy).unwrap();
        assert!(doas_allows_or_unknown(&policy));
        std::fs::remove_dir_all(root).unwrap();
    }
}
