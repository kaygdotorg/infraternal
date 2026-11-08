//! Ask the host whether an account could rewrite a root-owned access record.
//! A negative answer covers only the checks listed in this module. Unknown
//! results fail closed. Queries run in the access scan's blocking worker,
//! never the reactor.
//!
//! Out of scope (J357 P3, owner 2026-11-08): `pam_cap` grants from
//! `/etc/security/capability.conf`; root-run scripts owned by the account;
//! and group-writable root paths. These require a capabilities audit or tracing
//! root's executable inputs, file ownership, ACLs and writable path components
//! across the host. This detector does neither, and a negative answer does not
//! establish their absence. The report names the routes actually checked.
use std::{ffi::CString, io::Read, path::Path, process::Stdio, time::Duration};

use nix::unistd::{Group, Uid, User};
use tokio::io::AsyncReadExt as _;

/// Root-equivalent groups, including common administrative policy groups.
/// sudo, wheel and admin conventionally grant administrative commands; docker
/// can mount the host filesystem in a root container; lxd and incus can start
/// privileged containers with host mounts; libvirt can attach host disks to a
/// guest; disk grants raw host-disk writes. Membership is therefore enough to
/// distrust the account, even when sudo itself explicitly denies all commands.
const ROOT_GROUPS: &[&str] = &[
    "sudo", "wheel", "admin", "docker", "lxd", "incus", "libvirt", "disk",
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

/// An absent or protected empty/comment-only doas file grants nothing. Active
/// policy is conservatively privileged: proving its account, group, include
/// and command semantics would require duplicating the host policy engine.
/// Unreadable, oversized, symlinked or writable policy is unknown as well.
fn doas_allows_or_unknown(path: &Path) -> bool {
    use std::os::unix::{fs::MetadataExt as _, fs::OpenOptionsExt as _};
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    let Ok(metadata) = file.metadata() else {
        return true;
    };
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return true;
    }
    let mut text = String::new();
    if file
        .take(OUTPUT_BYTES + 1)
        .read_to_string(&mut text)
        .is_err()
        || text.len() as u64 > OUTPUT_BYTES
    {
        return true;
    }
    text.lines()
        .any(|line| !line.split('#').next().unwrap_or_default().trim().is_empty())
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
pub(crate) fn account_groups(account: &User) -> Option<Vec<nix::unistd::Gid>> {
    let name = CString::new(account.name.as_bytes()).ok()?;
    nix::unistd::getgrouplist(&name, account.gid).ok()
}

/// Use the already completed job inventory, rather than scan host units twice.
fn job_route(_account: &User, jobs: &crate::access_jobs::Observation) -> bool {
    jobs.privileged || !jobs.complete
}

/// Inspect current policy through the registry's common context signature.
fn polkit_route(account: &User, _jobs: &crate::access_jobs::Observation) -> bool {
    crate::access_polkit::privileged(account)
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
