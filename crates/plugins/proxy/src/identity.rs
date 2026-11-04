//! Resolves the dedicated system account the rootful Traefik child runs as [#281].
//!
//! The account `infraternal-proxy` and its private group share one ID, chosen by us from
//! [`PROXY_ID_RANGE`] and handed explicitly to the host's account tools, which record it in
//! `/etc/passwd` and `/etc/group`. Those entries are the record of the choice.
//!
//! The account tools' own system allocation is never used: it takes the highest free ID at or
//! below `SYS_UID_MAX`, which is 999 on a stock host. Common container images (postgres, redis
//! and many others) also run as 999, and without a user namespace their processes and
//! bind-mounted files have that host UID. A conventional fixed ID such as the 65532 `nonroot` user
//! has the same problem. The range sits where no convention allocates: above `login.defs`'
//! `UID_MAX` (60000) and systemd-homed's 60001–60513, below systemd's dynamic users (61184+), and
//! below the 65536 boundary that subordinate ID ranges usually start beyond.
//!
//! A candidate ID is free when no passwd entry has it as UID or primary GID, no group has it, no
//! `/etc/subuid` or `/etc/subgid` range covers it, and no running process uses it. The resolved
//! identity is refused when:
//!
//! - it is outside the range, root, or its UID and GID differ (an account left by an older build
//!   or created by hand is not adopted);
//! - another passwd entry has the same UID or uses the GID as its primary group;
//! - another group entry has the same GID, or the group lists members;
//! - any running process other than this agent's own children uses the UID or GID.
//!
//! The process check repeats before every child start. Files are not scanned: a full file-system
//! walk costs seconds to minutes on a large host. So the range choice lowers, but cannot rule out,
//! the chance that some file on the host is already owned by the ID.

use std::{fs, io, ops::RangeInclusive, process::Command, sync::OnceLock};

/// Name of the dedicated account and its private group.
pub(crate) const PROXY_ACCOUNT: &str = "infraternal-proxy";

/// IDs the dedicated account may take; the lowest free one is chosen. See the module doc.
pub(crate) const PROXY_ID_RANGE: RangeInclusive<u32> = 60_514..=60_999;

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
        // an account in the proxy range, so it runs rootless.
        maps_proxy_range("/proc/self/uid_map") && maps_proxy_range("/proc/self/gid_map")
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
        let id = choose_id(&IdDatabases::read()?, &ids_in_use()?, &SystemDirectory)?;
        let created = create_account(id);
        // A concurrent creator (another agent process) may have won; its account is as good,
        // and it passes the same checks below.
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
    check_in_range(ids.0, ids.1)?;
    let databases = IdDatabases::read()?;
    check_unique(
        &databases.passwd,
        &databases.groups,
        ids.0,
        ids.1,
        &SystemDirectory,
    )?;
    Ok(*PROXY_IDS.get_or_init(|| ids))
}

/// The account databases an ID choice consults. Missing subordinate ID files mean no ranges.
struct IdDatabases {
    passwd: String,
    groups: String,
    subuid: String,
    subgid: String,
}

impl IdDatabases {
    fn read() -> io::Result<Self> {
        let optional = |path: &str| match fs::read_to_string(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            other => other,
        };
        Ok(Self {
            passwd: fs::read_to_string("/etc/passwd")?,
            groups: fs::read_to_string("/etc/group")?,
            subuid: optional("/etc/subuid")?,
            subgid: optional("/etc/subgid")?,
        })
    }
}

/// The system's user and group lookup (NSS), which also answers for accounts that live in a
/// directory service (LDAP, SSSD) and so never appear in `/etc/passwd` or `/etc/group`.
trait Directory {
    /// The name of the user with this UID, if any. An error means the lookup could not answer.
    fn user(&self, uid: u32) -> io::Result<Option<String>>;
    /// The name of the group with this GID, if any.
    fn group(&self, gid: u32) -> io::Result<Option<String>>;
}

struct SystemDirectory;

impl Directory for SystemDirectory {
    fn user(&self, uid: u32) -> io::Result<Option<String>> {
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .map(|user| user.map(|user| user.name))
            .map_err(io::Error::from)
    }

    fn group(&self, gid: u32) -> io::Result<Option<String>> {
        nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
            .map(|group| group.map(|group| group.name))
            .map_err(io::Error::from)
    }
}

/// The lowest ID in the range that no account, group, subordinate range or process uses.
///
/// The files are read directly for the primary-group and subordinate ranges that lookups do not
/// expose; the `directory` lookup adds accounts the files do not list. A lookup that fails
/// counts as taken: an ID is never given away on a guess.
fn choose_id(
    databases: &IdDatabases,
    in_use: &std::collections::BTreeSet<u32>,
    directory: &dyn Directory,
) -> io::Result<u32> {
    let taken = |id: u32| {
        // passwd: UID (field 2) and primary GID (field 3); group: GID (field 2).
        field_ids(&databases.passwd, 2).any(|(_, entry)| entry == id)
            || field_ids(&databases.passwd, 3).any(|(_, entry)| entry == id)
            || field_ids(&databases.groups, 2).any(|(_, entry)| entry == id)
            || subordinate_covers(&databases.subuid, id)
            || subordinate_covers(&databases.subgid, id)
            || in_use.contains(&id)
            || directory.user(id).map_or(true, |name| name.is_some())
            || directory.group(id).map_or(true, |name| name.is_some())
    };
    PROXY_ID_RANGE
        .clone()
        .find(|id| !taken(*id))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "no free ID for the {PROXY_ACCOUNT} account in {}-{}; free one in that range",
                    PROXY_ID_RANGE.start(),
                    PROXY_ID_RANGE.end()
                ),
            )
        })
}

fn check_in_range(user: u32, group: u32) -> io::Result<()> {
    if user == group && PROXY_ID_RANGE.contains(&user) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "the {PROXY_ACCOUNT} account has UID {user} and GID {group}, outside the reserved range \
             {}-{}; remove the account and its group so infraternal can recreate it",
            PROXY_ID_RANGE.start(),
            PROXY_ID_RANGE.end()
        ),
    ))
}

/// Every UID and GID (real, effective, saved, file system, supplementary) of running processes.
fn ids_in_use() -> io::Result<std::collections::BTreeSet<u32>> {
    let mut ids = std::collections::BTreeSet::new();
    for entry in fs::read_dir("/proc")? {
        let name = entry?.file_name();
        if name
            .to_str()
            .is_none_or(|name| name.parse::<u32>().is_err())
        {
            continue;
        }
        // A process can exit between listing and reading.
        let Ok(status) = fs::read_to_string(format!("/proc/{}/status", name.to_string_lossy()))
        else {
            continue;
        };
        for line in status.lines() {
            if let Some(("Uid" | "Gid" | "Groups", values)) = line.split_once(':') {
                ids.extend(
                    values
                        .split_whitespace()
                        .filter_map(|value| value.parse::<u32>().ok()),
                );
            }
        }
    }
    Ok(ids)
}

// `name:start:count` lines; a malformed line covers nothing.
fn subordinate_covers(ranges: &str, id: u32) -> bool {
    ranges.lines().any(|line| {
        let mut fields = line.split(':').skip(1).map(str::parse::<u64>);
        matches!(
            (fields.next(), fields.next()),
            (Some(Ok(start)), Some(Ok(count))) if (start..start.saturating_add(count)).contains(&u64::from(id))
        )
    })
}

fn field_ids(database: &str, field: usize) -> impl Iterator<Item = (&str, u32)> {
    database
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(move |line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            Some((name, fields.nth(field - 1)?.parse().ok()?))
        })
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

// The host's own tools record the account with the ID we chose; they never pick one.
fn create_account(id: u32) -> io::Result<()> {
    let id = id.to_string();
    let id = id.as_str();
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
    // The group is created first so the account can name it; a failed account creation removes
    // the group again, leaving no half-created identity behind.
    for (groupadd, useradd, groupdel) in [
        (
            "/usr/sbin/groupadd",
            "/usr/sbin/useradd",
            "/usr/sbin/groupdel",
        ),
        ("/sbin/groupadd", "/sbin/useradd", "/sbin/groupdel"),
    ] {
        if run(groupadd, &["--system", "--gid", id, PROXY_ACCOUNT])? {
            let args = [
                "--system",
                "--uid",
                id,
                "--gid",
                id,
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                nologin,
                PROXY_ACCOUNT,
            ];
            if matches!(run(useradd, &args), Ok(true)) {
                return Ok(());
            }
            let _ = run(groupdel, &[PROXY_ACCOUNT]);
            return Err(io::Error::other("creating the proxy account failed"));
        }
    }
    // BusyBox systems (Alpine) ship adduser/addgroup instead.
    for (addgroup, adduser, delgroup) in [
        (
            "/usr/sbin/addgroup",
            "/usr/sbin/adduser",
            "/usr/sbin/delgroup",
        ),
        ("/bin/addgroup", "/bin/adduser", "/bin/delgroup"),
    ] {
        if run(addgroup, &["-S", "-g", id, PROXY_ACCOUNT])? {
            let args = [
                "-S",
                "-D",
                "-H",
                "-u",
                id,
                "-h",
                "/nonexistent",
                "-s",
                nologin,
                "-G",
                PROXY_ACCOUNT,
                PROXY_ACCOUNT,
            ];
            if matches!(run(adduser, &args), Ok(true)) {
                return Ok(());
            }
            let _ = run(delgroup, &[PROXY_ACCOUNT]);
            return Err(io::Error::other("creating the proxy account failed"));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no account tool is available to create the proxy account",
    ))
}

fn check_unique(
    passwd: &str,
    groups: &str,
    user: u32,
    group: u32,
    directory: &dyn Directory,
) -> io::Result<()> {
    fn shares<'a>(mut entries: impl Iterator<Item = (&'a str, u32)>, id: u32) -> bool {
        entries.any(|(name, entry)| entry == id && name != PROXY_ACCOUNT)
    }
    // The name the system resolves for our IDs must be ours alone, also when the other owner
    // is in a directory service. A failed lookup refuses.
    let foreign = |name: io::Result<Option<String>>| {
        name.map_or(true, |name| name.is_some_and(|name| name != PROXY_ACCOUNT))
    };
    if foreign(directory.user(user)) || foreign(directory.group(group)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the proxy account's ID is shared with an account or group of the system's user directory",
        ));
    }
    // Another member, by list or by primary group, could traverse the 0750 proxy directory and
    // read its 0640 config.
    let has_members = groups
        .lines()
        .filter(|line| line.split(':').next() == Some(PROXY_ACCOUNT))
        .any(|line| {
            line.split(':')
                .nth(3)
                .is_some_and(|members| !members.trim().is_empty())
        });
    if user == 0
        || group == 0
        || shares(field_ids(passwd, 2), user)
        || shares(field_ids(passwd, 3), group)
        || shares(field_ids(groups, 2), group)
        || has_members
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the proxy account's ID is shared with another account or group, or its group has members",
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
fn maps_proxy_range(path: &str) -> bool {
    // One mapping from 0 must reach the top of the proxy range, so root can both stay root and
    // switch to any ID the account may have.
    let needed = u64::from(*PROXY_ID_RANGE.end()) + 1;
    fs::read_to_string(path).is_ok_and(|mapping| {
        mapping.lines().any(|line| {
            let mut fields = line.split_whitespace().map(str::parse::<u64>);
            matches!(
                (fields.next(), fields.next(), fields.next()),
                (Some(Ok(0)), Some(Ok(_)), Some(Ok(length))) if length >= needed
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

    /// A fake lookup: the listed IDs belong to directory-service accounts and groups.
    #[derive(Default)]
    struct FakeDirectory {
        users: Vec<(u32, &'static str)>,
        groups: Vec<(u32, &'static str)>,
        broken: bool,
    }

    impl Directory for FakeDirectory {
        fn user(&self, uid: u32) -> io::Result<Option<String>> {
            if self.broken {
                return Err(io::Error::other("directory unreachable"));
            }
            Ok(self
                .users
                .iter()
                .find(|(id, _)| *id == uid)
                .map(|(_, n)| (*n).to_owned()))
        }

        fn group(&self, gid: u32) -> io::Result<Option<String>> {
            if self.broken {
                return Err(io::Error::other("directory unreachable"));
            }
            Ok(self
                .groups
                .iter()
                .find(|(id, _)| *id == gid)
                .map(|(_, n)| (*n).to_owned()))
        }
    }

    #[test]
    fn ids_held_by_a_directory_service_are_never_chosen_or_shared() {
        let databases = IdDatabases {
            passwd: String::new(),
            groups: String::new(),
            subuid: String::new(),
            subgid: String::new(),
        };
        let none = std::collections::BTreeSet::new();
        let directory = FakeDirectory {
            users: vec![(60_514, "ldap-alice")],
            groups: vec![(60_515, "ldap-staff")],
            broken: false,
        };
        assert_eq!(
            choose_id(&databases, &none, &directory).expect("a free ID"),
            60_516,
            "a UID or a GID known only to the directory is skipped"
        );
        let unreachable = FakeDirectory {
            broken: true,
            ..FakeDirectory::default()
        };
        assert!(
            choose_id(&databases, &none, &unreachable).is_err(),
            "a lookup that cannot answer never hands out an ID"
        );

        let passwd = "infraternal-proxy:x:60514:60514::/nonexistent:/usr/sbin/nologin\n";
        let groups = "infraternal-proxy:x:60514:\n";
        let ours = FakeDirectory {
            users: vec![(60_514, PROXY_ACCOUNT)],
            groups: vec![(60_514, PROXY_ACCOUNT)],
            broken: false,
        };
        check_unique(passwd, groups, 60_514, 60_514, &ours).expect("our own account is fine");
        assert!(check_unique(passwd, groups, 60_514, 60_514, &directory).is_err());
        let shared_group = FakeDirectory {
            groups: vec![(60_514, "ldap-staff")],
            ..FakeDirectory::default()
        };
        assert!(check_unique(passwd, groups, 60_514, 60_514, &shared_group).is_err());
        assert!(check_unique(passwd, groups, 60_514, 60_514, &unreachable).is_err());
    }

    #[test]
    fn a_proxy_id_shared_with_another_account_or_group_is_refused() {
        let passwd = "root:x:0:0::/root:/bin/sh\ninfraternal-proxy:x:60514:60514::/nonexistent:/usr/sbin/nologin\n";
        let groups = "root:x:0:\ninfraternal-proxy:x:60514:\n";
        check_unique(passwd, groups, 60_514, 60_514, &FakeDirectory::default())
            .expect("a dedicated identity");
        let nonroot = format!("{passwd}nonroot:x:60514:65532::/home/nonroot:/bin/sh\n");
        assert!(check_unique(&nonroot, groups, 60_514, 60_514, &FakeDirectory::default()).is_err());
        let shared_group = format!("{groups}docker:x:60514:\n");
        assert!(
            check_unique(
                passwd,
                &shared_group,
                60_514,
                60_514,
                &FakeDirectory::default()
            )
            .is_err()
        );
        assert!(check_unique(passwd, groups, 0, 60_514, &FakeDirectory::default()).is_err());
    }

    #[test]
    fn a_proxy_group_that_other_users_belong_to_is_refused() {
        let passwd = "infraternal-proxy:x:60514:60514::/nonexistent:/usr/sbin/nologin\n";
        let groups = "infraternal-proxy:x:60514:\n";
        let listed = "infraternal-proxy:x:60514:alice\n";
        assert!(
            check_unique(passwd, listed, 60_514, 60_514, &FakeDirectory::default()).is_err(),
            "a listed member could read the proxy's group-readable config"
        );
        let primary = format!("{passwd}alice:x:1000:60514::/home/alice:/bin/sh\n");
        assert!(
            check_unique(&primary, groups, 60_514, 60_514, &FakeDirectory::default()).is_err(),
            "a user whose primary group is the proxy group is a member too"
        );
    }

    #[test]
    fn the_proxy_id_is_chosen_from_its_range_past_every_used_id() {
        let databases = IdDatabases {
            // 999 is where the account tools' own system allocation lands.
            passwd: "postgres:x:999:999::/var/lib/postgresql:/bin/sh\n\
                     taken:x:60514:100::/:/bin/sh\nprimary:x:1001:60515::/:/bin/sh\n"
                .to_owned(),
            groups: "postgres:x:999:\ntaken:x:60516:\n".to_owned(),
            subuid: "alice:60517:1\nmalformed\n".to_owned(),
            subgid: "alice:60518:1\n".to_owned(),
        };
        let processes = [999, 60_519].into_iter().collect();
        assert_eq!(
            choose_id(&databases, &processes, &FakeDirectory::default()).expect("a free ID"),
            60_520
        );

        let full = PROXY_ID_RANGE.collect();
        let error = choose_id(&databases, &full, &FakeDirectory::default())
            .expect_err("an exhausted range is refused");
        assert!(error.to_string().contains("60514-60999"), "{error}");
    }

    #[test]
    fn an_account_outside_the_proxy_range_is_not_adopted() {
        check_in_range(60_514, 60_514).expect("an ID from the range");
        for (user, group) in [(999, 999), (999, 987), (60_514, 60_515), (65_532, 65_532)] {
            let error = check_in_range(user, group).expect_err("not adopted");
            assert!(error.to_string().contains("remove the account"), "{error}");
        }
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
        assert!(
            PROXY_ID_RANGE.contains(&user) && user == group,
            "the account takes one ID from the reserved range, never the account tools' \
             system allocation (999 on a stock host, shared with container images): {user}:{group}"
        );
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
