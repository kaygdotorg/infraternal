//! What a person may have left behind on a host account (D356, #355).
//!
//! A person with a shell on a host account can leave their own way back in:
//! an SSH key in `~/.ssh/authorized_keys`, a crontab or `at` job, a systemd
//! user unit or drop-in, an XDG autostart entry, or a line in a shell startup
//! file. A revoke ends their processes (D353) but does not, and must not,
//! touch those files: restoring them could undo legitimate changes by the
//! host owner or by other people on the account.
//!
//! So when a person first gets a login on an account (the grant), the agent
//! records each access file's kind, mode, owner, size, a SHA-256 of its whole
//! content (streamed), the target text of a symbolic link, and, for small
//! files only, a hash of each line. Never the lines themselves: the record
//! holds no secrets. On revoke it looks again and reports, per account, one
//! of three outcomes: checked and unchanged, changed (with each changed file
//! and, when small enough, its new lines), or not checked with the reason.
//! It never says "unchanged" for something it did not check.
//!
//! Where the record lives decides what it is worth. A remote agent keeps it
//! beside its identity in its private, persistent data directory (an
//! installed root agent's is under `/var/lib/infraternal`, root-only), one
//! directory per account, and the accounts to report are found there, so a
//! reboot that empties `/run` loses nothing. Rootless, the agent runs as the account the
//! person had a shell on (D18), so the person could have rewritten the
//! record: those reports are always "not checked: unverified", with what was
//! found shown as a hint, never as a clean result.
//!
//! The reads are hostile-input safe and bounded. Home files are opened
//! beneath the home one component at a time with `O_NOFOLLOW`; a symlink is
//! recorded by its target text and never followed, and a target inside the
//! home is checked as its own entry, opened the same way. Only regular files
//! owned by the account are read. One file is in memory at a time; hashing
//! stops at a per-file and a per-account byte budget, and the number of
//! entries per account is capped. Anything left out sets `truncated` and is
//! named in `unscanned`; nothing is dropped silently. The report goes only
//! into the revoke result, never into a log.
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
    unistd::User,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::{self, Read as _},
    os::{fd::OwnedFd, unix::fs::MetadataExt as _},
    path::{Component, Path, PathBuf},
};

/// Entries (files, links, spool jobs) checked per account; past it the rest
/// is named in `unscanned`.
const ENTRIES: usize = 256;
/// Names read from one directory; a larger directory is not scanned at all
/// (its listing order is arbitrary, so a part of it would not compare).
const DIRECTORY_NAMES: usize = 1024;
/// Bytes hashed of one file; a larger file is hashed up to here, with its size.
const HASH_BYTES: u64 = 8 * 1024 * 1024;
/// Bytes hashed per account across all files.
const ACCOUNT_HASH_BYTES: u64 = 128 * 1024 * 1024;
/// Files up to this size keep line hashes, so their new lines can be shown.
const LINE_FILE_BYTES: u64 = 64 * 1024;
/// Line hashes kept per file.
const FILE_LINES: usize = 2048;
/// Line hashes kept per record.
const RECORD_LINES: usize = 16 * 1024;
/// Largest record written or read.
const RECORD_BYTES: usize = 2 * 1024 * 1024;
/// Changed lines reported per revocation, across all accounts and files.
const REPORTED_LINES: usize = 64;
/// Characters of one reported line before it is cut in the middle.
const LINE_CHARS: usize = 200;
/// Accounts whose files are scanned per revocation; any excess is counted.
const ACCOUNTS: usize = 64;
/// Bytes read from one spool file or command.
const SPOOL_BYTES: usize = 256 * 1024;
/// Not-scanned names kept per account (the count past it still truncates).
const UNSCANNED_NAMES: usize = 32;

/// Directories visited per account (each costs a walk from the home).
const DIRECTORIES: usize = 256;
/// Links followed lexically inside the home to resolve one path.
const LINK_HOPS: usize = 8;

/// What a watched place is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Watch {
    /// One file.
    File,
    /// A directory's entries.
    Directory,
    /// A systemd user unit directory: its entries, and the `*.wants`,
    /// `*.requires`, `*.upholds` and drop-in `*.d` directories systemd reads.
    Units,
    /// The host's crontab for the account.
    Spools,
    /// An atd spool directory; only this account's regular jobs are read.
    AtSpool,
    /// Effective SSH key sources, resolved for this account by sshd.
    Sshd,
}

/// One place the agent watches for a way back into an account.
#[derive(Debug)]
pub(crate) struct Watched {
    /// What kind of access it gives, in plain words; reports list these
    /// (D360: "the 214 places we watch (SSH keys, cron, …)").
    pub(crate) category: &'static str,
    /// Its path under the home (or a name, for the spools).
    pub(crate) path: &'static str,
    /// How it is scanned.
    pub(crate) watch: Watch,
}

/// The categories of [`WATCHED`], each once, in table order: what a report
/// names as watched (D360).
pub(crate) fn categories() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for place in WATCHED {
        if !out.iter().any(|known| known == place.category) {
            out.push(place.category.to_owned());
        }
    }
    out
}

/// How many places this agent watches; a report covering fewer comes from
/// an older agent, and the server never vouches for it.
pub const WATCHED_PLACES: usize = WATCHED.len();

/// Names of the root routes the current detector checks. This is registry
/// metadata, not an inspection: a host attaches it only after every check
/// completed negatively. The server uses it to reject missing check evidence.
#[must_use]
pub fn root_check_names() -> Vec<String> {
    crate::access_privilege::check_names()
}

/// Every place D356 watches, in scan order: what admits a login first, then
/// what runs without one, then what runs at a login. A report covers
/// `WATCHED.len()` places; a place not in this table is not watched, and
/// the owner is told how many places were.
pub(crate) const WATCHED: &[Watched] = &[
    Watched {
        category: "SSH keys",
        path: ".ssh/authorized_keys",
        watch: Watch::File,
    },
    Watched {
        category: "SSH keys",
        path: ".ssh/authorized_keys2",
        watch: Watch::File,
    },
    Watched {
        category: "cron and at jobs",
        path: "crontab",
        watch: Watch::Spools,
    },
    Watched {
        category: "user services",
        path: ".config/systemd/user",
        watch: Watch::Units,
    },
    Watched {
        category: "user services",
        path: ".local/share/systemd/user",
        watch: Watch::Units,
    },
    Watched {
        category: "user services",
        path: ".config/environment.d",
        watch: Watch::Directory,
    },
    Watched {
        category: "SSH settings",
        path: ".ssh/rc",
        watch: Watch::File,
    },
    Watched {
        category: "SSH settings",
        path: ".ssh/config",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".bashrc",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".bash_profile",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".bash_login",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".bash_logout",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".bash_aliases",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".profile",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".zshrc",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".zprofile",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".zshenv",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".zlogin",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".config/fish/config.fish",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".config/fish/conf.d",
        watch: Watch::Directory,
    },
    Watched {
        category: "desktop autostart",
        path: ".config/autostart",
        watch: Watch::Directory,
    },
    Watched {
        category: "programs on PATH",
        path: ".local/bin",
        watch: Watch::Directory,
    },
    Watched {
        category: "programs on PATH",
        path: "bin",
        watch: Watch::Directory,
    },
    Watched {
        category: "user services",
        path: ".config/systemd/user.conf",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".config/fish/functions",
        watch: Watch::Directory,
    },
    Watched {
        category: "shell startup files",
        path: ".zlogout",
        watch: Watch::File,
    },
    Watched {
        category: "shell startup files",
        path: ".bashrc.d",
        watch: Watch::Directory,
    },
    Watched {
        category: "cron and at jobs",
        path: "/var/spool/cron/atjobs",
        watch: Watch::AtSpool,
    },
    Watched {
        category: "cron and at jobs",
        path: "/var/spool/at",
        watch: Watch::AtSpool,
    },
    Watched {
        category: "SSH keys",
        path: "sshd effective configuration",
        watch: Watch::Sshd,
    },
];

/// What one access file was, at the grant or now. Never its content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    /// `file`, `link`, `other` (not a regular file), `foreign` (not owned by
    /// the account, not read), or `error`.
    kind: String,
    /// Permission bits.
    #[serde(default)]
    mode: u32,
    /// Owning uid.
    #[serde(default)]
    owner: u32,
    /// Size in bytes, for regular files.
    #[serde(default)]
    size: u64,
    /// Hex SHA-256 of the content, of its first `HASH_BYTES` for a larger file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    /// A symbolic link's target text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    /// Short hashes of each non-blank line, for small files only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lines: Option<Vec<String>>,
    /// Why it was not fully hashed, or the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    /// For a file larger than `HASH_BYTES` only: its inode and change time
    /// (`ino:seconds.nanoseconds`). The hash covers only the file's start,
    /// so a same-size edit past it would otherwise compare equal (J1013).
    /// The account cannot set a change time: any write, rename over or
    /// metadata change moves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changed: Option<String>,
}

impl Entry {
    /// Whether `self` and `now` describe the same file; line hashes follow
    /// from the content hash and are not compared.
    fn same(&self, now: &Self) -> bool {
        (
            &self.kind,
            self.mode,
            self.owner,
            self.size,
            &self.sha256,
            &self.target,
            &self.note,
            &self.changed,
        ) == (
            &now.kind,
            now.mode,
            now.owner,
            now.size,
            &now.sha256,
            &now.target,
            &now.note,
            &now.changed,
        )
    }
}

/// An account's access files at the grant, keyed by display path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    /// The account's name at the grant.
    account: String,
    /// Each access file, by display path.
    entries: BTreeMap<String, Entry>,
    /// Something was left out at the grant.
    #[serde(default)]
    truncated: bool,
    /// What was not scanned at the grant.
    #[serde(default)]
    unscanned: Vec<String>,
    /// When it was taken (seconds since the epoch); 0 for older records.
    #[serde(default)]
    recorded_at: u64,
}

/// The outcome for one account, or for the whole revocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Checked; nothing changed since the grant.
    #[default]
    Unchanged,
    /// Checked; these files changed.
    Changed,
    /// Not checked, for `reason`.
    NotChecked,
}

/// Why an account was not checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No record from the grant (granted before D356, or the record is gone).
    RecordMissing,
    /// A rootless agent runs as the account itself (D18): the person could
    /// have changed the record, so nothing found can be vouched for.
    RootlessUnverified,
    /// The account is root or may become root (sudo, wheel, admin): it can
    /// rewrite the record and plant anywhere (J334 P1-4).
    Privileged,
    /// Something was not scanned, at the grant or now (J334 P1-1).
    Incomplete,
    /// The account's programs may still run after the revoke and can change
    /// its files later (D353, J334 P2-1).
    ProgramsMayRemain,
    /// Recording the grant failed, so no later login may set the baseline.
    RecordFailed,
}

/// Whether a reported file is new or was there at the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Not there at the grant.
    Added,
    /// There at the grant, different now.
    Changed,
    /// There at the grant, gone now (J334 P2-3).
    Removed,
}

/// One changed access file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Where, as the person revoking would look for it (`~/.ssh/authorized_keys`).
    pub path: String,
    /// Whether it is new or was there at the grant.
    pub change: ChangeKind,
    /// Its new lines, when the file is small enough to show them.
    pub lines: Vec<String>,
    /// What changed that lines cannot show (a link's target, a mode, a size).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The outcome for one host account. Each flag is an independent fact the
/// outcome rule reads, so they stay separate fields.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountReport {
    /// The account's name.
    pub account: String,
    /// Checked and unchanged, changed, or not checked.
    pub state: State,
    /// Why it was not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// The changed files.
    pub files: Vec<Change>,
    /// Something was left out: see `unscanned` and `omitted_files`.
    pub truncated: bool,
    /// Directories and files not scanned, at the grant or now.
    #[serde(default)]
    pub unscanned: Vec<String>,
    /// Changed files not listed because the reply had no room for them.
    #[serde(default)]
    pub omitted_files: usize,
    /// Every place watched was scanned, at the grant and now.
    #[serde(default)]
    pub complete: bool,
    /// How many rows of [`WATCHED`] this report covers (its coverage).
    #[serde(default)]
    pub watched: usize,
    /// Entries observed (files, links and spool jobs), for diagnostics.
    /// The coverage sentence uses `watched`, including absent places.
    #[serde(default)]
    pub places: usize,
    /// The categories watched, in plain words (D360).
    #[serde(default)]
    pub categories: Vec<String>,
    /// Root routes actually ruled out by this scan, from the check registry.
    /// Empty for privileged, rootless and historical reports without evidence.
    #[serde(default)]
    pub root_checks: Vec<String>,
    /// Root, or may become root.
    #[serde(default)]
    pub privileged: bool,
    /// Other people still have access to the account (D353).
    #[serde(default)]
    pub shared: bool,
    /// The account's programs may still be running after the revoke.
    #[serde(default)]
    pub programs_may_remain: bool,
    /// PIDs and printable kernel command names still running, bounded to 64 entries.
    #[serde(default)]
    pub processes: Vec<String>,
    /// System jobs that may write later, or whose root authority is unknown.
    #[serde(default)]
    pub jobs: Vec<String>,
    /// When the grant was recorded (seconds since the epoch; 0 if unknown).
    #[serde(default)]
    pub recorded_at: u64,
    /// When the account was scanned for this report.
    #[serde(default)]
    pub scanned_at: u64,
}

impl AccountReport {
    /// An account that could not be checked, for `reason`.
    fn not_checked(account: String, reason: Reason) -> Self {
        Self {
            account,
            state: State::NotChecked,
            reason: Some(reason),
            files: Vec::new(),
            truncated: false,
            unscanned: Vec::new(),
            omitted_files: 0,
            complete: false,
            watched: 0,
            places: 0,
            categories: Vec::new(),
            root_checks: Vec::new(),
            privileged: false,
            shared: false,
            programs_may_remain: false,
            processes: Vec::new(),
            jobs: Vec::new(),
            recorded_at: 0,
            scanned_at: now(),
        }
    }

    /// The one rule for an account's outcome (the server applies the same
    /// rule again and has the last word). Root authority always requires
    /// `not_checked: privileged`, including when changed files are listed.
    /// Remaining programs otherwise require
    /// `not_checked` even when changed files are listed (D362).
    /// Otherwise `unchanged` holds only when the scan was complete over every
    /// watched place, the account cannot rewrite its record (not rootless,
    /// not privileged), and nothing of the person's may still run; anything
    /// else is `not_checked` with the first reason that applies.
    pub(crate) fn decide(&mut self, rootless: bool) {
        self.programs_may_remain |= !self.processes.is_empty() || !self.jobs.is_empty();
        let own = self
            .reason
            .filter(|reason| matches!(reason, Reason::RecordMissing | Reason::RecordFailed));
        let reason = if rootless {
            Some(Reason::RootlessUnverified)
        } else if own.is_some() {
            // No record to compare with: that, not "incomplete", is why.
            own
        } else if self.recorded_at == 0 {
            Some(Reason::RecordMissing)
        } else if self.privileged {
            Some(Reason::Privileged)
        } else if !self.complete
            || self.truncated
            || self.omitted_files > 0
            || !self.unscanned.is_empty()
            || self.watched < WATCHED.len()
        {
            Some(Reason::Incomplete)
        } else if self.programs_may_remain {
            Some(Reason::ProgramsMayRemain)
        } else {
            self.reason
                .filter(|reason| matches!(reason, Reason::RecordMissing | Reason::RecordFailed))
        };
        if !rootless && self.privileged {
            self.state = State::NotChecked;
            self.reason = Some(Reason::Privileged);
        } else if !rootless && self.programs_may_remain {
            self.state = State::NotChecked;
            self.reason = Some(Reason::ProgramsMayRemain);
        } else if !self.files.is_empty() || self.omitted_files > 0 {
            self.state = if rootless || self.recorded_at == 0 {
                State::NotChecked
            } else {
                State::Changed
            };
            self.reason = reason.filter(|_| rootless || self.recorded_at == 0);
        } else if let Some(reason) = reason {
            self.state = State::NotChecked;
            self.reason = Some(reason);
        } else {
            self.state = State::Unchanged;
            self.reason = None;
        }
    }
}

/// Seconds since the epoch, 0 if the clock is before it.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What a revocation found, per account, with the overall outcome.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    /// Changed if any account changed; otherwise not checked if any account
    /// was not checked (or there was no record at all); otherwise unchanged.
    pub state: State,
    /// Why, when not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Each account the person had a grant or a login on.
    pub accounts: Vec<AccountReport>,
    /// Accounts beyond the bounded list, preserved even when text is trimmed.
    #[serde(default)]
    pub omitted_accounts: usize,
}

impl Access {
    /// The overall outcome of `accounts`; no account at all is "not checked:
    /// no record", never "unchanged".
    fn of(accounts: Vec<AccountReport>) -> Self {
        let unchecked = accounts
            .iter()
            .find(|account| account.state == State::NotChecked)
            .map(|account| account.reason);
        let (state, reason) = if accounts.iter().any(|a| a.state == State::Changed) {
            (State::Changed, None)
        } else if let Some(reason) = unchecked {
            (State::NotChecked, reason)
        } else if accounts.is_empty() {
            (State::NotChecked, Some(Reason::RecordMissing))
        } else {
            (State::Unchanged, None)
        };
        Self {
            state,
            reason,
            accounts,
            omitted_accounts: 0,
        }
    }
}

/// Extra sources outside the home (crontab, `at` jobs), handed one at a time
/// to the visitor as display path and bounded content. Production reads the
/// host's spools.
pub(crate) type Extra = dyn Fn(&User, &mut dyn FnMut(String, io::Result<Vec<u8>>));

/// One observed entry, with its content when it is small enough to show.
type Visit<'a> = dyn FnMut(String, Entry, Option<&[u8]>) + 'a;

/// How a scan ended: what was left out, and how many watched places it
/// went through.
struct Ended {
    /// Something was left out.
    truncated: bool,
    /// What was left out.
    unscanned: Vec<String>,
    /// Watched places gone through.
    watched: usize,
    /// Entries observed (files, links and spool jobs), separate from coverage.
    places: usize,
}

/// A walk over one account's access files, in the order of [`WATCHED`],
/// bounded in entries, directories and bytes.
struct Scan<'a> {
    /// The account being walked.
    account: &'a User,
    /// Its home, opened without following a link; `None` if it could not be.
    home: Option<OwnedFd>,
    /// Entries taken from the budget so far.
    entries: usize,
    /// Directories visited so far.
    directories: usize,
    /// Bytes hashed so far.
    hashed: u64,
    /// Something was left out.
    truncated: bool,
    /// What was left out.
    unscanned: Vec<String>,
    /// Link targets inside the home, checked as their own entries at the end.
    targets: BTreeSet<PathBuf>,
    /// Display paths already handed out.
    seen: BTreeSet<String>,
}

impl<'a> Scan<'a> {
    /// Walks `account`'s watched places, handing each entry to `visit`.
    fn run(account: &'a User, extra: &Extra, visit: &mut Visit<'_>) -> Ended {
        let mut scan = Scan {
            account,
            home: home(account).ok(),
            entries: 0,
            directories: 0,
            hashed: 0,
            truncated: false,
            unscanned: Vec::new(),
            targets: BTreeSet::new(),
            seen: BTreeSet::new(),
        };
        if scan.home.is_none() {
            scan.skip("~ (the home directory could not be opened)");
        }
        let mut watched = 0;
        let mut extra_read = false;
        for place in WATCHED {
            let path = Path::new(place.path);
            match place.watch {
                Watch::File => scan.file(path, visit),
                Watch::Directory => scan.directory(path, false, visit),
                Watch::Units => scan.directory(path, true, visit),
                Watch::Spools if !extra_read => {
                    // Host sources keep their early table priority, so a home
                    // file flood cannot hide an account's scheduled jobs.
                    extra(account, &mut |path, content| {
                        if path == "sshd effective configuration" {
                            scan.ssh_keys(content, visit);
                        } else {
                            scan.spool(path, content, visit);
                        }
                    });
                    extra_read = true;
                }
                Watch::Spools | Watch::AtSpool | Watch::Sshd => {}
            }
            watched += 1;
        }
        // A link's target inside the home is what actually runs; it is opened
        // beneath the home like any entry (a link there is not followed again).
        for target in std::mem::take(&mut scan.targets) {
            scan.file(&target, visit);
        }
        Ended {
            truncated: scan.truncated,
            unscanned: scan.unscanned,
            watched: if cfg!(target_os = "macos") {
                0
            } else {
                watched
            },
            places: scan.entries,
        }
    }

    /// Names `what` as not scanned (printable, bounded) and marks the scan
    /// incomplete.
    fn skip(&mut self, what: &str) {
        self.truncated = true;
        if self.unscanned.len() < UNSCANNED_NAMES {
            self.unscanned.push(shown(what.as_bytes()));
        }
    }

    /// Takes one entry from the budget, or names `what` as not scanned.
    fn admit(&mut self, what: &str) -> bool {
        if self.entries >= ENTRIES {
            self.skip(what);
            return false;
        }
        self.entries += 1;
        true
    }

    /// One crontab or `at` job from the host spool.
    fn spool(&mut self, path: String, content: io::Result<Vec<u8>>, visit: &mut Visit<'_>) {
        if matches!(&content, Err(error) if error.kind() == io::ErrorKind::NotFound)
            || !self.admit(&path)
        {
            return;
        }
        self.seen.insert(path.clone());
        match content {
            Err(error) => {
                self.skip(&path);
                visit(path, error_entry(&error), None);
            }
            Ok(bytes) => {
                let entry = Entry {
                    kind: "file".to_owned(),
                    size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    sha256: Some(hex(&Sha256::digest(&bytes))),
                    lines: Some(line_hashes(&bytes)),
                    ..Entry::default()
                };
                visit(path, entry, Some(&bytes));
            }
        }
    }

    /// Scans the key files sshd actually reads for this account. Commands,
    /// certificate principals and outside-home paths are unsupported sources,
    /// so the account is incomplete instead of being vouched for.
    fn ssh_keys(&mut self, config: io::Result<Vec<u8>>, visit: &mut Visit<'_>) {
        let Some(config) = config.ok().and_then(|bytes| String::from_utf8(bytes).ok()) else {
            self.skip("sshd effective configuration (could not be read)");
            return;
        };
        let mut keys_seen = false;
        for line in config.lines() {
            let mut words = line.split_whitespace();
            let Some(option) = words.next() else { continue };
            match option {
                "authorizedkeysfile" => {
                    keys_seen = true;
                    let paths: Vec<_> = words.collect();
                    if paths.is_empty() {
                        self.skip("sshd AuthorizedKeysFile (no paths returned)");
                    }
                    for path in paths {
                        if path == "none" {
                            continue;
                        }
                        let inside = ssh_key_path(self.account, path);
                        match inside {
                            Some(inside) => self.file(&inside, visit),
                            None => self.skip(
                                "sshd AuthorizedKeysFile (outside the home or unsupported path)",
                            ),
                        }
                    }
                }
                "authorizedkeyscommand"
                | "authorizedprincipalsfile"
                | "authorizedprincipalscommand"
                | "trustedusercakeys"
                    if words.next().is_none_or(|value| value != "none") =>
                {
                    self.skip(&format!("sshd {option} (key source not scanned)"));
                }
                _ => {}
            }
        }
        if !keys_seen {
            self.skip("sshd AuthorizedKeysFile (not returned)");
        }
    }

    /// The target text of the link at `rel`, read from its parent directory.
    fn read_link(&self, rel: &Path) -> Option<String> {
        let home = self.home.as_ref()?;
        let name = rel.file_name()?;
        let target = match rel.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(parent) => {
                let directory = open_beneath(home, parent, true).ok()?;
                nix::fcntl::readlinkat(&directory, name).ok()?
            }
            None => nix::fcntl::readlinkat(home, name).ok()?,
        };
        Some(target.to_string_lossy().into_owned())
    }

    /// `rel` with every link among its directories resolved lexically inside
    /// the home (a dotfile manager's `~/.ssh -> .dotfiles/ssh`, J334 P2-4).
    /// Nothing is followed on disk: each hop is opened again beneath the home
    /// with `O_NOFOLLOW`. A link that leaves the home, or too many hops,
    /// makes the account incomplete and returns `None`. With `whole`, the
    /// last component is resolved too: a watched directory that is itself a
    /// link (`~/.local/bin -> ../.dotfiles/bin`) is scanned at its target
    /// (J343 P2-C); a file's own link is kept, and reported as a link.
    fn resolve(&mut self, rel: &Path, whole: bool) -> Option<PathBuf> {
        let mut path = rel.to_owned();
        let mut linked = false;
        for _ in 0..LINK_HOPS {
            let home = self.home.as_ref()?;
            let parts: Vec<_> = path.components().collect();
            let mut prefix = PathBuf::new();
            let mut next = None;
            let walked = if whole {
                parts.len()
            } else {
                parts.len().saturating_sub(1)
            };
            for part in &parts[..walked] {
                prefix.push(part);
                match open_beneath(home, &prefix, true) {
                    Ok(_) => {}
                    Err(error) if is_link_error(&error) => {
                        let rest = path.strip_prefix(&prefix).ok()?.to_owned();
                        let target = self.read_link(&prefix);
                        // A regular final file also returns ENOTDIR when probed
                        // as a directory. Its caller will read it without links.
                        if whole
                            && prefix == path
                            && target.is_none()
                            && error.raw_os_error() == Some(nix::libc::ENOTDIR)
                        {
                            return Some(path);
                        }
                        let inside =
                            target.and_then(|target| beneath_home(self.account, &prefix, &target));
                        let Some(inside) = inside else {
                            self.skip(&format!(
                                "~/{} (a link that leaves the home; not followed)",
                                prefix.display()
                            ));
                            return None;
                        };
                        linked = true;
                        next = Some(if rest.as_os_str().is_empty() {
                            inside
                        } else {
                            inside.join(rest)
                        });
                        break;
                    }
                    // Ordinary absent places are fine; a broken link is not.
                    Err(error) if error.kind() == io::ErrorKind::NotFound && !linked => {
                        return Some(path);
                    }
                    Err(error) => {
                        self.skip(&format!(
                            "~/{} (could not be resolved: {})",
                            rel.display(),
                            error.kind()
                        ));
                        return None;
                    }
                }
            }
            match next {
                Some(next) => path = next,
                None => return Some(path),
            }
        }
        self.skip(&format!("~/{} (too many links)", rel.display()));
        None
    }

    /// One file under the home, if present. Its kind is read with
    /// `fstatat` first, so only a regular file is ever opened: a FIFO is
    /// not, and no writer blocked on it learns of the scan (J334 P3).
    fn file(&mut self, rel: &Path, visit: &mut Visit<'_>) {
        let shown_path = format!("~/{}", rel.display());
        if self.seen.contains(&shown_path) {
            return;
        }
        let Some(resolved) = self.resolve(rel, false) else {
            return;
        };
        let Some(home) = &self.home else {
            return;
        };
        let Some(name) = resolved.file_name().map(std::ffi::OsStr::to_owned) else {
            return;
        };
        let parent = match resolved.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(parent) => match open_beneath(home, parent, true) {
                Ok(directory) => OwnedFd::from(directory),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return,
                Err(error) => {
                    if self.admit(&shown_path) {
                        self.seen.insert(shown_path.clone());
                        self.skip(&shown_path);
                        visit(shown_path, error_entry(&error), None);
                    }
                    return;
                }
            },
            None => {
                if let Ok(home) = home.try_clone() {
                    home
                } else {
                    self.skip(&shown_path);
                    return;
                }
            }
        };
        let stat = match nix::sys::stat::fstatat(
            &parent,
            name.as_os_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(nix::errno::Errno::ENOENT) => return,
            Err(errno) => {
                if self.admit(&shown_path) {
                    self.seen.insert(shown_path.clone());
                    self.skip(&shown_path);
                    visit(shown_path, error_entry(&io::Error::from(errno)), None);
                }
                return;
            }
        };
        if !self.admit(&shown_path) {
            return;
        }
        self.seen.insert(shown_path.clone());
        let kind =
            nix::sys::stat::SFlag::from_bits_truncate(stat.st_mode) & nix::sys::stat::SFlag::S_IFMT;
        if kind == nix::sys::stat::SFlag::S_IFLNK {
            let entry = self.link(&resolved);
            visit(shown_path, entry, None);
        } else if kind == nix::sys::stat::SFlag::S_IFREG {
            let opened = openat(
                &parent,
                name.as_os_str(),
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            );
            match opened {
                Ok(fd) => {
                    let (entry, bytes) = self.read(std::fs::File::from(fd));
                    if entry.kind == "error" || entry.kind == "foreign" {
                        self.skip(&shown_path);
                    }
                    visit(shown_path, entry, bytes.as_deref());
                }
                Err(errno) => {
                    self.skip(&shown_path);
                    visit(shown_path, error_entry(&io::Error::from(errno)), None);
                }
            }
        } else {
            let entry = Entry {
                kind: "other".to_owned(),
                owner: stat.st_uid,
                ..Entry::default()
            };
            visit(shown_path, entry, None);
        }
    }

    /// A symbolic link at `rel`: its target text, never followed. A target
    /// inside the home is queued to be checked as its own entry.
    fn link(&mut self, rel: &Path) -> Entry {
        let target = self.read_link(rel);
        if target.is_none() {
            self.skip(&format!("~/{} (the link could not be read)", rel.display()));
        } else if let Some(inside) = self.resolve(rel, true)
            && inside != rel
        {
            self.targets.insert(inside);
        }
        Entry {
            kind: "link".to_owned(),
            note: target.is_none().then(|| "a symbolic link".to_owned()),
            target,
            ..Entry::default()
        }
    }

    /// Hashes an opened file, streaming, if it is a regular file the account
    /// owns; keeps its bytes only when it is small enough to show lines.
    fn read(&mut self, file: std::fs::File) -> (Entry, Option<Vec<u8>>) {
        let small = usize::try_from(LINE_FILE_BYTES).unwrap_or(0);
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => return (error_entry(&error), None),
        };
        let mut entry = Entry {
            kind: "file".to_owned(),
            mode: metadata.mode() & 0o7777,
            owner: metadata.uid(),
            size: metadata.len(),
            ..Entry::default()
        };
        if !metadata.is_file() {
            "other".clone_into(&mut entry.kind);
            entry.size = 0;
            return (entry, None);
        }
        if metadata.uid() != self.account.uid.as_raw() {
            // Possibly a hard link to someone else's file: never read.
            "foreign".clone_into(&mut entry.kind);
            return (entry, None);
        }
        let limit = HASH_BYTES.min(ACCOUNT_HASH_BYTES.saturating_sub(self.hashed));
        if limit < metadata.len().min(HASH_BYTES) {
            self.truncated = true;
            entry.note = Some("not hashed: this account's hashing budget ran out".to_owned());
            return (entry, None);
        }
        let keep = metadata.len() <= LINE_FILE_BYTES;
        let mut hasher = Sha256::new();
        let mut kept = Vec::new();
        let mut buffer = vec![0; 64 * 1024];
        let mut reader = file.take(limit);
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    hasher.update(&buffer[..read]);
                    self.hashed = self
                        .hashed
                        .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                    if keep && kept.len() <= small {
                        kept.extend_from_slice(&buffer[..read]);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return (error_entry(&error), None),
            }
        }
        entry.sha256 = Some(hex(&hasher.finalize()));
        if metadata.len() > HASH_BYTES {
            entry.note = Some(format!(
                "only the first {} MiB are compared",
                HASH_BYTES / (1024 * 1024)
            ));
            entry.changed = Some(format!(
                "{}:{}.{:09}",
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec()
            ));
        }
        // A file that grew past the bound while it was read shows no lines.
        if keep && kept.len() <= small {
            entry.lines = Some(line_hashes(&kept));
            (entry, Some(kept))
        } else {
            (entry, None)
        }
    }

    /// The entries of a directory under the home. `units`: a systemd user
    /// unit directory, whose `*.wants`, `*.requires`, `*.upholds` and `*.d`
    /// subdirectories systemd reads too; other subdirectories run nothing.
    fn directory(&mut self, rel: &Path, units: bool, visit: &mut Visit<'_>) {
        let shown_path = format!("~/{}", rel.display());
        if let Some(parent_resolved) = self.resolve(rel, false)
            && self.read_link(&parent_resolved).is_some()
        {
            self.file(rel, visit);
        }
        // Resolved to the end: a watched directory that is a link inside the
        // home is scanned at its target; one leaving the home has already
        // made the scan incomplete (J343 P2-C).
        let Some(resolved) = self.resolve(rel, true) else {
            return;
        };
        let Some(home) = &self.home else {
            return;
        };
        let opened = open_beneath(home, &resolved, true);
        let directory = match opened {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(error) => {
                // Not a directory, or unreadable: nothing in it was checked.
                self.skip(&format!(
                    "{shown_path} (could not be read: {})",
                    error.kind()
                ));
                return;
            }
            Ok(directory) => OwnedFd::from(directory),
        };
        if self.entries >= ENTRIES {
            self.skip(&shown_path);
            return;
        }
        self.directories += 1;
        if self.directories > DIRECTORIES {
            self.skip(&format!(
                "{shown_path} (more than {DIRECTORIES} directories)"
            ));
            return;
        }
        let Some(names) = names(directory) else {
            self.skip(&format!(
                "{shown_path} (more than {DIRECTORY_NAMES} entries)"
            ));
            return;
        };
        for name in names {
            let child = rel.join(&name);
            let Some(home) = &self.home else {
                return;
            };
            let unit_directory = units && {
                let name = name.to_string_lossy();
                name.ends_with(".wants")
                    || name.ends_with(".requires")
                    || name.ends_with(".upholds")
                    || name.ends_with(".d")
            };
            if unit_directory {
                // Unit subdirectories may themselves be links; resolve them
                // before deciding what to read, just like the watched root.
                self.directory(&child, false, visit);
            } else if open_beneath(home, &resolved.join(&name), true).is_err() {
                // Not a directory (a file, a link, a FIFO): one entry.
                self.file(&child, visit);
            }
        }
    }
}

/// The sorted names in an opened directory, or `None` past `DIRECTORY_NAMES`.
fn names(directory: OwnedFd) -> Option<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut listing = nix::dir::Dir::from_fd(directory).ok()?;
    let mut names = Vec::new();
    for entry in listing.iter().filter_map(Result::ok) {
        let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
        if name == "." || name == ".." {
            continue;
        }
        if names.len() == DIRECTORY_NAMES {
            return None;
        }
        names.push(name.to_owned());
    }
    names.sort();
    Some(names)
}

/// Whether opening failed because the path is, or goes through, a symbolic
/// link (`ELOOP`, or `ENOTDIR` for a link where a directory was asked for).
fn is_link_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(nix::libc::ELOOP | nix::libc::ENOTDIR | nix::libc::EMLINK)
    )
}

/// An entry for a file that could not be read.
fn error_entry(error: &io::Error) -> Entry {
    Entry {
        kind: "error".to_owned(),
        note: Some(format!("could not be read ({})", error.kind())),
        ..Entry::default()
    }
}

/// The path beneath the home that link `rel`'s `target` names, lexically,
/// if it stays inside the home. Nothing is resolved on disk.
fn beneath_home(account: &User, rel: &Path, target: &str) -> Option<PathBuf> {
    let target = Path::new(target);
    let start = if target.is_absolute() {
        target.strip_prefix(&account.dir).ok()?.to_owned()
    } else {
        rel.parent().unwrap_or(Path::new("")).join(target)
    };
    let mut inside = PathBuf::new();
    for part in start.components() {
        match part {
            Component::Normal(name) => inside.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                if !inside.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!inside.as_os_str().is_empty()).then_some(inside)
}

/// Expands only sshd's documented key-path tokens, then confines the path
/// lexically to the home. An unknown token cannot silently name another file.
fn ssh_key_path(account: &User, template: &str) -> Option<PathBuf> {
    let mut expanded = String::new();
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            expanded.push(c);
            continue;
        }
        match chars.next()? {
            '%' => expanded.push('%'),
            'h' => expanded.push_str(account.dir.to_str()?),
            'u' => expanded.push_str(&account.name),
            'U' => expanded.push_str(&account.uid.as_raw().to_string()),
            _ => return None,
        }
    }
    beneath_home(account, Path::new("keys"), &expanded)
}

/// Non-blank lines of `bytes`, without their line ending.
fn split(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
}

/// The short hash of one line.
fn line_hash(line: &[u8]) -> String {
    hex(&Sha256::digest(line)[..16])
}

/// Short hashes of each non-blank line, at most `FILE_LINES`.
fn line_hashes(bytes: &[u8]) -> Vec<String> {
    split(bytes).take(FILE_LINES).map(line_hash).collect()
}

/// A line as shown to the person revoking: printable, long whitespace runs
/// counted rather than shown, and a long line cut in the middle with the cut
/// said, so its end (where `; curl … | sh` hides) stays visible.
fn shown(line: &[u8]) -> String {
    /// Ends a whitespace run: short runs as they are, long ones counted.
    fn flush(text: &mut String, run: &mut usize) {
        if *run > 8 {
            text.push('[');
            text.push_str(&run.to_string());
            text.push_str(" spaces]");
        } else {
            text.extend(std::iter::repeat_n(' ', *run));
        }
        *run = 0;
    }
    let mut text = String::new();
    let mut run = 0;
    for c in String::from_utf8_lossy(line).chars() {
        if c == ' ' || c == '\t' {
            run += 1;
            continue;
        }
        flush(&mut text, &mut run);
        text.push(if c.is_control() { '\u{fffd}' } else { c });
    }
    flush(&mut text, &mut run);
    let count = text.chars().count();
    if count <= LINE_CHARS {
        return text;
    }
    let head: String = text.chars().take(LINE_CHARS / 2).collect();
    let tail: String = text.chars().skip(count - LINE_CHARS / 2).collect();
    format!("{head} …[{} characters cut]… {tail}", count - LINE_CHARS)
}

/// The command part of an `at` job: what follows atd's `cd … || { … }`
/// preamble, never the environment it saved (which can hold tokens).
fn at_command(bytes: &[u8]) -> Option<&[u8]> {
    let mut offset = 0;
    let mut in_preamble = false;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        offset += line.len();
        let text = String::from_utf8_lossy(line);
        let text = text.trim();
        if !in_preamble && text.starts_with("cd ") && text.ends_with("|| {") {
            in_preamble = true;
        } else if in_preamble && text == "}" {
            return Some(&bytes[offset..]);
        }
    }
    None
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Takes the record of `account`'s access files.
pub(crate) fn capture(account: &User, extra: &Extra) -> Record {
    let mut entries = BTreeMap::new();
    let ended = Scan::run(account, extra, &mut |path, entry, _| {
        entries.insert(path, entry);
    });
    let mut record = Record {
        account: account.name.clone(),
        entries,
        truncated: ended.truncated,
        unscanned: ended.unscanned,
        recorded_at: now(),
    };
    bound(&mut record);
    record
}

/// Keeps a record within `RECORD_LINES` line hashes and `RECORD_BYTES`:
/// line hashes go first (those files then report "changed" without lines).
fn bound(record: &mut Record) {
    let mut lines = 0;
    for entry in record.entries.values_mut() {
        let count = entry.lines.as_ref().map_or(0, Vec::len);
        if lines + count > RECORD_LINES {
            entry.lines = None;
        } else {
            lines += count;
        }
    }
    while serde_json::to_vec(record).map_or(0, |bytes| bytes.len()) > RECORD_BYTES {
        let Some(entry) = record
            .entries
            .values_mut()
            .rev()
            .find(|entry| entry.lines.is_some())
        else {
            break;
        };
        entry.lines = None;
    }
}

/// What changed in `account`'s access files since `base`. `budget` is the
/// number of lines this revocation may still show.
fn compare(base: &Record, account: &User, extra: &Extra, budget: &mut usize) -> AccountReport {
    let mut files = Vec::new();
    let mut line_cut = false;
    let mut present = BTreeSet::new();
    let scanned_at = now();
    let ended = Scan::run(account, extra, &mut |path, now, bytes| {
        present.insert(path.clone());
        let before = base.entries.get(&path);
        if before.is_some_and(|before| before.same(&now)) {
            return;
        }
        let mut notes = Vec::new();
        if let Some(before) = before {
            describe(before, &now, &mut notes);
        } else if base
            .unscanned
            .iter()
            .any(|skipped| path.starts_with(skipped.split(" (").next().unwrap_or(skipped)))
        {
            notes.push("was not scanned at the grant".to_owned());
        }
        let shown_bytes = match bytes {
            Some(bytes) if path.starts_with("at job") => {
                let command = at_command(bytes);
                if command.is_none() {
                    notes.push(
                        "its commands could not be told apart from its saved environment; not shown"
                            .to_owned(),
                    );
                }
                command
            }
            other => other,
        };
        let mut lines = Vec::new();
        match (shown_bytes, now.kind.as_str()) {
            (Some(bytes), _) => {
                let known = before.and_then(|before| before.lines.as_ref());
                if before.is_some() && known.is_none() {
                    notes.push(
                        "its lines at the grant were not recorded; all lines shown".to_owned(),
                    );
                }
                let mut seen: HashMap<&str, usize> = HashMap::new();
                for hash in known.into_iter().flatten() {
                    *seen.entry(hash.as_str()).or_default() += 1;
                }
                let mut cut_here = false;
                for line in split(bytes) {
                    match seen.get_mut(line_hash(line).as_str()) {
                        Some(count) if *count > 0 => *count -= 1,
                        _ if *budget == 0 => cut_here = true,
                        _ => {
                            *budget -= 1;
                            lines.push(shown(line));
                        }
                    }
                }
                if cut_here {
                    line_cut = true;
                    notes.push("more new lines than the report shows".to_owned());
                } else if lines.is_empty() && before.is_some() {
                    notes.push("lines were removed or reordered; no new lines".to_owned());
                }
            }
            (None, "file") => notes.push(format!("{} bytes: too large to show lines", now.size)),
            (None, "foreign") => notes.push("not owned by the account; not read".to_owned()),
            (None, "other") => notes.push("not a regular file; not read".to_owned()),
            (None, _) => {}
        }
        if now.kind == "link" && before.is_none() {
            notes.push(match &now.target {
                Some(target) => format!(
                    "a symbolic link to {}; not followed",
                    shown(target.as_bytes())
                ),
                None => "a symbolic link; not followed".to_owned(),
            });
        }
        if let Some(note) = &now.note
            && before.and_then(|before| before.note.as_ref()) != Some(note)
        {
            notes.push(note.clone());
        }
        files.push(Change {
            // A file name is the account's text too: shown printable, while
            // the record is keyed by the name as it is on disk.
            path: shown(path.as_bytes()),
            change: if before.is_some() {
                ChangeKind::Changed
            } else {
                ChangeKind::Added
            },
            lines,
            note: (!notes.is_empty()).then(|| notes.join("; ")),
        });
    });
    let mut unscanned = ended.unscanned;
    for skipped in &base.unscanned {
        if !unscanned.contains(skipped) && unscanned.len() < UNSCANNED_NAMES {
            unscanned.push(format!("{skipped} (at the grant)"));
        }
    }
    let complete = !ended.truncated && !base.truncated && unscanned.is_empty();
    // What was there at the grant and is gone now (J334 P2-3: a deleted
    // mask re-enables a unit). Spool removal needs complete scans. Home
    // paths need proven absence even if another place was skipped (a link
    // target that is merely no longer linked is still there).
    {
        let gone = |path: &str| {
            path.strip_prefix("~/")
                .map_or(complete, |rel| absent_beneath(account, Path::new(rel)))
        };
        for (path, before) in &base.entries {
            if present.contains(path) || !gone(path) {
                continue;
            }
            files.push(Change {
                path: shown(path.as_bytes()),
                change: ChangeKind::Removed,
                lines: Vec::new(),
                note: Some(format!(
                    "{} at the grant; gone now",
                    kind_words(&before.kind)
                )),
            });
        }
    }
    let mut report = AccountReport {
        account: account.name.clone(),
        state: State::Unchanged,
        reason: None,
        files,
        truncated: ended.truncated || base.truncated || line_cut,
        unscanned,
        omitted_files: 0,
        complete,
        watched: ended.watched,
        places: ended.places,
        categories: categories(),
        root_checks: Vec::new(),
        privileged: false,
        shared: false,
        programs_may_remain: false,
        processes: Vec::new(),
        jobs: Vec::new(),
        recorded_at: base.recorded_at,
        scanned_at,
    };
    report.decide(false);
    report
}

/// Whether `rel` is absent beneath `account`'s home (opened without
/// following a link); an unreadable path is not called absent.
fn absent_beneath(account: &User, rel: &Path) -> bool {
    home(account).is_ok_and(|home| {
        matches!(open_beneath(&home, rel, false), Err(error) if error.kind() == io::ErrorKind::NotFound)
    })
}

/// What differs between two observations of one path, beyond its lines.
fn describe(before: &Entry, now: &Entry, notes: &mut Vec<String>) {
    if before.kind != now.kind {
        notes.push(format!(
            "was {}, now {}",
            kind_words(&before.kind),
            kind_words(&now.kind)
        ));
    }
    if before.target != now.target {
        let target = |entry: &Entry| {
            entry
                .target
                .as_deref()
                .map_or_else(|| "nothing".to_owned(), |target| shown(target.as_bytes()))
        };
        notes.push(format!(
            "now points to {} (was {})",
            target(now),
            target(before)
        ));
    }
    if before.kind == now.kind && before.mode != now.mode {
        notes.push(format!("mode {:o} → {:o}", before.mode, now.mode));
    }
    if before.kind == now.kind && before.owner != now.owner {
        notes.push(format!("owner uid {} → {}", before.owner, now.owner));
    }
}

/// A kind as words.
fn kind_words(kind: &str) -> &'static str {
    match kind {
        "file" => "a file",
        "link" => "a symbolic link",
        "foreign" => "a file of another owner",
        "other" => "not a regular file",
        _ => "unreadable",
    }
}

/// The account's home directory, opened without following a symlink and
/// owned by the account.
fn home(account: &User) -> io::Result<OwnedFd> {
    let fd = nix::fcntl::open(
        &account.dir,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = std::fs::File::from(fd);
    if file.metadata()?.uid() != account.uid.as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "home is not the account's",
        ));
    }
    Ok(OwnedFd::from(file))
}

/// Opens `rel` beneath `home` without following any symlink on the way: each
/// component is opened from the last with `O_NOFOLLOW`, so a symlink anywhere
/// fails with `ELOOP` (or `ENOTDIR` where a directory is asked for), and
/// `rel` never holds `..` (constants, directory entries, and link targets
/// already resolved lexically inside the home).
fn open_beneath(home: &OwnedFd, rel: &Path, directory: bool) -> io::Result<std::fs::File> {
    let parts: Vec<_> = rel.components().collect();
    let mut current = home.try_clone()?;
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not beneath home",
            ));
        };
        let last = index + 1 == parts.len();
        let mut flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        if !last || directory {
            flags |= OFlag::O_DIRECTORY;
        } else {
            flags |= OFlag::O_NONBLOCK;
        }
        current = openat(&current, *name, flags, Mode::empty()).map_err(|errno| {
            // A symlink as an intermediate directory reads as ENOTDIR on some
            // systems: report it the same way, never followed.
            if errno == nix::errno::Errno::ENOTDIR && !last {
                io::Error::from_raw_os_error(nix::libc::ELOOP)
            } else {
                io::Error::from(errno)
            }
        })?;
    }
    Ok(std::fs::File::from(current))
}

/// The host's crontab and `at` spools for `account`: read directly as root,
/// through `crontab -l` and `atq` when rootless (only the account's own).
pub(crate) fn host_spools(account: &User, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)) {
    if nix::unistd::Uid::effective().is_root() {
        let crontab = ["/var/spool/cron/crontabs", "/var/spool/cron"]
            .iter()
            .map(|spool| Path::new(spool).join(&account.name))
            .find(|path| path.is_file());
        if let Some(path) = crontab {
            visit("crontab".to_owned(), read_spool(&path, account));
        }
        for place in WATCHED.iter().filter(|place| place.watch == Watch::AtSpool) {
            at_spool(account, Path::new(place.path), visit);
        }
        visit(
            "sshd effective configuration".to_owned(),
            sshd_configuration(account),
        );
    } else {
        visit("crontab".to_owned(), command_output("crontab", &["-l"]));
        visit("at queue".to_owned(), command_output("atq", &[]));
    }
}

/// Reads this account's jobs from one watched atd spool. Missing spools are
/// absent; unreadable listings or metadata make coverage incomplete.
fn at_spool(account: &User, spool: &Path, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)) {
    let entries = match std::fs::read_dir(spool) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            visit(format!("at jobs {}", spool.display()), Err(error));
            return;
        }
    };
    let mut jobs = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                visit(format!("at jobs {}", spool.display()), Err(error));
                continue;
            }
        };
        match entry.metadata() {
            Ok(metadata) if metadata.is_file() && metadata.uid() == account.uid.as_raw() => {
                jobs.push(entry.path());
                // One beyond the scanner's budget ensures it names omissions.
                if jobs.len() > ENTRIES {
                    break;
                }
            }
            Ok(_) => {}
            Err(error) => visit(format!("at jobs {}", spool.display()), Err(error)),
        }
    }
    jobs.sort();
    for job in jobs {
        visit(
            format!("at job {}", job.display()),
            read_spool(&job, account),
        );
    }
}

/// The configuration `sshd -T` reads when given no `-f`.
const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

/// What one walk of sshd's configuration tree may still read.
struct SshdBudget {
    /// Files still to open, includes counted.
    files: usize,
    /// Bytes still to read across them.
    bytes: usize,
}

/// Whether `name` matches an sshd `Include` pattern's last component, where
/// `*` stands for any run of characters and `?` for one, as in glob(3).
fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    match (pattern.split_first(), name.split_first()) {
        (None, None) => true,
        (Some((b'*', rest)), _) => {
            wildcard(rest, name)
                || name
                    .split_first()
                    .is_some_and(|(_, tail)| wildcard(pattern, tail))
        }
        (Some((b'?', rest)), Some((_, tail))) => wildcard(rest, tail),
        (Some((want, rest)), Some((have, tail))) if want == have => wildcard(rest, tail),
        _ => false,
    }
}

/// Fail unless every `Match` block in sshd's configuration selects only by
/// `User`, `Group` or `All`. `sshd -T -C user=…` evaluates those, but treats
/// a block on `Address`, `Host`, `LocalAddress` or `RDomain` as not matching
/// (OpenSSH 10.0 exits 0 and leaves it out), so an `AuthorizedKeysFile` set
/// inside one would never be watched and a key added there would read
/// "No changes found" (J1013). Such a configuration is reported as not
/// readable, which makes the account incomplete.
///
/// `Include` is followed like sshd does: a relative path is under `base`
/// (`/etc/ssh`), and `*`/`?` may appear in the last component only. Files
/// are opened without blocking and read through that descriptor; links are
/// followed (some systems link the whole file in). Depth, file count and
/// bytes are bounded, and running out is an error too.
fn sshd_matches_known(
    path: &Path,
    base: &Path,
    depth: usize,
    budget: &mut SshdBudget,
) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let unknown = |why: &str| Err(io::Error::other(format!("sshd configuration: {why}")));
    if depth > 8 {
        return unknown("includes nest too deeply");
    }
    let Some(files) = budget.files.checked_sub(1) else {
        return unknown("too many files");
    };
    budget.files = files;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return unknown("not a regular file");
    }
    let mut text = String::new();
    file.take(u64::try_from(budget.bytes).unwrap_or(u64::MAX) + 1)
        .read_to_string(&mut text)?;
    let Some(left) = budget.bytes.checked_sub(text.len()) else {
        return unknown("too large");
    };
    budget.bytes = left;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line
            .split(|c: char| c.is_ascii_whitespace() || c == '=')
            .filter(|word| !word.is_empty());
        let Some(keyword) = words.next() else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("match") {
            let words: Vec<&str> = words.collect();
            let mut index = 0;
            while let Some(criterion) = words.get(index) {
                if criterion.eq_ignore_ascii_case("all") {
                    index += 1;
                } else if (criterion.eq_ignore_ascii_case("user")
                    || criterion.eq_ignore_ascii_case("group"))
                    && index + 1 < words.len()
                {
                    index += 2;
                } else {
                    return unknown("a Match block depends on the connection");
                }
            }
            if words.is_empty() {
                return unknown("an empty Match line");
            }
        } else if keyword.eq_ignore_ascii_case("include") {
            for pattern in words {
                if pattern.contains(['"', '\\', '[', '{', '~']) {
                    return unknown("an include pattern this check does not expand");
                }
                let pattern = base.join(pattern);
                let (Some(parent), Some(last)) = (pattern.parent(), pattern.file_name()) else {
                    return unknown("an include pattern this check does not expand");
                };
                if parent.to_string_lossy().contains(['*', '?']) {
                    return unknown("an include pattern this check does not expand");
                }
                let last = last.as_encoded_bytes();
                if !last.contains(&b'*') && !last.contains(&b'?') {
                    match sshd_matches_known(&pattern, base, depth + 1, budget) {
                        // sshd skips an include that matches nothing.
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        result => result?,
                    }
                    continue;
                }
                let entries = match std::fs::read_dir(parent) {
                    Ok(entries) => entries,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                for (index, entry) in entries.enumerate() {
                    if index >= 1024 {
                        return unknown("an include directory is too large");
                    }
                    let entry = entry?;
                    let name = entry.file_name();
                    // glob(3) does not match a leading dot with a wildcard.
                    if name.as_encoded_bytes().first() == Some(&b'.') && last.first() != Some(&b'.')
                    {
                        continue;
                    }
                    if wildcard(last, name.as_encoded_bytes()) {
                        sshd_matches_known(&entry.path(), base, depth + 1, budget)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Gets sshd's effective per-account settings as root, with bounded output
/// and a two-second process deadline. Missing tools or refusals are incomplete;
/// neither the effective configuration nor diagnostics are ever logged.
fn sshd_configuration(account: &User) -> io::Result<Vec<u8>> {
    use std::process::{Command, Stdio};
    sshd_matches_known(
        Path::new(SSHD_CONFIG),
        Path::new("/etc/ssh"),
        0,
        &mut SshdBudget {
            files: 64,
            bytes: 1024 * 1024,
        },
    )?;
    let mut child = Command::new("/usr/bin/timeout")
        .args(["--signal=KILL", "2s", "/usr/sbin/sshd", "-T", "-C"])
        .arg(format!("user={}", account.name))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| {
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no sshd output"))?
            .take(u64::try_from(SPOOL_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)?;
        if bytes.len() > SPOOL_BYTES {
            return Err(io::Error::other("sshd output exceeded its bound"));
        }
        if !child.wait()?.success() {
            return Err(io::Error::other("sshd configuration unavailable"));
        }
        Ok(bytes)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

/// A spool file of the account: opened without following a symlink, owned by
/// the account, bounded. A file over the bound is an error, never its first
/// `SPOOL_BYTES`: a cut copy would hide an edit past the cut (J1013).
fn read_spool(path: &Path, account: &User) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != account.uid.as_raw() {
        return Err(io::Error::other("not the account's regular file"));
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(SPOOL_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > SPOOL_BYTES {
        return Err(io::Error::other("spool file exceeded its bound"));
    }
    Ok(bytes)
}

/// The bounded stdout of a short command run as this (rootless) agent's own
/// account; a missing tool or a refusal reads as absent.
fn command_output(program: &str, args: &[&str]) -> io::Result<Vec<u8>> {
    let output = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::ErrorKind::NotFound.into());
    }
    let mut bytes = output.stdout;
    bytes.truncate(SPOOL_BYTES);
    Ok(bytes)
}

/// Where this agent keeps access records, set once when it starts.
static RECORDS: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Keeps this agent's access records in `dir`: the remote agent passes a
/// directory beside its identity in its private, persistent data directory.
pub fn keep_records_in(dir: &Path) {
    let _ = RECORDS.set(dir.to_owned());
}

/// Where records are kept. A remote agent keeps them beside its identity in
/// its private data directory (`--data`), which is persistent: an installed
/// root agent's is under `/var/lib/infraternal` (`state` for a setup
/// install, `agent` for `up`), root-only and removed by its uninstall with
/// the rest of the install. Without one (an embedded agent), rootless
/// records go to the account's own state, and root's to its runtime root,
/// which a reboot empties: the report then says "not checked: no record",
/// never "unchanged". Rootless records are in a place the account can
/// change, so rootless reports are never vouched for.
pub(crate) fn store(runtime_root: &Path) -> PathBuf {
    if cfg!(test) {
        return runtime_root.join("access-records");
    }
    if let Some(dir) = RECORDS.get() {
        return dir.clone();
    }
    if nix::unistd::Uid::effective().is_root() {
        runtime_root.join("infraternal-access-records")
    } else {
        let home = std::env::var_os("HOME").map_or_else(|| runtime_root.to_owned(), PathBuf::from);
        home.join(".local/state/infraternal/access-records")
    }
}

/// The record file of `person` on account `uid`: one directory per account.
fn record_path(store: &Path, person: uuid::Uuid, uid: u32) -> PathBuf {
    store
        .join(uid.to_string())
        .join(format!("{}.json", person.simple()))
}

/// The marker left when recording `person`'s grant on account `uid` failed.
/// It sits in the store's root, not in the account's directory, so a failure
/// to create or write that directory can still be marked.
fn failed_path(store: &Path, person: uuid::Uuid, uid: u32) -> PathBuf {
    store.join(format!("{uid}-{}.failed", person.simple()))
}

/// The marker that account `uid` was shared when someone's access to it
/// ended: their programs may have written to it later, so every later
/// report on the account says it was shared (J334 P2-1).
fn shared_path(store: &Path, uid: u32) -> PathBuf {
    store.join(uid.to_string()).join("shared")
}

/// The last report sent for `person`, kept so a retried revocation whose
/// reply was lost sends it again instead of "no record" (J334 P2-2).
fn report_path(store: &Path, person: uuid::Uuid) -> PathBuf {
    store
        .join("reports")
        .join(format!("{}.json", person.simple()))
}

/// Writes `bytes` to `path` atomically, private (0600), in a private
/// (0700) directory, without following a link at `path`.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::{
        fs::DirBuilder,
        io::Write as _,
        os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    };
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("no directory"))?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    let staging = path.with_extension("staging");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&staging)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&staging, path)?;
    std::fs::File::open(directory)?.sync_all()
}

/// Records `account`'s access files for `person` if nothing is recorded:
/// the first login of that person on that account is the grant, and a later
/// login cannot record over a plant. If recording fails, a marker says so,
/// and no later login may record instead (J334 P2-7): that revocation will
/// read "not checked: recording failed".
pub(crate) fn record_grant(
    store: &Path,
    person: uuid::Uuid,
    account: &User,
    extra: &Extra,
) -> io::Result<()> {
    let uid = account.uid.as_raw();
    let path = record_path(store, person, uid);
    if path.exists() || failed_path(store, person, uid).exists() {
        return Ok(());
    }
    // A new grant: an earlier revocation's kept report is over.
    let _ = std::fs::remove_file(report_path(store, person));
    let recorded = serde_json::to_vec(&capture(account, extra))
        .map_err(io::Error::other)
        .and_then(|bytes| write_private(&path, &bytes));
    if recorded.is_err() {
        let _ = write_private(&failed_path(store, person, uid), b"");
    }
    recorded
}

/// The accounts `person` has records (or failed records) on, from the store
/// itself (not from runtime state, which a reboot empties).
pub(crate) fn recorded_accounts(
    store: &Path,
    person: uuid::Uuid,
) -> impl Iterator<Item = u32> + '_ {
    let failed = format!("-{}.failed", person.simple());
    std::fs::read_dir(store)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(move |entry| {
            let name = entry.file_name().into_string().ok()?;
            match name.strip_suffix(&failed) {
                // A baseline and its failure marker name the same account.
                Some(uid) => {
                    let uid = uid.parse().ok()?;
                    (!record_path(store, person, uid).is_file()).then_some(uid)
                }
                None => name
                    .parse()
                    .ok()
                    .filter(|uid| record_path(store, person, *uid).is_file()),
            }
        })
}

/// Durable holders of `uid`, including failed grant recordings. These records
/// outlive runtime scope files, so D362 must consult them before stopping a
/// whole account. Missing directories mean no record; unreadable state is an
/// error that the caller treats as shared. Records disappear only on revoke.
pub(crate) fn recorded_holders(store: &Path, uid: u32) -> io::Result<Vec<uuid::Uuid>> {
    let mut holders = Vec::new();
    for (directory, failed) in [
        (store.join(uid.to_string()), false),
        (store.to_owned(), true),
    ] {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let name = entry?.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| io::Error::other("invalid grant record name"))?;
            let person = if failed {
                name.strip_prefix(&format!("{uid}-"))
                    .and_then(|name| name.strip_suffix(".failed"))
            } else {
                name.strip_suffix(".json")
            };
            if let Some(person) = person {
                holders.push(uuid::Uuid::parse_str(person).map_err(io::Error::other)?);
            }
        }
    }
    Ok(holders)
}

/// What the revocation knows about an account beyond its files.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    /// Other people still have access to the account (D353).
    pub(crate) shared: bool,
    /// The account's programs may still run after the revoke.
    pub(crate) programs_may_remain: bool,
    /// PIDs and command names observed after the access scan.
    pub(crate) processes: Vec<String>,
    /// Named system work that can write as the account later.
    pub(crate) jobs: Vec<String>,
    /// The account is root or may become root (host policy query).
    pub(crate) privileged: bool,
}

/// What changed on each account `person` had a grant on, since that grant.
/// `live` adds accounts the person still had logins on, so an account with a
/// login but no record reads "not checked: no record". `lookup` finds an
/// account by uid; `facts` says what the revocation knows about it. Each
/// account's outcome comes from [`AccountReport::decide`]. The report is
/// kept so that a retry, after the records are forgotten, sends it again.
pub(crate) fn since_grant(
    store: &Path,
    person: uuid::Uuid,
    live: &[u32],
    lookup: &dyn Fn(u32) -> Option<User>,
    facts: &dyn Fn(u32) -> Facts,
    extra: &Extra,
    rootless: bool,
) -> Access {
    let mut uids = Vec::new();
    let mut omitted = 0_usize;
    for uid in recorded_accounts(store, person) {
        if uids.len() < ACCOUNTS {
            uids.push(uid);
        } else {
            omitted = omitted.saturating_add(1);
        }
    }
    uids.sort_unstable();
    if uids.is_empty()
        && let Some(kept) = std::fs::read(report_path(store, person))
            .ok()
            .filter(|bytes| bytes.len() <= RECORD_BYTES)
            .and_then(|bytes| serde_json::from_slice::<Access>(&bytes).ok())
    {
        return kept;
    }
    for (index, uid) in live.iter().enumerate() {
        if uids.contains(uid)
            || live[..index].contains(uid)
            || record_path(store, person, *uid).is_file()
            || failed_path(store, person, *uid).exists()
        {
            continue;
        }
        if uids.len() < ACCOUNTS {
            uids.push(*uid);
        } else {
            omitted = omitted.saturating_add(1);
        }
    }
    let mut budget = REPORTED_LINES;
    let mut accounts = Vec::new();
    for uid in uids {
        let user = lookup(uid);
        let record = std::fs::read(record_path(store, person, uid))
            .ok()
            .filter(|bytes| bytes.len() <= RECORD_BYTES)
            .and_then(|bytes| serde_json::from_slice::<Record>(&bytes).ok());
        let failed = failed_path(store, person, uid).exists();
        let mut report = match (record, &user) {
            (Some(record), Some(user)) => compare(&record, user, extra, &mut budget),
            (record, user) => AccountReport::not_checked(
                user.as_ref()
                    .map(|user| user.name.clone())
                    .or(record.map(|record| record.account))
                    .unwrap_or_else(|| format!("uid {uid}")),
                if failed {
                    Reason::RecordFailed
                } else {
                    Reason::RecordMissing
                },
            ),
        };
        let known = facts(uid);
        // Shared now, or shared when an earlier person's access ended.
        report.shared = known.shared || shared_path(store, uid).exists();
        if known.shared {
            let _ = write_private(
                &shared_path(store, uid),
                report.scanned_at.to_string().as_bytes(),
            );
        }
        report.programs_may_remain = known.programs_may_remain;
        report.processes = known.processes;
        report.jobs = known.jobs;
        report.privileged = known.privileged;
        report.root_checks = if !rootless && !known.privileged {
            root_check_names()
        } else {
            Vec::new()
        };
        report.decide(rootless);
        accounts.push(report);
    }
    if omitted > 0
        && let Some(last) = accounts.last_mut()
    {
        last.complete = false;
        last.truncated = true;
        last.decide(rootless);
    }
    let mut access = Access::of(accounts);
    access.omitted_accounts = omitted;
    if omitted > 0 {
        access.state = State::NotChecked;
        access.reason = Some(Reason::Incomplete);
    }
    if rootless {
        access.state = State::NotChecked;
        access.reason = Some(Reason::RootlessUnverified);
    }
    if let Ok(bytes) = serde_json::to_vec(&access) {
        let _ = write_private(&report_path(store, person), &bytes);
    }
    access
}

/// Forgets `person`'s records once their revocation is done (the last
/// report stays until their next grant), and an account directory left
/// empty.
pub(crate) fn forget(store: &Path, person: uuid::Uuid) -> io::Result<()> {
    for uid in recorded_accounts(store, person) {
        for path in [
            record_path(store, person, uid),
            failed_path(store, person, uid),
        ] {
            match std::fs::remove_file(path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        // The account's directory goes with its last record, and with it
        // the shared marker; one that still holds another person's record
        // stays.
        let directory = store.join(uid.to_string());
        let others = std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name() != "shared");
        if !others {
            let _ = std::fs::remove_file(shared_path(store, uid));
            let _ = std::fs::remove_dir(&directory);
        }
    }
    Ok(())
}

/// J322's planted cases and the report's outcomes and bounds.
#[cfg(test)]
#[path = "access_files_tests.rs"]
mod tests;
