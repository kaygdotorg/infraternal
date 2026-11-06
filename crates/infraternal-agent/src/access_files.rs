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
//! Where the record lives decides what it is worth. As root it is kept under
//! the install's own `/var/lib/infraternal`, root-only, one directory per
//! account, and the accounts to report are found there, so a reboot that
//! empties `/run` loses nothing. Rootless, the agent runs as the account the
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
/// Accounts with records looked at per revocation.
const ACCOUNTS: usize = 64;
/// Bytes read from one spool file or command.
const SPOOL_BYTES: usize = 256 * 1024;
/// Not-scanned names kept per account (the count past it still truncates).
const UNSCANNED_NAMES: usize = 32;

/// Files that admit a login: checked first.
const KEY_FILES: &[&str] = &[".ssh/authorized_keys", ".ssh/authorized_keys2"];
/// Startup files and other single files under the home that can run code.
const HOME_FILES: &[&str] = &[
    ".ssh/rc",
    ".ssh/config",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".config/fish/config.fish",
];
/// The systemd user unit directory: units, timers, and the `*.wants`,
/// `*.requires` and drop-in `*.d` directories systemd reads in it.
const UNIT_DIRECTORY: &str = ".config/systemd/user";
/// Directories whose entries run at login.
const HOME_DIRECTORIES: &[&str] = &[".config/autostart", ".config/fish/conf.d"];

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
        ) == (
            &now.kind,
            now.mode,
            now.owner,
            now.size,
            &now.sha256,
            &now.target,
            &now.note,
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
}

/// Whether a reported file is new or was there at the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Not there at the grant.
    Added,
    /// There at the grant, different now.
    Changed,
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

/// The outcome for one host account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }
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
        }
    }
}

/// Extra sources outside the home (crontab, `at` jobs), handed one at a time
/// to the visitor as display path and bounded content. Production reads the
/// host's spools.
pub(crate) type Extra = dyn Fn(&User, &mut dyn FnMut(String, io::Result<Vec<u8>>));

/// One observed entry, with its content when it is small enough to show.
type Visit<'a> = dyn FnMut(String, Entry, Option<&[u8]>) + 'a;

/// A walk over one account's access files, in a fixed order with the most
/// valuable first, bounded in entries and bytes.
struct Scan<'a> {
    /// The account being walked.
    account: &'a User,
    /// Its home, opened without following a link; `None` if it could not be.
    home: Option<OwnedFd>,
    /// Entries taken from the budget so far.
    entries: usize,
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
    /// Walks `account`'s access files, handing each to `visit`. Returns
    /// whether anything was left out, and what.
    fn run(account: &'a User, extra: &Extra, visit: &mut Visit<'_>) -> (bool, Vec<String>) {
        let mut scan = Scan {
            account,
            home: home(account).ok(),
            entries: 0,
            hashed: 0,
            truncated: false,
            unscanned: Vec::new(),
            targets: BTreeSet::new(),
            seen: BTreeSet::new(),
        };
        if scan.home.is_none() {
            scan.truncated = true;
            scan.unscanned
                .push("~ (the home directory could not be opened)".to_owned());
        }
        for rel in KEY_FILES {
            scan.file(Path::new(rel), visit);
        }
        extra(account, &mut |path, content| {
            scan.spool(path, content, visit)
        });
        scan.directory(Path::new(UNIT_DIRECTORY), true, visit);
        for rel in HOME_FILES {
            scan.file(Path::new(rel), visit);
        }
        for rel in HOME_DIRECTORIES {
            scan.directory(Path::new(rel), false, visit);
        }
        // A link's target inside the home is what actually runs; it is opened
        // beneath the home like any entry (a link there is not followed again).
        for target in std::mem::take(&mut scan.targets) {
            scan.file(&target, visit);
        }
        (scan.truncated, scan.unscanned)
    }

    /// Takes one entry from the budget, or names `what` as not scanned.
    fn admit(&mut self, what: &str) -> bool {
        if self.entries >= ENTRIES {
            self.truncated = true;
            if self.unscanned.len() < UNSCANNED_NAMES {
                self.unscanned.push(what.to_owned());
            }
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
            Err(error) => visit(path, error_entry(&error), None),
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

    /// One file under the home, if present.
    fn file(&mut self, rel: &Path, visit: &mut Visit<'_>) {
        let shown = format!("~/{}", rel.display());
        if self.seen.contains(&shown) {
            return;
        }
        let Some(home) = &self.home else {
            return;
        };
        let opened = open_beneath(home, rel, false);
        if matches!(&opened, Err(error) if error.kind() == io::ErrorKind::NotFound) {
            return;
        }
        if !self.admit(&shown) {
            return;
        }
        self.seen.insert(shown.clone());
        match opened {
            Err(error) if is_link_error(&error) => {
                let entry = self.link(rel);
                visit(shown, entry, None);
            }
            Err(error) => visit(shown, error_entry(&error), None),
            Ok(file) => {
                let (entry, bytes) = self.read(file);
                visit(shown, entry, bytes.as_deref());
            }
        }
    }

    /// A symbolic link at `rel`: its target text, never followed. A target
    /// inside the home is queued to be checked as its own entry.
    fn link(&mut self, rel: &Path) -> Entry {
        let target = self
            .home
            .as_ref()
            .and_then(|home| {
                let name = rel.file_name()?;
                match rel.parent().filter(|p| !p.as_os_str().is_empty()) {
                    Some(parent) => {
                        let directory = open_beneath(home, parent, true).ok()?;
                        nix::fcntl::readlinkat(&directory, name).ok()
                    }
                    None => nix::fcntl::readlinkat(home, name).ok(),
                }
            })
            .map(|target| target.to_string_lossy().into_owned());
        if let Some(inside) = target
            .as_deref()
            .and_then(|target| beneath_home(self.account, rel, target))
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
            entry.kind = "other".to_owned();
            entry.size = 0;
            return (entry, None);
        }
        if metadata.uid() != self.account.uid.as_raw() {
            // Possibly a hard link to someone else's file: never read.
            entry.kind = "foreign".to_owned();
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
        }
        // A file that grew past the bound while it was read shows no lines.
        if keep && kept.len() <= small {
            entry.lines = Some(line_hashes(&kept));
            (entry, Some(kept))
        } else {
            (entry, None)
        }
    }

    /// The entries of a directory under the home. `units`: the systemd user
    /// directory, whose `*.wants`, `*.requires` and `*.d` subdirectories
    /// systemd reads too; other subdirectories run nothing and are skipped.
    fn directory(&mut self, rel: &Path, units: bool, visit: &mut Visit<'_>) {
        let shown = format!("~/{}", rel.display());
        let Some(home) = &self.home else {
            return;
        };
        let opened = open_beneath(home, rel, true);
        let directory = match opened {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(error) if is_link_error(&error) => {
                // The directory itself is a link (to /etc/xdg/autostart, say).
                if self.admit(&shown) {
                    self.seen.insert(shown.clone());
                    let entry = self.link(rel);
                    visit(shown, entry, None);
                }
                return;
            }
            Err(error) => {
                if self.admit(&shown) {
                    visit(shown, error_entry(&error), None);
                }
                return;
            }
            Ok(directory) => OwnedFd::from(directory),
        };
        if self.entries >= ENTRIES {
            self.admit(&shown);
            return;
        }
        let Some(names) = names(directory) else {
            self.truncated = true;
            if self.unscanned.len() < UNSCANNED_NAMES {
                self.unscanned
                    .push(format!("{shown} (more than {DIRECTORY_NAMES} entries)"));
            }
            return;
        };
        for name in names {
            let child = rel.join(&name);
            let Some(home) = &self.home else {
                return;
            };
            if open_beneath(home, &child, true).is_ok() {
                let name = name.to_string_lossy();
                if units
                    && (name.ends_with(".wants")
                        || name.ends_with(".requires")
                        || name.ends_with(".d"))
                {
                    self.directory(&child, false, visit);
                }
            } else {
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
    let (truncated, unscanned) = Scan::run(account, extra, &mut |path, entry, _| {
        entries.insert(path, entry);
    });
    let mut record = Record {
        account: account.name.clone(),
        entries,
        truncated,
        unscanned,
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
    let (truncated, mut unscanned) = Scan::run(account, extra, &mut |path, now, bytes| {
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
            path,
            change: if before.is_some() {
                ChangeKind::Changed
            } else {
                ChangeKind::Added
            },
            lines,
            note: (!notes.is_empty()).then(|| notes.join("; ")),
        });
    });
    for skipped in &base.unscanned {
        if !unscanned.contains(skipped) && unscanned.len() < UNSCANNED_NAMES {
            unscanned.push(format!("{skipped} (at the grant)"));
        }
    }
    AccountReport {
        account: account.name.clone(),
        state: if files.is_empty() {
            State::Unchanged
        } else {
            State::Changed
        },
        reason: None,
        files,
        truncated: truncated || base.truncated || line_cut,
        unscanned,
        omitted_files: 0,
    }
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
        let mut jobs = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/var/spool/cron/atjobs") {
            // The account's own jobs, then the bound: another account's many
            // jobs cannot push this one's out (J322 P3).
            for entry in entries.filter_map(Result::ok) {
                if entry
                    .metadata()
                    .is_ok_and(|m| m.is_file() && m.uid() == account.uid.as_raw())
                {
                    jobs.push(entry.path());
                    if jobs.len() > ENTRIES {
                        break;
                    }
                }
            }
        }
        jobs.sort();
        for job in jobs {
            let name = job
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            visit(format!("at job {name}"), read_spool(&job, account));
        }
    } else {
        visit("crontab".to_owned(), command_output("crontab", &["-l"]));
        visit("at queue".to_owned(), command_output("atq", &[]));
    }
}

/// A spool file of the account: opened without following a symlink, owned by
/// the account, bounded.
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
    file.take(u64::try_from(SPOOL_BYTES).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
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

/// Where records are kept: persistent (a grant outlives a reboot) and, as
/// root, inside the install's root-only `/var/lib/infraternal`, which its
/// uninstall removes. Rootless, in the account's own state, which the
/// account can change: such reports are never vouched for.
pub(crate) fn store(runtime_root: &Path) -> PathBuf {
    if cfg!(test) {
        return runtime_root.join("access-records");
    }
    if nix::unistd::Uid::effective().is_root() {
        PathBuf::from("/var/lib/infraternal/access-records")
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

/// Records `account`'s access files for `person` if nothing is recorded:
/// the first login of that person on that account is the grant, and a later
/// login cannot record over a plant.
pub(crate) fn record_grant(
    store: &Path,
    person: uuid::Uuid,
    account: &User,
    extra: &Extra,
) -> io::Result<()> {
    use std::{
        fs::DirBuilder,
        io::Write as _,
        os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    };
    let path = record_path(store, person, account.uid.as_raw());
    if path.exists() {
        return Ok(());
    }
    let directory = path.parent().unwrap_or(store);
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    let staging = path.with_extension("json.staging");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&staging)?;
    file.write_all(&serde_json::to_vec(&capture(account, extra)).map_err(io::Error::other)?)?;
    file.sync_all()?;
    std::fs::rename(&staging, &path)?;
    std::fs::File::open(directory)?.sync_all()
}

/// The accounts `person` has records on, from the store itself (not from
/// runtime state, which a reboot empties).
fn recorded_accounts(store: &Path, person: uuid::Uuid) -> Vec<u32> {
    let mut uids: Vec<u32> = std::fs::read_dir(store)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .filter(|uid| record_path(store, person, *uid).is_file())
        .take(ACCOUNTS)
        .collect();
    uids.sort_unstable();
    uids
}

/// What changed on each account `person` had a grant on, since that grant.
/// `live` adds accounts the person still had logins on, so an account with a
/// login but no record reads "not checked: no record". `lookup` finds an
/// account by uid. Rootless reports are never vouched for.
pub(crate) fn since_grant(
    store: &Path,
    person: uuid::Uuid,
    live: &[u32],
    lookup: &dyn Fn(u32) -> Option<User>,
    extra: &Extra,
    rootless: bool,
) -> Access {
    let mut uids = recorded_accounts(store, person);
    for uid in live {
        if !uids.contains(uid) && uids.len() < ACCOUNTS {
            uids.push(*uid);
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
        let mut report = match (record, user) {
            (Some(record), Some(user)) => compare(&record, &user, extra, &mut budget),
            (record, user) => AccountReport::not_checked(
                user.map(|user| user.name)
                    .or(record.map(|record| record.account))
                    .unwrap_or_else(|| format!("uid {uid}")),
                Reason::RecordMissing,
            ),
        };
        if rootless {
            report.state = State::NotChecked;
            report.reason = Some(Reason::RootlessUnverified);
        }
        accounts.push(report);
    }
    let mut access = Access::of(accounts);
    if rootless {
        access.state = State::NotChecked;
        access.reason = Some(Reason::RootlessUnverified);
    }
    access
}

/// Forgets `person`'s records once their revocation is done.
pub(crate) fn forget(store: &Path, person: uuid::Uuid) -> io::Result<()> {
    for uid in recorded_accounts(store, person) {
        match std::fs::remove_file(record_path(store, person, uid)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "access_files_tests.rs"]
mod tests;
