//! What a person may have left behind on a host account (D356, #355).
//!
//! A person with a shell on a host account can leave their own way back in:
//! an SSH key in `~/.ssh/authorized_keys`, a crontab or `at` job, an enabled
//! systemd user unit, an XDG autostart entry, or a line in a shell startup
//! file. A revoke ends their processes (D353) but does not, and must not,
//! touch those files: restoring them could undo legitimate changes by the
//! host owner or by other people on the account.
//!
//! So when a person first gets a login on an account, the agent records a
//! fingerprint of these access files: for each, whether it exists, and a
//! SHA-256 hash of each of its lines, never the lines themselves, so the
//! baseline holds no secrets. On revoke it reads the files again and reports
//! exactly which files and lines are new since the grant, for the person
//! revoking to review and remove. It never edits them.
//!
//! The reads are hostile-input safe. Home files are opened beneath the home
//! directory one component at a time with `O_NOFOLLOW`, and only
//! regular files owned by the account are read: a symlink or hard link the
//! account planted (say `~/.bashrc` -> `/etc/shadow`) is reported as present
//! but never read. Everything is bounded: bytes per file, files per account,
//! and reported lines and their length. The report goes only into the revoke
//! result, never into a log.
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
    unistd::User,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    io::{self, Read as _},
    os::{fd::OwnedFd, unix::fs::MetadataExt as _},
    path::{Path, PathBuf},
};

/// Bytes of one access file that are compared; the rest is reported as such.
const FILE_BYTES: usize = 64 * 1024;
/// Access files and directory entries fingerprinted per account.
const FILES: usize = 64;
/// Changed lines reported per revocation, across all files.
const REPORTED_LINES: usize = 64;
/// Characters of one reported line.
const LINE_CHARS: usize = 200;

/// Single files under the home directory that can run or admit code.
const HOME_FILES: &[&str] = &[
    ".ssh/authorized_keys",
    ".ssh/authorized_keys2",
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

/// Directories under the home directory whose entries can run code, with how
/// deep to look: autostart entries, fish snippets, and systemd user units,
/// timers and their `*.wants` links.
const HOME_DIRS: &[(&str, usize)] = &[
    (".config/autostart", 1),
    (".config/fish/conf.d", 1),
    (".config/systemd/user", 2),
];

/// One access source at grant time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Source {
    /// Hex SHA-256 of each line, with multiplicity.
    lines: Vec<String>,
    /// Present but not compared (a link, not owned by the account, too big).
    note: Option<String>,
}

/// An account's access sources at grant time, keyed by display path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Fingerprint {
    sources: BTreeMap<String, Source>,
}

/// One access source with lines that are new since the grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Where, as the person revoking would look for it (`~/.ssh/authorized_keys`).
    pub path: String,
    /// The new or changed lines, shortened to a bounded length.
    pub lines: Vec<String>,
    /// Why some of it could not be compared, if so.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What a revocation found changed, bounded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    pub files: Vec<Change>,
    /// More lines or files changed than are reported.
    pub truncated: bool,
}

/// Extra sources outside the home directory (crontab, `at` jobs), as
/// display path and raw content. Production reads the host's spools.
pub(crate) type Extra = dyn Fn(&User) -> Vec<(String, io::Result<Vec<u8>>)>;

/// Takes the fingerprint of `account`'s access files.
pub(crate) fn capture(account: &User, extra: &Extra) -> Fingerprint {
    let mut sources = BTreeMap::new();
    for (path, content) in read_all(account, extra) {
        sources.insert(path, fingerprint(&content));
    }
    Fingerprint { sources }
}

/// What is new in `account`'s access files since `base`.
pub(crate) fn changes(base: &Fingerprint, account: &User, extra: &Extra) -> Changes {
    let mut report = Changes::default();
    let mut budget = REPORTED_LINES;
    for (path, content) in read_all(account, extra) {
        let now = fingerprint(&content);
        let before = base.sources.get(&path);
        if before == Some(&now) {
            continue;
        }
        let mut seen: HashMap<&str, usize> = HashMap::new();
        for hash in before.map_or(&[][..], |source| source.lines.as_slice()) {
            *seen.entry(hash.as_str()).or_default() += 1;
        }
        let mut lines = Vec::new();
        if let Ok(Content::Bytes(bytes)) = &content {
            let compared = &bytes[..bytes.len().min(FILE_BYTES)];
            for (line, hash) in split(compared).zip(now.lines.iter()) {
                match seen.get_mut(hash.as_str()) {
                    Some(count) if *count > 0 => *count -= 1,
                    _ if budget == 0 => report.truncated = true,
                    _ => {
                        budget -= 1;
                        lines.push(shown(line));
                    }
                }
            }
        }
        let note = now
            .note
            .clone()
            .filter(|note| before.and_then(|b| b.note.as_ref()) != Some(note));
        if lines.is_empty() && note.is_none() {
            continue;
        }
        report.files.push(Change { path, lines, note });
    }
    report
}

/// What was read for one source.
enum Content {
    Bytes(Vec<u8>),
    /// Present, but deliberately not read.
    Note(String),
}

/// Lines and notes of one read source; absent sources hash to nothing.
fn fingerprint(content: &io::Result<Content>) -> Source {
    match content {
        Ok(Content::Bytes(bytes)) => {
            let mut note = None;
            if bytes.len() > FILE_BYTES {
                note = Some(format!(
                    "larger than {} KiB; only the start was compared",
                    FILE_BYTES / 1024
                ));
            }
            let bytes = &bytes[..bytes.len().min(FILE_BYTES)];
            Source {
                lines: split(bytes)
                    .map(|line| hex(&Sha256::digest(line)))
                    .collect(),
                note,
            }
        }
        Ok(Content::Note(note)) => Source {
            lines: Vec::new(),
            note: Some(note.clone()),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Source::default(),
        Err(error) => Source {
            lines: Vec::new(),
            note: Some(format!("could not be read ({})", error.kind())),
        },
    }
}

/// Non-empty lines of `bytes`, without their line ending.
fn split(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
}

/// A line as shown to the person revoking: printable, and at most `LINE_CHARS`.
fn shown(line: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(line)
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();
    if text.chars().count() > LINE_CHARS {
        let mut short: String = text.chars().take(LINE_CHARS).collect();
        short.push('…');
        short
    } else {
        text
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Every source of `account`, as (display path, content), bounded in count.
fn read_all(account: &User, extra: &Extra) -> Vec<(String, io::Result<Content>)> {
    let mut out = Vec::new();
    match home(account) {
        Ok(home) => {
            for rel in HOME_FILES {
                out.push((
                    format!("~/{rel}"),
                    read_beneath(&home, Path::new(rel), account),
                ));
            }
            for (dir, depth) in HOME_DIRS {
                list_beneath(&home, Path::new(dir), *depth, account, &mut out);
            }
        }
        Err(error) => out.push(("~".to_owned(), Err(error))),
    }
    for (path, content) in extra(account) {
        out.push((path, content.map(Content::Bytes)));
    }
    if out.len() > FILES {
        out.truncate(FILES);
        out.push((
            format!("(more than {FILES} access files)"),
            Ok(Content::Note("not all compared".to_owned())),
        ));
    }
    out
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
/// fails with `ELOOP`, and `rel` never holds `..` (constants and directory
/// entries only). Portable to every platform the agent runs on.
fn open_beneath(home: &OwnedFd, rel: &Path, directory: bool) -> io::Result<std::fs::File> {
    use std::path::Component;
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

/// Reads `rel` beneath `home`, if it is a regular file the account owns.
fn read_beneath(home: &OwnedFd, rel: &Path, account: &User) -> io::Result<Content> {
    let file = match open_beneath(home, rel, false) {
        Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => {
            return Ok(Content::Note("a symbolic link; not followed".to_owned()));
        }
        result => result?,
    };
    read_owned(file, account)
}

/// Reads an opened file if it is a regular file owned by the account,
/// at most `FILE_BYTES + 1` bytes (so an oversized file can say so).
fn read_owned(file: std::fs::File, account: &User) -> io::Result<Content> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Ok(Content::Note("not a regular file; not read".to_owned()));
    }
    if metadata.uid() != account.uid.as_raw() {
        return Ok(Content::Note(
            "not owned by the account; not read".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(FILE_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    Ok(Content::Bytes(bytes))
}

/// Lists `rel` beneath `home` to `depth`: regular files are read, symlinks
/// (enabled units in `*.wants`) are recorded by their target text, unread.
fn list_beneath(
    home: &OwnedFd,
    rel: &Path,
    depth: usize,
    account: &User,
    out: &mut Vec<(String, io::Result<Content>)>,
) {
    let directory = match open_beneath(home, rel, true) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => {
            out.push((
                format!("~/{}", rel.display()),
                Ok(Content::Note("a symbolic link; not followed".to_owned())),
            ));
            return;
        }
        Err(error) => {
            out.push((format!("~/{}", rel.display()), Err(error)));
            return;
        }
        Ok(directory) => directory,
    };
    let fd = OwnedFd::from(directory);
    // The opened directory itself, through its descriptor: no path is
    // resolved again, so nothing can be swapped in between.
    let Ok(mut listing) = fd
        .try_clone()
        .map_err(io::Error::from)
        .and_then(|copy| nix::dir::Dir::from_fd(copy).map_err(io::Error::from))
    else {
        return;
    };
    let mut names: Vec<std::ffi::OsString> = listing
        .iter()
        .filter_map(Result::ok)
        .map(|entry| {
            use std::os::unix::ffi::OsStrExt as _;
            std::ffi::OsStr::from_bytes(entry.file_name().to_bytes()).to_owned()
        })
        .filter(|name| name != "." && name != "..")
        .collect();
    names.sort();
    let mut links = Vec::new();
    for name in names.into_iter().take(FILES) {
        let child = rel.join(&name);
        let shown_path = format!("~/{}", child.display());
        match open_beneath(home, &child, false) {
            Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => {
                // An enabled unit: record where the link points, never follow it.
                let target = nix::fcntl::readlinkat(&fd, name.as_os_str())
                    .map(|target| target.to_string_lossy().into_owned())
                    .unwrap_or_default();
                links.push(format!("{} -> {target}", child.display()));
            }
            Ok(file) if file.metadata().is_ok_and(|m| m.is_dir()) => {
                if depth > 1 {
                    list_beneath(home, &child, depth - 1, account, out);
                }
            }
            Ok(file) => out.push((shown_path, read_owned(file, account))),
            Err(error) => out.push((shown_path, Err(error))),
        }
    }
    if !links.is_empty() {
        out.push((
            format!("~/{} (enabled links)", rel.display()),
            Ok(Content::Bytes(links.join("\n").into_bytes())),
        ));
    }
}

/// The host's crontab and `at` spools for `account`: read directly as root,
/// through `crontab -l` and `atq` when rootless (only the account's own).
pub(crate) fn host_spools(account: &User) -> Vec<(String, io::Result<Vec<u8>>)> {
    let mut out = Vec::new();
    if nix::unistd::Uid::effective().is_root() {
        let crontab = ["/var/spool/cron/crontabs", "/var/spool/cron"]
            .iter()
            .map(|spool| Path::new(spool).join(&account.name))
            .find(|path| path.is_file());
        out.push((
            "crontab".to_owned(),
            crontab.map_or_else(
                || Err(io::ErrorKind::NotFound.into()),
                |path| read_spool(&path, account),
            ),
        ));
        let mut jobs = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/var/spool/cron/atjobs") {
            for entry in entries.filter_map(Result::ok).take(FILES) {
                if entry
                    .metadata()
                    .is_ok_and(|m| m.is_file() && m.uid() == account.uid.as_raw())
                {
                    jobs.push(entry.path());
                }
            }
        }
        jobs.sort();
        for job in jobs {
            out.push((
                format!(
                    "at job {}",
                    job.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
                read_spool(&job, account),
            ));
        }
    } else {
        out.push(("crontab".to_owned(), command_output("crontab", &["-l"])));
        out.push(("at queue".to_owned(), command_output("atq", &[])));
    }
    out
}

/// A spool file of the account: opened without following a symlink, owned by
/// the account, bounded.
fn read_spool(path: &Path, account: &User) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    match read_owned(file, account)? {
        Content::Bytes(bytes) => Ok(bytes),
        Content::Note(note) => Err(io::Error::other(note)),
    }
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
    bytes.truncate(FILE_BYTES + 1);
    Ok(bytes)
}

/// Where baselines are kept: persistent (a grant outlives a reboot), private.
pub(crate) fn store(runtime_root: &Path) -> PathBuf {
    if cfg!(test) {
        return runtime_root.join("access-baselines");
    }
    if nix::unistd::Uid::effective().is_root() {
        PathBuf::from("/var/lib/infraternal-agent/access-baselines")
    } else {
        let home = std::env::var_os("HOME").map_or_else(|| runtime_root.to_owned(), PathBuf::from);
        home.join(".local/state/infraternal/access-baselines")
    }
}

/// The baseline file of `person` on account `uid`.
fn baseline(store: &Path, person: uuid::Uuid, uid: u32) -> PathBuf {
    store.join(format!("{}-{uid}.json", person.simple()))
}

/// Records `account`'s fingerprint for `person` if none is recorded: the
/// first login of that person on that account is the grant.
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
    let path = baseline(store, person, account.uid.as_raw());
    if path.exists() {
        return Ok(());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(store)?;
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
    std::fs::File::open(store)?.sync_all()
}

/// What changed in `account`'s access files since `person`'s grant. With no
/// recorded grant, says so instead of guessing.
pub(crate) fn since_grant(
    store: &Path,
    person: uuid::Uuid,
    account: &User,
    extra: &Extra,
) -> Changes {
    let path = baseline(store, person, account.uid.as_raw());
    let base = std::fs::read(&path)
        .ok()
        .filter(|bytes| bytes.len() <= 4 * 1024 * 1024)
        .and_then(|bytes| serde_json::from_slice::<Fingerprint>(&bytes).ok());
    match base {
        Some(base) => changes(&base, account, extra),
        None => Changes {
            files: vec![Change {
                path: format!("account {}", account.name),
                lines: Vec::new(),
                note: Some("no record from when access was granted; check the account's access files by hand".to_owned()),
            }],
            truncated: false,
        },
    }
}

/// Forgets `person`'s baseline on account `uid` once their revocation is done.
pub(crate) fn forget(store: &Path, person: uuid::Uuid, uid: u32) -> io::Result<()> {
    match std::fs::remove_file(baseline(store, person, uid)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    //! D356: grant-time fingerprints and revoke-time reports of new access lines.
    use super::*;

    /// A fake account whose home is a fresh private directory.
    fn account() -> (User, PathBuf) {
        let mut user = User::from_uid(nix::unistd::Uid::effective())
            .unwrap()
            .unwrap();
        let home = nix::unistd::mkdtemp("/tmp/af-XXXXXX").unwrap();
        user.dir.clone_from(&home);
        (user, home)
    }

    fn no_extra(_: &User) -> Vec<(String, io::Result<Vec<u8>>)> {
        Vec::new()
    }

    /// A key appended to authorized_keys and a new autostart entry are
    /// reported with exactly their new lines; untouched files are not.
    #[test]
    fn new_access_lines_since_the_grant_are_reported_exactly() {
        let (user, home) = account();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(
            home.join(".ssh/authorized_keys"),
            "ssh-ed25519 AAAAold owner\n",
        )
        .unwrap();
        std::fs::write(home.join(".bashrc"), "export PATH=$PATH:~/bin\n").unwrap();
        let base = capture(&user, &no_extra);
        assert_eq!(
            changes(&base, &user, &no_extra),
            Changes::default(),
            "nothing changed yet"
        );
        std::fs::write(
            home.join(".ssh/authorized_keys"),
            "ssh-ed25519 AAAAold owner\nssh-ed25519 AAAAnew left-behind\n",
        )
        .unwrap();
        std::fs::create_dir_all(home.join(".config/autostart")).unwrap();
        std::fs::write(
            home.join(".config/autostart/back.desktop"),
            "[Desktop Entry]\nExec=/tmp/back\n",
        )
        .unwrap();
        let report = changes(&base, &user, &no_extra);
        assert_eq!(
            report.files,
            [
                Change {
                    path: "~/.ssh/authorized_keys".into(),
                    lines: vec!["ssh-ed25519 AAAAnew left-behind".into()],
                    note: None
                },
                Change {
                    path: "~/.config/autostart/back.desktop".into(),
                    lines: vec!["[Desktop Entry]".into(), "Exec=/tmp/back".into()],
                    note: None
                },
            ]
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    /// A symlink planted at a startup file is reported but never read, so a
    /// revoke cannot be made to show another file's content (/etc/shadow).
    #[test]
    fn a_planted_symlink_is_reported_but_never_followed() {
        let (user, home) = account();
        let base = capture(&user, &no_extra);
        std::os::unix::fs::symlink("/etc/passwd", home.join(".profile")).unwrap();
        let report = changes(&base, &user, &no_extra);
        assert_eq!(
            report.files,
            [Change {
                path: "~/.profile".into(),
                lines: Vec::new(),
                note: Some("a symbolic link; not followed".into())
            }]
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    /// The report is bounded: at most REPORTED_LINES lines, each shortened.
    #[test]
    fn the_report_is_bounded() {
        let (user, home) = account();
        let base = capture(&user, &no_extra);
        let long = "x".repeat(LINE_CHARS * 2);
        let many: String = (0..REPORTED_LINES * 2)
            .map(|i| format!("{long}{i}\n"))
            .collect();
        std::fs::write(home.join(".zshrc"), many).unwrap();
        let report = changes(&base, &user, &no_extra);
        assert!(report.truncated);
        let lines: Vec<_> = report.files.iter().flat_map(|file| &file.lines).collect();
        assert_eq!(lines.len(), REPORTED_LINES);
        assert!(
            lines
                .iter()
                .all(|line| line.chars().count() == LINE_CHARS + 1)
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    /// Enabled systemd user units are recorded by their link, unread, and a
    /// crontab line from the host spool is reported like any file's.
    #[test]
    fn enabled_units_and_crontab_lines_are_reported() {
        let (user, home) = account();
        let crontab = std::sync::Arc::new(std::sync::Mutex::new(b"0 * * * * backup\n".to_vec()));
        let spool = crontab.clone();
        let extra = move |_: &User| vec![("crontab".to_owned(), Ok(spool.lock().unwrap().clone()))];
        let base = capture(&user, &extra);
        let wants = home.join(".config/systemd/user/default.target.wants");
        std::fs::create_dir_all(&wants).unwrap();
        std::fs::write(
            home.join(".config/systemd/user/back.service"),
            "[Service]\nExecStart=/tmp/back\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("../back.service", wants.join("back.service")).unwrap();
        crontab
            .lock()
            .unwrap()
            .extend_from_slice(b"@reboot /tmp/back\n");
        let report = changes(&base, &user, &extra);
        let paths: Vec<_> = report.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "~/.config/systemd/user/back.service",
                "~/.config/systemd/user/default.target.wants (enabled links)",
                "crontab"
            ]
        );
        assert_eq!(
            report.files[1].lines,
            [".config/systemd/user/default.target.wants/back.service -> ../back.service"]
        );
        assert_eq!(report.files[2].lines, ["@reboot /tmp/back"]);
        std::fs::remove_dir_all(home).unwrap();
    }

    /// The baseline holds line hashes only, never the lines (no secrets at rest),
    /// and a revoke without a recorded grant says so.
    #[test]
    fn the_baseline_holds_no_content_and_a_missing_one_says_so() {
        let (user, home) = account();
        std::fs::write(home.join(".bashrc"), "export TOKEN=secret-canary\n").unwrap();
        let store = home.join("store");
        let person = uuid::Uuid::new_v4();
        record_grant(&store, person, &user, &no_extra).unwrap();
        let saved = std::fs::read_to_string(baseline(&store, person, user.uid.as_raw())).unwrap();
        assert!(
            !saved.contains("secret-canary"),
            "the baseline stored a line"
        );
        forget(&store, person, user.uid.as_raw()).unwrap();
        let report = since_grant(&store, person, &user, &no_extra);
        assert!(
            report.files[0]
                .note
                .as_deref()
                .is_some_and(|note| note.starts_with("no record"))
        );
        std::fs::remove_dir_all(home).unwrap();
    }
}
