//! D362 observes remaining account processes through kernel UID records, including processes
//! outside systemd's user slice. Root logins are systemd-only under D354; this
//! module observes processes and never sends signals or implements a kill loop.
//!
//! The stop covers logind sessions and the account's user services. A system
//! service or scheduler can run as the same UID in `system.slice`; these belong
//! to the system and are reported, never killed by revocation (D362, amended
//! 2026-11-08). Any observed survivor forces `not_checked/programs_may_remain`
//! with its PID and printable command, even if every watched file is unchanged.
//!
//! Subordinate-UID container processes are out of scope for this observation
//! (J357 P3, owner 2026-11-08): their host UIDs can differ from the account's
//! real, effective, saved and filesystem UIDs. The systemd stop still removes
//! them while they remain in the account's sessions or user slice, regardless
//! of UID. Outside that slice they can survive without appearing in this UID
//! listing. This module does not infer account ownership from namespace UID
//! maps or `/etc/subuid`, including ranges containing host uid 0, and never
//! promises that such processes were checked (D367, follow-up #429).
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    time::{Duration, Instant},
};

/// A bounded process listing and whether every readable UID was accounted for.
#[derive(Debug, Default)]
pub(crate) struct Snapshot {
    /// PID and printable kernel command name, at most 64 entries, without argv secrets.
    pub(crate) processes: Vec<String>,
    /// False on unreadable or malformed state, or when the traversal budget expires.
    pub(crate) complete: bool,
}

impl Snapshot {
    /// Whether this observation permits a claim that no account process remains.
    pub(crate) fn empty(&self) -> bool {
        self.complete && self.processes.is_empty()
    }
}

/// Read one small kernel record without allocating for an unbounded input.
fn record(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(io::Error::other("process record too large"));
    }
    String::from_utf8(bytes).map_err(io::Error::other)
}

/// Whether any real, effective, saved or filesystem UID belongs to the account.
fn belongs(status: &str, uid: u32) -> Option<bool> {
    let values = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    let ids = values
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (ids.len() == 4).then(|| ids.contains(&uid))
}

/// Inspect `/proc` once. Races with an exited process are harmless; every other
/// read failure fails closed. A one-second traversal budget also fails closed.
/// The kernel command name is used instead of cmdline because argv can contain
/// credentials. ASCII replacement prevents controls and invisible Unicode text.
pub(crate) fn scan(root: &Path, uid: u32) -> Snapshot {
    let mut found = Snapshot {
        complete: true,
        ..Snapshot::default()
    };
    let Ok(entries) = std::fs::read_dir(root) else {
        return Snapshot::default();
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    for entry in entries {
        if Instant::now() >= deadline {
            found.complete = false;
            break;
        }
        let Ok(entry) = entry else {
            found.complete = false;
            continue;
        };
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let status = match record(&entry.path().join("status")) {
            Ok(status) => status,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(nix::libc::ENOENT | nix::libc::ESRCH)
                ) =>
            {
                continue;
            }
            Err(_) => {
                found.complete = false;
                continue;
            }
        };
        match belongs(&status, uid) {
            Some(false) => continue,
            None => {
                found.complete = false;
                continue;
            }
            Some(true) => {}
        }
        let command = record(&entry.path().join("comm")).unwrap_or_else(|_| "?".to_owned());
        let command: String = command
            .trim_end_matches('\n')
            .chars()
            .take(64)
            .map(|c| {
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '\u{fffd}'
                }
            })
            .collect();
        if found.processes.len() < 64 {
            found.processes.push(format!("{pid} {command}"));
        }
    }
    found.processes.sort_unstable();
    found
}

#[cfg(test)]
mod tests {
    //! UID and presentation checks that never inspect or stop real host processes.
    use super::*;

    /// Saved and filesystem UIDs still grant account powers; malformed records prove nothing.
    #[test]
    fn every_uid_column_counts_and_unknown_records_fail_closed() {
        assert_eq!(belongs("Uid:\t0\t0\t42\t0\n", 42), Some(true));
        assert_eq!(belongs("Uid:\t0\t0\t0\t42\n", 42), Some(true));
        assert_eq!(belongs("Uid:\t7\t7\t7\t7\n", 42), Some(false));
        assert_eq!(belongs("Uid:\t42\tbad\t42\t42\n", 42), None);
        assert_eq!(belongs("Uid:\t42\n", 42), None);
        assert_eq!(belongs("Name:\tworker\n", 42), None);
    }

    /// Process evidence is bounded and printable, while missing process state is never clean.
    #[test]
    fn process_evidence_is_bounded_and_unreadable_state_is_uncertain() {
        let root = nix::unistd::mkdtemp("/tmp/rvp-XXXXXX").unwrap();
        for pid in 1..=70 {
            let process = root.join(pid.to_string());
            std::fs::create_dir(&process).unwrap();
            std::fs::write(process.join("status"), "Uid:\t42\t42\t42\t42\n").unwrap();
            std::fs::write(
                process.join("comm"),
                format!("{}\u{1b}\u{202e}\n", "a".repeat(80)),
            )
            .unwrap();
        }
        let found = scan(&root, 42);
        assert!(!found.empty());
        assert_eq!(found.processes.len(), 64);
        assert!(found.processes.iter().all(|row| row.len() <= 67));
        assert!(scan(&root, 99).empty());
        std::fs::remove_file(root.join("1/status")).unwrap();
        std::fs::create_dir(root.join("1/status")).unwrap();
        assert!(!scan(&root, 99).empty());
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!scan(&root, 42).empty());
    }
}
