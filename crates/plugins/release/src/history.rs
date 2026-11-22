//! The update history (#211 S5): a short, bounded list of what the updater did, for the Updates row.
//!
//! It lives in `updates/history.json` beside `state.json`, for the same reason: S4's D295 undo
//! restores the pre-update database copy, and that restore must not erase the record of the update
//! that was undone. The file keeps the newest [`KEEP`] entries, newest last, and is replaced
//! atomically, so a reader sees the old or the new list, never a torn one. A missing or malformed
//! file reads as an empty history: the history is a convenience, never a gate.
//!
//! The updater records what it does itself: a release staged, a staged release removed, and every
//! switch outcome (`applied`, `rolled_back` for an undo or a manual roll back, `failed`). All of
//! them are written where `state.json` changes, in `UpdateLock::write_state` (J1130).
use serde::{Deserialize, Serialize};
use std::path::Path;

/// How many entries the file keeps.
pub const KEEP: usize = 30;
/// The largest history file the reader accepts (30 short entries are about 6 KiB).
const MAX_BYTES: u64 = 32 * 1024;

/// What happened to a release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A verified release was downloaded and staged (nothing was applied).
    Staged,
    /// A staged release was thrown away without being applied; `detail` says why.
    Removed,
    /// The server switched to this version and it passed its health check.
    Applied,
    /// The server went back to the previous version; `detail` says why and what data was lost.
    RolledBack,
    /// An update failed before or during the switch; `detail` says why.
    Failed,
}

/// One line of the history. Times are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// When it happened.
    pub at: i64,
    /// What happened.
    pub kind: Kind,
    /// The release it happened to, when known (a label for a failed or removed folder).
    pub version: Option<String>,
    /// A plain, fixed sentence saying why, when there is something to say.
    pub detail: Option<String>,
}

/// Read the history of the server whose data folder is `data`, oldest first.
/// A missing, oversized, unreadable or malformed file is an empty history.
#[must_use]
pub fn read(data: &Path) -> Vec<Entry> {
    read_in(&data.join("updates"))
}

/// [`read`] for the `updates/` folder itself.
pub(crate) fn read_in(directory: &Path) -> Vec<Entry> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(directory.join("history.json"))
    else {
        return Vec::new();
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if file.take(MAX_BYTES + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > MAX_BYTES {
        return Vec::new();
    }
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// Add `entry` to the history in the `updates/` folder `directory`, dropping the oldest entries
/// beyond [`KEEP`]. Callers hold the folder lock (the updater always does), so two writers never
/// race. A failure is ignored on purpose: a history that cannot be written must never fail an update.
pub fn append(directory: &Path, entry: Entry) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut all = read_in(directory);
    all.push(entry);
    if all.len() > KEEP {
        all.drain(..all.len() - KEEP);
    }
    let temporary = directory.join("history.json.tmp");
    let _ = std::fs::remove_file(&temporary);
    let Ok(bytes) = serde_json::to_vec(&all) else {
        return;
    };
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temporary)
        .and_then(|mut file| file.write_all(&bytes).and_then(|()| file.sync_all()));
    if written.is_ok() {
        let _ = std::fs::rename(&temporary, directory.join("history.json"));
    }
}

/// The current time in Unix seconds (0 if the clock is before 1970).
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
/// Checks the bounded list and the tolerant reader.
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// A staged-release entry at time `at`, for filling the list.
    fn entry(at: i64, kind: Kind) -> Entry {
        Entry {
            at,
            kind,
            version: Some("1.2.3".into()),
            detail: None,
        }
    }

    /// The list keeps the newest entries in order and survives a missing or garbled file.
    #[test]
    fn keeps_the_newest_entries_and_tolerates_a_bad_file() {
        let dir = std::env::temp_dir().join(format!("hist-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(read_in(&dir).len(), 0);
        let keep = i64::try_from(KEEP).unwrap();
        for at in 0..(keep + 5) {
            append(&dir, entry(at, Kind::Staged));
        }
        let all = read_in(&dir);
        assert_eq!(all.len(), KEEP);
        assert_eq!((all[0].at, all[KEEP - 1].at), (5, keep + 4));
        std::fs::write(dir.join("history.json"), b"not json").unwrap();
        assert_eq!(read_in(&dir).len(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
