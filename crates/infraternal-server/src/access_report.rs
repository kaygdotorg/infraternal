//! D356's access report on the server: the access files of a host account that
//! changed since a person's login was granted, as the infraternal agent
//! returned them when it revoked that login.
//!
//! A host is less trusted than the server, so the server bounds and cleans the
//! report again on arrival instead of relying on the agent's own bounds:
//! at most `FILES` files and `LINES` lines in total, each path, line and note
//! cut to its character limit, and control and bidirectional-override
//! characters replaced, so that printing a report can never drive a terminal
//! or reorder what the owner reads. Anything cut sets `truncated`.
//!
//! The report holds file paths and line text only. It is stored per host and
//! person in the same transaction that confirms the revocation, read only by
//! the owner, and never logged.
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Most files kept from one report (the agent's own bound).
const FILES: usize = 64;
/// Most lines kept across all files of one report (the agent's own bound).
const LINES: usize = 64;
/// Characters kept of one line, before the cut mark.
const LINE_CHARS: usize = 200;
/// Characters kept of one path, before the cut mark.
const PATH_CHARS: usize = 256;
/// Characters kept of one note, before the cut mark.
const NOTE_CHARS: usize = 200;
/// Largest stored report in bytes; the table checks the same bound.
pub(crate) const STORED_BYTES: usize = 32 * 1024;

/// Access files changed since the grant. `truncated` says that the agent or
/// the server left some out.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessReport {
    /// The changed files, in the agent's order.
    pub(crate) files: Vec<AccessFile>,
    /// Whether the agent or the server left changes out.
    pub(crate) truncated: bool,
}

/// One changed access file: its path under the account's home, its new or
/// changed lines, and a note when it could not be compared line by line.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessFile {
    /// The path under the account's home, such as `~/.bashrc`.
    pub(crate) path: String,
    /// The new or changed lines.
    pub(crate) lines: Vec<String>,
    /// Why the file has no lines, such as a symbolic link that was not followed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
}

/// What the owner can read about one host's revoked logins.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reading {
    /// The revocation has not been confirmed by the host yet.
    Pending,
    /// The revocation is confirmed, and these reports were returned with it.
    Ready(Vec<(Uuid, AccessReport)>),
    /// No access file changed since the grant, or no revocation of this host
    /// has run yet.
    None,
}

/// Replace characters that could drive a terminal or reorder text.
fn printable(text: &str, limit: usize, cut: &mut bool) -> String {
    let mut out = String::new();
    for (index, c) in text.chars().enumerate() {
        if index == limit {
            out.push('…');
            *cut = true;
            break;
        }
        let bidi = matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        out.push(if c.is_control() || bidi {
            '\u{fffd}'
        } else {
            c
        });
    }
    out
}

impl AccessReport {
    /// The report as the server keeps it: bounded, printable, and marked
    /// `truncated` when anything was cut. Empty files are kept only with a
    /// note, because a path alone tells the owner nothing.
    #[must_use]
    pub(crate) fn bounded(self) -> Self {
        let mut cut = self.truncated || self.files.len() > FILES;
        let mut budget = LINES;
        let mut files = Vec::new();
        for file in self.files.into_iter().take(FILES) {
            let keep = file.lines.len().min(budget);
            cut |= keep < file.lines.len();
            budget -= keep;
            let lines: Vec<String> = file
                .lines
                .iter()
                .take(keep)
                .map(|line| printable(line, LINE_CHARS, &mut cut))
                .collect();
            let note = file.note.map(|note| printable(&note, NOTE_CHARS, &mut cut));
            if lines.is_empty() && note.is_none() {
                continue;
            }
            files.push(AccessFile {
                path: printable(&file.path, PATH_CHARS, &mut cut),
                lines,
                note,
            });
        }
        let mut report = Self {
            files,
            truncated: cut,
        };
        // Four-byte characters and JSON escapes can still pass the byte
        // bound; drop lines from the end until the report fits.
        while report.json().len() > STORED_BYTES {
            report.truncated = true;
            let Some(last) = report.files.last_mut() else {
                break;
            };
            if last.lines.pop().is_none() || (last.lines.is_empty() && last.note.is_none()) {
                report.files.pop();
            }
        }
        report
    }

    /// Whether the owner has anything to read.
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty() && !self.truncated
    }

    /// The stored form; serializing these plain fields cannot fail.
    fn json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Keep `report` for `host` and `person` inside the transaction that confirms
/// the revocation, so a confirmed revocation never loses its report. An empty
/// report removes an older one.
pub(crate) async fn store(
    transaction: &mut sqlx::SqliteConnection,
    host: Uuid,
    person: Uuid,
    report: Option<&AccessReport>,
    now: i64,
) -> Result<(), sqlx::Error> {
    match report.filter(|report| !report.is_empty()) {
        Some(report) => {
            sqlx::query("INSERT INTO remote_access_reports(host_id,person_id,report,recorded_at) VALUES(?,?,?,?) ON CONFLICT(host_id,person_id) DO UPDATE SET report=excluded.report, recorded_at=excluded.recorded_at")
                .bind(host.as_bytes().as_slice())
                .bind(person.to_string())
                .bind(report.json())
                .bind(now)
                .execute(&mut *transaction)
                .await?;
        }
        None => {
            sqlx::query("DELETE FROM remote_access_reports WHERE host_id=? AND person_id=?")
                .bind(host.as_bytes().as_slice())
                .bind(person.to_string())
                .execute(&mut *transaction)
                .await?;
        }
    }
    Ok(())
}

/// The reports of `host` for its owner `owner`, or `None` when the host is not
/// theirs (the caller answers that as not found).
pub(crate) async fn read(
    pool: &SqlitePool,
    owner: &str,
    host: Uuid,
) -> Result<Option<Reading>, sqlx::Error> {
    let state: Option<(Option<i64>,)> = sqlx::query_as(
        "SELECT q.confirmed FROM remote_hosts h LEFT JOIN remote_login_cleanup q ON q.host_id=h.id WHERE h.id=? AND h.owner_id=?",
    )
    .bind(host.as_bytes().as_slice())
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    let Some((confirmed,)) = state else {
        return Ok(None);
    };
    if confirmed == Some(0) {
        return Ok(Some(Reading::Pending));
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT person_id,report FROM remote_access_reports WHERE host_id=? ORDER BY recorded_at,person_id LIMIT 16",
    )
    .bind(host.as_bytes().as_slice())
    .fetch_all(pool)
    .await?;
    let reports: Vec<(Uuid, AccessReport)> = rows
        .into_iter()
        .filter_map(|(person, report)| {
            // Stored reports were bounded on the way in; a row that no longer
            // decodes is skipped rather than shown half-read.
            Some((
                Uuid::parse_str(&person).ok()?,
                serde_json::from_str(&report).ok()?,
            ))
        })
        .collect();
    Ok(Some(if reports.is_empty() {
        Reading::None
    } else {
        Reading::Ready(reports)
    }))
}

#[cfg(test)]
mod tests {
    //! Bounds and cleaning of a host's report before the server keeps it.
    use super::*;

    /// A reported file with `lines` and no note.
    fn file(path: &str, lines: &[&str]) -> AccessFile {
        AccessFile {
            path: path.to_owned(),
            lines: lines.iter().map(|line| (*line).to_owned()).collect(),
            note: None,
        }
    }

    /// A host cannot make a stored report drive the owner's terminal or
    /// reorder its text: escapes and bidirectional overrides are replaced.
    #[test]
    fn control_and_bidi_characters_never_reach_the_owner() {
        let report = AccessReport {
            files: vec![file(
                "~/.bashrc\u{1b}[2J",
                &[
                    "curl x | sh\u{1b}]0;title\u{7}",
                    "safe\u{202e}txt.exe",
                    "tab\there",
                ],
            )],
            truncated: false,
        }
        .bounded();
        let text = report.json();
        for bad in ['\u{1b}', '\u{7}', '\u{202e}', '\t'] {
            assert!(
                !text.contains(bad),
                "{bad:?} reached the stored report: {text}"
            );
        }
        assert_eq!(
            report.files[0].lines[0],
            "curl x | sh\u{fffd}]0;title\u{fffd}"
        );
        assert!(!report.truncated, "cleaning is not cutting");
    }

    /// A host that ignores the agent's bounds is cut to them, and the cut is
    /// said: at most `FILES` files and `LINES` lines, each line shortened.
    #[test]
    fn an_oversized_report_is_bounded_and_says_so() {
        let long = "x".repeat(LINE_CHARS * 4);
        let lines: Vec<&str> = std::iter::repeat_n(long.as_str(), 40).collect();
        let report = AccessReport {
            files: (0..FILES * 2)
                .map(|index| file(&format!("~/f{index}"), &lines))
                .collect(),
            truncated: false,
        }
        .bounded();
        assert!(report.truncated);
        assert!(report.files.len() <= FILES);
        assert!(
            report
                .files
                .iter()
                .map(|file| file.lines.len())
                .sum::<usize>()
                <= LINES
        );
        assert!(
            report
                .files
                .iter()
                .flat_map(|file| &file.lines)
                .all(|line| line.chars().count() <= LINE_CHARS + 1)
        );
        assert!(report.json().len() <= STORED_BYTES);
    }

    /// Lines made only of four-byte characters (64 x 200 x 4 bytes is past
    /// 32 KiB) still fit the stored bound, with the cut said.
    #[test]
    fn wide_characters_cannot_push_a_report_past_the_stored_bound() {
        let wide = "\u{1f600}".repeat(LINE_CHARS);
        let report = AccessReport {
            files: vec![file("~/.zshrc", &vec![wide.as_str(); LINES])],
            truncated: false,
        }
        .bounded();
        assert!(
            report.json().len() <= STORED_BYTES,
            "{}",
            report.json().len()
        );
        assert!(report.truncated);
    }
}
