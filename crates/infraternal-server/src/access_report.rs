//! D356's access report on the server: what the infraternal agent found in a
//! person's access files when it revoked their logins, per host account.
//!
//! Every confirmed revocation keeps one report per host and person, with one
//! of three outcomes, so the owner is never told "nothing changed" for
//! something that was not checked:
//! - `changed`: these files changed since the grant;
//! - `unchanged`: checked, nothing changed;
//! - `not_checked`, with a reason: the agent had no record from the grant,
//!   the host runs rootless so the person could have changed the record
//!   (D18), the agent is older than D356 and sent nothing, the agent was
//!   removed before it could answer, or the revocation predates these
//!   reports.
//!
//! A host is less trusted than the server, so the server bounds and cleans
//! the report again on arrival: counts of accounts, files and lines, the
//! length of every string (cut in the middle, saying how much was cut),
//! and control, bidirectional and invisible format characters replaced, so
//! printing a report can never drive a terminal or hide or reorder text.
//! Files over the bounds are counted, never dropped silently. D353's warning
//! (background programs may remain) is kept with the report.
//!
//! A report holds account names, file paths, line text and notes only. It is
//! stored in the transaction that confirms the revocation, read only by the
//! owner inside the admin window, and never logged.
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Accounts kept from one report.
const ACCOUNTS: usize = 64;
/// Files listed across all accounts of one report; more are counted.
const FILES: usize = 256;
/// Lines kept across all files of one report.
const LINES: usize = 64;
/// Characters kept of one line (the agent already cuts at about 230).
const LINE_CHARS: usize = 400;
/// Characters kept of one path, note, warning or not-scanned name.
const TEXT_CHARS: usize = 400;
/// Characters kept of an account name.
const ACCOUNT_CHARS: usize = 64;
/// Not-scanned names kept per account.
const UNSCANNED: usize = 32;
/// Largest stored report in bytes; the table checks the same bound.
pub(crate) const STORED_BYTES: usize = 32 * 1024;
/// What the owner is told when anything was cut from a file's lines.
const MORE_LINES: &str = "more new lines than the report shows";

/// An outcome, for one account or for the whole report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    /// Checked; nothing changed since the grant.
    Unchanged,
    /// Checked; these files changed.
    Changed,
    /// Not checked, for `reason`.
    #[default]
    NotChecked,
}

/// Why something was not checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    /// The agent had no record from the grant.
    RecordMissing,
    /// A rootless host: the person could have changed the record (D18).
    RootlessUnverified,
    /// The agent predates D356 and sent no report.
    OlderAgent,
    /// The agent was removed before it could answer.
    AgentRemoved,
    /// The revocation was confirmed before these reports were kept.
    NotRecorded,
}

/// Whether a file is new since the grant or was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChangeKind {
    /// Not there at the grant.
    Added,
    /// There at the grant, different now.
    Changed,
}

/// One changed access file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessFile {
    /// Its path under the account's home, or `crontab`, `at job …`.
    pub(crate) path: String,
    /// New or changed.
    pub(crate) change: ChangeKind,
    /// Its new lines, when the agent could show them.
    pub(crate) lines: Vec<String>,
    /// What lines cannot show: a link's target, a mode, a size, a cut.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
}

/// The outcome for one host account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountReport {
    /// The account's name.
    pub(crate) account: String,
    /// Its outcome.
    pub(crate) state: State,
    /// Why it was not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<Reason>,
    /// The changed files.
    pub(crate) files: Vec<AccessFile>,
    /// Something was left out.
    pub(crate) truncated: bool,
    /// What was not scanned.
    #[serde(default)]
    pub(crate) unscanned: Vec<String>,
    /// Changed files not listed.
    #[serde(default)]
    pub(crate) omitted_files: u64,
}

/// One person's report from one host.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessReport {
    /// The overall outcome.
    pub(crate) state: State,
    /// Why, when not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<Reason>,
    /// Each account.
    pub(crate) accounts: Vec<AccountReport>,
    /// D353: background programs of an account may still be running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) warning: Option<String>,
}

/// What the owner can read about one host's revoked logins.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reading {
    /// A revocation is waiting for the host to confirm it.
    Pending,
    /// Confirmed revocations, with each person's report.
    Reported(Vec<(Uuid, AccessReport)>),
    /// No revocation has run on this host.
    NotRevoked,
}

/// Whether `c` could drive a terminal or hide or reorder text: controls,
/// and the invisible format characters (Unicode category Cf), which include
/// every bidirectional mark, override and isolate.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

/// `text` made printable and at most `limit` characters: hidden characters
/// replaced, and a longer text cut in the middle, saying how much was cut,
/// so its end stays visible.
fn printable(text: &str, limit: usize, cut: &mut bool) -> String {
    let clean: Vec<char> = text
        .chars()
        .map(|c| if hidden(c) { '\u{fffd}' } else { c })
        .collect();
    if clean.len() <= limit {
        return clean.into_iter().collect();
    }
    *cut = true;
    let half = limit / 2;
    let head: String = clean[..half].iter().collect();
    let tail: String = clean[clean.len() - half..].iter().collect();
    format!(
        "{head} …[{} characters cut]… {tail}",
        clean.len() - 2 * half
    )
}

/// Adds `more` to a file's note once.
fn note_more(note: &mut Option<String>, more: &str) {
    match note {
        Some(note) if note.contains(more) => {}
        Some(note) => {
            note.push_str("; ");
            note.push_str(more);
        }
        None => *note = Some(more.to_owned()),
    }
}

impl AccessReport {
    /// A report for something not checked, for `reason`.
    pub(crate) fn not_checked(reason: Reason) -> Self {
        Self {
            state: State::NotChecked,
            reason: Some(reason),
            accounts: Vec::new(),
            warning: None,
        }
    }

    /// The report as the server keeps it: bounded, printable, consistent
    /// (an account listing files never reads "unchanged"), and marked
    /// truncated when anything was cut. Files past the bounds are counted.
    #[must_use]
    pub(crate) fn bounded(mut self) -> Self {
        let mut ignored = false;
        self.warning = self
            .warning
            .map(|warning| printable(&warning, TEXT_CHARS, &mut ignored));
        if self.accounts.len() > ACCOUNTS {
            self.accounts.truncate(ACCOUNTS);
        }
        let mut files_left = FILES;
        let mut lines_left = LINES;
        for account in &mut self.accounts {
            let mut cut = account.truncated;
            account.account = printable(&account.account, ACCOUNT_CHARS, &mut cut);
            if account.unscanned.len() > UNSCANNED {
                account.unscanned.truncate(UNSCANNED);
                cut = true;
            }
            for name in &mut account.unscanned {
                *name = printable(name, TEXT_CHARS, &mut cut);
            }
            if account.files.len() > files_left {
                let dropped = account.files.len() - files_left;
                account.files.truncate(files_left);
                account.omitted_files = account
                    .omitted_files
                    .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
                cut = true;
            }
            files_left -= account.files.len();
            for file in &mut account.files {
                file.path = printable(&file.path, TEXT_CHARS, &mut cut);
                file.note = file
                    .note
                    .take()
                    .map(|note| printable(&note, TEXT_CHARS, &mut cut));
                if file.lines.len() > lines_left {
                    file.lines.truncate(lines_left);
                    note_more(&mut file.note, MORE_LINES);
                    cut = true;
                }
                lines_left -= file.lines.len();
                for line in &mut file.lines {
                    *line = printable(line, LINE_CHARS, &mut cut);
                }
            }
            if account.state == State::Unchanged
                && (!account.files.is_empty() || account.omitted_files > 0)
            {
                account.state = State::Changed;
            }
            account.truncated = cut;
        }
        self.settle();
        while self.json().len() > STORED_BYTES && self.trim() {}
        self
    }

    /// The overall outcome from the accounts: changed if any changed, else
    /// not checked if any was not checked (or there is no account and the
    /// report did not already say why), else unchanged.
    fn settle(&mut self) {
        let unchecked = self
            .accounts
            .iter()
            .find(|account| account.state == State::NotChecked)
            .map(|account| account.reason);
        if self.accounts.iter().any(|a| a.state == State::Changed)
            && self.state != State::NotChecked
        {
            self.state = State::Changed;
            self.reason = None;
        } else if let Some(reason) = unchecked {
            self.state = State::NotChecked;
            self.reason = self.reason.or(reason);
        } else if self.accounts.is_empty() {
            self.state = State::NotChecked;
            self.reason = self.reason.or(Some(Reason::RecordMissing));
        } else if self.state != State::NotChecked {
            self.state = State::Unchanged;
            self.reason = None;
        }
    }

    /// Drops one line, or failing that one file (counted), from the end.
    fn trim(&mut self) -> bool {
        for account in self.accounts.iter_mut().rev() {
            if let Some(file) = account.files.iter_mut().rev().find(|f| !f.lines.is_empty()) {
                file.lines.pop();
                note_more(&mut file.note, MORE_LINES);
                account.truncated = true;
                return true;
            }
        }
        for account in self.accounts.iter_mut().rev() {
            if account.files.pop().is_some() {
                account.omitted_files = account.omitted_files.saturating_add(1);
                account.truncated = true;
                return true;
            }
        }
        for account in self.accounts.iter_mut().rev() {
            if account.unscanned.pop().is_some() {
                account.truncated = true;
                return true;
            }
        }
        false
    }

    /// The stored form; serializing these plain fields cannot fail.
    fn json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Keeps `report` for `host` and `person` inside the transaction that
/// confirms the revocation, so a confirmed revocation always has one.
pub(crate) async fn store(
    transaction: &mut sqlx::SqliteConnection,
    host: Uuid,
    person: Uuid,
    report: &AccessReport,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO remote_access_reports(host_id,person_id,report,recorded_at) VALUES(?,?,?,?) ON CONFLICT(host_id,person_id) DO UPDATE SET report=excluded.report, recorded_at=excluded.recorded_at")
        .bind(host.as_bytes().as_slice())
        .bind(person.to_string())
        .bind(report.json())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    Ok(())
}

/// The reports of `host` for its owner `owner`, or `None` when the host is not
/// theirs (the caller answers that as not found).
pub(crate) async fn read(
    pool: &SqlitePool,
    owner: &str,
    host: Uuid,
) -> Result<Option<Reading>, sqlx::Error> {
    let state: Option<(bool, Option<String>)> = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0), (SELECT q.person_id FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=1 ORDER BY q.person_id LIMIT 1) FROM remote_hosts h WHERE h.id=? AND h.owner_id=?",
    )
    .bind(host.as_bytes().as_slice())
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    let Some((pending, confirmed)) = state else {
        return Ok(None);
    };
    if pending {
        return Ok(Some(Reading::Pending));
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT person_id,report FROM remote_access_reports WHERE host_id=? ORDER BY recorded_at,person_id LIMIT 16",
    )
    .bind(host.as_bytes().as_slice())
    .fetch_all(pool)
    .await?;
    let mut reports: Vec<(Uuid, AccessReport)> = rows
        .into_iter()
        .filter_map(|(person, report)| {
            let person = Uuid::parse_str(&person).ok()?;
            // Stored reports were bounded on the way in; one that no longer
            // decodes reads as not checked rather than half-read.
            let report = serde_json::from_str(&report)
                .unwrap_or_else(|_| AccessReport::not_checked(Reason::NotRecorded));
            Some((person, report))
        })
        .collect();
    if reports.is_empty()
        && let Some(person) = confirmed.and_then(|person| Uuid::parse_str(&person).ok())
    {
        reports.push((person, AccessReport::not_checked(Reason::NotRecorded)));
    }
    Ok(Some(if reports.is_empty() {
        Reading::NotRevoked
    } else {
        Reading::Reported(reports)
    }))
}

#[cfg(test)]
mod tests {
    //! Bounds, cleaning and outcomes of a host's report before the server keeps it.
    use super::*;

    /// A changed file with `lines`.
    fn file(path: &str, lines: &[&str]) -> AccessFile {
        AccessFile {
            path: path.to_owned(),
            change: ChangeKind::Changed,
            lines: lines.iter().map(|line| (*line).to_owned()).collect(),
            note: None,
        }
    }

    /// One account with `files`, as the agent reports it.
    fn report(state: State, files: Vec<AccessFile>) -> AccessReport {
        AccessReport {
            state,
            reason: None,
            accounts: vec![AccountReport {
                account: "deploy".to_owned(),
                state,
                reason: None,
                files,
                truncated: false,
                unscanned: Vec::new(),
                omitted_files: 0,
            }],
            warning: None,
        }
    }

    /// A host cannot make a stored report drive the owner's terminal, or
    /// hide or reorder its text: controls, bidirectional marks and invisible
    /// format characters (J322 P3: U+061C, U+200B, U+2060, U+FEFF) are
    /// replaced in every string.
    #[test]
    fn hidden_characters_never_reach_the_owner() {
        let mut report = report(
            State::Changed,
            vec![file(
                "~/.bashrc\u{1b}[2J",
                &[
                    "curl x | sh\u{1b}]0;title\u{7}",
                    "safe\u{202e}txt.exe",
                    "a\u{61c}b\u{200b}c\u{2060}d\u{feff}e",
                ],
            )],
        );
        report.warning = Some("still running\u{1b}[31m".into());
        let report = report.bounded();
        let text = report.json();
        for bad in [
            '\u{1b}', '\u{7}', '\u{202e}', '\u{61c}', '\u{200b}', '\u{2060}', '\u{feff}',
        ] {
            assert!(
                !text.contains(bad),
                "{bad:?} reached the stored report: {text}"
            );
        }
        assert_eq!(
            report.accounts[0].files[0].lines[0],
            "curl x | sh\u{fffd}]0;title\u{fffd}"
        );
        assert!(!report.accounts[0].truncated, "cleaning is not cutting");
    }

    /// A host that ignores the agent's bounds is cut to them and says so:
    /// lines past the limit are noted, files past it are counted, and a long
    /// line keeps its end with the cut said.
    #[test]
    fn an_oversized_report_is_bounded_and_counts_what_it_drops() {
        let long = format!("{}; curl x | sh", "x".repeat(LINE_CHARS * 3));
        let lines: Vec<&str> = std::iter::repeat_n(long.as_str(), 40).collect();
        let files = (0..FILES + 10)
            .map(|index| file(&format!("~/f{index}"), &lines))
            .collect();
        let report = report(State::Changed, files).bounded();
        let account = &report.accounts[0];
        assert!(account.truncated);
        assert!(account.omitted_files >= 10, "{}", account.omitted_files);
        let shown: Vec<_> = account.files.iter().flat_map(|file| &file.lines).collect();
        assert!(shown.len() <= LINES);
        assert!(shown[0].ends_with("; curl x | sh"), "{}", shown[0]);
        assert!(shown[0].contains("characters cut]"), "{}", shown[0]);
        assert!(
            account
                .files
                .iter()
                .any(|f| f.note.as_deref().unwrap_or("").contains(MORE_LINES))
        );
        assert!(report.json().len() <= STORED_BYTES);
    }

    /// Four-byte characters cannot push a report past the stored bound.
    #[test]
    fn wide_characters_cannot_push_a_report_past_the_stored_bound() {
        let wide = "\u{1f600}".repeat(LINE_CHARS);
        let report = report(
            State::Changed,
            vec![file("~/.zshrc", &vec![wide.as_str(); LINES])],
        )
        .bounded();
        assert!(
            report.json().len() <= STORED_BYTES,
            "{}",
            report.json().len()
        );
        assert!(report.accounts[0].truncated);
    }

    /// The owner is never told "unchanged" next to listed files, and a report
    /// with no account is "not checked", never "unchanged".
    #[test]
    fn unchanged_is_only_said_when_nothing_was_listed() {
        let listed = report(State::Unchanged, vec![file("~/.bashrc", &["x"])]).bounded();
        assert_eq!(listed.state, State::Changed);
        assert_eq!(listed.accounts[0].state, State::Changed);
        let empty = AccessReport {
            state: State::Unchanged,
            ..AccessReport::default()
        }
        .bounded();
        assert_eq!(empty.state, State::NotChecked);
        assert_eq!(empty.reason, Some(Reason::RecordMissing));
        let clean = report(State::Unchanged, Vec::new()).bounded();
        assert_eq!(clean.state, State::Unchanged);
    }
}
