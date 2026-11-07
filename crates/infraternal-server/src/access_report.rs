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
/// Reports returned per host; the rest are counted (J334 P2-5).
pub(crate) const SHOWN: i64 = 16;
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
    /// The account is root or may become root (J334 P1-4).
    Privileged,
    /// Something was not scanned (J334 P1-1).
    Incomplete,
    /// The account's programs may still run and change its files (P2-1).
    ProgramsMayRemain,
    /// Recording the grant failed (P2-7).
    RecordFailed,
    /// The agent watches fewer places than this server expects.
    CoverageMissing,
}

/// Whether a file is new since the grant or was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChangeKind {
    /// Not there at the grant.
    Added,
    /// There at the grant, different now.
    Changed,
    /// There at the grant, gone now.
    Removed,
}

/// One changed access file. Unknown fields inside a report are ignored
/// (J334 P3: a future field must not make a revocation a protocol error);
/// the revoke reply's envelope stays strict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// The outcome for one host account. Each flag is an independent fact the
/// outcome rule reads, so they stay separate fields.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The agent scanned every watched place, at the grant and now.
    #[serde(default)]
    pub(crate) complete: bool,
    /// How many watched places the report covers.
    #[serde(default)]
    pub(crate) watched: u64,
    /// Root, or may become root.
    #[serde(default)]
    pub(crate) privileged: bool,
    /// Other people still have access to the account.
    #[serde(default)]
    pub(crate) shared: bool,
    /// The account's programs may still run after the revoke.
    #[serde(default)]
    pub(crate) programs_may_remain: bool,
    /// When the grant was recorded (seconds since the epoch; 0 if unknown).
    #[serde(default)]
    pub(crate) recorded_at: u64,
    /// When the account was scanned.
    #[serde(default)]
    pub(crate) scanned_at: u64,
}

/// One person's report from one host.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Confirmed revocations: the newest reports, how many more there are,
    /// and the outcome over all of them (never only the ones shown).
    Reported {
        /// The newest reports, at most [`SHOWN`].
        reports: Vec<(Uuid, AccessReport)>,
        /// Reports not shown.
        more: u64,
        /// Changed if any report changed, else not checked if any was not
        /// checked, else unchanged.
        overall: State,
    },
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
            account.truncated = cut;
        }
        while self.json().len() > STORED_BYTES && self.trim() {}
        self
    }

    /// THE rule for what the owner is told, applied by the server to every
    /// report it keeps, whatever state the host sent (J334): an account
    /// listing files is `changed`; otherwise it is `not_checked` with the
    /// first reason that applies; only when none does is it `unchanged`.
    /// The reasons, in order: the host runs rootless (taken from the
    /// server's own record of the host, never from the host, P1-3); the
    /// account is privileged (P1-4); anything was not scanned, cut or
    /// omitted, including by the server's own bounds (P1-1, P2-2); the
    /// agent watches fewer places than this server knows of; programs may
    /// still run (P2-1); the record failed or is missing. No account at all
    /// is never `unchanged`.
    #[must_use]
    pub(crate) fn decided(mut self, rootless: bool) -> Self {
        let watched =
            u64::try_from(infraternal_agent::access_files::WATCHED_PLACES).unwrap_or(u64::MAX);
        for account in &mut self.accounts {
            let reason = if rootless {
                Some(Reason::RootlessUnverified)
            } else if account.privileged {
                Some(Reason::Privileged)
            } else if !account.complete
                || account.truncated
                || account.omitted_files > 0
                || !account.unscanned.is_empty()
            {
                Some(Reason::Incomplete)
            } else if account.watched < watched {
                Some(Reason::CoverageMissing)
            } else if account.programs_may_remain {
                Some(Reason::ProgramsMayRemain)
            } else {
                account
                    .reason
                    .filter(|reason| matches!(reason, Reason::RecordMissing | Reason::RecordFailed))
            };
            // A record the agent did not have is never "complete": keep its
            // own reason ahead of "incomplete".
            let reason = match account.reason {
                Some(own @ (Reason::RecordMissing | Reason::RecordFailed)) if !rootless => {
                    Some(own)
                }
                _ => reason,
            };
            if !account.files.is_empty() || account.omitted_files > 0 {
                account.state = if rootless {
                    State::NotChecked
                } else {
                    State::Changed
                };
                account.reason = reason.filter(|_| rootless);
            } else if let Some(reason) = reason {
                account.state = State::NotChecked;
                account.reason = Some(reason);
            } else {
                account.state = State::Unchanged;
                account.reason = None;
            }
        }
        let unchecked = self
            .accounts
            .iter()
            .find(|account| account.state == State::NotChecked)
            .and_then(|account| account.reason);
        if rootless {
            self.state = State::NotChecked;
            self.reason = Some(Reason::RootlessUnverified);
        } else if self.accounts.iter().any(|a| a.state == State::Changed) {
            self.state = State::Changed;
            self.reason = None;
        } else if let Some(reason) = unchecked {
            self.state = State::NotChecked;
            self.reason = Some(reason);
        } else if self.accounts.is_empty() {
            // Keep the reason the server or agent gave (older agent, agent
            // removed), else say there was no record.
            self.state = State::NotChecked;
            self.reason = self.reason.or(Some(Reason::RecordMissing));
        } else {
            self.state = State::Unchanged;
            self.reason = None;
        }
        self
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
    // Newest first; the outcome comes from every row, so a hidden report
    // can never leave the headline reading "unchanged" (J334 P2-5).
    let (total, changed, unchecked): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(json_extract(report,'$.state')='changed'),0), coalesce(sum(json_extract(report,'$.state')<>'unchanged' AND json_extract(report,'$.state')<>'changed'),0) FROM remote_access_reports WHERE host_id=?",
    )
    .bind(host.as_bytes().as_slice())
    .fetch_one(pool)
    .await?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT person_id,report FROM remote_access_reports WHERE host_id=? ORDER BY recorded_at DESC,person_id LIMIT ?",
    )
    .bind(host.as_bytes().as_slice())
    .bind(SHOWN)
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
    let mut overall = if changed > 0 {
        State::Changed
    } else if unchecked > 0 {
        State::NotChecked
    } else {
        State::Unchanged
    };
    if reports.is_empty()
        && let Some(person) = confirmed.and_then(|person| Uuid::parse_str(&person).ok())
    {
        reports.push((person, AccessReport::not_checked(Reason::NotRecorded)));
        overall = State::NotChecked;
    }
    Ok(Some(if reports.is_empty() {
        Reading::NotRevoked
    } else {
        Reading::Reported {
            more: u64::try_from(total - i64::try_from(reports.len()).unwrap_or(0)).unwrap_or(0),
            reports,
            overall,
        }
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
                files,
                complete: true,
                watched: u64::try_from(infraternal_agent::access_files::WATCHED_PLACES).unwrap(),
                ..AccountReport::default()
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
            vec![file("~/.zshrc", &[wide.as_str(); LINES])],
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
        let listed = report(State::Unchanged, vec![file("~/.bashrc", &["x"])]).decided(false);
        assert_eq!(listed.state, State::Changed);
        assert_eq!(listed.accounts[0].state, State::Changed);
        let empty = AccessReport {
            state: State::Unchanged,
            ..AccessReport::default()
        }
        .decided(false);
        assert_eq!(empty.state, State::NotChecked);
        assert_eq!(empty.reason, Some(Reason::RecordMissing));
        let older = AccessReport::not_checked(Reason::OlderAgent).decided(false);
        assert_eq!(older.reason, Some(Reason::OlderAgent));
        let clean = report(State::Unchanged, Vec::new()).decided(false);
        assert_eq!(clean.state, State::Unchanged);
    }

    /// J334: each of the four conditions, broken, turns a clean account into
    /// "not checked" with its reason, whatever state the host sent; the
    /// server's own bounds count as incomplete too.
    #[test]
    fn the_server_decides_unchanged_only_when_all_four_conditions_hold() {
        let clean = || report(State::Unchanged, Vec::new());
        let reason = |report: AccessReport, rootless: bool| {
            let report = report.decided(rootless);
            assert_eq!(report.state, State::NotChecked, "{report:?}");
            report.accounts[0].reason
        };
        assert_eq!(reason(clean(), true), Some(Reason::RootlessUnverified));
        let mut privileged = clean();
        privileged.accounts[0].privileged = true;
        assert_eq!(reason(privileged, false), Some(Reason::Privileged));
        let mut incomplete = clean();
        incomplete.accounts[0].unscanned =
            vec!["~/.config/systemd/user (more than 1024 entries)".into()];
        assert_eq!(reason(incomplete, false), Some(Reason::Incomplete));
        let mut partial = clean();
        partial.accounts[0].complete = false;
        assert_eq!(reason(partial, false), Some(Reason::Incomplete));
        let mut older = clean();
        older.accounts[0].watched = 14;
        assert_eq!(reason(older, false), Some(Reason::CoverageMissing));
        let mut remaining = clean();
        remaining.accounts[0].programs_may_remain = true;
        assert_eq!(reason(remaining, false), Some(Reason::ProgramsMayRemain));
        // A host that claims "unchanged" and "complete" with files to show is
        // still "changed".
        let mut claimed = report(State::Unchanged, vec![file("~/.bashrc", &["curl x | sh"])]);
        claimed.accounts[0].reason = None;
        assert_eq!(claimed.decided(false).state, State::Changed);
        // The server's own bound cutting the report makes it incomplete.
        let long = "x".repeat(LINE_CHARS * 2);
        let lines: Vec<&str> = std::iter::repeat_n(long.as_str(), LINES + 1).collect();
        let cut = report(State::Unchanged, vec![file("~/.zshrc", &lines)]).bounded();
        assert!(cut.accounts[0].truncated);
    }

    /// J334 P3: a field this server does not know inside the report is
    /// ignored, so a newer agent's report is still kept.
    #[test]
    fn unknown_fields_inside_a_report_are_ignored() {
        let report: AccessReport = serde_json::from_value(serde_json::json!({
            "state": "changed", "future": 1,
            "accounts": [{"account": "deploy", "state": "changed", "files": [], "truncated": false, "later": true}]
        }))
        .unwrap();
        assert_eq!(report.accounts[0].account, "deploy");
    }
}
