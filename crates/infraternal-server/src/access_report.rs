//! D356's access report on the server: what the infraternal agent found in a
//! person's access files when it revoked their logins, per host account.
//!
//! Revoking a person while the host stays keeps one report per host and
//! person (D398); it reaches the owner as an Inbox item. A host removal keeps
//! none: it deletes infraternal and its state and nothing else, so nothing
//! scans for it. Each report has one of three outcomes, so the owner is never
//! told "nothing changed" for something that was not checked:
//! - `changed`: these files changed since the grant;
//! - `unchanged`: checked, nothing changed;
//! - `not_checked`, with a reason: the agent had no record from the grant,
//!   the host runs rootless so the person could have changed the record
//!   (D18), the agent is older than D356 and sent nothing, or the
//!   revocation predates these reports.
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
//! owner, and never logged.
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
/// Watched categories kept per account, and their length (D360).
const CATEGORIES: usize = 16;
/// Reports returned per host; the rest are counted (J334 P2-5).
pub(crate) const SHOWN: i64 = 16;
/// Largest stored report in bytes; the table checks the same bound.
pub(crate) const STORED_BYTES: usize = 32 * 1024;
/// Bytes [`AccessReport::decided`] may add to one account, or to the report
/// itself, when it rewrites a state and adds its reason: `"unchanged"`
/// becomes `"not_checked"` (+4) and `,"reason":"programs_may_remain"` (31,
/// the longest reason) is new. [`AccessReport::bounded`] keeps this much
/// room per account plus one, so an honest report near the bound keeps its
/// detail once decided; `decided` still enforces the bound itself.
const DECISION_BYTES: usize = 40;
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
    /// How many rows of the agent's watched table the report covers.
    #[serde(default)]
    pub(crate) watched: u64,
    /// Entries observed, separate from the watched-place coverage count.
    #[serde(default)]
    pub(crate) places: u64,
    /// The categories watched, in plain words (D360).
    #[serde(default)]
    pub(crate) categories: Vec<String>,
    /// Root routes the host actually ruled out, never inferred by the server.
    #[serde(default)]
    pub(crate) root_checks: Vec<String>,
    /// Root, or may become root.
    #[serde(default)]
    pub(crate) privileged: bool,
    /// Other people still have access to the account.
    #[serde(default)]
    pub(crate) shared: bool,
    /// The account's programs may still run after the revoke.
    #[serde(default)]
    pub(crate) programs_may_remain: bool,
    /// PIDs and printable kernel command names remaining after the scan (D362).
    #[serde(default)]
    pub(crate) processes: Vec<String>,
    /// System jobs that may write later, or whose root authority is unknown.
    #[serde(default)]
    pub(crate) jobs: Vec<String>,
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
    /// Accounts not listed, kept independently of text trimming.
    #[serde(default)]
    pub(crate) omitted_accounts: u64,
    /// D353: background programs of an account may still be running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) warning: Option<String>,
}

/// One report waiting in the owner's Inbox (D398).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Waiting {
    /// The host the person was revoked on.
    pub(crate) host: Uuid,
    /// The host's name for the owner: its address, or its id when it has none.
    pub(crate) host_name: String,
    /// The revoked person.
    pub(crate) person: Uuid,
    /// When the revocation was confirmed (Unix seconds).
    pub(crate) recorded_at: i64,
    /// What the host reported.
    pub(crate) report: AccessReport,
}

/// What the owner's Inbox holds: the newest waiting reports and how many more
/// there are.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Inbox {
    /// The newest reports, at most [`SHOWN`].
    pub(crate) reports: Vec<Waiting>,
    /// Waiting reports not listed.
    pub(crate) more: u64,
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
            omitted_accounts: 0,
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
            self.omitted_accounts = self
                .omitted_accounts
                .saturating_add(u64::try_from(self.accounts.len() - ACCOUNTS).unwrap_or(u64::MAX));
            self.accounts.truncate(ACCOUNTS);
        }
        if self.omitted_accounts > 0
            && let Some(last) = self.accounts.last_mut()
        {
            last.complete = false;
            last.truncated = true;
        }
        let mut files_left = FILES;
        let mut lines_left = LINES;
        let mut root_check_bytes = STORED_BYTES / 8;
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
            account.programs_may_remain |=
                !account.processes.is_empty() || !account.jobs.is_empty();
            if account.jobs.len() > 64 {
                account.jobs.truncate(64);
                cut = true;
            }
            for job in &mut account.jobs {
                *job = printable(job, TEXT_CHARS, &mut cut);
            }
            account.processes.truncate(64);
            for process in &mut account.processes {
                let mut shortened = false;
                *process = printable(process, 80, &mut shortened);
            }
            account.categories.truncate(CATEGORIES);
            let mut ignored = false;
            for category in &mut account.categories {
                *category = printable(category, ACCOUNT_CHARS, &mut ignored);
            }
            if account.root_checks.len() > CATEGORIES {
                account.root_checks.truncate(CATEGORIES);
                cut = true;
            }
            for check in &mut account.root_checks {
                *check = printable(check, ACCOUNT_CHARS, &mut cut);
            }
            account.root_checks.retain(|check| {
                if let Some(left) = root_check_bytes.checked_sub(check.len()) {
                    root_check_bytes = left;
                    true
                } else {
                    cut = true;
                    false
                }
            });
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
        // Leave room for what `decided` adds, or a report trimmed to just
        // under the bound grows past the table's CHECK once decided.
        let limit = STORED_BYTES
            .saturating_sub(DECISION_BYTES.saturating_mul(self.accounts.len().saturating_add(1)));
        while self.json().len() > limit && self.trim() {}
        if self.json().len() > limit {
            // Nothing trimmable is left, and the fixed per-account fields
            // (name, categories) still exceed what the table accepts. A row
            // over its CHECK would fail the transaction that confirms the
            // revocation, so keep no account detail and count every account
            // as omitted: `decided` then reads "not checked: incomplete".
            self.omitted_accounts = self
                .omitted_accounts
                .saturating_add(u64::try_from(self.accounts.len()).unwrap_or(u64::MAX));
            self.accounts.clear();
        }
        self
    }

    /// THE rule for what the owner is told, applied by the server to every
    /// report it keeps, whatever state the host sent (J334): an account
    /// with remaining programs is `not_checked` (D362), retaining any file
    /// changes for review. Otherwise listed files mean `changed`, or it is
    /// `not_checked` with the
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
        let required_checks = infraternal_agent::access_files::root_check_names();
        for account in &mut self.accounts {
            // An old or incomplete reply cannot claim checks merely because
            // this server knows how to run them in its embedded host runtime.
            account.privileged |= !rootless
                && account.recorded_at > 0
                && required_checks
                    .iter()
                    .any(|check| !account.root_checks.contains(check));
            account.programs_may_remain |=
                !account.processes.is_empty() || !account.jobs.is_empty();
            let reason = if rootless {
                Some(Reason::RootlessUnverified)
            } else if account.recorded_at == 0 {
                Some(Reason::RecordMissing)
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
            if !rootless && account.privileged {
                account.state = State::NotChecked;
                account.reason = Some(Reason::Privileged);
            } else if !rootless && account.programs_may_remain {
                account.state = State::NotChecked;
                account.reason = Some(Reason::ProgramsMayRemain);
            } else if !account.files.is_empty() || account.omitted_files > 0 {
                account.state = if rootless || account.recorded_at == 0 {
                    State::NotChecked
                } else {
                    State::Changed
                };
                account.reason = reason.filter(|_| rootless || account.recorded_at == 0);
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
        } else if self.omitted_accounts > 0 {
            self.state = State::NotChecked;
            self.reason = Some(Reason::Incomplete);
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
        if self.json().len() > STORED_BYTES {
            // `bounded` leaves room for the rewrite above, but this is what
            // the store's CHECK accepts, and a row over it fails the
            // transaction that confirms the revocation, so the removal could
            // never finish. Keep no account detail rather than no receipt.
            self.omitted_accounts = self
                .omitted_accounts
                .saturating_add(u64::try_from(self.accounts.len()).unwrap_or(u64::MAX));
            self.accounts.clear();
            self.state = State::NotChecked;
            self.reason = Some(if rootless {
                Reason::RootlessUnverified
            } else {
                Reason::Incomplete
            });
        }
        self
    }

    /// Drops one line, or failing that one file (counted), from the end.
    fn trim(&mut self) -> bool {
        for account in self.accounts.iter_mut().rev() {
            if !account.jobs.is_empty() {
                account.jobs.truncate(account.jobs.len() / 2);
                account.truncated = true;
                return true;
            }
            if !account.processes.is_empty() {
                account.processes.truncate(account.processes.len() / 2);
                // The surviving-process flag stays true even if its list is shortened.
                return true;
            }
        }
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
        for account in self.accounts.iter_mut().rev() {
            if account.root_checks.pop().is_some() {
                // Missing evidence is privileged when decided; never shorten
                // the claim without invalidating the account's clean result.
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

/// The display name of `person` for the owner reading a report (J323,
/// 84303): the display name, else the name, else the username, cleaned and
/// bounded like every other string shown; `None` for a person no longer on
/// this server.
pub(crate) async fn person_name(
    pool: &SqlitePool,
    person: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let name: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(display_name,''), NULLIF(name,''), username) FROM users WHERE id=?",
    )
    .bind(person.to_string())
    .fetch_optional(pool)
    .await?
    .flatten();
    let mut ignored = false;
    Ok(name.map(|name| printable(&name, ACCOUNT_CHARS, &mut ignored)))
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
    sqlx::query("INSERT INTO remote_access_reports(host_id,person_id,report,recorded_at) VALUES(?,?,?,?) ON CONFLICT(host_id,person_id) DO UPDATE SET report=excluded.report, recorded_at=excluded.recorded_at, seen_at=NULL")
        .bind(host.as_bytes().as_slice())
        .bind(person.to_string())
        .bind(report.json())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    Ok(())
}

/// The reports waiting for `owner` (D398): those of revocations on hosts
/// they own that they have not dismissed, newest first. A stored report that
/// no longer decodes reads as not checked rather than half-read.
pub(crate) async fn inbox(pool: &SqlitePool, owner: &str) -> Result<Inbox, sqlx::Error> {
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM remote_access_reports r JOIN remote_hosts h ON h.id=r.host_id WHERE h.owner_id=? AND r.seen_at IS NULL",
    )
    .bind(owner)
    .fetch_one(pool)
    .await?;
    let rows: Vec<(Vec<u8>, String, i64, String, String)> = sqlx::query_as(
        "SELECT r.host_id, r.person_id, r.recorded_at, r.report, COALESCE(b.address, lower(hex(r.host_id))) FROM remote_access_reports r JOIN remote_hosts h ON h.id=r.host_id LEFT JOIN remote_host_bootstrap b ON b.host_id=r.host_id WHERE h.owner_id=? AND r.seen_at IS NULL ORDER BY r.recorded_at DESC, r.person_id LIMIT ?",
    )
    .bind(owner)
    .bind(SHOWN)
    .fetch_all(pool)
    .await?;
    let reports: Vec<Waiting> = rows
        .into_iter()
        .filter_map(|(host, person, recorded_at, report, name)| {
            let mut ignored = false;
            Some(Waiting {
                host: Uuid::from_slice(&host).ok()?,
                host_name: printable(&name, ACCOUNT_CHARS, &mut ignored),
                person: Uuid::parse_str(&person).ok()?,
                recorded_at,
                report: serde_json::from_str(&report)
                    .unwrap_or_else(|_| AccessReport::not_checked(Reason::NotRecorded)),
            })
        })
        .collect();
    Ok(Inbox {
        more: u64::try_from(total - i64::try_from(reports.len()).unwrap_or(0)).unwrap_or(0),
        reports,
    })
}

/// The owner dismisses the Inbox item of `person` on `host`. `false` when
/// there is no such waiting report on a host they own, so a foreign or
/// repeated dismissal changes nothing.
pub(crate) async fn dismiss(
    pool: &SqlitePool,
    owner: &str,
    host: Uuid,
    person: Uuid,
    now: i64,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE remote_access_reports SET seen_at=? WHERE host_id=? AND person_id=? AND seen_at IS NULL AND EXISTS(SELECT 1 FROM remote_hosts h WHERE h.id=remote_access_reports.host_id AND h.owner_id=?)",
    )
    .bind(now)
    .bind(host.as_bytes().as_slice())
    .bind(person.to_string())
    .bind(owner)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
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
            omitted_accounts: 0,
            accounts: vec![AccountReport {
                account: "deploy".to_owned(),
                recorded_at: 1,
                state,
                files,
                complete: true,
                watched: u64::try_from(infraternal_agent::access_files::WATCHED_PLACES).unwrap(),
                root_checks: infraternal_agent::access_files::root_check_names(),
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
        let mut privileged_changed = report(State::Changed, vec![file("~/.bashrc", &["id"])]);
        privileged_changed.accounts[0].privileged = true;
        privileged_changed.accounts[0].programs_may_remain = true;
        assert_eq!(reason(privileged_changed, false), Some(Reason::Privileged));
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

    /// Old saved reports have no evidence that newly added root routes ran.
    #[test]
    fn missing_root_check_evidence_cannot_be_clean() {
        let sent = serde_json::to_value(report(State::Unchanged, vec![])).unwrap();
        let mut legacy = sent;
        legacy["accounts"][0]
            .as_object_mut()
            .unwrap()
            .remove("root_checks");
        let received: AccessReport = serde_json::from_value(legacy).unwrap();
        assert_eq!(received.decided(false).state, State::NotChecked);
    }

    /// A partial check list cannot hide the missing route, even with files to
    /// show. Malformed display names stay bounded and cannot drive a terminal.
    #[test]
    fn root_check_evidence_is_complete_printable_and_bounded() {
        let mut partial = report(State::Unchanged, vec![file("~/.bashrc", &["id"])]);
        partial.accounts[0].root_checks.pop();
        let partial = partial.decided(false);
        assert_eq!(partial.accounts[0].reason, Some(Reason::Privileged));
        assert_eq!(partial.accounts[0].state, State::NotChecked);
        assert_eq!(partial.accounts[0].files.len(), 1);
        let mut sent = report(State::Unchanged, vec![]);
        sent.accounts[0].root_checks = vec!["sudo\u{1b}[2J".repeat(100); 100];
        let kept = sent.bounded().decided(false);
        assert!(kept.accounts[0].root_checks.len() <= CATEGORIES);
        assert!(!kept.json().contains('\u{1b}'));
        assert_eq!(kept.state, State::NotChecked);
    }

    /// A missing baseline cannot justify a since-time or a clean result.
    #[test]
    fn a_missing_baseline_is_not_checked() {
        for files in [Vec::new(), vec![file("~/.bashrc", &["plant"])]] {
            let mut input = report(State::Unchanged, files);
            input.accounts[0].recorded_at = 0;
            let result = input.decided(false);
            assert_eq!(result.state, State::NotChecked);
        }
    }

    /// A host can fill every account's fixed fields (name, categories) so
    /// that nothing trimmable is left and the report is still over the
    /// store's 32 KiB CHECK. The server must still keep a row it can store,
    /// or the revocation receipt's transaction fails; it keeps no account
    /// detail and reads "not checked".
    #[test]
    fn a_report_over_the_store_bound_after_trimming_is_not_checked() {
        let mut input = report(State::Unchanged, Vec::new());
        input.accounts[0].account = "\u{10348}".repeat(ACCOUNT_CHARS);
        input.accounts[0].categories = vec!["\u{10348}".repeat(ACCOUNT_CHARS); CATEGORIES];
        input.accounts = vec![input.accounts[0].clone(); ACCOUNTS];
        let kept = input.bounded();
        assert!(
            kept.json().len() <= STORED_BYTES,
            "{} bytes would fail the table's CHECK",
            kept.json().len()
        );
        let kept = kept.decided(false);
        assert_eq!(kept.state, State::NotChecked);
        assert_eq!(kept.reason, Some(Reason::Incomplete));
        assert_eq!(kept.omitted_accounts, u64::try_from(ACCOUNTS).unwrap());
    }

    /// A report trimmed to just under the bound grows when `decided` adds
    /// each account's state and reason (J1013). Every decided report, on a
    /// rootless host or with missing root-check evidence, must still fit the
    /// table's CHECK, or the transaction that confirms the revocation fails
    /// on every delivery and the removal never finishes.
    #[test]
    fn a_decided_report_still_fits_the_store() {
        for (rootless, keep_checks) in [(true, true), (false, false), (false, true)] {
            let mut input = report(State::Unchanged, Vec::new());
            input.accounts[0].unscanned = vec!["x".repeat(TEXT_CHARS); UNSCANNED];
            if !keep_checks {
                input.accounts[0].root_checks.clear();
            }
            input.accounts = vec![input.accounts[0].clone(); ACCOUNTS];
            let kept = input.bounded().decided(rootless);
            assert!(
                kept.json().len() <= STORED_BYTES,
                "{} bytes would fail the table's CHECK (rootless {rootless})",
                kept.json().len()
            );
            assert_eq!(kept.state, State::NotChecked);
            assert!(!kept.accounts.is_empty(), "the trimmed detail was kept");
        }
        // `decided` itself enforces the bound for a report that skipped it.
        let mut input = report(State::Unchanged, Vec::new());
        input.accounts[0].unscanned = vec!["x".repeat(TEXT_CHARS); UNSCANNED];
        input.accounts = vec![input.accounts[0].clone(); ACCOUNTS];
        let kept = input.decided(false);
        assert!(kept.json().len() <= STORED_BYTES);
        assert_eq!(kept.state, State::NotChecked);
        assert_eq!(kept.reason, Some(Reason::Incomplete));
        assert_eq!(kept.omitted_accounts, u64::try_from(ACCOUNTS).unwrap());
    }

    /// Bounding the account list must say how many accounts were not checked.
    #[test]
    fn accounts_past_the_bound_are_not_silently_clean() {
        let mut input = report(State::Unchanged, Vec::new());
        input.accounts[0].recorded_at = 1;
        input.accounts = vec![input.accounts[0].clone(); 67];
        let result = input.bounded().decided(false);
        assert_eq!(result.state, State::NotChecked, "{result:?}");
        let json = serde_json::to_value(result).unwrap();
        assert_eq!(json["omitted_accounts"], 3);
    }

    /// Reducing a large reply must preserve its omitted-account count.
    #[test]
    fn trimming_preserves_the_number_of_omitted_accounts() {
        let mut input = report(State::Changed, vec![file("~/.bashrc", &["plant"])]);
        input.accounts = vec![input.accounts[0].clone(); 67];
        let mut result = input.bounded();
        while result.trim() {}
        assert_eq!(result.omitted_accounts, 3);
        assert_eq!(result.decided(false).state, State::NotChecked);
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

    /// D360: the places count and categories a "no changes found" report
    /// names are kept, printable and bounded.
    #[test]
    fn the_watched_places_and_categories_are_kept() {
        let mut sent = report(State::Unchanged, Vec::new());
        sent.accounts[0].places = 214;
        sent.accounts[0].categories = std::iter::once("SSH keys\u{1b}[2J".to_owned())
            .chain((0..40).map(|index| format!("kind {index}")))
            .collect();
        let kept = sent.bounded().decided(false);
        let account = &kept.accounts[0];
        assert_eq!(account.places, 214);
        assert_eq!(account.categories.len(), CATEGORIES);
        assert!(!account.categories[0].contains('\u{1b}'));
        assert_eq!(kept.state, State::Unchanged);
    }
    /// Future work prevents a clean result even if its sender cleared the flag.
    /// Both the row cap and total byte budget can shorten long Unicode rows.
    #[test]
    fn system_jobs_are_bounded_printable_and_prevent_a_clean_report() {
        let mut access = report(State::Unchanged, Vec::new());
        access.accounts[0].jobs = vec!["system job\u{1b}\u{202e}".repeat(100); 100];
        let access = access.bounded().decided(false);
        assert_eq!(access.accounts[0].state, State::NotChecked);
        assert_eq!(access.accounts[0].reason, Some(Reason::ProgramsMayRemain));
        assert!(access.accounts[0].programs_may_remain);
        assert!((1..=64).contains(&access.accounts[0].jobs.len()));
        assert!(access.json().len() <= STORED_BYTES);
        assert!(access.accounts[0].truncated);
        assert!(
            access.accounts[0]
                .jobs
                .iter()
                .all(|job| !job.contains('\u{1b}') && !job.contains('\u{202e}'))
        );
    }

    /// D362: process evidence cannot be hidden by a clean state, false flag or file changes.
    #[test]
    fn surviving_processes_prevent_a_clean_report_and_stay_printable() {
        let mut access = report(State::Unchanged, vec![file("~/.bashrc", &["new"])]);
        access.accounts[0].processes = vec!["4321 worker\u{1b}\u{202e}".to_owned(); 100];
        let access = access.bounded().decided(false);
        assert_eq!(access.accounts[0].state, State::NotChecked);
        assert_eq!(access.accounts[0].reason, Some(Reason::ProgramsMayRemain));
        assert_eq!(access.accounts[0].processes.len(), 64);
        assert!(
            access.accounts[0]
                .processes
                .iter()
                .all(|row| !row.contains('\u{1b}') && !row.contains('\u{202e}'))
        );
        assert_eq!(access.accounts[0].files.len(), 1);
    }
}
