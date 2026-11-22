//! The words of an access report (D360, D364, D367, D383): what the owner reads
//! in the Inbox when a person was revoked and the host stayed.
//!
//! One place builds every sentence, so the web Inbox and any other reader say
//! the same thing. It works on the report as the server serializes it (a JSON
//! object), never on the host's own text beyond what the server already
//! cleaned. A clean report names what was watched, since when, and the root
//! checks that ran, and ends with "Access outside these checks isn't covered";
//! a report that was not fully checked says why and never reads as clean.
//! infraternal never changes the reported files, and the text says so.
use serde_json::Value;

/// D360: the owner-facing words for an account (or host) that was checked
/// and where nothing was found: what was watched and since when, never
/// "unchanged". The only place this sentence is built.
pub(crate) fn no_changes_found(
    places: u64,
    categories: &[String],
    since: Option<String>,
    root_checks: &[String],
) -> String {
    let Some((last, preceding)) = root_checks.split_last() else {
        return "Not checked: root access was not verified".to_owned();
    };
    let mut sentence = format!(
        "No changes found in the {places} {} we watch",
        if places == 1 { "place" } else { "places" }
    );
    if !categories.is_empty() {
        sentence.push_str(" (");
        sentence.push_str(&categories.join(", "));
        sentence.push(')');
    }
    if let Some(since) = since {
        sentence.push_str(" since ");
        sentence.push_str(&since);
    }
    sentence.push_str(". They had no root access through ");
    if !preceding.is_empty() {
        sentence.push_str(&preceding.join(", "));
        sentence.push_str(" or ");
    }
    sentence.push_str(last);
    sentence.push_str(". Access outside these checks isn't covered");
    sentence
}

/// The root routes the host actually checked for this account. No names are
/// supplied here: older reports cannot gain evidence on presentation.
fn root_checks_of(account: &Value) -> Vec<String> {
    account["root_checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The categories in `account`'s report.
fn categories_of(account: &Value) -> Vec<String> {
    account["categories"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// `seconds` since the epoch as `3 Nov 2026, 14:02 UTC` (D360's form, with
/// the year and the zone, since a host's and a reader's clocks differ), or
/// `None` for 0.
fn utc(seconds: u64) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if seconds == 0 {
        return None;
    }
    let days = i64::try_from(seconds / 86_400).ok()?;
    let rest = seconds % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let name = MONTHS.get(usize::try_from(month - 1).ok()?)?;
    Some(format!(
        "{day} {name} {year}, {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    ))
}

/// The one sentence that heads a report, from the server's outcome over the
/// reports given (D360, D364, D367). A clean report names what was watched,
/// since when, and the root checks that ran, and ends with the coverage
/// boundary; anything not fully checked says so and never reads as clean.
pub(crate) fn headline(value: &Value) -> String {
    let reports = value["reports"].as_array().map_or(&[][..], Vec::as_slice);
    let outcome = value["outcome"].as_str().unwrap_or("not_checked");
    match value["state"].as_str() {
        Some("reported") if outcome == "changed" => {
            "These access files changed on the host since the person's logins were granted."
                .to_owned()
        }
        Some("reported") if outcome == "unchanged" && !reports.is_empty() => {
            let accounts = || {
                reports
                    .iter()
                    .flat_map(|report| report["accounts"].as_array().into_iter().flatten())
            };
            let places = accounts()
                .fold(
                    std::collections::BTreeMap::<&str, u64>::new(),
                    |mut places, account| {
                        let name = account["account"].as_str().unwrap_or("?");
                        let watched = account["watched"].as_u64().unwrap_or(0);
                        places
                            .entry(name)
                            .and_modify(|count| *count = (*count).max(watched))
                            .or_insert(watched);
                        places
                    },
                )
                .values()
                .fold(0_u64, |total, count| total.saturating_add(*count));
            let mut categories: Vec<String> = Vec::new();
            for category in accounts().flat_map(categories_of) {
                if !categories.contains(&category) {
                    categories.push(category);
                }
            }
            let since = accounts()
                .filter_map(|account| account["recorded_at"].as_u64())
                .filter(|seconds| *seconds > 0)
                .max()
                .and_then(utc);
            let mut root_checks = accounts().next().map_or_else(Vec::new, root_checks_of);
            for account in accounts() {
                let checks = root_checks_of(account);
                root_checks.retain(|check| checks.contains(check));
            }
            if value["more"].as_u64().unwrap_or(0) > 0 {
                return "The reports below name their checked places and root access routes; more reports are not shown.".to_owned();
            }
            if since.is_none()
                || accounts().any(|a| {
                    a["recorded_at"]
                        .as_u64()
                        .filter(|t| *t > 0)
                        .and_then(utc)
                        .is_none()
                })
            {
                return "The host's access files were not fully checked; the time access was granted is missing.".to_owned();
            }
            format!(
                "{}.",
                no_changes_found(places, &categories, since, &root_checks)
            )
        }
        Some("reported") => {
            "The host's access files were not fully checked; see why below.".to_owned()
        }
        _ => "The host sent an access report this version cannot read.".to_owned(),
    }
}

/// Why something was not checked, in plain words.
fn reason_words(reason: &str) -> &'static str {
    match reason {
        "record_missing" => {
            "not checked: there is no record from when access was granted (granted before this check, or the record is gone); check its access files by hand"
        }
        "record_failed" => {
            "not checked: recording its access files at the grant failed; check them by hand"
        }
        "rootless_unverified" => {
            "not verified: infraternal runs as this account itself, so the person could have changed the record; anything below is only a hint, check by hand"
        }
        "privileged" => {
            "Not checked: this account may have root authority, so it could have changed the record and files anywhere; check by hand"
        }
        "incomplete" => "not fully checked: some places were not scanned (listed below)",
        "programs_may_remain" => "Not checked: programs may still be running",
        "coverage_missing" => {
            "not fully checked: the host's infraternal agent watches fewer places than this server knows of"
        }
        "older_agent" => {
            "not checked: the host's infraternal agent is too old to report access files"
        }
        "not_recorded" => {
            "not checked: this revocation was recorded before access reports were kept"
        }
        _ => "not checked",
    }
}

/// Each person's report for people: per account, its outcome, then the
/// changed files with their new lines, then what was left out. infraternal
/// never changes these files; the text says so and leaves removal to the
/// reader.
pub(crate) fn report_body(report: &Value) -> Option<String> {
    let reports = report["reports"]
        .as_array()
        .filter(|reports| !reports.is_empty())?;
    let mut lines = Vec::new();
    let mut files_shown = false;
    for entry in reports {
        if let Some(warning) = entry["warning"].as_str() {
            lines.push(format!("Warning: {warning}"));
        }
        let omitted = entry["omitted_accounts"].as_u64().unwrap_or(0);
        if omitted > 0 {
            lines.push(format!("{omitted} more accounts were not checked."));
        }
        let accounts = entry["accounts"].as_array().map_or(&[][..], Vec::as_slice);
        if accounts.is_empty() && entry["state"] == "not_checked" {
            let reason = entry["reason"].as_str().unwrap_or("");
            lines.push(format!("Access files: {}.", reason_words(reason)));
        }
        for account in accounts {
            account_lines(account, &mut lines, &mut files_shown);
        }
    }
    let more = report["more"].as_u64().unwrap_or(0);
    if more > 0 {
        lines.push(format!("{more} more reports are not shown."));
    }
    if files_shown {
        lines.push(
            "Remove what you do not recognise. infraternal did not change these files.".to_owned(),
        );
    }
    Some(lines.join("\n"))
}

/// One account's lines in [`report_body`].
fn account_lines(account: &Value, lines: &mut Vec<String>, files_shown: &mut bool) {
    let name = account["account"].as_str().unwrap_or("?");
    let since = account["recorded_at"]
        .as_u64()
        .filter(|time| *time > 0)
        .and_then(utc);
    let outcome = match account["state"].as_str() {
        Some("changed") => "changed since the grant".to_owned(),
        Some("unchanged") if since.is_some() => no_changes_found(
            account["watched"].as_u64().unwrap_or(0),
            &categories_of(account),
            since.clone(),
            &root_checks_of(account),
        ),
        Some("unchanged") => reason_words("record_missing").to_owned(),
        _ => reason_words(account["reason"].as_str().unwrap_or("")).to_owned(),
    };
    lines.push(format!("Account {name}: {outcome}."));
    if account["state"] != "unchanged" {
        let scanned = account["scanned_at"].as_u64().and_then(utc);
        match (since, scanned) {
            (Some(since), Some(scanned)) => {
                lines.push(format!("  Baseline from {since}; checked at {scanned}."));
            }
            (None, Some(scanned)) => lines.push(format!("  Checked at {scanned}.")),
            _ => {}
        }
    }
    if account["shared"] == true {
        lines.push(
            "  Other people also have access to this account: changes may be theirs, and nothing after this check is known."
                .to_owned(),
        );
    }
    for job in account["jobs"].as_array().into_iter().flatten() {
        if let Some(job) = job.as_str() {
            lines.push(format!("  Scheduled or root-run job: {job}"));
        }
    }
    for process in account["processes"].as_array().into_iter().flatten() {
        if let Some(process) = process.as_str() {
            lines.push(format!("  Running: {process}"));
        }
    }
    for file in account["files"].as_array().into_iter().flatten() {
        *files_shown = true;
        let path = file["path"].as_str().unwrap_or("?");
        let kind = match file["change"].as_str() {
            Some("added") => "new: ",
            Some("removed") => "removed: ",
            _ => "",
        };
        lines.push(match file["note"].as_str() {
            Some(note) => format!("  {kind}{path} ({note})"),
            None => format!("  {kind}{path}"),
        });
        for line in file["lines"].as_array().into_iter().flatten() {
            lines.push(format!("    + {}", line.as_str().unwrap_or("")));
        }
    }
    let omitted = account["omitted_files"].as_u64().unwrap_or(0);
    if omitted > 0 {
        lines.push(format!("  {omitted} more changed files are not listed."));
    }
    let unscanned: Vec<&str> = account["unscanned"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !unscanned.is_empty() {
        lines.push(format!("  Not scanned: {}.", unscanned.join(", ")));
    } else if account["truncated"] == true && omitted == 0 {
        lines.push("  Some changes were left out; check the account by hand.".to_owned());
    }
}

#[cfg(test)]
mod tests {
    //! The owner-facing words of a report: what is said, and what is never said.
    use super::*;

    /// A one-report object as the server serializes it for the Inbox.
    fn one(outcome: &str, report: Value) -> Value {
        let mut value =
            serde_json::json!({"state": "reported", "outcome": outcome, "more": 0, "reports": []});
        value["reports"] = Value::Array(vec![report]);
        value
    }

    /// D356: people see each account's outcome and each reported file with its
    /// new lines, with the reminder that infraternal did not change them.
    #[test]
    fn a_changed_report_lists_files_and_lines() {
        let value = one(
            "changed",
            serde_json::json!({
                "state": "changed",
                "warning": "Background programs of this host account may still be running.",
                "accounts": [{
                    "account": "deploy",
                    "state": "changed",
                    "files": [
                        {"path": "~/.ssh/authorized_keys", "change": "changed", "lines": ["ssh-ed25519 AAAAleft left-behind"]},
                        {"path": "~/.profile", "change": "added", "lines": [], "note": "a symbolic link to /etc/passwd; not followed"}
                    ],
                    "truncated": true,
                    "unscanned": ["~/.config/systemd/user/a.service.d"],
                    "omitted_files": 2,
                }],
            }),
        );
        let output = report_body(&value).unwrap();
        for expected in [
            "Warning: Background programs",
            "Account deploy: changed since the grant.",
            "~/.ssh/authorized_keys",
            "    + ssh-ed25519 AAAAleft left-behind",
            "new: ~/.profile (a symbolic link to /etc/passwd; not followed)",
            "2 more changed files are not listed.",
            "Not scanned: ~/.config/systemd/user/a.service.d.",
            "infraternal did not change these files",
        ] {
            assert!(
                output.contains(expected),
                "{expected:?} missing from: {output}"
            );
        }
    }

    /// J322 P2: "nothing changed" is said only when everything was checked.
    /// An older agent, a missing record and a rootless host each say why they
    /// were not checked.
    #[test]
    fn not_checked_is_never_shown_as_nothing_changed() {
        let older = one(
            "not_checked",
            serde_json::json!({"state": "not_checked", "reason": "older_agent", "accounts": []}),
        );
        assert!(
            headline(&older).contains("not fully checked"),
            "{}",
            headline(&older)
        );
        let body = report_body(&older).unwrap();
        assert!(body.contains("too old to report"), "{body}");
        let rootless = one(
            "not_checked",
            serde_json::json!({"state": "not_checked", "reason": "rootless_unverified", "accounts": [
                {"account": "me", "state": "not_checked", "reason": "rootless_unverified", "files": [], "truncated": false, "unscanned": [], "omitted_files": 0}
            ]}),
        );
        assert!(
            report_body(&rootless)
                .unwrap()
                .contains("Account me: not verified")
        );
        let clean = one(
            "unchanged",
            serde_json::json!({"state": "unchanged", "accounts": [
                {"account": "me", "state": "unchanged", "files": [], "truncated": false, "unscanned": [], "omitted_files": 0,
                 "complete": true, "watched": 214, "places": 22, "categories": ["SSH keys", "cron and at jobs", "user services", "shell startup files"],
                 "root_checks": ["sudo", "doas", "polkit", "admin groups"],
                 "recorded_at": 1_700_000_000_u64, "scanned_at": 1_700_000_100_u64}
            ]}),
        );
        let sentence = "No changes found in the 214 places we watch (SSH keys, cron and at jobs, user services, shell startup files) since 14 Nov 2023, 22:13 UTC.";
        assert!(headline(&clean).contains(sentence), "{}", headline(&clean));
        assert!(
            report_body(&clean)
                .unwrap()
                .contains(&format!("Account me: {sentence}")),
            "{}",
            report_body(&clean).unwrap()
        );
        assert!(!headline(&clean).contains("unchanged"));
    }

    /// Shared accounts count once, and the headline uses the latest baseline.
    #[test]
    fn headline_counts_watched_places_once_and_uses_the_latest_baseline() {
        let account = |name: &str, watched: u64, recorded_at: u64| {
            serde_json::json!({
                "account": name, "state": "unchanged", "watched": watched,
                "places": 1, "categories": ["SSH keys"], "recorded_at": recorded_at,
                "root_checks": ["sudo", "doas", "polkit", "admin groups"]
            })
        };
        let value = serde_json::json!({"state":"reported", "outcome":"unchanged", "reports":[
            {"accounts":[account("deploy", 28, 1_700_000_000), account("ops", 28, 1_700_000_120)]},
            {"accounts":[account("deploy", 28, 1_700_000_060)]}
        ]});
        let message = headline(&value);
        assert!(message.contains("56 places"), "{message}");
        assert!(message.contains("22:15 UTC"), "{message}");
    }

    /// The displayed root routes come from the host's actual result, so a new
    /// check needs no second list here.
    #[test]
    fn clean_report_names_the_root_checks_that_ran() {
        let value = serde_json::json!({"state":"reported", "outcome":"unchanged", "reports":[
            {"state":"unchanged", "accounts":[{
                "account":"deploy", "state":"unchanged", "watched":30,
                "recorded_at":1_700_000_000_u64,
                "root_checks":["sudo", "doas", "polkit", "admin groups", "custom permission check"]
            }]}
        ]});
        let root_sentence = "They had no root access through sudo, doas, polkit, admin groups or custom permission check.";
        assert!(
            headline(&value).contains(root_sentence),
            "{}",
            headline(&value)
        );
        assert!(report_body(&value).unwrap().contains(root_sentence));
    }

    /// The shared sentence builder always ends with D367's coverage boundary.
    #[test]
    fn clean_sentence_ends_with_coverage_caveat() {
        let sentence = no_changes_found(30, &[], None, &["sudo".to_owned()]);
        assert!(
            sentence.ends_with("Access outside these checks isn't covered"),
            "{sentence}"
        );
    }

    /// A historical result with no root-check evidence cannot gain the clean
    /// sentence merely because this server knows about more checks.
    #[test]
    fn missing_root_checks_never_read_as_clean() {
        let value = serde_json::json!({"state":"reported", "outcome":"unchanged", "reports":[
            {"state":"unchanged", "accounts":[{
                "account":"deploy", "state":"unchanged", "watched":30,
                "recorded_at":1_700_000_000_u64
            }]}
        ]});
        assert!(!headline(&value).contains("No changes found"));
        let body = report_body(&value).unwrap();
        assert!(!body.contains("No changes found"), "{body}");
        assert!(body.contains("Not checked"), "{body}");
    }

    /// Older replies without a grant time cannot produce a clean sentence.
    #[test]
    fn missing_baselines_and_omitted_accounts_are_visible() {
        let value = serde_json::json!({"state":"reported", "outcome":"unchanged", "reports":[
            {"state":"not_checked", "omitted_accounts":3, "accounts":[
                {"account":"deploy", "state":"unchanged", "watched":30, "recorded_at":0}
            ]}
        ]});
        assert!(!headline(&value).contains("No changes found"));
        let body = report_body(&value).unwrap();
        assert!(body.contains("3 more accounts were not checked"), "{body}");
        assert!(!body.contains("No changes found"), "{body}");
    }

    /// J334: a shared account says changes may be someone else's, a removed
    /// file is marked, and each report shows its baseline time.
    #[test]
    fn shared_and_removed_files_are_said() {
        let value = one(
            "changed",
            serde_json::json!({"state": "changed", "accounts": [
                {"account": "deploy", "state": "changed", "shared": true, "files": [
                    {"path": "~/.config/systemd/user/m.service", "change": "removed", "lines": [], "note": "a symbolic link at the grant; gone now"}
                ], "truncated": false, "unscanned": [], "omitted_files": 0, "recorded_at": 1_700_000_000_u64, "scanned_at": 1_700_000_100_u64}
            ]}),
        );
        let output = report_body(&value).unwrap();
        for expected in [
            "removed: ~/.config/systemd/user/m.service",
            "Other people also have access to this account",
            "Baseline from 14 Nov 2023, 22:13 UTC; checked at 14 Nov 2023, 22:15 UTC.",
        ] {
            assert!(
                output.contains(expected),
                "{expected:?} missing from: {output}"
            );
        }
    }
}
