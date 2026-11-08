//! Adapts the remote plugin's removal action to private-stdin HTTPS requests and organized CLI
//! results [16][168][202], #87. The start is the dry run; the finish sends its review, inside the
//! session's admin window (D339). The access report (D356) lists the access files the host
//! reported as changed since its logins were granted; the finish shows it when the host has
//! already confirmed, and `--access-report` reads it later. Reading it changes nothing.
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    process::ExitCode,
};
use uuid::Uuid;

use crate::cli::output::{CommandResult, CommandState, Exit, emit};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    session: String,
    #[serde(default)]
    review: Option<String>,
}
/// Which removal request one run sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The dry run.
    Start,
    /// The removal, with the review from the dry run.
    Finish,
    /// The read-only access report (D356).
    Report,
}
impl Step {
    /// `--access-report` reads; otherwise `--finish` removes and its absence is the dry run.
    pub(crate) fn from_flags(finish: bool, report: bool) -> Self {
        match (report, finish) {
            (true, _) => Self::Report,
            (false, true) => Self::Finish,
            (false, false) => Self::Start,
        }
    }
    /// The server route this step posts to.
    fn path(self) -> &'static str {
        match self {
            Self::Start => "/remote/hosts/remove/start",
            Self::Finish => "/remote/hosts/remove/finish",
            Self::Report => "/remote/hosts/access-report",
        }
    }
}
/// Session cookies and reviews enter only through bounded private stdin.
pub(crate) fn run(server: &str, host: Uuid, step: Step, retain: bool, machine: bool) -> ExitCode {
    let operation = || -> io::Result<Value> {
        let mut bytes = Vec::new();
        io::stdin().take(32769).read_to_end(&mut bytes)?;
        if bytes.len() > 32768 {
            return Err(denied());
        }
        let input: Input = serde_json::from_slice(&bytes).map_err(|_| denied())?;
        let body = match step {
            Step::Finish => json!({"host_id":host,"review":input.review.ok_or_else(denied)?}),
            Step::Start => json!({"host_id":host,"uninstall":!retain}),
            Step::Report => json!({"host_id":host}),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        crate::block_on(&runtime, async {
            let mut value = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                request(server, &input.session, step.path(), body),
            )
            .await
            .map_err(|_| denied())??;
            if step == Step::Finish {
                // The removal is done; a report the host already returned is
                // shown with it. Failing to read it never fails the removal.
                let report = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    request(
                        server,
                        &input.session,
                        Step::Report.path(),
                        json!({"host_id":host}),
                    ),
                )
                .await;
                if let Ok(Ok(report)) = report {
                    value["access_report"] = report;
                }
            }
            Ok(value)
        })
    };
    match operation() {
        // The review or the result of the hosted action travels in `data`; the
        // sentence says which step the person is on.
        Ok(value) => {
            let result = match step {
                Step::Report => report_result(host, &value, machine),
                _ => command_result(host, value, step == Step::Finish, machine),
            };
            emit(result, machine, Exit::Ok)
        }
        Err(_) => super::output::refuse(
            machine,
            infraternal_plugin_remote::REMOVE.id,
            "Host removal was refused.",
            "Use an owner session signed in within 15 minutes, and a review from its dry run on standard input.",
            Exit::NotAllowed,
        ),
    }
}
/// Present the dry run or final response, keeping structured fields for scripts.
/// Human output hides the private review but includes any manual uninstall command,
/// and any access report the host returned (D356).
fn command_result(host: Uuid, value: Value, finish: bool, machine: bool) -> CommandResult<Value> {
    let (state, message, next) = if finish {
        (
            if value["state"] == "pending" {
                CommandState::Pending
            } else {
                CommandState::Ready
            },
            value["message"]
                .as_str()
                .unwrap_or("The host was removed.")
                .to_owned(),
            "",
        )
    } else {
        (
            CommandState::Pending,
            "Review what removing this host does.".to_owned(),
            "To remove it, pass the session and the review on standard input with --finish within two minutes.",
        )
    };
    // A short pending status must not hide the separate ownership-checked
    // uninstall command. Avoid repeating it when the sentence includes it.
    let manual = value["manual"]
        .as_str()
        .filter(|command| finish && !machine && !command.is_empty() && !message.contains(*command))
        .map(str::to_owned);
    let report = finish.then(|| value["access_report"].clone());
    // The review is for scripts; a person at a terminal needs the sentence, not the capability.
    let data = if machine { value } else { json!({}) };
    let mut result = CommandResult::new("remove-host", state, message, data);
    if !next.is_empty() {
        result = result.with_next_step(next);
    }
    if let Some(manual) = manual {
        result = result.with_next_step(manual);
    }
    match report.as_ref().map(|report| &report["state"]) {
        Some(state) if state == "reported" && !machine => {
            if let Some(body) = report.as_ref().and_then(report_body) {
                result = result.with_body(body);
            }
        }
        Some(state) if state == "pending" && !machine => {
            result = result.with_next_step(format!(
                "When the host confirms, see the access files it reports as changed: infraternal remove-host {host} --access-report"
            ));
        }
        _ => {}
    }
    result
}

/// Present the access report on its own (D356). Scripts get the server's
/// object in `data`; people get each account's outcome, files and lines.
fn report_result(host: Uuid, value: &Value, machine: bool) -> CommandResult<Value> {
    let (state, message) = report_message(value);
    let message = message.as_str();
    let data = if machine { value.clone() } else { json!({}) };
    let mut result = CommandResult::new("remove-host", state, message, data);
    if machine {
        return result;
    }
    if let Some(body) = report_body(value) {
        result = result.with_body(body);
    }
    if value["state"] == "pending" {
        result = result.with_next_step(format!(
            "Run infraternal remove-host {host} --access-report again once the host is back online."
        ));
    }
    result
}

/// D360: the owner-facing words for an account (or host) that was checked
/// and where nothing was found: what was watched and since when, never
/// "unchanged". The only place this sentence is built.
fn no_changes_found(
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
    sentence
}

/// The root routes the host actually checked for this account. No names are
/// supplied by the CLI: older reports cannot gain evidence on presentation.
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

/// The headline for a report, from the server's outcome over every report
/// (not only the ones shown).
fn report_message(value: &Value) -> (CommandState, String) {
    let reports = value["reports"].as_array().map_or(&[][..], Vec::as_slice);
    let outcome = value["outcome"].as_str().unwrap_or("not_checked");
    match value["state"].as_str() {
        Some("pending") => (
            CommandState::Pending,
            "The host has not confirmed the revocation yet, so it has not reported its access files.".to_owned(),
        ),
        Some("not_revoked") => (
            CommandState::Ready,
            "No revocation has run on this host yet, so there is no access report.".to_owned(),
        ),
        Some("reported") if outcome == "changed" => (
            CommandState::Ready,
            "These access files changed on the host since its logins were granted.".to_owned(),
        ),
        Some("reported") if outcome == "unchanged" && !reports.is_empty() => {
            let accounts = || {
                reports
                    .iter()
                    .flat_map(|report| report["accounts"].as_array().into_iter().flatten())
            };
            let places = accounts()
                .fold(std::collections::BTreeMap::<&str, u64>::new(), |mut places, account| {
                    let name = account["account"].as_str().unwrap_or("?");
                    let watched = account["watched"].as_u64().unwrap_or(0);
                    places.entry(name).and_modify(|count| *count = (*count).max(watched)).or_insert(watched);
                    places
                })
                .values().fold(0_u64, |total, count| total.saturating_add(*count));
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
                return (CommandState::Ready, "The reports below name their checked places and root access routes; more reports are not shown.".to_owned());
            }
            if since.is_none() || accounts().any(|a| a["recorded_at"].as_u64().filter(|t| *t > 0).and_then(utc).is_none()) {
                return (CommandState::Ready, "The host's access files were not fully checked; the time access was granted is missing.".to_owned());
            }
            (
                CommandState::Ready,
                format!("{}.", no_changes_found(places, &categories, since, &root_checks)),
            )
        }
        Some("reported") => (
            CommandState::Ready,
            "The host's access files were not fully checked; see why below.".to_owned(),
        ),
        _ => (
            CommandState::Ready,
            "The server sent an access report this version cannot read.".to_owned(),
        ),
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
        "agent_removed" => {
            "not checked: the host's infraternal agent was removed before it could report"
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
fn report_body(report: &Value) -> Option<String> {
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

/// The TLS client for the removal routes: the connector `sign-in` and the hosted actions use,
/// so all of them trust the host's public CA bundle even when the linked OpenSSL's default paths
/// hold no roots (a vendored build names its build prefix). TLS 1.3, peer and hostname
/// verification, HTTP/1.1 ALPN.
fn removal_tls_connector() -> io::Result<openssl::ssl::SslConnector> {
    crate::remote::outbound_tls_connector(None).map_err(|_| denied())
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
/// Post `body` to `path` on `server` over verified TLS with the session cookie,
/// and read a bounded JSON answer. Anything but 200 is refused.
async fn request(server: &str, cookie: &str, path: &str, body: Value) -> io::Result<Value> {
    use http_body_util::BodyExt;
    let url = url::Url::parse(server).map_err(|_| denied())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(denied());
    }
    let name = url.host_str().ok_or_else(denied)?;
    let ssl = removal_tls_connector()?
        .configure()
        .map_err(|_| denied())?
        .into_ssl(name)
        .map_err(|_| denied())?;
    let socket =
        tokio::net::TcpStream::connect((name, url.port_or_known_default().ok_or_else(denied)?))
            .await?;
    let mut stream = tokio_openssl::SslStream::new(ssl, socket).map_err(|_| denied())?;
    std::pin::Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|_| denied())?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| denied())?;
    let task = Connection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header(
            "host",
            url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
        )
        .header("origin", url.origin().ascii_serialization())
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            serde_json::to_vec(&body).map_err(|_| denied())?,
        )))
        .map_err(|_| denied())?;
    let response = sender.send_request(request).await.map_err(|_| denied())?;
    if response.status() != hyper::StatusCode::OK {
        return Err(denied());
    }
    let bytes = http_body_util::Limited::new(response.into_body(), 32768)
        .collect()
        .await
        .map_err(|_| denied())?
        .to_bytes();
    drop(task);
    serde_json::from_slice(&bytes).map_err(|_| denied())
}
struct Connection(tokio::task::JoinHandle<()>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    //! Human rendering and transport regressions for reviewed host removal.
    /// Human output must include the structured leftover-install command even
    /// when a pending response has only a short status sentence.
    #[test]
    fn pending_removal_prints_manual_command_for_people() {
        use crate::cli::output::{RenderOptions, render_pretty};
        let command =
            "/usr/local/bin/infraternal --bootstrap-uninstall 0123456789abcdef0123456789abcdef";
        let value = serde_json::json!({"state":"pending", "message":"worker: revoked, cleanup pending.", "manual":command});
        let result = super::command_result(uuid::Uuid::nil(), value, true, false);
        let output = render_pretty(
            &result,
            RenderOptions {
                terminal: false,
                color: false,
                width: 100,
            },
        )
        .unwrap();
        assert!(
            output.contains(command),
            "manual uninstall missing from human output: {output}"
        );
        assert_eq!(result.state, crate::cli::output::CommandState::Pending);
        assert_eq!(result.data, serde_json::json!({}));
    }

    /// D356: people see each account's outcome and each reported file with
    /// its new lines after a removal, with the reminder that infraternal did
    /// not change them; scripts get the server's object. A report still
    /// pending points at `--access-report`.
    #[test]
    fn removal_shows_the_access_files_the_host_reported() {
        use crate::cli::output::{RenderOptions, render_pretty};
        let host = uuid::Uuid::from_u128(7);
        let report = serde_json::json!({"host_id": host, "state": "reported", "reports": [{
            "person_id": uuid::Uuid::from_u128(9),
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
        }]});
        let finished = serde_json::json!({"state": "ready", "message": "The host was removed.", "access_report": report});
        let options = RenderOptions {
            terminal: false,
            color: false,
            width: 100,
        };
        let output = render_pretty(
            &super::command_result(host, finished.clone(), true, false),
            options,
        )
        .unwrap();
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
        let machine = super::command_result(host, finished, true, true);
        assert_eq!(machine.data["access_report"], report);
        let pending = serde_json::json!({"state": "pending", "message": "worker: revoked, cleanup pending.", "access_report": {"host_id": host, "state": "pending", "reports": []}});
        let output =
            render_pretty(&super::command_result(host, pending, true, false), options).unwrap();
        // Next steps wrap at the layout width; compare words, not lines.
        let words = output.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains(&format!("infraternal remove-host {host} --access-report")),
            "pending report has no way to read it later: {output}"
        );
        let later = render_pretty(&super::report_result(host, &report, false), options).unwrap();
        assert!(
            later.contains("    + ssh-ed25519 AAAAleft left-behind"),
            "{later}"
        );
    }

    /// J322 P2: "nothing changed" is said only when everything was checked.
    /// An older agent, a missing record and a rootless host each say why
    /// they were not checked.
    #[test]
    fn not_checked_is_never_shown_as_nothing_changed() {
        use crate::cli::output::{RenderOptions, render_pretty};
        let host = uuid::Uuid::from_u128(7);
        let options = RenderOptions {
            terminal: false,
            color: false,
            width: 200,
        };
        let render = |reports: serde_json::Value| {
            let value =
                serde_json::json!({"host_id": host, "state": "reported", "reports": reports});
            render_pretty(&super::report_result(host, &value, false), options).unwrap()
        };
        let older = render(
            serde_json::json!([{"person_id": host, "state": "not_checked", "reason": "older_agent", "accounts": []}]),
        );
        assert!(older.contains("were not fully checked"), "{older}");
        assert!(older.contains("too old to report"), "{older}");
        assert!(!older.contains("no access file"), "{older}");
        let rootless = render(
            serde_json::json!([{"person_id": host, "state": "not_checked", "reason": "rootless_unverified", "accounts": [
                {"account": "me", "state": "not_checked", "reason": "rootless_unverified", "files": [], "truncated": false, "unscanned": [], "omitted_files": 0}
            ]}]),
        );
        assert!(rootless.contains("Account me: not verified"), "{rootless}");
        let value = serde_json::json!({"host_id": host, "state": "reported", "outcome": "unchanged", "more": 0, "reports": [
            {"person_id": host, "state": "unchanged", "accounts": [
                {"account": "me", "state": "unchanged", "files": [], "truncated": false, "unscanned": [], "omitted_files": 0,
                 "complete": true, "watched": 214, "places": 22, "categories": ["SSH keys", "cron and at jobs", "user services", "shell startup files"],
                 "root_checks": ["sudo", "doas", "polkit", "admin groups"],
                 "recorded_at": 1_700_000_000_u64, "scanned_at": 1_700_000_100_u64}
            ]}
        ]});
        let clean = render_pretty(&super::report_result(host, &value, false), options).unwrap();
        let sentence = "No changes found in the 214 places we watch (SSH keys, cron and at jobs, user services, shell startup files) since 14 Nov 2023, 22:13 UTC.";
        assert!(clean.contains(sentence), "{clean}");
        assert!(
            clean.contains(&format!("Account me: {sentence}")),
            "{clean}"
        );
        assert!(!clean.contains("unchanged"), "{clean}");
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
        let (_, message) = super::report_message(&value);
        assert!(message.contains("56 places"), "{message}");
        assert!(message.contains("22:15 UTC"), "{message}");
    }

    /// The displayed root routes come from the host's actual result, so a new
    /// check needs no second list in the presentation code.
    #[test]
    fn clean_report_names_the_root_checks_that_ran() {
        let value = serde_json::json!({"state":"reported", "outcome":"unchanged", "reports":[
            {"state":"unchanged", "accounts":[{
                "account":"deploy", "state":"unchanged", "watched":30,
                "recorded_at":1_700_000_000_u64,
                "root_checks":["sudo", "doas", "polkit", "admin groups", "custom permission check"]
            }]}
        ]});
        let (_, message) = super::report_message(&value);
        let root_sentence = "They had no root access through sudo, doas, polkit, admin groups or custom permission check.";
        assert!(message.contains(root_sentence), "{message}");
        let body = super::report_body(&value).unwrap();
        assert!(body.contains(root_sentence), "{body}");
    }

    /// A historical result with no root-check evidence cannot gain the new
    /// clean sentence merely because this CLI knows about more checks.
    #[test]
    fn missing_root_checks_never_read_as_clean() {
        let value = serde_json::json!({"state":"reported", "outcome":"unchanged", "reports":[
            {"state":"unchanged", "accounts":[{
                "account":"deploy", "state":"unchanged", "watched":30,
                "recorded_at":1_700_000_000_u64
            }]}
        ]});
        let (_, message) = super::report_message(&value);
        assert!(!message.contains("No changes found"), "{message}");
        let body = super::report_body(&value).unwrap();
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
        let (_, message) = super::report_message(&value);
        assert!(!message.contains("No changes found"), "{message}");
        let body = super::report_body(&value).unwrap();
        assert!(body.contains("3 more accounts were not checked"), "{body}");
        assert!(!body.contains("No changes found"), "{body}");
    }

    /// J334: a shared account says changes may be someone else's, a removed
    /// file is marked, each report shows its baseline time, and reports past
    /// the shown ones are counted.
    #[test]
    fn shared_removed_and_more_reports_are_said() {
        use crate::cli::output::{RenderOptions, render_pretty};
        let host = uuid::Uuid::from_u128(7);
        let value = serde_json::json!({"host_id": host, "state": "reported", "outcome": "not_checked", "more": 3, "reports": [
            {"person_id": host, "state": "changed", "accounts": [
                {"account": "deploy", "state": "changed", "shared": true, "files": [
                    {"path": "~/.config/systemd/user/m.service", "change": "removed", "lines": [], "note": "a symbolic link at the grant; gone now"}
                ], "truncated": false, "unscanned": [], "omitted_files": 0, "recorded_at": 1_700_000_000_u64, "scanned_at": 1_700_000_100_u64}
            ]}
        ]});
        let options = RenderOptions {
            terminal: false,
            color: false,
            width: 200,
        };
        let output = render_pretty(&super::report_result(host, &value, false), options).unwrap();
        for expected in [
            "removed: ~/.config/systemd/user/m.service",
            "Other people also have access to this account",
            "Baseline from 14 Nov 2023, 22:13 UTC; checked at 14 Nov 2023, 22:15 UTC.",
            "3 more reports are not shown.",
        ] {
            assert!(
                output.contains(expected),
                "{expected:?} missing from: {output}"
            );
        }
    }

    /// Found on the test server (#303, J94f): `remove-host` refused every step, its dry run
    /// included, while the same session's browser dry run succeeded. With `SSL_CERT_FILE` set to
    /// the system bundle the same binary removed the host. A vendored OpenSSL's default paths
    /// name its build prefix and hold no roots on the host; J94e fixed the same defect for the
    /// hosted actions (`2f0f4a007`). The child run points OpenSSL's defaults at nothing, so
    /// only explicitly loaded roots count.
    #[test]
    fn removal_trusts_the_host_ca_bundle() {
        let bundles = [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
        ];
        if !bundles
            .iter()
            .any(|bundle| std::path::Path::new(bundle).is_file())
        {
            return;
        }
        let child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "host_remove::tests::removal_trust_probe",
                "--ignored",
                "--test-threads=1",
            ])
            .env(
                "SSL_CERT_FILE",
                "/nonexistent/infraternal-no-default-roots.pem",
            )
            .env("SSL_CERT_DIR", "/nonexistent/infraternal-no-default-roots")
            .output()
            .expect("run the trust probe");
        let output = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success() && output.contains("1 passed"),
            "host removal has no trust roots without OpenSSL's defaults:\n{output}"
        );
    }

    /// Run only by `removal_trusts_the_host_ca_bundle`, with OpenSSL's defaults unset.
    #[test]
    #[ignore = "child of removal_trusts_the_host_ca_bundle"]
    fn removal_trust_probe() {
        let ssl = super::removal_tls_connector()
            .expect("removal TLS connector")
            .configure()
            .expect("TLS configuration")
            .into_ssl("ssh.kayg.org")
            .expect("TLS session");
        assert!(!ssl.ssl_context().cert_store().all_certificates().is_empty());
    }
}
