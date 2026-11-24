//! `infraternal server update adopt <RELEASE>`: move an existing server onto the boot pointer (#211 S6).
//!
//! A server whose unit starts a fixed path (production before S6: an operator's unit with
//! `ExecStart=/opt/infraternal/<build>/infraternal server --data … --web-root …/web …`)
//! runs an applied update only until its next cold start, because the cold start runs the
//! fixed path again. This command moves such a server, once, onto the updater's boot
//! pointer `<data>/updates/current/<image>`, which the updater moves only after a new
//! release passed its health check (D295):
//!
//! 1. **Check everything first** and refuse with the reason if anything does not match:
//!    this runs as root on Linux; the unit exists as a plain file, has one `ExecStart`
//!    that runs an infraternal server for this `--data` folder, no drop-in overrides it,
//!    it runs as root and is active; the running server answers on its private control
//!    socket and says its version; the release folder is signed, for this machine, and
//!    not older than the running version.
//! 2. **Install the release** as `<data>/updates/releases/<version>/` (its web build
//!    unpacked into `web/`) and point `current` at it
//!    (`infraternal_plugin_release::adopt`).
//! 3. **Rewrite the unit**: back it up into `<data>/unit-backups/`, then change only the
//!    `ExecStart` line: the program becomes `<data>/updates/current/<image>` and every
//!    flag stays, except `--web-root` when the release carries its own web build (the
//!    release serves that, see `infraternal_plugin_release::web`). `systemctl
//!    daemon-reload`.
//! 4. **Restart warm** into the release, the same request as `infraternal server restart
//!    --binary <data>/updates/releases/<version>/<image>`: same PID, the terminal
//!    sessions keep running in their shims, and the unlocked CA is handed over (D217).
//! 5. **Confirm** that the server answers again with the release's version. If it does
//!    not within a minute, the old unit is put back (and reloaded), so the next cold
//!    start runs the build that worked, and the command says how to start it.
//!
//! `--dry-run` runs step 1 and prints exactly what steps 2 to 4 would change (the files,
//! the old and new `ExecStart` lines, the commands), changing nothing. A second run on an
//! adopted server changes nothing.
use crate::cli::output::{CommandResult, CommandState, Exit, emit};
use infraternal_plugin_release::{adopt, update};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

/// The command's name in results.
const COMMAND: &str = "server update adopt";
/// How long the restarted server has to answer with the release's version.
const COME_BACK: Duration = Duration::from_mins(1);

/// Run `infraternal server update adopt` with the parsed `matches` (`release`, `--data`,
/// `--unit`, `--dry-run`). Prints the result and returns its exit code (D303).
pub(crate) fn run(matches: &clap::ArgMatches, json_output: bool) -> ExitCode {
    let get = |name: &str| matches.try_get_one::<String>(name).ok().flatten().cloned();
    let release = get("release").map(PathBuf::from).unwrap_or_default();
    let unit = get("unit").unwrap_or_else(|| "infraternal-server".to_owned());
    let dry_run = matches.try_get_one::<bool>("dry_run").ok().flatten() == Some(&true);
    let data =
        crate::server_data_directory(get("data").as_deref(), infraternal_status::Roots::detect);
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return refuse(
            &Refusal::failed(
                "The command could not start its async runtime.",
                "Free some memory, then run it again.",
            ),
            json_output,
        );
    };
    let outcome = crate::block_on(&runtime, adopt_server(&data, &release, &unit, dry_run));
    match outcome {
        Ok(report) => emit(
            CommandResult::new(
                COMMAND,
                CommandState::Ready,
                report.message,
                json!({"adopt": report.data}),
            )
            .with_body(report.body)
            .with_next_step(report.next),
            json_output,
            Exit::Ok,
        ),
        Err(refusal) => refuse(&refusal, json_output),
    }
}

/// A finished adoption (or dry run), ready to print.
struct Report {
    /// One sentence saying what happened.
    message: String,
    /// The plan or the changes, one per line.
    body: String,
    /// What to do next.
    next: &'static str,
    /// The details, kept whole in the envelope's `data.adopt`.
    data: Value,
}

/// Why the command stopped, with what to do about it.
#[derive(Debug)]
struct Refusal {
    /// What did not match, in one sentence.
    message: String,
    /// What to do about it.
    next: String,
    /// The exit code.
    exit: Exit,
}
impl Refusal {
    /// The inputs or the machine do not match what adoption needs.
    fn refused(message: impl Into<String>, next: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            next: next.into(),
            exit: Exit::NotAllowed,
        }
    }
    /// A step failed.
    fn failed(message: impl Into<String>, next: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            next: next.into(),
            exit: Exit::Failed,
        }
    }
}

/// Print `refusal` and return its exit code.
fn refuse(refusal: &Refusal, json_output: bool) -> ExitCode {
    let state = if refusal.exit == Exit::Failed {
        CommandState::Failed
    } else {
        CommandState::Refused
    };
    emit(
        CommandResult::new(COMMAND, state, refusal.message.clone(), json!({}))
            .with_next_step(refusal.next.clone()),
        json_output,
        refusal.exit,
    )
}

/// The server unit as found on disk.
struct UnitFile {
    /// The unit file (a plain file, never a link).
    path: PathBuf,
    /// Its whole text.
    text: String,
    /// The `ExecStart=` value, as written.
    exec_start: String,
    /// The `ExecStart` words.
    words: Vec<String>,
}

/// Steps 1 to 5 of the module docs (only step 1 and the plan for `dry_run`).
async fn adopt_server(
    data: &Path,
    release: &Path,
    unit_name: &str,
    dry_run: bool,
) -> Result<Report, Refusal> {
    if !nix::unistd::geteuid().is_root() {
        return Err(Refusal::refused(
            "Only root can move the server onto self-updating releases.",
            "Run it as root on the server machine, for example with sudo.",
        ));
    }
    let artifact = update::server_image().ok_or_else(|| {
        Refusal::refused(update::OFF_PLATFORM, "Run it on the Linux server machine.")
    })?;
    if !release.is_absolute() {
        return Err(Refusal::refused(
            format!(
                "The release folder {} is not an absolute path.",
                release.display()
            ),
            "Pass the release folder as an absolute path.",
        ));
    }
    let data = std::fs::canonicalize(data).map_err(|_| {
        Refusal::refused(
            format!("The data folder {} does not exist.", data.display()),
            "Pass --data with the running server's data folder.",
        )
    })?;
    let unit = read_unit(&data, unit_name)?;
    let service = format!("{unit_name}.service");
    let pid = active_root_service(&service)?;
    let running = running_version(&data).await?;
    let verify = |version: &std::fs::File,
                  file: &std::fs::File,
                  name: &str,
                  sums: &[u8],
                  sig: &[u8]| {
        infraternal_server::release_verify::verify_release_identity(version, file, name, sums, sig)
            .map_err(|_| "the release is not signed by the release keys, or its files do not match its signed list")
    };
    let plan = adopt::plan(&data, release, artifact, &verify).map_err(|reason| {
        Refusal::refused(
            format!("The release folder cannot be used: {reason}."),
            "Pass the folder of a signed release, as the release build writes it.",
        )
    })?;
    let pointer = data.join("updates").join("current").join(artifact);
    let target_exec = rewrite_exec(&unit.words, &pointer, plan.web).map_err(|reason| {
        Refusal::refused(
            format!("The unit's ExecStart cannot be rewritten: {reason}."),
            "Write the unit's ExecStart as one plain command line.",
        )
    })?;
    let points_here = plan.current.as_deref() == Some(&Path::new("releases").join(&plan.version));
    if unit.exec_start == target_exec && points_here && running == plan.version {
        return Ok(Report {
            message: format!(
                "This server already starts the boot pointer and runs {running}; nothing changed."
            ),
            body: format!(
                "Unit: {}\nExecStart={}",
                unit.path.display(),
                unit.exec_start
            ),
            next: "infraternal server update status",
            data: json!({"changed": false, "version": running, "unit": unit.path, "exec_start": unit.exec_start}),
        });
    }
    if unit
        .words
        .first()
        .is_some_and(|program| Path::new(program) == pointer)
        && running != plan.version
    {
        return Err(Refusal::refused(
            format!(
                "This server already starts the boot pointer and runs {running}, not {}.",
                plan.version
            ),
            "Use infraternal server update check and apply to change its version.",
        ));
    }
    match update::guard(&running, &plan.version, update::Admission::Forward) {
        Ok(_) => {}
        Err(reason) => {
            return Err(Refusal::refused(
                format!(
                    "The release {} cannot replace the running {running}: {reason}.",
                    plan.version
                ),
                "Use a release that is the same as, or newer than, the running version, on its channel.",
            ));
        }
    }
    let selinux = crate::selinux::plan_for_host(&data, dry_run)
        .map_err(|error| Refusal::refused(error.to_string(), error.next_step()))?;
    let image = data
        .join("updates/releases")
        .join(&plan.version)
        .join(artifact);
    let backup = data
        .join("unit-backups")
        .join(format!("{service}.{}", utc_stamp()));
    let places = Places {
        data: &data,
        release,
        backup: &backup,
        image: &image,
    };
    let lines = plan_lines(&plan, &unit, &target_exec, &places, pid, selinux.as_ref());
    let details = json!({
        "version": plan.version,
        "previous_version": running,
        "unit": unit.path,
        "exec_start_before": unit.exec_start,
        "exec_start_after": target_exec,
        "image": image,
        "web": plan.web,
        "pid": pid,
        "backup": backup,
    });
    if dry_run {
        return Ok(Report {
            message: format!(
                "Dry run: this would move the server from {running} onto the signed release {} and the boot pointer; nothing changed.",
                plan.version
            ),
            body: lines.join("\n"),
            next: "Run the same command without --dry-run to do it.",
            data: json!({"changed": false, "dry_run": true, "plan": details}),
        });
    }

    // Step 2: the release and the boot pointer.
    let installed = adopt::install(&data, release, artifact, &verify).map_err(|reason| {
        Refusal::failed(
            format!("The release could not be installed: {reason}."),
            "Fix the cause and run it again; nothing else changed.",
        )
    })?;
    // Step 2b: on SELinux hosts, label `<data>/updates(/.*)?` executable before rewriting the unit (#211).
    if let Some(selinux_plan) = selinux.as_ref() {
        crate::selinux::apply_on_host(selinux_plan)
            .map_err(|error| Refusal::failed(error.to_string(), error.next_step()))?;
    }
    // Step 3: the unit (skipped when an interrupted run already rewrote it).
    let ca_before = crate::restart::query_ca_status(&data)
        .ok()
        .and_then(|status| status.locked);
    let rewritten = unit.exec_start != target_exec;
    if rewritten {
        write_backup(&unit, &backup).map_err(|reason| {
            Refusal::failed(
                reason,
                "Nothing in the unit changed; fix the cause and run it again.",
            )
        })?;
        let text = replace_exec(&unit.text, &target_exec);
        crate::install::write_atomic(&unit.path, text.as_bytes()).map_err(|_| {
            Refusal::failed(
                "The unit could not be rewritten.",
                format!("The unit is unchanged; its backup is {}.", backup.display()),
            )
        })?;
        if !daemon_reload() {
            restore(&unit);
            return Err(Refusal::failed(
                "systemctl daemon-reload failed, so the old unit was put back.",
                "Check systemctl, then run it again.",
            ));
        }
    }
    // Step 4: the warm restart into the installed release.
    let requested = tokio::time::timeout(
        Duration::from_secs(5),
        crate::restart::request(&data, Some(&installed.image), false),
    )
    .await;
    let Ok(Ok(warm)) = requested else {
        if rewritten {
            restore(&unit);
        }
        return Err(Refusal::failed(
            "The running server refused to restart into the release, so the old unit was put back.",
            format!(
                "The server keeps running {running}. Check its log (journalctl -u {service}) and run it again."
            ),
        ));
    };
    // Step 5: the server answers with the release's version.
    if !comes_back(&data, &installed.version).await {
        if rewritten {
            restore(&unit);
        }
        return Err(Refusal::failed(
            format!(
                "The server did not come back on {} within a minute, so the old unit was put back.",
                installed.version
            ),
            format!(
                "Start the previous build with systemctl restart {service} (its CA then needs a passkey unlock), and read journalctl -u {service}."
            ),
        ));
    }
    let ca_after = crate::restart::query_ca_status(&data)
        .ok()
        .and_then(|status| status.locked);
    let pid_after = active_root_service(&service).ok();
    Ok(Report {
        message: format!(
            "Moved the server from {running} onto {} and the boot pointer{}.",
            installed.version,
            if warm {
                ", warm (sessions and the unlocked CA kept)"
            } else {
                "; the restart was cold, so the CA needs a passkey unlock"
            }
        ),
        body: lines.join("\n").replace("Would ", ""),
        next: "infraternal server update status",
        data: json!({
            "changed": true,
            "warm": warm,
            "pid_after": pid_after,
            "ca_locked_before": ca_before,
            "ca_locked_after": ca_after,
            "unit_rewritten": rewritten,
            "release_kept": installed.kept,
            "plan": details,
        }),
    })
}

/// Where the change happens, for [`plan_lines`].
struct Places<'a> {
    /// The data folder.
    data: &'a Path,
    /// The release folder given on the command line.
    release: &'a Path,
    /// Where the unit backup goes.
    backup: &'a Path,
    /// The installed image the server restarts into.
    image: &'a Path,
}

/// The plan, one line per change, as the dry run prints it.
fn plan_lines(
    plan: &adopt::Plan,
    unit: &UnitFile,
    target_exec: &str,
    places: &Places<'_>,
    pid: u32,
    selinux: Option<&crate::selinux::LabelPlan>,
) -> Vec<String> {
    let Places {
        data,
        release,
        backup,
        image,
    } = *places;
    let folder = data.join("updates/releases").join(&plan.version);
    let mut lines = vec![if plan.installed {
        format!(
            "Would keep {} (already installed with these bytes)",
            folder.display()
        )
    } else {
        format!(
            "Would install {} as {} (VERSION, SHA256SUMS, SHA256SUMS.sig, the image{})",
            release.display(),
            folder.display(),
            if plan.web {
                ", and web/ from infraternal-web.tar"
            } else {
                "; the release has no web build, so --web-root stays"
            }
        )
    }];
    lines.push(format!(
        "Would point {} at releases/{} (now: {})",
        data.join("updates/current").display(),
        plan.version,
        plan.current.as_ref().map_or_else(
            || "missing".to_owned(),
            |current| current.display().to_string()
        )
    ));
    if let Some(selinux_plan) = selinux {
        for command in selinux_plan.dry_run_commands() {
            lines.push(format!("Would run {command}"));
        }
    }
    if unit.exec_start == target_exec {
        lines.push(format!(
            "Would leave {} as it is (it already starts the boot pointer)",
            unit.path.display()
        ));
    } else {
        lines.push(format!(
            "Would back up {} to {}",
            unit.path.display(),
            backup.display()
        ));
        lines.push(format!(
            "Would change ExecStart in {}:",
            unit.path.display()
        ));
        lines.push(format!("  - ExecStart={}", unit.exec_start));
        lines.push(format!("  + ExecStart={target_exec}"));
        lines.push("Would run systemctl daemon-reload".to_owned());
    }
    lines.push(format!(
        "Would restart the running server (PID {pid}) warm into {} (as infraternal server restart --binary does)",
        image.display()
    ));
    lines
}

/// Find the unit file systemd loaded for `<name>.service` and check it (see the module docs).
///
/// systemd itself says where the unit is (`FragmentPath`) and which drop-ins apply
/// (`DropInPaths`), so a unit in `/etc/systemd/system`, `/run/systemd/system` or anywhere
/// else is found exactly as the manager reads it.
fn read_unit(data: &Path, name: &str) -> Result<UnitFile, Refusal> {
    let service = format!("{name}.service");
    let shown = show(&service, &["LoadState", "FragmentPath", "DropInPaths"])?;
    let path = PathBuf::from(shown("FragmentPath"));
    if shown("LoadState") != "loaded" || !path.is_absolute() {
        return Err(Refusal::refused(
            format!("systemd has no unit named {service}."),
            "Pass --unit with the name of the server's systemd unit.",
        ));
    }
    if !std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
        return Err(Refusal::refused(
            format!(
                "{} is a link, not a plain unit file, so it cannot be rewritten here.",
                path.display()
            ),
            "Change the unit where it is defined, or replace the link with a plain file.",
        ));
    }
    for drop_in in shown("DropInPaths").split_whitespace() {
        let text = std::fs::read_to_string(drop_in).unwrap_or_default();
        if text
            .lines()
            .any(|line| line.trim_start().starts_with("ExecStart"))
        {
            return Err(Refusal::refused(
                format!(
                    "The drop-in {drop_in} sets ExecStart, so changing the unit would not change what starts."
                ),
                "Move that ExecStart into the unit file, then run it again.",
            ));
        }
    }
    let text = std::fs::read_to_string(&path).map_err(|_| {
        Refusal::refused(
            format!("{} cannot be read.", path.display()),
            "Run it as root.",
        )
    })?;
    let exec_start = single_exec(&text).map_err(|reason| {
        Refusal::refused(
            format!("{}: {reason}.", path.display()),
            "Write the unit with one plain ExecStart line.",
        )
    })?;
    let words = infraternal_status::exec_words(&exec_start).ok_or_else(|| {
        Refusal::refused(
            format!("{}: its ExecStart cannot be read.", path.display()),
            "Fix the quoting of ExecStart.",
        )
    })?;
    if !words.iter().skip(1).any(|word| word == "server") {
        return Err(Refusal::refused(
            format!("{} does not run an infraternal server.", path.display()),
            "Pass --unit with the server's unit.",
        ));
    }
    let recorded = option(&words, "--data").and_then(|folder| std::fs::canonicalize(folder).ok());
    if recorded.as_deref() != Some(data) {
        return Err(Refusal::refused(
            format!(
                "{} serves another data folder than {}.",
                path.display(),
                data.display()
            ),
            "Pass --data with the folder the unit's --data names.",
        ));
    }
    if text.lines().any(|line| {
        line.trim_start()
            .strip_prefix("User=")
            .is_some_and(|user| !matches!(user.trim(), "" | "root" | "0"))
    }) {
        return Err(Refusal::refused(
            format!(
                "{} runs the server as another account; only a root server updates itself.",
                path.display()
            ),
            "Run the server as root (D251), then run it again.",
        ));
    }
    Ok(UnitFile {
        path,
        text,
        exec_start,
        words,
    })
}

/// The one `ExecStart=` value of `text`. Prefixes (`-`, `@`, `+`, `!`, `:`), several lines,
/// and continuation lines are refused: the rewrite must replace exactly what systemd runs.
fn single_exec(text: &str) -> Result<String, &'static str> {
    let values: Vec<&str> = text
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("ExecStart="))
        .collect();
    let [value] = values.as_slice() else {
        return Err(if values.is_empty() {
            "it has no ExecStart"
        } else {
            "it has more than one ExecStart"
        });
    };
    let value = value.trim();
    if value.ends_with('\\') {
        return Err("its ExecStart continues on another line");
    }
    if value.starts_with(['-', '@', '+', '!', ':']) {
        return Err("its ExecStart has a special prefix");
    }
    Ok(value.to_owned())
}

/// The value after `flag` (`--flag value` or `--flag=value`) in `words`.
fn option(words: &[String], flag: &str) -> Option<PathBuf> {
    words.iter().enumerate().find_map(|(index, word)| {
        if word == flag {
            words.get(index + 1).map(PathBuf::from)
        } else {
            word.strip_prefix(flag)
                .and_then(|rest| rest.strip_prefix('='))
                .map(PathBuf::from)
        }
    })
}

/// The new `ExecStart` value: `pointer` as the program and every other word kept, minus
/// `--web-root <folder>` when `drop_web` (the release serves its own web build). Each word
/// is quoted the way `server init` writes units.
fn rewrite_exec(words: &[String], pointer: &Path, drop_web: bool) -> Result<String, &'static str> {
    let mut kept = vec![pointer.as_os_str().to_owned()];
    let mut skip = false;
    for word in words.iter().skip(1) {
        if skip {
            skip = false;
            continue;
        }
        if drop_web && word == "--web-root" {
            skip = true;
            continue;
        }
        if drop_web && word.starts_with("--web-root=") {
            continue;
        }
        kept.push(word.into());
    }
    kept.iter()
        .map(|word| {
            crate::install::quote_systemd(word).map_err(|_| "a word holds a control character")
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|words| words.join(" "))
}

/// `text` with its one `ExecStart=` line replaced by `exec`, keeping its indentation and
/// every other line byte for byte.
fn replace_exec(text: &str, exec: &str) -> String {
    let mut out = String::with_capacity(text.len() + exec.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("ExecStart=") {
            let indent = &line[..line.len() - trimmed.len()];
            out.push_str(indent);
            out.push_str("ExecStart=");
            out.push_str(exec);
            out.push('\n');
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Copy the unit to `backup` (0600, in a 0700 folder) before it changes.
fn write_backup(unit: &UnitFile, backup: &Path) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let folder = backup.parent().ok_or("the backup folder is missing")?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(folder)
        .map_err(|_| {
            format!(
                "The unit backup folder {} could not be made.",
                folder.display()
            )
        })?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(backup)
        .map_err(|_| format!("The unit backup {} could not be written.", backup.display()))?;
    file.write_all(unit.text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| format!("The unit backup {} could not be written.", backup.display()))
}

/// Put the unit's old text back and reload systemd (best effort: the caller reports failure anyway).
fn restore(unit: &UnitFile) {
    let _ = crate::install::write_atomic(&unit.path, unit.text.as_bytes());
    let _ = daemon_reload();
}

/// `systemctl daemon-reload`; whether it succeeded.
fn daemon_reload() -> bool {
    crate::install::systemctl_program()
        .ok()
        .and_then(|program| {
            crate::install::systemctl_command(&program)
                .arg("daemon-reload")
                .status()
                .ok()
        })
        .is_some_and(|status| status.success())
}

/// `systemctl show <service>` for `properties`, as a lookup from a property to its value
/// (empty when systemd did not print it).
fn show(service: &str, properties: &[&str]) -> Result<impl Fn(&str) -> String, Refusal> {
    let program = crate::install::systemctl_program().map_err(|_| {
        Refusal::refused("systemctl was not found.", "Run it on a systemd machine.")
    })?;
    let mut command = crate::install::systemctl_command(&program);
    command.args(["show", service]);
    for property in properties {
        command.arg(format!("--property={property}"));
    }
    let output = command.output().map_err(|_| {
        Refusal::refused(
            "systemctl could not be asked about the unit.",
            "Check systemctl.",
        )
    })?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    Ok(move |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or("")
            .to_owned()
    })
}

/// The unit's main PID, if it is active and its process runs as root.
fn active_root_service(service: &str) -> Result<u32, Refusal> {
    let value = show(service, &["ActiveState", "MainPID"])?;
    let pid: u32 = value("MainPID").parse().unwrap_or(0);
    if value("ActiveState") != "active" || pid == 0 {
        return Err(Refusal::refused(
            format!("{service} is not running, so there is no server to move warm."),
            format!("Start it with systemctl start {service}, unlock its CA, then run it again."),
        ));
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let euid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().nth(1))
        .unwrap_or("");
    if euid != "0" {
        return Err(Refusal::refused(
            format!("{service} does not run as root; only a root server updates itself."),
            "Run the server as root (D251), then run it again.",
        ));
    }
    Ok(pid)
}

/// The running server's version, from `release.update.status` on its control socket.
async fn running_version(data: &Path) -> Result<String, Refusal> {
    use infraternal_server::release_control::{CallError, call};
    let status = infraternal_plugin_release::descriptor::UPDATE_STATUS.id;
    match call(data, status, &json!({})).await {
        Ok(value) => value["current"]
            .as_str()
            .filter(|version| infraternal_plugin_api::release_version::channel(version).is_some())
            .map(str::to_owned)
            .ok_or_else(|| {
                Refusal::refused(
                    "The running server is not a signed release build, so its version is unknown.",
                    "Deploy a release build first, then run it again.",
                )
            }),
        Err(CallError::NotRunning) => Err(Refusal::refused(
            format!("No running server answered in {}.", data.display()),
            "Pass --data with the running server's data folder.",
        )),
        Err(CallError::NotAllowed) => Err(Refusal::refused(
            "The server's control socket did not accept this account.",
            "Run it as root on the server machine.",
        )),
        Err(_) => Err(Refusal::refused(
            "The running server did not say its version; it may be older than infraternal server update.",
            "Move it once to a build that has infraternal server update (infraternal server restart --binary), then run it again.",
        )),
    }
}

/// Now as a UTC stamp (`YYYYMMDD-HHMMSS`), for the unit backup's name.
fn utc_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let (year, month, day, hour, minute, second) = crate::install_move::utc_parts(seconds);
    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}")
}

/// Wait until the server answers its control socket with `version`, for up to [`COME_BACK`].
async fn comes_back(data: &Path, version: &str) -> bool {
    let deadline = tokio::time::Instant::now() + COME_BACK;
    while tokio::time::Instant::now() < deadline {
        if running_version(data)
            .await
            .is_ok_and(|running| running == version)
        {
            return true;
        }
        // sleep: the restarted server is starting its control socket; poll it at 4 Hz.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Unit checks for the unit rewrite.
#[cfg(test)]
#[path = "server_adopt_tests.rs"]
mod tests;
