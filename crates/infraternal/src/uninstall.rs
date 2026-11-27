//! Preview and remove one native host installation using its existing ownership checks.

use crate::cli::output::{CommandResult, CommandState, Exit, emit, print};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::{Command, ExitCode},
};

/// Trusted per-platform details found before any removal or elevation.
struct Plan {
    /// System or current account's service.
    system: bool,
    /// Stable host ID where the receipt is readable.
    host: Option<String>,
    /// Native installation root, also used to pin the reviewed install across sudo.
    base: PathBuf,
    /// Private host enrollment, read only by the installation owner.
    data: PathBuf,
    /// Files and resources affected by removal.
    targets: Vec<String>,
    /// Shell changes the installer asked the person to make manually.
    notes: Vec<String>,
}

impl Plan {
    /// Present a consistent human and JSON review without exposing enrollment material.
    fn preview(&self, keep: bool, sudo: bool) -> CommandResult<Value> {
        let mut targets = self.targets.clone();
        if keep {
            targets.push(format!(
                "Save enrollment from {}",
                safe_text(&self.data.to_string_lossy())
            ));
        } else {
            targets.push(format!(
                "Delete enrollment and keys in {}",
                self.data.display()
            ));
        }
        let mut body = targets
            .iter()
            .map(|target| format!("  {target}"))
            .collect::<Vec<_>>();
        body.push("Ask the server to retire this host and end its remote sessions.".into());
        body.extend(self.notes.iter().cloned());
        if sudo {
            body.push("Administrator access stops the system service and removes its files and network settings.".into());
        }
        CommandResult::new(
            "uninstall",
            CommandState::Pending,
            if self.system { "Remove the system installation?" } else { "Remove your infraternal installation?" },
            json!({"system": self.system, "remove": targets, "notes": self.notes, "keep_state": keep, "administrator_required": sudo}),
        ).with_body(body.join("\n"))
    }

    /// Identify the reviewed directory so a replacement cannot be selected after sudo.
    fn identity(&self) -> io::Result<String> {
        let metadata = fs::symlink_metadata(&self.base)?;
        if !metadata.is_dir() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(format!("{}:{}", metadata.dev(), metadata.ino()))
    }
}

/// Run a read-only review, or collect consent and remove the reviewed installation.
pub(crate) fn run(matches: &clap::ArgMatches, json: bool) -> ExitCode {
    let keep = matches.get_flag("keep_state");
    let yes = matches.get_flag("yes");
    let plan = match discover(matches.get_flag("system")) {
        Ok(plan) => plan,
        Err(error) => return discovery_error(error, json),
    };
    let sudo = plan.system && !nix::unistd::Uid::effective().is_root();
    let preview = plan.preview(keep, sudo);
    if matches.get_flag("dry_run") || (!yes && (json || !io::stdin().is_terminal())) {
        let system_flag = if plan.system { " --system" } else { "" };
        let keep_flag = if keep { " --keep-state" } else { "" };
        return emit(
            preview.with_next_step(format!("Run infraternal uninstall{system_flag}{keep_flag} --yes to remove this installation.")),
            json,
            Exit::Ok,
        );
    }
    let identity = match plan.identity() {
        Ok(identity) => identity,
        Err(error) => return discovery_error(error, json),
    };
    if !json {
        print(&preview, false, true);
    }
    if !yes && !confirm(&mut io::stdin().lock(), &mut io::stderr().lock()) {
        return emit(
            CommandResult::new(
                "uninstall",
                CommandState::Stopped,
                "Kept infraternal on this machine.",
                json!({}),
            ),
            json,
            Exit::Ok,
        );
    }
    if sudo {
        return elevate(&plan, &identity, keep, json);
    }
    if plan.identity().as_deref().ok() != Some(&identity) {
        return discovery_error(io::ErrorKind::PermissionDenied.into(), json);
    }
    execute(&plan, keep, json)
}

/// Enter keeps the install. This is the only destructive confirmation.
fn confirm(input: &mut impl io::BufRead, output: &mut impl Write) -> bool {
    let mut answer = String::new();
    write!(
        output,
        "Type Remove to uninstall, or press Enter to keep it. "
    )
    .is_ok()
        && output.flush().is_ok()
        && input.read_line(&mut answer).is_ok()
        && answer.trim().eq_ignore_ascii_case("remove")
}

/// Use the current command if it is trusted, otherwise the installed system image.
fn elevate(plan: &Plan, identity: &str, keep: bool, json: bool) -> ExitCode {
    use crate::trusted_program::trusted_program;
    let sudo = trusted_program(&["/usr/bin/sudo", "/bin/sudo", "/run/wrappers/bin/sudo"], 0);
    let executable = std::env::current_exe()
        .ok()
        .and_then(|path| trusted_program(&[path], 0).ok())
        .or_else(|| trusted_program(&[system_binary(plan)], 0).ok());
    let (Ok(sudo), Some(executable)) = (sudo, executable) else {
        return emit(CommandResult::new("uninstall", CommandState::Refused,
            "Couldn't start the system uninstall.", json!({}))
            .with_next_step("Run an up-to-date, administrator-owned infraternal binary with uninstall --system."), json, Exit::NotAllowed);
    };
    let mut command = Command::new(sudo);
    command.env_clear();
    if json || !io::stdin().is_terminal() {
        command.arg("-n");
    } else {
        command.args(["-p", "Password: "]);
    }
    command.arg("--").arg(executable).args([
        "__uninstall-reviewed",
        identity,
        if keep { "keep" } else { "remove" },
        if json { "json" } else { "text" },
    ]);
    if json {
        if let Ok(output) = command.output()
            && serde_json::from_slice::<Value>(&output.stdout).is_ok()
            && io::stdout().write_all(&output.stdout).is_ok()
            && let Some(code) = exit_status(output.status)
        {
            return code;
        }
    } else {
        if io::stderr().is_terminal() {
            eprintln!(
                "Administrator access stops the system service and removes its files and mesh settings.\nGrant access to finish the uninstall. If you decline, the system installation stays in place."
            );
        }
        if let Ok(status) = command.status()
            && status.success()
        {
            return ExitCode::SUCCESS;
        }
    }
    emit(
        CommandResult::new(
            "uninstall",
            CommandState::Failed,
            "Couldn't complete the system uninstall.",
            json!({}),
        )
        .with_next_step(
            "Check your administrator access and run an up-to-date infraternal uninstall --system.",
        ),
        json,
        Exit::Failed,
    )
}

/// Forward an elevated child status through the public CLI.
fn exit_status(status: std::process::ExitStatus) -> Option<ExitCode> {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map(ExitCode::from)
}

/// Accept only the fixed system operation and the fingerprint of the previewed directory.
pub(crate) fn elevated_if_requested() -> Option<ExitCode> {
    let mut args = std::env::args_os().skip(1);
    if args.next()? != "__uninstall-reviewed" {
        return None;
    }
    let [Some(identity), Some(keep), Some(format), None] = std::array::from_fn(|_| args.next())
    else {
        return Some(ExitCode::FAILURE);
    };
    let json = format == "json";
    if !nix::unistd::Uid::effective().is_root()
        || (keep != "keep" && keep != "remove")
        || (!json && format != "text")
    {
        return Some(discovery_error(
            io::ErrorKind::PermissionDenied.into(),
            json,
        ));
    }
    Some(match discover(true) {
        Ok(plan)
            if plan
                .identity()
                .is_ok_and(|actual| identity == actual.as_str()) =>
        {
            execute(&plan, keep == "keep", json)
        }
        Ok(_) => discovery_error(io::ErrorKind::PermissionDenied.into(), json),
        Err(error) => discovery_error(error, json),
    })
}

/// Keep a discovery failure distinct from a failure after cleanup has started.
fn discovery_error(error: io::Error, json: bool) -> ExitCode {
    if error.kind() == io::ErrorKind::NotFound {
        return emit(
            CommandResult::new(
                "uninstall",
                CommandState::Stopped,
                "No infraternal installation found for this account or system.",
                json!({}),
            ),
            json,
            Exit::Ok,
        );
    }
    emit(CommandResult::new("uninstall", CommandState::Refused, "Couldn't verify the infraternal installation.", json!({}))
        .with_details(error.to_string())
        .with_next_step("Check the service with infraternal status, then run uninstall from the account that installed it."), json, Exit::NotAllowed)
}

/// Ask the server before stopping its local link, then carry out owned cleanup.
fn execute(plan: &Plan, keep: bool, json_output: bool) -> ExitCode {
    let Some(host) = plan.host.as_deref() else {
        return discovery_error(io::ErrorKind::PermissionDenied.into(), json_output);
    };
    let backup =
        keep.then(|| infraternal_plugin_api::uninstall_state::destination(&plan.base, host));
    if let Some(path) = &backup
        && let Err(error) = infraternal_plugin_api::uninstall_state::check_destination(path)
    {
        return discovery_error(error, json_output);
    }
    let server = crate::remote::retire_for_local_uninstall(&plan.data, host);
    let left = match remove(plan, host, keep) {
        Ok(left) => left,
        Err(error) => {
            return emit(
                CommandResult::new(
                    "uninstall",
                    CommandState::Failed,
                    "Couldn't finish removing infraternal.",
                    json!({"host_id": host, "server_retired": server}),
                )
                .with_details(error.to_string())
                .with_next_step("Check the reported resource and run infraternal uninstall again."),
                json_output,
                Exit::Failed,
            );
        }
    };
    let mut data = json!({"host_id": host, "server_retired": server, "remaining": left});
    if let Some(backup) = backup {
        data["saved_state"] = json!(backup);
    }
    let mut result = CommandResult::new(
        "uninstall",
        CommandState::Ready,
        "Removed infraternal from this machine.",
        data,
    );
    if !server {
        result = result.with_next_step("The server may still list this host. In the machine list, select Remove, then Forget if cleanup is pending.");
    }
    emit(result, json_output, Exit::Ok)
}

/// Show native paths without interpolating raw terminal control characters.
fn paths(targets: impl IntoIterator<Item = PathBuf>) -> Vec<String> {
    targets
        .into_iter()
        .map(|file| safe_text(&file.to_string_lossy()))
        .collect()
}

/// Preserve printable path characters while escaping terminal control characters.
fn safe_text(text: &str) -> String {
    let mut escaped = String::new();
    for character in text.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Discover the caller's native service first, or the system service when selected or alone.
fn discover(system: bool) -> io::Result<Plan> {
    let uid = nix::unistd::Uid::effective().as_raw();
    if !system && uid != 0 {
        match user_plan(uid) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            result => return result,
        }
    }
    system_plan(uid)
}

#[cfg(target_os = "linux")]
/// Read the password database so a shell's HOME cannot select another install.
fn home(uid: u32) -> io::Result<PathBuf> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?
        .map(|user| user.dir)
        .ok_or_else(|| io::ErrorKind::NotFound.into())
}

#[cfg(target_os = "linux")]
/// Review this account's systemd installation.
fn user_plan(uid: u32) -> io::Result<Plan> {
    linux_plan(uid, uid)
}

#[cfg(target_os = "linux")]
/// Review the installed systemd system service and associated mesh resources.
fn system_plan(caller: u32) -> io::Result<Plan> {
    linux_plan(0, caller)
}

#[cfg(target_os = "linux")]
/// Adapt the bootstrap ownership check to the public preview.
fn linux_plan(uid: u32, caller: u32) -> io::Result<Plan> {
    let review = infraternal_plugin_remote::uninstall::review(&home(uid)?, uid, caller)?;
    let mut targets = paths(review.paths);
    if uid == 0 {
        targets.push(
            "Owned infraternal0 mesh interface, routes and firewall rules, if present".into(),
        );
    }
    Ok(Plan {
        system: uid == 0,
        host: Some(review.context.host),
        base: review.base,
        data: review.context.data,
        targets,
        notes: vec!["Systemd keeps service logs in the shared journal until they expire.".into()],
    })
}

#[cfg(target_os = "linux")]
/// The root-owned image under the bootstrap install's binary directory.
fn system_binary(plan: &Plan) -> PathBuf {
    plan.base.join("bin/live")
}

#[cfg(target_os = "linux")]
/// Share the legacy removal path's service, shim and kernel cleanup.
fn remove(_plan: &Plan, host: &str, keep: bool) -> io::Result<Vec<String>> {
    use infraternal_plugin_remote::uninstall::{cleanup_with_state, installation};
    let uid = nix::unistd::Uid::effective().as_raw();
    let home = home(uid)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(cleanup_with_state(
            &installation(host, &home, uid),
            &home,
            uid,
            infraternal_agent::plugins::KERNEL,
            keep,
        )))
}

#[cfg(target_os = "macos")]
/// Review the GUI user's LaunchAgent and the helper provisioned for that uid.
fn user_plan(uid: u32) -> io::Result<Plan> {
    use infraternal_plugin_mesh::macos_user_mode as names;
    let review = crate::up::macos_user::review_uninstall(uid)?;
    let mut targets = paths(review.paths);
    targets.push("Mesh tunnel and its routes, if active".into());
    if review.helper {
        targets.extend(
            [
                names::HELPER_PLIST,
                names::HELPER_BINARY,
                names::HELPER_SOCKET,
                "Resolver files in /etc/resolver written by the infraternal mesh helper",
            ]
            .map(str::to_owned),
        );
    }
    Ok(Plan {
        system: false,
        host: Some(review.host),
        base: review.base,
        data: review.data,
        targets,
        notes: vec![format!(
            "If you added this PATH line, remove it from your shell configuration.\n  {}",
            safe_text(&review.path_line)
        )],
    })
}

#[cfg(target_os = "macos")]
/// Review the root-mode LaunchDaemon and its fixed machine paths.
fn system_plan(_caller: u32) -> io::Result<Plan> {
    use infraternal_plugin_mesh::macos_service as service;
    let (host, paths_to_remove) = service::review_removal()?;
    let mut targets = paths(paths_to_remove);
    targets.push("Mesh tunnel and its routes, if active".into());
    Ok(Plan {
        system: true,
        host,
        base: service::MACHINE_BASE.into(),
        data: service::MACHINE_DATA.into(),
        targets,
        notes: Vec::new(),
    })
}

#[cfg(target_os = "macos")]
/// The trusted system image used by the root LaunchDaemon.
fn system_binary(_plan: &Plan) -> PathBuf {
    infraternal_plugin_mesh::macos_service::MACHINE_BINARY.into()
}

#[cfg(target_os = "macos")]
/// Share the existing launchd, helper and file cleanup paths.
fn remove(plan: &Plan, host: &str, keep: bool) -> io::Result<Vec<String>> {
    if plan.system {
        infraternal_plugin_mesh::macos_service::remove_installation(host, keep)?;
    } else {
        crate::up::macos_user::remove_user_install(
            nix::unistd::Uid::effective().as_raw(),
            host,
            keep,
        )?;
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    //! Consent and preview behave consistently in interactive and scripted use.

    use super::*;

    /// Closing stdin, Enter, or a mistyped answer leaves the installation in place.
    #[test]
    fn confirmation_requires_the_remove_verb() {
        for answer in ["", "\n", "yes\n", "remove system\n"] {
            assert!(!confirm(&mut answer.as_bytes(), &mut Vec::new()));
        }
        assert!(confirm(&mut "Remove\n".as_bytes(), &mut Vec::new()));
    }

    /// Keeping enrollment changes the preview and leaves the service and network targets visible.
    #[test]
    fn preview_describes_the_scope_and_saved_state() {
        let plan = Plan {
            system: true,
            host: None,
            base: "/install".into(),
            data: "/install/enrollment".into(),
            targets: vec!["Service".into(), "Mesh interface".into()],
            notes: Vec::new(),
        };
        let preview = plan.preview(true, true);
        assert_eq!(preview.data["system"], true);
        assert_eq!(preview.data["administrator_required"], true);
        assert_eq!(
            preview.data["remove"][2],
            "Save enrollment from /install/enrollment"
        );
        assert_eq!(
            plan.preview(false, false).data["remove"][2],
            "Delete enrollment and keys in /install/enrollment"
        );
    }
}
