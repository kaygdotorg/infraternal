//! Writes and enables the server's systemd service while preserving a different existing unit unless forced [49].

use super::{InstallArgs, ServerArgs, origin_for_listener};
use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(target_os = "linux")]
use infraternal_plugin_mesh::host_firewall::{self, Policy, PolicyRole};

#[cfg(target_os = "linux")]
/// The boot unit whose rules are loaded before network setup.
const FIREWALL_SERVICE: &str = "infraternal-firewall.service";

#[cfg(target_os = "linux")]
/// Systemd destination replaced when the product takes over the hand unit.
const FIREWALL_UNIT_PATH: &str = "/etc/systemd/system/infraternal-firewall.service";

#[cfg(target_os = "linux")]
/// Files and policy that one system server install publishes together.
#[derive(serde::Deserialize, serde::Serialize)]
struct FirewallInstall {
    /// The generated boot-time unit that supersedes the hand-installed service.
    unit: String,
    /// The complete structured server policy saved for boot-time application.
    policy: Policy,
    /// JSON kept in the dry-run plan for review before installation.
    policy_json: String,
}

/// Install failures expose the failed operation without including service arguments or key contents.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The requested unit name or path contains unsupported data.
    #[error("invalid unit name or path")]
    Invalid,
    /// The destination cannot be inspected or written.
    #[error("unit file I/O failed")]
    Io(#[source] std::io::Error),
    /// A different unit already exists and `--force` was not specified.
    #[error("a different unit already exists; pass --force to replace it")]
    ExistingUnit,
    /// The requested migration would change the active service configuration.
    #[error(transparent)]
    Move(#[from] super::install_move::MoveError),
    /// systemd rejected the requested reload or enable operation.
    #[error("systemctl failed")]
    Systemctl,
    /// A server host-firewall setting is malformed or unsafe to apply.
    #[error("host firewall configuration is invalid: {0}")]
    HostFirewall(String),
    /// `SELinux` labeling for `<data>/updates` could not be planned or applied (#211).
    #[cfg(target_os = "linux")]
    #[error("SELinux setup failed: {0}")]
    Selinux(String),
}

/// Install the unit and enable it, or print the exact operations in dry-run mode.
pub fn install(args: &ServerArgs, options: &InstallArgs) -> Result<String, InstallError> {
    validate_name(&options.name)?;
    let user = !options.system || options.user;
    if args.host_firewall_off && user {
        return Err(InstallError::HostFirewall(
            "--host-firewall-off is available only for a system install".to_owned(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    if args.host_firewall_off {
        return Err(InstallError::Invalid);
    }
    let path = unit_path(user, &options.name)?;
    let origin = args
        .public_origin
        .clone()
        .unwrap_or_else(|| origin_for_listener(args.listen));
    let unit = render_unit(args, &options.name, &origin, user)?;
    let scope_args = if user { vec!["--user"] } else { Vec::new() };
    let service = format!("{}.service", options.name);
    let reload = format!("systemctl {} daemon-reload", scope_args.join(" "));
    let enable = format!("systemctl {} enable --now {service}", scope_args.join(" "));
    #[cfg(target_os = "linux")]
    if options.system && options.name == "infraternal-firewall" {
        return Err(InstallError::Invalid);
    }

    if options.dry_run {
        // Every plan, firewall or not, starts with the folders the unit will
        // use, so a system plan shows the D395 default or the folder a re-run
        // keeps from the installed unit (#516, J692).
        let folders = format!(
            "Data folder: {}\n{}",
            absolute(&args.data)?.display(),
            match &args.web_root {
                Some(web_root) => format!("Web folder: {}\n", absolute(web_root)?.display()),
                None => String::new(),
            },
        );
        #[cfg(target_os = "linux")]
        if options.system {
            let selinux_lines = selinux_dry_run_lines(&absolute(&args.data)?)?;
            if args.host_firewall_off {
                return Ok(format!(
                    "{folders}Would clear the server host policy, remove only marked infraternal host table and loader state when no agent policy remains, and write {}:\n{}\nWould run:\n{selinux_lines}  systemctl daemon-reload\n  systemctl enable --now {}.service\n",
                    path.display(),
                    unit,
                    options.name,
                ) + &link_plan(user, &args.data)?);
            }
            let firewall = make_firewall_install(args)?;
            return Ok(format!(
                "{folders}Would replace the hand-installed {FIREWALL_SERVICE} and take over inet infraternal_host.\nWould write {}:\n{}\nWould write {}:\n{}\nWould write {}:\n{}\nWould run:\n{selinux_lines}  systemctl daemon-reload\n  systemctl enable {FIREWALL_SERVICE}\n  systemctl restart {FIREWALL_SERVICE}\n  {}\n",
                host_firewall::SERVER_POLICY_PATH,
                firewall.policy_json,
                FIREWALL_UNIT_PATH,
                firewall.unit,
                path.display(),
                unit,
                enable,
            ) + &link_plan(user, &args.data)?);
        }
        return Ok(format!(
            "{folders}Would write {}:\n{}\nWould run:\n  {}\n  {}\n",
            path.display(),
            unit,
            reload,
            enable
        ) + &link_plan(user, &args.data)?);
    }

    let systemctl = systemctl_program()?;
    let data_dir = absolute(&args.data)?;
    let ((firewall, _selinux), removal_report) = install_in_order(
        &path,
        unit.as_bytes(),
        &data_dir,
        options.force,
        || {
            let firewall = plan_firewall(args, options)?;
            let selinux = plan_selinux(&data_dir, options)?;
            Ok((firewall, selinux))
        },
        |(firewall, selinux)| {
            let report = publish_planned_firewall(firewall, &systemctl)?;
            apply_planned_selinux(selinux.as_ref())?;
            Ok(report)
        },
    )?;

    if !systemctl_command(&systemctl)
        .args(&scope_args)
        .arg("daemon-reload")
        .status()
        .map_err(InstallError::Io)?
        .success()
    {
        return Err(InstallError::Systemctl);
    }
    if !systemctl_command(&systemctl)
        .args(&scope_args)
        .args(["enable", "--now", &service])
        .status()
        .map_err(InstallError::Io)?
        .success()
    {
        return Err(InstallError::Systemctl);
    }
    // Last, so a failed install never leaves a link to a service that is not there.
    // A problem here is reported, not fatal: the service itself is already running.
    // Every successful path reaches this line, the firewall ones included (J755).
    eprintln!("{}", link_note(user, &args.data));
    Ok(match (firewall, removal_report) {
        #[cfg(target_os = "linux")]
        (FirewallPlan::Install(_), _) => firewall_install_confirmation(&path),
        (_, Some(report)) => format!("{report}Installed and enabled {}\n", path.display()),
        _ => format!("Installed and enabled {}\n", path.display()),
    })
}

/// Admission and fixed manager program for a move of an existing service.
#[derive(serde::Deserialize, serde::Serialize)]
pub struct MoveInstall {
    /// The same manager used for both the firewall and server restart.
    pub systemctl: PathBuf,
    /// Policy checked before any change to data or units.
    firewall: FirewallPlan,
}

impl MoveInstall {
    /// Publish the policy before the migration can switch `ExecStart`.
    pub fn publish(&self) -> std::io::Result<()> {
        publish_planned_firewall(&self.firewall, &self.systemctl)
            .map(drop)
            .map_err(std::io::Error::other)
    }
}

/// Validate the final command and firewall before the migration can stop the service.
pub fn prepare_move(
    args: &ServerArgs,
    options: &InstallArgs,
    relocation: &super::install_move::Relocation,
) -> Result<MoveInstall, InstallError> {
    validate_name(&options.name)?;
    let user = !options.system || options.user;
    if (args.host_firewall_off && (user || cfg!(not(target_os = "linux"))))
        || (options.system && options.name == "infraternal-firewall")
    {
        return Err(InstallError::Invalid);
    }
    let firewall = plan_firewall(args, options)?;
    #[cfg(target_os = "linux")]
    if matches!(firewall, FirewallPlan::ClearServerRole)
        && host_firewall::read_policy_file(Path::new(host_firewall::SERVER_POLICY_PATH))
            .map_err(|error| InstallError::HostFirewall(error.to_string()))?
            .is_some()
    {
        return Err(InstallError::HostFirewall(
            "move with the existing host firewall policy before clearing it".to_owned(),
        ));
    }
    if args.listen.port() == 0 {
        return Err(InstallError::Invalid);
    }
    let origin = args
        .public_origin
        .clone()
        .unwrap_or_else(|| origin_for_listener(args.listen));
    let unit = render_unit(args, &options.name, &origin, user)?;
    relocation.check_command(&unit)?;
    Ok(MoveInstall {
        systemctl: systemctl_program()?,
        firewall,
    })
}

/// Publish the convenience link after the moved service is healthy.
pub fn finish_move(user: bool, data: &Path) {
    eprintln!("{}", link_note(user, data));
}

/// What a server install does to the host firewall, decided before anything is written.
///
/// Only a system install on Linux touches the host firewall (D392): it
/// either publishes the server's default-drop policy or, with
/// `--host-firewall-off`, clears the server role.
#[derive(serde::Deserialize, serde::Serialize)]
enum FirewallPlan {
    /// A user install, or a platform without the host firewall.
    Untouched,
    /// Publish this checked policy and its loader unit.
    #[cfg(target_os = "linux")]
    Install(FirewallInstall),
    /// Clear the server role from the saved host policy.
    #[cfg(target_os = "linux")]
    ClearServerRole,
}

/// Decide the firewall step and run its checks, the sshd admission check included, without side effects.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
fn plan_firewall(args: &ServerArgs, options: &InstallArgs) -> Result<FirewallPlan, InstallError> {
    #[cfg(target_os = "linux")]
    if options.system {
        return Ok(if args.host_firewall_off {
            FirewallPlan::ClearServerRole
        } else {
            FirewallPlan::Install(make_firewall_install(args)?)
        });
    }
    let _ = (args, options);
    Ok(FirewallPlan::Untouched)
}

/// Indented dry-run lines for `SELinux` boot-pointer labeling on Linux system installs (#211).
///
/// Returns an empty string on non-SELinux hosts so their dry-run output is unchanged.
#[cfg(target_os = "linux")]
fn selinux_dry_run_lines(data: &Path) -> Result<String, InstallError> {
    let plan = crate::selinux::plan_for_host(data, true)
        .map_err(|error| InstallError::Selinux(error.to_string()))?;
    Ok(format_selinux_dry_run_lines(plan.as_ref()))
}

/// Format planned `SELinux` commands as indented `Would run:` lines.
#[cfg(target_os = "linux")]
fn format_selinux_dry_run_lines(plan: Option<&crate::selinux::LabelPlan>) -> String {
    let Some(plan) = plan else {
        return String::new();
    };
    let mut lines = String::new();
    for command in plan.dry_run_commands() {
        lines.push_str("  ");
        lines.push_str(&command);
        lines.push('\n');
    }
    lines
}

/// Plan `SELinux` labeling for `<data>/updates` on Linux system installs without side effects (#211).
#[cfg(target_os = "linux")]
fn plan_selinux(
    data: &Path,
    options: &InstallArgs,
) -> Result<Option<crate::selinux::LabelPlan>, InstallError> {
    if !options.system {
        return Ok(None);
    }
    crate::selinux::plan_for_host(data, false)
        .map_err(|error| InstallError::Selinux(error.to_string()))
}

/// Non-Linux hosts have no `SELinux` policy to configure.
#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the Linux signature used by install_in_order"
)]
fn plan_selinux(_data: &Path, _options: &InstallArgs) -> Result<Option<()>, InstallError> {
    Ok(None)
}

/// Apply the planned `SELinux` labeling before the systemd unit is written (#211).
#[cfg(target_os = "linux")]
fn apply_planned_selinux(plan: Option<&crate::selinux::LabelPlan>) -> Result<(), InstallError> {
    if let Some(plan) = plan {
        crate::selinux::apply_on_host(plan)
            .map_err(|error| InstallError::Selinux(error.to_string()))?;
    }
    Ok(())
}

/// Non-Linux no-op counterpart of [`apply_planned_selinux`].
#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the Linux signature used by install_in_order"
)]
fn apply_planned_selinux(_plan: Option<&()>) -> Result<(), InstallError> {
    Ok(())
}

/// Carry out a [`FirewallPlan`]; returns the removal report when the server role was cleared.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
fn publish_planned_firewall(
    plan: &FirewallPlan,
    systemctl: &Path,
) -> Result<Option<String>, InstallError> {
    match plan {
        FirewallPlan::Untouched => {
            let _ = systemctl;
            Ok(None)
        }
        #[cfg(target_os = "linux")]
        FirewallPlan::ClearServerRole => host_firewall::clear_role_from_config(PolicyRole::Server)
            .map(Some)
            .map_err(|error| InstallError::HostFirewall(error.to_string())),
        #[cfg(target_os = "linux")]
        FirewallPlan::Install(firewall) => {
            publish_firewall(
                firewall,
                &FirewallTargets {
                    policy: Path::new(host_firewall::SERVER_POLICY_PATH),
                    unit: Path::new(FIREWALL_UNIT_PATH),
                },
                &|path, policy| {
                    host_firewall::write_policy_file(path, policy)
                        .map_err(|error| InstallError::Io(std::io::Error::other(error)))
                },
                &mut |arguments| {
                    Ok(systemctl_command(systemctl)
                        .args(arguments)
                        .status()
                        .map_err(InstallError::Io)?
                        .success())
                },
            )?;
            Ok(None)
        }
    }
}

/// Run a server install's file steps in the one order every path uses (#483, #516, J755).
///
/// 1. Decide whether the unit may be written ([`ensure_server_unit_writable`]).
/// 2. `admit`: every check that can refuse, such as the host firewall's sshd
///    admission check. It must have no side effects.
/// 3. Create the data folder 0700 ([`create_private_dir`]; an existing
///    folder keeps its mode).
/// 4. `publish`: the host firewall's policy and loader.
/// 5. Write the unit, only when its bytes changed.
///
/// So a refusal in 1 or 2 creates nothing, not even the data folder. The
/// folder exists, private, before the firewall policy is saved, because the
/// server policy lives in `/var/lib/infraternal` (D395) and the policy writer
/// would otherwise create it. A failed folder or firewall step leaves no new
/// unit, so no service starts without its data or its firewall. A
/// byte-identical unit is never rewritten, so re-running init on an unchanged
/// install keeps the file as it was (J692).
///
/// [`create_private_dir`]: super::install_paths::create_private_dir
fn install_in_order<A, P>(
    path: &Path,
    unit: &[u8],
    data: &Path,
    force: bool,
    admit: impl FnOnce() -> Result<A, InstallError>,
    publish: impl FnOnce(&A) -> Result<P, InstallError>,
) -> Result<(A, P), InstallError> {
    let write_unit = ensure_server_unit_writable(path, unit, force)?;
    let admitted = admit()?;
    if cfg!(target_os = "linux") && data == Path::new(super::install_paths::LINUX_COMBINED_SERVER) {
        super::install_move::create_combined_server_dir(data).map_err(InstallError::Io)?;
    } else {
        super::install_paths::create_private_dir(data).map_err(InstallError::Io)?;
    }
    let published = publish(&admitted)?;
    if write_unit {
        write_atomic(path, unit).map_err(InstallError::Io)?;
    }
    Ok((admitted, published))
}

/// Where a system server install publishes its host firewall policy and loader unit.
///
/// Production uses the fixed paths ([`host_firewall::SERVER_POLICY_PATH`],
/// [`FIREWALL_UNIT_PATH`]); tests point both into a scratch directory.
#[cfg(target_os = "linux")]
struct FirewallTargets<'a> {
    /// The saved server policy the loader applies at boot.
    policy: &'a Path,
    /// The `infraternal-firewall.service` unit file.
    unit: &'a Path,
}

/// Save the server policy and loader unit, then enable the loader and apply the table now; undo all of it on failure.
///
/// `write_policy` saves the policy (production: the root-only atomic
/// writer) and `systemctl` runs one system-manager command, answering
/// whether it succeeded; both are parameters so the order and failure
/// handling can be tested without root.
///
/// Invariants (J658, #483):
/// - A unit already at the loader's path is replaced only when it carries
///   the product marker or is the known hand loader (#274,
///   [`host_firewall::known_hand_firewall_unit`]). Anything else is refused
///   before a file is written or a command runs (D386: only what is ours).
/// - When any step up to `restart` fails, the previous policy and unit are
///   restored (or removed when there were none), a loader that was not
///   enabled before is disabled, and the manager is reloaded. Otherwise a
///   rejected table left a saved policy and an enabled loader that the next
///   boot applied. The error says when the rollback itself failed.
#[cfg(target_os = "linux")]
fn publish_firewall(
    firewall: &FirewallInstall,
    targets: &FirewallTargets<'_>,
    write_policy: &dyn Fn(&Path, &Policy) -> Result<(), InstallError>,
    systemctl: &mut dyn FnMut(&[&str]) -> Result<bool, InstallError>,
) -> Result<(), InstallError> {
    let previous_unit = read_previous(targets.unit)?;
    if let Some(bytes) = &previous_unit
        && !bytes
            .split(|byte| *byte == b'\n')
            .any(|line| line == host_firewall::HOST_FIREWALL_UNIT_MARKER.as_bytes())
        && !host_firewall::known_hand_firewall_unit(bytes)
    {
        return Err(InstallError::HostFirewall(format!(
            "{} is not an infraternal firewall unit and was left unchanged; inspect it, move it \
             aside if it is no longer needed, then retry",
            targets.unit.display()
        )));
    }
    let previous_policy = read_previous(targets.policy)?;
    let was_enabled = systemctl(&["is-enabled", "--quiet", FIREWALL_SERVICE])?;
    let result = (|| -> Result<(), InstallError> {
        write_policy(targets.policy, &firewall.policy)?;
        write_atomic(targets.unit, firewall.unit.as_bytes()).map_err(InstallError::Io)?;
        for arguments in [
            &["daemon-reload"][..],
            &["enable", FIREWALL_SERVICE],
            &["restart", FIREWALL_SERVICE],
        ] {
            if !systemctl(arguments)? {
                return Err(InstallError::Systemctl);
            }
        }
        Ok(())
    })();
    let Err(error) = result else {
        return Ok(());
    };
    let mut incomplete = Vec::new();
    // Disable before the unit file goes: systemctl cannot disable a unit it no longer finds.
    if !was_enabled && !matches!(systemctl(&["disable", FIREWALL_SERVICE]), Ok(true)) {
        incomplete.push(format!("systemctl disable {FIREWALL_SERVICE}"));
    }
    for (path, bytes, mode) in [
        (targets.policy, previous_policy.as_deref(), 0o600),
        (targets.unit, previous_unit.as_deref(), 0o644),
    ] {
        if let Err(restore_error) = restore_previous(path, bytes, mode) {
            incomplete.push(format!("restore {}: {restore_error}", path.display()));
        }
    }
    if !matches!(systemctl(&["daemon-reload"]), Ok(true)) {
        incomplete.push("systemctl daemon-reload".to_owned());
    }
    if incomplete.is_empty() {
        return Err(error);
    }
    Err(InstallError::HostFirewall(format!(
        "{error}; rolling back also failed ({}); inspect {} and {} before the next boot",
        incomplete.join("; "),
        targets.policy.display(),
        targets.unit.display()
    )))
}

/// The bytes of a regular file that an install may replace, or `None` when it is absent.
///
/// A symlink or other non-regular file is refused rather than followed.
#[cfg(target_os = "linux")]
fn read_previous(path: &Path) -> Result<Option<Vec<u8>>, InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => fs::read(path).map(Some).map_err(InstallError::Io),
        Ok(_) => Err(InstallError::HostFirewall(format!(
            "{} is not a regular file; inspect it before retrying",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(InstallError::Io(error)),
    }
}

/// Put back the bytes `path` held before an install, or remove it when it did not exist.
#[cfg(target_os = "linux")]
fn restore_previous(path: &Path, bytes: Option<&[u8]>, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match bytes {
        Some(bytes) => {
            write_atomic(path, bytes)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
        }
        None => match fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        },
    }
}

/// The system manager at its fixed, root-owned path, never found through `PATH` (D384, D386).
///
/// `server init --system` runs these commands as root, so a writable
/// directory early in `PATH` must not be able to supply its own
/// `systemctl` (J658). The same binary serves `--user` installs.
#[cfg(target_os = "linux")]
pub(super) fn systemctl_program() -> Result<PathBuf, InstallError> {
    host_firewall::discover_systemctl(None)
        .map_err(|error| InstallError::HostFirewall(error.to_string()))
}

/// Elsewhere there is no systemd, so a real install stops here with [`InstallError::Systemctl`].
#[cfg(not(target_os = "linux"))]
pub(super) fn systemctl_program() -> Result<PathBuf, InstallError> {
    Err(InstallError::Systemctl)
}

/// A `systemctl` command with the child hygiene every install command gets and no stdin.
pub(super) fn systemctl_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    infraternal_shim::prepare_child(&mut command);
    command.stdin(std::process::Stdio::null());
    command
}

/// Tell operators that the product unit now owns the named host firewall service and table.
#[cfg(target_os = "linux")]
fn firewall_install_confirmation(server_unit: &Path) -> String {
    format!(
        "Installed and enabled {} and {FIREWALL_SERVICE}; it replaces the hand-installed {FIREWALL_SERVICE} and owns inet infraternal_host.\n",
        server_unit.display()
    )
}

/// Refuse a conflicting server unit before publishing the host policy, and say whether it must be written.
///
/// Returns `false` when the installed unit already holds exactly these
/// bytes (nothing to write), `true` when the unit is missing or `--force`
/// replaces a different one. It also refreshes the exact unit generated by
/// the previous server installer, whose only difference is its network
/// ordering. Other different units without `--force` are
/// [`InstallError::ExistingUnit`].
fn ensure_server_unit_writable(
    path: &Path,
    unit: &[u8],
    force: bool,
) -> Result<bool, InstallError> {
    match fs::read(path) {
        Ok(existing) if existing == unit => Ok(false),
        Ok(existing) if is_previous_generated_network_unit(&existing, unit) => Ok(true),
        Ok(_) if force => Ok(true),
        Ok(_) => Err(InstallError::ExistingUnit),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(InstallError::Io(error)),
    }
}

/// The system-scoped server unit's current network dependency lines.
const CURRENT_SERVER_NETWORK_ORDER: &[u8] =
    b"After=network-online.target\nWants=network-online.target\n";

/// The network dependency line written by the previous server installer.
const PREVIOUS_SERVER_NETWORK_ORDER: &[u8] = b"After=network.target\n";

/// Recognize only a generated unit that differs from `unit` by the old network-order line.
///
/// A byte-for-byte match after this one substitution lets `server init` refresh
/// its own previous output without treating a hand-edited service as managed.
fn is_previous_generated_network_unit(existing: &[u8], unit: &[u8]) -> bool {
    let Some(position) = unit
        .windows(CURRENT_SERVER_NETWORK_ORDER.len())
        .position(|window| window == CURRENT_SERVER_NETWORK_ORDER)
    else {
        return false;
    };
    if unit[position + CURRENT_SERVER_NETWORK_ORDER.len()..]
        .windows(CURRENT_SERVER_NETWORK_ORDER.len())
        .any(|window| window == CURRENT_SERVER_NETWORK_ORDER)
    {
        return false;
    }

    let mut previous = Vec::with_capacity(unit.len());
    previous.extend_from_slice(&unit[..position]);
    previous.extend_from_slice(PREVIOUS_SERVER_NETWORK_ORDER);
    previous.extend_from_slice(&unit[position + CURRENT_SERVER_NETWORK_ORDER.len()..]);
    previous == existing
}

/// Build and validate the system firewall unit and saved policy for a server install.
///
/// The same rule holds from a console and over SSH (J671, #483): the live
/// session's own path must survive ([`host_firewall::validate_ssh_connection`]),
/// and so must every port sshd uses now or after a restart
/// ([`sshd_admin_path`]). Checking only the session let an edited
/// `sshd_config` (`Port 2222`, not yet restarted) save a 22-only table that
/// dropped sshd at its next start (J670).
#[cfg(target_os = "linux")]
fn make_firewall_install(args: &ServerArgs) -> Result<FirewallInstall, InstallError> {
    let policy = super::host_firewall_policy(args).map_err(InstallError::HostFirewall)?;
    let ssh_connection = match env::var("SSH_CONNECTION") {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => return Err(InstallError::Invalid),
    };
    host_firewall::validate_ssh_connection(&policy, ssh_connection.as_deref())
        .map_err(|error| InstallError::HostFirewall(error.to_string()))?;
    sshd_admin_path(&policy.admin_rules, &host_sshd_ports()).map_err(InstallError::HostFirewall)?;
    let policy_json = serde_json::to_string_pretty(&policy)
        .map_err(|error| InstallError::HostFirewall(error.to_string()))?;
    let unit = render_firewall_unit()?;
    Ok(FirewallInstall {
        unit,
        policy,
        policy_json,
    })
}

/// sshd's ports as the host reports them ([`host_firewall::sshd_ports`]).
#[cfg(all(target_os = "linux", not(test)))]
fn host_sshd_ports() -> host_firewall::SshdPorts {
    host_firewall::sshd_ports()
}

/// A fixed dual-stack sshd on 22 for unit tests, so install plans don't depend on the runner.
///
/// The real lookup reads root-only sshd state and the host's units, which a
/// test runner may or may not see; `sshd_admin_path` and the parsers have
/// their own tests, and the root path is proven by
/// `review_j635_running_sshd_port_override.sh` and
/// `review_j671_sshd_invariant.sh`.
#[cfg(all(target_os = "linux", test))]
fn host_sshd_ports() -> host_firewall::SshdPorts {
    host_firewall::SshdPorts::Known(vec![host_firewall::SshdPortSource {
        source: "unit test".to_owned(),
        ports: vec![host_firewall::SshdPort::dual_stack(22)],
    }])
}

/// Require an admin rule for every port sshd uses, worded for `server init`'s flags.
///
/// The check is [`host_firewall::check_sshd_admission`], the same one every
/// apply and the boot loader run; only the message names
/// `--host-firewall-allow`. Unknown ports are refused, never assumed to be
/// 22 (J608).
#[cfg(target_os = "linux")]
fn sshd_admin_path(
    rules: &[host_firewall::AllowRule],
    sshd: &host_firewall::SshdPorts,
) -> Result<(), String> {
    match host_firewall::check_sshd_admission(rules, sshd) {
        Ok(()) => Ok(()),
        Err(host_firewall::PolicyError::SshdNotAdmitted { missing, uses }) => Err(format!(
            "no --host-firewall-allow rule admits sshd's port {missing}; sshd uses {uses}; \
             every one needs a rule; rules limited to lo, to one source address, to a loopback \
             network or to an address family sshd does not accept on that port do not count; \
             add one such as '*,*,tcp,<port>' so the default-drop host table keeps an SSH path \
             now and after sshd restarts"
        )),
        Err(host_firewall::PolicyError::SshdPortsUnknown { failed, seen }) => Err(format!(
            "sshd's port could not be determined ({failed}); ports seen so far: {seen}; run \
             server init as root and fix what is named above before a default-drop host table \
             is saved; then allow every port sshd uses with --host-firewall-allow"
        )),
        Err(error) => Err(error.to_string()),
    }
}

/// Render the boot unit that applies the saved infraternal host policy before networking.
#[cfg(target_os = "linux")]
fn render_firewall_unit() -> Result<String, InstallError> {
    let binary = env::current_exe().map_err(InstallError::Io)?;
    let executable = quote_systemd(binary.as_os_str())?;
    Ok(format!(
        "{}\n[Unit]\nDescription=infraternal host input firewall\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nExecStart={executable} __host-firewall-apply\nRemainAfterExit=yes\n\n[Install]\nWantedBy=network-pre.target\n",
        host_firewall::HOST_FIREWALL_UNIT_MARKER
    ))
}

/// The program the unit runs and the PATH link points at: one path for both (J719 P2).
///
/// The link must name exactly what the service runs, so it can never be left
/// pointing at a binary the service no longer uses. `server init` does not
/// copy itself into an install folder, so that program is the running binary.
/// It is canonicalised so neither the unit nor the link records a symlink:
/// on macOS the running path may be the PATH link itself, and a link to
/// itself would loop. On Linux `current_exe` is already the resolved
/// `/proc/self/exe`, so units written before this keep their exact text.
pub(super) fn service_program() -> std::io::Result<PathBuf> {
    env::current_exe().and_then(fs::canonicalize)
}

/// Check that the binary a root-run service will start is one only root can change (#146).
///
/// `server init --system` (and root installing a per-user service for
/// itself) writes units that root runs: the server, the boot-time firewall
/// loader and the data-move hooks, and it links `/usr/local/bin/infraternal`.
/// All of them name [`service_program`], the running binary itself, because
/// `server init` does not copy it anywhere. So that file and every folder
/// above it must be ones only root can change. Otherwise the account that
/// owns, for example, a release unpacked in its home folder could replace
/// the file and run its own code as root at the next restart or boot (J1087).
/// The rule is the shared [`crate::trusted_program::trusted_program`] check
/// that `infraternal up` applies to the tools it runs.
///
/// `owner` is the account trusted besides root: 0 in production, the test
/// user in tests. The error is a complete sentence that says what to do.
pub(super) fn check_root_service_program(program: &Path, owner: u32) -> Result<(), String> {
    use crate::trusted_program::{ToolError, trusted_program};
    match trusted_program(&[program], owner) {
        Ok(_) => Ok(()),
        Err(ToolError::Missing) => Err(format!(
            "{} is gone, so a service cannot run it; run server init from the installed binary",
            program.display()
        )),
        Err(ToolError::Untrusted) => Err(format!(
            "root would run {}, but an account other than root can replace it, because it or \
             a folder above it is not owned by root or can be written by others; move the \
             release folder (the binary and its web folder) somewhere only root can change, \
             such as /opt/infraternal, and run server init from there",
            program.display()
        )),
    }
}

/// Check that the web folder a root-run server will serve is one only root can change (#146).
///
/// The server sends this folder's files to every browser that signs in,
/// administrators included. If an account other than root could change a
/// file in it, or swap the folder or one above it, that account could serve
/// its own script to an administrator's signed-in page and act with that
/// session (J1101's question 1). So a `--system` install, or root's own
/// per-user one, holds the folder to the rule of the binary
/// ([`check_root_service_program`]): see
/// [`crate::trusted_program::trusted_folder`].
///
/// Returns the folder's canonical path. The caller stores that path, never
/// the one it was given, so a link on the given path cannot be repointed
/// after this check (J1180, F3).
///
/// `owner` is the account trusted besides root: 0 in production, the test
/// user in tests. The error is a complete sentence that says what to do.
pub(super) fn check_root_web_folder(web: &Path, owner: u32) -> Result<PathBuf, String> {
    use crate::trusted_program::{FolderError, trusted_folder};
    match trusted_folder(web, owner) {
        Ok(canonical) => Ok(canonical),
        Err(FolderError::Missing) => Err(format!(
            "the web folder {} is not there, so the server cannot serve it; pass --web-root \
             with the release's web folder",
            web.display()
        )),
        Err(FolderError::Untrusted(path)) => Err(format!(
            "the server would serve the web folder {} to administrators, but an account other \
             than root can change {}, because it is not owned by root, can be written by \
             others, or is a link; move the release folder (the binary and its web folder) \
             somewhere only root can change, such as /opt/infraternal, and run server init \
             from there",
            web.display(),
            path.display()
        )),
    }
}

/// Whether `binary` lives under the temporary folder, where it may vanish.
fn in_temporary_folder(binary: &Path) -> bool {
    fs::canonicalize(env::temp_dir()).is_ok_and(|temporary| binary.starts_with(temporary))
}

/// The scope and binary the PATH link is made for, from the real environment.
fn link_target(
    user: bool,
) -> Result<
    (
        super::install_paths::Scope,
        super::install_paths::Environment,
        PathBuf,
    ),
    InstallError,
> {
    let binary = service_program().map_err(InstallError::Io)?;
    let scope = if user {
        super::install_paths::Scope::User
    } else {
        super::install_paths::Scope::System
    };
    Ok((scope, super::install_paths::Environment::detect(), binary))
}

/// The dry-run line saying where the PATH link would go.
fn link_plan(user: bool, data: &Path) -> Result<String, InstallError> {
    let (scope, environment, binary) = link_target(user)?;
    Ok(match super::install_paths::path_link(scope, &environment) {
        Ok(Some(link)) if keep_combined_link(user, data, &link) => {
            format!("Would keep the shared command at {}\n", link.display())
        }
        Ok(Some(link)) => format!("Would link {} to {}\n", link.display(), binary.display()),
        Ok(None) => format!(
            "Would print the PATH line for {}\n",
            binary.parent().unwrap_or(&binary).display()
        ),
        Err(error) => format!("Would not link: {error}\n"),
    })
}

/// Publish the PATH link and describe the result in one sentence for the install output.
fn link_note(user: bool, data: &Path) -> String {
    let result = link_target(user).and_then(|(scope, environment, binary)| {
        if let Ok(Some(link)) = super::install_paths::path_link(scope, &environment)
            && keep_combined_link(user, data, &link)
        {
            return Ok(format!("Kept the shared command at {}.", link.display()));
        }
        super::install_paths::link_for_install(scope, &binary, &environment)
            .map(|outcome| outcome.describe(&binary))
            .map_err(|error| InstallError::Io(std::io::Error::other(error.to_string())))
    });
    let note = result
        .unwrap_or_else(|error| format!("Could not set up the `infraternal` command: {error}"));
    match service_program() {
        Ok(binary) if in_temporary_folder(&binary) => format!(
            "{note} Note: the service and the link use {}, which is in the temporary folder; \
             move the binary somewhere permanent and run init again from there.",
            binary.display()
        ),
        _ => note,
    }
}

/// Keep the existing command link on combined hosts where the infraternal agent uses it.
fn keep_combined_link(user: bool, data: &Path, link: &Path) -> bool {
    cfg!(target_os = "linux")
        && !user
        && data == Path::new(super::install_paths::LINUX_COMBINED_SERVER)
        && std::fs::symlink_metadata(link).is_ok()
}

fn validate_name(name: &str) -> Result<(), InstallError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.@-".contains(&byte))
    {
        return Err(InstallError::Invalid);
    }
    Ok(())
}

/// The unit file `server init` writes for this scope and name.
pub(super) fn unit_path(user: bool, name: &str) -> Result<PathBuf, InstallError> {
    let basename = format!("{name}.service");
    if user {
        Ok(
            user_unit_directory(env::var_os("XDG_CONFIG_HOME"), env::var_os("HOME"))?
                .join(basename),
        )
    } else {
        Ok(PathBuf::from("/etc/systemd/system").join(basename))
    }
}

/// The folder the user's service manager reads units from, given the
/// `XDG_CONFIG_HOME` and `HOME` values.
///
/// An empty or relative `XDG_CONFIG_HOME` is invalid by the XDG rules and is
/// ignored, as `install_paths` does for `XDG_STATE_HOME`. Using it would put
/// the unit under the current folder, where systemd never looks (D395,
/// J1087 #6). `HOME` must be set when the variable is not usable.
fn user_unit_directory(
    config_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, InstallError> {
    match config_home
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        Some(path) => Ok(path.join("systemd/user")),
        None => Ok(PathBuf::from(home.ok_or(InstallError::Invalid)?).join(".config/systemd/user")),
    }
}

/// The boot pointer's image in `data`, `<data>/updates/current/infraternal`, when the
/// server's updater has installed a release there (#211 S6).
///
/// A unit that starts this path follows every update across cold starts: the updater
/// moves `current` only after a new release passed its health check (D295). The image is
/// the release's server image (the release plugin's `update::server_image`, which this
/// module cannot call: it builds without that plugin), never an `infraternal-<arch>-musl`
/// add-host payload, which has no `server` command (J1134). Machines the releases publish
/// no server image for (everything but `x86_64` Linux) have no boot pointer. The folder is
/// root-only (0700) by construction.
pub(super) fn boot_pointer(data: &Path) -> Option<PathBuf> {
    let image = match (env::consts::ARCH, env::consts::OS) {
        ("x86_64", "linux") => "infraternal",
        _ => return None,
    };
    let current = data.join("updates").join("current");
    let pointer = current.join(image);
    (fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink())
        && fs::metadata(&pointer).is_ok_and(|metadata| metadata.is_file()))
    .then_some(pointer)
}

/// Render the server process unit and preserve all typed runtime options.
///
/// Every path in `ExecStart` is absolute and quoted. When the data folder holds an
/// installed release ([`boot_pointer`]), the unit starts that image instead of the
/// running binary, so an applied update survives the next cold start; a release that
/// carries its own web build serves it, so `--web-root` is left out then (#211 S6).
/// System services wait for network-online and pull that target into the boot
/// transaction. The user manager has no system-wide network target, so its
/// existing ordering stays unchanged; the listener's bounded bind retry covers
/// an address that appears after either manager starts the service.
fn render_unit(
    args: &ServerArgs,
    name: &str,
    origin: &str,
    user: bool,
) -> Result<String, InstallError> {
    let data = absolute(&args.data)?;
    let pointer = boot_pointer(&data);
    let release_web = pointer.as_ref().is_some_and(|pointer| {
        pointer
            .parent()
            .is_some_and(|release| release.join("web").is_dir())
    });
    let binary = match pointer {
        Some(pointer) => pointer,
        None => service_program().map_err(InstallError::Io)?,
    };
    let mut command = vec![binary.into_os_string()];
    command.extend([
        OsString::from("server"),
        OsString::from("--listen"),
        OsString::from(args.listen.to_string()),
        OsString::from("--data"),
        data.into_os_string(),
        OsString::from("--public-origin"),
        OsString::from(origin),
    ]);
    if let Some(web_root) = args.web_root.as_ref().filter(|_| !release_web) {
        command.push(OsString::from("--web-root"));
        command.push(absolute(web_root)?.into_os_string());
    }
    if let Some(certificate) = &args.tls_cert {
        command.push(OsString::from("--tls-cert"));
        command.push(absolute(certificate)?.into_os_string());
    }
    if let Some(key) = &args.tls_key {
        command.push(OsString::from("--tls-key"));
        command.push(absolute(key)?.into_os_string());
    }
    if let Some(listen) = args.remote.remote_listen {
        command.push(OsString::from("--remote-listen"));
        command.push(OsString::from(listen.to_string()));
    }
    if let Some(directory) = &args.remote.remote_ca_dir {
        command.push(OsString::from("--remote-ca-dir"));
        command.push(absolute(directory)?.into_os_string());
    }
    if args.behind_proxy {
        command.push(OsString::from("--behind-proxy"));
        for proxy in &args.trusted_proxies {
            command.push(OsString::from("--trusted-proxy"));
            command.push(OsString::from(proxy.to_string()));
        }
    }
    if let Some(interface) = &args.host_firewall_listen_interface {
        command.push(OsString::from("--host-firewall-listen-interface"));
        command.push(OsString::from(interface));
    }
    if let Some(interface) = &args.host_firewall_remote_interface {
        command.push(OsString::from("--host-firewall-remote-interface"));
        command.push(OsString::from(interface));
    }
    for source in &args.host_firewall_remote_sources {
        command.push(OsString::from("--host-firewall-remote-source"));
        command.push(OsString::from(source));
    }
    for interface in &args.host_firewall_accept_interfaces {
        command.push(OsString::from("--host-firewall-accept-interface"));
        command.push(OsString::from(interface));
    }
    for rule in &args.host_firewall_allow {
        command.push(OsString::from("--host-firewall-allow"));
        command.push(OsString::from(rule));
    }
    let command = command
        .into_iter()
        .map(|part| quote_systemd(&part))
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    let target = if user {
        "default.target"
    } else {
        "multi-user.target"
    };
    let scope = if user {
        ""
    } else {
        "Environment=INFRATERNAL_SERVER_SERVICE_SCOPE=system\n"
    };
    let reload = if cfg!(feature = "remote") {
        "ExecReload=/bin/kill -HUP $MAINPID\n"
    } else {
        ""
    };
    let network_order = if user {
        "After=network.target\n"
    } else {
        "After=network-online.target\nWants=network-online.target\n"
    };
    Ok(format!(
        "[Unit]\nDescription=infraternal server ({name})\n{network_order}\n[Service]\nType=simple\n{scope}ExecStart={command}\n{reload}Restart=on-failure\nRestartSec=2\nKillMode=process\nDelegate=yes\n\n[Install]\nWantedBy={target}\n"
    ))
}

fn absolute(path: &Path) -> Result<PathBuf, InstallError> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(InstallError::Io)
    }
}

/// Quote one `ExecStart` word as `server init` writes it; control characters are refused.
pub(super) fn quote_systemd(value: &std::ffi::OsStr) -> Result<String, InstallError> {
    let value = value.to_str().ok_or(InstallError::Invalid)?;
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b'\n' || byte == b'\r')
    {
        return Err(InstallError::Invalid);
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// Replace a file by writing a fsynced sibling and renaming it over the original.
pub(super) fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "unit path has no parent")
    })?;
    fs::create_dir_all(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unit path has no filename",
        )
    })?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    OpenOptions::new().read(true).open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    //! Verifies dry-run service rendering without writing outside the worktree.

    use super::*;
    use std::net::SocketAddr;

    /// A user-scoped service keeps its process and command-line configuration.
    #[test]
    fn dry_run_prints_a_process_surviving_user_unit() {
        let args = ServerArgs {
            remote: super::super::remote_server::Options::default(),
            listen: SocketAddr::from(([127, 0, 0, 1], 47361)),
            data: PathBuf::from("./state"),
            public_origin: Some("https://localhost:47361".to_owned()),
            web_root: None,
            tls_cert: Some(PathBuf::from("server.crt")),
            tls_key: Some(PathBuf::from("server.key")),
            behind_proxy: false,
            trusted_proxies: Vec::new(),
            host_firewall_listen_interface: None,
            host_firewall_remote_interface: None,
            host_firewall_remote_sources: Vec::new(),
            host_firewall_accept_interfaces: Vec::new(),
            host_firewall_allow: Vec::new(),
            host_firewall_off: false,
        };
        let options = InstallArgs {
            system: false,
            user: true,
            dry_run: true,
            force: false,
            name: "tracer-server".to_owned(),
        };
        let output = install(&args, &options).expect("dry-run output");
        assert!(output.contains("tracer-server.service"));
        assert!(output.contains("KillMode=process"));
        // The proxy puts each Traefik child in its own cgroup under the unit's [#281, D336].
        assert!(output.contains("Delegate=yes"));
        assert!(output.contains("systemctl --user enable --now tracer-server.service"));
        assert!(output.contains("--tls-key"));
        assert!(!output.contains("INFRATERNAL_SERVER_SERVICE_SCOPE"));
    }

    /// A system server plan includes firewall takeover and boot ordering.
    #[test]
    fn system_units_mark_the_scope_used_by_first_run_status() {
        let args = ServerArgs {
            remote: super::super::remote_server::Options::default(),
            listen: SocketAddr::from(([127, 0, 0, 1], 47361)),
            data: PathBuf::from("./state"),
            public_origin: Some("https://localhost:47361".to_owned()),
            web_root: None,
            tls_cert: None,
            tls_key: None,
            behind_proxy: false,
            trusted_proxies: Vec::new(),
            host_firewall_listen_interface: None,
            host_firewall_remote_interface: None,
            host_firewall_remote_sources: Vec::new(),
            host_firewall_accept_interfaces: Vec::new(),
            host_firewall_allow: vec!["*,*,tcp,22".to_owned()],
            host_firewall_off: false,
        };
        let options = InstallArgs {
            system: true,
            user: false,
            dry_run: true,
            force: false,
            name: "infraternal-server".to_owned(),
        };

        let output = install(&args, &options).expect("dry-run output");
        assert!(output.contains("Environment=INFRATERNAL_SERVER_SERVICE_SCOPE=system"));
        assert!(output.contains(
            "Description=infraternal server (infraternal-server)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]"
        ));
        assert!(output.contains("/etc/systemd/system/infraternal-firewall.service"));
        assert!(output.contains("Before=network-pre.target"));
        assert!(output.contains("__host-firewall-apply"));
        assert!(output.contains("host-firewall-server.json"));
        assert!(output.contains("Would replace the hand-installed infraternal-firewall.service"));
        assert!(output.contains("systemctl restart infraternal-firewall.service"));
        assert!(
            output.starts_with("Data folder: /"),
            "a firewall plan names its data folder first (#516): {output}"
        );
        assert!(
            ends_with_link_plan(&output),
            "a system firewall plan ends with the PATH link (D395, J755): {output}"
        );
    }

    /// Whether a dry-run plan's last line is one of [`link_plan`]'s answers.
    fn ends_with_link_plan(output: &str) -> bool {
        output.lines().last().is_some_and(|line| {
            ["Would link ", "Would print the PATH line", "Would not link"]
                .iter()
                .any(|start| line.starts_with(start))
        })
    }

    /// An identical or exactly previous generated unit can be installed without force; hand edits need force.
    #[test]
    fn an_identical_server_unit_is_left_unwritten() {
        let directory = std::env::temp_dir().join(format!("j731-unit-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("scratch folder");
        let path = directory.join("infraternal-server.service");
        assert!(ensure_server_unit_writable(&path, b"a", false).expect("missing unit"));
        fs::write(&path, b"a").expect("installed unit");
        assert!(!ensure_server_unit_writable(&path, b"a", false).expect("same unit"));
        assert!(!ensure_server_unit_writable(&path, b"a", true).expect("same unit, forced"));
        assert!(ensure_server_unit_writable(&path, b"b", true).expect("forced replacement"));
        assert!(matches!(
            ensure_server_unit_writable(&path, b"b", false),
            Err(InstallError::ExistingUnit)
        ));
        fs::remove_dir_all(&directory).expect("remove scratch folder");
    }

    /// `server init` refreshes only an old generated service whose network line changed.
    #[test]
    fn a_previous_generated_unit_is_refreshed_but_a_hand_edit_is_refused() {
        use std::os::unix::fs::MetadataExt;

        let directory =
            std::env::temp_dir().join(format!("j905-network-unit-{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("scratch folder");
        let path = directory.join("infraternal-server.service");
        let data = directory.join("data");
        let current = b"[Unit]\nDescription=infraternal server (infraternal-server)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart=/var/lib/infraternal/bin/infraternal server\n";
        let previous = b"[Unit]\nDescription=infraternal server (infraternal-server)\nAfter=network.target\n\n[Service]\nExecStart=/var/lib/infraternal/bin/infraternal server\n";

        fs::write(&path, previous).expect("write previous generated unit");
        install_in_order(&path, current, &data, false, || Ok(()), |()| Ok(()))
            .expect("generated unit refresh");
        assert_eq!(fs::read(&path).expect("refreshed unit"), current);

        let before_rerun = fs::metadata(&path).expect("refreshed unit metadata");
        install_in_order(&path, current, &data, false, || Ok(()), |()| Ok(()))
            .expect("identical re-run");
        let after_rerun = fs::metadata(&path).expect("re-run unit metadata");
        assert_eq!(
            (before_rerun.ino(), before_rerun.mtime_nsec()),
            (after_rerun.ino(), after_rerun.mtime_nsec()),
            "an identical re-run leaves the refreshed unit alone"
        );

        let hand_edited = b"[Unit]\nDescription=infraternal server (infraternal-server)\nAfter=network.target\n\n[Service]\nExecStart=/custom/server\n";
        fs::write(&path, hand_edited).expect("write hand-edited unit");
        let error = install_in_order(&path, current, &data, false, || Ok(()), |()| Ok(()))
            .expect_err("hand edit requires force");
        assert!(matches!(error, InstallError::ExistingUnit));
        assert!(error.to_string().contains("--force"));
        assert_eq!(fs::read(&path).expect("hand-edited unit"), hand_edited);

        fs::remove_dir_all(&directory).expect("remove scratch folder");
    }

    /// The dry run shows the folders the unit will use, as absolute paths.
    #[test]
    fn dry_run_prints_the_resolved_absolute_folders() {
        let args = ServerArgs {
            remote: super::super::remote_server::Options::default(),
            listen: SocketAddr::from(([127, 0, 0, 1], 47361)),
            data: PathBuf::from("/srv/state"),
            public_origin: Some("https://localhost:47361".to_owned()),
            web_root: Some(PathBuf::from("/srv/web")),
            tls_cert: None,
            tls_key: None,
            behind_proxy: false,
            trusted_proxies: Vec::new(),
            host_firewall_listen_interface: None,
            host_firewall_remote_interface: None,
            host_firewall_remote_sources: Vec::new(),
            host_firewall_accept_interfaces: Vec::new(),
            host_firewall_allow: Vec::new(),
            host_firewall_off: false,
        };
        let options = InstallArgs {
            system: false,
            user: true,
            dry_run: true,
            force: false,
            name: "x".to_owned(),
        };
        let output = install(&args, &options).unwrap();
        assert!(output.contains("Data folder: /srv/state\n"));
        assert!(output.contains("Web folder: /srv/web\n"));
    }

    /// With a release installed in the data folder, the unit starts the boot pointer, so an
    /// applied update survives a cold start; a release with its own web build drops
    /// `--web-root`, and every other flag stays (#211 S6). The pointer is the server image
    /// `infraternal`: an `infraternal-x86_64-musl` add-host payload there never counts (J1134).
    /// Only `x86_64` Linux has a published server image, so only it has a boot pointer.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_unit_starts_the_boot_pointer_once_a_release_is_installed() {
        use std::os::unix::fs::DirBuilderExt;
        let image = "infraternal";
        let data = env::temp_dir().join(format!("init-pointer-{}", std::process::id()));
        let _ = fs::remove_dir_all(&data);
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&data)
            .unwrap();
        let args = ServerArgs {
            remote: super::super::remote_server::Options::default(),
            listen: SocketAddr::from(([127, 0, 0, 1], 47362)),
            data: data.clone(),
            public_origin: Some("https://localhost:47362".to_owned()),
            web_root: Some(PathBuf::from("/opt/infraternal/old/web")),
            tls_cert: None,
            tls_key: None,
            behind_proxy: true,
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
            host_firewall_listen_interface: None,
            host_firewall_remote_interface: None,
            host_firewall_remote_sources: Vec::new(),
            host_firewall_accept_interfaces: Vec::new(),
            host_firewall_allow: Vec::new(),
            host_firewall_off: false,
        };
        let exec = |unit: String| {
            unit.lines()
                .find_map(|line| line.strip_prefix("ExecStart="))
                .unwrap()
                .to_owned()
        };
        let running = quote_systemd(service_program().unwrap().as_os_str()).unwrap();
        let before = exec(
            render_unit(
                &args,
                "infraternal-server",
                "https://localhost:47362",
                false,
            )
            .unwrap(),
        );
        assert!(before.starts_with(&running), "{before}");
        assert!(before.contains("\"--web-root\" \"/opt/infraternal/old/web\""));

        let release = data.join("updates/releases/edge-20261122T000000Z");
        fs::create_dir_all(&release).unwrap();
        fs::write(release.join("infraternal-x86_64-musl"), b"host payload").unwrap();
        std::os::unix::fs::symlink(
            "releases/edge-20261122T000000Z",
            data.join("updates/current"),
        )
        .unwrap();
        let host_payload_only = exec(
            render_unit(
                &args,
                "infraternal-server",
                "https://localhost:47362",
                false,
            )
            .unwrap(),
        );
        assert!(
            host_payload_only.starts_with(&running),
            "a host payload is never the boot pointer: {host_payload_only}"
        );
        fs::write(release.join(image), b"image").unwrap();
        let pointer = format!("\"{}/updates/current/{image}\"", data.display());
        let without_web = exec(
            render_unit(
                &args,
                "infraternal-server",
                "https://localhost:47362",
                false,
            )
            .unwrap(),
        );
        assert!(without_web.starts_with(&pointer), "{without_web}");
        assert!(
            without_web.contains("--web-root"),
            "a release without web keeps the flag"
        );

        fs::create_dir(release.join("web")).unwrap();
        let with_web = exec(
            render_unit(
                &args,
                "infraternal-server",
                "https://localhost:47362",
                false,
            )
            .unwrap(),
        );
        assert!(with_web.starts_with(&pointer));
        assert!(!with_web.contains("--web-root"), "{with_web}");
        assert!(with_web.contains("\"--behind-proxy\" \"--trusted-proxy\" \"127.0.0.1\""));
        fs::remove_dir_all(&data).unwrap();
    }

    /// `server init` refuses when sshd's port is unknown and names the port it needs (J608, J658, J671).
    ///
    /// The same check runs from a console and over SSH; only its wording
    /// names `--host-firewall-allow`.
    #[cfg(target_os = "linux")]
    #[test]
    fn server_init_never_guesses_sshd_port() {
        use super::host_firewall::{SshdPort, SshdPortSource, SshdPorts};
        let rules = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.parse().expect("rule"))
                .collect::<Vec<super::host_firewall::AllowRule>>()
        };
        let source = |source: &str, ports: &[u16]| SshdPortSource {
            source: source.to_owned(),
            ports: ports.iter().copied().map(SshdPort::dual_stack).collect(),
        };
        let unknown = SshdPorts::Unknown {
            failed: "sshd's configuration: sshd -G: Permission denied".to_owned(),
            seen: Vec::new(),
        };
        let refused = super::sshd_admin_path(&rules(&["*,*,tcp,22"]), &unknown)
            .expect_err("an unknown sshd port must not pass as 22");
        assert!(refused.contains("could not be determined"), "{refused}");
        let on_2222 = SshdPorts::Known(vec![source("sshd's configuration", &[2222])]);
        let refused = super::sshd_admin_path(&rules(&["*,*,tcp,22"]), &on_2222)
            .expect_err("tcp/22 does not reach an sshd on 2222");
        assert!(
            refused.contains("2222 (from sshd's configuration)"),
            "{refused}"
        );
        assert_eq!(
            super::sshd_admin_path(&rules(&["*,*,tcp,2222"]), &on_2222),
            Ok(())
        );
        // J658: configured 22, running on 2222; both need a rule.
        let split = SshdPorts::Known(vec![
            source("sshd's configuration", &[22]),
            source("running sshd processes", &[2222]),
        ]);
        let refused = super::sshd_admin_path(&rules(&["*,*,tcp,22"]), &split)
            .expect_err("tcp/22 alone drops the sshd running on 2222");
        assert!(
            refused.contains("admits sshd's port 2222;")
                && refused.contains("22 (from sshd's configuration)")
                && refused.contains("2222 (from running sshd processes)"),
            "{refused}"
        );
        assert_eq!(
            super::sshd_admin_path(&rules(&["*,*,tcp,22", "*,*,tcp,2222"]), &split),
            Ok(())
        );
    }

    /// Preview an explicit server-policy clear without writing host state.
    #[test]
    fn system_host_firewall_off_dry_run_names_only_product_owned_removal() {
        let args = ServerArgs {
            remote: super::super::remote_server::Options::default(),
            listen: SocketAddr::from(([127, 0, 0, 1], 47361)),
            data: PathBuf::from("./state"),
            public_origin: Some("https://localhost:47361".to_owned()),
            web_root: None,
            tls_cert: None,
            tls_key: None,
            behind_proxy: false,
            trusted_proxies: Vec::new(),
            host_firewall_listen_interface: None,
            host_firewall_remote_interface: None,
            host_firewall_remote_sources: Vec::new(),
            host_firewall_accept_interfaces: Vec::new(),
            host_firewall_allow: Vec::new(),
            host_firewall_off: true,
        };
        let options = InstallArgs {
            system: true,
            user: false,
            dry_run: true,
            force: false,
            name: "infraternal-server".to_owned(),
        };

        let output = install(&args, &options).expect("dry-run output");

        assert!(output.contains("Would clear the server host policy"));
        assert!(output.contains("marked infraternal host table and loader state"));
        assert!(output.contains("systemctl enable --now infraternal-server.service"));
        assert!(!output.contains("Would replace the hand-installed"));
        assert!(output.starts_with("Data folder: /"), "{output}");
        assert!(ends_with_link_plan(&output), "{output}");
    }

    /// A scratch policy/unit pair plus a recording, scriptable systemctl for publish tests.
    #[cfg(target_os = "linux")]
    struct PublishFixture {
        /// Private scratch directory, removed by [`Drop`].
        root: PathBuf,
        /// The firewall install the test publishes.
        firewall: FirewallInstall,
    }

    #[cfg(target_os = "linux")]
    impl PublishFixture {
        /// A fresh scratch directory and a server policy admitting tcp/22.
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!("j662-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("scratch");
            let args = ServerArgs {
                remote: super::super::remote_server::Options::default(),
                listen: SocketAddr::from(([127, 0, 0, 1], 47361)),
                data: PathBuf::from("./state"),
                public_origin: Some("https://localhost:47361".to_owned()),
                web_root: None,
                tls_cert: None,
                tls_key: None,
                behind_proxy: false,
                trusted_proxies: Vec::new(),
                host_firewall_listen_interface: None,
                host_firewall_remote_interface: None,
                host_firewall_remote_sources: Vec::new(),
                host_firewall_accept_interfaces: Vec::new(),
                host_firewall_allow: vec!["*,*,tcp,22".to_owned()],
                host_firewall_off: false,
            };
            let policy = super::super::host_firewall_policy(&args).expect("policy");
            let firewall = FirewallInstall {
                unit: render_firewall_unit().expect("unit"),
                policy_json: String::new(),
                policy,
            };
            Self { root, firewall }
        }

        /// Publish into the scratch paths; `fails` names the systemctl verb that fails.
        fn publish(
            &self,
            enabled_before: bool,
            fails: &str,
        ) -> (Result<(), InstallError>, Vec<String>) {
            let mut calls = Vec::new();
            let result = publish_firewall(
                &self.firewall,
                &FirewallTargets {
                    policy: &self.policy(),
                    unit: &self.unit(),
                },
                &|path, _policy| fs::write(path, b"NEW POLICY").map_err(InstallError::Io),
                &mut |arguments| {
                    calls.push(arguments.join(" "));
                    Ok(match arguments.first() {
                        Some(&"is-enabled") => enabled_before,
                        Some(verb) => *verb != fails,
                        None => false,
                    })
                },
            );
            (result, calls)
        }

        /// The scratch policy path.
        fn policy(&self) -> PathBuf {
            self.root.join("host-firewall-server.json")
        }

        /// The scratch loader unit path.
        fn unit(&self) -> PathBuf {
            self.root.join("infraternal-firewall.service")
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for PublishFixture {
        /// Remove the scratch directory, even when the test panicked.
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// J658 (P3): a failed loader restart on a fresh host leaves no saved policy and no enabled loader.
    ///
    /// The policy and unit used to be written and the loader enabled before
    /// `restart` proved the table loads; a rejected table returned an error
    /// but left a policy the next boot applied.
    #[cfg(target_os = "linux")]
    #[test]
    fn review_j658_failed_firewall_restart_rolls_back_a_fresh_install() {
        let fixture = PublishFixture::new("fresh");
        let (result, calls) = fixture.publish(false, "restart");
        assert!(result.is_err(), "a failed restart must fail the install");
        assert!(
            !fixture.policy().exists(),
            "the policy stayed saved for the next boot: {calls:?}"
        );
        assert!(
            !fixture.unit().exists(),
            "the loader unit stayed: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call == "disable infraternal-firewall.service"),
            "the loader was left enabled: {calls:?}"
        );
    }

    /// J658 (P3): a failed restart over an earlier install restores its policy, unit and enablement.
    #[cfg(target_os = "linux")]
    #[test]
    fn review_j658_failed_firewall_restart_restores_the_previous_install() {
        let fixture = PublishFixture::new("previous");
        fs::write(fixture.policy(), b"OLD POLICY").expect("old policy");
        let old_unit = format!(
            "{}\n[Service]\nExecStart=/old/infraternal __host-firewall-apply\n",
            host_firewall::HOST_FIREWALL_UNIT_MARKER
        );
        fs::write(fixture.unit(), &old_unit).expect("old unit");
        let (result, calls) = fixture.publish(true, "restart");
        assert!(result.is_err(), "a failed restart must fail the install");
        assert_eq!(fs::read(fixture.policy()).expect("policy"), b"OLD POLICY");
        assert_eq!(fs::read_to_string(fixture.unit()).expect("unit"), old_unit);
        assert!(
            !calls.iter().any(|call| call.starts_with("disable")),
            "a loader that was enabled before stays enabled: {calls:?}"
        );
    }

    /// J658 (P3): `server init` never overwrites a firewall unit that is neither ours nor the known hand loader.
    #[cfg(target_os = "linux")]
    #[test]
    fn review_j658_a_foreign_firewall_unit_is_never_overwritten() {
        let fixture = PublishFixture::new("foreign");
        let foreign = "[Service]\nExecStart=/usr/sbin/iptables-restore /etc/iptables/rules\n";
        fs::write(fixture.unit(), foreign).expect("foreign unit");
        let (result, calls) = fixture.publish(false, "");
        assert!(result.is_err(), "a foreign unit must be refused");
        assert_eq!(fs::read_to_string(fixture.unit()).expect("unit"), foreign);
        assert!(!fixture.policy().exists(), "a policy was saved anyway");
        assert!(calls.is_empty(), "systemctl ran: {calls:?}");
        // The known hand loader (#274) is still taken over.
        let hand = "[Service]\nExecStart=/usr/sbin/nft -f /etc/nftables/infraternal-host.nft\n";
        fs::write(fixture.unit(), hand).expect("hand unit");
        let (result, _) = fixture.publish(false, "");
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            fs::read_to_string(fixture.unit()).expect("unit"),
            fixture.firewall.unit
        );
    }

    /// J658 (P3): root `systemctl` calls use the fixed, root-owned path, never a `PATH` lookup (D384, D386).
    #[test]
    fn review_j658_systemctl_is_never_found_through_path() {
        let source = include_str!("install.rs");
        let path_lookup = concat!("Command::new(", "\"systemctl\")");
        assert!(
            !source.contains(path_lookup),
            "install.rs runs systemctl through PATH"
        );
    }

    /// A data folder that cannot be created leaves no unit behind; a refused re-run creates nothing.
    #[test]
    fn a_failed_data_folder_leaves_no_unit_and_a_refusal_creates_no_folder() {
        let root = env::temp_dir().join(format!("unit-order-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let blocker = root.join("file");
        fs::write(&blocker, "x").unwrap();
        let unit = root.join("x.service");
        let error = install_in_order(
            &unit,
            b"new",
            &blocker.join("data"),
            false,
            || Ok(()),
            |()| Ok(()),
        );
        assert!(matches!(error, Err(InstallError::Io(_))));
        assert!(!unit.exists());

        fs::write(&unit, "old").unwrap();
        let data = root.join("data");
        let error = install_in_order(&unit, b"new", &data, false, || Ok(()), |()| Ok(()));
        assert!(matches!(error, Err(InstallError::ExistingUnit)));
        assert!(!data.exists());
        assert_eq!(fs::read_to_string(&unit).unwrap(), "old");
        install_in_order(&unit, b"new", &data, true, || Ok(()), |()| Ok(())).unwrap();
        assert_eq!(fs::read_to_string(&unit).unwrap(), "new");
        assert!(data.is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    /// The unit's program and the PATH link's target are the same canonical path (J719 P2).
    #[test]
    fn the_link_points_at_exactly_what_the_unit_runs() {
        let args = ServerArgs {
            remote: super::super::remote_server::Options::default(),
            listen: SocketAddr::from(([127, 0, 0, 1], 47361)),
            data: PathBuf::from("/srv/state"),
            public_origin: Some("https://localhost:47361".to_owned()),
            web_root: None,
            tls_cert: None,
            tls_key: None,
            behind_proxy: false,
            trusted_proxies: Vec::new(),
            host_firewall_listen_interface: None,
            host_firewall_remote_interface: None,
            host_firewall_remote_sources: Vec::new(),
            host_firewall_accept_interfaces: Vec::new(),
            host_firewall_allow: Vec::new(),
            host_firewall_off: true,
        };
        let unit = render_unit(&args, "x", "https://localhost:47361", true).unwrap();
        let (_, _, linked) = link_target(true).unwrap();
        let program = service_program().unwrap();
        assert_eq!(linked, program);
        assert_eq!(
            fs::canonicalize(&program).unwrap(),
            program,
            "no symlink recorded"
        );
        let exec = unit
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .unwrap();
        let words = infraternal_status::exec_words(exec).unwrap();
        assert_eq!(Path::new(&words[0]), program);
        assert!(in_temporary_folder(
            &fs::canonicalize(env::temp_dir())
                .unwrap()
                .join("infraternal")
        ));
        assert!(!in_temporary_folder(Path::new(
            "/usr/local/bin/infraternal"
        )));
    }

    /// A refused firewall check creates no data folder, publishes nothing and writes no unit (J755 P3-1).
    #[test]
    fn a_refused_firewall_check_creates_no_data_folder() {
        let root = env::temp_dir().join(format!("unit-order-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let unit = root.join("x.service");
        let data = root.join("var/lib/infraternal");
        let mut published = false;
        let error = install_in_order(
            &unit,
            b"new",
            &data,
            false,
            || -> Result<(), InstallError> {
                Err(InstallError::HostFirewall("no ssh path".to_owned()))
            },
            |()| {
                published = true;
                Ok(())
            },
        );
        assert!(matches!(error, Err(InstallError::HostFirewall(_))));
        assert!(!published);
        assert!(!data.exists(), "a refused install left {}", data.display());
        assert!(!unit.exists());
        fs::remove_dir_all(root).unwrap();
    }

    /// The firewall is published into a data folder that already exists with mode 0700 (c161b0897, J755 P3-4).
    ///
    /// The server policy lives in the D395 data folder; if the policy writer
    /// ran first it would create the folder 0755. A failed publish also
    /// leaves no unit.
    #[cfg(unix)]
    #[test]
    fn the_firewall_is_published_into_a_private_data_folder_before_the_unit() {
        use std::os::unix::fs::PermissionsExt;
        let root = env::temp_dir().join(format!("unit-order-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let unit = root.join("x.service");
        let data = root.join("var/lib/infraternal");
        let error = install_in_order(
            &unit,
            b"new",
            &data,
            false,
            || Ok(()),
            |()| {
                let mode = fs::metadata(&data)
                    .map_err(InstallError::Io)?
                    .permissions()
                    .mode();
                assert_eq!(
                    mode & 0o777,
                    0o700,
                    "data folder mode when the firewall is published"
                );
                assert!(!unit.exists(), "the unit was written before the firewall");
                fs::write(data.join("host-firewall-server.json"), "{}")
                    .map_err(InstallError::Io)?;
                Err::<(), _>(InstallError::Systemctl)
            },
        );
        assert!(matches!(error, Err(InstallError::Systemctl)));
        assert!(!unit.exists(), "a failed firewall publish left a unit");
        fs::remove_dir_all(root).unwrap();
    }

    /// Re-running init with a byte-identical unit never rewrites it (c161b0897, J692, J755 P3-4).
    ///
    /// `write_atomic` publishes by rename, so a rewrite gives the path a new
    /// inode; an unchanged inode and mtime prove the file was left alone.
    #[cfg(unix)]
    #[test]
    fn an_identical_unit_is_not_rewritten() {
        use std::os::unix::fs::MetadataExt;
        let root = env::temp_dir().join(format!("unit-order-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let unit = root.join("x.service");
        let data = root.join("data");
        install_in_order(&unit, b"same", &data, false, || Ok(()), |()| Ok(())).unwrap();
        let before = fs::metadata(&unit).unwrap();
        install_in_order(&unit, b"same", &data, false, || Ok(()), |()| Ok(())).unwrap();
        let after = fs::metadata(&unit).unwrap();
        assert_eq!(
            (before.ino(), before.mtime_nsec()),
            (after.ino(), after.mtime_nsec())
        );
        install_in_order(&unit, b"different", &data, true, || Ok(()), |()| Ok(())).unwrap();
        assert_ne!(fs::metadata(&unit).unwrap().ino(), before.ino());
        fs::remove_dir_all(root).unwrap();
    }

    /// J1087 #6: only an absolute `XDG_CONFIG_HOME` chooses the user unit folder.
    #[test]
    fn an_empty_or_relative_config_home_falls_back_to_home() {
        let home = Some(OsString::from("/home/person"));
        let fallback = PathBuf::from("/home/person/.config/systemd/user");
        for ignored in ["", "relative", "./config", "config/../x"] {
            assert_eq!(
                user_unit_directory(Some(OsString::from(ignored)), home.clone()).unwrap(),
                fallback,
                "{ignored:?}"
            );
        }
        assert_eq!(user_unit_directory(None, home.clone()).unwrap(), fallback);
        assert_eq!(
            user_unit_directory(Some(OsString::from("/srv/config")), home).unwrap(),
            PathBuf::from("/srv/config/systemd/user")
        );
        assert!(matches!(
            user_unit_directory(Some(OsString::from("")), None),
            Err(InstallError::Invalid)
        ));
    }

    /// A folder under the temporary folder for one ownership test, removed on drop.
    struct Fixture(PathBuf);

    impl Fixture {
        /// Make `<tmp>/<unique>/bin/infraternal` with the given folder and file modes.
        fn new(tag: &str, folder_mode: u32, file_mode: u32) -> (Self, PathBuf) {
            use std::os::unix::fs::PermissionsExt;
            let root = env::temp_dir().join(format!(
                "infraternal-init-owner-{}-{tag}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            let bin = root.join("bin");
            fs::create_dir_all(&bin).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&bin, fs::Permissions::from_mode(folder_mode)).unwrap();
            let program = bin.join("infraternal");
            fs::write(&program, "#!/bin/sh\n").unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(file_mode)).unwrap();
            (Self(root), program)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The test account, standing in for root as the one trusted owner.
    fn me() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    /// #146: a binary only the trusted owner can change is accepted; the same
    /// binary seen by root, when another account owns it, is refused.
    #[test]
    fn a_root_service_binary_must_be_one_only_root_can_change() {
        let (_fixture, program) = Fixture::new("owned", 0o755, 0o755);
        assert_eq!(check_root_service_program(&program, me()), Ok(()));
        if me() != 0 {
            // Root's view of a release unpacked in a user's folder (J1087 receipt A).
            let refusal = check_root_service_program(&program, 0).unwrap_err();
            assert!(
                refusal.contains(&program.display().to_string()),
                "{refusal}"
            );
            assert!(refusal.contains("/opt/infraternal"), "{refusal}");
        }
    }

    /// #146: a writable folder anywhere above, or a writable file, is refused.
    #[test]
    fn a_writable_binary_or_folder_above_it_is_refused() {
        for (tag, folder_mode, file_mode) in [
            ("group-folder", 0o775, 0o755),
            ("world-folder", 0o777, 0o755),
            ("group-file", 0o755, 0o775),
            ("world-file", 0o755, 0o757),
        ] {
            let (_fixture, program) = Fixture::new(tag, folder_mode, file_mode);
            assert!(
                check_root_service_program(&program, me()).is_err(),
                "{tag}: folder {folder_mode:o}, file {file_mode:o}"
            );
        }
        // An ancestor two levels up, not only the binary's own folder.
        let (fixture, program) = Fixture::new("ancestor", 0o755, 0o755);
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o777)).unwrap();
        }
        assert!(check_root_service_program(&program, me()).is_err());
    }

    /// #146: links cannot launder a binary. A link in a writable folder is
    /// refused even when it points at a trusted file, and a trusted-looking
    /// path whose real file sits in a writable folder is refused too.
    #[test]
    fn symlinks_through_writable_folders_are_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (_trusted, program) = Fixture::new("link-target", 0o755, 0o755);
        let (open, _) = Fixture::new("link-open", 0o755, 0o755);
        fs::set_permissions(open.0.join("bin"), fs::Permissions::from_mode(0o777)).unwrap();
        let link = open.0.join("bin/link");
        symlink(&program, &link).unwrap();
        assert!(check_root_service_program(&link, me()).is_err());

        let (_writable, replaceable) = Fixture::new("real-open", 0o777, 0o755);
        let (protected, _) = Fixture::new("link-protected", 0o755, 0o755);
        let link = protected.0.join("bin/link");
        symlink(&replaceable, &link).unwrap();
        assert!(check_root_service_program(&link, me()).is_err());
        // A folder link pointing into the writable folder fails the same way.
        let folder_link = protected.0.join("folder");
        symlink(replaceable.parent().unwrap(), &folder_link).unwrap();
        assert!(check_root_service_program(&folder_link.join("infraternal"), me()).is_err());
    }

    /// A binary that vanished cannot back a service, and the message says so.
    #[test]
    fn a_missing_binary_is_refused_by_name() {
        let (fixture, _) = Fixture::new("missing", 0o755, 0o755);
        let gone = fixture.0.join("bin/absent");
        let refusal = check_root_service_program(&gone, me()).unwrap_err();
        assert!(refusal.contains("is gone"), "{refusal}");
    }

    /// #146 (J1151): the web folder beside the binary is held to the same
    /// rule. Accepted when only the trusted owner can change it; refused,
    /// naming the folder, the changeable path and the fix, when root would
    /// serve a folder another account owns or can write; reported by name
    /// when it is missing.
    #[test]
    fn a_root_served_web_folder_must_be_one_only_root_can_change() {
        use std::os::unix::fs::PermissionsExt;
        let (fixture, _) = Fixture::new("web", 0o755, 0o755);
        let web = fixture.0.join("web");
        fs::create_dir(&web).unwrap();
        fs::set_permissions(&web, fs::Permissions::from_mode(0o755)).unwrap();
        let index = web.join("index.html");
        fs::write(&index, "<!doctype html>").unwrap();
        fs::set_permissions(&index, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            check_root_web_folder(&web, me()),
            Ok(fs::canonicalize(&web).unwrap())
        );
        // A link to it checks out, but the answer is the real folder, which
        // is what the unit must store (J1180, F3).
        let link = fixture.0.join("web-link");
        std::os::unix::fs::symlink(&web, &link).unwrap();
        assert_eq!(
            check_root_web_folder(&link, me()),
            Ok(fs::canonicalize(&web).unwrap())
        );
        fs::remove_file(&link).unwrap();
        if me() != 0 {
            // Root's view of a release unpacked in a user's folder.
            let refusal = check_root_web_folder(&web, 0).unwrap_err();
            assert!(refusal.contains(&web.display().to_string()), "{refusal}");
            assert!(refusal.contains("/opt/infraternal"), "{refusal}");
        }
        // One group-writable file inside is enough to refuse, and is named.
        fs::set_permissions(&index, fs::Permissions::from_mode(0o664)).unwrap();
        let refusal = check_root_web_folder(&web, me()).unwrap_err();
        let named = fs::canonicalize(&index).unwrap();
        assert!(refusal.contains(&named.display().to_string()), "{refusal}");
        let refusal = check_root_web_folder(&fixture.0.join("absent"), me()).unwrap_err();
        assert!(refusal.contains("is not there"), "{refusal}");
    }

    /// `server init --system --dry-run` formats `SELinux` commands only when `SELinux` is active (#211).
    #[cfg(target_os = "linux")]
    #[test]
    fn selinux_dry_run_lines_reflect_host_state_and_rule_presence() {
        assert_eq!(format_selinux_dry_run_lines(None), "");

        let add_plan = crate::selinux::plan_for_tests(Path::new("/var/lib/infraternal"), true);
        assert_eq!(
            format_selinux_dry_run_lines(Some(&add_plan)),
            "  semanage fcontext -a -t bin_t \"/var/lib/infraternal/updates(/.*)?\"\n  restorecon -R /var/lib/infraternal/updates\n"
        );

        let existing_plan =
            crate::selinux::plan_for_tests(Path::new("/var/lib/infraternal"), false);
        assert_eq!(
            format_selinux_dry_run_lines(Some(&existing_plan)),
            "  restorecon -R /var/lib/infraternal/updates\n"
        );
    }
}
