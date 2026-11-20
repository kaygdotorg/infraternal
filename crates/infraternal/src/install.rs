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
            if args.host_firewall_off {
                return Ok(format!(
                    "{folders}Would clear the server host policy, remove only marked infraternal host table and loader state when no agent policy remains, and write {}:\n{}\nWould run:\n  systemctl daemon-reload\n  systemctl enable --now {}.service\n",
                    path.display(),
                    unit,
                    options.name,
                ) + &link_plan(user, &args.data)?);
            }
            let firewall = make_firewall_install(args)?;
            return Ok(format!(
                "{folders}Would replace the hand-installed {FIREWALL_SERVICE} and take over inet infraternal_host.\nWould write {}:\n{}\nWould write {}:\n{}\nWould write {}:\n{}\nWould run:\n  systemctl daemon-reload\n  systemctl enable {FIREWALL_SERVICE}\n  systemctl restart {FIREWALL_SERVICE}\n  {}\n",
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
    let (firewall, removal_report) = install_in_order(
        &path,
        unit.as_bytes(),
        &absolute(&args.data)?,
        options.force,
        || plan_firewall(args, options),
        |plan| publish_planned_firewall(plan, &systemctl),
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
fn systemctl_command(program: &Path) -> Command {
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
        let directory = match env::var_os("XDG_CONFIG_HOME") {
            Some(path) => PathBuf::from(path).join("systemd/user"),
            None => PathBuf::from(env::var_os("HOME").ok_or(InstallError::Invalid)?)
                .join(".config/systemd/user"),
        };
        Ok(directory.join(basename))
    } else {
        Ok(PathBuf::from("/etc/systemd/system").join(basename))
    }
}

/// Render the server process unit and preserve all typed runtime options.
///
/// Every path in `ExecStart` is absolute and quoted.
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
    let binary = service_program().map_err(InstallError::Io)?;
    let data = absolute(&args.data)?;
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
    if let Some(web_root) = &args.web_root {
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
}
