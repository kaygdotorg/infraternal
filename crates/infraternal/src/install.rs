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
        #[cfg(target_os = "linux")]
        if options.system {
            if args.host_firewall_off {
                return Ok(format!(
                    "Would clear the server host policy, remove only marked infraternal host table and loader state when no agent policy remains, and write {}:\n{}\nWould run:\n  systemctl daemon-reload\n  systemctl enable --now {}.service\n",
                    path.display(),
                    unit,
                    options.name,
                ));
            }
            let firewall = make_firewall_install(args)?;
            return Ok(format!(
                "Would replace the hand-installed {FIREWALL_SERVICE} and take over inet infraternal_host.\nWould write {}:\n{}\nWould write {}:\n{}\nWould write {}:\n{}\nWould run:\n  systemctl daemon-reload\n  systemctl enable {FIREWALL_SERVICE}\n  systemctl restart {FIREWALL_SERVICE}\n  {}\n",
                host_firewall::SERVER_POLICY_PATH,
                firewall.policy_json,
                FIREWALL_UNIT_PATH,
                firewall.unit,
                path.display(),
                unit,
                enable,
            ));
        }
        return Ok(format!(
            "Data folder: {}\n{}Would write {}:\n{}\nWould run:\n  {}\n  {}\n",
            absolute(&args.data)?.display(),
            match &args.web_root {
                Some(web_root) => format!("Web folder: {}\n", absolute(web_root)?.display()),
                None => String::new(),
            },
            path.display(),
            unit,
            reload,
            enable
        ));
    }

    ensure_server_unit_writable(&path, unit.as_bytes(), options.force)?;

    #[cfg(target_os = "linux")]
    let firewall = if options.system {
        (!args.host_firewall_off)
            .then(|| make_firewall_install(args))
            .transpose()?
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let firewall_removal_report = if options.system && args.host_firewall_off {
        Some(
            host_firewall::clear_role_from_config(PolicyRole::Server)
                .map_err(|error| InstallError::HostFirewall(error.to_string()))?,
        )
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    if let Some(firewall) = &firewall {
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
                let mut command = Command::new("systemctl");
                infraternal_shim::prepare_child(&mut command);
                command.stdin(std::process::Stdio::null());
                command.args(arguments);
                Ok(command.status().map_err(InstallError::Io)?.success())
            },
        )?;
    }
    write_atomic(&path, unit.as_bytes()).map_err(InstallError::Io)?;
    // Create the data folder private before the service first starts, only
    // once the unit is accepted; an existing folder keeps its mode [#516].
    super::install_paths::create_private_dir(&absolute(&args.data)?).map_err(InstallError::Io)?;

    let mut command = Command::new("systemctl");
    infraternal_shim::prepare_child(&mut command);
    command.stdin(std::process::Stdio::null());
    command.args(&scope_args).arg("daemon-reload");
    if !command.status().map_err(InstallError::Io)?.success() {
        return Err(InstallError::Systemctl);
    }
    let mut command = Command::new("systemctl");
    infraternal_shim::prepare_child(&mut command);
    command.stdin(std::process::Stdio::null());
    command
        .args(&scope_args)
        .args(["enable", "--now", &service]);
    if !command.status().map_err(InstallError::Io)?.success() {
        return Err(InstallError::Systemctl);
    }
    #[cfg(target_os = "linux")]
    if firewall.is_some() {
        return Ok(firewall_install_confirmation(&path));
    }
    #[cfg(target_os = "linux")]
    if let Some(report) = firewall_removal_report {
        return Ok(format!(
            "{report}Installed and enabled {}\n",
            path.display()
        ));
    }
    Ok(format!("Installed and enabled {}\n", path.display()))
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

/// Save the server policy and loader unit, then enable the loader and apply the table now.
///
/// `write_policy` saves the policy (production: the root-only atomic
/// writer) and `systemctl` runs one system-manager command, answering
/// whether it succeeded; both are parameters so the order and failure
/// handling can be tested without root.
#[cfg(target_os = "linux")]
fn publish_firewall(
    firewall: &FirewallInstall,
    targets: &FirewallTargets<'_>,
    write_policy: &dyn Fn(&Path, &Policy) -> Result<(), InstallError>,
    systemctl: &mut dyn FnMut(&[&str]) -> Result<bool, InstallError>,
) -> Result<(), InstallError> {
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
}

/// Tell operators that the product unit now owns the named host firewall service and table.
#[cfg(target_os = "linux")]
fn firewall_install_confirmation(server_unit: &Path) -> String {
    format!(
        "Installed and enabled {} and {FIREWALL_SERVICE}; it replaces the hand-installed {FIREWALL_SERVICE} and owns inet infraternal_host.\n",
        server_unit.display()
    )
}

/// Refuse a conflicting server unit before publishing the host policy.
fn ensure_server_unit_writable(path: &Path, unit: &[u8], force: bool) -> Result<(), InstallError> {
    match fs::read(path) {
        Ok(existing) if existing == unit => Ok(()),
        Ok(_) if force => Ok(()),
        Ok(_) => Err(InstallError::ExistingUnit),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(InstallError::Io(error)),
    }
}

/// Build and validate the system firewall unit and saved policy for a server install.
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
    if ssh_connection.is_none() {
        console_admin_path(&policy.admin_rules, &console_sshd_ports())
            .map_err(InstallError::HostFirewall)?;
    }
    let policy_json = serde_json::to_string_pretty(&policy)
        .map_err(|error| InstallError::HostFirewall(error.to_string()))?;
    let unit = render_firewall_unit()?;
    Ok(FirewallInstall {
        unit,
        policy,
        policy_json,
    })
}

/// sshd's ports as the host reports them, for a console install.
#[cfg(all(target_os = "linux", not(test)))]
fn console_sshd_ports() -> host_firewall::SshdPorts {
    host_firewall::sshd_ports()
}

/// A fixed sshd on 22 for unit tests, so install plans don't depend on the runner.
///
/// The real lookup reads root-only sshd configuration and the host's socket
/// units, which a test runner may or may not see; `console_admin_path` and
/// the parsers have their own tests, and the root path is proven by
/// `review_j608_socket_sshd_console.sh`.
#[cfg(all(target_os = "linux", test))]
fn console_sshd_ports() -> host_firewall::SshdPorts {
    host_firewall::SshdPorts::Known(vec![host_firewall::SshdPortSource {
        source: "unit test",
        ports: vec![22],
    }])
}

/// From a console, require an admin rule for every port sshd uses (J589 P3, J608, J658).
///
/// Over SSH the live session's port is checked by
/// `validate_ssh_connection`. From a console nothing proves the saved
/// default-drop table keeps an SSH path, so the rules must admit every port
/// [`host_firewall::sshd_ports`] learned: the configured ones, the socket
/// unit's and the running sshd's. A rule for the configured port alone
/// dropped an sshd running with `-p 2222` (J658). When no port can be
/// learned the install is refused: guessing 22 locked out an sshd on 2222.
#[cfg(target_os = "linux")]
fn console_admin_path(
    rules: &[host_firewall::AllowRule],
    sshd: &host_firewall::SshdPorts,
) -> Result<(), String> {
    match sshd {
        host_firewall::SshdPorts::Known(_) => {
            let missing = host_firewall::uncovered_sshd_ports(rules, &sshd.required());
            if missing.is_empty() {
                return Ok(());
            }
            let missing = missing
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!(
                "no --host-firewall-allow rule admits sshd's port {missing}; sshd uses {}; \
                 every one needs a rule; rules limited to lo, to one source address or to a \
                 loopback network do not count; add one such as '*,*,tcp,<port>' so the \
                 default-drop host table keeps an SSH path",
                sshd.describe()
            ))
        }
        host_firewall::SshdPorts::Unknown(tried) => Err(format!(
            "sshd's port could not be determined ({tried}); run server init as root, or over \
             SSH so the live session's port is checked, before a default-drop host table is saved"
        )),
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

fn unit_path(user: bool, name: &str) -> Result<PathBuf, InstallError> {
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
fn render_unit(
    args: &ServerArgs,
    name: &str,
    origin: &str,
    user: bool,
) -> Result<String, InstallError> {
    let binary = env::current_exe().map_err(InstallError::Io)?;
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
    Ok(format!(
        "[Unit]\nDescription=infraternal server ({name})\nAfter=network.target\n\n[Service]\nType=simple\n{scope}ExecStart={command}\n{reload}Restart=on-failure\nRestartSec=2\nKillMode=process\nDelegate=yes\n\n[Install]\nWantedBy={target}\n"
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

fn quote_systemd(value: &std::ffi::OsStr) -> Result<String, InstallError> {
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

fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
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
    if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
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
        assert!(output.contains("/etc/systemd/system/infraternal-firewall.service"));
        assert!(output.contains("Before=network-pre.target"));
        assert!(output.contains("__host-firewall-apply"));
        assert!(output.contains("host-firewall-server.json"));
        assert!(output.contains("Would replace the hand-installed infraternal-firewall.service"));
        assert!(output.contains("systemctl restart infraternal-firewall.service"));
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

    /// A console install refuses when sshd's port is unknown and names the port it needs (J608).
    #[cfg(target_os = "linux")]
    #[test]
    fn console_install_never_guesses_sshd_port() {
        use super::host_firewall::{SshdPortSource, SshdPorts};
        let rules = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.parse().expect("rule"))
                .collect::<Vec<super::host_firewall::AllowRule>>()
        };
        let unknown = SshdPorts::Unknown("sshd -G: Permission denied".to_owned());
        let refused = super::console_admin_path(&rules(&["*,*,tcp,22"]), &unknown)
            .expect_err("an unknown sshd port must not pass as 22");
        assert!(refused.contains("could not be determined"), "{refused}");
        let on_2222 = SshdPorts::Known(vec![SshdPortSource {
            source: "sshd's configuration",
            ports: vec![2222],
        }]);
        let refused = super::console_admin_path(&rules(&["*,*,tcp,22"]), &on_2222)
            .expect_err("tcp/22 does not reach an sshd on 2222");
        assert!(
            refused.contains("2222 (from sshd's configuration)"),
            "{refused}"
        );
        assert_eq!(
            super::console_admin_path(&rules(&["*,*,tcp,2222"]), &on_2222),
            Ok(())
        );
        // J658: configured 22, running on 2222; both need a rule.
        let split = SshdPorts::Known(vec![
            SshdPortSource {
                source: "sshd's configuration",
                ports: vec![22],
            },
            SshdPortSource {
                source: "running sshd processes",
                ports: vec![2222],
            },
        ]);
        let refused = super::console_admin_path(&rules(&["*,*,tcp,22"]), &split)
            .expect_err("tcp/22 alone drops the sshd running on 2222");
        assert!(
            refused.contains("admits sshd's port 2222;")
                && refused.contains("22 (from sshd's configuration)")
                && refused.contains("2222 (from running sshd processes)"),
            "{refused}"
        );
        assert_eq!(
            super::console_admin_path(&rules(&["*,*,tcp,22", "*,*,tcp,2222"]), &split),
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
            let root =
                std::env::temp_dir().join(format!("j662-{name}-{}", std::process::id()));
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
                &|path, _policy| {
                    fs::write(path, b"NEW POLICY").map_err(InstallError::Io)
                },
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
        assert!(!fixture.unit().exists(), "the loader unit stayed: {calls:?}");
        assert!(
            calls.iter().any(|call| call == "disable infraternal-firewall.service"),
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
}
