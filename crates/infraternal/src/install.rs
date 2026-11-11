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
use infraternal_plugin_mesh::host_firewall::{self, Policy};

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
        Some(make_firewall_install(args)?)
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    if let Some(firewall) = &firewall {
        host_firewall::write_policy_file(
            Path::new(host_firewall::SERVER_POLICY_PATH),
            &firewall.policy,
        )
        .map_err(|error| InstallError::Io(std::io::Error::other(error)))?;
        write_atomic(Path::new(FIREWALL_UNIT_PATH), firewall.unit.as_bytes())
            .map_err(InstallError::Io)?;
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
    #[cfg(target_os = "linux")]
    if firewall.is_some() {
        let mut command = Command::new("systemctl");
        infraternal_shim::prepare_child(&mut command);
        command.stdin(std::process::Stdio::null());
        command.args(["enable", FIREWALL_SERVICE]);
        if !command.status().map_err(InstallError::Io)?.success() {
            return Err(InstallError::Systemctl);
        }
        let mut command = Command::new("systemctl");
        infraternal_shim::prepare_child(&mut command);
        command.stdin(std::process::Stdio::null());
        command.args(["restart", FIREWALL_SERVICE]);
        if !command.status().map_err(InstallError::Io)?.success() {
            return Err(InstallError::Systemctl);
        }
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
    Ok(format!("Installed and enabled {}\n", path.display()))
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
    let policy_json = serde_json::to_string_pretty(&policy)
        .map_err(|error| InstallError::HostFirewall(error.to_string()))?;
    let unit = render_firewall_unit()?;
    Ok(FirewallInstall {
        unit,
        policy,
        policy_json,
    })
}

/// Render the boot unit that applies the saved infraternal host policy before networking.
#[cfg(target_os = "linux")]
fn render_firewall_unit() -> Result<String, InstallError> {
    let binary = env::current_exe().map_err(InstallError::Io)?;
    let executable = quote_systemd(binary.as_os_str())?;
    Ok(format!(
        "[Unit]\nDescription=infraternal host input firewall\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nExecStart={executable} __host-firewall-apply\nRemainAfterExit=yes\n\n[Install]\nWantedBy=network-pre.target\n"
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
}
