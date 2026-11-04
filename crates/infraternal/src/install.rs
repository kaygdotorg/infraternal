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

    if options.dry_run {
        return Ok(format!(
            "Would write {}:\n{}\nWould run:\n  {}\n  {}\n",
            path.display(),
            unit,
            reload,
            enable
        ));
    }

    match fs::read(&path) {
        Ok(existing) if existing == unit.as_bytes() => {}
        Ok(_) if !options.force => return Err(InstallError::ExistingUnit),
        Ok(_) => write_atomic(&path, unit.as_bytes()).map_err(InstallError::Io)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_atomic(&path, unit.as_bytes()).map_err(InstallError::Io)?;
        }
        Err(error) => return Err(InstallError::Io(error)),
    }

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
    Ok(format!("Installed and enabled {}\n", path.display()))
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
    }
}
