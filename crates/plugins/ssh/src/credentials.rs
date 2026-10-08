//! Hands decrypted SSH material to ephemeral helpers without secret files, argv or environment values [23][141].

use crate::{
    model::{Failure, FailureKind},
    process::execute,
    transport::{Credentials, Input, Secret, shell_quote},
};
use std::{
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::UnixListener,
    process::{Child, Command},
    task::JoinHandle,
};

/// Trusted helper paths and private socket root; requests cannot set these paths.
pub struct CredentialConfig {
    pub ssh_agent: PathBuf,
    pub ssh_add: PathBuf,
    pub askpass_binary: PathBuf,
    pub scratch: PathBuf,
}

/// Scope owns every helper and its 0700 directory, including during failed preparation.
pub struct CredentialSession {
    directory: Option<PathBuf>,
    agent: Option<Child>,
    askpass: Option<JoinHandle<()>>,
    password: bool,
    prompt_helper: bool,
}

impl CredentialSession {
    /// Materialize only private helper programs/sockets; secrets stay in stdin or memory.
    /// # Errors
    /// Refuses invalid material, long socket paths or unavailable/refusing helpers.
    pub async fn prepare(
        adapter: &CredentialConfig,
        credentials: Credentials,
    ) -> Result<Self, Failure> {
        let mut session = Self {
            directory: None,
            agent: None,
            askpass: None,
            password: false,
            prompt_helper: false,
        };
        if matches!(credentials, Credentials::Automatic(_)) {
            return Err(Failure::install(
                "Automatic SSH authentication requires its ordered adapter.",
            ));
        }
        if matches!(credentials, Credentials::Network) {
            return Ok(session);
        }
        match std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&adapter.scratch)
        {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(Failure::install(
                    "The private SSH helper root could not be created.",
                ));
            }
        }
        let root = std::fs::symlink_metadata(&adapter.scratch)
            .map_err(|_| Failure::install("The private SSH helper root is unavailable."))?;
        if !root.is_dir()
            || root.permissions().mode() & 0o077 != 0
            || root.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err(Failure::install(
                "The SSH helper root must be a private owned directory.",
            ));
        }
        let directory = adapter
            .scratch
            // 96 random bits keep helper socket paths within Linux sun_path.
            .join(format!(
                "ssh-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..24]
            ));
        if directory.join("askpass.sock").as_os_str().len() >= 108 {
            return Err(Failure::install(
                "The SSH helper socket directory is too long.",
            ));
        }
        // scratch is explicit trusted server configuration. Do not follow a request path.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| {
                Failure::install("The private SSH helper directory could not be created.")
            })?;
        session.directory = Some(directory.clone());
        let (key, prompt_secret) = match credentials {
            Credentials::Network | Credentials::Automatic(_) => unreachable!(),
            Credentials::PrivateKey { key, passphrase } => (Some(key), passphrase),
            Credentials::Password(password) => {
                session.password = true;
                (None, Some(password))
            }
        };
        // Missing passphrases must refuse through the private route rather than
        // allowing ssh-add to open the server operator's controlling terminal.
        session.prepare_prompt(adapter, &directory, prompt_secret)?;
        if let Some(key) = key {
            session.prepare_key(adapter, &directory, key).await?;
            // The key is now inside the scoped ssh-agent. Its passphrase is no
            // longer needed by SSH and must not remain in the prompt task.
            if let Some(task) = session.askpass.take() {
                task.abort();
            }
        }
        Ok(session)
    }

    fn prepare_prompt(
        &mut self,
        adapter: &CredentialConfig,
        directory: &std::path::Path,
        secret: Option<Secret>,
    ) -> Result<(), Failure> {
        if secret.as_ref().is_some_and(|secret| {
            secret.expose().is_empty()
                || secret.expose().len() > 16 * 1024
                || secret.expose().contains(&0)
                || secret.expose().contains(&b'\n')
        }) {
            return Err(Failure::new(
                FailureKind::Auth,
                "The SSH password or passphrase is invalid.",
            ));
        }
        let socket_path = directory.join("askpass.sock");
        let prompt = if let Some(secret) = secret {
            let listener = UnixListener::bind(&socket_path)
                .map_err(|_| Failure::install("The private SSH prompt socket could not start."))?;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| Failure::install("The SSH prompt socket could not be protected."))?;
            Some((listener, secret))
        } else {
            None
        };
        let binary = adapter
            .askpass_binary
            .to_str()
            .ok_or_else(|| Failure::install("The SSH prompt helper path is invalid."))?;
        let mut helper = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(directory.join("askpass"))
            .map_err(|_| Failure::install("The SSH prompt helper could not be created."))?;
        writeln!(
            helper,
            "#!/bin/sh\n# Private credential reply; never approve a trust or permission prompt.\ncase \"${{1-}}\" in\n\"Enter passphrase for \"*\": \"|*\"'s password: \") ;;\n*) exit 1;;\nesac\nexec {} __ssh-askpass",
            shell_quote(binary)
        )
        .map_err(|_| Failure::install("The SSH prompt helper could not be written."))?;
        self.prompt_helper = true;
        if let Some((listener, secret)) = prompt {
            self.askpass = Some(tokio::spawn(serve_prompt(listener, secret)));
        }
        Ok(())
    }
    async fn prepare_key(
        &mut self,
        adapter: &CredentialConfig,
        directory: &std::path::Path,
        key: Secret,
    ) -> Result<(), Failure> {
        if key.expose().is_empty() || key.expose().len() > 64 * 1024 {
            return Err(Failure::new(
                FailureKind::Auth,
                "The SSH private key is invalid.",
            ));
        }
        let agent_socket = directory.join("agent.sock");
        let agent = Command::new(&adapter.ssh_agent)
            .args(["-D", "-a"])
            .arg(&agent_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Failure::install("The temporary SSH key helper could not start."))?;
        self.agent = Some(agent);
        // Only active startup uses a short retry; healthy helpers have no polling task.
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if tokio::net::UnixStream::connect(&agent_socket).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| Failure::install("The temporary SSH key helper did not become ready."))?;
        let mut add = Command::new(&adapter.ssh_add);
        add.arg("-");
        self.configure_helpers(&mut add);
        let output = execute(
            &mut add,
            Input::Bytes(key.expose()),
            Duration::from_secs(10),
        )
        .await?;
        if !output.success {
            return Err(Failure::new(
                FailureKind::Auth,
                "The SSH private key or passphrase was refused.",
            ));
        }
        Ok(())
    }

    fn configure_helpers(&self, command: &mut Command) {
        if let Some(directory) = &self.directory {
            // These are paths, never credential values. Supplied keys use only
            // this child's ephemeral helper, independently of inherited identities.
            if self.agent.is_some() {
                command.env("SSH_AUTH_SOCK", directory.join("agent.sock"));
            }
            if self.prompt_helper {
                command
                    .env("SSH_ASKPASS", directory.join("askpass"))
                    .env("SSH_ASKPASS_REQUIRE", "force")
                    .env("DISPLAY", ":0")
                    .env(
                        "INFRATERNAL_SSH_ASKPASS_SOCKET",
                        directory.join("askpass.sock"),
                    );
            } else {
                command
                    .env_remove("SSH_ASKPASS")
                    .env("SSH_ASKPASS_REQUIRE", "never");
            }
        }
    }

    /// Apply credential paths and authentication policy to one OpenSSH child.
    pub fn configure(&self, command: &mut Command) {
        // Replace the inherited agent only with this scope's helper, if any.
        command.env_remove("SSH_AUTH_SOCK");
        self.configure_helpers(command);
        command.env("LC_ALL", "C");
        // No method may accidentally use system identity files, certificates or
        // hardware providers inherited from the server user's SSH configuration.
        command.args([
            "-o",
            "IdentityFile=none",
            "-o",
            "CertificateFile=none",
            "-o",
            "PKCS11Provider=none",
            "-o",
            "HostbasedAuthentication=no",
            "-o",
            "GSSAPIDelegateCredentials=no",
        ]);
        if self.directory.is_none() {
            command
                .env_remove("SSH_AUTH_SOCK")
                .env_remove("SSH_ASKPASS")
                .env("SSH_ASKPASS_REQUIRE", "never");
            command.args([
                "-o",
                "IdentityAgent=none",
                "-o",
                "BatchMode=yes",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "GSSAPIDelegateCredentials=no",
            ]);
            // Agent-free mesh SSH can authenticate its network identity without
            // any local public-key/password material. Trusted inventory reports
            // the provider; a remote banner is never authority for that label.
            return;
        }
        if self.agent.is_some() {
            command.args(["-o", "IdentityFile=none", "-o", "IdentitiesOnly=no"]);
            if let Some(directory) = &self.directory {
                command.arg("-o").arg(format!(
                    "IdentityAgent={}",
                    directory.join("agent.sock").display()
                ));
            }
        }
        if self.password {
            command.args([
                "-o",
                "IdentityAgent=none",
                "-o",
                "PasswordAuthentication=yes",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "BatchMode=no",
                "-o",
                "PreferredAuthentications=password",
                "-o",
                "PubkeyAuthentication=no",
            ]);
        } else {
            command.args([
                "-o",
                "BatchMode=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
            ]);
        }
    }
}

async fn serve_prompt(listener: UnixListener, secret: Secret) {
    // The enclosing 0700 directory is the authority boundary. Limit helper requests
    // as a second bound; each accepted helper gets one reply and its socket closes.
    for _ in 0..32 {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            stream.write_all(secret.expose()).await?;
            stream.shutdown().await
        })
        .await;
    }
}

impl Drop for CredentialSession {
    fn drop(&mut self) {
        if let Some(task) = self.askpass.take() {
            task.abort();
        }
        if let Some(agent) = &mut self.agent {
            let _ = agent.start_kill();
        }
        if let Some(directory) = &self.directory {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

/// Hidden CLI mode invoked only by SSH's askpass protocol; stdout is its private reply pipe.
/// # Errors
/// Refuses missing/oversized socket paths, unavailable helpers or oversized replies.
pub fn askpass_reply() -> std::io::Result<()> {
    let path = std::env::var_os("INFRATERNAL_SSH_ASKPASS_SOCKET")
        .ok_or_else(|| std::io::Error::other("SSH prompt unavailable"))?;
    if path.len() > 108 {
        return Err(std::io::Error::other("SSH prompt unavailable"));
    }
    let stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut bytes = Vec::new();
    stream.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    let secret = Secret::new(bytes);
    if secret.expose().is_empty() || secret.expose().len() > 16 * 1024 {
        return Err(std::io::Error::other("SSH prompt unavailable"));
    }
    std::io::stdout().write_all(secret.expose())
}
