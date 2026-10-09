//! Runs bounded OpenSSH children with strict host trust and isolated D183 credential policy [141 H12].

use crate::process::{execute, execute_bounded};
use crate::{
    config::PublicSshConfiguration,
    credentials::{CredentialConfig, CredentialSession},
    master::Master,
    model::{Destination, Failure, FailureKind, MeshEvidence},
    transport::{
        CommandOutput, Credentials, Input, Operation, SshSession, SshTransport, shell_quote,
    },
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::process::Command;

/// Executable paths are server configuration, never request fields.
pub struct OpenSsh {
    pub ssh: PathBuf,
    pub ssh_agent: PathBuf,
    pub ssh_add: PathBuf,
    pub ssh_keyscan: PathBuf,
    pub ssh_keygen: PathBuf,
    pub askpass_binary: PathBuf,
    pub scratch: PathBuf,
    pub command_timeout: Duration,
}

impl SshTransport for OpenSsh {
    fn open(
        &self,
        destination: Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            // Outer strict checking is not inherited by arbitrary proxy hops.
            // Refuse those configurations before materializing credentials or
            // contacting a host; a future adapter must enforce every hop.
            let configuration = effective_destination(&self.ssh, &destination).await?;
            self.open_configuration(configuration, credentials, mesh)
                .await
        })
    }
}

impl OpenSsh {
    pub(crate) fn open_configuration(
        &self,
        configuration: PublicSshConfiguration,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            if !configuration.validate_trust_paths() {
                return Err(Failure::unsupported(
                    "The SSH public trust paths are ambiguous or inaccessible.",
                ));
            }
            let credentials = CredentialSession::prepare(
                &CredentialConfig {
                    ssh_agent: self.ssh_agent.clone(),
                    ssh_add: self.ssh_add.clone(),
                    askpass_binary: self.askpass_binary.clone(),
                    scratch: self.scratch.clone(),
                },
                credentials,
            )
            .await?;
            let mut session = Session {
                ssh: self.ssh.clone(),
                keyscan: self.ssh_keyscan.clone(),
                keygen: self.ssh_keygen.clone(),
                configuration,
                credentials,
                mesh,
                timeout: self.command_timeout,
                master: None,
            };
            let socket = session.credentials.control_socket()?;
            match Master::start(
                session.command(&socket),
                socket,
                session.timeout,
                session.mesh,
            )
            .await
            {
                Ok(master) => session.master = Some(master),
                Err(mut failure) => {
                    if failure.kind == FailureKind::HostKey {
                        failure.fingerprints = session.observed_fingerprints().await;
                    }
                    return Err(failure);
                }
            }
            session.credentials.authenticated().await?;
            Ok(Arc::new(session) as Arc<dyn SshSession>)
        })
    }
}

struct Session {
    ssh: PathBuf,
    keyscan: PathBuf,
    keygen: PathBuf,
    configuration: PublicSshConfiguration,
    credentials: CredentialSession,
    mesh: MeshEvidence,
    timeout: Duration,
    master: Option<Master>,
}

impl Session {
    async fn observed_fingerprints(&self) -> Vec<String> {
        let destination = &self.configuration.destination;
        // Keyscan is an unauthenticated observation, never an admission path or
        // known_hosts update. Configuration aliases/proxies may not be scannable.
        let mut scan = Command::new(&self.keyscan);
        scan.args(["-T", "3", "-t", "ed25519,ecdsa,rsa", "-p"])
            .arg(destination.port().unwrap_or(22).to_string())
            .arg("--")
            .arg(destination.host());
        let Ok(output) = execute(&mut scan, Input::Empty, Duration::from_secs(5)).await else {
            return Vec::new();
        };
        let mut fingerprints = Command::new(&self.keygen);
        fingerprints.args(["-l", "-E", "sha256", "-f", "/dev/stdin"]);
        let Ok(output) = execute(
            &mut fingerprints,
            Input::Bytes(&output.stdout),
            Duration::from_secs(3),
        )
        .await
        else {
            return Vec::new();
        };
        output
            .stdout
            .split(u8::is_ascii_whitespace)
            .filter_map(|bytes| std::str::from_utf8(bytes).ok())
            .filter(|word| {
                word.starts_with("SHA256:")
                    && word.len() == 50
                    && word[7..]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
            })
            .take(4)
            .map(str::to_owned)
            .collect()
    }
    fn command(&self, socket: &std::path::Path) -> Command {
        let mut command = Command::new(&self.ssh);
        // Method-specific authentication precedes retained public preferences;
        // OpenSSH singleton command-line options keep their first value.
        self.credentials.configure(&mut command);
        self.configuration.configure(&mut command);
        // Command-line precedence forces these over config: host keys cannot be accepted or rewritten;
        // forwarding/control sockets from server config must not outlive bootstrap.
        command.args([
            "-T",
            "-o",
            "ProxyJump=none",
            "-o",
            "ProxyCommand=none",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "VerifyHostKeyDNS=no",
            "-o",
            "KnownHostsCommand=none",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ControlPersist=no",
            "-o",
            "ForkAfterAuthentication=no",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "LogLevel=ERROR",
        ]);
        let destination = &self.configuration.destination;
        command.args(["-M", "-N", "-S"]).arg(socket);
        command.arg("-l").arg(destination.user());
        if let Some(port) = destination.port() {
            command.arg("-p").arg(port.to_string());
        }
        command.arg("--").arg(destination.host());
        command
    }
}

pub(crate) async fn effective_destination(
    ssh: &std::path::Path,
    destination: &Destination,
) -> Result<PublicSshConfiguration, Failure> {
    let mut configuration = Command::new(ssh);
    configuration
        .args(["-G", "-o", "ForkAfterAuthentication=no", "-l"])
        .arg(destination.user());
    if let Some(port) = destination.port() {
        configuration.arg("-p").arg(port.to_string());
    }
    configuration.arg("--").arg(destination.host());
    let configuration = execute_bounded(
        &mut configuration,
        Input::Empty,
        Duration::from_secs(3),
        65536,
    )
    .await?;
    if !configuration.success {
        return Err(Failure::unsupported(
            "The SSH configuration cannot be used for bootstrap.",
        ));
    }
    PublicSshConfiguration::parse(destination, &configuration.stdout).ok_or_else(|| {
        Failure::unsupported(
            "SSH proxies or invalid effective addresses are unsupported by bootstrap.",
        )
    })
}

/// Resolve only the effective network endpoint; never scan a different configured port or proxy hop.
#[must_use]
pub fn scan_destination(original: &Destination, bytes: &[u8]) -> Option<Destination> {
    if bytes.len() > 65536 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut host = None;
    let mut port = None;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(' ') else {
            continue;
        };
        let value = value.trim();
        match name {
            "hostname" => {
                if host.replace(value).is_some() {
                    return None;
                }
            }
            "port" => {
                if port.replace(value).is_some() {
                    return None;
                }
            }
            "proxyjump" | "proxycommand" if value != "none" => return None,
            _ => {}
        }
    }
    let host = host?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Destination::parse(&format!("{}@{host}:{}", original.user(), port?)).ok()
}

impl SshSession for Session {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let master = self.master.as_ref().ok_or_else(|| {
                Failure::new(FailureKind::Unreachable, "The SSH connection has closed.")
            })?;
            if !master.alive()? {
                return Err(Failure::new(
                    FailureKind::Unreachable,
                    "The SSH connection has closed.",
                ));
            }
            let mut command = Command::new(&self.ssh);
            command
                .env_remove("SSH_AUTH_SOCK")
                .env_remove("SSH_ASKPASS")
                .env("SSH_ASKPASS_REQUIRE", "never")
                .env("LC_ALL", "C");
            // A missing/stale master must fail locally, never create another
            // connection or reuse the browser's now-erased credential.
            command
                .args(["-F", "/dev/null", "-T", "-S"])
                .arg(master.socket())
                .args([
                    "-o",
                    "ControlMaster=no",
                    "-o",
                    "ControlPersist=no",
                    "-o",
                    "ProxyJump=none",
                    "-o",
                    "ProxyCommand=/bin/sh -c 'exit 1'",
                    "-o",
                    "ForkAfterAuthentication=no",
                    "-o",
                    "IdentityFile=none",
                    "-o",
                    "CertificateFile=none",
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
                    "GSSAPIAuthentication=no",
                ]);
            let destination = &self.configuration.destination;
            command
                .arg("-l")
                .arg(destination.user())
                .arg("-p")
                .arg(destination.port().unwrap_or(22).to_string())
                .arg("--")
                .arg(destination.host());
            command.arg(format!("sh -c {}", shell_quote(script)));
            let result = execute(&mut command, input, self.timeout).await?;
            if result.success {
                return Ok(CommandOutput {
                    stdout: result.stdout,
                });
            }
            // Authentication already succeeded. Never treat remote stderr or
            // a command's exit 255 as permission to try a different credential.
            Err(Failure::install("The authenticated SSH command failed."))
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Retire the unreaped master group before removing its private scope.
        drop(self.master.take());
    }
}

/// Only allowlisted categories/text survive; remote banners and command output are discarded.
#[must_use]
pub fn classify(stderr: &[u8], ssh_failure: bool, mesh: MeshEvidence) -> Failure {
    let text = String::from_utf8_lossy(&stderr[..stderr.len().min(8192)]);
    let mut failure = if !ssh_failure {
        Failure::install("The remote bootstrap command failed.")
    } else if text.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
        || text.contains("Host key verification failed")
        || text.contains("host key is known")
    {
        Failure::new(
            FailureKind::HostKey,
            "The SSH host key needs review before connecting.",
        )
    } else if text.contains("Permission denied") || text.contains("Authentication failed") {
        Failure::new(
            FailureKind::Auth,
            "SSH authentication failed. Choose another credential.",
        )
    } else if ssh_failure
        && (text.contains("Connection refused") || text.contains("Connection timed out"))
        && mesh.is_peer
        && mesh.reachable_otherwise
    {
        Failure::new(
            FailureKind::MeshPolicy,
            "The mesh peer is reachable, but its policy may block SSH.",
        )
    } else if ssh_failure {
        Failure::new(
            FailureKind::Unreachable,
            "The SSH host could not be reached.",
        )
    } else {
        Failure::install("The remote bootstrap command failed.")
    };
    failure.log_tail.push(match failure.kind {
        FailureKind::HostKey => "OpenSSH refused host-key verification.",
        FailureKind::Auth => "OpenSSH refused authentication.",
        FailureKind::MeshPolicy => {
            "Discovery confirms mesh reachability; SSH was refused or timed out."
        }
        FailureKind::Unreachable => "OpenSSH could not establish the connection.",
        _ => "Remote command returned a failure status; raw output was withheld.",
    });
    failure
}
