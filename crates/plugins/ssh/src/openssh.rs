//! Runs bounded OpenSSH children with strict host keys and in-place server identity [141 H12].

use crate::process::{execute, execute_bounded};
use crate::{
    credentials::{CredentialConfig, CredentialSession},
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
            effective_destination(&self.ssh, &destination).await?;
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
            Ok(Arc::new(Session {
                ssh: self.ssh.clone(),
                keyscan: self.ssh_keyscan.clone(),
                keygen: self.ssh_keygen.clone(),
                destination,
                credentials,
                mesh,
                timeout: self.command_timeout,
            }) as Arc<dyn SshSession>)
        })
    }
}

struct Session {
    ssh: PathBuf,
    keyscan: PathBuf,
    keygen: PathBuf,
    destination: Destination,
    credentials: CredentialSession,
    mesh: MeshEvidence,
    timeout: Duration,
}

impl Session {
    async fn observed_fingerprints(&self) -> Vec<String> {
        let Ok(destination) = effective_destination(&self.ssh, &self.destination).await else {
            return Vec::new();
        };
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
    fn command(&self) -> Command {
        let mut command = Command::new(&self.ssh);
        // Force these after config loading: host keys cannot be accepted or rewritten;
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
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ControlPersist=no",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "LogLevel=ERROR",
        ]);
        self.credentials.configure(&mut command);
        command.arg("-l").arg(self.destination.user());
        if let Some(port) = self.destination.port() {
            command.arg("-p").arg(port.to_string());
        }
        command.arg("--").arg(self.destination.host());
        command
    }
}

async fn effective_destination(
    ssh: &std::path::Path,
    destination: &Destination,
) -> Result<Destination, Failure> {
    let mut configuration = Command::new(ssh);
    configuration.args(["-G", "-l"]).arg(destination.user());
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
    scan_destination(destination, &configuration.stdout).ok_or_else(|| {
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
            let mut command = self.command();
            command.arg(format!("sh -c {}", shell_quote(script)));
            let result = execute(&mut command, input, self.timeout).await?;
            if result.success {
                return Ok(CommandOutput {
                    stdout: result.stdout,
                });
            }
            let mut failure = classify(&result.stderr, result.ssh_failure, self.mesh);
            if failure.kind == FailureKind::HostKey {
                failure.fingerprints = self.observed_fingerprints().await;
            }
            Err(failure)
        })
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
