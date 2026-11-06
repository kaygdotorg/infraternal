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
    /// Trusted optional binary implementing only the private socket handoff.
    pub tcp_connector: Option<PathBuf>,
    pub scratch: PathBuf,
    /// Short-command bound and maximum idle interval between remote byte receipts.
    /// Production uses 30 seconds; payload length does not consume this interval.
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
                .map_err(|error| error.at_ssh_boundary(false))
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
            async {
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
                    tcp_connector: self.tcp_connector.clone(),
                    master: None,
                };
                let socket = session.credentials.control_socket()?;
                match Master::start(
                    session.command(&socket),
                    socket,
                    session.timeout,
                    session.mesh,
                    &session.credentials.prompt_parent,
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
            }
            .await
            .map_err(|error: Failure| error.at_ssh_boundary(false))
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
    tcp_connector: Option<PathBuf>,
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
        if let Some(connector) = &self.tcp_connector
            && self.configuration.permits_connector()
        {
            let destination = &self.configuration.destination;
            let dial = format!(
                "{} __ssh-connect {} {}",
                shell_quote(&connector.to_string_lossy()),
                shell_quote(destination.host()),
                destination.port().unwrap_or(22),
            );
            // This local helper receives no credential and passes a socket,
            // not a proxy stream. Public config was already checked for hops;
            // all host-key/authentication checks remain in the same SSH child.
            command
                .args(["-o", "ProxyUseFdpass=yes", "-o"])
                .arg(format!("ProxyCommand={dial}"));
        }
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
            "-o",
            "LogVerbose=sshconnect2.c:ssh_userauth2():*",
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

impl Session {
    fn channel_command(&self, script: &str) -> Result<Command, Failure> {
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
        Ok(command)
    }
}

impl SshSession for Session {
    fn session_bridge(&self) -> bool {
        true
    }

    fn stream<'a>(&'a self, script: &'a str) -> Operation<'a, crate::duplex::Duplex> {
        Box::pin(async move { crate::duplex::Duplex::spawn(&mut self.channel_command(script)?) })
    }

    fn check_stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, (CommandOutput, Option<crate::install::Checked>)> {
        Box::pin(async move {
            crate::install::Installation::check_channel(self, script)
                .await
                .map(|(output, channel)| (output, Some(channel)))
        })
    }
    fn setup_steps(&self) -> bool {
        true
    }
    fn authentication(&self) -> Option<crate::auth_order::Authentication> {
        self.master
            .as_ref()
            .filter(|master| master.network_authenticated())
            .map(|_| crate::auth_order::Authentication {
                method: crate::auth_order::AuthMethod::Network,
                network: None,
            })
    }
    fn trust_lookup(&self) -> Option<String> {
        self.configuration
            .trust_policy()
            .map(|policy| policy.lookup)
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        self.run_with_timeout(script, input, self.timeout)
    }

    fn run_with_timeout<'a>(
        &'a self,
        script: &'a str,
        input: Input<'a>,
        timeout: Duration,
    ) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let mut command = self.channel_command(script)?;
            let result = execute(&mut command, input, timeout).await?;
            if result.success {
                return Ok(CommandOutput {
                    stdout: result.stdout,
                });
            }
            // Authentication already succeeded. Never treat remote stderr or
            // a command's exit 255 as permission to try a different credential.
            if script.starts_with("# INFRATERNAL_TRANSFER_SETUP_V1\n")
                && let Err(error) = crate::install::parse_transfer_setup(&result.stdout)
                && error.exit_status.is_some()
                && error.exit_status == result.exit_status
            {
                return Err(capture_setup_stderr(error, script, &result.stderr));
            }
            let mut failure = classify(&result.stderr, false, MeshEvidence::default());
            failure.exit_status = result.exit_status;
            failure = capture_setup_stderr(failure, script, &result.stderr);
            if script.starts_with("# INFRATERNAL_SETUP_STEPS_V1\n") {
                failure.failed_step = crate::install::interrupted_setup_step(&result.stdout);
            } else if script.starts_with("# INFRATERNAL_TRANSFER_SETUP_V1\n") {
                failure.failed_step = crate::install::interrupted_transfer_step(&result.stdout);
            }
            Err(failure).map_err(|error: Failure| error.at_ssh_boundary(true))
        })
    }
}

/// Keep remote stderr only for the trusted setup script families sent by this adapter.
fn capture_setup_stderr(mut failure: Failure, script: &str, stderr: &[u8]) -> Failure {
    if script.starts_with("# INFRATERNAL_SETUP_STEPS_V1\n")
        || script.starts_with("# INFRATERNAL_TRANSFER_SETUP_V1\n")
    {
        failure = failure.with_captured_setup_stderr(stderr);
    }
    failure
}

impl Drop for Session {
    fn drop(&mut self) {
        // Retire the unreaped master group before removing its private scope.
        drop(self.master.take());
    }
}

/// The whole stderr of a NetBird SSH session for a login name that is no
/// account on the host (measured against NetBird-SSH-Server 0.82.0, #394).
const NETBIRD_NO_ACCOUNT: &str = "User authentication failed";

/// Only allowlisted categories/text survive; remote banners and command output are discarded.
#[must_use]
pub fn classify(stderr: &[u8], ssh_failure: bool, mesh: MeshEvidence) -> Failure {
    let text = String::from_utf8_lossy(&stderr[..stderr.len().min(8192)]);
    let mut failure = if text.trim() == NETBIRD_NO_ACCOUNT {
        // The NetBird SSH server accepts the network sign-in, then ends the
        // session with exactly this line and status 1 when the login name is
        // no account on the host (#394: kayg on Proxmox hosts). Read as a
        // command failure, it was reported as a generic setup failure.
        // Nothing else matches: only this whole stderr selects the kind.
        Failure::new(
            FailureKind::NoAccount,
            "This host has no account with that user name.",
        )
    } else if !ssh_failure {
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
        FailureKind::NoAccount => "The host's SSH server reported no such account.",
        _ => "Remote command returned a failure status; raw output was withheld.",
    });
    // Copy only canonical public error lines, never arbitrary remote bytes.
    // Even a compromised banner can select a category but cannot inject secrets.
    for line in crate::model::JOIN_DIAGNOSTICS.iter().copied() {
        if text.contains(line) && !failure.log_tail.iter().any(|known| known.contains(line)) {
            failure.log_tail.push(line);
        }
    }
    failure.at_ssh_boundary(!ssh_failure)
}

/// Pins stderr classification and setup-stderr capture to their allowlists.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InstallStep;

    /// #394: NetBird's SSH server signs in over the network, then ends the
    /// session with this one line when the login name is no account there.
    #[test]
    fn a_login_name_with_no_account_is_named_not_a_setup_failure() {
        for ssh_failure in [false, true] {
            let failure = classify(
                b"User authentication failed\n",
                ssh_failure,
                MeshEvidence::default(),
            );
            assert_eq!(failure.kind, FailureKind::NoAccount);
            assert_eq!(failure.diagnostic_kind(), "no-account");
        }
        // Only the whole stderr selects it: a script that mentions it is not it.
        let other = classify(
            b"step 3\nUser authentication failed\n",
            false,
            MeshEvidence::default(),
        );
        assert_eq!(other.kind, FailureKind::Install);
    }

    #[test]
    fn only_trusted_setup_scripts_retain_bounded_child_stderr() {
        let marker = b"private setup output";
        let setup = capture_setup_stderr(
            Failure::install("The remote bootstrap command failed."),
            "# INFRATERNAL_SETUP_STEPS_V1\ncommand",
            marker,
        );
        assert_eq!(setup.captured_setup_stderr(), Some(marker.as_slice()));

        let ordinary = capture_setup_stderr(
            Failure::install("The SSH command failed."),
            "printf ordinary",
            marker,
        );
        assert_eq!(ordinary.captured_setup_stderr(), None);

        let oversized = capture_setup_stderr(
            Failure::install("The remote bootstrap command failed."),
            "# INFRATERNAL_TRANSFER_SETUP_V1\ncommand",
            &[b'x'; 9 * 1024],
        );
        assert_eq!(oversized.captured_setup_stderr().unwrap().len(), 8 * 1024);
    }

    #[test]
    fn join_keeps_only_authored_https_preflight_diagnostics() {
        let cases = [
            (
                "The infraternal agent on this host cannot resolve the server's HTTPS origin. Check DNS for the public origin and allow outbound TCP 443.",
                "The infraternal agent on this host cannot resolve the server's HTTPS origin. Check DNS for the public origin and allow outbound TCP 443.",
            ),
            (
                "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin, then try again.",
                "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin, then try again.",
            ),
            (
                "The infraternal agent on this host could not verify the server's HTTPS certificate. Check the public certificate chain and server name, then try again.",
                "The infraternal agent on this host could not verify the server's HTTPS certificate. Check the public certificate chain and server name, then try again.",
            ),
            (
                "The infraternal agent on this host reached the server over HTTPS, but the server did not accept its WebSocket. Deploy a server with the /remote/agent route and allow WebSocket upgrades through the proxy, then try again.",
                "The infraternal agent on this host reached the server over HTTPS, but the server did not accept its WebSocket. Deploy a server with the /remote/agent route and allow WebSocket upgrades through the proxy, then try again.",
            ),
            (
                "The server opened the WebSocket but did not send a valid infraternal agent challenge. Deploy a compatible server build and try again.",
                "The server opened the WebSocket but did not send a valid infraternal agent challenge. Deploy a compatible server build and try again.",
            ),
        ];
        for (diagnostic, expected) in cases {
            let mut failure = classify(
                format!("setup failed: {diagnostic}\n").as_bytes(),
                false,
                MeshEvidence::default(),
            );
            failure = failure.at(InstallStep::Join);
            assert_eq!(failure.message, expected);
            assert!(failure.log_tail.contains(&expected));
        }

        let mut untrusted = classify(
            b"setup failed: private path /home/kayg/.ssh/id_ed25519\n",
            false,
            MeshEvidence::default(),
        );
        untrusted = untrusted.at(InstallStep::Join);
        assert_eq!(
            untrusted.message,
            "Joining the host to this server failed. Check the host can reach the server and resolve its address, then try again."
        );
        assert!(
            untrusted
                .log_tail
                .iter()
                .all(|line| !line.contains("id_ed25519"))
        );
    }
}
