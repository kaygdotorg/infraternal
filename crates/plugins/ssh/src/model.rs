//! Validates bootstrap admission before SSH or privilege changes, and defines content-free progress [139][141].

use crate::auth_order::Authentication;
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

/// A validated destination; fields are private to prevent bypassing shell/option safety.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    user: String,
    host: String,
    port: Option<u16>,
}

impl Destination {
    /// Accept `user@host[:port]`, including bracketed IPv6; never accept SSH options.
    /// # Errors
    /// Refuses malformed, unbounded, ambiguous or shell-active destination text.
    pub fn parse(value: &str) -> Result<Self, Failure> {
        if value.len() > 320 {
            return Err(Failure::unsupported("The SSH address is too long."));
        }
        let (user, address) = value
            .split_once('@')
            .ok_or_else(|| Failure::unsupported("Use an SSH address such as user@host."))?;
        if user.is_empty()
            || user.len() > 64
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            || user.starts_with('-')
        {
            return Err(Failure::unsupported("The SSH username is invalid."));
        }
        let (host, port) = if let Some(bracketed) = address.strip_prefix('[') {
            let (host, suffix) = bracketed
                .split_once(']')
                .ok_or_else(|| Failure::unsupported("The IPv6 address is invalid."))?;
            host.parse::<Ipv6Addr>()
                .map_err(|_| Failure::unsupported("The IPv6 address is invalid."))?;
            let port = if suffix.is_empty() {
                None
            } else {
                Some(parse_port(suffix.strip_prefix(':').ok_or_else(|| {
                    Failure::unsupported("The SSH port is invalid.")
                })?)?)
            };
            (host.to_owned(), port)
        } else {
            let (host, port) = match address.split_once(':') {
                Some((host, port)) => (host, Some(parse_port(port)?)),
                None => (address, None),
            };
            if host.is_empty()
                || host.len() > 253
                || host.starts_with('-')
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
            {
                return Err(Failure::unsupported("The SSH hostname is invalid."));
            }
            (host.to_owned(), port)
        };
        Ok(Self {
            user: user.to_owned(),
            host,
            port,
        })
    }

    /// SSH login name, separately passed with `-l`.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }
    /// Hostname or unbracketed numeric address.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
    /// Explicit port; absent preserves the server's SSH configuration.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

fn parse_port(value: &str) -> Result<u16, Failure> {
    value
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0 && value.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| Failure::unsupported("The SSH port is invalid."))
}

/// Root never follows automatically from sudo availability [139].
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InstallMode {
    #[default]
    Rootless,
    Root,
}

/// Source ids are resolved only by the trusted inventory adapter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum TargetAddress {
    Manual(String),
    Discovered(String),
}

/// Requests contain references to encrypted credentials, never plaintext secrets.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub address: TargetAddress,
    #[serde(default)]
    pub credential: Option<String>,
    #[serde(default)]
    pub mode: InstallMode,
    #[serde(default)]
    pub root_consent: bool,
}

impl Target {
    /// Check identifiers, privilege consent and destination grammar without making a connection.
    /// # Errors
    /// Refuses invalid identifiers, invalid credential references or root without consent.
    pub fn validate(&self) -> Result<(), Failure> {
        if !identifier(&self.id) || self.credential.as_ref().is_some_and(|v| !identifier(v)) {
            return Err(Failure::unsupported(
                "The host or credential reference is invalid.",
            ));
        }
        if self.mode == InstallMode::Root && !self.root_consent {
            return Err(Failure::unsupported(
                "Root installation needs explicit consent.",
            ));
        }
        match &self.address {
            TargetAddress::Manual(value) => {
                Destination::parse(value)?;
            }
            TargetAddress::Discovered(id) if !identifier(id) => {
                return Err(Failure::unsupported(
                    "The discovered host reference is invalid.",
                ));
            }
            TargetAddress::Discovered(_) => {}
        }
        Ok(())
    }
}

/// Stable request and vault identifiers are bounded and never become shell text.
#[must_use]
pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Public failure categories; raw process/database errors never enter the event stream.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FailureKind {
    Unreachable,
    Auth,
    MeshPolicy,
    HostKey,
    Unsupported,
    Install,
    #[serde(rename = "stale_previous_attempt")]
    StalePreviousAttempt,
    #[serde(rename = "setup_running")]
    SetupRunning,
}

/// Public, bounded findings from a host-local ownership check; paths belong in Details.
#[derive(Clone, Debug, Serialize)]
pub struct Leftovers {
    pub challenge: uuid::Uuid,
    pub mode: InstallMode,
    pub findings: Vec<&'static str>,
}

/// Trusted installation boundary; no request chooses its diagnostic context.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallStep {
    /// Trusted server-side payload selection, before the remote upload.
    GetArm64Binary,
    #[serde(rename = "get-x86-64-binary")]
    GetX86_64Binary,
    Connect,
    Upload,
    Install,
    Join,
    Start,
    Readiness,
}

/// Architecture and expected public path selected by the server's release bundle.
#[derive(Clone, Debug, Serialize)]
pub struct MissingBinary {
    pub architecture: &'static str,
    pub path: String,
}

/// Human diagnostics are trusted static text; fingerprints are independently validated.
#[derive(Clone, Debug, Serialize)]
pub struct Failure {
    pub kind: FailureKind,
    pub message: &'static str,
    pub log_tail: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<InstallStep>,
    /// Public process status only; command output is never serialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<u8>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub already_added: bool,
    /// Trusted server payload coordinates; never fields echoed from SSH stderr.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_binary: Option<Box<MissingBinary>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fingerprints: Vec<String>,
    /// Exact public key family selected for this confirmation and subsequent negotiation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_type: Option<String>,
    /// An existing application pin differs; replacement requires this explicit confirmation.
    #[serde(skip_serializing_if = "is_false")]
    pub host_key_changed: bool,
    /// Only exhausted D183 authentication permits the UI to request another method.
    #[serde(skip_serializing_if = "is_false")]
    pub choose_method: bool,
    /// Public first-contact handle; never admission by possession alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_challenge: Option<uuid::Uuid>,
}
impl Failure {
    #[must_use]
    pub fn new(kind: FailureKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            log_tail: Vec::new(),
            failed_step: None,
            exit_status: None,
            already_added: false,
            missing_binary: None,
            fingerprints: Vec::new(),
            host_key_type: None,
            host_key_changed: false,
            choose_method: false,
            host_key_challenge: None,
        }
    }
    /// Bounded diagnosis for server logs; authentication and trust always retain their categories.
    #[must_use]
    pub fn diagnostic_kind(&self) -> &'static str {
        match self.kind {
            FailureKind::Auth => "auth",
            FailureKind::HostKey => "host-key",
            FailureKind::Unreachable | FailureKind::MeshPolicy => "transport",
            _ if self.log_tail.contains(&"The SSH command channel failed.") => "channel",
            _ if self.log_tail.contains(&"The SSH connection setup failed.") => "transport",
            _ => "setup",
        }
    }

    /// Attach a fixed local boundary: channel execution when true, connection setup otherwise.
    #[must_use]
    pub fn at_ssh_boundary(mut self, channel: bool) -> Self {
        // Reuse bounded, static diagnostics rather than growing every retained
        // Failure/event with a field solely for server instrumentation.
        let boundary = if channel {
            "The SSH command channel failed."
        } else {
            "The SSH connection setup failed."
        };
        if !self.log_tail.contains(&boundary) {
            self.log_tail.push(boundary);
        }
        self
    }

    /// Attach the command boundary without changing authentication/trust classification.
    #[must_use]
    pub fn at(mut self, step: InstallStep) -> Self {
        self.failed_step = Some(step);
        if self.kind == FailureKind::Install
            && self.missing_binary.is_none()
            && !self.already_added
            && self.message != "The matching static infraternal binary is unavailable."
        {
            self.message = match step {
                InstallStep::GetArm64Binary | InstallStep::GetX86_64Binary => self.message,
                InstallStep::Connect => {
                    "Connecting to the host failed. Check SSH access and the host service, then try again."
                }
                InstallStep::Upload => {
                    "Uploading the infraternal binary failed. Check SSH access and free space on the host, then try again."
                }
                InstallStep::Install => {
                    "Installing the infraternal agent failed. Check the host service configuration and existing setup files, then try again."
                }
                InstallStep::Join => {
                    "Joining the host to this server failed. Check the host can reach the server and resolve its address, then try again."
                }
                InstallStep::Readiness => {
                    "Checking terminal readiness failed. Check the infraternal agent service and its terminal session, then try again."
                }
                InstallStep::Start => {
                    "Starting the infraternal agent service failed. Check the host service status and its configuration, then try again."
                }
            };
        }
        self
    }
    /// Classify fixed installer exit codes using the approved path. Join also
    /// executes the uploaded payload, whose status is not an ownership receipt.
    #[must_use]
    pub fn in_mode(mut self, mode: InstallMode) -> Self {
        if self.kind != FailureKind::Install {
            return self;
        }
        match (self.exit_status, mode) {
            (Some(71..=73), _) if matches!(self.failed_step, Some(InstallStep::Join)) => {}
            (Some(71), InstallMode::Rootless) => {
                self.message = "An existing folder ~/.local/share/infraternal on this host wasn't created by infraternal setup or isn't private. Move it aside, then try again.";
            }
            (Some(71), InstallMode::Root) => {
                self.message = "An existing folder /var/lib/infraternal on this host wasn't created by infraternal setup or isn't private. Move it aside with administrator access, then try again.";
            }
            (Some(72), _) => {
                self.message = "Host provisioning found another setup attempt. Retry the host check to continue.";
            }
            (Some(73), _) => {
                self.kind = FailureKind::SetupRunning;
                self.message =
                    "Setup is already running on this host. Wait for it to finish, then try again.";
            }
            _ => {}
        }
        if self.exit_status.is_some() {
            self.log_tail
                .retain(|line| !line.starts_with("Remote command returned"));
        }
        self
    }
    #[must_use]
    pub fn unsupported(message: &'static str) -> Self {
        Self::new(FailureKind::Unsupported, message)
    }
    #[must_use]
    pub fn install(message: &'static str) -> Self {
        Self::new(FailureKind::Install, message)
    }
}
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde skip predicates receive a reference."
)]
fn is_false(value: &bool) -> bool {
    !*value
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failed_step {
            Some(InstallStep::GetArm64Binary) => f.write_str("Get the arm64 binary: ")?,
            Some(InstallStep::GetX86_64Binary) => f.write_str("Get the x86_64 binary: ")?,
            _ => (),
        }
        f.write_str(self.message)
    }
}
impl std::error::Error for Failure {}

/// Mesh facts originate from server discovery, never a bootstrap request [141 H12].
#[derive(Clone, Copy, Debug, Default)]
pub struct MeshEvidence {
    pub is_peer: bool,
    pub reachable_otherwise: bool,
}

/// Only this fixed vocabulary is exposed as progress.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Step {
    Check,
    Install,
    Facts,
    Connect,
    Done,
    Failed,
}

/// Every attempt ends in exactly one done/failed record, and every record has a sequence.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub sequence: u64,
    pub target: String,
    pub attempt: u32,
    pub step: Step,
    pub message: &'static str,
    pub elapsed_ms: u64,
    pub log_tail: Vec<&'static str>,
    /// Present after the fixed authenticated check; never inferred from banners.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,
    /// Bound invitation identity; only done proves this host is ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leftovers: Option<Box<Leftovers>>,
}
