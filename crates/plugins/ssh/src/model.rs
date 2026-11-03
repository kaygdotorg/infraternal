//! Validates bootstrap admission before SSH or privilege changes, and defines content-free progress [139][141].

use crate::auth_order::Authentication;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Write as _;
use std::net::Ipv6Addr;

pub(crate) const SOCKET_PROBE_UNAVAILABLE: &str = "Finishing earlier setup needs the matching infraternal binary on this host. Its files were kept.";
pub(crate) const SOCKET_PROBE_UNCERTAIN: &str = "Setup could not determine whether the infraternal agent is still running. Its files were kept; check host permissions and retry.";

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
    pub findings: Vec<Cow<'static, str>>,
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

/// Authored setup messages that may cross the SSH join boundary without exposing remote output.
pub(super) const JOIN_DIAGNOSTICS: &[&str] = &[
    "Join DNS lookup failed: Temporary failure in name resolution.",
    "Join DNS lookup failed: Name or service not known.",
    "Join DNS lookup failed.",
    "Join connection failed.",
    "Join TLS verification failed.",
    "The infraternal agent on this host cannot resolve the server's HTTPS origin. Check DNS for the public origin and allow outbound TCP 443.",
    "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin, then try again.",
    "The infraternal agent on this host could not verify the server's HTTPS certificate. Check the public certificate chain and server name, then try again.",
    "The infraternal agent on this host reached the server over HTTPS, but the server did not accept its WebSocket. Deploy a server with the /remote/agent route and allow WebSocket upgrades through the proxy, then try again.",
    "The server opened the WebSocket but did not send a valid infraternal agent challenge. Deploy a compatible server build and try again.",
    "Failed to connect to bus: No medium found",
    "Failed to connect to bus: No such file or directory",
];

/// Architecture and expected public path selected by the server's release bundle.
#[derive(Clone, Debug, Serialize)]
pub struct MissingBinary {
    pub architecture: &'static str,
    pub path: String,
}

/// Human diagnostics are trusted static text; fingerprints are independently validated.
#[derive(Clone, Debug)]
pub struct Failure {
    pub kind: FailureKind,
    pub message: &'static str,
    pub log_tail: Vec<&'static str>,
    pub failed_step: Option<InstallStep>,
    /// Public process status only; command output is never serialized.
    pub exit_status: Option<u8>,
    pub already_added: bool,
    /// Trusted server payload coordinates; never fields echoed from SSH stderr.
    pub missing_binary: Option<Box<MissingBinary>>,
    pub fingerprints: Vec<String>,
    /// Exact public key family selected for this confirmation and subsequent negotiation.
    pub host_key_type: Option<String>,
    /// An existing application pin differs; replacement requires this explicit confirmation.
    pub host_key_changed: bool,
    /// Only exhausted D183 authentication permits the UI to request another method.
    pub choose_method: bool,
    /// The two rarely-set uuids, boxed so every `Result<_, Failure>` stays small (`clippy::result_large_err`).
    ids: Option<Box<FailureIds>>,
}

/// Each uuid keeps its own field, so one can never be read or sent as the other.
#[derive(Clone, Debug, Default)]
struct FailureIds {
    /// Binds a host-key confirmation to the observation that produced it.
    host_key_challenge: Option<uuid::Uuid>,
    /// The owner's existing host that makes this an already-added failure.
    existing_host_id: Option<uuid::Uuid>,
    /// Validated lease owner details for the setup-running and stuck-upgrade messages.
    setup_lock: Option<SetupLock>,
}

/// Host-local lease metadata parsed from the fixed setup-check record.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SetupLock {
    machine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    since: String,
    active: bool,
    /// The setup attempt that holds or last held the lock, by its first id characters (#305).
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<String>,
    /// Open terminal sessions a stuck-install replacement ends (#305, D13).
    #[serde(skip_serializing_if = "Option::is_none")]
    sessions: Option<u16>,
    /// The other server a stuck install is enrolled with; it may join as a new host (D335).
    #[serde(skip_serializing_if = "Option::is_none")]
    enrolled_with: Option<String>,
    /// An earlier add-host set this install aside and did not put it back (#305).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    set_aside: bool,
    /// The stuck install's agent is running and may be connected to its other server (#305).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    live: bool,
}

/// Serialize the failure's wire fields; each UUID has its own key and its own field.
impl Serialize for Failure {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Failure", 14)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("message", &self.public_message())?;
        state.serialize_field("log_tail", &self.log_tail)?;
        if let Some(setup_lock) = self.ids.as_deref().and_then(|ids| ids.setup_lock.as_ref()) {
            state.serialize_field("setup_lock", setup_lock)?;
        }
        if let Some(failed_step) = self.failed_step {
            state.serialize_field("failed_step", &failed_step)?;
        }
        if let Some(exit_status) = self.exit_status {
            state.serialize_field("exit_status", &exit_status)?;
        }
        if self.already_added {
            state.serialize_field("already_added", &self.already_added)?;
        }
        if let Some(missing_binary) = &self.missing_binary {
            state.serialize_field("missing_binary", missing_binary)?;
        }
        if !self.fingerprints.is_empty() {
            state.serialize_field("fingerprints", &self.fingerprints)?;
        }
        if let Some(host_key_type) = &self.host_key_type {
            state.serialize_field("host_key_type", host_key_type)?;
        }
        if self.host_key_changed {
            state.serialize_field("host_key_changed", &self.host_key_changed)?;
        }
        if self.choose_method {
            state.serialize_field("choose_method", &self.choose_method)?;
        }
        if let Some(uuid) = self.ids.as_deref().and_then(|ids| ids.host_key_challenge) {
            state.serialize_field("host_key_challenge", &uuid)?;
        }
        if let Some(uuid) = self.ids.as_deref().and_then(|ids| ids.existing_host_id)
            && self.already_added
        {
            state.serialize_field("host_id", &uuid)?;
        }
        state.end()
    }
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
            ids: None,
        }
    }
    /// Attach validated lease coordinates without growing the common failure payload.
    #[must_use]
    pub(crate) fn with_setup_lock(
        mut self,
        machine: String,
        pid: Option<u32>,
        since: String,
        active: bool,
    ) -> Self {
        self.ids.get_or_insert_with(Box::default).setup_lock = Some(SetupLock {
            machine,
            pid,
            since,
            active,
            attempt: None,
            sessions: None,
            enrolled_with: None,
            set_aside: false,
            live: false,
        });
        self
    }

    /// Mark the lock as an install an earlier add-host set aside and did not put back.
    #[must_use]
    pub(crate) fn with_set_aside(mut self) -> Self {
        if let Some(lock) = self
            .ids
            .as_deref_mut()
            .and_then(|ids| ids.setup_lock.as_mut())
        {
            lock.set_aside = true;
        }
        self
    }

    /// Name the setup attempt that holds the lock; the host's own name says only where it is.
    #[must_use]
    pub(crate) fn with_setup_attempt(mut self, attempt: Option<uuid::Uuid>) -> Self {
        if let Some(lock) = self
            .ids
            .as_deref_mut()
            .and_then(|ids| ids.setup_lock.as_mut())
        {
            lock.attempt = attempt.map(|attempt| attempt.simple().to_string()[..8].to_owned());
        }
        self
    }

    /// Name what confirming a stuck-install replacement ends and where the machine is enrolled.
    #[must_use]
    pub(crate) fn with_stuck_install(
        mut self,
        sessions: u16,
        enrolled_with: Option<String>,
        live: bool,
    ) -> Self {
        if let Some(lock) = self
            .ids
            .as_deref_mut()
            .and_then(|ids| ids.setup_lock.as_mut())
        {
            lock.sessions = Some(sessions);
            lock.enrolled_with = enrolled_with;
            lock.live = live;
        }
        self
    }

    fn public_message(&self) -> Cow<'_, str> {
        let Some(lock) = self.ids.as_deref().and_then(|ids| ids.setup_lock.as_ref()) else {
            return Cow::Borrowed(self.message);
        };
        let process = lock.pid.map_or_else(
            || "unknown process".to_owned(),
            |pid| format!("process {pid}"),
        );
        let holder = lock.attempt.as_ref().map_or_else(
            || process.clone(),
            |attempt| format!("setup attempt {attempt} ({process})"),
        );
        if lock.set_aside {
            return Cow::Owned(format!(
                "An earlier add-host on {} set this machine's infraternal agent aside and did not put it back. Nothing was deleted. Put it back as it was found, then add the host again to continue.",
                lock.machine
            ));
        }
        if lock.active {
            // Only an upgrade journal offers a replacement, and only once its
            // lease is gone; a running setup can only be waited for (#305).
            return Cow::Owned(format!(
                "On {}, {holder} has held the setup lock since {}. Wait for it to finish, then try again. A setup that stopped releases the lock within 3 minutes of its last step.",
                lock.machine, lock.since
            ));
        }
        let mut text = format!(
            "The failed setup on {} left a lease last held by {holder} since {}.",
            lock.machine, lock.since
        );
        if let Some(server) = &lock.enrolled_with {
            // An empty name: the host could not read its identity file, so
            // nothing shows that another server enrolled it (#305 P2-2).
            if server.is_empty() {
                text.push_str(" This server did not enroll this machine, and its identity cannot be read.");
            } else {
                let _ = write!(
                    text,
                    " This machine is enrolled with another server, {server}."
                );
            }
            if lock.live {
                let other = if server.is_empty() { "the server that enrolled it" } else { server.as_str() };
                let _ = write!(
                    text,
                    " Its infraternal agent is running and may be connected to {other} now. Joining it here disconnects it from {other}; remove it there afterwards."
                );
            }
            text.push_str(" Joining it to this server makes it a new host with a new key; its old infraternal agent is set aside, not deleted.");
        } else {
            text.push_str(" Replace the stuck install to continue.");
        }
        match lock.sessions {
            Some(0) => text.push_str(" No terminal sessions are open."),
            Some(1) => text.push_str(" 1 open terminal session will end."),
            Some(open) => {
                let _ = write!(text, " {open} open terminal sessions will end.");
            }
            None => {}
        }
        Cow::Owned(text)
    }
    /// Return the public challenge only while this error represents a host-key refusal.
    #[must_use]
    pub fn host_key_challenge(&self) -> Option<uuid::Uuid> {
        if self.already_added {
            None
        } else {
            self.ids.as_deref().and_then(|ids| ids.host_key_challenge)
        }
    }

    /// Record the challenge used to bind host-key confirmation to this observation.
    pub fn set_host_key_challenge(&mut self, challenge: Option<uuid::Uuid>) {
        if challenge.is_some() || self.ids.is_some() {
            self.ids.get_or_insert_with(Box::default).host_key_challenge = challenge;
        }
    }

    /// Attach the owner's existing host id to the already-added failure.
    #[must_use]
    pub fn with_existing_host_id(mut self, host_id: uuid::Uuid) -> Self {
        self.already_added = true;
        self.ids.get_or_insert_with(Box::default).existing_host_id = Some(host_id);
        self
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
    // Failure-only rewrites stay out of x86_64 async callers under the measured
    // size budget; ARM retains its existing code generation [243], #230.
    #[cfg_attr(target_arch = "x86_64", cold)]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
    pub fn at_ssh_boundary(mut self, channel: bool) -> Self {
        // Reuse bounded, static diagnostics rather than growing every retained
        // Failure/event with a field solely for server instrumentation.
        let boundary = if channel && self.exit_status.is_some() {
            // Authentication completed and the command returned a status. Its
            // refusal is setup evidence, not a broken SSH command channel.
            self.log_tail
                .retain(|line| *line != "The SSH command channel failed.");
            "The remote setup command returned a failure status."
        } else if channel {
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
    #[cfg_attr(target_arch = "x86_64", cold)]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
    pub fn at(mut self, step: InstallStep) -> Self {
        self.failed_step = Some(step);
        if self.kind == FailureKind::Install
            && self.missing_binary.is_none()
            && !self.already_added
            && self.message != "The matching static infraternal binary is unavailable."
        {
            let join_diagnostic = if matches!(step, InstallStep::Join) {
                self.log_tail
                    .iter()
                    .copied()
                    .find(|line| JOIN_DIAGNOSTICS.contains(line))
            } else {
                None
            };
            self.message = match (step, join_diagnostic) {
                (InstallStep::Join, Some(diagnostic)) => diagnostic,
                (InstallStep::GetArm64Binary | InstallStep::GetX86_64Binary, _) => self.message,
                (InstallStep::Connect, _) => {
                    "Connecting to the host failed. Check SSH access and the host service, then try again."
                }
                (InstallStep::Upload, _) => {
                    "Uploading the infraternal binary failed. Check SSH access and free space on the host, then try again."
                }
                (InstallStep::Install, _) => {
                    "Installing the infraternal agent failed. Check the host service configuration and existing setup files, then try again."
                }
                (InstallStep::Join, _) => {
                    "Joining the host to this server failed. Check the host can reach the server and resolve its address, then try again."
                }
                (InstallStep::Readiness, _) => {
                    "Checking terminal readiness failed. Check the infraternal agent service and its terminal session, then try again."
                }
                (InstallStep::Start, _) => {
                    "Starting the infraternal agent service failed. Check the host service status and its configuration, then try again."
                }
            };
        }
        self
    }
    /// Classify fixed installer exit codes using the approved path. Join also
    /// executes the uploaded payload, whose status is not an ownership receipt.
    #[must_use]
    #[cfg_attr(target_arch = "x86_64", cold)]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
    pub fn in_mode(mut self, mode: InstallMode) -> Self {
        if self.kind != FailureKind::Install {
            return self;
        }
        match (self.exit_status, mode) {
            (Some(71..=77), _) if matches!(self.failed_step, Some(InstallStep::Join)) => {}
            (Some(71), InstallMode::Rootless) => {
                self.message = "Setup could not verify ownership or permissions of its files on this host. Check ~/.local/share/infraternal, its parent folders and the infraternal service files, then try again.";
            }
            (Some(71), InstallMode::Root) => {
                self.message = "Setup could not verify ownership or permissions of its files on this host. Check /var/lib/infraternal, its parent folders and the infraternal service files with administrator access, then try again.";
            }
            (Some(72), _) => {
                self.message = "An earlier setup on this host did not finish. Retry the host check to finish its cleanup before continuing.";
            }
            (Some(73), _) => {
                self.kind = FailureKind::SetupRunning;
                self.message =
                    "Setup is already running on this host. Wait for it to finish, then try again.";
            }
            (Some(76), _) => self.message = SOCKET_PROBE_UNAVAILABLE,
            (Some(77), _) => self.message = SOCKET_PROBE_UNCERTAIN,
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
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failed_step {
            Some(InstallStep::GetArm64Binary) => f.write_str("Get the arm64 binary: ")?,
            Some(InstallStep::GetX86_64Binary) => f.write_str("Get the x86_64 binary: ")?,
            _ => (),
        }
        f.write_str(&self.public_message())
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
    /// Host-bound invitation identity; done publishes an attachable terminal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<uuid::Uuid>,
    /// The existing shim session to attach, present on early terminal publication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leftovers: Option<Box<Leftovers>>,
}

#[cfg(test)]
mod failure_serialization_tests {
    //! Preserve the public UUID key while sharing one compact failure reference slot.
    use super::{Failure, FailureKind};

    #[test]
    fn uuid_reference_uses_the_outcome_specific_wire_key() {
        let id = uuid::Uuid::from_u128(42);
        let mut challenge = Failure::new(FailureKind::HostKey, "Confirm this host key.");
        challenge.set_host_key_challenge(Some(id));
        let challenge = serde_json::to_value(challenge).unwrap();
        assert_eq!(challenge["host_key_challenge"], id.to_string());
        assert!(challenge.get("host_id").is_none());

        let duplicate = Failure::install("This host is already added.").with_existing_host_id(id);
        let duplicate = serde_json::to_value(duplicate).unwrap();
        assert_eq!(duplicate["host_id"], id.to_string());
        assert_eq!(duplicate["already_added"].as_bool(), Some(true));
        assert!(duplicate.get("host_key_challenge").is_none());
    }

    /// The exact JSON of both uuid-bearing shapes, and a size bound so `Result<_, Failure>` stays below the lint limit.
    #[test]
    fn wire_format_is_exact_and_failure_stays_small() {
        let id = uuid::Uuid::from_u128(42);
        let mut challenge = Failure::new(FailureKind::HostKey, "Confirm this host key.");
        challenge.set_host_key_challenge(Some(id));
        assert_eq!(
            serde_json::to_string(&challenge).unwrap(),
            format!(
                r#"{{"kind":"host-key","message":"Confirm this host key.","log_tail":[],"host_key_challenge":"{id}"}}"#
            )
        );
        let duplicate = Failure::install("Already added.").with_existing_host_id(id);
        assert_eq!(
            serde_json::to_string(&duplicate).unwrap(),
            format!(
                r#"{{"kind":"install","message":"Already added.","log_tail":[],"already_added":true,"host_id":"{id}"}}"#
            )
        );
        assert!(
            std::mem::size_of::<Failure>() <= 128,
            "{}",
            std::mem::size_of::<Failure>()
        );
    }
}
