//! Validates bootstrap admission and defines bounded progress plus API-only setup diagnostics [139][141].

use crate::auth_order::Authentication;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Write as _;
use std::net::Ipv6Addr;
use std::sync::Arc;

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
    /// Setup found a finished infraternal install for another host id at its
    /// location (#394): from another server, another person on this server, or
    /// an earlier setup. Nothing was changed; the location goes in Details.
    #[serde(rename = "unrecognized_install")]
    UnrecognizedInstall,
    /// A staging step met files at the setup location that it cannot prove are
    /// infraternal's own (exit 71), and changed nothing. `refusal` says which
    /// check refused, when the host named it (#394, J314 P2-1).
    #[serde(rename = "unproven_files")]
    UnprovenFiles,
    /// The host has no account with the login name; no sign-in method can
    /// help, so the person picks another account or root (#394).
    #[serde(rename = "no_account")]
    NoAccount,
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

/// Retain only a bounded child diagnostic; normal serialization and debug output stay opaque.
#[derive(Clone)]
struct CapturedSetupStderr(Arc<crate::transport::Secret>);

impl std::fmt::Debug for CapturedSetupStderr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
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
    /// Rare failure details stay boxed so every `Result<_, Failure>` remains small.
    ids: Option<Box<FailureIds>>,
}

/// Each uuid keeps its own field, so one can never be read or sent as the other.
#[derive(Clone, Debug, Default)]
struct FailureIds {
    /// Binds a host-key confirmation to the observation that produced it.
    host_key_challenge: Option<uuid::Uuid>,
    /// The owner's existing host that makes this an already-added failure.
    existing_host_id: Option<uuid::Uuid>,
    /// Bounded SSH setup output is released only by the API-key event adapter.
    captured_setup_stderr: Option<CapturedSetupStderr>,
    /// Validated lease owner details for the setup-running and stuck-upgrade messages.
    setup_lock: Option<SetupLock>,
    /// Which staging check refused with exit 71, as the host named it.
    refusal: Option<Refusal>,
    /// A finished install of another server that this attempt offers to take over (D359).
    takeover: Option<TakeoverOffer>,
}

/// The staging check that refused with exit 71 (#394, J314 P2-1). The host
/// names it with one fixed stderr line, `INFRATERNAL_REFUSED <cause>`, right
/// before its exit; nothing else from stderr is used. A host could name the
/// wrong one, which only selects another fixed sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// The private payload cache beside the setup location is not one setup made.
    Cache,
    /// A prepared copy of the infraternal agent from an earlier setup is in the way.
    Prepared,
    /// The setup location holds files but no owner record of an infraternal setup.
    Foreign,
    /// The setup location's owner record names another host.
    Owner,
}

impl Refusal {
    /// The cause named by the last `INFRATERNAL_REFUSED <cause>` line of
    /// `stderr`, if any.
    #[must_use]
    pub fn from_stderr(stderr: &str) -> Option<Self> {
        stderr
            .lines()
            .rev()
            .find_map(|line| match line.strip_prefix("INFRATERNAL_REFUSED ")? {
                "cache" => Some(Self::Cache),
                "prepared" => Some(Self::Prepared),
                "foreign" => Some(Self::Foreign),
                "owner" => Some(Self::Owner),
                _ => None,
            })
    }
}

/// What a Take over confirmation must show (D359): the old install's id, which
/// the person confirms, and whether its agent is running now (Take over stops it).
/// Public: the id is the host id in its `.bootstrap-owner`, never a secret.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TakeoverOffer {
    /// The old install's id, as 32 lowercase hex characters.
    install: String,
    live: bool,
    /// Each terminal that confirmation will close (D368).
    terminals: Vec<crate::previous_attempt::TakeoverTerminal>,
    /// Only a UI that understands terminal closure receives and submits this challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    close_challenge: Option<uuid::Uuid>,
}

/// Host-local lease metadata parsed from the fixed setup-check record.
// Each flag is its own optional field of the public wire shape the tracer
// reads; an enum would change that JSON, not the meaning (#305, D337).
#[allow(clippy::struct_excessive_bools)]
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
    /// Another server's install is running with open terminals, so it may be in use
    /// there: taking it over is refused until ownership of that server can be
    /// proven (D337).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    in_use: bool,
}

/// Serialize the failure's wire fields; each UUID has its own key and its own field.
impl Serialize for Failure {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Failure", 16)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("message", &self.public_message())?;
        state.serialize_field("log_tail", &self.log_tail)?;
        if let Some(setup_lock) = self.ids.as_deref().and_then(|ids| ids.setup_lock.as_ref()) {
            state.serialize_field("setup_lock", setup_lock)?;
        }
        if let Some(refusal) = self.ids.as_deref().and_then(|ids| ids.refusal) {
            state.serialize_field("refusal", &refusal)?;
        }
        if let Some(takeover) = self.ids.as_deref().and_then(|ids| ids.takeover.as_ref()) {
            state.serialize_field("takeover", takeover)?;
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
    /// Attach bounded output from a failed trusted setup command for API-action diagnostics.
    ///
    /// This data is intentionally omitted from `Debug` and normal serialization. The server
    /// may add it to a key-authorized setup event only.
    #[must_use]
    pub fn with_captured_setup_stderr(mut self, stderr: &[u8]) -> Self {
        let stderr = &stderr[..stderr.len().min(8 * 1024)];
        if !stderr.is_empty() {
            self.ids
                .get_or_insert_with(Box::default)
                .captured_setup_stderr = Some(CapturedSetupStderr(Arc::new(
                crate::transport::Secret::new(stderr.to_vec()),
            )));
        }
        self
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
            in_use: false,
            set_aside: false,
            live: false,
        });
        self
    }

    /// Record which staging check refused (exit 71), as the host named it.
    #[must_use]
    pub fn with_refusal(mut self, refusal: Option<Refusal>) -> Self {
        if refusal.is_some() {
            self.ids.get_or_insert_with(Box::default).refusal = refusal;
        }
        self
    }

    /// The staging check that refused, if the host named it.
    #[must_use]
    pub fn refusal(&self) -> Option<Refusal> {
        self.ids.as_deref().and_then(|ids| ids.refusal)
    }

    /// Offer to take over the finished install of another server whose id is
    /// `install`, and say whether its agent runs (D359).
    #[must_use]
    pub(crate) fn with_takeover(
        mut self,
        install: uuid::Uuid,
        live: bool,
        terminals: Vec<crate::previous_attempt::TakeoverTerminal>,
    ) -> Self {
        self.ids.get_or_insert_with(Box::default).takeover = Some(TakeoverOffer {
            install: install.simple().to_string(),
            live,
            terminals,
            close_challenge: None,
        });
        self
    }

    /// Bind terminal closure to its own confirmation, so cached UIs cannot use generic cleanup consent.
    #[must_use]
    pub(crate) fn with_terminal_confirmation(mut self, challenge: uuid::Uuid) -> Self {
        if let Some(offer) = self
            .ids
            .as_deref_mut()
            .and_then(|ids| ids.takeover.as_mut())
            && !offer.terminals.is_empty()
        {
            offer.close_challenge = Some(challenge);
        }
        self
    }

    /// The terminal-aware confirmation challenge, absent for ordinary cleanup and terminal-free takeover.
    #[must_use]
    pub(crate) fn terminal_confirmation(&self) -> Option<uuid::Uuid> {
        self.ids.as_deref()?.takeover.as_ref()?.close_challenge
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

    /// Read retained setup output only from the server's key-authorized event adapter.
    #[must_use]
    pub fn captured_setup_stderr(&self) -> Option<&[u8]> {
        self.ids
            .as_deref()
            .and_then(|details| details.captured_setup_stderr.as_ref())
            .map(|captured| captured.0.expose())
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

    /// Mark another server's stuck install as in use there, so it is refused, not offered (D337).
    #[must_use]
    pub(crate) fn in_use_elsewhere(mut self) -> Self {
        if let Some(lock) = self
            .ids
            .as_deref_mut()
            .and_then(|ids| ids.setup_lock.as_mut())
        {
            lock.in_use = true;
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
        if lock.in_use {
            // The host cannot see whether the old agent is connected; a running
            // agent with open terminals may be, so it is not taken (D337).
            let server = lock
                .enrolled_with
                .as_deref()
                .filter(|server| !server.is_empty())
                .unwrap_or("the server that enrolled it");
            let open = lock.sessions.unwrap_or(0);
            let terminals = if open == 1 {
                "1 open terminal".to_owned()
            } else {
                format!("{open} open terminals")
            };
            return Cow::Owned(format!(
                "{} is enrolled with {server}. Its infraternal agent is running with {terminals} and may still be connected to {server}. Prove you own {server} to take it over; that isn't available yet.",
                lock.machine
            ));
        }
        if let Some(server) = &lock.enrolled_with {
            // An empty name: the host could not read its identity file, so
            // nothing shows that another server enrolled it (#305 P2-2).
            if server.is_empty() {
                text.push_str(
                    " This server did not enroll this machine, and its identity cannot be read.",
                );
            } else {
                let _ = write!(
                    text,
                    " This machine is enrolled with another server, {server}."
                );
            }
            if lock.live {
                let other = if server.is_empty() {
                    "the server that enrolled it"
                } else {
                    server.as_str()
                };
                let _ = write!(
                    text,
                    " Its infraternal agent is running and may be connected to {other} now. Joining it here disconnects it from {other}; remove it there afterwards."
                );
            }
            text.push_str(" Joining it to this server makes it a new host with a new key; its old infraternal agent and key are deleted once it has joined.");
        } else {
            text.push_str(" Replace the stuck install to continue.");
        }
        // A Replace (no other server) hands open terminals to the new agent;
        // a Re-enroll ends them (D337).
        let fate = if lock.enrolled_with.is_some() {
            "will end"
        } else {
            "will carry over"
        };
        match lock.sessions {
            Some(0) => text.push_str(" No terminal sessions are open."),
            Some(1) => {
                let _ = write!(text, " 1 open terminal session {fate}.");
            }
            Some(open) => {
                let _ = write!(text, " {open} open terminal sessions {fate}.");
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
            FailureKind::UnrecognizedInstall => "unrecognized-install",
            FailureKind::UnprovenFiles => "unproven-files",
            FailureKind::NoAccount => "no-account",
            FailureKind::Unsupported => "unsupported",
            FailureKind::StalePreviousAttempt => "leftovers",
            FailureKind::SetupRunning => "setup-running",
            FailureKind::Install if self.log_tail.contains(&"The SSH command channel failed.") => {
                "channel"
            }
            FailureKind::Install if self.log_tail.contains(&"The SSH connection setup failed.") => {
                "transport"
            }
            FailureKind::Install => "setup",
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
            (Some(71), mode) => {
                // One plain finding, no chore and no second explanation: the
                // step's own advice ("copying didn't finish") does not apply
                // to a refusal, so the kind changes and the tracer shows only
                // this text; the location goes in Details (#394, TASTE). Each
                // check the host named gets its own sentence; only an owner
                // record for another host is "set up elsewhere" (J314 P2-1).
                (self.kind, self.message) = match self.refusal() {
                    Some(Refusal::Owner) => (
                        FailureKind::UnrecognizedInstall,
                        crate::previous_attempt::INSTALLED_ELSEWHERE,
                    ),
                    Some(Refusal::Cache) => (FailureKind::UnprovenFiles, UNPROVEN_CACHE),
                    Some(Refusal::Prepared) => (FailureKind::UnprovenFiles, UNPROVEN_PREPARED),
                    Some(Refusal::Foreign) => (FailureKind::UnprovenFiles, UNPROVEN_FOREIGN),
                    None => (FailureKind::UnprovenFiles, UNPROVEN_FILES),
                };
                self.log_tail.push(setup_location(mode));
            }
            (Some(72), _) => {
                self.message = "An earlier setup on this host did not finish. Retry the host check to finish its cleanup before continuing.";
            }
            (Some(73), _) => {
                self.kind = FailureKind::SetupRunning;
                self.message =
                    "Setup is already running on this host. Wait for it to finish, then try again.";
            }
            // ACTIVATE could not give the root agent binary an SELinux type
            // that systemd may start (#401).
            (Some(78), _) => {
                self.message = "SELinux would not let systemd start the infraternal agent: setup could not mark its binary in /var/lib/infraternal/bin as a program (bin_t). Check the host's SELinux policy, then try again.";
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
/// Exit 71 outside the read-only check: a staging step met files at the setup
/// location that it cannot prove are this setup's own, and changed nothing.
pub const UNPROVEN_FILES: &str = "Setup found infraternal files on this machine that it can't prove belong to this setup, so it changed nothing.";
/// [`Refusal::Cache`]'s sentence.
pub const UNPROVEN_CACHE: &str = "The infraternal agent's download cache on this machine wasn't made by setup, so setup changed nothing.";
/// [`Refusal::Prepared`]'s sentence.
pub const UNPROVEN_PREPARED: &str = "A copy of the infraternal agent left by an earlier setup is in the way, so setup changed nothing.";
/// [`Refusal::Foreign`]'s sentence.
pub const UNPROVEN_FOREIGN: &str = "The setup folder on this machine holds files that no infraternal setup made, so setup changed nothing.";

/// The Details line naming where setup looked, by install mode (#394).
#[must_use]
pub fn setup_location(mode: InstallMode) -> &'static str {
    match mode {
        InstallMode::Rootless => "Setup location: ~/.local/share/infraternal",
        InstallMode::Root => "Setup location: /var/lib/infraternal",
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

    /// #401: a root install whose binary `SELinux` would not mark executable
    /// (exit 78 from ACTIVATE) says so, instead of a generic setup failure.
    #[test]
    fn selinux_label_refusal_names_selinux() {
        let mut failure =
            Failure::install("The remote setup command failed.").at(super::InstallStep::Install);
        failure.exit_status = Some(78);
        let failure = failure.in_mode(super::InstallMode::Root);
        assert!(
            failure
                .message
                .starts_with("SELinux would not let systemd start")
        );
    }

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

    #[test]
    fn captured_setup_stderr_is_secret_debug_data_and_stays_out_of_normal_serialization() {
        let marker = "private-remote-setup-detail";
        let failure = Failure::install("The remote setup command failed.")
            .with_captured_setup_stderr(marker.as_bytes());

        assert_eq!(failure.captured_setup_stderr(), Some(marker.as_bytes()));
        assert!(!format!("{failure:?}").contains(marker));
        assert!(!serde_json::to_string(&failure).unwrap().contains(marker));
        assert!(
            !serde_json::to_string(&failure)
                .unwrap()
                .contains("captured_stderr")
        );
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
