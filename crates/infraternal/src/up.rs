//! Enrolls a Linux machine or Mac through device approval and starts its system service (#263, #483).

/// Keep fresh-host preflight, installation and rollback in one transaction.
#[cfg(target_os = "linux")]
#[path = "up_install.rs"]
mod install;

/// Install the Mac system service after device approval.
#[cfg(target_os = "macos")]
#[path = "up_macos.rs"]
mod macos;

/// Install and remove macOS user mode, the default for a Mac (#146).
#[cfg(target_os = "macos")]
#[path = "up_macos_user.rs"]
pub(crate) mod macos_user;

/// Route termination signals through enrollment cancellation and transaction cleanup.
#[path = "up_termination.rs"]
mod termination;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use hyper::StatusCode;
use infraternal_plugin_remote::enrollment::{JoinInvitation, Mode};
use infraternal_sign_in::{
    DeviceApproval, DeviceRedeemRequest, join_approval_link, parse_start_response,
};
use qrcodegen::{QrCode, QrCodeEcc};
use serde_json::json;
use std::{
    env, fs,
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::Duration,
};
use termination::Cancellation;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::output::{CommandResult, CommandState, Exit, emit};
use crate::trusted_program::{ToolError, trusted_program};
use infraternal_plugin_api::elevation_prompt::ElevationPrompt;
#[cfg(all(
    target_os = "linux",
    any(feature = "plugin-mesh", feature = "plugin-server")
))]
use infraternal_plugin_mesh::host_firewall;
#[cfg(all(
    any(feature = "plugin-mesh", feature = "plugin-server"),
    target_os = "linux"
))]
use infraternal_plugin_mesh::host_firewall::{AllowRule, Policy};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_INVITATION_BYTES: usize = 8 * 1024;
const MAX_KEY_BYTES: usize = 4 * 1024;
const MAX_HANDOFF_BYTES: usize = 16 * 1024;
/// Keep the private handoff bounded while supporting a small administrator list.
const MAX_HOST_FIREWALL_RULES: usize = 32;
/// Reject oversized rule strings before they reach the root installer.
const MAX_HOST_FIREWALL_RULE_BYTES: usize = 256;
#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "infraternal-agent.service";
/// The shared boot unit that restores product-owned input rules before networking.
///
/// Every build knows this name, even one without the mesh or server plugins
/// that install the unit: an install journal left on disk by a build that did
/// install it is recovered by whichever build runs `up` next, and that
/// rollback must stop our unit or restart the administrator's restored one
/// (#530).
#[cfg(target_os = "linux")]
const HOST_FIREWALL_SERVICE: &str = "infraternal-firewall.service";
#[cfg(target_os = "linux")]
const SERVICE_BINARY: &str = "/var/lib/infraternal/bin/infraternal";
#[cfg(target_os = "linux")]
const SERVICE_DATA: &str = "/var/lib/infraternal/agent";
#[cfg(target_os = "macos")]
use macos::{SERVICE_DATA, SERVICE_NAME};
const PATH_BINARY: &str = "/usr/local/bin/infraternal";
/// The image this process is running. Root installs this, never the file the
/// invoking user's path names: that file may be the user's to replace between
/// sudo starting the helper and the copy (#263, J134 P3-4).
#[cfg(target_os = "linux")]
const RUNNING_IMAGE: &str = "/proc/self/exe";
/// Where distributions (and `NixOS`) install the two programs `up` runs. PATH is
/// never searched: the invoking user controls it, and a sudo policy can keep
/// it for the root helper, so a PATH lookup could hand the machine key to
/// another program or run one as root (#263, J122 P2).
const SUDO_CANDIDATES: [&str; 3] = ["/usr/bin/sudo", "/bin/sudo", "/run/wrappers/bin/sudo"];
#[cfg(target_os = "linux")]
const SYSTEMCTL_CANDIDATES: [&str; 3] = [
    "/usr/bin/systemctl",
    "/bin/systemctl",
    "/run/current-system/sw/bin/systemctl",
];
/// The only environment the root helper gives systemctl.
#[cfg(target_os = "linux")]
const HELPER_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// A user-facing failure class with a stable D303 exit status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    InvalidServer,
    Permission,
    Expired,
    Unreachable,
    Partial,
    Unsupported,
    Throttled,
    Runtime,
    Failed,
    LocalState,
    SudoUnavailable,
    SudoDenied,
    UntrustedTool,
    #[cfg_attr(
        target_os = "macos",
        expect(dead_code, reason = "launchd is present on every Mac")
    )]
    NoSystemd,
    /// Local installation conflicts are distinct from a remote approval refusal.
    InstallConflict,
    /// The host firewall rules given to `up`, or the SSH session, could not be read.
    HostFirewall,
}

impl Failure {
    /// Classify a failure for the shared command result envelope.
    const fn state(self) -> CommandState {
        match self {
            Self::InvalidServer
            | Self::Permission
            | Self::Expired
            | Self::Unsupported
            | Self::HostFirewall
            | Self::SudoDenied
            | Self::UntrustedTool
            | Self::InstallConflict => CommandState::Refused,
            Self::Unreachable => CommandState::Unknown,
            Self::Partial
            | Self::Throttled
            | Self::Runtime
            | Self::Failed
            | Self::LocalState
            | Self::SudoUnavailable
            | Self::NoSystemd => CommandState::Failed,
        }
    }

    /// Map failures to stable D303 process statuses.
    const fn exit(self) -> Exit {
        match self {
            Self::InvalidServer => Exit::Usage,
            Self::Permission
            | Self::Expired
            | Self::SudoDenied
            | Self::UntrustedTool
            | Self::InstallConflict
            | Self::HostFirewall => Exit::NotAllowed,
            Self::Unsupported | Self::SudoUnavailable | Self::NoSystemd => Exit::NotFound,
            Self::Unreachable => Exit::Unreachable,
            Self::Partial => Exit::Partial,
            Self::Throttled | Self::Runtime | Self::Failed | Self::LocalState => Exit::Failed,
        }
    }

    /// Give a concise recovery hint without including private enrollment data.
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidServer => {
                "Use an HTTPS server origin with no path, credentials, query, or fragment."
            }
            Self::Permission => "The server refused this machine join.",
            Self::Expired => "The machine join code expired before approval.",
            Self::Unreachable => "Could not reach the server over HTTPS.",
            Self::Partial => {
                "The machine joined, but service setup or private-key cleanup did not finish."
            }
            Self::Unsupported => "This server does not support machine join.",
            Self::Throttled => "The server is limiting machine join requests.",
            Self::Runtime => "Could not start the machine join.",
            Self::Failed => "The machine join could not be completed.",
            Self::LocalState => {
                "Could not access local machine data. Check the infraternal data directory permissions and available disk space."
            }
            Self::SudoUnavailable => {
                "The system service needs sudo. Install sudo, then rerun infraternal up."
            }
            Self::SudoDenied => {
                "sudo did not authorize the system service installation. Check your privileges, then rerun infraternal up."
            }
            Self::UntrustedTool => {
                "sudo or systemctl can be changed by a user other than root. Give it and its directories back to root, then rerun infraternal up."
            }
            Self::InstallConflict => {
                "The local installation was refused. Resolve the conflict reported above before retrying infraternal up."
            }
            Self::HostFirewall => {
                "The host firewall settings are invalid. Check each --host-firewall-allow rule (INTERFACE,SOURCE,PROTOCOL,PORT), then rerun infraternal up."
            }
            Self::NoSystemd => {
                "infraternal up installs a systemd system service, and systemctl is not installed in a system directory."
            }
        }
    }

    const fn exit_code(self) -> u8 {
        self.exit().code()
    }

    /// Restore the matching failure kind from the root helper's bounded exit code.
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Failed),
            2 => Some(Self::InvalidServer),
            3 => Some(Self::Permission),
            4 => Some(Self::Expired),
            5 => Some(Self::Unreachable),
            6 => Some(Self::Partial),
            7 => Some(Self::HostFirewall),
            _ => None,
        }
    }
}

/// Which kind of installation a machine join asks the server for.
///
/// `System` is the root service on Linux and root mode on a Mac. `User` is macOS user mode
/// (#146): the infraternal agent runs as the person with this uid, and the server issues a
/// rootless invitation bound to that uid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JoinMode {
    /// A root service; the server records execution uid 0.
    System,
    /// A per-user install for this uid (never 0).
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only Macs have user mode yet")
    )]
    User(u32),
}

impl JoinMode {
    /// The `mode` text the device-approval request carries.
    const fn wire_mode(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User(_) => "user",
        }
    }

    /// The invitation mode and execution uid an approval must come back with.
    const fn invitation(self) -> (Mode, u32) {
        match self {
            Self::System => (Mode::Rootful, 0),
            Self::User(uid) => (Mode::Rootless, uid),
        }
    }
}

/// Carry the approved invitation, private key and host rules to the root installer over stdin.
struct Handoff {
    invitation: Zeroizing<Vec<u8>>,
    key_pkcs8: Zeroizing<Vec<u8>>,
    key_digest: [u8; 32],
    /// Administrator allow rules persisted for the next boot.
    ///
    /// The handoff format is the same in every build, so the rules are always
    /// carried and validated; only builds with the host firewall apply them.
    #[cfg_attr(
        not(all(
            target_os = "linux",
            any(feature = "plugin-mesh", feature = "plugin-server")
        )),
        allow(
            dead_code,
            reason = "The handoff format always carries admin_rules; only Linux builds with the host firewall read it."
        )
    )]
    admin_rules: Vec<String>,
}

/// The approved join, carrying its optional prior-install proof separately from the invitation.
struct ApprovedInvitation(
    JoinInvitation,
    #[cfg(all(target_os = "linux", feature = "plugin-ssh"))] bool,
);

impl ApprovedInvitation {
    fn wipe(&mut self) {
        self.0.token.zeroize();
    }
}

impl Drop for ApprovedInvitation {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Run a top-level join with cleanup before its final interrupt envelope and exit signal.
pub(crate) fn with_cancellation<F: std::future::Future<Output = Result<ExitCode, Failure>>>(
    command: impl FnOnce(Cancellation) -> F,
    json_output: bool,
) -> ExitCode {
    match termination::scope(|cancelled| async move {
        let result = command(cancelled.clone()).await;
        (result, cancelled.received())
    }) {
        Ok((Ok(code), signal)) => {
            if let Some(signal) = signal {
                infraternal_shim::exit_by_signal(signal);
            }
            code
        }
        Ok((Err(_), Some(signal))) => {
            if json_output {
                let _ = io::stdout().write_all(&crate::cli::output::interrupted_notice("up"));
            }
            infraternal_shim::exit_by_signal(signal);
        }
        Ok((Err(failure), None)) => fail(json_output, failure),
        Err(_) => fail(json_output, Failure::Runtime),
    }
}

/// Offer local retirement for a previous user installation after machine approval.
#[cfg(all(target_os = "linux", feature = "plugin-ssh"))]
#[path = "up_retire_previous.rs"]
mod retire_previous;

/// Request a fresh machine approval, wait for its one-use enrollment receipt, and install it.
pub(crate) async fn run(
    server_input: &str,
    host_firewall_allow: &[String],
    json_output: bool,
    cancelled: &Cancellation,
) -> Result<ExitCode, Failure> {
    let server = server_url(server_input)?;
    let origin = server.origin().ascii_serialization();
    // The code and link are a live approval capability for ten minutes. Show
    // them only to a person at a terminal, never into a pipe, file or CI log,
    // and do not wait out the lifetime when nobody can see them (#263).
    if !approval_display_is_terminal(json_output) {
        return Ok(needs_terminal(&origin, json_output));
    }
    // A redirected invocation exits before approval, so it should not fail a
    // host-policy check that only matters when installation can continue.
    #[cfg(all(
        target_os = "linux",
        any(feature = "plugin-mesh", feature = "plugin-server")
    ))]
    let admin_rules = {
        let ssh_connection = match env::var("SSH_CONNECTION") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                eprintln!("infraternal up: the active SSH path could not be read safely");
                return Err(Failure::HostFirewall);
            }
        };
        match agent_host_firewall_rules(host_firewall_allow, ssh_connection.as_deref()) {
            Ok(rules) => rules,
            Err(error) => {
                eprintln!("infraternal up host firewall: {error}");
                return Err(Failure::HostFirewall);
            }
        }
    };
    #[cfg(not(all(
        target_os = "linux",
        any(feature = "plugin-mesh", feature = "plugin-server")
    )))]
    let admin_rules = {
        // This build has no host firewall, and its command line never offers
        // the rules option, so the caller always passes an empty list.
        let _ = host_firewall_allow;
        Vec::new()
    };
    // Find both privileged programs before an approval is requested, so a
    // missing or replaceable one never wastes the owner's passkey approval.
    let Ok(executable) = env::current_exe() else {
        return Err(Failure::Permission);
    };
    let sudo = sudo_command(&executable, &origin, json_output)?;
    #[cfg(target_os = "linux")]
    trusted_tool(&SYSTEMCTL_CANDIDATES, Failure::NoSystemd)?;
    install_preflight()?;
    let hostname = local_hostname();
    let host_id = uuid::Uuid::new_v4();
    #[cfg(all(target_os = "linux", feature = "plugin-ssh"))]
    let old = retire_previous::inspect(json_output);
    #[cfg(all(target_os = "linux", feature = "plugin-ssh"))]
    let retirement_hint = old.as_ref().map(retire_previous::preference);
    #[cfg(not(all(target_os = "linux", feature = "plugin-ssh")))]
    let retirement_hint: Option<String> = None;
    let approval = async {
        let (key_pkcs8, key_digest) = crate::remote::prepare_machine_join_key(&origin)
            .await
            .map_err(|error| map_remote_failure(&error))?;
        let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(key_digest));
        let short_key = machine_key_short(&fingerprint).ok_or(Failure::Failed)?;
        let body = machine_start_body(host_id, &hostname, &fingerprint, JoinMode::System)?;
        let approval = start_approval(&server, &body).await?;
        let link = join_approval_link(&server, &approval.user_code);
        print_approval(json_output, &short_key, &approval.user_code, &link)?;
        let invitation = wait_for_approval(
            &server,
            &approval,
            host_id,
            &origin,
            JoinMode::System,
            retirement_hint.as_deref(),
        )
        .await?;
        Ok::<_, Failure>((invitation, key_pkcs8, key_digest, fingerprint, short_key))
    };
    let approved = cancelled
        .during(approval)
        .await
        .unwrap_or(Err(Failure::Failed));
    let (mut invitation, key_pkcs8, key_digest, fingerprint, short_key) =
        approved.inspect_err(|_| eprintln!("No system service was installed."))?;
    let payload = encode_handoff(&invitation.0, &key_pkcs8, &key_digest, &admin_rules)?;
    #[cfg(all(target_os = "linux", feature = "plugin-ssh"))]
    let retire = match old {
        Some(plan) if invitation.1 && retire_previous::confirm(&plan, cancelled).await => {
            Some(plan)
        }
        _ => None,
    };
    invitation.wipe();
    let installed = invoke_sudo(sudo, &payload, json_output, cancelled).await;
    if cancelled.received().is_some() {
        if installed.is_ok() {
            eprintln!("The installation finished and the system service remains installed.");
        }
        return Err(Failure::Failed);
    }
    installed?;
    #[cfg(all(target_os = "linux", feature = "plugin-ssh"))]
    if let Some(plan) = retire {
        retire_previous::finish(&plan);
    }
    #[cfg(all(
        target_os = "linux",
        any(feature = "plugin-mesh", feature = "plugin-server")
    ))]
    let host_firewall_service = Some(HOST_FIREWALL_SERVICE);
    #[cfg(not(all(
        target_os = "linux",
        any(feature = "plugin-mesh", feature = "plugin-server")
    )))]
    let host_firewall_service: Option<&str> = None;
    let success_message = if host_firewall_service.is_some() {
        "This machine joined; infraternal-firewall.service admits the mesh's input and blocks nothing else."
    } else {
        "This machine joined the server and its system service is active."
    };
    let success_body = if host_firewall_service.is_some() {
        format!(
            "Machine joined as {hostname}.\nService: active\nHost input firewall: mesh input only (infraternal-firewall.service)\nCommand: {PATH_BINARY}"
        )
    } else {
        format!("Machine joined as {hostname}.\nService: active\nCommand: {PATH_BINARY}")
    };
    Ok(emit(
        CommandResult::new(
            "up",
            CommandState::Ready,
            success_message,
            json!({
                "server": origin,
                "hostname": hostname,
                "mode": "system",
                "key_fingerprint": fingerprint,
                "machine_key": short_key,
                "service": SERVICE_NAME,
                "status": "active",
                "path": PATH_BINARY,
                "host_firewall_service": host_firewall_service,
                "host_firewall_status": if host_firewall_service.is_some() { "active" } else { "unavailable" },
            }),
        )
        .with_body(success_body),
        json_output,
        Exit::Ok,
    ))
}

/// Parse the small administrator-rule list used by a fresh system installation.
#[cfg(all(
    target_os = "linux",
    any(feature = "plugin-mesh", feature = "plugin-server")
))]
fn parse_agent_host_firewall_rules(values: &[String]) -> Result<Vec<AllowRule>, String> {
    if values.len() > MAX_HOST_FIREWALL_RULES
        || values
            .iter()
            .any(|value| value.len() > MAX_HOST_FIREWALL_RULE_BYTES)
    {
        return Err("host firewall administrator rule list is too large".to_owned());
    }
    values
        .iter()
        .map(|value| {
            value
                .parse::<AllowRule>()
                .map_err(|_| "host firewall administrator rule is invalid".to_owned())
        })
        .collect()
}

/// Build the validated agent policy saved for the new system service.
///
/// An agent policy on its own renders the mesh-only, accept-policy table
/// ([`host_firewall::InputMode::for_roles`]), so it needs no admin rule.
#[cfg(all(
    target_os = "linux",
    any(feature = "plugin-mesh", feature = "plugin-server")
))]
fn agent_host_firewall_policy(values: &[String]) -> Result<Policy, String> {
    let admin_rules = parse_agent_host_firewall_rules(values)?;
    let policy = Policy {
        admin_rules,
        ..Policy::default()
    };
    host_firewall::validate_agent(&policy).map_err(|error| error.to_string())?;
    Ok(policy)
}

/// Record the administrator rules to save with the agent policy, before approval.
///
/// A machine joined with `up` gets no default-drop input policy (J555, #483),
/// so nothing here can lock anyone out and a local terminal needs no rule.
/// Over SSH, the session's sshd port is still recorded, from any source and
/// on any interface, so the saved policy would keep every administrator's
/// SSH path if a default drop is ever applied on top of it. Rejected: pinning
/// the installer's own address, which drops a second administrator or the same
/// one after their address changes.
#[cfg(all(
    target_os = "linux",
    any(feature = "plugin-mesh", feature = "plugin-server")
))]
fn agent_host_firewall_rules(
    values: &[String],
    ssh_connection: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut admin_rules = parse_agent_host_firewall_rules(values)?;
    if let Some(connection) = ssh_connection {
        let session = host_firewall::admin_rule_for_ssh_session(connection)
            .map_err(|_| "the active SSH path could not be read".to_owned())?;
        if !admin_rules.contains(&session) {
            admin_rules.push(session);
        }
    }
    if admin_rules.len() > MAX_HOST_FIREWALL_RULES {
        return Err("host firewall administrator rule list is too large".to_owned());
    }
    let policy = Policy {
        admin_rules,
        ..Policy::default()
    };
    host_firewall::validate_agent(&policy).map_err(|error| error.to_string())?;
    Ok(policy.admin_rules.iter().map(ToString::to_string).collect())
}

/// Run only the privileged half requested by `sudo`; all credentials arrive on stdin.
pub(crate) fn run_helper(server_input: &str, _json_output: bool) -> ExitCode {
    let result = run_helper_inner(server_input);
    if result == Err(Failure::InstallConflict) {
        println!("UP_PREFLIGHT_REFUSED");
    }
    let code = result.map_or_else(Failure::exit_code, |()| 0);
    println!("UP_RESULT={code}");
    ExitCode::from(code)
}

/// Validate private enrollment input and keep the local install under rollback until active.
fn run_helper_inner(server_input: &str) -> Result<(), Failure> {
    if nix::unistd::Uid::effective().as_raw() != 0 {
        return Err(Failure::Permission);
    }
    let server = server_url(server_input)?;
    let origin = server.origin().ascii_serialization();
    let handoff = read_handoff(&mut io::stdin().lock())?;
    #[cfg(all(
        target_os = "linux",
        any(feature = "plugin-mesh", feature = "plugin-server")
    ))]
    let agent_policy = match agent_host_firewall_policy(&handoff.admin_rules) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("infraternal up host firewall: {error}");
            return Err(Failure::HostFirewall);
        }
    };
    // Resolved again as root: the caller's check proves nothing to this process.
    // After the handoff is read (the caller's write must not fail on a closed
    // pipe) and before enrollment, so a refusal leaves no half-joined machine.
    #[cfg(target_os = "linux")]
    let systemctl =
        trusted_tool(&SYSTEMCTL_CANDIDATES, Failure::NoSystemd).map_err(|_| Failure::Failed)?;
    let mut invitation = ApprovedInvitation(
        serde_json::from_slice(&handoff.invitation).map_err(|_| Failure::Permission)?,
        #[cfg(all(target_os = "linux", feature = "plugin-ssh"))]
        false,
    );
    validate_invitation(&invitation.0, &origin, None, JoinMode::System)?;
    if crate::remote::key_digest_from_pkcs8(&handoff.key_pkcs8).ok() != Some(handoff.key_digest) {
        return Err(Failure::Permission);
    }
    #[cfg(target_os = "macos")]
    let host = invitation.0.host_id;
    invitation.wipe();
    #[cfg(target_os = "linux")]
    let accepted = install_preflight()?;
    #[cfg(target_os = "macos")]
    install_preflight()?;
    let join_url = format!("{origin}/remote/join");
    let (result, signal) = termination::scope(|cancelled| async move {
        let result = async {
            cancelled.check().map_err(|_| Failure::Failed)?;
            println!("UP_STAGE=installation");
            #[cfg(target_os = "linux")]
            let install = install::Install::begin_accepted(accepted, &systemctl);
            #[cfg(target_os = "macos")]
            let install = macos::Install::begin();
            let install = install
                .map_err(|error| {
                    eprintln!("{error}");
                    Failure::LocalState
                })?
                .interrupt_on(cancelled.flag());
            #[cfg(all(
                target_os = "linux",
                any(feature = "plugin-mesh", feature = "plugin-server")
            ))]
            let install = install
                .with_host_firewall_policy(agent_policy)
                .map_err(|error| {
                    eprintln!("{error}");
                    Failure::HostFirewall
                })?;
            // The Linux installer copies the binary while the server issues the
            // certificate: neither needs the other, and each takes a large part of
            // the time between the approval and the service start (#580).
            #[cfg(target_os = "linux")]
            let mut install = install;
            #[cfg(target_os = "linux")]
            let copy = {
                let pending = install
                    .stage_image(Path::new(RUNNING_IMAGE))
                    .map_err(|error| {
                        eprintln!("{error}");
                        Failure::LocalState
                    })?;
                tokio::task::spawn_blocking(move || pending.copy())
            };
            println!("UP_STAGE=enrollment");
            let joined = cancelled
                .during(crate::remote::join_with_key(
                    &join_url,
                    Path::new(SERVICE_DATA),
                    &handoff.invitation,
                    &handoff.key_pkcs8,
                ))
                .await;
            // Reap the local copy even after cancellation so rollback never races
            // a writer still holding the staging file.
            #[cfg(target_os = "linux")]
            let copied = copy.await;
            joined
                .map_err(|_| Failure::Failed)?
                .map_err(|error| map_remote_failure(&error))?;
            cancelled.check().map_err(|_| Failure::Failed)?;
            #[cfg(target_os = "linux")]
            let activation = copied
                .map_err(io::Error::other)
                .and_then(|image| install.activate_copied(image?));
            #[cfg(target_os = "macos")]
            let activation = env::current_exe().and_then(|image| install.activate(&image, host));
            activation.map_err(|error| {
                #[cfg(target_os = "macos")]
                eprintln!("{error}");
                #[cfg(not(target_os = "macos"))]
                let _ = error;
                Failure::Partial
            })
        }
        .await;
        (result, cancelled.received())
    })
    .map_err(|error| {
        eprintln!("{error}");
        Failure::Failed
    })?;
    if let Some(signal) = signal {
        // Sudo may have owned the foreground terminal. Preserve the install result and
        // terminate by the signal so the unprivileged caller also notices Ctrl-C.
        println!(
            "UP_RESULT={}",
            result.map_or_else(Failure::exit_code, |()| 0)
        );
        infraternal_shim::exit_by_signal(signal);
    }
    result
}

fn server_url(input: &str) -> Result<Url, Failure> {
    let server = Url::parse(input).map_err(|_| Failure::InvalidServer)?;
    if server.scheme() != "https"
        || server.host_str().is_none()
        || !server.username().is_empty()
        || server.password().is_some()
        || server.query().is_some()
        || server.fragment().is_some()
        || server.path() != "/"
    {
        return Err(Failure::InvalidServer);
    }
    Ok(server)
}

/// The kernel's host name, the one fact the owner reads on the approval page.
/// Not `$HOSTNAME`: shells keep it unexported, so every machine showed the
/// fallback name (#263, J134 P2-3).
fn local_hostname() -> String {
    let name = nix::unistd::gethostname()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    shown_hostname(&name)
}

/// Keep only the ASCII set the server accepts (`[A-Za-z0-9._-]`, at most 128).
fn shown_hostname(name: &str) -> String {
    let safe = name
        .chars()
        .take(128)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches(|character| character == '-' || character == '.')
        .to_owned();
    if safe.is_empty() {
        if cfg!(target_os = "macos") {
            "mac-host"
        } else {
            "linux-host"
        }
        .to_owned()
    } else {
        safe
    }
}

/// The device-approval request body for one fresh machine, built by the shared sign-in crate
/// from this join mode's wire text and execution uid.
fn machine_start_body(
    host_id: uuid::Uuid,
    hostname: &str,
    key_fingerprint: &str,
    join: JoinMode,
) -> Result<Vec<u8>, Failure> {
    infraternal_sign_in::machine_start_body(
        host_id,
        hostname,
        key_fingerprint,
        join.wire_mode(),
        join.invitation().1,
    )
    .map_err(|_| Failure::Failed)
}

/// The first sixteen fingerprint characters in groups of four, as the browser shows them.
fn machine_key_short(fingerprint: &str) -> Option<String> {
    let encoded = fingerprint.strip_prefix("SHA256:")?;
    if encoded.len() < 16 || !encoded.is_ascii() {
        return None;
    }
    let first = &encoded[..16];
    Some(
        first
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).ok())
            .collect::<Option<Vec<_>>>()?
            .join(" "),
    )
}

fn approval_qr(link: &str) -> Result<String, Failure> {
    let qr = QrCode::encode_text(link, QrCodeEcc::Low).map_err(|_| Failure::Failed)?;
    let size = qr.size();
    let mut rendered = String::new();
    for y in -4..size + 4 {
        for x in -4..size + 4 {
            let dark = x >= 0 && y >= 0 && x < size && y < size && qr.get_module(x, y);
            rendered.push_str(if dark { "##" } else { "  " });
        }
        rendered.push('\n');
    }
    Ok(rendered)
}

/// Whether the stream the approval code goes to (stderr under `--json`, else
/// stdout) is a terminal.
fn approval_display_is_terminal(json_output: bool) -> bool {
    if json_output {
        io::stderr().is_terminal()
    } else {
        io::stdout().is_terminal()
    }
}

/// D303 pending result for a run nobody can approve from: no key is prepared,
/// the server is not contacted, and no code exists to leak.
fn needs_terminal(origin: &str, json_output: bool) -> ExitCode {
    emit(
        CommandResult::new(
            "up",
            CommandState::Pending,
            "Approving this machine needs a terminal; no join was started.",
            json!({ "server": origin }),
        )
        .with_next_step(format!(
            "Run infraternal up {origin} in a terminal, then approve the code it shows with your passkey."
        )),
        json_output,
        Exit::NotAllowed,
    )
}

fn print_approval(
    json_output: bool,
    short_key: &str,
    user_code: &str,
    link: &str,
) -> Result<(), Failure> {
    let qr = approval_qr(link)?;
    if json_output {
        eprintln!("Open this link and approve this machine with your passkey:\n{link}");
        eprintln!("Code: {user_code}    Machine key: {short_key}");
        eprintln!("{qr}");
        eprintln!("Waiting for approval...");
        io::stderr().flush().map_err(|_| Failure::Runtime)?;
    } else {
        println!("Open this link and approve this machine with your passkey:\n{link}");
        println!("Code: {user_code}    Machine key: {short_key}");
        println!("{qr}");
        println!("Waiting for approval...");
        io::stdout().flush().map_err(|_| Failure::Runtime)?;
    }
    Ok(())
}

/// Start machine approval and check the server returned the expected capability shapes.
async fn start_approval(server: &Url, body: &[u8]) -> Result<DeviceApproval, Failure> {
    let response = post_json(server, "/auth/device-start", body, None, REQUEST_TIMEOUT).await?;
    if response.status != StatusCode::OK {
        return Err(map_http_status(response.status));
    }
    let approval = parse_start_response(&response.body).map_err(|_| Failure::Failed)?;
    // This command also insists the capabilities are canonical base64url, which is
    // stricter than the shared character-set check; keep that behaviour.
    if !capability_has_shape(&approval.poll_token, 43)
        || !capability_has_shape(&approval.user_code, 16)
    {
        return Err(Failure::Failed);
    }
    Ok(approval)
}

/// Redeem as soon as approval arrives and retain the old cadence on polling-only servers.
async fn wait_for_approval(
    server: &Url,
    approval: &DeviceApproval,
    host_id: uuid::Uuid,
    origin: &str,
    join: JoinMode,
    retirement_hint: Option<&str>,
) -> Result<ApprovedInvitation, Failure> {
    let deadline = Instant::now() + approval.lifetime;
    let body = Zeroizing::new(
        serde_json::to_vec(&DeviceRedeemRequest {
            token: &approval.poll_token,
        })
        .map_err(|_| Failure::Failed)?,
    );
    let mut next = Instant::now();
    loop {
        tokio::time::sleep_until(next.min(deadline)).await;
        let started = Instant::now();
        let remaining = deadline.saturating_duration_since(started);
        if remaining.is_zero() {
            return Err(Failure::Expired);
        }
        next = started + POLL_INTERVAL;
        // Older servers ignore Prefer and respond immediately; new servers
        // spend the same interval waiting, with the usual request I/O budget.
        let response = match post_json(
            server,
            "/auth/device-redeem",
            &body,
            Some(retirement_hint.unwrap_or("wait=10")),
            remaining.min(POLL_INTERVAL + REQUEST_TIMEOUT),
        )
        .await
        {
            Ok(response) => response,
            Err(Failure::Unreachable) => continue,
            Err(failure) => return Err(failure),
        };
        match response.status {
            StatusCode::OK => {
                let invitation = ApprovedInvitation(
                    serde_json::from_slice(&response.body).map_err(|_| Failure::Failed)?,
                    #[cfg(all(target_os = "linux", feature = "plugin-ssh"))]
                    response.retirement_authorized,
                );
                validate_invitation(&invitation.0, origin, Some(host_id), join)?;
                return Ok(invitation);
            }
            StatusCode::UNAUTHORIZED => {}
            StatusCode::TOO_MANY_REQUESTS => {
                let delay = response
                    .retry_after
                    .unwrap_or(POLL_INTERVAL)
                    .max(Duration::from_secs(1))
                    .min(remaining);
                next = Instant::now() + delay;
            }
            status if status.is_server_error() => {}
            status => return Err(map_http_status(status)),
        }
    }
}

/// Apply the caller's timeout to the shared, bounded JSON transport.
async fn post_json(
    server: &Url,
    path: &'static str,
    body: &[u8],
    preference: Option<&str>,
    timeout: Duration,
) -> Result<crate::remote::ClientResponse, Failure> {
    let mut request_started = false;
    match tokio::time::timeout(
        timeout,
        crate::remote::post_json(
            server,
            path,
            bytes::Bytes::copy_from_slice(body),
            None,
            MAX_RESPONSE_BYTES,
            &mut request_started,
            preference,
        ),
    )
    .await
    {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) | Err(_) => Err(Failure::Unreachable),
    }
}

fn map_http_status(status: StatusCode) -> Failure {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Failure::Permission,
        StatusCode::NOT_FOUND => Failure::Unsupported,
        StatusCode::TOO_MANY_REQUESTS => Failure::Throttled,
        status if status.is_server_error() => Failure::Unreachable,
        _ => Failure::Failed,
    }
}

/// Check an approved invitation before anything is installed: a well-formed token, this
/// server's origin, the join mode and execution uid that were requested, and (when known)
/// the host id this run asked for.
fn validate_invitation(
    invitation: &JoinInvitation,
    origin: &str,
    host_id: Option<uuid::Uuid>,
    join: JoinMode,
) -> Result<(), Failure> {
    let token_ok = capability_has_shape(&invitation.token, 43);
    let (mode, execution_uid) = join.invitation();
    if !token_ok
        || invitation.public_origin != origin
        || invitation.mode != mode
        || invitation.execution_uid != execution_uid
        || host_id.is_some_and(|expected| invitation.host_id != expected)
    {
        return Err(Failure::Permission);
    }
    Ok(())
}

fn capability_has_shape(value: &str, length: usize) -> bool {
    value.len() == length
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|decoded| URL_SAFE_NO_PAD.encode(decoded) == value)
}

fn encode_handoff(
    invitation: &JoinInvitation,
    key_pkcs8: &[u8],
    key_digest: &[u8; 32],
    admin_rules: &[String],
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let invitation = Zeroizing::new(serde_json::to_vec(invitation).map_err(|_| Failure::Failed)?);
    let admin_rules = Zeroizing::new(serde_json::to_vec(admin_rules).map_err(|_| Failure::Failed)?);
    if invitation.is_empty()
        || invitation.len() > MAX_INVITATION_BYTES
        || key_pkcs8.is_empty()
        || key_pkcs8.len() > MAX_KEY_BYTES
        || admin_rules.len() > MAX_HOST_FIREWALL_RULES * (MAX_HOST_FIREWALL_RULE_BYTES + 3)
    {
        return Err(Failure::Failed);
    }
    let invitation_len = u32::try_from(invitation.len()).map_err(|_| Failure::Failed)?;
    let key_len = u32::try_from(key_pkcs8.len()).map_err(|_| Failure::Failed)?;
    let admin_rules_len = u32::try_from(admin_rules.len()).map_err(|_| Failure::Failed)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(
        16 + invitation.len() + key_pkcs8.len() + key_digest.len() + admin_rules.len(),
    ));
    payload.extend_from_slice(b"UPJ2");
    payload.extend_from_slice(&invitation_len.to_be_bytes());
    payload.extend_from_slice(&invitation);
    payload.extend_from_slice(&key_len.to_be_bytes());
    payload.extend_from_slice(key_pkcs8);
    payload.extend_from_slice(key_digest);
    payload.extend_from_slice(&admin_rules_len.to_be_bytes());
    payload.extend_from_slice(&admin_rules);
    if payload.len() > MAX_HANDOFF_BYTES {
        return Err(Failure::Failed);
    }
    Ok(payload)
}

/// Read a bounded root-helper payload and reject truncated or trailing fields.
fn read_handoff(reader: &mut impl Read) -> Result<Handoff, Failure> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_HANDOFF_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Permission)?;
    if bytes.len() > MAX_HANDOFF_BYTES || bytes.get(..4) != Some(&b"UPJ2"[..]) {
        return Err(Failure::Permission);
    }
    let mut offset = 4;
    let invitation_len = take_u32(&bytes, &mut offset)?;
    if invitation_len == 0 || invitation_len > MAX_INVITATION_BYTES {
        return Err(Failure::Permission);
    }
    let invitation = take_bytes(&bytes, &mut offset, invitation_len)?;
    let key_len = take_u32(&bytes, &mut offset)?;
    if key_len == 0 || key_len > MAX_KEY_BYTES {
        return Err(Failure::Permission);
    }
    let key_pkcs8 = take_bytes(&bytes, &mut offset, key_len)?;
    let digest_end = offset.checked_add(32).ok_or(Failure::Permission)?;
    let key_digest = bytes
        .get(offset..digest_end)
        .ok_or(Failure::Permission)?
        .try_into()
        .map_err(|_| Failure::Permission)?;
    offset = digest_end;
    let admin_rules_len = take_u32(&bytes, &mut offset)?;
    if admin_rules_len > MAX_HOST_FIREWALL_RULES * (MAX_HOST_FIREWALL_RULE_BYTES + 3) {
        return Err(Failure::Permission);
    }
    let admin_rules_bytes = take_bytes(&bytes, &mut offset, admin_rules_len)?;
    if offset != bytes.len() {
        return Err(Failure::Permission);
    }
    let admin_rules: Vec<String> =
        serde_json::from_slice(&admin_rules_bytes).map_err(|_| Failure::Permission)?;
    if admin_rules.len() > MAX_HOST_FIREWALL_RULES
        || admin_rules
            .iter()
            .any(|rule| rule.len() > MAX_HOST_FIREWALL_RULE_BYTES)
    {
        return Err(Failure::Permission);
    }
    Ok(Handoff {
        invitation,
        key_pkcs8,
        key_digest,
        admin_rules,
    })
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<usize, Failure> {
    let end = offset.checked_add(4).ok_or(Failure::Permission)?;
    let value: [u8; 4] = bytes
        .get(*offset..end)
        .ok_or(Failure::Permission)?
        .try_into()
        .map_err(|_| Failure::Permission)?;
    *offset = end;
    usize::try_from(u32::from_be_bytes(value)).map_err(|_| Failure::Permission)
}

/// Read `length` bytes from `bytes` starting at `offset` into a zeroizing buffer.
fn take_bytes(
    bytes: &[u8],
    offset: &mut usize,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let end = offset.checked_add(length).ok_or(Failure::Permission)?;
    let value = bytes.get(*offset..end).ok_or(Failure::Permission)?;
    *offset = end;
    Ok(Zeroizing::new(value.to_vec()))
}

/// Select the elevation explanation matching what this platform's `up` actually installs.
const fn system_elevation_prompt() -> ElevationPrompt {
    #[cfg(all(
        target_os = "linux",
        any(feature = "plugin-mesh", feature = "plugin-server")
    ))]
    {
        ElevationPrompt::LinuxSystemInstall {
            host_firewall: true,
        }
    }
    #[cfg(all(
        target_os = "linux",
        not(any(feature = "plugin-mesh", feature = "plugin-server"))
    ))]
    {
        ElevationPrompt::LinuxSystemInstall {
            host_firewall: false,
        }
    }
    #[cfg(target_os = "macos")]
    {
        ElevationPrompt::MacosSystemInstall
    }
}

/// The one sudo invocation: a root-owned sudo runs this binary's hidden helper.
fn sudo_command(executable: &Path, server: &str, json_output: bool) -> Result<Command, Failure> {
    let mut command = Command::new(trusted_tool(&SUDO_CANDIDATES, Failure::SudoUnavailable)?);
    command
        .arg("--")
        .arg(executable)
        .arg("__up-system")
        .arg(server);
    if json_output {
        command.arg("--json");
    }
    Ok(command)
}

/// The first of `candidates` that exists, if only root can replace it.
/// `missing` is the failure when none exists.
fn trusted_tool(candidates: &[&str], missing: Failure) -> Result<PathBuf, Failure> {
    trusted_program(candidates, 0).map_err(|error| match error {
        ToolError::Missing => missing,
        ToolError::Untrusted => Failure::UntrustedTool,
    })
}

/// Send enrollment input privately and preserve local preflight refusals from the helper.
async fn invoke_sudo(
    command: Command,
    payload: &[u8],
    json_output: bool,
    cancelled: &Cancellation,
) -> Result<(), Failure> {
    if cancelled.received().is_some() {
        eprintln!("No system service was installed.");
        return Err(Failure::Failed);
    }
    system_elevation_prompt().print_to_stderr(json_output);
    let mut child = tokio::process::Command::from(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| Failure::SudoUnavailable)?;
    let mut stdin = child.stdin.take().ok_or(Failure::Runtime)?;
    let mut stdout = child.stdout.take().ok_or(Failure::Runtime)?;
    let mut output = Vec::new();
    let (status, sent, read) = tokio::join!(
        cancelled.wait_for_child(&mut child),
        async move { cancelled.during(stdin.write_all(payload)).await },
        stdout.read_to_end(&mut output),
    );
    let status = status.map_err(|_| Failure::Partial)?;
    read.map_err(|_| Failure::Partial)?;
    if output
        .split(|byte| *byte == b'\n')
        .any(|line| line == b"UP_PREFLIGHT_REFUSED")
    {
        return Err(Failure::InstallConflict);
    }
    let installation_started = output
        .split(|byte| *byte == b'\n')
        .any(|line| line == b"UP_STAGE=installation");
    if let Some(code) = parse_result_marker(&output) {
        if code == 0 {
            return Ok(());
        }
        if !installation_started {
            eprintln!("No system service was installed.");
        }
        return Err(Failure::from_code(code).unwrap_or(Failure::Partial));
    }
    if installation_started {
        eprintln!(
            "The system installer did not confirm cleanup. Check the local installation before retrying."
        );
    } else {
        eprintln!("No system service was installed.");
    }
    if status.code() == Some(1) && sent.is_ok() {
        Err(Failure::SudoDenied)
    } else {
        Err(Failure::Partial)
    }
}

fn parse_result_marker(output: &[u8]) -> Option<u8> {
    std::str::from_utf8(output)
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("UP_RESULT=")?.parse().ok())
}

/// Check the host before approval and repeat as root before installing anything.
/// Refuse a host that cannot take a fresh installation, before anything asks
/// for an approval or writes. The result lets the Linux installer start without
/// repeating the pass it just made.
fn install_preflight() -> Result<Preflighted, Failure> {
    #[cfg(target_os = "linux")]
    let system = install::preflight(Path::new("/"), 0);
    #[cfg(target_os = "macos")]
    let system = macos::preflight();
    let result = system.and_then(|accepted| {
        if let Ok(data) = crate::remote::default_data() {
            match fs::symlink_metadata(data.join("identity.json")) {
                Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "An infraternal agent identity already exists for this user. Manage that installation instead of running infraternal up.")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
        }
        Ok(accepted)
    });
    result.map_err(|error| {
        eprintln!("{error}");
        Failure::InstallConflict
    })
}

/// What a passed [`install_preflight`] hands the installer: on Linux the proof
/// it can start from, on a Mac nothing.
#[cfg(target_os = "linux")]
type Preflighted = install::Accepted;
/// See the Linux definition; the Mac installer repeats its own cheap checks.
#[cfg(target_os = "macos")]
type Preflighted = ();

/// Exercise the same transaction as enrollment without contacting a server.
#[cfg(all(test, target_os = "linux"))]
fn install_system_service(
    root: &Path,
    source: &Path,
    systemctl: &Path,
    expected_uid: u32,
) -> io::Result<()> {
    if nix::unistd::Uid::effective().as_raw() != expected_uid {
        return Err(permission_error());
    }
    install::Install::begin(root, expected_uid, systemctl)?.activate(source)
}

/// Check directory ownership and replacement permissions without changing its mode.
fn check_directory(metadata: &fs::Metadata, owner: u32) -> io::Result<()> {
    if !metadata.is_dir() || metadata.uid() != owner || metadata.permissions().mode() & 0o022 != 0 {
        return Err(permission_error());
    }
    Ok(())
}

/// SHA-256 of everything `input` yields, copying it to `output` on the way.
fn hash_stream(input: &mut impl Read, mut output: Option<&mut fs::File>) -> io::Result<[u8; 32]> {
    let mut hasher = openssl::sha::Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = match input.read(&mut buffer) {
            Ok(0) => return Ok(hasher.finish()),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hasher.update(&buffer[..read]);
        if let Some(output) = output.as_deref_mut() {
            output.write_all(&buffer[..read])?;
        }
    }
}

/// Render the single system service installed by a fresh machine join.
///
/// `ExecStartPre` relabels the binary `bin_t` before every start (#401).
/// Install labels it once, but a later `restorecon` or full relabel puts it
/// back to `/var/lib`'s `var_lib_t`, which systemd refuses with `203/EXEC`
/// before the agent could heal itself. `+` runs the step as root, `-` means it
/// can never fail the unit, and the selinuxfs check makes it a no-op where
/// `SELinux` is absent or disabled. The SSH installer's root unit carries the
/// same step.
#[cfg(target_os = "linux")]
fn systemd_unit() -> String {
    format!(
        "[Unit]\nDescription=Infraternal machine service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStartPre=-+/bin/sh -c \"[ ! -e /sys/fs/selinux/enforce ] || chcon -t bin_t {SERVICE_BINARY}\"\nExecStart={SERVICE_BINARY} agent run --data {SERVICE_DATA}\nRestart=on-failure\nRestartSec=2\nKillMode=process\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

/// Render the agent's root firewall unit so its saved input rules load before network setup.
#[cfg(all(
    target_os = "linux",
    any(feature = "plugin-mesh", feature = "plugin-server")
))]
fn host_firewall_systemd_unit() -> String {
    format!(
        "{}\n[Unit]\nDescription=infraternal host input firewall\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nExecStart={SERVICE_BINARY} __host-firewall-apply\nRemainAfterExit=yes\n\n[Install]\nWantedBy=network-pre.target\n",
        host_firewall::HOST_FIREWALL_UNIT_MARKER
    )
}

/// Run a trusted service manager with a fixed environment and optional output check.
#[cfg(target_os = "linux")]
fn run_systemctl(
    systemctl: &Path,
    arguments: &[&str],
    expected_output: Option<&str>,
) -> io::Result<()> {
    // Root runs systemctl with a fixed environment, not whatever sudo kept.
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(systemctl);
    if !matches!(arguments.first().copied(), Some("is-active" | "show")) {
        // A manager write must finish before the installer can revert it.
        command.process_group(0);
    }
    let output = command
        .args(arguments)
        .env_clear()
        .env("PATH", HELPER_PATH)
        .output()?;
    if !output.status.success()
        || expected_output.is_some_and(|expected| {
            std::str::from_utf8(&output.stdout).ok().map(str::trim) != Some(expected)
        })
    {
        return Err(permission_error());
    }
    Ok(())
}

fn permission_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "system install refused")
}

/// Map remote setup errors to the operator-facing install outcomes.
fn map_remote_failure(error: &io::Error) -> Failure {
    match crate::remote::Failure::of(error) {
        None => Failure::LocalState,
        Some(
            crate::remote::Failure::Dns(_)
            | crate::remote::Failure::Connect
            | crate::remote::Failure::Tls
            | crate::remote::Failure::Upgrade
            | crate::remote::Failure::AgentLink,
        ) => Failure::Unreachable,
        Some(
            crate::remote::Failure::Refused
            | crate::remote::Failure::IdentityMismatch
            | crate::remote::Failure::SharedFile,
        ) => Failure::Permission,
    }
}

fn fail(json_output: bool, failure: Failure) -> ExitCode {
    if json_output {
        emit(
            CommandResult::new("up", failure.state(), failure.message(), json!({})),
            true,
            failure.exit(),
        )
    } else {
        eprintln!("{}", failure.message());
        ExitCode::from(failure.exit_code())
    }
}

/// Local enrollment, privilege, and transactional installation regressions.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        Failure, JoinInvitation, Mode, SUDO_CANDIDATES, ToolError, approval_qr, encode_handoff,
        install_system_service, invoke_sudo, machine_key_short, map_remote_failure, read_handoff,
        sudo_command, trusted_program,
    };
    use crate::cli::output::Exit;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };

    /// Child half of `the_machine_name_comes_from_the_kernel_not_the_environment`.
    #[test]
    #[ignore = "run only as a child process with a chosen environment"]
    fn print_local_hostname() {
        // On its own line: libtest prints the test name before the output.
        println!("\nLOCAL_HOSTNAME={}", super::local_hostname());
    }

    #[test]
    fn the_machine_name_comes_from_the_kernel_not_the_environment() {
        // J134 P2-3: shells do not export HOSTNAME, so it is usually unset.
        let kernel = fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
        let expected = super::shown_hostname(kernel.trim());
        assert_ne!(expected, "linux-host");
        for decoy in [None, Some("decoy-from-environment")] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child.args([
                "--exact",
                "up::tests::print_local_hostname",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ]);
            match decoy {
                None => child.env_remove("HOSTNAME"),
                Some(value) => child.env("HOSTNAME", value),
            };
            let output = child.output().unwrap();
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout).unwrap();
            let shown = stdout
                .lines()
                .find_map(|line| line.strip_prefix("LOCAL_HOSTNAME="))
                .unwrap_or_else(|| panic!("no LOCAL_HOSTNAME line in {stdout:?}"));
            assert_eq!(shown, expected, "HOSTNAME={decoy:?}");
        }
        assert_eq!(super::shown_hostname("a\u{202e}b c"), "a-b-c");
    }

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory(std::path::PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "infraternal-up-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn approval_qr_renders_a_square_matrix_with_a_four_module_quiet_zone() {
        let link = "https://mesh.example.org/#join=AbCdEfGhIjKlMnOp";
        let rendered = approval_qr(link).unwrap();
        let rows = rendered.lines().collect::<Vec<_>>();
        let quiet_zone = " ".repeat(8);

        assert_eq!(rows.len(), 37);
        assert!(rows.iter().all(|row| row.len() == 74));
        assert_eq!(rows.first(), Some(&" ".repeat(74).as_str()));
        assert_eq!(rows.last(), Some(&" ".repeat(74).as_str()));
        assert!(
            rows.iter()
                .all(|row| { row.starts_with(&quiet_zone) && row.ends_with(&quiet_zone) })
        );
    }

    /// The browser key label groups the first sixteen fingerprint characters.
    #[test]
    fn browser_key_label_groups_the_first_sixteen_fingerprint_characters() {
        assert_eq!(
            machine_key_short("SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCde"),
            Some("AbCd EfGh IjKl MnOp".to_owned())
        );
    }

    #[test]
    fn one_sudo_command_runs_the_hidden_system_enrollment_helper() {
        let Ok(command) = sudo_command(
            Path::new("/home/user/bin/infraternal"),
            "https://mesh.example.org",
            false,
        ) else {
            // A host without a root-owned sudo refuses before any approval.
            assert_eq!(
                trusted_program(&SUDO_CANDIDATES, 0),
                Err(ToolError::Missing)
            );
            return;
        };
        // Never a PATH lookup: the trusted, canonical sudo file itself.
        assert!(Path::new(command.get_program()).is_absolute());
        assert_eq!(
            Ok(Path::new(command.get_program()).to_path_buf()),
            trusted_program(&SUDO_CANDIDATES, 0)
        );
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("--"),
                std::ffi::OsStr::new("/home/user/bin/infraternal"),
                std::ffi::OsStr::new("__up-system"),
                std::ffi::OsStr::new("https://mesh.example.org"),
            ]
        );
    }

    /// The test account, which stands in for root as the trusted owner.
    fn me() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    /// Both public names must reach the installed system image.
    #[test]
    fn system_install_copies_the_running_binary_links_path_and_enables_one_unit() {
        let temporary = TemporaryDirectory::new();
        let source = temporary.0.join("running-infraternal");
        let systemctl = temporary.0.join("systemctl");
        let calls = temporary.0.join("systemctl-calls");
        fs::write(&source, b"running version bytes").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        crate::test_executable::write(
            &systemctl,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n[ \"$1\" != is-active ] || echo active\n",
                calls.display()
            ),
            0o755,
        );

        install_system_service(
            &temporary.0,
            &source,
            &systemctl,
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap();

        let binary = temporary.0.join("var/lib/infraternal/bin/infraternal");
        let link = temporary.0.join("usr/local/bin/infraternal");
        let unit = temporary
            .0
            .join("etc/systemd/system/infraternal-agent.service");
        assert_eq!(fs::read(&binary).unwrap(), b"running version bytes");
        assert_eq!(
            fs::read_link(&link).unwrap(),
            Path::new("/var/lib/infraternal/bin/infraternal")
        );
        assert_eq!(
            fs::read_link(link.with_file_name("infra")).unwrap(),
            Path::new("infraternal")
        );
        let unit_text = fs::read_to_string(unit).unwrap();
        assert!(unit_text.contains("ExecStart=/var/lib/infraternal/bin/infraternal agent run"));
        assert!(unit_text.contains("--data /var/lib/infraternal/agent"));
        assert_eq!(
            fs::read_to_string(calls).unwrap(),
            "daemon-reload\nenable --now infraternal-agent.service\nis-active infraternal-agent.service\n"
        );
    }

    /// A late service failure retires only the alias inode created by this attempt.
    #[test]
    fn rollback_after_alias_creation_preserves_preexisting_aliases() {
        for kind in ["absent", "file", "directory", "foreign-link", "owned-link"] {
            let temporary = TemporaryDirectory::new();
            let commands = temporary.0.join("usr/local/bin");
            fs::create_dir_all(&commands).unwrap();
            let alias = commands.join("infra");
            match kind {
                "file" => fs::write(&alias, b"foreign infra").unwrap(),
                "directory" => fs::create_dir(&alias).unwrap(),
                "foreign-link" => std::os::unix::fs::symlink("foreign-command", &alias).unwrap(),
                "owned-link" => std::os::unix::fs::symlink("infraternal", &alias).unwrap(),
                _ => {}
            }
            let before = fs::symlink_metadata(&alias).ok();
            let source = temporary.0.join("source");
            fs::write(&source, b"binary").unwrap();
            let systemctl = temporary.0.join("systemctl");
            let reached = temporary.0.join("activation-reached");
            fs::write(
                &systemctl,
                format!(
                    "#!/bin/sh\n[ \"$1\" != stop ] || exit 0\n[ -e '{}' ] || [ -L '{}' ] || exit 2\nprintf reached > '{}'\nexit 1\n",
                    alias.display(), alias.display(), reached.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(install_system_service(&temporary.0, &source, &systemctl, me()).is_err());
            assert_eq!(fs::read(&reached).unwrap(), b"reached", "{kind}");
            match before {
                None => assert!(
                    alias.symlink_metadata().is_err(),
                    "new infra survived rollback"
                ),
                Some(before) => {
                    use std::os::unix::fs::MetadataExt;
                    let after = fs::symlink_metadata(&alias).unwrap();
                    assert_eq!(
                        (after.dev(), after.ino()),
                        (before.dev(), before.ino()),
                        "{kind}"
                    );
                    match kind {
                        "file" => assert_eq!(fs::read(&alias).unwrap(), b"foreign infra"),
                        "directory" => assert_eq!(fs::read_dir(&alias).unwrap().count(), 0),
                        "foreign-link" => {
                            assert_eq!(
                                fs::read_link(&alias).unwrap(),
                                Path::new("foreign-command")
                            );
                        }
                        "owned-link" => {
                            assert_eq!(fs::read_link(&alias).unwrap(), Path::new("infraternal"));
                        }
                        _ => unreachable!(),
                    }
                }
            }
            assert!(!temporary.0.join("var").exists(), "{kind}");
            assert!(!temporary.0.join("etc").exists(), "{kind}");
            assert!(!commands.join("infraternal").exists(), "{kind}");
        }
    }

    /// A fresh install exposes its CLI while keeping enrollment state private.
    #[test]
    fn the_path_command_is_reachable_by_other_users_while_state_stays_private() {
        // A fresh layout must remain traversable even with a private umask.
        let temporary = TemporaryDirectory::new();
        let source = temporary.0.join("running-infraternal");
        let systemctl = temporary.0.join("systemctl");
        fs::write(&source, b"binary").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        crate::test_executable::write(
            &systemctl,
            "#!/bin/sh\n[ \"$1\" != is-active ] || echo active\n",
            0o755,
        );
        let base = temporary.0.join("var/lib/infraternal");

        install_system_service(
            &temporary.0,
            &source,
            &systemctl,
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&base), 0o711, "others must pass through, not list");
        assert_eq!(mode(&base.join("bin")), 0o755);
        assert_eq!(mode(&base.join("bin/infraternal")), 0o755);
        assert_eq!(mode(&base.join("agent")), 0o700, "state stays private");
    }

    #[test]
    fn root_installs_the_running_image_byte_for_byte() {
        // J134 P3-4: the helper copies /proc/self/exe, not a path.
        let temporary = TemporaryDirectory::new();
        let systemctl = temporary.0.join("systemctl");
        crate::test_executable::write(
            &systemctl,
            "#!/bin/sh\n[ \"$1\" != is-active ] || echo active\n",
            0o755,
        );

        install_system_service(
            &temporary.0,
            Path::new(super::RUNNING_IMAGE),
            &systemctl,
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap();

        let installed = fs::read(temporary.0.join("var/lib/infraternal/bin/infraternal")).unwrap();
        let running = fs::read(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(
            openssl::sha::sha256(&installed),
            openssl::sha::sha256(&running),
            "installed binary is not the running test binary"
        );
        assert_eq!(super::RUNNING_IMAGE, "/proc/self/exe");
    }

    #[test]
    fn system_install_refuses_to_replace_a_different_path_command() {
        let temporary = TemporaryDirectory::new();
        let source = temporary.0.join("running-infraternal");
        let systemctl = temporary.0.join("systemctl");
        fs::write(&source, b"binary").unwrap();
        crate::test_executable::write(&systemctl, "#!/bin/sh\nexit 0\n", 0o755);
        let bin_dir = temporary.0.join("usr/local/bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("infraternal"), b"another command").unwrap();

        assert!(
            install_system_service(
                &temporary.0,
                &source,
                &systemctl,
                nix::unistd::geteuid().as_raw()
            )
            .is_err()
        );
    }

    /// A foreign command is refused before any data or service directories are created.
    #[test]
    fn foreign_cli_preflight_is_read_only() {
        let temporary = TemporaryDirectory::new();
        let path = temporary.0.join("usr/local/bin");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("infraternal"), b"foreign").unwrap();
        let source = temporary.0.join("source");
        fs::write(&source, b"binary").unwrap();
        assert!(
            install_system_service(&temporary.0, &source, Path::new("/bin/false"), me()).is_err()
        );
        assert!(!temporary.0.join("var").exists());
        assert!(!temporary.0.join("etc").exists());
        assert_eq!(fs::read(path.join("infraternal")).unwrap(), b"foreign");
    }

    /// Existing machine enrollment belongs to its original install even if startup failed.
    #[test]
    fn existing_machine_preflight_is_read_only() {
        let temporary = TemporaryDirectory::new();
        let base = temporary.0.join("var/lib/infraternal");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(base.join("agent"))
            .unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(base.join("agent/keep"), b"existing enrollment").unwrap();
        let source = temporary.0.join("source");
        fs::write(&source, b"binary").unwrap();
        assert!(
            install_system_service(&temporary.0, &source, Path::new("/bin/false"), me()).is_err()
        );
        assert_eq!(
            fs::metadata(&base).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!base.join("bin").exists());
        assert!(!temporary.0.join("usr").exists());
        assert_eq!(
            fs::read(base.join("agent/keep")).unwrap(),
            b"existing enrollment"
        );
    }

    /// An installed server with a custom data directory is still a server host.
    #[test]
    fn installed_server_preflight_is_read_only() {
        let temporary = TemporaryDirectory::new();
        let units = temporary.0.join("etc/systemd/system");
        fs::create_dir_all(&units).unwrap();
        let contents = b"[Service]\nExecStart=/opt/infraternal server --data /srv/private\n";
        fs::write(units.join("custom-infraternal.service"), contents).unwrap();
        let source = temporary.0.join("source");
        fs::write(&source, b"binary").unwrap();
        assert!(
            install_system_service(&temporary.0, &source, Path::new("/bin/false"), me()).is_err()
        );
        assert!(!temporary.0.join("var").exists());
        assert_eq!(
            fs::read(units.join("custom-infraternal.service")).unwrap(),
            contents
        );
    }

    /// A refusal on a server host must preserve its private data byte for byte.
    #[test]
    fn server_preflight_preserves_modes_and_contents() {
        let temporary = TemporaryDirectory::new();
        let base = temporary.0.join("var/lib/infraternal");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&base)
            .unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(base.join("infraternal.sqlite"), b"server data").unwrap();
        let path = temporary.0.join("usr/local/bin");
        fs::create_dir_all(&path).unwrap();
        std::os::unix::fs::symlink("/opt/infraternal/server", path.join("infraternal")).unwrap();
        let source = temporary.0.join("source");
        fs::write(&source, b"binary").unwrap();
        println!(
            "fake server before: mode={:o} entries={}",
            fs::metadata(&base).unwrap().permissions().mode() & 0o777,
            fs::read_dir(&base).unwrap().count()
        );
        assert!(
            install_system_service(&temporary.0, &source, Path::new("/bin/false"), me()).is_err()
        );
        assert_eq!(
            fs::metadata(&base).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::read_dir(&base).unwrap().count(), 1);
        assert_eq!(
            fs::read(base.join("infraternal.sqlite")).unwrap(),
            b"server data"
        );
        assert_eq!(
            fs::read_link(path.join("infraternal")).unwrap(),
            Path::new("/opt/infraternal/server")
        );
        println!(
            "fake server after: mode={:o} entries={} contents=unchanged cli_link=unchanged",
            fs::metadata(&base).unwrap().permissions().mode() & 0o777,
            fs::read_dir(&base).unwrap().count()
        );
    }

    /// Unwinding during enrollment preserves a pre-existing base and the CLI link.
    #[test]
    fn enrollment_unwind_preserves_existing_paths() {
        let temporary = TemporaryDirectory::new();
        let base = temporary.0.join("var/lib/infraternal");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&base)
            .unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o711)).unwrap();
        let commands = temporary.0.join("usr/local/bin");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&commands)
            .unwrap();
        let link = commands.join("infraternal");
        std::os::unix::fs::symlink(super::SERVICE_BINARY, &link).unwrap();
        let before = fs::symlink_metadata(&link).unwrap();
        let unwind = std::panic::catch_unwind(|| {
            let _install =
                super::install::Install::begin(&temporary.0, me(), Path::new("/bin/false"))
                    .unwrap();
            fs::write(base.join("agent/partial-join"), b"fixture enrollment").unwrap();
            panic!("fixture enrollment failed");
        });
        assert!(unwind.is_err());
        assert_eq!(
            fs::metadata(&base).unwrap().permissions().mode() & 0o777,
            0o711
        );
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
        assert_eq!(
            fs::read_link(&link).unwrap(),
            Path::new(super::SERVICE_BINARY)
        );
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&fs::symlink_metadata(&link).unwrap()),
            std::os::unix::fs::MetadataExt::ino(&before)
        );
    }

    /// A service-start failure removes install paths and retains only the empty private lock journal.
    #[test]
    fn failed_install_rolls_back_new_paths() {
        let temporary = TemporaryDirectory::new();
        let source = temporary.0.join("source");
        fs::write(&source, b"binary").unwrap();
        fs::write(temporary.0.join("keep"), b"existing").unwrap();
        let manager = temporary.0.join("systemctl");
        crate::test_executable::write(&manager, "#!/bin/sh\n[ \"$1\" != is-active ]\n", 0o755);
        assert!(install_system_service(&temporary.0, &source, &manager, me()).is_err());
        let mut names = fs::read_dir(&temporary.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [".infraternal-up.journal", "keep", "source", "systemctl"]
        );
        let journal = temporary.0.join(".infraternal-up.journal");
        assert_eq!(fs::read(&journal).unwrap(), Vec::<u8>::new());
        assert_eq!(
            fs::metadata(journal).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(fs::read(temporary.0.join("keep")).unwrap(), b"existing");
    }

    #[test]
    fn up_failures_use_the_d303_exit_codes() {
        assert_eq!(Failure::InvalidServer.exit_code(), 2);
        assert_eq!(Failure::Permission.exit_code(), 3);
        assert_eq!(Failure::Expired.exit_code(), 3);
        assert_eq!(Failure::Unreachable.exit_code(), 5);
        assert_eq!(Failure::Partial.exit_code(), 6);
    }

    #[test]
    fn an_unclassified_local_join_error_is_not_reported_as_server_refusal() {
        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "local data");
        let failure = map_remote_failure(&error);

        assert_eq!(failure.exit(), Exit::Failed);
        assert!(failure.message().contains("local"));
    }

    /// A missing sudo executable reports which local dependency is unavailable.
    #[test]
    fn missing_sudo_has_a_local_not_found_cause() {
        let temporary = TemporaryDirectory::new();
        let command = std::process::Command::new(temporary.0.join("missing-sudo"));

        let failure = super::termination::scope(|cancelled| async move {
            invoke_sudo(command, b"", false, &cancelled)
                .await
                .unwrap_err()
        })
        .unwrap();

        assert_eq!(failure.exit(), Exit::NotFound);
        assert!(failure.message().contains("sudo"));
    }

    /// A sudo refusal stays a local permission error even if the child never reads stdin.
    #[test]
    fn sudo_denial_has_a_local_permission_cause() {
        let temporary = TemporaryDirectory::new();
        let sudo = temporary.0.join("sudo");
        crate::test_executable::write(&sudo, "#!/bin/sh\nexit 1\n", 0o755);
        let command = std::process::Command::new(sudo);

        let failure = super::termination::scope(|cancelled| async move {
            invoke_sudo(command, b"", false, &cancelled)
                .await
                .unwrap_err()
        })
        .unwrap();

        assert_eq!(failure.exit(), Exit::NotAllowed);
        assert!(failure.message().contains("sudo"));
    }

    /// Run the system elevation boundary with the test's sudo fixture and real signal handlers.
    #[test]
    #[ignore = "run only in the password-prompt test's private terminal"]
    fn sudo_password_prompt_child() {
        let fixture = std::env::var_os("INFRATERNAL_TEST_SUDO_FIXTURE").unwrap();
        let mut sudo = std::process::Command::new(Path::new(&fixture).join("sudo"));
        sudo.current_dir(fixture);
        // End libtest's status line before the CLI emits its JSON envelope.
        println!();
        super::with_cancellation(
            |cancelled| async move {
                invoke_sudo(sudo, b"", true, &cancelled).await?;
                Ok(std::process::ExitCode::SUCCESS)
            },
            true,
        );
    }

    /// Ctrl-C at the password prompt leaves the system installation baseline intact.
    #[test]
    fn ctrl_c_at_sudo_password_prompt_leaves_a_clean_baseline() {
        use nix::{
            poll::{PollFd, PollFlags, poll},
            pty::openpty,
        };
        use std::{
            io::{Read, Write},
            os::{fd::AsFd, unix::process::ExitStatusExt},
            process::{Command, Stdio},
        };

        let temporary = TemporaryDirectory::new();
        fs::write(temporary.0.join("keep"), b"existing").unwrap();
        crate::test_executable::write(
            &temporary.0.join("sudo"),
            "#!/bin/sh\nprintf 'Password: ' >/dev/tty\nread -r password </dev/tty || exit 1\n: >installed\n",
            0o755,
        );
        let tty = openpty(None, None).unwrap();
        let mut terminal = fs::File::from(tty.master);
        // A private controlling terminal delivers VINTR to the CLI and sudo's foreground group.
        let mut command = Command::new("setsid");
        command
            .arg("--ctty")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "up::tests::sudo_password_prompt_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("INFRATERNAL_TEST_SUDO_FIXTURE", &temporary.0)
            .env("TERM", "xterm")
            .env_remove("NO_COLOR")
            .stdin(tty.slave.try_clone().unwrap())
            .stdout(Stdio::piped())
            .stderr(tty.slave);
        infraternal_shim::prepare_child(&mut command);
        let mut child = crate::restart_binary::fixture::ChildGuard::new(command.spawn().unwrap());
        drop(command);

        let mut prompt = Vec::new();
        while !prompt.ends_with(b"Password: ") {
            let mut ready = [PollFd::new(terminal.as_fd(), PollFlags::POLLIN)];
            assert_eq!(poll(&mut ready, 5000_u16).unwrap(), 1, "no password prompt");
            let mut bytes = [0; 1024];
            let count = terminal.read(&mut bytes).unwrap();
            assert_ne!(count, 0, "terminal closed before the password prompt");
            prompt.extend_from_slice(&bytes[..count]);
        }
        terminal.write_all(b"\x03").unwrap();

        let mut done = [PollFd::new(
            child.process().stdout.as_ref().unwrap().as_fd(),
            PollFlags::POLLHUP,
        )];
        assert_eq!(poll(&mut done, 5000_u16).unwrap(), 1, "sudo kept running");
        let output = child.output();
        assert_eq!(output.status.signal(), Some(nix::libc::SIGINT));
        let stdout = String::from_utf8(output.stdout).unwrap();
        let envelopes: Vec<serde_json::Value> = stdout
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        assert_eq!(envelopes.len(), 1, "{stdout}");
        assert_eq!(envelopes[0]["error"]["code"], "interrupted");
        assert!(!temporary.0.join("installed").exists());
        assert_eq!(fs::read(temporary.0.join("keep")).unwrap(), b"existing");
        let prompt = String::from_utf8(prompt).unwrap();
        let action = prompt
            .find("Infraternal needs administrator privileges")
            .unwrap();
        let benefit = prompt.find("If you grant it, you get:").unwrap();
        let loss = prompt.find("If you don't, you won't be able to").unwrap();
        assert!(action < benefit && benefit < loss);
        assert!(!prompt.contains('\x1b'), "JSON mode styled the prompt");
    }

    #[test]
    /// Keep enrollment secrets and the host policy together on the private helper input stream.
    fn sudo_handoff_keeps_invitation_and_exact_key_together_on_private_input() {
        let invitation = JoinInvitation {
            host_id: uuid::Uuid::from_u128(1),
            mode: Mode::Rootful,
            execution_uid: 0,
            public_origin: "https://mesh.example.org".to_owned(),
            token: "A".repeat(43),
            ca_der: "public-ca".to_owned(),
            https_der: None,
            https_system_roots: true,
            endpoint: None,
            server_name: "mesh.example.org".to_owned(),
        };
        let key = b"pkcs8 private test bytes";
        let digest = [7; 32];
        let admin_rules = vec!["wt0,10.69.69.0/24,tcp,22".to_owned()];
        let encoded = encode_handoff(&invitation, key, &digest, &admin_rules).unwrap();
        let mut cursor = std::io::Cursor::new(&encoded[..]);
        let decoded = read_handoff(&mut cursor).unwrap();

        let expected_invitation = serde_json::to_vec(&invitation).unwrap();
        assert_eq!(
            decoded.invitation.as_slice(),
            expected_invitation.as_slice()
        );
        assert_eq!(&*decoded.key_pkcs8, key);
        assert_eq!(decoded.key_digest, digest);
        assert_eq!(decoded.admin_rules, admin_rules);
    }

    /// Save the active SSH port from any source, together with configured administrator paths.
    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn agent_host_policy_keeps_the_live_ssh_port_and_extra_admin_rule() {
        let rules = super::agent_host_firewall_rules(
            &["eth0,10.69.0.99,tcp,7011".to_owned()],
            Some("10.69.69.5 43122 10.69.69.89 2222"),
        )
        .expect("an active SSH path is recorded");

        assert_eq!(
            rules,
            vec![
                "eth0,10.69.0.99,tcp,7011".to_owned(),
                "*,*,tcp,2222".to_owned()
            ]
        );
    }

    /// J555 review (P1): `infraternal up` over SSH must not leave the machine
    /// reachable over SSH only from the one address the installer happened to
    /// use. A second administrator, or the same one after their address
    /// changes, connects from 192.0.2.6 and is dropped by the default-drop
    /// table that `up` now installs on every joined Linux machine.
    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn review_j555_up_over_ssh_does_not_pin_ssh_to_one_source_address() {
        use infraternal_plugin_mesh::host_firewall::{
            AllowRule, Policy, validate_ssh_connection_on,
        };
        let rules = super::agent_host_firewall_rules(&[], Some("192.0.2.5 43122 192.0.2.89 22"))
            .expect("an active SSH path supplies the administrator rule");
        let policy = Policy {
            admin_rules: rules
                .iter()
                .map(|rule| rule.parse::<AllowRule>().expect("saved rule parses"))
                .collect(),
            ..Policy::default()
        };
        let next_session =
            validate_ssh_connection_on(&policy, "192.0.2.6 50000 192.0.2.89 22", None);
        assert!(
            next_session.is_ok(),
            "SSH from another administrator address is dropped; saved rules: {rules:?}"
        );
    }

    /// J555 review (P2): running `infraternal up` in a local terminal (no SSH
    /// session, no `--host-firewall-allow`) must still join the machine.
    /// It used to be refused before approval because the host firewall
    /// demanded a TCP/22 administrator rule on every agent install.
    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn review_j555_local_up_without_ssh_still_joins() {
        let result = super::agent_host_firewall_rules(&[], None);
        assert!(result.is_ok(), "local up is refused: {result:?}");
    }

    /// Apply the agent's saved host input policy before system networking starts.
    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn agent_firewall_unit_runs_before_network_pre() {
        let unit = super::host_firewall_systemd_unit();

        assert!(unit.contains("DefaultDependencies=no"));
        assert!(unit.contains("Before=network-pre.target"));
        assert!(unit.contains("WantedBy=network-pre.target"));
        assert!(unit.contains("__host-firewall-apply"));
    }

    /// #401: the root unit `up` installs relabels its binary before every
    /// start, so a `restorecon` or a full relabel can't leave systemd refusing
    /// `/var/lib/infraternal/bin/infraternal` (`var_lib_t`) with `203/EXEC`.
    /// The line never fails the unit (`-`) and is a no-op without `SELinux`.
    #[test]
    fn the_unit_relabels_its_binary_before_every_start() {
        let unit = super::systemd_unit();
        let lines: Vec<&str> = unit.lines().collect();
        assert!(lines.contains(&"After=network-online.target"));
        assert!(lines.contains(&"Wants=network-online.target"));
        let relabel = lines.iter().position(|line| {
            *line
                == r#"ExecStartPre=-+/bin/sh -c "[ ! -e /sys/fs/selinux/enforce ] || chcon -t bin_t /var/lib/infraternal/bin/infraternal""#
        });
        let start = lines.iter().position(|line| line.starts_with("ExecStart="));
        assert!(relabel.is_some(), "{unit}");
        assert!(relabel < start, "{unit}");
    }

    /// #616: `infraternal up` selects the Linux system install elevation prompt
    /// matching whether this build includes the host input firewall.
    #[test]
    fn system_elevation_prompt_matches_linux_features() {
        assert_eq!(
            super::system_elevation_prompt(),
            super::ElevationPrompt::LinuxSystemInstall {
                host_firewall: cfg!(any(feature = "plugin-mesh", feature = "plugin-server")),
            }
        );
    }
}
