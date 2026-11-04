//! Enrolls a Linux machine through device approval and starts its system service (#263).

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use hyper::StatusCode;
use infraternal_plugin_remote::enrollment::{JoinInvitation, Mode};
use qrcodegen::{QrCode, QrCodeEcc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    env, fs,
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::{Duration, Instant},
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::output::{CommandResult, CommandState, Exit, emit};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_INVITATION_BYTES: usize = 8 * 1024;
const MAX_KEY_BYTES: usize = 4 * 1024;
const MAX_HANDOFF_BYTES: usize = 16 * 1024;
const SERVICE_NAME: &str = "infraternal-agent.service";
const SERVICE_BINARY: &str = "/var/lib/infraternal/bin/infraternal";
const SERVICE_DATA: &str = "/var/lib/infraternal/agent";
const PATH_BINARY: &str = "/usr/local/bin/infraternal";
/// The image this process is running. Root installs this, never the file the
/// invoking user's path names: that file may be the user's to replace between
/// sudo starting the helper and the copy (#263, J134 P3-4).
const RUNNING_IMAGE: &str = "/proc/self/exe";
/// Where distributions (and `NixOS`) install the two programs `up` runs. PATH is
/// never searched: the invoking user controls it, and a sudo policy can keep
/// it for the root helper, so a PATH lookup could hand the machine key to
/// another program or run one as root (#263, J122 P2).
const SUDO_CANDIDATES: [&str; 3] = ["/usr/bin/sudo", "/bin/sudo", "/run/wrappers/bin/sudo"];
const SYSTEMCTL_CANDIDATES: [&str; 3] = [
    "/usr/bin/systemctl",
    "/bin/systemctl",
    "/run/current-system/sw/bin/systemctl",
];
/// The only environment the root helper gives systemctl.
const HELPER_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// A user-facing failure class with a stable D303 exit status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
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
    NoSystemd,
}

impl Failure {
    const fn state(self) -> CommandState {
        match self {
            Self::InvalidServer | Self::Permission | Self::Expired | Self::Unsupported => {
                CommandState::Refused
            }
            Self::Unreachable => CommandState::Unknown,
            Self::Partial
            | Self::Throttled
            | Self::Runtime
            | Self::Failed
            | Self::LocalState
            | Self::SudoUnavailable
            | Self::NoSystemd => CommandState::Failed,
            Self::SudoDenied | Self::UntrustedTool => CommandState::Refused,
        }
    }

    const fn exit(self) -> Exit {
        match self {
            Self::InvalidServer => Exit::Usage,
            Self::Permission | Self::Expired | Self::SudoDenied | Self::UntrustedTool => {
                Exit::NotAllowed
            }
            Self::Unsupported | Self::SudoUnavailable | Self::NoSystemd => Exit::NotFound,
            Self::Unreachable => Exit::Unreachable,
            Self::Partial => Exit::Partial,
            Self::Throttled | Self::Runtime | Self::Failed | Self::LocalState => Exit::Failed,
        }
    }

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
            Self::NoSystemd => {
                "infraternal up installs a systemd system service, and systemctl is not installed in a system directory."
            }
        }
    }

    const fn exit_code(self) -> u8 {
        self.exit().code()
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Failed),
            2 => Some(Self::InvalidServer),
            3 => Some(Self::Permission),
            4 => Some(Self::Expired),
            5 => Some(Self::Unreachable),
            6 => Some(Self::Partial),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct MachineStartRequest<'a> {
    device: &'a str,
    kind: &'static str,
    request: MachineRequest<'a>,
}

#[derive(Serialize)]
struct MachineRequest<'a> {
    host_id: uuid::Uuid,
    hostname: &'a str,
    mode: &'static str,
    execution_uid: u32,
    key_fingerprint: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceStartResponse {
    poll_token: Zeroizing<String>,
    user_code: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct DeviceRedeemRequest<'a> {
    token: &'a str,
}

struct Approval {
    poll_token: Zeroizing<String>,
    user_code: String,
    lifetime: Duration,
}

struct Handoff {
    invitation: Zeroizing<Vec<u8>>,
    key_pkcs8: Zeroizing<Vec<u8>>,
    key_digest: [u8; 32],
}

struct ApprovedInvitation(JoinInvitation);

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

/// The invoking user's on-disk copy of the pending machine key, between its
/// preparation and [`take_join_key`]. A failure in that short window deletes
/// it on return or unwind (#263, J134 P3-5). A signal does not run `Drop`, so
/// the copy must not outlive that window: see [`take_join_key`].
struct PendingKeyCopy<'a>(&'a Path);

impl Drop for PendingKeyCopy<'_> {
    fn drop(&mut self) {
        // Best effort; take_join_key has normally removed it already.
        let _ = crate::remote::retire_prepared_join_key(self.0);
    }
}

/// Read the prepared machine key into zeroizing memory and delete its file at
/// once, before the code is shown. Nothing is then on disk during the
/// ten-minute wait or the root helper run, so Ctrl-C, a closed terminal or
/// SIGTERM cannot leave a root service's key readable in the user's home
/// (#263, J145 P3-1). A retry needs a new approval anyway, so it gets a new
/// key. Rejected: a signal handler that deletes the file, which adds async
/// signal-safety and still loses to SIGKILL.
fn take_join_key(data: &Path) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let key = crate::remote::prepared_join_key_pkcs8(data).map_err(|_| Failure::LocalState)?;
    crate::remote::retire_prepared_join_key(data).map_err(|_| Failure::LocalState)?;
    Ok(key)
}

/// Request a fresh machine approval, wait for its one-use enrollment receipt, and install it.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(server_input: &str, json_output: bool) -> ExitCode {
    let server = match server_url(server_input) {
        Ok(server) => server,
        Err(failure) => return fail(json_output, failure),
    };
    let origin = server.origin().ascii_serialization();
    // The code and link are a live approval capability for ten minutes. Show
    // them only to a person at a terminal, never into a pipe, file or CI log,
    // and do not wait out the lifetime when nobody can see them (#263).
    if !approval_display_is_terminal(json_output) {
        return needs_terminal(&origin, json_output);
    }
    // Find both privileged programs before an approval is requested, so a
    // missing or replaceable one never wastes the owner's passkey approval.
    let Ok(executable) = env::current_exe() else {
        return fail(json_output, Failure::Permission);
    };
    let mut sudo = match sudo_command(&executable, &origin, json_output) {
        Ok(command) => command,
        Err(failure) => return fail(json_output, failure),
    };
    if let Err(failure) = trusted_tool(&SYSTEMCTL_CANDIDATES, Failure::NoSystemd) {
        return fail(json_output, failure);
    }
    let hostname = local_hostname();
    let host_id = uuid::Uuid::new_v4();
    let Ok(data) = crate::remote::default_data() else {
        return fail(json_output, Failure::LocalState);
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return fail(json_output, Failure::Runtime);
    };
    let key_digest = match runtime.block_on(crate::remote::prepare_machine_join_key(&origin, &data))
    {
        Ok(digest) => digest,
        Err(error) => return fail(json_output, map_remote_failure(&error)),
    };
    let _key_copy = PendingKeyCopy(&data);
    let key_pkcs8 = match take_join_key(&data) {
        Ok(key) => key,
        Err(failure) => return fail(json_output, failure),
    };
    if crate::remote::key_digest_from_pkcs8(&key_pkcs8).ok() != Some(key_digest) {
        return fail(json_output, Failure::LocalState);
    }
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(key_digest));
    let Some(short_key) = machine_key_short(&fingerprint) else {
        return fail(json_output, Failure::Failed);
    };
    let body = match machine_start_body(host_id, &hostname, &fingerprint) {
        Ok(body) => body,
        Err(failure) => return fail(json_output, failure),
    };
    let approval = match runtime.block_on(start_approval(&server, &body)) {
        Ok(approval) => approval,
        Err(failure) => return fail(json_output, failure),
    };
    let link = join_approval_link(&server, &approval.user_code);
    if let Err(failure) = print_approval(json_output, &short_key, &approval.user_code, &link) {
        return fail(json_output, failure);
    }
    let mut invitation =
        match runtime.block_on(wait_for_approval(&server, &approval, host_id, &origin)) {
            Ok(invitation) => invitation,
            Err(failure) => return fail(json_output, failure),
        };
    let payload = match encode_handoff(&invitation.0, &key_pkcs8, &key_digest) {
        Ok(payload) => payload,
        Err(failure) => return fail(json_output, failure),
    };
    invitation.wipe();
    if let Err(failure) = invoke_sudo(&mut sudo, &payload) {
        return fail(json_output, failure);
    }
    emit(
        CommandResult::new(
            "up",
            CommandState::Ready,
            "This machine joined the server and its system service is active.",
            json!({
                "server": origin,
                "hostname": hostname,
                "mode": "system",
                "key_fingerprint": fingerprint,
                "machine_key": short_key,
                "service": SERVICE_NAME,
                "status": "active",
                "path": PATH_BINARY,
            }),
        )
        .with_body(format!(
            "Machine joined as {hostname}.\nService: active\nCommand: {PATH_BINARY}"
        )),
        json_output,
        Exit::Ok,
    )
}

/// Run only the privileged half requested by `sudo`; all credentials arrive on stdin.
pub(crate) fn run_helper(server_input: &str, _json_output: bool) -> ExitCode {
    let result = run_helper_inner(server_input);
    let code = result.map_or_else(Failure::exit_code, |()| 0);
    println!("UP_RESULT={code}");
    ExitCode::from(code)
}

#[allow(clippy::too_many_lines)]
fn run_helper_inner(server_input: &str) -> Result<(), Failure> {
    if nix::unistd::Uid::effective().as_raw() != 0 {
        return Err(Failure::Permission);
    }
    let server = server_url(server_input)?;
    let origin = server.origin().ascii_serialization();
    let handoff = read_handoff(&mut io::stdin().lock())?;
    // Resolved again as root: the caller's check proves nothing to this process.
    // After the handoff is read (the caller's write must not fail on a closed
    // pipe) and before enrollment, so a refusal leaves no half-joined machine.
    let systemctl =
        trusted_tool(&SYSTEMCTL_CANDIDATES, Failure::NoSystemd).map_err(|_| Failure::Failed)?;
    let mut invitation = ApprovedInvitation(
        serde_json::from_slice(&handoff.invitation).map_err(|_| Failure::Permission)?,
    );
    validate_invitation(&invitation.0, &origin, None)?;
    if crate::remote::key_digest_from_pkcs8(&handoff.key_pkcs8).ok() != Some(handoff.key_digest) {
        return Err(Failure::Permission);
    }
    invitation.wipe();
    // Before enrollment creates `agent/`: its recursive create would otherwise
    // make the shared base 0700 and the PATH link unusable (J134 P2-4).
    prepare_system_layout(Path::new("/"), 0).map_err(|_| Failure::LocalState)?;
    println!("UP_STAGE=enrollment");
    let join_url = format!("{origin}/remote/join");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Failure::Runtime)?;
    runtime
        .block_on(crate::remote::join_with_key(
            &join_url,
            Path::new(SERVICE_DATA),
            &handoff.invitation,
            &handoff.key_pkcs8,
        ))
        .map_err(|error| map_remote_failure(&error))?;
    install_system_service(Path::new("/"), Path::new(RUNNING_IMAGE), &systemctl, 0)
        .map_err(|_| Failure::Partial)
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
        "linux-host".to_owned()
    } else {
        safe
    }
}

fn machine_start_body(
    host_id: uuid::Uuid,
    hostname: &str,
    key_fingerprint: &str,
) -> Result<Vec<u8>, Failure> {
    if hostname.is_empty()
        || hostname.len() > 128
        || hostname.chars().any(char::is_control)
        || !valid_fingerprint(key_fingerprint)
    {
        return Err(Failure::Failed);
    }
    serde_json::to_vec(&MachineStartRequest {
        device: hostname,
        kind: "join_machine",
        request: MachineRequest {
            host_id,
            hostname,
            mode: "system",
            execution_uid: 0,
            key_fingerprint,
        },
    })
    .map_err(|_| Failure::Failed)
}

fn valid_fingerprint(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("SHA256:") else {
        return false;
    };
    let Ok(decoded) = STANDARD_NO_PAD.decode(encoded) else {
        return false;
    };
    decoded.len() == 32 && STANDARD_NO_PAD.encode(decoded) == encoded
}

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

fn join_approval_link(server: &Url, user_code: &str) -> String {
    format!(
        "{}/#join={user_code}",
        server.origin().ascii_serialization()
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

async fn start_approval(server: &Url, body: &[u8]) -> Result<Approval, Failure> {
    let response = post_json(server, "/auth/device-start", body).await?;
    if response.status != StatusCode::OK {
        return Err(map_http_status(response.status));
    }
    let started: DeviceStartResponse =
        serde_json::from_slice(&response.body).map_err(|_| Failure::Failed)?;
    if !capability_has_shape(&started.poll_token, 43)
        || !capability_has_shape(&started.user_code, 16)
        || started.expires_in != 600
    {
        return Err(Failure::Failed);
    }
    Ok(Approval {
        poll_token: started.poll_token,
        user_code: started.user_code,
        lifetime: Duration::from_secs(started.expires_in),
    })
}

async fn wait_for_approval(
    server: &Url,
    approval: &Approval,
    host_id: uuid::Uuid,
    origin: &str,
) -> Result<ApprovedInvitation, Failure> {
    let deadline = Instant::now() + approval.lifetime;
    let mut delay = POLL_INTERVAL;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Failure::Expired);
        }
        tokio::time::sleep(delay.min(remaining)).await;
        if Instant::now() >= deadline {
            return Err(Failure::Expired);
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&DeviceRedeemRequest {
                token: &approval.poll_token,
            })
            .map_err(|_| Failure::Failed)?,
        );
        let response = match post_json(server, "/auth/device-redeem", &body).await {
            Ok(response) => response,
            Err(Failure::Unreachable) => {
                delay = POLL_INTERVAL;
                continue;
            }
            Err(failure) => return Err(failure),
        };
        match response.status {
            StatusCode::OK => {
                let invitation = ApprovedInvitation(
                    serde_json::from_slice(&response.body).map_err(|_| Failure::Failed)?,
                );
                validate_invitation(&invitation.0, origin, Some(host_id))?;
                return Ok(invitation);
            }
            StatusCode::UNAUTHORIZED => delay = POLL_INTERVAL,
            StatusCode::TOO_MANY_REQUESTS => {
                delay = response
                    .retry_after
                    .unwrap_or(POLL_INTERVAL)
                    .max(Duration::from_secs(1));
            }
            status if status.is_server_error() => delay = POLL_INTERVAL,
            status => return Err(map_http_status(status)),
        }
    }
}

async fn post_json(
    server: &Url,
    path: &'static str,
    body: &[u8],
) -> Result<crate::remote::ClientResponse, Failure> {
    let mut request_started = false;
    match tokio::time::timeout(
        REQUEST_TIMEOUT,
        crate::remote::post_json(
            server,
            path,
            bytes::Bytes::copy_from_slice(body),
            None,
            MAX_RESPONSE_BYTES,
            &mut request_started,
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

fn validate_invitation(
    invitation: &JoinInvitation,
    origin: &str,
    host_id: Option<uuid::Uuid>,
) -> Result<(), Failure> {
    let token_ok = capability_has_shape(&invitation.token, 43);
    if !token_ok
        || invitation.public_origin != origin
        || invitation.mode != Mode::Rootful
        || invitation.execution_uid != 0
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
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let invitation = Zeroizing::new(serde_json::to_vec(invitation).map_err(|_| Failure::Failed)?);
    if invitation.is_empty()
        || invitation.len() > MAX_INVITATION_BYTES
        || key_pkcs8.is_empty()
        || key_pkcs8.len() > MAX_KEY_BYTES
    {
        return Err(Failure::Failed);
    }
    let invitation_len = u32::try_from(invitation.len()).map_err(|_| Failure::Failed)?;
    let key_len = u32::try_from(key_pkcs8.len()).map_err(|_| Failure::Failed)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(
        12 + invitation.len() + key_pkcs8.len() + key_digest.len(),
    ));
    payload.extend_from_slice(b"UPJ1");
    payload.extend_from_slice(&invitation_len.to_be_bytes());
    payload.extend_from_slice(&invitation);
    payload.extend_from_slice(&key_len.to_be_bytes());
    payload.extend_from_slice(key_pkcs8);
    payload.extend_from_slice(key_digest);
    if payload.len() > MAX_HANDOFF_BYTES {
        return Err(Failure::Failed);
    }
    Ok(payload)
}

fn read_handoff(reader: &mut impl Read) -> Result<Handoff, Failure> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_HANDOFF_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Permission)?;
    if bytes.len() > MAX_HANDOFF_BYTES || bytes.get(..4) != Some(&b"UPJ1"[..]) {
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
    if digest_end != bytes.len() {
        return Err(Failure::Permission);
    }
    let key_digest = bytes[offset..digest_end]
        .try_into()
        .map_err(|_| Failure::Permission)?;
    Ok(Handoff {
        invitation,
        key_pkcs8,
        key_digest,
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

#[derive(Debug, Eq, PartialEq)]
enum ToolError {
    Missing,
    Untrusted,
}

/// Resolve the first existing candidate to its canonical file, checking that
/// nobody but root (or `owner`, which tests set to themselves) can replace it.
/// An existing but replaceable candidate is refused, never skipped, so a
/// tampered first choice cannot quietly fall through to another.
fn trusted_program(candidates: &[&str], owner: u32) -> Result<PathBuf, ToolError> {
    for candidate in candidates {
        let candidate = Path::new(candidate);
        let canonical = match fs::canonicalize(candidate) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(ToolError::Untrusted),
        };
        // Both chains count: symlinks on the way (merged /usr, NixOS's
        // /run/current-system) live in the candidate's own directories.
        let trusted = regular_executable_of(&canonical, owner)
            && candidate
                .parent()
                .into_iter()
                .flat_map(Path::ancestors)
                .chain(canonical.parent().into_iter().flat_map(Path::ancestors))
                .all(|directory| protected_directory(directory, owner));
        return if trusted {
            Ok(canonical)
        } else {
            Err(ToolError::Untrusted)
        };
    }
    Err(ToolError::Missing)
}

fn regular_executable_of(path: &Path, owner: u32) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        let mode = metadata.permissions().mode();
        metadata.is_file()
            && (metadata.uid() == 0 || metadata.uid() == owner)
            && mode & 0o022 == 0
            && mode & 0o111 != 0
    })
}

/// A directory only root (or `owner`) can add to or rename in. A sticky
/// directory (such as `/nix/store`) may be group-writable: others can add
/// entries there but cannot replace the root-owned ones checked below it.
fn protected_directory(directory: &Path, owner: u32) -> bool {
    fs::metadata(directory).is_ok_and(|metadata| {
        let mode = metadata.permissions().mode();
        metadata.is_dir()
            && (metadata.uid() == 0 || metadata.uid() == owner)
            && (mode & 0o022 == 0 || mode & 0o1000 != 0)
    })
}

fn invoke_sudo(command: &mut Command, payload: &[u8]) -> Result<(), Failure> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| Failure::SudoUnavailable)?;
    let mut stdin = child.stdin.take().ok_or(Failure::Runtime)?;
    stdin.write_all(payload).map_err(|_| Failure::Partial)?;
    drop(stdin);
    let output = child.wait_with_output().map_err(|_| Failure::Partial)?;
    if let Some(code) = parse_result_marker(&output.stdout) {
        if code == 0 {
            Ok(())
        } else {
            Err(Failure::from_code(code).unwrap_or(Failure::Partial))
        }
    } else if output.status.success() {
        Err(Failure::Partial)
    } else if output.status.code().is_some_and(|code| code == 1) {
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

/// Install the running binary and its systemd unit without replacing foreign PATH entries.
#[allow(clippy::too_many_lines)]
fn install_system_service(
    root: &Path,
    source: &Path,
    systemctl: &Path,
    expected_uid: u32,
) -> io::Result<()> {
    if nix::unistd::Uid::effective().as_raw() != expected_uid {
        return Err(permission_error());
    }
    // Again here: it also repairs a base that an earlier run left at 0700.
    prepare_system_layout(root, expected_uid)?;
    let binary =
        ensure_directory(root, "var/lib/infraternal/bin", expected_uid)?.join("infraternal");
    copy_executable(source, &binary, expected_uid)?;

    let path_directory = ensure_directory(root, "usr/local/bin", expected_uid)?;
    install_path_link(&path_directory.join("infraternal"), expected_uid)?;
    if !infraternal_plugin_api::cli_alias::install(
        &path_directory.join("infraternal"),
        expected_uid,
    )? {
        eprintln!("infraternal: skipped infra; an existing path belongs to another command.");
    }

    let unit_directory = ensure_directory(root, "etc/systemd/system", expected_uid)?;
    let unit_path = unit_directory.join("infraternal-agent.service");
    let unit = systemd_unit();
    install_owned_file(&unit_path, unit.as_bytes(), 0o644, expected_uid)?;

    run_systemctl(systemctl, &["daemon-reload"], None)?;
    run_systemctl(systemctl, &["enable", "--now", SERVICE_NAME], None)?;
    run_systemctl(systemctl, &["is-active", SERVICE_NAME], Some("active"))
}

/// Lay out `/var/lib/infraternal` so the invoking user can run the CLI
/// through `/usr/local/bin/infraternal` while the state stays private
/// (#263, J134 P2-4):
///
/// - `var/lib/infraternal` is 0711: anyone may pass through it, no one but
///   root may list it. D17 keeps the binary out of `/usr`, so its directory
///   has to be traversable. The SSH installer and uninstaller accept 0711 for
///   the same base.
/// - `bin/` is 0755 and holds only the released binary.
/// - `agent/` is 0700, and everything enrollment writes in it is 0600.
///
/// The modes are set explicitly, because the umask sudo hands the helper can
/// be 077. An existing base is narrowed or widened to exactly these modes,
/// after the same ownership and no-group-write checks as every other
/// installed path.
fn prepare_system_layout(root: &Path, owner: u32) -> io::Result<()> {
    let bin = ensure_directory(root, "var/lib/infraternal/bin", owner)?;
    let base = bin.parent().ok_or_else(permission_error)?;
    fs::set_permissions(base, fs::Permissions::from_mode(0o711))?;
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))?;
    let agent = base.join("agent");
    match fs::symlink_metadata(&agent) {
        Ok(metadata) => check_directory(&metadata, owner)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(&agent)?;
            check_directory(&fs::symlink_metadata(&agent)?, owner)?;
        }
        Err(error) => return Err(error),
    }
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o700))
}

fn ensure_directory(root: &Path, relative: &str, owner: u32) -> io::Result<PathBuf> {
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.uid() != owner {
        return Err(permission_error());
    }
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let std::path::Component::Normal(component) = component else {
            return Err(permission_error());
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => check_directory(&metadata, owner)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o755).create(&current)?;
                check_directory(&fs::symlink_metadata(&current)?, owner)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(current)
}

fn check_directory(metadata: &fs::Metadata, owner: u32) -> io::Result<()> {
    if !metadata.is_dir() || metadata.uid() != owner || metadata.permissions().mode() & 0o022 != 0 {
        return Err(permission_error());
    }
    Ok(())
}

fn copy_executable(source: &Path, destination: &Path, owner: u32) -> io::Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata)
            if !metadata.is_file()
                || metadata.uid() != owner
                || metadata.permissions().mode() & 0o022 != 0 =>
        {
            return Err(permission_error());
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = destination.with_extension(format!("{}.pending", uuid::Uuid::new_v4()));
    let result = (|| {
        // Hash what is read, then hash what landed on disk, and publish only
        // a byte-identical copy. The source is opened once, so a path that
        // changes meanwhile cannot mix two files.
        let mut input = fs::File::open(source)?;
        if !input.metadata()?.is_file() {
            return Err(permission_error());
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)?;
        let read = hash_stream(&mut input, Some(&mut output))?;
        output.set_permissions(fs::Permissions::from_mode(0o755))?;
        output.sync_all()?;
        drop(output);
        let written = hash_stream(&mut fs::File::open(&temporary)?, None)?;
        if written != read {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed binary differs from the running image",
            ));
        }
        fs::rename(&temporary, destination)?;
        if let Some(parent) = destination.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
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

fn install_path_link(path: &Path, owner: u32) -> io::Result<()> {
    let target = Path::new(SERVICE_BINARY);
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if metadata.uid() == owner && fs::read_link(path)? == target {
                return Ok(());
            }
            return Err(permission_error());
        }
        Ok(_) => return Err(permission_error()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = path.with_extension(format!("{}.pending", uuid::Uuid::new_v4()));
    std::os::unix::fs::symlink(target, &temporary)?;
    let result = fs::rename(&temporary, path);
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    } else if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    result
}

fn install_owned_file(path: &Path, contents: &[u8], mode: u32, owner: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.is_file()
                || metadata.uid() != owner
                || metadata.permissions().mode() & 0o022 != 0 =>
        {
            return Err(permission_error());
        }
        Ok(_) => {
            if fs::read(path)? != contents {
                return Err(permission_error());
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = path.with_extension(format!("{}.pending", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn systemd_unit() -> String {
    format!(
        "[Unit]\nDescription=Infraternal machine service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={SERVICE_BINARY} agent run --data {SERVICE_DATA}\nRestart=on-failure\nRestartSec=2\nKillMode=process\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

fn run_systemctl(
    systemctl: &Path,
    arguments: &[&str],
    expected_output: Option<&str>,
) -> io::Result<()> {
    // Root runs systemctl with a fixed environment, not whatever sudo kept.
    let output = Command::new(systemctl)
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

fn map_remote_failure(error: &io::Error) -> Failure {
    match crate::remote::Failure::of(error) {
        None => Failure::LocalState,
        Some(
            crate::remote::Failure::Dns(_)
            | crate::remote::Failure::Connect
            | crate::remote::Failure::Tls
            | crate::remote::Failure::Upgrade
            | crate::remote::Failure::Challenge,
        ) => Failure::Unreachable,
        Some(crate::remote::Failure::Refused) => Failure::Permission,
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

#[cfg(test)]
mod tests {
    use super::{
        Failure, JoinInvitation, Mode, SUDO_CANDIDATES, ToolError, approval_qr, encode_handoff,
        install_system_service, invoke_sudo, join_approval_link, machine_key_short,
        machine_start_body, map_remote_failure, read_handoff, sudo_command, trusted_program,
    };
    use crate::cli::output::Exit;
    use serde_json::json;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };
    use url::Url;

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
    fn join_approval_link_places_only_the_user_code_in_the_fragment() {
        let server = Url::parse("https://mesh.example.org:8443/").unwrap();
        assert_eq!(
            join_approval_link(&server, "AbCdEfGhIjKlMnOp"),
            "https://mesh.example.org:8443/#join=AbCdEfGhIjKlMnOp"
        );
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

    #[test]
    fn browser_key_label_groups_the_first_sixteen_fingerprint_characters() {
        assert_eq!(
            machine_key_short("SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCde"),
            Some("AbCd EfGh IjKl MnOp".to_owned())
        );
    }

    #[test]
    fn machine_start_body_binds_the_requested_system_mode_and_key() {
        let body = machine_start_body(
            uuid::Uuid::from_u128(1),
            "workstation",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value,
            json!({
                "kind": "join_machine",
                "device": "workstation",
                "request": {
                    "host_id": "00000000-0000-0000-0000-000000000001",
                    "hostname": "workstation",
                    "mode": "system",
                    "execution_uid": 0,
                    "key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            })
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

    /// A private directory chain the test user owns, holding one program.
    fn program_in(temporary: &TemporaryDirectory, directory_mode: u32, file_mode: u32) -> String {
        let directory = temporary.0.join("bin");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&temporary.0, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(directory_mode)).unwrap();
        let program = directory.join("tool");
        fs::write(&program, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(file_mode)).unwrap();
        program.to_str().unwrap().to_owned()
    }

    fn me() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    #[test]
    fn a_program_only_its_owner_can_replace_is_trusted_at_its_canonical_path() {
        let temporary = TemporaryDirectory::new();
        let program = program_in(&temporary, 0o755, 0o755);
        assert_eq!(
            trusted_program(&[program.as_str()], me()),
            Ok(fs::canonicalize(&program).unwrap())
        );
        // A sticky shared directory (like /nix/store) is still protected.
        let sticky = TemporaryDirectory::new();
        let program = program_in(&sticky, 0o1777, 0o755);
        assert!(trusted_program(&[program.as_str()], me()).is_ok());
    }

    #[test]
    fn a_program_others_can_replace_is_refused() {
        for (directory_mode, file_mode) in [
            (0o755, 0o775),
            (0o755, 0o757),
            (0o777, 0o755),
            (0o775, 0o755),
        ] {
            let temporary = TemporaryDirectory::new();
            let program = program_in(&temporary, directory_mode, file_mode);
            assert_eq!(
                trusted_program(&[program.as_str()], me()),
                Err(ToolError::Untrusted),
                "directory {directory_mode:o}, file {file_mode:o}"
            );
        }
        // Owned by someone else entirely: the test user cannot vouch for it.
        let temporary = TemporaryDirectory::new();
        let program = program_in(&temporary, 0o755, 0o755);
        assert_eq!(
            trusted_program(&[program.as_str()], me().wrapping_add(1)),
            if me() == 0 {
                Ok(fs::canonicalize(&program).unwrap())
            } else {
                Err(ToolError::Untrusted)
            }
        );
    }

    #[test]
    fn a_replaceable_first_candidate_is_refused_not_skipped() {
        let bad = TemporaryDirectory::new();
        let good = TemporaryDirectory::new();
        let bad = program_in(&bad, 0o777, 0o755);
        let good = program_in(&good, 0o755, 0o755);
        assert_eq!(
            trusted_program(&[bad.as_str(), good.as_str()], me()),
            Err(ToolError::Untrusted)
        );
        let missing = TemporaryDirectory::new();
        let missing = missing.0.join("absent");
        assert_eq!(
            trusted_program(&[missing.to_str().unwrap(), good.as_str()], me()),
            Ok(fs::canonicalize(&good).unwrap())
        );
        assert_eq!(
            trusted_program(&[missing.to_str().unwrap()], me()),
            Err(ToolError::Missing)
        );
    }

    #[test]
    fn a_symlink_in_a_writable_directory_is_refused_even_to_a_trusted_file() {
        let target = TemporaryDirectory::new();
        let target = program_in(&target, 0o755, 0o755);
        let open = TemporaryDirectory::new();
        fs::set_permissions(&open.0, fs::Permissions::from_mode(0o777)).unwrap();
        let link = open.0.join("tool");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            trusted_program(&[link.to_str().unwrap()], me()),
            Err(ToolError::Untrusted)
        );
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
        fs::write(
            &systemctl,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n[ \"$1\" != is-active ] || echo active\n",
                calls.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();

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
        // A later foreign command wins even when this installation is repeated.
        let alias = link.with_file_name("infra");
        fs::remove_file(&alias).unwrap();
        fs::write(&alias, b"foreign infra").unwrap();
        install_system_service(
            &temporary.0,
            &source,
            &systemctl,
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap();
        assert_eq!(fs::read(alias).unwrap(), b"foreign infra");
    }

    #[test]
    fn the_path_command_is_reachable_by_other_users_while_state_stays_private() {
        // J134 P2-4: enrollment's recursive create made the base 0700.
        let temporary = TemporaryDirectory::new();
        let source = temporary.0.join("running-infraternal");
        let systemctl = temporary.0.join("systemctl");
        fs::write(&source, b"binary").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            &systemctl,
            "#!/bin/sh\n[ \"$1\" != is-active ] || echo active\n",
        )
        .unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
        let base = temporary.0.join("var/lib/infraternal");
        fs::create_dir_all(temporary.0.join("var/lib")).unwrap();
        std::os::unix::fs::DirBuilderExt::mode(fs::DirBuilder::new().recursive(true), 0o700)
            .create(base.join("agent"))
            .unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();

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

    /// Child half of `a_signal_during_up_leaves_no_copy_of_the_machine_key`:
    /// takes the key the way `up` does, then waits like `up` waits.
    #[test]
    #[ignore = "run only as a child process that the parent signals"]
    fn hold_a_taken_join_key() {
        let data = Path::new(&std::env::var_os("UP_TEST_KEY_DIR").unwrap()).to_path_buf();
        let _copy = super::PendingKeyCopy(&data);
        let key = super::take_join_key(&data).unwrap();
        assert!(!key.is_empty());
        println!("\nKEY_TAKEN");
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    #[test]
    fn a_signal_during_up_leaves_no_copy_of_the_machine_key() {
        // J145 P3-1: Ctrl-C, a closed terminal or SIGTERM skip Drop.
        use nix::sys::signal::{Signal, kill};
        use std::io::BufRead;
        for signal in [Signal::SIGINT, Signal::SIGHUP, Signal::SIGTERM] {
            let temporary = TemporaryDirectory::new();
            let data = temporary.0.join("data");
            fs::create_dir(&data).unwrap();
            fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
            // The key `up` prepared before the code is shown.
            crate::remote::prepared_join_key_pkcs8(&data).unwrap();
            assert_eq!(fs::read_dir(&data).unwrap().count(), 1);
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "up::tests::hold_a_taken_join_key",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("UP_TEST_KEY_DIR", &data)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
            let ready = stdout
                .lines()
                .map_while(Result::ok)
                .any(|line| line == "KEY_TAKEN");
            assert!(ready, "the child never took the key");
            kill(
                nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap()),
                signal,
            )
            .unwrap();
            let status = child.wait().unwrap();
            assert!(!status.success(), "{signal:?}: the child was not stopped");
            assert_eq!(
                fs::read_dir(&data).unwrap().count(),
                0,
                "{signal:?}: the key copy survived the signal"
            );
        }
    }

    #[test]
    fn a_failed_up_leaves_no_copy_of_the_machine_key() {
        // J134 P3-5: the key stayed in the user's home after any failure.
        let temporary = TemporaryDirectory::new();
        let data = temporary.0.join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        // The same preparation `up` runs after its server preflight.
        let key = crate::remote::prepared_join_key_pkcs8(&data).unwrap();
        assert!(crate::remote::key_digest_from_pkcs8(&key).is_ok());
        let before = fs::read_dir(&data).unwrap().count();
        assert_eq!(before, 1, "one pending key file");
        {
            let _copy = super::PendingKeyCopy(&data);
            // Any failure return happens here.
        }
        assert_eq!(
            fs::read_dir(&data).unwrap().count(),
            0,
            "the key copy was left behind"
        );
    }

    #[test]
    fn root_installs_the_running_image_byte_for_byte() {
        // J134 P3-4: the helper copies /proc/self/exe, not a path.
        let temporary = TemporaryDirectory::new();
        let systemctl = temporary.0.join("systemctl");
        fs::write(
            &systemctl,
            "#!/bin/sh\n[ \"$1\" != is-active ] || echo active\n",
        )
        .unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();

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
        fs::write(&systemctl, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
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

    #[test]
    fn missing_sudo_has_a_local_not_found_cause() {
        let temporary = TemporaryDirectory::new();
        let mut command = std::process::Command::new(temporary.0.join("missing-sudo"));

        let failure = invoke_sudo(&mut command, b"").unwrap_err();

        assert_eq!(failure.exit(), Exit::NotFound);
        assert!(failure.message().contains("sudo"));
    }

    #[test]
    fn sudo_denial_has_a_local_permission_cause() {
        let temporary = TemporaryDirectory::new();
        let sudo = temporary.0.join("sudo");
        fs::write(&sudo, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&sudo, fs::Permissions::from_mode(0o755)).unwrap();
        let mut command = std::process::Command::new(sudo);

        let failure = invoke_sudo(&mut command, b"").unwrap_err();

        assert_eq!(failure.exit(), Exit::NotAllowed);
        assert!(failure.message().contains("sudo"));
    }

    #[test]
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
        let encoded = encode_handoff(&invitation, key, &digest).unwrap();
        let mut cursor = std::io::Cursor::new(&encoded[..]);
        let decoded = read_handoff(&mut cursor).unwrap();

        let expected_invitation = serde_json::to_vec(&invitation).unwrap();
        assert_eq!(
            decoded.invitation.as_slice(),
            expected_invitation.as_slice()
        );
        assert_eq!(&*decoded.key_pkcs8, key);
        assert_eq!(decoded.key_digest, digest);
    }
}
