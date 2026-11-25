//! Device approval, without any I/O: the JSON the two sides exchange and the checks on it [#580].
//!
//! A device (the CLI, a joining machine, later the app) asks a server for an
//! approval, shows the owner a link, and polls until a passkey tap approves it.
//! This crate holds the one copy of what travels in that exchange and of the
//! checks that decide whether a reply is believable:
//!
//! - the request and reply types of `/auth/device-start` and
//!   `/auth/device-redeem` ([`DeviceStartRequest`], [`DeviceStartResponse`],
//!   [`DeviceRedeemRequest`], [`DeviceRedeemResponse`]),
//! - the server-origin, scope and link rules ([`server_url`],
//!   [`requested_scopes`], [`approval_link`]),
//! - the shape checks on a server-made capability
//!   ([`server_capability_has_shape`], [`parse_start_response`],
//!   [`parse_redemption_response`]),
//! - the redeem status mapping ([`interpret_redemption`]),
//! - the machine-join start body ([`machine_start_body`]) and its approval
//!   link ([`join_approval_link`]).
//!
//! **It never touches the network or the disk.** The caller moves the bytes:
//! the CLI with its own HTTPS client, the app with `URLSession`. Credential
//! files, host names and terminal output stay with the caller too.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The scopes every sign-in asks for.
pub const SCOPES: [&str; 3] = ["hosts:read", "sessions:read", "status:read"];
/// Scopes a caller may add on top of [`SCOPES`] when it asks explicitly.
pub const ADDITIONAL_SCOPES: [&str; 3] = ["hosts:write", "terminal:connect", "actions:dry-run"];
/// How long the server keeps one approval, in seconds (the server's `APPROVAL_LIFETIME`).
pub const APPROVAL_LIFETIME_SECONDS: u64 = 10 * 60;
/// Length of a server-made poll token or API key (43 base64url characters, 256 bits).
pub const POLL_TOKEN_LENGTH: usize = 43;
/// Length of a server-made user code (16 base64url characters).
pub const USER_CODE_LENGTH: usize = 16;

/// The longest host name a machine join may carry.
pub const MAX_HOSTNAME_LENGTH: usize = 128;

/// Why a pure check refused its input. Callers map this to their own error and exit codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckFailure {
    /// The server address is not a bare HTTPS origin.
    InvalidServer,
    /// A requested scope is not one this crate knows.
    InvalidScope,
    /// A start reply was not the expected JSON or had a wrong shape.
    BadResponse,
    /// A successful redeem reply could not be used; the key may already be spent.
    RedemptionUncertain,
    /// A machine-join field is empty, too long, has control characters, or is not a key fingerprint.
    InvalidMachine,
}

/// The body of `POST /auth/device-start` for a sign-in: who is asking and for which scopes.
#[derive(Serialize)]
pub struct DeviceStartRequest<'a> {
    /// A short device label the owner reads before approving.
    pub device: &'a str,
    /// The scopes the new API key would carry.
    pub scopes: &'a [String],
}

/// The server's reply to `/auth/device-start`: what to poll with and what to show.
///
/// The same type is built by the server and parsed by clients, so the bytes
/// cannot drift; the server tests pin them.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStartResponse {
    /// The secret the device polls with. Zeroed when dropped.
    pub poll_token: Zeroizing<String>,
    /// The code the owner sees in the approval link.
    pub user_code: String,
    /// Seconds until the approval expires.
    pub expires_in: u64,
}

/// The body of `POST /auth/device-redeem`: the poll token of an approval.
#[derive(Serialize)]
pub struct DeviceRedeemRequest<'a> {
    /// The poll token from [`DeviceStartResponse`].
    pub token: &'a str,
}

/// The server's reply to a redeem of an approved sign-in: the API key, shown once.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRedeemResponse {
    /// The new API key. Zeroed when dropped.
    pub api_key: Zeroizing<String>,
}

/// The body of `POST /auth/device-start` for a machine join, which asks for an invitation instead of an API key.
#[derive(Serialize)]
pub struct MachineStartRequest<'a> {
    /// The host name again, as the device label.
    pub device: &'a str,
    /// Always `join_machine`.
    pub kind: &'static str,
    /// The machine facts the owner inspects before approving.
    pub request: MachineRequest<'a>,
}

/// The facts the owner reads before a passkey approves one machine.
#[derive(Serialize)]
pub struct MachineRequest<'a> {
    /// The fresh id of the machine's host record.
    pub host_id: Uuid,
    /// The host name the owner reads.
    pub hostname: &'a str,
    /// The join mode, `system` or `user`.
    pub mode: &'static str,
    /// The uid the joined agent runs as (0 for a system join).
    pub execution_uid: u32,
    /// The `SHA256:` fingerprint of the machine's new key; the approval binds to it.
    pub key_fingerprint: &'a str,
}

/// A start reply that passed the shape checks, ready for polling.
pub struct DeviceApproval {
    /// The secret to poll with.
    pub poll_token: Zeroizing<String>,
    /// The code the owner sees in the approval link.
    pub user_code: String,
    /// How long to keep polling.
    pub lifetime: Duration,
}

/// What one redeem poll answered.
pub enum Redemption {
    /// Not approved yet: poll again after the usual interval.
    Pending,
    /// The server asked for patience; `None` means it did not say for how long.
    RetryAfter(Option<Duration>),
    /// Approved: the API key.
    Credential(Zeroizing<String>),
    /// Any other status; the caller maps it to its own failure.
    Other(u16),
}

/// The device-approval request body for one fresh machine: its new host id, the host name
/// the owner reads before approving, the join mode with its execution uid, and the exact key
/// fingerprint the approval binds to.
///
/// Refuses an empty or over-long host name, one with control characters, and
/// anything that is not a canonical `SHA256:` fingerprint of a 32-byte digest.
///
/// # Errors
///
/// [`CheckFailure::InvalidMachine`] when the host name or fingerprint is unusable.
pub fn machine_start_body(
    host_id: Uuid,
    hostname: &str,
    key_fingerprint: &str,
    mode: &'static str,
    execution_uid: u32,
) -> Result<Vec<u8>, CheckFailure> {
    if hostname.is_empty()
        || hostname.len() > MAX_HOSTNAME_LENGTH
        || hostname.chars().any(char::is_control)
        || !valid_fingerprint(key_fingerprint)
    {
        return Err(CheckFailure::InvalidMachine);
    }
    serde_json::to_vec(&MachineStartRequest {
        device: hostname,
        kind: "join_machine",
        request: MachineRequest {
            host_id,
            hostname,
            mode,
            execution_uid,
            key_fingerprint,
        },
    })
    .map_err(|_| CheckFailure::InvalidMachine)
}

/// Whether `value` is `SHA256:` plus the canonical unpadded base64 of exactly 32 bytes.
fn valid_fingerprint(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("SHA256:") else {
        return false;
    };
    let Ok(decoded) = STANDARD_NO_PAD.decode(encoded) else {
        return false;
    };
    decoded.len() == 32 && STANDARD_NO_PAD.encode(decoded) == encoded
}

/// The link the owner opens to approve a machine join; the code travels in the fragment, never to the server log.
#[must_use]
pub fn join_approval_link(server: &Url, user_code: &str) -> String {
    format!(
        "{}/#join={user_code}",
        server.origin().ascii_serialization()
    )
}

/// The default scopes plus the extra ones asked for, each only once; unknown scopes are refused.
///
/// A scope that no action declares is not grantable: a later action that
/// declared it would otherwise become callable by keys already issued.
///
/// # Errors
///
/// [`CheckFailure::InvalidScope`] for a scope no action declares.
pub fn requested_scopes(requested: &[&str]) -> Result<Vec<String>, CheckFailure> {
    let mut scopes = SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect::<Vec<_>>();
    for scope in requested {
        if !ADDITIONAL_SCOPES.contains(scope) && !SCOPES.contains(scope) {
            return Err(CheckFailure::InvalidScope);
        }
        if !scopes.iter().any(|existing| existing == scope) {
            scopes.push((*scope).to_owned());
        }
    }
    Ok(scopes)
}

/// Parses a server address, accepting only a bare HTTPS origin: no path, credentials, query or fragment.
///
/// # Errors
///
/// [`CheckFailure::InvalidServer`] when the input is not a bare HTTPS origin.
pub fn server_url(input: &str) -> Result<Url, CheckFailure> {
    let server = Url::parse(input).map_err(|_| CheckFailure::InvalidServer)?;
    if server.scheme() != "https"
        || server.host_str().is_none()
        || !server.username().is_empty()
        || server.password().is_some()
        || server.query().is_some()
        || server.fragment().is_some()
        || server.path() != "/"
    {
        return Err(CheckFailure::InvalidServer);
    }
    Ok(server)
}

/// The link the owner opens to approve a sign-in; it carries only the user code.
#[must_use]
pub fn approval_link(server: &Url, user_code: &str) -> String {
    let mut link = server.clone();
    link.query_pairs_mut().append_pair("device_code", user_code);
    link.to_string()
}

/// Whether `value` is exactly `expected_length` base64url characters, the shape of every server-made capability.
#[must_use]
pub fn server_capability_has_shape(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Parses and checks a `200` start reply: the token and code shapes and the exact approval lifetime.
///
/// # Errors
///
/// [`CheckFailure::BadResponse`] for malformed JSON, extra fields, wrong shapes or a wrong lifetime.
pub fn parse_start_response(body: &[u8]) -> Result<DeviceApproval, CheckFailure> {
    let started: DeviceStartResponse =
        serde_json::from_slice(body).map_err(|_| CheckFailure::BadResponse)?;
    if !server_capability_has_shape(started.poll_token.as_str(), POLL_TOKEN_LENGTH)
        || !server_capability_has_shape(&started.user_code, USER_CODE_LENGTH)
        || started.expires_in != APPROVAL_LIFETIME_SECONDS
    {
        return Err(CheckFailure::BadResponse);
    }
    Ok(DeviceApproval {
        poll_token: started.poll_token,
        user_code: started.user_code,
        lifetime: Duration::from_secs(started.expires_in),
    })
}

/// Parses a `200` redeem reply into its API key, checking the key's shape.
///
/// A bad body is [`CheckFailure::RedemptionUncertain`], not a plain bad reply:
/// the server may already have spent the approval.
///
/// # Errors
///
/// [`CheckFailure::RedemptionUncertain`] for any body that is not a well-formed key.
pub fn parse_redemption_response(body: &[u8]) -> Result<Zeroizing<String>, CheckFailure> {
    let redeemed: DeviceRedeemResponse =
        serde_json::from_slice(body).map_err(|_| CheckFailure::RedemptionUncertain)?;
    if !server_capability_has_shape(redeemed.api_key.as_str(), POLL_TOKEN_LENGTH) {
        return Err(CheckFailure::RedemptionUncertain);
    }
    Ok(redeemed.api_key)
}

/// Maps one redeem answer: `200` is the credential, `401` still pending, `429` retry later.
///
/// `retry_after` is the parsed `Retry-After` header, if there was one.
///
/// # Errors
///
/// [`CheckFailure::RedemptionUncertain`] when a `200` body cannot be used.
pub fn interpret_redemption(
    status: u16,
    body: &[u8],
    retry_after: Option<Duration>,
) -> Result<Redemption, CheckFailure> {
    match status {
        200 => parse_redemption_response(body).map(Redemption::Credential),
        401 => Ok(Redemption::Pending),
        429 => Ok(Redemption::RetryAfter(retry_after)),
        other => Ok(Redemption::Other(other)),
    }
}

/// Unit tests for the pure checks and wire types.
#[cfg(test)]
mod tests;
