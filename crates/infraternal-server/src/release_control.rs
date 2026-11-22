//! The server's update controls over its private control socket, for `infraternal server update` (#211, D400).
//!
//! The running server already listens on `<data>/restart/control.sock`, a 0600 socket in a 0700
//! folder that only its own account (and root) can open; the restart and database checks use it.
//! This module adds one request kind to that socket: "run this `release.update.*` action". It is
//! how an operator on the server machine updates the server from a shell, without a browser and
//! without a passkey.
//!
//! **Why no passkey (D400).** The caller is identified by the kernel (`SO_PEERCRED`), not by
//! anything it sends: it must be root or the account the server runs as. Either one can already
//! replace the server's binary and its data on disk, so asking it for a passkey would protect
//! nothing. The action therefore runs as the *local operator* ([`ReleaseService::call`] with no
//! socket host), the same authority the local `server channel` command has always had. Every
//! other device (the web app, a remote CLI) still goes through the WebSocket API, where the
//! owner with a fresh passkey tap is required, unchanged.
//!
//! **One service.** The action runs in the server process, through the very [`ReleaseService`]
//! the release plugin serves on the WebSocket ([`register`] is called when the plugin is built).
//! Apply and roll back must run there: they wake the server's own quiet-window task and restart
//! loop, which another process cannot reach.
//!
//! **Wire format** (after the control socket's common header `[0, 0, 3]`):
//! - request: a big-endian `u16` length, then that many bytes of JSON
//!   `{"action": "<id>", "input": {…}}`, at most [`MAX_REQUEST`] bytes;
//! - reply: a big-endian `u32` length, then JSON `{"ok": true, "value": …}` or
//!   `{"ok": false, "error": "<fixed sentence>"}`, at most [`MAX_REPLY`] bytes.
//!
//! An apply or roll back restarts the server warm right after it answers, which closes this
//! connection; the reply can therefore be lost. Callers treat a closed connection after such a
//! request as "the switch started" and read the outcome from `release.update.status`.
use infraternal_plugin_release::{
    descriptor::{
        UPDATE_APPLY, UPDATE_CANCEL, UPDATE_CHECK, UPDATE_HISTORY, UPDATE_ROLLBACK,
        UPDATE_SETTINGS, UPDATE_STATUS,
    },
    service::ReleaseService,
};
use serde_json::{Value, json};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

/// The control socket's header for a release action: a zero length, then opcode 3.
///
/// Opcodes 1 (CA status) and 2 (open database) are the restart control's own.
pub const RELEASE_REQUEST: [u8; 3] = [0, 0, 3];
/// The opcode byte of [`RELEASE_REQUEST`], as the restart control reads it.
pub const RELEASE_OPCODE: u8 = 3;
/// Largest request body: an action id and a small input object.
pub const MAX_REQUEST: usize = 2048;
/// Largest reply body. A status is about 1 KiB and the history (30 entries) a few KiB.
pub const MAX_REPLY: usize = 256 * 1024;
/// How long either side waits for the other to send its part.
const IO_LIMIT: Duration = Duration::from_secs(5);
/// How long an action may take: a check downloads and verifies a release (bounded at 60 s by
/// the downloader), so allow a little more.
const ACTION_LIMIT: Duration = Duration::from_secs(150);

/// The actions this socket runs. Channel changes keep their own `server channel` command,
/// which works on a stopped server too.
pub const LOCAL_ACTIONS: [&str; 7] = [
    UPDATE_STATUS.id,
    UPDATE_CHECK.id,
    UPDATE_APPLY.id,
    UPDATE_ROLLBACK.id,
    UPDATE_CANCEL.id,
    UPDATE_HISTORY.id,
    UPDATE_SETTINGS.id,
];

/// The running server's release service and the data folder it serves.
static REGISTERED: Mutex<Option<(PathBuf, ReleaseService)>> = Mutex::new(None);

/// Remember `service` as the one that serves the data folder `state`.
///
/// The release plugin calls this when the server builds it. A process runs one server, so the
/// latest registration wins; [`registered`] still checks the folder, so a service built for
/// another folder (in tests) never answers for this one.
pub fn register(state: &Path, service: ReleaseService) {
    let state = state.canonicalize().unwrap_or_else(|_| state.to_owned());
    *REGISTERED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((state, service));
}

/// The service registered for the data folder `data`, if any.
#[must_use]
pub fn registered(data: &Path) -> Option<ReleaseService> {
    let data = data.canonicalize().ok()?;
    REGISTERED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .filter(|(state, _)| *state == data)
        .map(|(_, service)| service.clone())
}

/// Whether a caller with kernel uid `peer` may run update actions on a server whose process
/// runs as `server` (D400): root, or the server's own account. Nobody else.
#[must_use]
pub fn caller_allowed(peer: u32, server: u32) -> bool {
    peer == 0 || peer == server
}

/// One parsed request.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// One of [`LOCAL_ACTIONS`].
    action: String,
    /// The action's JSON input object.
    input: Value,
}

/// Answer one release request on `stream`, whose header ([`RELEASE_REQUEST`]) was already read.
///
/// The caller must have checked the peer with [`caller_allowed`] first. Runs the action as the
/// local operator (no passkey, D400) and writes the reply. Run it in its own task: an apply or
/// roll back ends in a warm restart, and the control loop must stay free to perform it.
///
/// # Errors
/// I/O and framing failures; the connection is then simply closed.
pub async fn answer(stream: &mut UnixStream, service: Option<ReleaseService>) -> io::Result<()> {
    let length = tokio::time::timeout(IO_LIMIT, stream.read_u16())
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    let length = usize::from(length);
    if length == 0 || length > MAX_REQUEST {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0; length];
    tokio::time::timeout(IO_LIMIT, stream.read_exact(&mut body))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    let request = serde_json::from_slice::<Request>(&body);
    let action = request
        .as_ref()
        .ok()
        .and_then(|request| LOCAL_ACTIONS.iter().find(|id| **id == request.action))
        .copied();
    let reply = match (request, service) {
        (Err(_), _) => json!({"ok":false,"error":"invalid input"}),
        (Ok(request), _) if !LOCAL_ACTIONS.contains(&request.action.as_str()) => {
            json!({"ok":false,"error":"not an update action"})
        }
        (Ok(_), None) => json!({"ok":false,"error":"release unavailable"}),
        (Ok(request), Some(service)) => {
            let input = serde_json::to_vec(&request.input).unwrap_or_default();
            match tokio::time::timeout(ACTION_LIMIT, service.call(&request.action, &input, None))
                .await
            {
                Ok(Ok(value)) => json!({"ok":true,"value":value}),
                Ok(Err(error)) => json!({"ok":false,"error":error}),
                Err(_) => json!({"ok":false,"error":"the server did not finish in time"}),
            }
        }
    };
    // Only the fixed action id and the outcome are logged, never the input or the answer.
    tracing::info!(
        action = action.unwrap_or("unknown"),
        ok = reply["ok"].as_bool().unwrap_or(false),
        "server_update_control"
    );
    let payload = serde_json::to_vec(&reply).map_err(io::Error::other)?;
    if payload.len() > MAX_REPLY {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let length = u32::try_from(payload.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    tokio::time::timeout(IO_LIMIT, async {
        stream.write_u32(length).await?;
        stream.write_all(&payload).await
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

/// Why a [`call`] did not return the action's answer.
#[derive(Debug, PartialEq, Eq)]
pub enum CallError {
    /// No server answers on this data folder's control socket.
    NotRunning,
    /// This account may not open the socket, or the process behind it is not the server's
    /// account: run it as root (or the server's account) on the server machine.
    NotAllowed,
    /// The connection closed before a reply. After an apply or roll back this is expected:
    /// the server restarted warm.
    Closed,
    /// The server refused the action, with its fixed sentence.
    Refused(String),
    /// The reply did not follow the format, or the socket failed in another way.
    Broken,
}

/// Run one `release.update.*` action on the server whose data folder is `data`.
///
/// Connects to `<data>/restart/control.sock` and checks the process at the other end by its
/// kernel credentials before sending anything: it must run as this account, or, when this is
/// root, as the account that owns `data` (the server's account). Then it sends `action` with
/// `input` and returns the action's JSON answer.
///
/// # Errors
/// See [`CallError`].
pub async fn call(data: &Path, action: &str, input: &Value) -> Result<Value, CallError> {
    use std::os::unix::fs::MetadataExt;
    let mut stream = match UnixStream::connect(data.join("restart/control.sock")).await {
        Ok(stream) => stream,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return Err(CallError::NotAllowed);
        }
        Err(_) => return Err(CallError::NotRunning),
    };
    let me = nix::unistd::geteuid().as_raw();
    let peer = stream.peer_cred().map_err(|_| CallError::Broken)?.uid();
    let owner = std::fs::metadata(data).map(|m| m.uid()).ok();
    if peer != me && !(me == 0 && Some(peer) == owner) {
        return Err(CallError::NotAllowed);
    }
    let body = serde_json::to_vec(&Request {
        action: action.to_owned(),
        input: input.clone(),
    })
    .map_err(|_| CallError::Broken)?;
    if body.len() > MAX_REQUEST {
        return Err(CallError::Broken);
    }
    let length = u16::try_from(body.len()).map_err(|_| CallError::Broken)?;
    let sent = tokio::time::timeout(IO_LIMIT, async {
        stream.write_all(&RELEASE_REQUEST).await?;
        stream.write_u16(length).await?;
        stream.write_all(&body).await
    })
    .await;
    if !matches!(sent, Ok(Ok(()))) {
        return Err(CallError::Closed);
    }
    let received = tokio::time::timeout(ACTION_LIMIT + IO_LIMIT, async {
        let length = usize::try_from(stream.read_u32().await?).unwrap_or(usize::MAX);
        if length == 0 || length > MAX_REPLY {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        Ok(payload)
    })
    .await;
    let payload = match received {
        Ok(Ok(payload)) => payload,
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(CallError::Closed);
        }
        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset => {
            return Err(CallError::Closed);
        }
        _ => return Err(CallError::Broken),
    };
    let reply: Value = serde_json::from_slice(&payload).map_err(|_| CallError::Broken)?;
    match (
        reply["ok"].as_bool(),
        reply.get("value"),
        reply["error"].as_str(),
    ) {
        (Some(true), Some(value), _) => Ok(value.clone()),
        (Some(false), _, Some(error)) => Err(CallError::Refused(error.to_owned())),
        _ => Err(CallError::Broken),
    }
}

#[cfg(test)]
mod tests {
    //! The caller rule on its own; the socket round trip is proved in `release_update_tests`.
    use super::caller_allowed;

    /// Root and the server's own account may update; every other account may not (D400).
    #[test]
    fn only_root_or_the_servers_account_may_update() {
        assert!(caller_allowed(0, 0));
        assert!(caller_allowed(0, 991));
        assert!(caller_allowed(991, 991));
        assert!(!caller_allowed(1000, 0));
        assert!(!caller_allowed(1000, 991));
        assert!(!caller_allowed(65534, 0));
    }
}
