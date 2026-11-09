//! The infraternal agent's part in its own upgrade to root (D274, D376, #399).
//!
//! The server drives a root upgrade of a rootless infraternal agent with five
//! control actions, in this order:
//!
//! | Action | What this infraternal agent does |
//! |---|---|
//! | `privilege.probe` | Finds the way in: passwordless sudo, sudo, doas, or su (D274's order). |
//! | `privilege.key` | Makes the one-use seal key for one attempt and returns its public half. |
//! | `privilege.elevate` | Opens the sealed password, becomes root with it once, and waits for the relay. |
//! | `privilege.pump` | Carries relay bytes both ways. It never reads them. |
//! | `privilege.end` | Closes the relay (or stops an elevation still in flight). |
//!
//! After the handover the *root* infraternal agent gets one more:
//!
//! | `privilege.take_over` | Retires the rootless install it replaced, then leaves standby. |
//!
//! They arrive only on the authenticated server control stream, in their own
//! small lane beside terminal dispatch ([`LANE`], each call bounded by
//! [`CALL_BOUND`]), so a stuck relay can't hold up certificate renewal or
//! terminal startup (J415 B4). They don't go through the plugin worker,
//! because an elevation takes seconds and the relay carries the payload.
//!
//! Nothing the rootless agent does here holds root. The password lives only
//! inside `elevate`, in a wiping buffer. The relay socket sits in a fresh
//! 0700 directory of this account, it accepts one peer, which must be uid 0,
//! and the first frame this agent writes on it is the one-time token it
//! typed to the relay's terminal (J415 B5).
use crate::privilege_elevate::{self, Outcome, Way};
use base64::Engine as _;
use infraternal_plugin_remote::privilege_relay::Frame;
use infraternal_plugin_remote::privilege_seal::{Binding, Method, SealKey};
use serde::Deserialize;
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Mutex, watch},
};

/// How long a seal key waits for its sealed password.
const KEY_LIFETIME: Duration = Duration::from_mins(2);
/// How long sudo, doas or su get to prompt and answer.
const ELEVATE_BOUND: Duration = Duration::from_mins(1);
/// How long the relay gets to connect once root is reached.
const CONNECT_BOUND: Duration = Duration::from_secs(20);
/// Most bytes one pump call returns. With base64 and JSON this stays well
/// under the protocol's 4 MiB frame.
const PUMP_CHUNK: usize = 1 << 20;
/// Longest a pump call waits for the relay to say something.
const PUMP_WAIT: Duration = Duration::from_secs(1);
/// Longest a pump call may take to hand its bytes to the relay. A relay that
/// stops reading for this long is treated as gone (B4).
const PUMP_WRITE: Duration = Duration::from_secs(10);
/// The server pumps a live relay about every second. When no pump has come
/// for this long, the server or its link is gone: the relay is closed, which
/// makes it roll the host back unless the server committed (J415 R4, B1).
const PUMP_IDLE: Duration = Duration::from_secs(30);
/// Most `privilege.*` calls running at once in the daemon's lane.
pub const LANE: usize = 2;
/// Longest any one `privilege.*` call may run before the daemon answers it
/// with a failure: an elevation's prompt and relay bounds, plus margin.
pub const CALL_BOUND: Duration = Duration::from_mins(2);

/// The action ids, as the server sends them.
pub const ACTIONS: [&str; 6] = [
    "privilege.probe",
    "privilege.key",
    "privilege.elevate",
    "privilege.pump",
    "privilege.end",
    "privilege.take_over",
];

/// Everything one upgrade keeps between calls. One per process.
///
/// The lock is held only for short bookkeeping, never across an elevation
/// or a relay read or write (J415 B4, B10).
#[derive(Default)]
struct State {
    /// The one seal key waiting for its password: one per host (B8).
    key: Option<([u8; 16], SealKey, Instant)>,
    /// The elevation in flight, and the switch that stops it (B10).
    elevating: Option<([u8; 16], watch::Sender<bool>)>,
    /// The running relay, if any.
    relay: Option<Arc<Relay>>,
}

/// A relay that reached root and connected.
struct Relay {
    attempt: [u8; 16],
    /// The socket, locked per pump (never under [`State`]'s lock).
    stream: Mutex<UnixStream>,
    /// Keeps sudo, doas or su (and so the relay's terminal) alive.
    elevated: std::sync::Mutex<Option<privilege_elevate::Elevated>>,
    /// The private directory of the socket, removed at the end.
    directory: PathBuf,
    /// When the server last pumped; the watchdog closes an idle relay.
    pumped: std::sync::Mutex<Instant>,
}

/// The one state of this process.
fn state() -> &'static Mutex<State> {
    /// Created on first use; lives as long as the process.
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(Mutex::default)
}

/// Run one `privilege.*` action and return its JSON reply.
///
/// `sessions` is this infraternal agent's private sessions directory (the
/// relay socket goes in a fresh directory under it).
///
/// # Errors
/// A malformed request, an unknown action, or a local failure. The server
/// treats every error as "nothing changed".
pub async fn execute(action: &str, input: &[u8], sessions: &Path) -> io::Result<Vec<u8>> {
    if nix::unistd::Uid::effective().is_root() {
        // A root infraternal agent is already the upgraded one; it only
        // finishes the upgrade that made it (R5).
        return match action {
            "privilege.take_over" => crate::privilege_take_over::execute(input).await,
            _ => Ok(br#"{"full":true}"#.to_vec()),
        };
    }
    match action {
        "privilege.probe" => Ok(probe().await.into_bytes()),
        "privilege.key" => key(input).await,
        "privilege.elevate" => elevate(input, sessions).await,
        "privilege.pump" => pump(input).await,
        "privilege.end" => end(input).await,
        _ => Err(io::ErrorKind::Unsupported.into()),
    }
}

/// An invalid request.
fn invalid() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}

/// Parse a 32-character lowercase hex attempt id.
fn attempt_id(text: &str) -> io::Result<[u8; 16]> {
    uuid::Uuid::try_parse(text)
        .map(|id| *id.as_bytes())
        .map_err(|_| invalid())
}

/// Run a probe command with no input, a clean environment and a bound;
/// return its exit success and its combined output.
async fn quiet(program: &str, args: &[&str]) -> Option<(bool, String)> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Some((output.status.success(), text))
}

/// The first of `paths` that exists.
fn first(paths: &[&'static str]) -> Option<&'static str> {
    paths.iter().copied().find(|path| Path::new(path).exists())
}

/// What sudo said, without a password.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Sudo {
    /// sudo isn't installed.
    #[default]
    Absent,
    /// `sudo -n true` worked: passwordless sudo.
    NoPassword,
    /// sudo is installed and wants a password (or refuses; it can't say which).
    Password,
}

/// What the probe learned about this host, before choosing the way in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Facts {
    /// What sudo said.
    sudo: Sudo,
    /// The account is in a group that conventionally may use sudo or doas
    /// (`wheel`, `sudo`, `admin`).
    admin_group: bool,
    /// doas is installed and has a rule for this account.
    doas: bool,
    /// su is installed.
    su: bool,
}

/// Choose the way in from the facts, in D274's order, as `(way, denied)`.
///
/// `sudo -n -l` can't tell "sudo needs your password" from "you may not use
/// sudo at all": sudo asks for the password before it checks the rules, so
/// both answer "a password is required" (seen for real on `AlmaLinux` 10, #399).
/// Membership in an admin group decides instead. An account outside them is
/// offered su with the root password, and is told sudo isn't allowed for it
/// (D286's "denied"). An account with a per-user sudo rule outside those
/// groups gets the same: elevating with sudo would report `denied` anyway if
/// the guess were wrong, never a wrong password.
fn choose(facts: Facts) -> (&'static str, bool) {
    match facts.sudo {
        Sudo::NoPassword => ("sudo-nopasswd", false),
        Sudo::Password if facts.admin_group => ("sudo", false),
        _ if facts.doas => ("doas", false),
        sudo if facts.su => ("su", sudo != Sudo::Absent),
        _ => ("none", true),
    }
}

/// Whether this process's account is in a conventional admin group.
fn in_admin_group() -> bool {
    nix::unistd::getgroups().is_ok_and(|groups| {
        groups
            .into_iter()
            .chain([nix::unistd::getegid()])
            .any(|gid| {
                nix::unistd::Group::from_gid(gid)
                    .ok()
                    .flatten()
                    .is_some_and(|group| matches!(group.name.as_str(), "wheel" | "sudo" | "admin"))
            })
    })
}

/// Find the way in, in D274's order. Never prompts and never sends a password.
async fn probe() -> String {
    let mut facts = Facts {
        admin_group: in_admin_group(),
        su: first(&["/bin/su", "/usr/bin/su"]).is_some(),
        ..Facts::default()
    };
    if let Some(sudo) = first(&["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"]) {
        facts.sudo = if matches!(quiet(sudo, &["-n", "true"]).await, Some((true, _))) {
            Sudo::NoPassword
        } else {
            Sudo::Password
        };
    }
    if let Some(doas) = first(&["/usr/bin/doas", "/bin/doas", "/usr/local/bin/doas"]) {
        // doas checks its rules before asking, so "Authorization required"
        // means a rule exists; "Operation not permitted" means none does.
        facts.doas = quiet(doas, &["-n", "true"])
            .await
            .is_some_and(|(ok, text)| {
                ok || text.contains("Authorization required")
                    || text.contains("a password is required")
            });
    }
    let (way, denied) = choose(facts);
    format!(r#"{{"way":"{way}","denied":{denied}}}"#)
}

/// `privilege.key {attempt}`: a fresh one-use seal key for this attempt.
async fn key(input: &[u8]) -> io::Result<Vec<u8>> {
    /// The `privilege.key` request body.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        attempt: String,
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| invalid())?;
    let attempt = attempt_id(&request.attempt)?;
    let key = SealKey::new().map_err(|_| io::Error::other("random source"))?;
    let public = base64::engine::general_purpose::STANDARD.encode(key.public());
    let mut state = state().lock().await;
    // B8: one waiting key per host, and an attempt is keyed once. A second
    // attempt waits for the first key to be used or to expire; re-keying the
    // same attempt is refused rather than silently replacing its key.
    if let Some((waiting, _, made)) = &state.key
        && made.elapsed() < KEY_LIFETIME
    {
        return Err(if *waiting == attempt {
            invalid()
        } else {
            io::ErrorKind::WouldBlock.into()
        });
    }
    state.key = Some((attempt, key, Instant::now()));
    Ok(format!(r#"{{"key":"{public}"}}"#).into_bytes())
}

/// The way named in a request.
fn way(word: &str) -> io::Result<Way> {
    match word {
        "sudo-nopasswd" => Ok(Way::SudoNoPassword),
        "sudo" => Ok(Way::Sudo),
        "doas" => Ok(Way::Doas),
        "su" => Ok(Way::Su),
        _ => Err(invalid()),
    }
}

/// `privilege.elevate {attempt, host, way, sealed?, digest}`: open the sealed
/// password (when the way needs one), become root once, and wait for the
/// relay to connect. Replies `{"outcome": …, "typed": bool}`; `typed` says
/// whether the password reached PAM, which then counts the try even on a
/// timeout or failure (J415 B2).
///
/// The process-wide lock is not held while sudo, doas or su run, so
/// `privilege.end` can stop an elevation in flight (B10).
async fn elevate(input: &[u8], sessions: &Path) -> io::Result<Vec<u8>> {
    /// The `privilege.elevate` request body.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        attempt: String,
        host: String,
        way: String,
        sealed: Option<String>,
        digest: String,
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| invalid())?;
    let attempt = attempt_id(&request.attempt)?;
    let host = attempt_id(&request.host)?;
    let way = way(&request.way)?;
    if request.digest.len() != 64
        || !request
            .digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    // Passwordless sudo takes no password; every other way needs one.
    if (way == Way::SudoNoPassword) == request.sealed.is_some() {
        return Err(invalid());
    }
    let (cancel, mut cancelled) = watch::channel(false);
    let key = {
        let mut state = state().lock().await;
        if state.relay.is_some() || state.elevating.is_some() {
            return Ok(br#"{"outcome":"busy","typed":false}"#.to_vec());
        }
        // The key is taken out before anything is checked, so it opens at
        // most one blob whatever happens next.
        let key = state
            .key
            .take_if(|(waiting, _, _)| *waiting == attempt)
            .map(|(_, key, made)| (key, made));
        state.elevating = Some((attempt, cancel));
        key
    };
    let result = elevate_unlocked(
        way,
        host,
        attempt,
        key,
        request.sealed,
        &request.digest,
        sessions,
        &mut cancelled,
    )
    .await;
    let mut state = state().lock().await;
    state.elevating = None;
    let (word, typed, relay) = match result {
        Ok(done) => done,
        Err(error) => return Err(error),
    };
    if let Some(relay) = relay {
        state.relay = Some(Arc::new(relay));
        tokio::spawn(watchdog(attempt));
    }
    Ok(format!(r#"{{"outcome":"{word}","typed":{typed}}}"#).into_bytes())
}

/// The body of [`elevate`], run without the process-wide lock. Returns the
/// outcome word, whether the password was typed, and the connected relay.
async fn elevate_unlocked(
    way: Way,
    host: [u8; 16],
    attempt: [u8; 16],
    key: Option<(SealKey, Instant)>,
    sealed: Option<String>,
    digest: &str,
    sessions: &Path,
    cancelled: &mut watch::Receiver<bool>,
) -> io::Result<(&'static str, bool, Option<Relay>)> {
    let secret = match (way, sealed) {
        (Way::SudoNoPassword, None) => None,
        (Way::SudoNoPassword, Some(_)) | (_, None) => return Err(invalid()),
        (way, Some(sealed)) => {
            let (key, made) = key.ok_or_else(invalid)?;
            if made.elapsed() >= KEY_LIFETIME {
                return Ok(("timeout", false, None));
            }
            let sealed = base64::engine::general_purpose::STANDARD
                .decode(sealed)
                .map_err(|_| invalid())?;
            let method = match way {
                Way::Doas => Method::Doas,
                Way::Su => Method::Su,
                _ => Method::Sudo,
            };
            Some(
                key.open(
                    &Binding {
                        host,
                        attempt,
                        method,
                    },
                    &sealed,
                )
                .map_err(|_| invalid())?,
            )
        }
    };
    // Short, under the 108-byte cap on Unix socket paths however long the
    // account's home is; a clash only fails this one try.
    let directory = sessions.join(format!(
        "privilege-{}",
        &uuid::Uuid::from_bytes(attempt).simple().to_string()[..12]
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let socket = directory.join("relay.sock");
    let listener = UnixListener::bind(&socket)?;
    let exe = std::env::current_exe()?;
    let uid = nix::unistd::Uid::effective().as_raw().to_string();
    let token = zeroize::Zeroizing::new(rand_token()?);
    let exe = exe.to_string_lossy().into_owned();
    let socket_text = socket.to_string_lossy().into_owned();
    let tried = tokio::select! {
        biased;
        _ = cancelled.wait_for(|stop| *stop) => None,
        tried = privilege_elevate::elevate(
            way,
            secret.as_deref().map(|secret| &secret[..]),
            &token,
            [&exe, digest, &socket_text, &uid],
            ELEVATE_BOUND,
        ) => Some(tried?),
    };
    drop(secret);
    let Some(tried) = tried else {
        // Stopped by `privilege.end`: dropping the elevation future killed
        // sudo, doas or su. Whether the password had reached PAM is unknown,
        // so it counts.
        let _ = std::fs::remove_dir_all(&directory);
        return Ok(("cancelled", secret_was_sent(way), None));
    };
    let connected = match (tried.outcome, tried.elevated) {
        (Outcome::Started, Some(elevated)) => {
            let accepted = tokio::select! {
                biased;
                _ = cancelled.wait_for(|stop| *stop) => None,
                accepted = tokio::time::timeout(CONNECT_BOUND, listener.accept()) => accepted.ok().and_then(Result::ok),
            };
            match accepted {
                Some((mut stream, _)) if stream.peer_cred().is_ok_and(|cred| cred.uid() == 0) => {
                    // B5: our first frame proves to the relay that we are the
                    // process that typed its token.
                    let mut first = Vec::with_capacity(41);
                    Frame::Token { bytes: *token }.encode(&mut first);
                    match tokio::time::timeout(PUMP_WRITE, stream.write_all(&first)).await {
                        Ok(Ok(())) => Some((stream, elevated)),
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        _ => None,
    };
    drop(listener);
    let _ = std::fs::remove_file(&socket);
    let word = match (tried.outcome, &connected) {
        (Outcome::Started, Some(_)) => "started",
        (Outcome::Wrong, _) => "wrong",
        (Outcome::Denied, _) => "denied",
        (Outcome::Mismatch, _) => "mismatch",
        (Outcome::Timeout, _) => "timeout",
        (Outcome::RootShell, _) => "rootshell",
        (Outcome::Started, None) | (Outcome::Failed, _) => "failed",
    };
    let relay = if let Some((stream, elevated)) = connected {
        Some(Relay {
            attempt,
            stream: Mutex::new(stream),
            elevated: std::sync::Mutex::new(Some(elevated)),
            directory,
            pumped: std::sync::Mutex::new(Instant::now()),
        })
    } else {
        let _ = std::fs::remove_dir_all(&directory);
        None
    };
    Ok((word, tried.typed, relay))
}

/// Whether a cancelled elevation may already have handed its password to
/// PAM. It can't be known once the command ran, so every way with a
/// password counts (the safe side of D376's two tries).
const fn secret_was_sent(way: Way) -> bool {
    !matches!(way, Way::SudoNoPassword)
}

/// 32 random bytes for the relay's one-time token.
fn rand_token() -> io::Result<[u8; 32]> {
    infraternal_plugin_remote::privilege_seal::random_token()
        .map_err(|_| io::Error::other("random source"))
}

/// The relay of `attempt`, without holding the process-wide lock after.
async fn relay_of(attempt: [u8; 16]) -> io::Result<Arc<Relay>> {
    state()
        .lock()
        .await
        .relay
        .clone()
        .filter(|relay| relay.attempt == attempt)
        .ok_or_else(invalid)
}

/// `privilege.pump {attempt, send}`: write `send` (base64) to the relay, then
/// return what it says within [`PUMP_WAIT`] as `{"recv": base64, "closed": bool}`.
///
/// The write is bounded by [`PUMP_WRITE`]; a relay that stops reading is
/// treated as gone, and its end (rollback included) is the relay's own (B4).
async fn pump(input: &[u8]) -> io::Result<Vec<u8>> {
    /// The `privilege.pump` request body.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        attempt: String,
        send: String,
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| invalid())?;
    let attempt = attempt_id(&request.attempt)?;
    let send = base64::engine::general_purpose::STANDARD
        .decode(request.send)
        .map_err(|_| invalid())?;
    let relay = relay_of(attempt).await?;
    *relay
        .pumped
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    let mut received = vec![0; PUMP_CHUNK];
    let mut filled = 0;
    let mut closed = false;
    {
        let Ok(mut stream) = tokio::time::timeout(PUMP_WRITE, relay.stream.lock()).await else {
            return Err(io::ErrorKind::TimedOut.into());
        };
        if !send.is_empty()
            && !matches!(
                tokio::time::timeout(PUMP_WRITE, stream.write_all(&send)).await,
                Ok(Ok(()))
            )
        {
            closed = true;
        }
        // Wait for the first bytes, then take whatever else is already there.
        if !closed {
            match tokio::time::timeout(PUMP_WAIT, stream.read(&mut received)).await {
                Ok(Ok(0) | Err(_)) => closed = true,
                Ok(Ok(read)) => filled = read,
                Err(_) => {}
            }
        }
        while !closed && filled < PUMP_CHUNK {
            match stream.try_read(&mut received[filled..]) {
                Ok(0) => closed = true,
                Ok(read) => filled += read,
                Err(_) => break,
            }
        }
    }
    received.truncate(filled);
    let recv = base64::engine::general_purpose::STANDARD.encode(&received);
    if closed {
        close(attempt).await;
    }
    Ok(format!(r#"{{"recv":"{recv}","closed":{closed}}}"#).into_bytes())
}

/// Close the relay of `attempt` once the server stops pumping it for
/// [`PUMP_IDLE`]: a server restart or a lost link must not keep a root
/// relay waiting for its whole lifetime (J415 R4, B1).
async fn watchdog(attempt: [u8; 16]) {
    loop {
        // sleep: check the relay's last pump on a slow, fixed beat.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Ok(relay) = relay_of(attempt).await else {
            return;
        };
        let idle = relay
            .pumped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed();
        drop(relay);
        if idle >= PUMP_IDLE {
            close(attempt).await;
            return;
        }
    }
}

/// `privilege.end {attempt}`: close the relay of this attempt, stop its
/// elevation if one is still in flight, and drop its unused key.
async fn end(input: &[u8]) -> io::Result<Vec<u8>> {
    /// The `privilege.end` request body.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        attempt: String,
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| invalid())?;
    let attempt = attempt_id(&request.attempt)?;
    {
        let mut state = state().lock().await;
        if state
            .key
            .as_ref()
            .is_some_and(|(waiting, _, _)| *waiting == attempt)
        {
            state.key = None;
        }
        if let Some((elevating, stop)) = &state.elevating
            && *elevating == attempt
        {
            stop.send_replace(true);
        }
    }
    close(attempt).await;
    Ok(br#"{"ended":true}"#.to_vec())
}

/// Take the relay of `attempt` out of the state and let it go: closing the
/// socket makes the relay stop its steps and, unless the server committed,
/// roll the host back (J415 R4). Then the terminal is released.
async fn close(attempt: [u8; 16]) {
    let relay = {
        let mut state = state().lock().await;
        state.relay.take_if(|relay| relay.attempt == attempt)
    };
    let Some(relay) = relay else {
        return;
    };
    // Closing our end of the socket is the relay's signal to end.
    let _ = relay.stream.lock().await.shutdown().await;
    let elevated = relay
        .elevated
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(mut elevated) = elevated {
        // The relay ignores the terminal's hangup and finishes its rollback
        // on its own; this only reaps sudo, doas or su.
        let _ = tokio::time::timeout(Duration::from_secs(5), elevated.child.wait()).await;
    }
    let _ = std::fs::remove_dir_all(&relay.directory);
}

use std::os::unix::fs::DirBuilderExt as _;

#[cfg(test)]
mod tests {
    //! Requests are checked before anything runs.
    use super::*;

    /// D274's order, and the denied case found on the guest: sudo installed
    /// but the account outside the admin groups gets su, marked denied.
    #[test]
    fn the_way_in_follows_d274s_order() {
        let base = Facts {
            sudo: Sudo::Password,
            su: true,
            ..Facts::default()
        };
        assert_eq!(
            choose(Facts {
                sudo: Sudo::NoPassword,
                ..base
            }),
            ("sudo-nopasswd", false)
        );
        assert_eq!(
            choose(Facts {
                admin_group: true,
                ..base
            }),
            ("sudo", false)
        );
        assert_eq!(choose(base), ("su", true));
        assert_eq!(
            choose(Facts {
                doas: true,
                sudo: Sudo::Absent,
                ..base
            }),
            ("doas", false)
        );
        assert_eq!(
            choose(Facts {
                sudo: Sudo::Absent,
                ..base
            }),
            ("su", false)
        );
        assert_eq!(choose(Facts::default()), ("none", true));
    }

    /// Attempt ids must be UUIDs; anything else is refused.
    #[test]
    fn attempt_ids_are_strict() {
        assert!(attempt_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(attempt_id("../../etc").is_err());
        assert!(attempt_id("").is_err());
    }

    /// Unknown ways and a sealed password for passwordless sudo are refused.
    #[tokio::test]
    async fn malformed_elevations_are_refused_before_anything_runs() {
        let dir = std::env::temp_dir();
        for body in [
            r#"{"attempt":"0123456789abcdef0123456789abcdef","host":"0123456789abcdef0123456789abcdef","way":"pkexec","digest":"00"}"#,
            r#"{"attempt":"0123456789abcdef0123456789abcdef","host":"0123456789abcdef0123456789abcdef","way":"sudo-nopasswd","sealed":"AA==","digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
            r#"{"attempt":"0123456789abcdef0123456789abcdef","host":"0123456789abcdef0123456789abcdef","way":"sudo","digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
            r#"{"attempt":"x","host":"y","way":"sudo","digest":"z","extra":1}"#,
        ] {
            if nix::unistd::Uid::effective().is_root() {
                return;
            }
            assert!(
                execute("privilege.elevate", body.as_bytes(), &dir)
                    .await
                    .is_err(),
                "{body}"
            );
        }
    }

    /// B8: one waiting key per host. A second attempt waits, and an
    /// attempt can't be keyed twice; once ended, a new key can be made.
    #[tokio::test]
    async fn one_seal_key_waits_at_a_time() {
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let dir = std::env::temp_dir();
        let call = |action: &'static str, id: &'static str| {
            let dir = dir.clone();
            async move {
                execute(action, format!(r#"{{"attempt":"{id}"}}"#).as_bytes(), &dir)
                    .await
                    .is_ok()
            }
        };
        let first = "10000000000000000000000000000001";
        let second = "10000000000000000000000000000002";
        assert!(call("privilege.key", first).await);
        assert!(!call("privilege.key", first).await);
        assert!(!call("privilege.key", second).await);
        assert!(call("privilege.end", first).await);
        assert!(call("privilege.key", second).await);
        assert!(call("privilege.end", second).await);
    }

    /// Pumping without a relay is refused.
    #[tokio::test]
    async fn pumping_needs_a_relay() {
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let body = r#"{"attempt":"20000000000000000000000000000001","send":""}"#;
        assert!(
            execute("privilege.pump", body.as_bytes(), &std::env::temp_dir())
                .await
                .is_err()
        );
    }
}
