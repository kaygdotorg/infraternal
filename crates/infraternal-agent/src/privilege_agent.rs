//! The rootless infraternal agent's part in its own upgrade to root (D274, D376, #399).
//!
//! The server drives a root upgrade with five control actions, in this order:
//!
//! | Action | What this infraternal agent does |
//! |---|---|
//! | `privilege.probe` | Finds the way in: passwordless sudo, sudo, doas, or su (D274's order). |
//! | `privilege.key` | Makes a one-use seal key for one attempt and returns its public half. |
//! | `privilege.elevate` | Opens the sealed password, becomes root with it once, and waits for the relay. |
//! | `privilege.pump` | Carries relay bytes both ways. It never reads them. |
//! | `privilege.end` | Closes the relay. |
//!
//! They arrive only on the authenticated server control stream and run here,
//! beside terminal dispatch. They don't go through the plugin worker, because
//! an elevation takes seconds and the relay carries the 28 MB payload.
//!
//! Nothing here ever holds root. The password lives only inside `elevate`, in
//! a wiping buffer. The relay socket sits in a fresh 0700 directory of this
//! account, and it accepts one peer, which must be uid 0.
use crate::privilege_elevate::{self, Outcome, Way};
use base64::Engine as _;
use infraternal_plugin_remote::privilege_seal::{Binding, Method, SealKey};
use serde::Deserialize;
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};

/// How long a seal key waits for its sealed password.
const KEY_LIFETIME: Duration = Duration::from_secs(120);
/// How long sudo, doas or su get to prompt and answer.
const ELEVATE_BOUND: Duration = Duration::from_secs(60);
/// How long the relay gets to connect once root is reached.
const CONNECT_BOUND: Duration = Duration::from_secs(20);
/// Most bytes one pump call returns. With base64 and JSON this stays well
/// under the protocol's 4 MiB frame.
const PUMP_CHUNK: usize = 1 << 20;
/// Longest a pump call waits for the relay to say something.
const PUMP_WAIT: Duration = Duration::from_secs(1);

/// The action ids, as the server sends them.
pub const ACTIONS: [&str; 5] = [
    "privilege.probe",
    "privilege.key",
    "privilege.elevate",
    "privilege.pump",
    "privilege.end",
];

/// Everything one upgrade keeps between calls. One per process.
#[derive(Default)]
struct State {
    /// Seal keys waiting for their password, by attempt.
    keys: HashMap<[u8; 16], (SealKey, Instant)>,
    /// The running relay, if any.
    relay: Option<Relay>,
}

/// A relay that reached root and connected.
struct Relay {
    attempt: [u8; 16],
    stream: UnixStream,
    /// Keeps sudo, doas or su (and so the relay) alive; dropping it ends them.
    elevated: privilege_elevate::Elevated,
    /// The private directory of the socket, removed at the end.
    directory: PathBuf,
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
        // A root infraternal agent is already the upgraded one.
        return Ok(br#"{"full":true}"#.to_vec());
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
    state
        .keys
        .retain(|_, (_, made)| made.elapsed() < KEY_LIFETIME);
    // At most two waiting keys: an upgrade has one try in flight at a time.
    if state.keys.len() >= 2 && !state.keys.contains_key(&attempt) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    state.keys.insert(attempt, (key, Instant::now()));
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
/// relay to connect. Replies `{"outcome": …}`.
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
    let mut state = state().lock().await;
    if state.relay.is_some() {
        return Ok(br#"{"outcome":"busy"}"#.to_vec());
    }
    let key = state.keys.remove(&attempt);
    let secret = match (way, request.sealed) {
        (Way::SudoNoPassword, None) => None,
        (Way::SudoNoPassword, Some(_)) | (_, None) => return Err(invalid()),
        (way, Some(sealed)) => {
            let (key, made) = key.ok_or_else(invalid)?;
            if made.elapsed() >= KEY_LIFETIME {
                return Ok(br#"{"outcome":"timeout"}"#.to_vec());
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
    let directory = sessions.join(format!(
        "privilege-{}",
        uuid::Uuid::from_bytes(attempt).simple()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let socket = directory.join("relay.sock");
    let listener = UnixListener::bind(&socket)?;
    let exe = std::env::current_exe()?;
    let uid = nix::unistd::Uid::effective().as_raw().to_string();
    let (outcome, elevated) = privilege_elevate::elevate(
        way,
        secret.as_deref().map(|secret| &secret[..]),
        [
            &exe.to_string_lossy(),
            &request.digest,
            &socket.to_string_lossy(),
            &uid,
        ],
        ELEVATE_BOUND,
    )
    .await?;
    drop(secret);
    let connected = match (outcome, elevated) {
        (Outcome::Started, Some(elevated)) => {
            match tokio::time::timeout(CONNECT_BOUND, listener.accept()).await {
                Ok(Ok((stream, _))) if stream.peer_cred().is_ok_and(|cred| cred.uid() == 0) => {
                    Some((stream, elevated))
                }
                _ => None,
            }
        }
        _ => None,
    };
    drop(listener);
    let _ = std::fs::remove_file(&socket);
    let word = match (outcome, &connected) {
        (Outcome::Started, Some(_)) => "started",
        (Outcome::Started, None) | (Outcome::Failed, _) => "failed",
        (Outcome::Wrong, _) => "wrong",
        (Outcome::Denied, _) => "denied",
        (Outcome::Mismatch, _) => "mismatch",
        (Outcome::Timeout, _) => "timeout",
    };
    match connected {
        Some((stream, elevated)) => {
            state.relay = Some(Relay {
                attempt,
                stream,
                elevated,
                directory,
            });
        }
        None => {
            let _ = std::fs::remove_dir_all(&directory);
        }
    }
    Ok(format!(r#"{{"outcome":"{word}"}}"#).into_bytes())
}

/// `privilege.pump {attempt, send}`: write `send` (base64) to the relay, then
/// return what it says within [`PUMP_WAIT`] as `{"recv": base64, "closed": bool}`.
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
    let mut state = state().lock().await;
    let relay = state
        .relay
        .as_mut()
        .filter(|relay| relay.attempt == attempt)
        .ok_or_else(invalid)?;
    if !send.is_empty() {
        relay.stream.write_all(&send).await?;
    }
    let mut received = vec![0; PUMP_CHUNK];
    let mut filled = 0;
    let mut closed = false;
    // Wait for the first bytes, then take whatever else is already there.
    match tokio::time::timeout(PUMP_WAIT, relay.stream.read(&mut received)).await {
        Ok(Ok(0) | Err(_)) => closed = true,
        Ok(Ok(read)) => filled = read,
        Err(_) => {}
    }
    while !closed && filled < PUMP_CHUNK {
        match relay.stream.try_read(&mut received[filled..]) {
            Ok(0) => closed = true,
            Ok(read) => filled += read,
            Err(_) => break,
        }
    }
    received.truncate(filled);
    let recv = base64::engine::general_purpose::STANDARD.encode(&received);
    if closed && let Some(relay) = state.relay.take() {
        finish(relay).await;
    }
    Ok(format!(r#"{{"recv":"{recv}","closed":{closed}}}"#).into_bytes())
}

/// `privilege.end {attempt}`: close the relay of this attempt.
async fn end(input: &[u8]) -> io::Result<Vec<u8>> {
    /// The `privilege.end` request body.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        attempt: String,
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| invalid())?;
    let attempt = attempt_id(&request.attempt)?;
    let mut state = state().lock().await;
    state.keys.remove(&attempt);
    if state
        .relay
        .as_ref()
        .is_some_and(|relay| relay.attempt == attempt)
        && let Some(relay) = state.relay.take()
    {
        finish(relay).await;
    }
    Ok(br#"{"ended":true}"#.to_vec())
}

/// Close the relay's socket, give it a moment to stop its scripts and exit,
/// then close the terminal (which ends the session if it is still there).
async fn finish(relay: Relay) {
    let Relay {
        stream,
        mut elevated,
        directory,
        ..
    } = relay;
    drop(stream);
    let _ = tokio::time::timeout(Duration::from_secs(5), elevated.child.wait()).await;
    drop(elevated);
    let _ = std::fs::remove_dir_all(directory);
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

    /// A key is made per attempt, and at most two wait at once.
    #[tokio::test]
    async fn seal_keys_are_bounded() {
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let dir = std::env::temp_dir();
        let ids = [
            "10000000000000000000000000000001",
            "10000000000000000000000000000002",
            "10000000000000000000000000000003",
        ];
        let made: Vec<bool> = {
            let mut made = Vec::new();
            for id in ids {
                made.push(
                    execute(
                        "privilege.key",
                        format!(r#"{{"attempt":"{id}"}}"#).as_bytes(),
                        &dir,
                    )
                    .await
                    .is_ok(),
                );
            }
            made
        };
        assert_eq!(made, [true, true, false]);
        for id in ids {
            let _ = execute(
                "privilege.end",
                format!(r#"{{"attempt":"{id}"}}"#).as_bytes(),
                &dir,
            )
            .await;
        }
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
