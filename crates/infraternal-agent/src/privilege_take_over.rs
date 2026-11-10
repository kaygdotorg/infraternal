//! The root infraternal agent finishing the upgrade that made it (D376, #399; J415 R5, R6).
//!
//! After the handover, the server asks the new root infraternal agent, from
//! a durable outbox, to retire the rootless install it replaced
//! (`privilege.take_over {attempt, host, fromUid}`). This runs until the
//! server has the receipt, so it must be idempotent: a rootless install
//! that is already gone is a success.
//!
//! Least privilege (D270, D376): root never touches the account's files
//! itself. It starts this same binary *as that account* (`setpriv` to its
//! uid, gid and groups, with a clean environment), which retires the
//! rootless install the way the account's own uninstall would, minus the
//! running terminals: their shims and sockets stay, so they can be adopted
//! (see `infraternal_plugin_remote::uninstall::retire_for_promotion`). Root
//! never opens a path under the person's home (J415 R6).
//!
//! Until this runs the root agent is in standby by construction: the server
//! admits it only as a private successor before the handover, whose link
//! carries no terminal, login, mesh or proxy work, and after the handover
//! this call comes first on its ordinary link.
use serde::Deserialize;
use std::{io, path::PathBuf, process::Stdio, time::Duration};

/// The hidden command word the root agent runs as the account.
pub const COMMAND: &str = "--promotion-retire";
/// The hidden command word of an abandoned successor's cleanup (J465 P1).
pub const ABANDON_COMMAND: &str = "--promotion-abandon";
/// How long retiring the rootless install may take (it stops a user unit).
const RETIRE_BOUND: Duration = Duration::from_secs(90);

/// Run `privilege.take_over` and return `{"retired":true}` once the rootless
/// install of `fromUid` is gone.
///
/// # Errors
/// A malformed request, an unknown account, or a retirement that failed;
/// the server keeps its outbox entry and asks again on the next connection.
pub async fn execute(input: &[u8]) -> io::Result<Vec<u8>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Request {
        attempt: String,
        host: String,
        from_uid: u32,
    }
    let request: Request =
        serde_json::from_slice(input).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    uuid::Uuid::try_parse(&request.attempt).map_err(|_| io::ErrorKind::InvalidInput)?;
    if request.host.len() != 32
        || !request
            .host
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || request.from_uid == 0
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let account = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(request.from_uid))?
        .ok_or(io::ErrorKind::NotFound)?;
    let exe = std::env::current_exe()?;
    let mut command = tokio::process::Command::new("/usr/bin/setpriv");
    command
        .arg(format!("--reuid={}", account.uid))
        .arg(format!("--regid={}", account.gid))
        .arg("--init-groups")
        .arg("--")
        .arg(&exe)
        .arg(COMMAND)
        .arg(&request.host)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("HOME", &account.dir)
        .env(
            "XDG_RUNTIME_DIR",
            PathBuf::from(format!("/run/user/{}", account.uid)),
        )
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(RETIRE_BOUND, command.status())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if !status.success() {
        return Err(io::Error::other("the rootless install was not retired"));
    }
    Ok(br#"{"retired":true}"#.to_vec())
}

/// `privilege.abandon {host, transaction}`: the promotion that installed
/// this root infraternal agent was abandoned (J465 P1). Put the host back:
/// roll back that exact install transaction (its journal is still open when
/// the relay died mid-install), then uninstall this agent, then sweep the
/// relay's leftovers in `/run`.
///
/// Stopping this agent's own unit would kill a child, so the work runs in a
/// separate transient unit, started here; the reply (`{"accepted":true}`)
/// goes out before that unit stops this agent. Only ids cross the wire: the
/// host builds the rollback itself from its install scripts.
///
/// # Errors
/// A malformed request, or the transient unit couldn't be started; the
/// server keeps its outbox entry and asks again on the next connection.
pub async fn abandon(input: &[u8]) -> io::Result<Vec<u8>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    /// The `privilege.abandon` request body.
    struct Request {
        host: String,
        transaction: String,
    }
    let request: Request =
        serde_json::from_slice(input).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let host = uuid::Uuid::try_parse(&request.host).map_err(|_| io::ErrorKind::InvalidInput)?;
    let transaction =
        uuid::Uuid::try_parse(&request.transaction).map_err(|_| io::ErrorKind::InvalidInput)?;
    let exe = std::env::current_exe()?;
    let unit = format!(
        "infraternal-promotion-abandon-{}",
        &transaction.simple().to_string()[..12]
    );
    let status = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("systemd-run")
            .args(["--quiet", "--collect", "--service-type=exec", "--unit"])
            .arg(&unit)
            .arg("--")
            .arg(&exe)
            .arg(ABANDON_COMMAND)
            .arg(host.simple().to_string())
            .arg(transaction.simple().to_string())
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if !status.success() {
        return Err(io::Error::other("the cleanup unit could not start"));
    }
    Ok(br#"{"accepted":true}"#.to_vec())
}
