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
