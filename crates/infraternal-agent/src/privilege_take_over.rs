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
use infraternal_plugin_api::ActionReply;
use serde::Deserialize;
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

/// The hidden command word the root agent runs as the account.
pub const COMMAND: &str = "--promotion-retire";
/// The hidden command word of an abandoned successor's cleanup (J465 P1).
pub const ABANDON_COMMAND: &str = "--promotion-abandon";
/// How long retiring the rootless install may take (it stops a user unit).
const RETIRE_BOUND: Duration = Duration::from_secs(90);
/// Bound rollback and uninstall in the independent transient unit.
const ABANDON_BOUND: Duration = Duration::from_secs(250);
/// A successful no-op for a stale transaction leaves the current daemon running.
pub const STALE_ABANDON_EXIT_CODE: u8 = 75;

/// The result of a completed abandonment unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AbandonResult {
    /// This request rolled back or removed the installation it named.
    Removed,
    /// A different transaction now owns the installation, so no files changed.
    Stale,
}

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
/// The rollback and transaction-bound uninstall run in a transient unit and
/// must finish before the receipt is returned. Its unit disables and removes
/// the installed service but leaves this process alive until the receipt frame
/// has been written; the post-write hook then stops this process. Only ids
/// cross the wire: the host builds the rollback from its install scripts.
///
/// # Errors
/// A malformed request, or the transient unit couldn't be started; the
/// server keeps its outbox entry and asks again on the next connection.
pub async fn abandon(input: &[u8]) -> io::Result<ActionReply> {
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
    let runner = crate::privilege_relay_host::fixed_root_binary("systemd-run")?;
    let unit = format!("infraternal-promotion-abandon-{}", transaction.simple());
    let args = [
        OsString::from(ABANDON_COMMAND),
        OsString::from(host.simple().to_string()),
        OsString::from(transaction.simple().to_string()),
    ];
    let result = run_cleanup_unit(&runner, &unit, &exe, &args).await?;
    let after_write = (result == AbandonResult::Removed).then(|| {
        Box::new(|| {
            let _ =
                nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM);
        }) as infraternal_plugin_api::AfterReply
    });
    Ok(ActionReply {
        json: br#"{"completed":true}"#.to_vec(),
        after_write,
    })
}

/// Wait for the independent abandonment unit's final exit status. A zero exit
/// proves cleanup finished; code 75 is the transaction-bound stale no-op.
async fn run_cleanup_unit(
    runner: &Path,
    unit: &str,
    executable: &Path,
    args: &[OsString],
) -> io::Result<AbandonResult> {
    if !runner.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cleanup runner must be a fixed absolute path",
        ));
    }
    let status = tokio::time::timeout(
        ABANDON_BOUND,
        tokio::process::Command::new(runner)
            .args([
                "--quiet",
                "--collect",
                "--wait",
                "--service-type=exec",
                "--property=RuntimeMaxSec=240s",
                "--unit",
            ])
            .arg(unit)
            .arg("--")
            .arg(executable)
            .args(args)
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
    match status.code() {
        Some(0) => Ok(AbandonResult::Removed),
        Some(code) if code == i32::from(STALE_ABANDON_EXIT_CODE) => Ok(AbandonResult::Stale),
        _ => Err(io::Error::other(
            "abandonment cleanup did not finish successfully",
        )),
    }
}

#[cfg(test)]
mod tests {
    //! A cleanup receipt means the independent cleanup process has finished.
    use super::*;
    use std::{ffi::OsString, os::unix::fs::PermissionsExt};

    /// The action cannot return its receipt while a detached cleanup child is still running.
    #[tokio::test]
    async fn cleanup_receipt_waits_for_the_unit_to_finish() {
        let root = std::env::temp_dir().join(format!(
            "infraternal-abandon-wait-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runner = root.join("systemd-run");
        std::fs::write(
            &runner,
            b"#!/bin/sh\nwait_for_child=no\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --wait ]; then wait_for_child=yes; fi\n  if [ \"$1\" = -- ]; then shift; break; fi\n  shift\ndone\n\"$@\" &\nchild=$!\nif [ \"$wait_for_child\" = yes ]; then wait \"$child\"; else exit 0; fi\n",
        )
        .unwrap();
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o700)).unwrap();
        let started = root.join("started");
        let release = root.join("release");
        let finished = root.join("finished");
        // sleep: the fake cleanup child waits for explicit release so the test can observe early acknowledgement.
        let child = format!(
            "touch '{}'; while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}'",
            started.display(),
            release.display(),
            finished.display()
        );
        let executable = PathBuf::from("/bin/sh");
        let args = vec![OsString::from("-c"), OsString::from(child)];
        let unit = format!("infraternal-promotion-test-{}", std::process::id());
        let running =
            tokio::spawn(async move { run_cleanup_unit(&runner, &unit, &executable, &args).await });

        tokio::time::timeout(Duration::from_secs(5), async {
            while !started.exists() {
                // sleep: poll the fake cleanup child until its start marker appears.
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let returned_before_cleanup = running.is_finished();
        std::fs::write(release, b"continue").unwrap();
        assert_eq!(running.await.unwrap().unwrap(), AbandonResult::Removed);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !finished.exists() {
                // sleep: poll until the fake cleanup child records its exit work.
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(finished.exists());
        assert!(
            !returned_before_cleanup,
            "cleanup was acknowledged before it finished"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A privileged cleanup worker refuses a command name that would be resolved through `PATH`.
    #[tokio::test]
    async fn cleanup_refuses_a_path_searched_runner() {
        let result = run_cleanup_unit(
            Path::new("systemd-run"),
            "infraternal-promotion-test",
            Path::new("/bin/true"),
            &[],
        )
        .await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
