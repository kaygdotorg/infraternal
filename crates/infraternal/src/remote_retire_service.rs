//! Disable the systemd service that owns the retired infraternal agent.

use std::{io, path::Path, process::Stdio, time::Duration};
use tokio::process::Command;

/// The service name both SSH bootstrap and `infraternal up` install.
const UNIT: &str = "infraternal-agent.service";

/// Use a trusted systemctl binary regardless of which service manager owns us.
pub(super) async fn disable(uid: u32) -> io::Result<bool> {
    if !Path::new("/run/systemd/system").is_dir() {
        return Ok(false);
    }
    let manager = crate::trusted_program::trusted_program(
        &[
            "/usr/bin/systemctl",
            "/bin/systemctl",
            "/run/current-system/sw/bin/systemctl",
        ],
        0,
    )
    .map_err(|_| io::ErrorKind::NotFound)?;
    disable_owned(&manager, uid, std::process::id()).await
}

/// Check MainPID before changing enablement. A manual run may share the
/// product unit's name and filesystem layout but is not its main process.
async fn disable_owned(manager: &Path, uid: u32, pid: u32) -> io::Result<bool> {
    let output = call(
        manager,
        uid,
        &["show", "--property=MainPID", "--value", UNIT],
    )
    .await?;
    if output.trim().parse::<u32>().ok() != Some(pid) {
        return Ok(false);
    }
    call(manager, uid, &["disable", UNIT]).await?;
    eprintln!("Disabled infraternal-agent.service.");
    // SSH-installed units use Restart=always. Queue the stop without waiting
    // for our own exit, and only after the ordinary component stop hooks ran.
    call(manager, uid, &["--no-block", "stop", UNIT]).await?;
    Ok(true)
}

/// Call the system manager as root, or this uid's user manager. Bound each
/// command and keep the daemon's environment out of privileged systemctl.
async fn call(manager: &Path, uid: u32, arguments: &[&str]) -> io::Result<String> {
    let mut command = Command::new(manager);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if uid != 0 {
        command
            .arg("--user")
            .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
    }
    let output = tokio::time::timeout(Duration::from_secs(5), command.args(arguments).output())
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    if !output.status.success() {
        return Err(io::Error::other("systemctl refused the retired service"));
    }
    String::from_utf8(output.stdout).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    //! A retired service uses its own manager, and a manual run leaves the unit alone.

    use super::*;
    use std::fs;

    /// Verify the PID fence and both manager scopes without touching real units.
    #[tokio::test]
    async fn only_the_installed_main_pid_can_disable_the_unit() {
        let fixture = std::env::temp_dir().join(format!("retirement-{}", uuid::Uuid::new_v4()));
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&fixture).unwrap();
        let manager = fixture.join("systemctl");
        let log = fixture.join("calls");
        crate::test_executable::write(
            &manager,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in *'show '*) echo 42;; esac\n",
                log.display()
            ),
            0o700,
        );
        assert!(!disable_owned(&manager, 1000, 43).await.unwrap());
        assert!(disable_owned(&manager, 1000, 42).await.unwrap());
        assert!(disable_owned(&manager, 0, 42).await.unwrap());
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            "\
--user show --property=MainPID --value infraternal-agent.service
--user show --property=MainPID --value infraternal-agent.service
--user disable infraternal-agent.service
--user --no-block stop infraternal-agent.service
show --property=MainPID --value infraternal-agent.service
disable infraternal-agent.service
--no-block stop infraternal-agent.service
"
        );
        fs::remove_dir_all(fixture).unwrap();
    }
}
