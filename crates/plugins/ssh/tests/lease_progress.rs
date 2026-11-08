//! Exercises setup lease retirement and renewal with real process and lock ownership.
#![allow(clippy::unwrap_used)]

/// Shared short, private fixture directories.
mod common;

use infraternal_plugin_ssh::{process::execute, transport::Input};
use std::{os::unix::fs::PermissionsExt, time::Duration};

/// An exited lease keeps its PID and birth time until its parent reaps it,
/// although the kernel has already closed its lock descriptors. Recovery must
/// use the journal flock as authority, including when another holder has it.
#[cfg(target_os = "linux")]
#[test]
fn released_lease_owner_can_stay_unreaped_without_blocking_recovery() {
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let scratch = common::scratch();
    let stage = scratch.join(format!("retired-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&stage).unwrap();
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "exec 7< \"$1\"; flock -n 7 || exit 1; printf 'ready\\n'; read -r finish",
            "lease",
        ])
        .arg(&stage)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
    let birth = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let lease = stage.join("lease");
    std::fs::write(&lease, format!("{} {birth}\n", child.id())).unwrap();
    std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(child.stdin.take());
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while waitid(Id::Pid(pid), flags).unwrap() == WaitStatus::StillAlive {
        assert!(std::time::Instant::now() < deadline, "lease did not exit");
        std::thread::yield_now();
    }
    let script = format!(
        "set -euC\nstage={}\n{}\n{}\nretire_setup_lease\n",
        infraternal_plugin_ssh::transport::shell_quote(stage.to_str().unwrap()),
        include_str!("../src/setup_guard.sh"),
        include_str!("../src/setup_lock.sh"),
    );
    let mut results = Vec::new();
    for held in [false, true] {
        let lock = held.then(|| {
            nix::fcntl::Flock::lock(
                std::fs::File::open(&stage).unwrap(),
                nix::fcntl::FlockArg::LockExclusiveNonblock,
            )
            .unwrap()
        });
        results.push(
            Command::new("/bin/sh")
                .args(["-c", &script])
                .status()
                .unwrap()
                .code(),
        );
        drop(lock);
    }
    // Reap only after both probes, so neither outcome depends on init's timing.
    child.wait().unwrap();
    std::fs::remove_dir_all(stage).unwrap();
    assert_eq!(results, [Some(0), Some(73)]);
}

/// Fresh payload consumption keeps transaction protection beyond the first lease interval.
#[tokio::test]
async fn remote_payload_progress_renews_the_lease_but_idle_does_not() {
    let scratch = common::scratch();
    let root = scratch.join(format!("lease-{}", uuid::Uuid::new_v4().simple()));
    let tools = root.join("tools");
    let stage = root.join("stage");
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::create_dir_all(&stage).unwrap();
    let sleep = tools.join("sleep");
    std::fs::write(
        &sleep,
        format!(
            r"#!/usr/bin/python3
import pathlib, sys, time
root = pathlib.Path({root:?})
if sys.argv[1] != '180':
    time.sleep(float(sys.argv[1]))
    sys.exit(0)
index = 0
while (root / ('entered' + str(index))).exists(): index += 1
(root / ('entered' + str(index))).touch()
while not (root / ('release' + str(index))).exists():
    # sleep: the test explicitly releases each synthetic lease interval.
    time.sleep(.001)
",
            root = root.to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&sleep, std::fs::Permissions::from_mode(0o700)).unwrap();
    let script = format!(
        "{}\n{}\nstage={}\nstart_setup_lease\nwhile [ ! -f {} ]; do sleep .001; done\n",
        include_str!("../src/setup_guard.sh"),
        include_str!("../src/setup_lock.sh"),
        infraternal_plugin_ssh::transport::shell_quote(stage.to_str().unwrap()),
        infraternal_plugin_ssh::transport::shell_quote(root.join("finish").to_str().unwrap()),
    );
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args(["-c", &script])
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()));
    let running =
        tokio::spawn(
            async move { execute(&mut command, Input::Empty, Duration::from_secs(600)).await },
        );
    let guard = std::time::Instant::now() + Duration::from_secs(600);
    while !root.join("entered0").exists() {
        assert!(!running.is_finished());
        assert!(std::time::Instant::now() < guard);
        tokio::task::yield_now().await;
    }
    std::fs::write(stage.join("transfer-progress"), b"1024\n").unwrap();
    std::fs::set_permissions(
        stage.join("transfer-progress"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(root.join("release0"), []).unwrap();
    while !root.join("entered1").exists() {
        let file = std::fs::File::open(&stage).unwrap();
        assert!(
            nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock).is_err(),
            "lease released transaction protection despite fresh payload consumption"
        );
        assert!(std::time::Instant::now() < guard);
        tokio::task::yield_now().await;
    }
    std::fs::write(root.join("release1"), []).unwrap();
    loop {
        let file = std::fs::File::open(&stage).unwrap();
        if nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock).is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < guard,
            "an idle lease did not retire"
        );
        tokio::task::yield_now().await;
    }
    std::fs::write(root.join("finish"), []).unwrap();
    assert!(running.await.unwrap().unwrap().success);
    std::fs::remove_dir_all(root).unwrap();
}
