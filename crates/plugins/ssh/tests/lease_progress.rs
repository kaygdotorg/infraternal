//! Exercises lease renewal and idle retirement with real locks and controlled lease intervals.
#![allow(clippy::unwrap_used)]

/// Shared short, private fixture directories.
mod common;

use infraternal_plugin_ssh::{process::execute, transport::Input};
use std::{os::unix::fs::PermissionsExt, time::Duration};

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
