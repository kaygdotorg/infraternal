//! Proves active helper cancellation and bounded output using real child processes, including a descendant.
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::{
    process::execute,
    transport::{Input, shell_quote},
};
use std::time::Duration;
use tokio::process::Command;

fn live(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| stat.split_whitespace().nth(2) != Some("Z"))
}

fn birth(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field can contain spaces; count from its final delimiter.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
}
struct Descendant {
    pid: u32,
    birth: Option<String>,
}
impl Drop for Descendant {
    fn drop(&mut self) {
        if !live(self.pid) || self.birth.is_none() || birth(self.pid) != self.birth {
            return;
        }
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(self.pid).unwrap()),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

#[tokio::test]
async fn cancellation_retires_the_helper_descendant_too() {
    let root = common::scratch();
    let path = root.join(format!("ssh-owned-pid-{}", uuid::Uuid::new_v4().simple()));
    let script = format!(
        "sleep 60 & printf '%s' \"$!\" > {}; wait",
        shell_quote(path.to_str().unwrap())
    );
    let running = tokio::spawn(async move {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        execute(&mut command, Input::Empty, Duration::from_secs(70)).await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while std::fs::read_to_string(&path)
            .unwrap_or_default()
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let child: u32 = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    let _cleanup = Descendant {
        pid: child,
        birth: birth(child),
    };
    assert!(live(child));
    running.abort();
    let _ = running.await;
    let retired = tokio::time::timeout(Duration::from_secs(1), async {
        while live(child) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    std::fs::remove_file(path).unwrap();
    assert!(
        retired.is_ok(),
        "the owned descendant remained live after helper cancellation"
    );
}

#[tokio::test]
async fn oversized_remote_output_is_bounded_and_active_timeout_is_enforced() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "head -c 4097 /dev/zero"]);
    assert!(
        execute(&mut command, Input::Empty, Duration::from_secs(2))
            .await
            .is_err()
    );
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exec sleep 60"]);
    assert!(
        execute(&mut command, Input::Empty, Duration::from_millis(25))
            .await
            .is_err()
    );
}
