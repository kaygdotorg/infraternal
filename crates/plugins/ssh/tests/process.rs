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

#[tokio::test]
async fn group_identity_is_retained_until_inherited_pipes_finish() {
    let path = common::scratch().join(format!("ssh-pipe-owner-{}", uuid::Uuid::new_v4().simple()));
    let script = format!(
        "import os, subprocess, time; child=subprocess.Popen(['/bin/sleep','60'],start_new_session=True); open({},'w').write(str(os.getpid())+' '+str(child.pid)); time.sleep(.05); os._exit(0)",
        shell_quote(path.to_str().unwrap())
    );
    let running = tokio::spawn(async move {
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", &script]);
        execute(&mut command, Input::Empty, Duration::from_secs(3)).await
    });
    let ids = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ids: Vec<u32> = std::fs::read_to_string(&path)
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|id| id.parse().ok())
                .collect();
            if ids.len() == 2 {
                break ids;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let escape_cleanup = Descendant {
        pid: ids[1],
        birth: birth(ids[1]),
    };
    let leader_birth = birth(ids[0]);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !running.is_finished(),
        "the fixture must keep its inherited pipe open"
    );
    let retained = leader_birth.is_some() && birth(ids[0]) == leader_birth;
    running.abort();
    let _ = running.await;
    drop(escape_cleanup);
    std::fs::remove_file(path).unwrap();
    assert!(
        retained,
        "the cancellation group id was released while owned I/O remained pending"
    );
}

#[tokio::test]
async fn completed_helper_retires_descendants_with_closed_pipes() {
    let mut command = Command::new("/bin/sh");
    // A child can close its inherited pipes while remaining in the owned group.
    // Successful leader exit must not leave that group running after scope retirement.
    command.args([
        "-c",
        "sleep 60 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\"",
    ]);
    let output = execute(&mut command, Input::Empty, Duration::from_secs(3))
        .await
        .unwrap();
    assert!(output.success);
    let pid = std::str::from_utf8(&output.stdout)
        .unwrap()
        .parse()
        .unwrap();
    let cleanup = Descendant {
        pid,
        birth: birth(pid),
    };
    // Group signals are asynchronous. Bound termination as the cancellation
    // oracle does, rather than racing delivery immediately after killpg returns.
    let retired = tokio::time::timeout(Duration::from_secs(1), async {
        while live(pid) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    drop(cleanup);
    assert!(
        retired.is_ok(),
        "owned descendant remained live after helper completion"
    );
}

#[tokio::test]
async fn reviewer_ssh_helper_does_not_inherit_server_reload_mask() {
    use nix::sys::signal::{SigSet, SigmaskHow, Signal};
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGHUP);
    let previous = blocked.thread_swap_mask(SigmaskHow::SIG_BLOCK).unwrap();
    let mut command = Command::new("/usr/bin/python3");
    command.args([
        "-c",
        "import signal; print(int(signal.SIGHUP in signal.pthread_sigmask(signal.SIG_BLOCK, [])))",
    ]);
    // Server runtime workers inherit the mask installed before runtime startup.
    // Exercise the normal helper launcher on that thread, then restore the mask
    // before any assertion so other tests retain their own signal policy.
    let result = execute(&mut command, Input::Empty, Duration::from_secs(3)).await;
    previous.thread_set_mask().unwrap();
    let output = result.unwrap();
    assert!(output.success);
    assert_eq!(
        output.stdout, b"0\n",
        "an SSH helper must receive SIGHUP normally rather than inherit the server reload mask"
    );
}
