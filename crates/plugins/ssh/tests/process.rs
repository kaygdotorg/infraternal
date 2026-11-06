//! Proves progress deadlines, helper cancellation and bounded output using real child processes.
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
    let scratch = common::scratch();
    let path = scratch.join(format!("ssh-pipe-owner-{}", uuid::Uuid::new_v4().simple()));
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

#[tokio::test]
async fn negotiated_sources_require_an_exact_receipt_before_private_input() {
    use infraternal_plugin_ssh::transport::{PayloadInput, TransferChoice};
    for receipt in [
        "TRANSFER raw\n",
        "TRANSFER reuse\n",
        "UNKNOWN\n",
        "TRANSFER raw\r\n",
    ] {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            &format!(
                "printf 'STEP upload\\n'; printf %s {}; cat",
                shell_quote(receipt)
            ),
        ]);
        let output = execute(
            &mut command,
            Input::Negotiated {
                raw: PayloadInput::Bytes(b"public-frame"),
                gzip: None,
                zstd: None,
                invitation: b"synthetic-invitation",
                payload_ack: false,
                declared: None,
            },
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        if TransferChoice::parse(receipt.as_bytes()).is_some() {
            assert!(text.contains("synthetic-invitation"));
            assert_eq!(text.contains("public-frame"), receipt == "TRANSFER raw\n");
            assert!(text.contains(receipt));
        } else {
            assert!(!text.contains("synthetic-invitation"));
            assert!(!text.contains("public-frame"));
        }
    }
}

#[tokio::test]
async fn unavailable_negotiated_codec_never_sends_invitation() {
    use infraternal_plugin_ssh::transport::PayloadInput;
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'STEP upload\nTRANSFER gzip\n'; cat"]);
    assert!(
        execute(
            &mut command,
            Input::Negotiated {
                raw: PayloadInput::Bytes(b"public-frame"),
                gzip: None,
                zstd: None,
                invitation: b"synthetic-invitation",
                payload_ack: false,
                declared: None,
            },
            Duration::from_secs(60)
        )
        .await
        .is_err()
    );
}

// A setup child can refuse enrollment without reading private stdin. The
// compound command reports that refusal in stdout while exiting successfully.
#[tokio::test]
async fn review_compound_refusal_preserves_receipt_when_invitation_pipe_closes() {
    use infraternal_plugin_ssh::{
        install::parse_transfer_setup, model::InstallStep, transport::PayloadInput,
    };
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "exec 0<&-; printf 'STEP upload\nTRANSFER reuse\nSTEP join\nFAIL join 71\n'",
    ]);
    let result = execute(
        &mut command,
        Input::Negotiated {
            raw: PayloadInput::Bytes(b"unused public payload"),
            gzip: None,
            zstd: None,
            invitation: b"synthetic-capability\n",
            payload_ack: false,
            declared: None,
        },
        Duration::from_secs(10),
    )
    .await;
    assert!(
        result.is_ok(),
        "fixed refusal receipt must survive closed invitation input"
    );
    let output = result.unwrap();
    let failure = parse_transfer_setup(&output.stdout).unwrap_err();
    assert!(matches!(failure.failed_step, Some(InstallStep::Join)));
    assert_eq!(failure.exit_status, Some(71));
}

/// The public payload may precede transfer receipts, but its private tail must
/// wait for both the declared selection and the verified staging receipt.
#[tokio::test]
async fn declared_payload_flows_before_receipts_and_private_input_waits() {
    use infraternal_plugin_ssh::transport::{PayloadInput, TransferChoice};
    let mut command = Command::new("/usr/bin/python3");
    command.args([
        "-c",
        r"
import os, select, sys
out = sys.stdout.buffer
payload = os.read(0, 12)
assert payload == b'public-frame', payload
assert not select.select([0], [], [], 0.05)[0], 'private input preceded verification'
out.write(b'STEP upload\nTRANSFER raw\nPAYLOAD ready\n'); out.flush()
private = sys.stdin.buffer.read()
assert private == b'synthetic-invitation', private
out.write(b'STEP join\nSTEP install\nSTEP start\nSTEP linger\nyes\nDONE\n')
",
    ]);
    let result = execute(
        &mut command,
        Input::Negotiated {
            raw: PayloadInput::Bytes(b"public-frame"),
            gzip: None,
            zstd: None,
            invitation: b"synthetic-invitation",
            payload_ack: true,
            declared: Some(TransferChoice::Raw),
        },
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert!(result.success);
    assert!(infraternal_plugin_ssh::install::parse_transfer_setup(&result.stdout).unwrap());
}

/// A lying or missing transfer receipt must never release private stdin, even
/// when the public source was optimistically sent from earlier capabilities.
#[tokio::test]
async fn declared_selection_mismatch_and_missing_verification_withhold_private_input() {
    use infraternal_plugin_ssh::transport::{PayloadInput, TransferChoice};
    for receipt in [
        "TRANSFER gzip\nPAYLOAD ready\n",
        "TRANSFER raw\nFAIL upload 1\n",
    ] {
        let scratch = common::scratch();
        let path = scratch.join(format!("private-barrier-{}", uuid::Uuid::new_v4().simple()));
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            &format!(
                "printf 'STEP upload\\n%s' {}; cat > {}",
                shell_quote(receipt),
                shell_quote(path.to_str().unwrap())
            ),
        ]);
        let result = execute(
            &mut command,
            Input::Negotiated {
                raw: PayloadInput::Bytes(b"public-frame"),
                gzip: Some(b"other-public"),
                zstd: None,
                invitation: b"synthetic-invitation",
                payload_ack: true,
                declared: Some(TransferChoice::Raw),
            },
            Duration::from_secs(3),
        )
        .await;
        let bytes = std::fs::read(&path).unwrap_or_default();
        assert!(
            !bytes
                .windows(b"synthetic-invitation".len())
                .any(|b| b == b"synthetic-invitation")
        );
        assert!(
            result.is_err()
                || result.is_ok_and(|out| infraternal_plugin_ssh::install::parse_transfer_setup(
                    &out.stdout
                )
                .is_err())
        );
        std::fs::remove_file(&path).ok();
    }
}

/// Advance a virtual clock while a real child consumes gated payload chunks.
/// Restoring the total helper timeout makes this fail after the third advance.
#[tokio::test]
async fn progressing_upload_outlives_thirty_seconds() {
    let scratch = common::scratch();
    let root = scratch.join(format!("progress-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&root).unwrap();
    let script = r"
import os, pathlib, sys, time
root = pathlib.Path(sys.argv[1])
for index in range(8):
    remaining = 65536
    while remaining:
        chunk = os.read(0, remaining)
        assert chunk
        remaining -= len(chunk)
    (root / str(index)).touch()
    while not (root / ('release' + str(index))).exists():
        # sleep: wait for the test to advance virtual time before accepting more bytes.
        time.sleep(.001)
assert not os.read(0, 1)
";
    let path = root.clone();
    let running = tokio::spawn(async move {
        let payload = vec![42; 8 * 65536];
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", script]).arg(path);
        execute(
            &mut command,
            Input::Bytes(&payload),
            Duration::from_secs(30),
        )
        .await
    });
    tokio::time::pause();
    // The product clock is virtual. This generous real-time guard only catches
    // a wedged fixture while waiting for an external child's acknowledgment.
    let hang_guard = std::time::Instant::now() + Duration::from_secs(600);
    for index in 0..8 {
        while !root.join(index.to_string()).exists() {
            assert!(!running.is_finished(), "upload ended before chunk {index}");
            assert!(
                std::time::Instant::now() < hang_guard,
                "the upload fixture stopped acknowledging chunks"
            );
            tokio::task::yield_now().await;
        }
        // The child's acknowledgment proves these bytes passed the input pipe.
        tokio::time::advance(Duration::from_secs(10)).await;
        std::fs::write(root.join(format!("release{index}")), []).unwrap();
    }
    tokio::time::resume();
    let result = running.await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
    assert!(result.is_ok_and(|output| output.success));
}

/// A child that accepts no input must expire even when no wall time elapses.
#[tokio::test]
async fn stalled_upload_expires_under_virtual_time() {
    let mut command = Command::new("/bin/sleep");
    command.arg("600");
    tokio::time::pause();
    let bytes = vec![42; 1024 * 1024];
    let result = execute(&mut command, Input::Bytes(&bytes), Duration::from_secs(30)).await;
    tokio::time::resume();
    assert_eq!(
        result.err().unwrap().message,
        "The SSH operation timed out."
    );
}
