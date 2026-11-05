//! Proves lifecycle admission across simultaneous actor quotas and real shim owner limits [D18,D240,D247].
use super::*;
use infraternal_agent::sessions;
use std::{
    fs,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::PermissionsExt,
    },
    process::{Child, Command as Process, Stdio},
};

struct Host {
    root: PathBuf,
    child: Child,
}
impl Host {
    fn start() -> (Self, UnixStream) {
        let binary = std::env::var_os("INFRATERNAL_TEST_BINARY")
            .expect("set the built real binary for this gate");
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/rl10")
            .join(format!("s{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let (parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        let child = Process::new("bash")
            .args([
                "-c",
                "exec 3<&0; exec 0</dev/null; exec \"$@\"",
                "login-limit-fixture",
            ])
            .arg(binary)
            .args(["agent", "--fd", "3", "--state"])
            .arg(&root)
            .env(
                "ZDOTDIR",
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../infraternal/tests/profile"),
            )
            .stdin(Stdio::from(OwnedFd::from(child)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        parent.set_nonblocking(true).unwrap();
        (Self { root, child }, UnixStream::from_std(parent).unwrap())
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Existing fixture cleanup targets only this private state directory.
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let _ = Process::new("python3").current_dir(repo).args(["-B", "-c",
            "import sys; sys.path.insert(0,'scripts'); from agent_fixture import cleanup; from pathlib import Path; cleanup(Path(sys.argv[1]))"])
            .arg(&self.root).status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Hold only artificial ordinary replies. Every login frame reaches the real
/// inherited daemon unchanged; no mock can manufacture cleanup acknowledgement.
async fn bridge(front: UnixStream, back: UnixStream, full: oneshot::Sender<()>) {
    let (mut front_read, mut front_write) = front.into_split();
    let (mut back_read, mut back_write) = back.into_split();
    let replies =
        tokio::spawn(async move { tokio::io::copy(&mut back_read, &mut front_write).await });
    let mut input = BytesMut::new();
    let mut count = 0;
    let mut full = Some(full);
    loop {
        let decoded = loop {
            match decode_muxed_frame(&input) {
                Ok(frame) => break frame,
                Err(DecodeError::Incomplete) => {
                    if front_read.read_buf(&mut input).await.unwrap() == 0 {
                        replies.abort();
                        return;
                    }
                }
                Err(error) => panic!("invalid limit fixture: {error:?}"),
            }
        };
        let size = decoded.wire_len;
        if matches!(
            decoded.frame,
            Frame::Call {
                action_id: "review.pending",
                ..
            }
        ) {
            count += 1;
            assert!(count <= COMMAND_CAPACITY);
            if count == COMMAND_CAPACITY {
                full.take().unwrap().send(()).unwrap();
            }
        } else if back_write.write_all(&input[..size]).await.is_err() {
            replies.abort();
            return;
        }
        input.advance(size);
    }
}

#[tokio::test]
#[ignore = "requires INFRATERNAL_TEST_BINARY; real host combined limits gate"]
async fn full_command_queue_pending_table_and_owner_links_preserve_real_cleanup() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let (host, daemon) = Host::start();
    let (server, front) = UnixStream::pair().unwrap();
    let (full, barrier) = oneshot::channel();
    let proxy = tokio::spawn(bridge(front, daemon, full));
    let actor = EmbeddedAgent::from_test_socket(server);
    let person = uuid::Uuid::new_v4();
    let uid = nix::unistd::Uid::effective();
    let account = nix::unistd::User::from_uid(uid).unwrap().unwrap().name;
    let id = actor
        .open_for(
            TerminalSize {
                cols: 80,
                rows: 24,
                px_w: 0,
                px_h: 0,
            },
            person,
            Some(account),
        )
        .await
        .unwrap();
    let path = sessions::rendezvous(&host.root, id);
    let mut session = sessions::connect(path.clone(), id).await.unwrap();
    let pid_path = host.root.join("shell.pid");
    sessions::send(
        &mut session.peer,
        &infraternal_shim::frame::Frame::Input(
            format!("printf '%s\\n' \"$$\" > '{}'\n", pid_path.display()).into_bytes(),
        ),
    )
    .await
    .unwrap();
    let pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(value) = fs::read_to_string(&pid_path)
                && let Ok(pid) = value.trim().parse::<u32>()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let pin = infraternal_shim::process_exit_descriptor(pid).unwrap();
    drop(session);
    let mut owners = Vec::new();
    for _ in 0..32 {
        owners.push(sessions::own(path.clone(), id).await.unwrap().unwrap());
    }
    for _ in 0..32 {
        assert!(sessions::own(path.clone(), id).await.is_err());
    }
    let mut calls = Vec::new();
    for _ in 0..COMMAND_CAPACITY {
        let actor = actor.clone();
        calls.push(tokio::spawn(async move {
            actor.call("review.pending".into(), b"{}".to_vec()).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(10), barrier)
        .await
        .unwrap()
        .unwrap();
    // No await while filling: the current-thread fixture proves the mailbox
    // is exactly full at submission, as well as the pending table and32 links.
    let mut queued = Vec::new();
    for _ in 0..COMMAND_CAPACITY {
        let (reply, receive) = oneshot::channel();
        assert!(
            actor
                .commands
                .try_send(Command::Call {
                    action_id: "review.pending".into(),
                    input_json: b"{}".to_vec(),
                    reply
                })
                .is_ok()
        );
        queued.push(receive);
    }
    let (reply, _) = oneshot::channel();
    assert!(matches!(
        actor.commands.try_send(Command::Call {
            action_id: "review.pending".into(),
            input_json: b"{}".to_vec(),
            reply
        }),
        Err(mpsc::error::TrySendError::Full(_))
    ));
    assert_eq!(actor.commands.capacity(), 0);
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(10),
            actor.downgrade().revoke_login(person)
        )
        .await
        .unwrap(),
        Ok(())
    );
    let mut exited = [nix::poll::PollFd::new(
        pin.as_fd(),
        nix::poll::PollFlags::POLLIN,
    )];
    assert_eq!(
        nix::poll::poll(&mut exited, nix::poll::PollTimeout::ZERO).unwrap(),
        1
    );
    eprintln!(
        "ordinary_pending=64 queued_commands=64 command_overflow_refused=true owner_links=32 owner_overflow_refused=32 cleanup_confirmed=true pinned_shell_stopped=true"
    );
    drop(owners);
    drop(queued);
    for call in calls {
        call.abort();
    }
    drop(actor);
    proxy.abort();
}
