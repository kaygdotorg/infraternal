//! Real PTY checks for frozen shim frames across a research host's independent sessions [D268].
#![cfg(feature = "process-per-user")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_shim::frame::{
    APPROXIMATE_SNAPSHOT, Frame, MULTI_WRITER, SEQUENCED_INPUT, SESSION_OWNER,
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Host {
    child: Child,
    state: PathBuf,
    ids: [String; 2],
}
impl Host {
    fn new() -> Self {
        Self::with_accounting(false)
    }
    fn with_accounting(accounted: bool) -> Self {
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/t{}-{serial}",
            std::process::id()
        ));
        let origin = (u128::from(std::process::id()) << 64) | (u128::from(serial) << 32);
        let ids = [format!("{origin:032x}"), format!("{:032x}", origin + 1)];
        let mut command = Command::new(env!("CARGO_BIN_EXE_infraternal"));
        command
            .args([
                "__shim",
                "--session",
                &ids[0],
                "--uid",
                &nix::unistd::Uid::effective().as_raw().to_string(),
                "--host-sessions",
                "2",
                "--ring-capacity",
                "128",
                "--state",
            ])
            .arg(&root);
        if accounted {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&root)
                .unwrap();
            command.arg("--host-accounting").arg(root.join("ownership"));
        }
        let child = command
            .env(
                "ZDOTDIR",
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/profile"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            state: root,
            ids,
        }
    }
    fn connect(&self, index: usize) -> UnixStream {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(stream) = UnixStream::connect(
                self.state
                    .join("sessions")
                    .join(format!("{}.sock", self.ids[index])),
            ) {
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                return stream;
            }
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        // Terminate only fixture-owned shells; killing the host alone can leave descendants.
        if let Ok(children) = fs::read_to_string(format!(
            "/proc/{}/task/{}/children",
            self.child.id(),
            self.child.id()
        )) {
            for pid in children.split_whitespace() {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid.parse().unwrap()),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.state);
    }
}
fn read(stream: &mut UnixStream) -> Frame {
    let mut size = [0; 4];
    stream.read_exact(&mut size).unwrap();
    let mut bytes = vec![0; u32::from_le_bytes(size) as usize];
    stream.read_exact(&mut bytes).unwrap();
    Frame::decode(&bytes).unwrap()
}
fn send(stream: &mut UnixStream, frame: &Frame) {
    stream.write_all(&frame.encode().unwrap()).unwrap();
}
fn writer_state(peer: &mut UnixStream) -> (u64, u64) {
    send(peer, &Frame::InputStateRequest);
    loop {
        match read(peer) {
            Frame::InputState(written, accepted) => return (written, accepted),
            Frame::InputAck(_) => {}
            _ => panic!("unexpected writer-state frame kind"),
        }
    }
}

#[test]
fn ownership_receipt_is_private_numeric_and_never_overwritten() {
    use std::os::unix::fs::PermissionsExt;
    let mut host = Host::with_accounting(true);
    let mut peer = host.connect(0);
    assert!(matches!(read(&mut peer), Frame::Hello { .. }));
    let path = host.state.join("ownership");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(host.child.id()).unwrap()),
        nix::sys::signal::Signal::SIGUSR2,
    )
    .unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    let content = loop {
        let text = fs::read_to_string(&path).unwrap();
        if text.lines().count() == 2 {
            break text;
        }
        assert!(Instant::now() < until, "ownership receipt incomplete");
        std::thread::sleep(Duration::from_millis(10));
    };
    for (index, line) in content.lines().enumerate() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let row = row.as_object().unwrap();
        assert_eq!(row["kind"], "ownership");
        assert_eq!(row["session"], index);
        assert!(
            row.iter().all(|(key, value)| {
                key == "kind"
                    || value.is_u64()
                    || (key == "reactor"
                        && value
                            .as_object()
                            .is_some_and(|fields| fields.values().all(serde_json::Value::is_u64)))
            }),
            "ownership row has a non-numeric field: {row:?}"
        );
        assert!(row["total_bytes"].as_u64().unwrap() > 0);
    }
    let duplicate = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args([
            "__shim",
            "--session",
            &host.ids[0],
            "--uid",
            &nix::unistd::Uid::effective().as_raw().to_string(),
            "--host-sessions",
            "2",
            "--state",
        ])
        .arg(&host.state)
        .arg("--host-accounting")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert_eq!(fs::read_to_string(path).unwrap(), content);
    assert!(host.child.try_wait().unwrap().is_none());
    send(&mut peer, &Frame::Attach(SEQUENCED_INPUT));
    assert_eq!(writer_state(&mut peer), (0, 0));
}

#[test]
fn session_exit_reconnect_writer_ack_resize_and_replay_keep_siblings_alive() {
    let mut host = Host::new();
    let mut first = host.connect(0);
    let mut second = host.connect(1);
    let Frame::Hello { pid, .. } = read(&mut first) else {
        panic!("Hello")
    };
    assert!(matches!(read(&mut second),Frame::Hello{pid:other,..} if other==pid));
    send(&mut first, &Frame::Attach(APPROXIMATE_SNAPSHOT));
    send(&mut first, &Frame::ReadFrom(0));
    send(
        &mut second,
        &Frame::Attach(SEQUENCED_INPUT | MULTI_WRITER | APPROXIMATE_SNAPSHOT),
    );
    send(&mut second, &Frame::SelectWriter(1));
    send(&mut second, &Frame::InputStateRequest);
    assert_eq!(read(&mut second), Frame::InputState(0, 0));
    let input = b"printf 'host-check\\n'\n";
    send(&mut second, &Frame::SequencedInput(0, input.to_vec()));
    assert_eq!(read(&mut second), Frame::InputAck(input.len() as u64));
    drop(second);
    let mut second = host.connect(1);
    assert!(matches!(read(&mut second), Frame::Hello { .. }));
    send(
        &mut second,
        &Frame::Attach(SEQUENCED_INPUT | MULTI_WRITER | APPROXIMATE_SNAPSHOT),
    );
    send(&mut second, &Frame::SelectWriter(1));
    assert_eq!(
        writer_state(&mut second),
        (input.len() as u64, input.len() as u64)
    );
    send(
        &mut second,
        &Frame::Resize {
            cols: 40,
            rows: 12,
            px_w: 0,
            px_h: 0,
        },
    );
    send(&mut second, &Frame::SnapshotRequest);
    assert!(matches!(
        read(&mut second),
        Frame::Snapshot(_, _) | Frame::SnapshotWithFlags(_, _, _)
    ));
    let mut owner = host.connect(0);
    read(&mut owner);
    send(&mut owner, &Frame::Attach(SESSION_OWNER));
    send(&mut owner, &Frame::InputStateRequest);
    assert_eq!(read(&mut owner), Frame::InputState(0, 0));
    send(&mut first, &Frame::Input(b"exit 7\n".to_vec()));
    loop {
        match read(&mut first) {
            Frame::Exited(7, _) => break,
            Frame::Output(_, _) | Frame::Snapshot(_, _) | Frame::SnapshotWithFlags(_, _, _) => {}
            Frame::Error(code, _) => panic!("unexpected snapshot error code {code}"),
            Frame::Exited(status, _) => panic!("unexpected exit status {status}"),
            _ => panic!("unexpected final-delivery frame kind"),
        }
    }
    assert!(host.child.try_wait().unwrap().is_none());
    drop(owner);
    drop(first);
    drop(second);
    let mut resumed = host.connect(1);
    assert!(matches!(read(&mut resumed), Frame::Hello { .. }));
    send(
        &mut resumed,
        &Frame::Attach(SEQUENCED_INPUT | MULTI_WRITER | APPROXIMATE_SNAPSHOT),
    );
    send(&mut resumed, &Frame::SelectWriter(1));
    assert_eq!(
        writer_state(&mut resumed),
        (input.len() as u64, input.len() as u64)
    );
}

#[cfg(feature = "plugin-agent")]
#[tokio::test]
async fn real_infraternal_agent_discovers_shared_pid_sessions_and_recovers_writer_state() {
    use infraternal_agent::sessions;
    let host = Host::new();
    for i in 0..2 {
        let mut peer = host.connect(i);
        assert!(matches!(read(&mut peer), Frame::Hello { .. }));
    }
    let found = sessions::discover(&host.state).await.unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|session| session.pid == host.child.id()));
    assert_ne!(found[0].id, found[1].id);
    drop(found);
    let id = u128::from_str_radix(&host.ids[1], 16)
        .unwrap()
        .to_be_bytes();
    let path = sessions::rendezvous(&host.state, id);
    let mut writer = sessions::connect_writer(path.clone(), id, 42)
        .await
        .unwrap();
    sessions::send(&mut writer.peer, &Frame::InputStateRequest)
        .await
        .unwrap();
    assert_eq!(
        sessions::Reader::default()
            .read(&mut writer.peer)
            .await
            .unwrap(),
        Frame::InputState(0, 0)
    );
    let input = b"printf 'handover-check\n'\n";
    sessions::send(&mut writer.peer, &Frame::SequencedInput(0, input.to_vec()))
        .await
        .unwrap();
    assert_eq!(
        sessions::Reader::default()
            .read(&mut writer.peer)
            .await
            .unwrap(),
        Frame::InputAck(input.len() as u64)
    );
    drop(writer);
    let mut resumed = sessions::connect_writer(path, id, 42).await.unwrap();
    sessions::send(&mut resumed.peer, &Frame::InputStateRequest)
        .await
        .unwrap();
    // Reconnecting a durable writer may first receive its current Ack. The
    // production recovery reader accepts it before the requested State fence.
    let mut reader = sessions::Reader::default();
    loop {
        match reader.read(&mut resumed.peer).await.unwrap() {
            Frame::InputAck(written) => assert_eq!(written, input.len() as u64),
            Frame::InputState(written, accepted) => {
                assert_eq!(
                    (written, accepted),
                    (input.len() as u64, input.len() as u64)
                );
                break;
            }
            _ => panic!("unexpected writer-state frame kind"),
        }
    }
}
