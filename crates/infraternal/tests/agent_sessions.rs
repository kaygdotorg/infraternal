//! Real shim launch, session discovery and exact byte-offset replay [13][41].
#![cfg(feature = "plugin-agent")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_agent::sessions::{Manager, Reader, discover, launch, send, state};
use infraternal_shim::frame::Frame;
use std::{
    fs,
    io::Write,
    os::unix::ffi::OsStrExt,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{net::UnixStream, time::timeout};

struct Cleanup {
    state: PathBuf,
    pid: u32,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.pid != 0
            && let Ok(pid) = i32::try_from(self.pid)
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = fs::remove_dir_all(&self.state);
    }
}

struct CleanupMany {
    state: PathBuf,
    pids: Vec<u32>,
}
impl Drop for CleanupMany {
    fn drop(&mut self) {
        for pid in self.pids.iter().copied().filter(|pid| *pid != 0) {
            if let Ok(pid) = i32::try_from(pid) {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        let _ = fs::remove_dir_all(&self.state);
    }
}

// Share the native fixture owner so fallback directories are also removed on panic.
#[path = "../../infraternal-shim/tests/unit/fixture_state.rs"]
mod fixture_state;

async fn until(peer: &mut UnixStream, cursor: &mut u64, marker: &[u8]) {
    let mut reader = Reader::default();
    let mut tail = Vec::new();
    timeout(Duration::from_secs(10), async {
        loop {
            let Frame::Output(seq, bytes) = reader.read(peer).await.unwrap() else {
                panic!("expected raw shim output");
            };
            assert_eq!(
                seq, *cursor,
                "replay must be contiguous without duplication"
            );
            *cursor += u64::try_from(bytes.len()).unwrap();
            tail.extend_from_slice(&bytes);
            if tail.windows(marker.len()).any(|part| part == marker) {
                break;
            }
            // This oracle retains only a marker-sized suffix, independent of the
            // amount of shell output received. No screen contents are logged.
            if tail.len() > marker.len() {
                tail.drain(..tail.len() - marker.len());
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out awaiting {} at offset {}",
            String::from_utf8_lossy(marker),
            cursor
        )
    });
}

#[tokio::test(flavor = "current_thread")]
async fn detached_shim_is_discovered_and_replays_from_the_last_observed_offset() {
    let fixture = fixture_state::fixture_state();
    let directory = fixture.clone();
    // Validate the actual rendezvous after applying the configured fixture root.
    let socket = directory
        .join("sessions")
        .join(format!("{}.sock", "a".repeat(32)));
    assert!(
        socket.as_os_str().as_bytes().len() < 108,
        "test session socket path exceeds the Unix socket path limit"
    );
    let directory = state(Some(directory)).unwrap();
    // Reuse the shim lane's isolated login profile. User startup scripts can
    // consume terminal queries/input before the prompt, making early typing an
    // uncontrolled oracle. The wrapper changes only this test child's env.
    let wrapper = directory.join("launch");
    let profile = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/profile");
    let quote = |path: &Path| format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"));
    let script = format!(
        "#!/bin/sh\n# Launch the real shim with the existing canary profile.\nZDOTDIR={}; export ZDOTDIR\nexec {} \"$@\"\n",
        quote(&profile),
        quote(Path::new(env!("CARGO_BIN_EXE_infraternal")))
    );
    fs::write(&wrapper, script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let mut session = launch(
        &wrapper,
        &directory,
        Manager::Detached,
        nix::unistd::Uid::effective().as_raw(),
        80,
        24,
    )
    .await
    .unwrap();
    let _cleanup = Cleanup {
        state: directory.clone(),
        pid: session.pid,
    };
    let id = session.id;
    let mut cursor = 0;
    send(&mut session.peer, &Frame::ReadFrom(cursor))
        .await
        .unwrap();
    send(
        &mut session.peer,
        &Frame::Input(b"printf 'OPEN_%s\\n' OK\n".to_vec()),
    )
    .await
    .unwrap();
    until(&mut session.peer, &mut cursor, b"OPEN_OK\r\n").await;
    // A FIFO barrier holds the shell until the replacement reader is attached;
    // scheduler delays cannot coalesce BEFORE and AFTER into one old-peer frame.
    let pipe = std::env::current_dir()
        .unwrap()
        .join(&directory)
        .join("resume-gate");
    nix::unistd::mkfifo(
        &pipe,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    // Open both ends in the fixture so a failed test never leaves a blocking
    // FIFO writer behind; the shell alone reads the queued release line.
    let mut barrier = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pipe)
        .unwrap();
    let command = format!(
        "printf 'BEFORE_%s\\n' DROP; read marker < '{}'; printf 'AFTER_%s\\n' DROP\n",
        pipe.display()
    );
    send(&mut session.peer, &Frame::Input(command.into_bytes()))
        .await
        .unwrap();
    until(&mut session.peer, &mut cursor, b"BEFORE_DROP\r\n").await;
    drop(session); // Close the sole infraternal agent connection, retaining the shim.
    let mut discovered = discover(&directory).await.unwrap();
    assert_eq!(discovered.len(), 1);
    let mut session = discovered.pop().unwrap();
    assert_eq!(session.id, id);
    send(&mut session.peer, &Frame::ReadFrom(cursor))
        .await
        .unwrap();
    barrier.write_all(b"resume\n").unwrap();
    until(&mut session.peer, &mut cursor, b"AFTER_DROP\r\n").await;
    send(
        &mut session.peer,
        &Frame::Resize {
            cols: 91,
            rows: 31,
            px_w: 0,
            px_h: 0,
        },
    )
    .await
    .unwrap();
    send(&mut session.peer, &Frame::Input(b"stty size\n".to_vec()))
        .await
        .unwrap();
    until(&mut session.peer, &mut cursor, b"31 91\r\n").await;
}

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn restart_discovery_keeps_a_live_shim_and_drops_clean_exit_and_sigkill() {
    let fixture = fixture_state::fixture_state();
    let base = fixture.clone();
    let directory = state(Some(base)).unwrap();
    let mut cleanup = CleanupMany {
        state: directory.clone(),
        pids: Vec::new(),
    };
    let wrapper = directory.join("launch");
    let profile = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/profile");
    let quote = |path: &Path| format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"));
    let script = format!(
        "#!/bin/sh\n# Start a real shim with the isolated test login profile.\nZDOTDIR={}; export ZDOTDIR\nexec {} \"$@\"\n",
        quote(&profile),
        quote(Path::new(env!("CARGO_BIN_EXE_infraternal")))
    );
    fs::write(&wrapper, script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();

    let mut old_agent_sessions = Vec::with_capacity(16);
    let mut live_ids = Vec::with_capacity(16);
    for _ in 0..16 {
        let live = launch(
            &wrapper,
            &directory,
            Manager::Detached,
            nix::unistd::Uid::effective().as_raw(),
            80,
            24,
        )
        .await
        .unwrap();
        live_ids.push(live.id);
        cleanup.pids.push(live.pid);
        old_agent_sessions.push(live);
    }

    let mut clean_exit = launch(
        &wrapper,
        &directory,
        Manager::Detached,
        nix::unistd::Uid::effective().as_raw(),
        80,
        24,
    )
    .await
    .unwrap();
    let clean_session_id = clean_exit.id;
    let clean_process_id = clean_exit.pid;
    cleanup.pids.push(clean_process_id);
    let clean_exit_ready = infraternal_shim::readiness::Registration::new(
        infraternal_shim::process_exit_descriptor(clean_process_id).unwrap(),
    )
    .unwrap();
    send(&mut clean_exit.peer, &Frame::ReadFrom(clean_exit.head))
        .await
        .unwrap();
    send(&mut clean_exit.peer, &Frame::Input(b"exit\n".to_vec()))
        .await
        .unwrap();
    let mut reader = Reader::default();
    timeout(Duration::from_secs(60), clean_exit_ready.readable())
        .await
        .expect("the cleanly exited shim did not become readable")
        .unwrap();
    timeout(Duration::from_secs(60), async {
        loop {
            match reader.read(&mut clean_exit.peer).await.unwrap() {
                Frame::Exited(status, _) => {
                    assert_eq!(status, 0, "the clean-exit fixture must exit successfully");
                    break;
                }
                Frame::Output(..) | Frame::Snapshot(..) | Frame::SnapshotWithFlags(..) => {}
                frame => panic!("unexpected clean-exit frame: {frame:?}"),
            }
        }
    })
    .await
    .expect("the cleanly exited shim did not publish its exit event");
    let clean_socket = clean_exit.path.clone();
    drop(clean_exit);
    timeout(Duration::from_secs(5), async {
        while clean_socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the cleanly exited shim must remove its rendezvous");
    cleanup.pids.retain(|pid| *pid != clean_process_id);

    let killed = launch(
        &wrapper,
        &directory,
        Manager::Detached,
        nix::unistd::Uid::effective().as_raw(),
        80,
        24,
    )
    .await
    .unwrap();
    let killed_session_id = killed.id;
    let killed_process_id = i32::try_from(killed.pid).unwrap();
    let death = infraternal_shim::readiness::Registration::new(
        infraternal_shim::process_exit_descriptor(killed.pid).unwrap(),
    )
    .unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(killed_process_id),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    // Signal submission is not process death. Await kernel readiness before
    // testing a restart census so an in-flight listener teardown cannot reset
    // the discovery handshake. The separate exit-latency probe starts at kill.
    let _ = timeout(Duration::from_secs(5), death.readable())
        .await
        .unwrap()
        .unwrap();
    drop(death);
    cleanup.pids.retain(|pid| *pid != killed.pid);
    drop(killed);

    // Dropping the old agent's authenticated links leaves only the 16 real live
    // shims reattachable; discovery removes the clean and abruptly stopped rendezvous.
    drop(old_agent_sessions);
    let discovery_started = std::time::Instant::now();
    let discovered = timeout(Duration::from_secs(15), discover(&directory))
        .await
        .unwrap()
        .unwrap();
    let discovery_elapsed = discovery_started.elapsed();
    println!(
        "restart_inventory_discovery: live_shims=16 elapsed_ms={}",
        discovery_elapsed.as_millis()
    );
    assert_eq!(discovered.len(), live_ids.len());
    for id in &live_ids {
        assert!(discovered.iter().any(|session| session.id == *id));
    }
    assert!(
        !discovered
            .iter()
            .any(|session| session.id == clean_session_id)
    );
    assert!(
        !discovered
            .iter()
            .any(|session| session.id == killed_session_id)
    );

    for (index, mut live) in discovered.into_iter().enumerate() {
        let mut cursor = live.head;
        send(&mut live.peer, &Frame::ReadFrom(cursor))
            .await
            .unwrap();
        let marker = format!("RESTART_INVENTORY_LIVE_{index}");
        send(
            &mut live.peer,
            &Frame::Input(format!("printf '{marker}\\n'\n").into_bytes()),
        )
        .await
        .unwrap();
        until(
            &mut live.peer,
            &mut cursor,
            format!("{marker}\r\n").as_bytes(),
        )
        .await;
    }
}

#[test]
fn latency_fixture_accepts_the_unsolicited_startup_inventory() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    // Use the real shared verification fixture. Construct it separately from
    // initialization so a refused greeting still releases its owned daemon.
    let script = r#"
import os, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path('scripts').resolve()))
from agent_fixture import Binary, fixture_state, cleanup
with tempfile.TemporaryDirectory(prefix='ir', dir='/tmp') as root:
    # A private short root keeps every fixture socket within AF_UNIX limits,
    # independently of the caller's HOME and worktree path.
    os.environ['INFRATERNAL_AGENT_TEST_STATE_ROOT'] = root
    state = fixture_state('ir')
    socket_path = state / 'sessions' / ('a' * 32 + '.sock')
    upstream_path = socket_path.with_suffix('.upstream')
    assert max(len(os.fsencode(path)) for path in (socket_path, upstream_path)) < 108
    state.mkdir(mode=0o700)
    client = Binary.__new__(Binary)
    try:
        client.__init__(Path(sys.argv[1]), state)
        client.open()
        assert str(client.id) in client.inventory['session_ids'], 'open Result overtook its live census'
        client.attach()
        client.input(b"printf 'CENSUS_FIXTURE_OK\\n'\n")
        client.until(b'CENSUS_FIXTURE_OK')
        client.ping(168, 0)
    finally:
        if hasattr(client, 'child'):
            client.kill()
        cleanup(state)
"#;
    let result = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_infraternal"))
        .current_dir(root)
        .env("INFRATERNAL_TEST_RTT", "0")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "the existing latency fixture refused startup inventory: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
