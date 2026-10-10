//! Real shim launch, session discovery and exact byte-offset replay [13][41].
#![cfg(feature = "plugin-agent")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_agent::sessions::{Manager, Reader, discover, launch, send, state};
use infraternal_shim::frame::Frame;
use std::{
    fs,
    io::Write,
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
    let directory = PathBuf::from(format!("../../target/ar{}", std::process::id()));
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
