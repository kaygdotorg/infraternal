//! Root upgrade steps over the relay behave like SSH commands, through the real helper binary (D376, #399).
//!
//! `RelaySession` runs each install step through `infraternal
//! __privilege-channel`, so these tests use the built binary
//! (`CARGO_BIN_EXE_infraternal`). A stand-in relay in this process runs each
//! step under `/bin/sh -c` as this account and answers with the real frames.
#![cfg(all(feature = "ssh", feature = "remote", target_os = "linux"))]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_remote::privilege_relay::{Decoder, Frame};
use infraternal_plugin_ssh::{
    relay_session::{Pump, RelaySession},
    transport::{Input, Operation, SshSession as _},
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{io::AsyncWriteExt as _, sync::mpsc};

/// A relay stand-in: runs each `Open` under `/bin/sh -c` and answers with
/// `Stdout`, `Stderr` and `Exit` frames. Setting `closed` makes it vanish.
struct FakeRelay {
    inbox: Mutex<Decoder>,
    outbox: Arc<Mutex<Vec<u8>>>,
    children: Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    closed: AtomicBool,
}

impl FakeRelay {
    /// A stand-in that has already said `Ready`.
    fn new() -> Arc<Self> {
        let relay = Arc::new(Self {
            inbox: Mutex::new(Decoder::default()),
            outbox: Arc::new(Mutex::new(Vec::new())),
            children: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        Frame::Ready.encode(&mut relay.outbox.lock().unwrap());
        relay
    }

    /// Start one script as this process's child.
    fn open(&self, channel: u32, script: String) {
        let (stdin, mut input) = mpsc::unbounded_channel::<Vec<u8>>();
        self.children.lock().unwrap().insert(channel, stdin);
        let outbox = self.outbox.clone();
        tokio::spawn(async move {
            let mut child = tokio::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut pipe = child.stdin.take().unwrap();
            tokio::spawn(async move {
                while let Some(bytes) = input.recv().await {
                    if pipe.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
            });
            let output = child.wait_with_output().await.unwrap();
            let mut out = outbox.lock().unwrap();
            Frame::Stdout {
                channel,
                bytes: output.stdout,
            }
            .encode(&mut out);
            Frame::Stderr {
                channel,
                bytes: output.stderr,
            }
            .encode(&mut out);
            Frame::Exit {
                channel,
                code: output
                    .status
                    .code()
                    .and_then(|code| u8::try_from(code).ok()),
            }
            .encode(&mut out);
        });
    }
}

impl Pump for FakeRelay {
    /// Takes the server's frames, runs what they ask, and returns what the scripts said.
    fn pump(&self, bytes: Vec<u8>) -> Operation<'_, (Vec<u8>, bool)> {
        Box::pin(async move {
            let mut frames = Vec::new();
            {
                let mut inbox = self.inbox.lock().unwrap();
                inbox.push(&bytes);
                while let Ok(Some(frame)) = inbox.frame() {
                    frames.push(frame);
                }
            }
            for frame in frames {
                match frame {
                    Frame::Open { channel, script } => self.open(channel, script),
                    Frame::Stdin { channel, bytes } => {
                        if let Some(child) = self.children.lock().unwrap().get(&channel) {
                            let _ = child.send(bytes);
                        }
                    }
                    Frame::StdinEnd { channel } => {
                        self.children.lock().unwrap().remove(&channel);
                    }
                    Frame::Close => self.closed.store(true, Ordering::SeqCst),
                    _ => {}
                }
            }
            // sleep: pace the stand-in like the real pump's short wait for news.
            tokio::time::sleep(Duration::from_millis(5)).await;
            let out = std::mem::take(&mut *self.outbox.lock().unwrap());
            Ok((out, self.closed.load(Ordering::SeqCst)))
        })
    }
}

/// A private scratch directory for the helper socket.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("relay-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Start a session on a fresh stand-in relay.
async fn session(name: &str) -> (Arc<FakeRelay>, RelaySession, PathBuf) {
    let dir = scratch(name);
    let relay = FakeRelay::new();
    let session = RelaySession::start(
        relay.clone(),
        &dir,
        PathBuf::from(env!("CARGO_BIN_EXE_infraternal")),
        Duration::from_secs(30),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    (relay, session, dir)
}

/// Output, stdin and exit codes come through as over SSH, and an exit-71
/// refusal keeps its exit code for the installer's typed refusal.
#[tokio::test]
async fn steps_behave_like_ssh_commands() {
    let (_relay, session, dir) = session("steps").await;
    let output = session
        .run(
            "read line; printf 'got %s' \"$line\"",
            Input::Bytes(b"hello\n"),
        )
        .await
        .unwrap();
    assert_eq!(output.stdout, b"got hello");
    let large = vec![b'x'; 700_000];
    let output = session
        .run("wc -c | tr -d ' '", Input::Bytes(&large))
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "700000");
    let Err(failure) = session
        .run(
            "printf 'INFRATERNAL_REFUSED owner\\n' >&2; exit 71",
            Input::Empty,
        )
        .await
    else {
        panic!("the refusal should fail the step");
    };
    assert_eq!(failure.exit_status, Some(71));
    session.close();
    let _ = std::fs::remove_dir_all(dir);
}

/// When the relay vanishes, a running step ends like a dropped SSH
/// connection (exit 255) and later steps are refused.
#[tokio::test]
async fn a_lost_relay_fails_every_step() {
    let (relay, session, dir) = session("lost").await;
    let running = tokio::spawn({
        let relay = relay.clone();
        async move {
            // sleep: let the step below reach the stand-in before it vanishes.
            tokio::time::sleep(Duration::from_millis(300)).await;
            relay.closed.store(true, Ordering::SeqCst);
        }
    });
    let Err(failure) = session.run("sleep 30", Input::Empty).await else {
        panic!("the step should fail");
    };
    running.await.unwrap();
    assert_eq!(failure.exit_status, Some(255), "{failure:?}");
    assert!(session.lost());
    assert!(session.run("true", Input::Empty).await.is_err());
    let _ = std::fs::remove_dir_all(dir);
}
