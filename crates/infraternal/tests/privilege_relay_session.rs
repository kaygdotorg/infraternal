//! Root upgrade steps over the relay behave like SSH commands, through the real helper binary (D376, #399).
//!
//! `RelaySession` runs each install step through `infraternal
//! __privilege-channel`, so these tests use the built binary
//! (`CARGO_BIN_EXE_infraternal`). A stand-in relay in this process runs each
//! step under `/bin/sh -c` as this account and answers with the real frames.
#![cfg(all(feature = "ssh", feature = "remote", target_os = "linux"))]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_remote::privilege_relay::{Decoder, Frame, GuardState};
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
    arm_state: GuardState,
    commit_state: GuardState,
    closed: AtomicBool,
}

impl FakeRelay {
    /// A stand-in that has already said Ready.
    fn new() -> Arc<Self> {
        Self::with_guard_states(GuardState::Armed, GuardState::Committed)
    }

    /// A stand-in that returns `state` for each transaction's guard request.
    fn with_guard_state(guard_state: GuardState) -> Arc<Self> {
        Self::with_guard_states(guard_state, GuardState::Committed)
    }

    /// A stand-in that returns separate arm and commit receipts.
    fn with_guard_states(arm_state: GuardState, commit_state: GuardState) -> Arc<Self> {
        let relay = Arc::new(Self {
            inbox: Mutex::new(Decoder::default()),
            outbox: Arc::new(Mutex::new(Vec::new())),
            children: Mutex::new(HashMap::new()),
            arm_state,
            commit_state,
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
                    Frame::Rollback { transaction, .. } => {
                        Frame::Guard {
                            transaction,
                            state: self.arm_state,
                        }
                        .encode(&mut self.outbox.lock().unwrap());
                    }
                    Frame::Commit { transaction } => {
                        Frame::Guard {
                            transaction,
                            state: self.commit_state,
                        }
                        .encode(&mut self.outbox.lock().unwrap());
                    }
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
    session
        .arm_rollback(uuid::Uuid::nil(), "true".to_owned())
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
        panic!("a refused step must fail");
    };
    assert_eq!(failure.exit_status, Some(71));
    session.close();
    let _ = std::fs::remove_dir_all(dir);
}

/// The server reports a missing system manager and never starts an install step.
#[tokio::test]
async fn an_unavailable_guard_refuses_root_promotion_before_steps() {
    let dir = scratch("no-guard");
    let relay = FakeRelay::with_guard_state(GuardState::SystemdUnavailable);
    let session = RelaySession::start(
        relay,
        &dir,
        PathBuf::from(env!("CARGO_BIN_EXE_infraternal")),
        Duration::from_secs(30),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    let transaction = uuid::Uuid::from_u128(0xa);
    let armed = session.arm_rollback(transaction, "true".to_owned()).await;
    let marker = dir.join("install-step-ran");
    let step_failed = session
        .run(&format!("touch '{}'", marker.display()), Input::Empty)
        .await
        .is_err();
    let systemd_refusal = armed
        .as_ref()
        .err()
        .is_some_and(|failure| failure.to_string().contains("systemd system manager"));

    assert!(
        systemd_refusal && step_failed && !marker.exists(),
        "systemd_refusal={systemd_refusal}, step_failed={step_failed}, step_ran={}",
        marker.exists()
    );
    session.close();
    let _ = std::fs::remove_dir_all(dir);
}

/// A failed disarm receipt stops promotion before the server hands the host over.
#[tokio::test]
async fn a_guard_disarm_failure_keeps_handover_unconfirmed() {
    let dir = scratch("disarm-failed");
    let relay = FakeRelay::with_guard_states(GuardState::Armed, GuardState::DisarmFailed);
    let session = RelaySession::start(
        relay,
        &dir,
        PathBuf::from(env!("CARGO_BIN_EXE_infraternal")),
        Duration::from_secs(30),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    let transaction = uuid::Uuid::from_u128(0xb);
    session
        .arm_rollback(transaction, "true".to_owned())
        .await
        .unwrap();
    let commit = session.commit(transaction).await;
    let failure = commit.err();
    let cleanup_failure = failure.as_ref().is_some_and(|failure| {
        failure
            .to_string()
            .contains("could not finish removing its rollback guard")
    });

    assert!(cleanup_failure, "commit failure was {failure:?}");
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
        panic!("a step of a vanished relay must fail");
    };
    running.await.unwrap();
    assert_eq!(failure.exit_status, Some(255), "{failure:?}");
    assert!(session.lost());
    assert!(session.run("true", Input::Empty).await.is_err());
    let _ = std::fs::remove_dir_all(dir);
}

/// A pump onto the *real* relay loop (`privilege_relay_host::serve`) over an
/// in-memory pipe, playing the rootless agent: it writes the token first,
/// then carries the session's bytes. Dropping it is a lost link.
struct RealRelay {
    to_relay: tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
    from_relay: tokio::sync::Mutex<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    requests: tokio::sync::Mutex<Decoder>,
    lost: AtomicBool,
}

impl Pump for RealRelay {
    fn pump(&self, bytes: Vec<u8>) -> Operation<'_, (Vec<u8>, bool)> {
        Box::pin(async move {
            use tokio::io::AsyncReadExt as _;
            if self.lost.load(Ordering::SeqCst) {
                return Err(infraternal_plugin_ssh::model::Failure::install("lost"));
            }
            let mut guard_receipts = Vec::new();
            if !bytes.is_empty() {
                let mut requests = self.requests.lock().await;
                requests.push(&bytes);
                while let Ok(Some(frame)) = requests.frame() {
                    match frame {
                        Frame::Rollback { transaction, .. } => Frame::Guard {
                            transaction,
                            state: GuardState::Armed,
                        }
                        .encode(&mut guard_receipts),
                        Frame::Commit { transaction } => Frame::Guard {
                            transaction,
                            state: GuardState::Committed,
                        }
                        .encode(&mut guard_receipts),
                        _ => {}
                    }
                }
                self.to_relay.lock().await.write_all(&bytes).await.unwrap();
            }
            let mut buffer = vec![0; 1 << 20];
            let mut reader = self.from_relay.lock().await;
            let mut received =
                match tokio::time::timeout(Duration::from_millis(50), reader.read(&mut buffer))
                    .await
                {
                    Ok(Ok(0) | Err(_)) => return Ok((Vec::new(), true)),
                    Ok(Ok(read)) => buffer[..read].to_vec(),
                    Err(_) => Vec::new(),
                };
            received.extend_from_slice(&guard_receipts);
            Ok((received, false))
        })
    }
}

/// Start the real relay loop with `rollback`, and a session over it.
async fn real_session(
    name: &str,
    rollback: String,
) -> (
    Arc<RealRelay>,
    RelaySession,
    tokio::task::JoinHandle<std::io::Result<()>>,
    PathBuf,
) {
    let dir = scratch(name);
    let token = [9u8; 32];
    let (agent_side, relay_side) = tokio::io::duplex(1 << 20);
    let (relay_read, relay_write) = tokio::io::split(relay_side);
    let relay = tokio::spawn(async move {
        infraternal_agent::privilege_relay_host::serve(
            relay_read,
            relay_write,
            &token,
            Duration::from_secs(60),
        )
        .await
    });
    let (from_relay, mut to_relay) = tokio::io::split(agent_side);
    let mut first = Vec::new();
    Frame::Token { bytes: token }.encode(&mut first);
    to_relay.write_all(&first).await.unwrap();
    let pump = Arc::new(RealRelay {
        to_relay: tokio::sync::Mutex::new(to_relay),
        from_relay: tokio::sync::Mutex::new(from_relay),
        requests: tokio::sync::Mutex::new(Decoder::default()),
        lost: AtomicBool::new(false),
    });
    let session = RelaySession::start(
        pump.clone(),
        &dir,
        PathBuf::from(env!("CARGO_BIN_EXE_infraternal")),
        Duration::from_secs(30),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    session
        .arm_rollback(uuid::Uuid::nil(), rollback)
        .await
        .unwrap();
    (pump, session, relay, dir)
}

/// J415 R4 / B1: a link lost mid-install makes the real relay run the
/// install's rollback by itself; nothing from the server is needed.
#[tokio::test]
async fn a_lost_link_mid_install_rolls_back_on_the_host() {
    let marks = scratch("lost-link-marks");
    let rollback = format!(
        "rm -f '{0}/installed'; touch '{0}/rolled-back'",
        marks.display()
    );
    let (pump, session, relay, dir) = real_session("lost-link", rollback).await;
    session
        .run(
            &format!("touch '{}/installed'", marks.display()),
            Input::Empty,
        )
        .await
        .unwrap();
    assert!(marks.join("installed").exists());
    // The link goes: the rootless agent's socket end closes.
    pump.lost.store(true, Ordering::SeqCst);
    pump.to_relay.lock().await.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!marks.join("installed").exists());
    assert!(marks.join("rolled-back").exists());
    drop(session);
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(marks);
}

/// J415 R4: after the session's commit, closing ends the relay without a rollback.
#[tokio::test]
async fn a_committed_upgrade_is_not_rolled_back() {
    let marks = scratch("committed-marks");
    let rollback = format!("touch '{}/rolled-back'", marks.display());
    let (_pump, session, relay, dir) = real_session("committed", rollback).await;
    session.run("true", Input::Empty).await.unwrap();
    session.commit(uuid::Uuid::nil()).await.unwrap();
    session.close();
    tokio::time::timeout(Duration::from_secs(30), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!marks.join("rolled-back").exists());
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(marks);
}
