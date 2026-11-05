//! Compares native QUIC replay with an independently read real shim ring across connection replacement [13][64][130], #78.

use super::Pair;
use crate::{
    channel::Channel,
    daemon,
    remote_native::NativeChannel,
    remote_quic, sessions,
    transport::{Receive, Transmit},
};
use infraternal_protocol::Frame;
use infraternal_shim::frame::Frame as Shim;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;

struct State {
    path: PathBuf,
    pid: Option<u32>,
}
impl Drop for State {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.and_then(|pid| i32::try_from(pid).ok()) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct Progress {
    cursor: u64,
    ack: u64,
    bytes: Vec<u8>,
}
impl Progress {
    async fn until(&mut self, rx: &mut Receive, channel: &impl Channel, marker: &[u8], ack: u64) {
        let result = tokio::time::timeout(Duration::from_secs(8), async {
            while self.ack < ack
                || !self
                    .bytes
                    .windows(marker.len())
                    .any(|bytes| bytes == marker)
            {
                let decoded = rx.next(channel).await.unwrap();
                assert_eq!(decoded.stream_id, 42);
                match decoded.frame {
                    Frame::Ack { in_seq_acked } => {
                        assert!(in_seq_acked >= self.ack);
                        self.ack = in_seq_acked;
                    }
                    Frame::Output { out_seq, bytes } => {
                        assert_eq!(
                            out_seq, self.cursor,
                            "raw output must be contiguous across reconnect"
                        );
                        self.cursor += u64::try_from(bytes.len()).unwrap();
                        self.bytes.extend_from_slice(bytes);
                        assert!(self.bytes.len() < 256 * 1024);
                    }
                    _ => panic!("unexpected native terminal frame"),
                }
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "native terminal timeout: public_marker={} cursor={} ack={} wanted_ack={} bytes={}",
            String::from_utf8_lossy(marker),
            self.cursor,
            self.ack,
            ack,
            self.bytes.len()
        );
    }
}

async fn attached(
    pair: &Pair,
    state: &State,
    id: [u8; 16],
    cursor: u64,
    input: u64,
) -> (
    NativeChannel,
    Receive,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let host = Arc::new(NativeChannel::terminal(host.unwrap()).unwrap());
    let path = state.path.clone();
    let daemon =
        tokio::spawn(async move { daemon::run_bound_terminal(host.as_ref(), Some(path)).await });
    let channel = NativeChannel::terminal(server.unwrap()).unwrap();
    let mut tx = Transmit::default();
    tx.send(
        &channel,
        42,
        &Frame::AttachTerm {
            session_id: &id,
            last_out_seq: cursor,
            last_in_seq: input,
        },
    )
    .await
    .unwrap();
    tx.send(&channel, 42, &Frame::Credit { bytes: 1_048_576 })
        .await
        .unwrap();
    let mut rx = Receive::default();
    assert!(
        matches!(rx.next(&channel).await.unwrap().frame,Frame::Ack {in_seq_acked} if in_seq_acked == input)
    );
    (channel, rx, daemon)
}

#[tokio::test]
#[ignore = "real CLI/shim oracle; set INFRATERNAL_TEST_BINARY and run alone under CPUWeight10000"]
async fn real_pty_resumes_native_writer_after_25_connection_replacements() {
    let binary = std::env::var_os("INFRATERNAL_TEST_BINARY").expect("explicit built CLI path");
    let id = uuid::Uuid::new_v4();
    let base = crate::test_state_root();
    let path = base.join(format!("n{}", &id.simple().to_string()[..8]));
    let path = sessions::state(Some(path)).unwrap();
    let mut state = State { path, pid: None };
    let profile = state.path.join("zsh");
    std::fs::create_dir(&profile).unwrap();
    std::fs::write(profile.join(".zshrc"), "# Isolated real-shell canary prompt for remote replay verification.\nPROMPT='NATIVE_FIXTURE> '\nRPROMPT=''\n").unwrap();
    let status = Command::new(binary)
        .env("ZDOTDIR", &profile)
        .args([
            "__shim",
            "--session",
            &id.simple().to_string(),
            "--uid",
            &nix::unistd::Uid::effective().as_raw().to_string(),
            "--state",
        ])
        .arg(&state.path)
        .arg("--detach")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let socket = state
        .path
        .join("sessions")
        .join(format!("{}.sock", id.simple()));
    let identity = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(session) = sessions::connect(socket.clone(), id.into_bytes()).await {
                break session;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    state.pid = Some(identity.pid);
    drop(identity);
    let mut pair = Pair::new().await;
    let (mut channel, mut rx, mut daemon) = attached(&pair, &state, id.into_bytes(), 0, 0).await;
    let mut progress = Progress {
        cursor: 0,
        ack: 0,
        bytes: Vec::new(),
    };
    // Wait for the real shell's prompt before sending a command. Bytes written
    // during login startup need not reach its later line editor unchanged.
    progress
        .until(&mut rx, &channel, b"NATIVE_FIXTURE>", 0)
        .await;
    // The full ready marker exists only in printed output, so receiving it also
    // proves stty executed before any subsequent raw replay-test payload is sent.
    let prelude = b"stty raw -echo; printf '__READY_%s__' native; cat\n";
    let mut tx = Transmit::default();
    tx.send(
        &channel,
        42,
        &Frame::Input {
            in_seq: 0,
            bytes: prelude,
        },
    )
    .await
    .unwrap();
    let mut input = u64::try_from(prelude.len()).unwrap();
    progress
        .until(&mut rx, &channel, b"__READY_native__", input)
        .await;
    let mut previous = b"__NATIVE_0__".to_vec();
    let mut previous_start = input;
    tx.send(
        &channel,
        42,
        &Frame::Input {
            in_seq: input,
            bytes: &previous,
        },
    )
    .await
    .unwrap();
    input += u64::try_from(previous.len()).unwrap();
    progress
        .until(&mut rx, &channel, b"__NATIVE_0__", input)
        .await;
    let mut elapsed = Vec::new();
    for sample in 1..=25 {
        tx.send(
            &channel,
            42,
            &Frame::Close {
                code: 1000,
                reason: "reattach",
            },
        )
        .await
        .unwrap();
        daemon.await.unwrap().unwrap();
        drop(channel);
        let begin = Instant::now();
        pair.client.close(0u32.into(), b"connection replacement");
        pair.server.close(0u32.into(), b"connection replacement");
        let (host, server) = tokio::join!(
            pair.client_endpoint
                .connect(pair.server_endpoint.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { pair.server_endpoint.accept().await.unwrap().await }
        );
        pair.client = host.unwrap();
        pair.server = server.unwrap();
        (channel, rx, daemon) =
            attached(&pair, &state, id.into_bytes(), progress.cursor, input).await;
        elapsed.push(begin.elapsed().as_micros());
        // Replay the already-written previous payload. The surviving shim's
        // writer cursor, not the replacement QUIC stream id, must discard it.
        tx.send(
            &channel,
            42,
            &Frame::Input {
                in_seq: previous_start,
                bytes: &previous,
            },
        )
        .await
        .unwrap();
        let marker = format!("__NATIVE_{sample}__");
        previous = marker.clone().into_bytes();
        previous_start = input;
        tx.send(
            &channel,
            42,
            &Frame::Input {
                in_seq: input,
                bytes: &previous,
            },
        )
        .await
        .unwrap();
        input += u64::try_from(previous.len()).unwrap();
        progress
            .until(&mut rx, &channel, marker.as_bytes(), input)
            .await;
    }
    tx.send(
        &channel,
        42,
        &Frame::Close {
            code: 1000,
            reason: "done",
        },
    )
    .await
    .unwrap();
    daemon.await.unwrap().unwrap();
    for sample in 0..=25 {
        let marker = format!("__NATIVE_{sample}__");
        assert_eq!(
            progress
                .bytes
                .windows(marker.len())
                .filter(|bytes| *bytes == marker.as_bytes())
                .count(),
            1,
            "duplicate payload delivery"
        );
    }
    // Read the surviving ring through a second authenticated local shim socket,
    // independent of QUIC, to prove the relayed prefix equals actual PTY bytes.
    let mut source = sessions::connect_writer(socket, id.into_bytes(), 44)
        .await
        .unwrap();
    let mut encoded = Vec::new();
    Shim::ReadFrom(0).encode_into(&mut encoded).unwrap();
    source.peer.write_all(&encoded).await.unwrap();
    let mut original = Vec::new();
    let mut reader = sessions::Reader::default();
    tokio::time::timeout(Duration::from_secs(5), async {
        while original.len() < progress.bytes.len() {
            match reader.read(&mut source.peer).await.unwrap() {
                Shim::Output(seq, bytes) => {
                    assert_eq!(seq, u64::try_from(original.len()).unwrap());
                    original.extend_from_slice(&bytes);
                }
                Shim::InputAck(_) => {}
                _ => panic!("unexpected retained source frame"),
            }
        }
    })
    .await
    .unwrap();
    assert!(
        original[..progress.bytes.len()] == progress.bytes,
        "retained source bytes differ"
    );
    elapsed.sort_unstable();
    println!(
        "native_terminal_recovery n=25 rtt_ms=0 p50_us={} p99_us={} exact_replayed_bytes={} echoed_markers=26 duplicate_payloads=0 uid={} load={}",
        elapsed[12],
        elapsed[24],
        progress.bytes.len(),
        nix::unistd::Uid::effective().as_raw(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}

#[path = "native_credit_tests.rs"]
mod credits;

#[path = "native_gone_review_tests.rs"]
mod gone_review;
