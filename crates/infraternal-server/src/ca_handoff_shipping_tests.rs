//! Runs the shipping restart CLI, reload signal, rollback and cold-start paths against real listeners [168][217], #154.

use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn shipping_child() {
    use std::os::unix::{fs::DirBuilderExt, process::CommandExt};
    let Some(directory) = std::env::var_os("INFRATERNAL_HANDOFF_TEST_DIRECTORY") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let ca = directory.join("ca");
    let input = if let Ok(failure) = std::env::var("INFRATERNAL_HANDOFF_TEST_FAILURE") {
        let material = crate::ca::tests::test_material();
        let mut frame = encode(&material).unwrap();
        if failure == "truncated" {
            frame.truncate(HEADER - 1);
        } else {
            frame[4] = 2;
        }
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.write_all(&frame).unwrap();
        drop(writer);
        reader
    } else {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&ca)
            .unwrap();
        std::fs::File::create(ca.join("pending")).unwrap();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let configuration = crate::ca_bootstrap::BootstrapConfig {
            directory: ca.clone(),
            name: "localhost".into(),
            address: "127.0.0.1:0".parse().unwrap(),
            deferred: false,
        };
        // Use the real encrypted publication path. The signing seed and wrapping
        // key never enter a fixture file, argument, environment variable or log.
        let wrapping = Zeroizing::new(rand::random::<[u8; 32]>());
        let material = crate::ca_bootstrap::publish_first(
            &configuration,
            "test-owner",
            1,
            &[0; 32],
            &wrapping,
            now,
        )
        .unwrap();
        let source = std::sync::Arc::new(MemoryCaSource::cold_start_with_system_https(
            material.issuer().clone(),
        ));
        crate::ca_bootstrap::install(&source, material).unwrap();
        prepare(source.as_ref()).unwrap()
    };
    let binary = std::env::var_os("INFRATERNAL_TEST_BINARY").unwrap();
    let error = Command::new(binary)
        .arg("server")
        .args([
            "--listen",
            &std::env::var("INFRATERNAL_HANDOFF_TEST_ADDRESS").unwrap(),
        ])
        .arg("--data")
        .arg(directory.join("data"))
        .args([
            "--public-origin",
            "https://localhost",
            "--behind-proxy",
            "--trusted-proxy",
            "127.0.0.1",
            "--remote-listen",
            &std::env::var("INFRATERNAL_HANDOFF_TEST_REMOTE_ADDRESS").unwrap(),
        ])
        .arg("--remote-ca-dir")
        .arg(ca)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(input)))
        .exec();
    panic!("shipping exec failed: {}", error.kind());
}

struct Fixture {
    child: Child,
    directory: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Every socket under this fixture was created by its own shim. Terminate
        // only those verified same-UID peer PIDs before removing test state.
        let sessions = self
            .directory
            .parent()
            .unwrap()
            .join("r/infraternal/sessions");
        if let Ok(entries) = std::fs::read_dir(sessions) {
            for entry in entries.flatten() {
                if let Ok(socket) = UnixStream::connect(entry.path())
                    && let Ok(peer) = getsockopt(&socket, sockopt::PeerCredentials)
                    && peer.uid() == nix::unistd::Uid::effective().as_raw()
                    && peer.pid() > 0
                {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(peer.pid()),
                        nix::sys::signal::Signal::SIGTERM,
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.directory);
        let _ = std::fs::remove_dir_all(self.directory.parent().unwrap().join("r"));
    }
}

async fn http(
    address: std::net::SocketAddr,
    path: &str,
    token: Option<&str>,
) -> Option<serde_json::Value> {
    let mut socket = tokio::net::TcpStream::connect(address).await.ok()?;
    let cookie = token.map_or_else(String::new, |token| {
        format!("Cookie: __Host-infraternal={token}\r\n")
    });
    let request = format!(
        "{} {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: https://localhost\r\n{cookie}Content-Length: 0\r\nConnection: close\r\n\r\n",
        if token.is_some() { "POST" } else { "GET" }
    );
    socket.write_all(request.as_bytes()).await.ok()?;
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).await.ok()?;
    if !bytes.starts_with(b"HTTP/1.1 200") {
        return None;
    }
    let body = bytes.windows(4).position(|part| part == b"\r\n\r\n")? + 4;
    serde_json::from_slice(&bytes[body..]).ok()
}
async fn healthy(address: std::net::SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::timeout(Duration::from_secs(1), http(address, "/healthz", None))
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "shipping health deadline exceeded"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit shipping-binary integration/benchmark; set INFRATERNAL_TEST_BINARY"]
async fn shipping_restart_reload_rollback_and_cold_start() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_TEST_BINARY").unwrap());
    let root =
        PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/codex-scratch/ca-handoff");
    // Short path preserves Linux's Unix-socket limit for the real shims.
    let directory = root.join(format!("p{}", std::process::id()));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root.join("r"))
        .unwrap();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let remote_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_address = remote_reservation.local_addr().unwrap();
    drop(remote_reservation);
    let profile = directory.join("profile");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&profile)
        .unwrap();
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../infraternal/tests/profile/.zshrc"),
        profile.join(".zshrc"),
    )
    .unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "ca_handoff::shipping_tests::shipping_child",
            "--nocapture",
        ])
        .env("INFRATERNAL_HANDOFF_TEST_DIRECTORY", &directory)
        .env("INFRATERNAL_HANDOFF_TEST_ADDRESS", address.to_string())
        .env(
            "INFRATERNAL_HANDOFF_TEST_REMOTE_ADDRESS",
            remote_address.to_string(),
        )
        .env("XDG_RUNTIME_DIR", root.join("r"))
        .env("ZDOTDIR", &profile)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(root.join("shipping-server.log")).unwrap())
        .spawn()
        .unwrap();
    let mut fixture = Fixture { child, directory };
    healthy(address).await;
    let data = fixture.directory.join("data");
    let denied = Command::new("sudo").args(["-n", "-u", "nobody", "python3", "-c",
        "import socket,sys; s=socket.socket(socket.AF_UNIX);\ntry: s.connect(sys.argv[1])\nexcept PermissionError: sys.exit(0)\nsys.exit(1)"])
        .arg(data.join("restart/control.sock")).output().unwrap();
    assert!(
        denied.status.success(),
        "non-owner could reach the restart socket"
    );
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new().filename(data.join("infraternal.sqlite")),
        )
        .await
        .unwrap();
    // This fixture session tests status/terminal continuity; CA authorization is
    // separately exercised by the real passkey suite. Only its hash is persisted.
    let token = B64.encode(rand::random::<[u8; 32]>());
    sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES('test-owner','Fixture','fixture','Fixture',1,'unused')").execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO passkeys(id,user_id,credential) VALUES('fixture-key','test-owner','{}')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked,passkey_id) VALUES(?,'test-owner','fixture',unixepoch()+3600,unixepoch(),1,'fixture-key')")
        .bind(crate::auth::hash(&token)).execute(&pool).await.unwrap();
    assert_eq!(
        http(address, "/remote/ca/status", Some(&token))
            .await
            .unwrap()["locked"],
        false
    );

    // Exercise the real process after the socket reply has become unwritable.
    // Shutting down the read half before sending makes EPIPE deterministic.
    let endpoint = data.join("restart/control.sock");
    let before_reply_failure = std::fs::metadata(&endpoint).unwrap();
    let mut closed = UnixStream::connect(&endpoint).unwrap();
    closed.shutdown(std::net::Shutdown::Read).unwrap();
    let request_path = binary.as_os_str().as_encoded_bytes();
    closed
        .write_all(&u16::try_from(request_path.len()).unwrap().to_be_bytes())
        .unwrap();
    closed.write_all(request_path).unwrap();
    closed.shutdown(std::net::Shutdown::Write).unwrap();
    drop(closed);
    tokio::time::sleep(Duration::from_millis(250)).await;
    healthy(address).await;
    assert!(
        std::fs::read_to_string(root.join("shipping-server.log"))
            .unwrap()
            .contains("reply_failed"),
        "shipping EPIPE must reach and exercise the reply failure branch"
    );
    assert_eq!(
        std::fs::metadata(&endpoint).unwrap().ino(),
        before_reply_failure.ino(),
        "failed reply restarted the real server"
    );
    assert_eq!(
        http(address, "/remote/ca/status", Some(&token))
            .await
            .unwrap()["locked"],
        false
    );
    assert!(fixture.child.try_wait().unwrap().is_none());

    if !nix::unistd::Uid::effective().is_root() {
        // A real user-mode server still replaces its image, but never exports.
        cold_replacement(&binary, &binary, &data, address, &token, &mut fixture).await;
        println!(
            "METRIC name=ca_handoff_rootless n=1 restart_cold=true reply_cold=true pid_preserved=true fd0_dev_null=true epipe_keeps_server=true"
        );
        pool.close().await;
        return;
    }

    let mut transaction = pool.begin().await.unwrap();
    for index in 0..49 {
        sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES(?, 'Fixture', ?, 'Fixture',0,'unused')")
            .bind(format!("fixture-{index}")).bind(format!("fixture-{index}")).execute(&mut *transaction).await.unwrap();
    }
    for _ in 0..10000 {
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'test-owner',?,?,unixepoch())")
            .bind(uuid::Uuid::new_v4().as_bytes().as_slice()).bind(if nix::unistd::Uid::effective().is_root() { "rootful" } else { "rootless" }).bind(nix::unistd::Uid::effective().as_raw()).execute(&mut *transaction).await.unwrap();
    }
    transaction.commit().await.unwrap();
    let sessions = terminals(address, &token, "https://localhost").await;
    let original_pids = shim_pids(&fixture.directory, &sessions);
    let mut attached = attach_all(address, &token, &sessions, "https://localhost").await;
    let candidate = fixture.directory.join("candidate");
    std::fs::copy(&binary, &candidate).unwrap();
    let mut times = Vec::new();
    let mut gaps = Vec::new();
    for iteration in 0..25 {
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let probe_active = active.clone();
        let (ready, preparation) = tokio::sync::oneshot::channel();
        let probe = tokio::spawn(async move {
            // Establish the pre-restart success before the caller triggers exec.
            drop(tokio::net::TcpStream::connect(address).await.unwrap());
            let start = Instant::now();
            ready.send(()).unwrap();
            let mut first = None;
            let mut last_success = Duration::ZERO;
            let mut recovered = None;
            let mut failures = 0;
            while probe_active.load(std::sync::atomic::Ordering::Relaxed) {
                if tokio::net::TcpStream::connect(address).await.is_err() {
                    first.get_or_insert(last_success);
                    failures += 1;
                } else {
                    let stamp = start.elapsed();
                    if first.is_some() && recovered.is_none() {
                        recovered = Some(stamp);
                    }
                    last_success = stamp;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            (
                // The caller stops sampling only after successful live CA status.
                // Termination time bounds that success if the probe missed it.
                first
                    .zip(Some(recovered.unwrap_or_else(|| start.elapsed())))
                    .map_or(0.0, |(first, last)| {
                        last.checked_sub(first).unwrap().as_secs_f64() * 1000.0
                    }),
                failures,
            )
        });
        preparation.await.unwrap();
        let old_socket = std::fs::metadata(data.join("restart/control.sock")).unwrap();
        let start = Instant::now();
        if iteration == 24 {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(fixture.child.id()).unwrap()),
                nix::sys::signal::Signal::SIGHUP,
            )
            .unwrap();
        } else {
            let mut request = tokio::process::Command::new(&binary);
            request
                .arg("server")
                .arg("--data")
                .arg(&data)
                .arg("restart")
                .arg("--json");
            if iteration != 23 {
                request.arg("--binary").arg(if iteration % 2 == 0 {
                    &candidate
                } else {
                    &binary
                });
            }
            let output = request.output().await.unwrap();
            assert!(output.status.success(), "shipping restart request refused");
        }
        // Wait until the new control endpoint exists and reports CA state. The
        // old health response alone could otherwise race ahead of exec.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let replaced = std::fs::metadata(data.join("restart/control.sock")).is_ok_and(|meta| {
                (meta.ino(), meta.ctime_nsec()) != (old_socket.ino(), old_socket.ctime_nsec())
            });
            if replaced
                && http(address, "/remote/ca/status", Some(&token))
                    .await
                    .is_some_and(|status| status["locked"] == false)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "restart did not restore unlocked CA"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(
            fixture.child.try_wait().unwrap().is_none(),
            "exec did not preserve the service process"
        );
        times.push(start.elapsed().as_secs_f64() * 1000.0);
        if iteration == 0 {
            attached.clear();
        }
        assert!(
            shim_pids(&fixture.directory, &sessions) == original_pids,
            "restart replaced a surviving shim"
        );
        active.store(false, std::sync::atomic::Ordering::Relaxed);
        gaps.push(probe.await.unwrap());
    }
    attached = attach_all(address, &token, &sessions, "https://localhost").await;
    assert_eq!(attached.len(), sessions.len().div_ceil(25));
    wire_send(
        &mut attached[0],
        1,
        &infraternal_protocol::Frame::Input {
            in_seq: 0,
            bytes: b"printf '%s%s\\n' 'handoff-' 'continued'\n",
        },
    )
    .await;
    let mut echo = Vec::new();
    loop {
        let bytes = wire_read(&mut attached[0]).await;
        let decoded = infraternal_protocol::decode_muxed_frame(&bytes).unwrap();
        if decoded.stream_id == 1
            && let infraternal_protocol::Frame::Output { bytes, .. } = decoded.frame
        {
            echo.extend_from_slice(bytes);
            if echo
                .windows(b"handoff-continued".len())
                .any(|part| part == b"handoff-continued")
            {
                break;
            }
            assert!(
                echo.len() < 65536,
                "resumed PTY output exceeded fixture budget"
            );
        }
    }
    attached.clear();

    // Remove only the compatibility record from PT_NOTE, keeping the actual
    // executable otherwise identical. This models a pre-import rollback.
    let rollback = fixture.directory.join("unmarked-rollback");
    let mut bytes = std::fs::read(&binary).unwrap();
    let table = usize::try_from(u64::from_le_bytes(bytes[32..40].try_into().unwrap())).unwrap();
    let count = usize::from(u16::from_le_bytes(bytes[56..58].try_into().unwrap()));
    let marker = b"\x0c\0\0\0\x04\0\0\0ACFIINFRATERNAL\0\x01\0\0\0";
    let mut removed = false;
    for index in 0..count {
        let program = table + index * 56;
        if bytes[program..program + 4] != 4u32.to_le_bytes() {
            continue;
        }
        let offset = usize::try_from(u64::from_le_bytes(
            bytes[program + 8..program + 16].try_into().unwrap(),
        ))
        .unwrap();
        let length = usize::try_from(u64::from_le_bytes(
            bytes[program + 32..program + 40].try_into().unwrap(),
        ))
        .unwrap();
        if let Some(position) = bytes[offset..offset + length]
            .windows(marker.len())
            .position(|record| record == marker)
        {
            bytes[offset + position + 24] = 0;
            removed = true;
        }
    }
    assert!(removed);
    std::fs::write(&rollback, bytes).unwrap();
    std::fs::set_permissions(
        &rollback,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    assert!(!crate::ca_handoff_binary::capable(&std::fs::File::open(&rollback).unwrap()).unwrap());
    cold_replacement(&binary, &rollback, &data, address, &token, &mut fixture).await;
    let audit = std::fs::read_to_string(root.join("shipping-server.log")).unwrap();
    assert!(
        audit
            .lines()
            .any(|line| line.contains("server_ca_startup") && line.contains("warm"))
    );
    assert!(
        audit
            .lines()
            .any(|line| line.contains("server_ca_startup") && line.contains("cold"))
    );
    assert!(audit.contains(&format!("service_pid={}", fixture.child.id())));
    println!(
        "METRIC name=ca_handoff_unmarked_rollback root_owned=true restart_cold=true reply_cold=true pid_preserved=true fd0_dev_null=true epipe_keeps_server=true"
    );

    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    fixture.child = Command::new(&binary)
        .arg("server")
        .args([
            "--listen",
            &address.to_string(),
            "--public-origin",
            "https://localhost",
            "--behind-proxy",
            "--trusted-proxy",
            "127.0.0.1",
            "--remote-listen",
            &remote_address.to_string(),
        ])
        .arg("--data")
        .arg(&data)
        .arg("--remote-ca-dir")
        .arg(fixture.directory.join("ca"))
        .env("XDG_RUNTIME_DIR", root.join("r"))
        .env("ZDOTDIR", &profile)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    healthy(address).await;
    assert_eq!(
        http(address, "/remote/ca/status", Some(&token))
            .await
            .unwrap()["locked"],
        true
    );
    for failure in ["truncated", "wrong-version"] {
        fixture.child.kill().unwrap();
        fixture.child.wait().unwrap();
        fixture.child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ca_handoff::shipping_tests::shipping_child",
                "--nocapture",
            ])
            .env("INFRATERNAL_HANDOFF_TEST_DIRECTORY", &fixture.directory)
            .env("INFRATERNAL_HANDOFF_TEST_ADDRESS", address.to_string())
            .env(
                "INFRATERNAL_HANDOFF_TEST_REMOTE_ADDRESS",
                remote_address.to_string(),
            )
            .env("INFRATERNAL_HANDOFF_TEST_FAILURE", failure)
            .env("XDG_RUNTIME_DIR", root.join("r"))
            .env("ZDOTDIR", &profile)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        healthy(address).await;
        assert_eq!(
            http(address, "/remote/ca/status", Some(&token))
                .await
                .unwrap()["locked"],
            true
        );
    }
    times.sort_by(f64::total_cmp);
    let refusals: usize = gaps.iter().map(|(_, count)| count).sum();
    let mut windows: Vec<f64> = gaps.iter().map(|(gap, _)| *gap).collect();
    windows.sort_by(f64::total_cmp);
    println!(
        "METRIC name=ca_handoff_restart n=25 retained_nodes=10000 users=50 real_pty_sessions=128 reattached_sessions=128 p50_ms={:.3} max_ms={:.3} refused_window_bracket_p50_ms={:.3} refused_window_bracket_max_ms={:.3} refused_samples={} probe_interval_ms=1 cold_start_locked=true invalid_frame_locked=true non_owner_refused=true resumed_pty_input=true",
        times[12], times[24], windows[12], windows[24], refusals
    );
    pool.close().await;
}

#[path = "ca_handoff_browser_tests.rs"]
mod browser_client;
pub(crate) use browser_client::Browser;

pub(crate) async fn wire_send(
    socket: &mut Browser,
    stream: u32,
    frame: &infraternal_protocol::Frame<'_>,
) {
    socket.send(stream, frame).await;
}
pub(crate) async fn wire_read(socket: &mut Browser) -> bytes::Bytes {
    socket.read().await
}
pub(crate) async fn connect_browser(
    address: std::net::SocketAddr,
    token: &str,
    origin: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://{address}/v1/ws")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Origin", origin.parse().unwrap());
    request.headers_mut().insert(
        "Cookie",
        format!("__Host-infraternal={token}").parse().unwrap(),
    );
    let (socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    socket
}
async fn browser(address: std::net::SocketAddr, token: &str, origin: &str) -> Browser {
    use infraternal_protocol::{Frame, decode_muxed_frame};
    let mut socket = Browser::new(connect_browser(address, token, origin).await);
    let hello = wire_read(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&hello).unwrap().frame,
        Frame::Hello { .. }
    ));
    wire_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "handoff-fixture",
        },
    )
    .await;
    let welcome = wire_read(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&welcome).unwrap().frame,
        Frame::Welcome { .. }
    ));
    socket
}
pub(crate) async fn terminals(
    address: std::net::SocketAddr,
    token: &str,
    origin: &str,
) -> Vec<[u8; 16]> {
    use infraternal_protocol::{Frame, decode_muxed_frame};
    let mut socket = browser(address, token, origin).await;
    let mut sessions = Vec::new();
    for call_id in 1..=u32::try_from(infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS).unwrap()
    {
        wire_send(
            &mut socket,
            0,
            &Frame::Call {
                call_id,
                action_id: "terminal.open",
                input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
            },
        )
        .await;
        loop {
            let result = wire_read(&mut socket).await;
            match decode_muxed_frame(&result).unwrap().frame {
                Frame::Result { ok: true, json, .. } => {
                    let value: serde_json::Value = serde_json::from_slice(json).unwrap();
                    sessions.push(
                        *uuid::Uuid::parse_str(value["session_id"].as_str().unwrap())
                            .unwrap()
                            .as_bytes(),
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    break;
                }
                Frame::Result { ok: false, .. } => {
                    panic!("real PTY backend refused call {call_id}")
                }
                Frame::Event { .. } => {}
                Frame::Close { code, .. } => {
                    panic!("PTY creation socket closed with code {code} at call {call_id}")
                }
                frame => panic!(
                    "unexpected frame kind {:?} while opening real PTY at call {call_id}",
                    std::mem::discriminant(&frame)
                ),
            }
        }
    }
    sessions
}
pub(crate) async fn attach_all(
    address: std::net::SocketAddr,
    token: &str,
    sessions: &[[u8; 16]],
    origin: &str,
) -> Vec<Browser> {
    use infraternal_protocol::{Frame, decode_muxed_frame};
    let mut browsers = Vec::new();
    for chunk in sessions.chunks(25) {
        let mut socket = browser(address, token, origin).await;
        for (index, session_id) in chunk.iter().enumerate() {
            let stream = u32::try_from(index * 2 + 1).unwrap();
            wire_send(
                &mut socket,
                stream,
                &Frame::AttachTerm {
                    session_id,
                    last_out_seq: 0,
                    last_in_seq: 0,
                },
            )
            .await;
            loop {
                let bytes = wire_read(&mut socket).await;
                let frame = decode_muxed_frame(&bytes).unwrap();
                if frame.stream_id == stream && matches!(frame.frame, Frame::Ack { .. }) {
                    break;
                }
            }
            wire_send(&mut socket, stream, &Frame::Credit { bytes: 65536 }).await;
        }
        browsers.push(socket);
    }
    browsers
}
pub(crate) fn shim_pids(directory: &std::path::Path, sessions: &[[u8; 16]]) -> Vec<i32> {
    shim_pids_at(
        &directory.parent().unwrap().join("r/infraternal/sessions"),
        sessions,
    )
}

pub(crate) fn shim_pids_at(runtime: &std::path::Path, sessions: &[[u8; 16]]) -> Vec<i32> {
    sessions
        .iter()
        .map(|id| {
            let socket = UnixStream::connect(
                runtime.join(format!("{}.sock", uuid::Uuid::from_bytes(*id).simple())),
            )
            .unwrap();
            getsockopt(&socket, sockopt::PeerCredentials).unwrap().pid()
        })
        .collect()
}

/// The reply and the successor's CA state must agree on a deliberately cold exec.
async fn cold_replacement(
    binary: &std::path::Path,
    target: &std::path::Path,
    data: &std::path::Path,
    address: std::net::SocketAddr,
    token: &str,
    fixture: &mut Fixture,
) {
    use std::os::unix::fs::MetadataExt;
    let endpoint = data.join("restart/control.sock");
    let previous = std::fs::metadata(&endpoint).unwrap();
    let output = tokio::process::Command::new(binary)
        .arg("server")
        .arg("--data")
        .arg(data)
        .arg("restart")
        .arg("--binary")
        .arg(target)
        .arg("--json")
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout).unwrap().contains("cold"),
        "cold restart reply omitted CA state"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let replaced = std::fs::metadata(&endpoint).is_ok_and(|now| {
            (now.ino(), now.ctime_nsec()) != (previous.ino(), previous.ctime_nsec())
        });
        if replaced
            && http(address, "/remote/ca/status", Some(token))
                .await
                .is_some_and(|status| status["locked"] == true)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cold successor did not serve locked CA"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(fixture.child.try_wait().unwrap().is_none());
    let descriptor = format!("/proc/{}/fd/0", fixture.child.id());
    let null = if nix::unistd::Uid::effective().is_root() {
        std::fs::read_link(&descriptor).unwrap()
    } else {
        // Inspect only this fixture's fd 0: dumpability blocks same-UID proc reads.
        let inspected = Command::new("sudo")
            .args(["-n", "readlink", &descriptor])
            .output()
            .unwrap();
        assert!(inspected.status.success());
        PathBuf::from(String::from_utf8(inspected.stdout).unwrap().trim())
    };
    assert_eq!(null, std::path::Path::new("/dev/null"));
}
