//! Proves signed deployment, real passkey CA custody and 128 live PTYs in an isolated perf-VM unit [217,250], #188.
use super::*;
use crate::ca_handoff::shipping_tests::{attach_all, terminals, wire_read, wire_send};
use std::net::SocketAddr;

/// Keeps staging fixtures inside normalized throwaway roots intended for the perf VM.
fn staging_root_is_allowed(root: &std::path::Path) -> bool {
    let Ok(relative) = root.strip_prefix("/root/infraternal-bench") else {
        return false;
    };
    let components: Vec<_> = relative.components().collect();
    if components
        .iter()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return false;
    }
    let Some(job) = components
        .first()
        .and_then(|component| component.as_os_str().to_str())
    else {
        return false;
    };
    if job == "deploy" {
        return components.len() >= 2;
    }
    components.len() >= 3
        && components
            .get(1)
            .and_then(|component| component.as_os_str().to_str())
            == Some("signed")
}

/// Reads session shim PIDs from the staging server's cgroup without crossing its private `/run` mount.
/// That bind mount hides the system manager socket, so session startup uses detached shims in this unit.
fn staging_shim_pids(unit: &str, sessions: &[[u8; 16]]) -> Vec<i32> {
    let output = std::process::Command::new("systemctl")
        .args(["show", unit, "--property=ControlGroup", "--value"])
        .output()
        .unwrap();
    assert!(output.status.success(), "staging server cgroup unavailable");
    let group = String::from_utf8(output.stdout).unwrap();
    let group = group.trim();
    assert!(!group.is_empty(), "staging server unit has no cgroup");
    let relative = group.strip_prefix('/').unwrap();
    let processes = std::fs::read_to_string(
        std::path::Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("cgroup.procs"),
    )
    .unwrap();
    let expected: Vec<_> = sessions
        .iter()
        .map(|id| uuid::Uuid::from_bytes(*id).simple().to_string())
        .collect();
    let mut found: Vec<Vec<i32>> = vec![Vec::new(); sessions.len()];
    for pid in processes.lines().filter_map(|pid| pid.parse::<i32>().ok()) {
        let Ok(command_line) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let args: Vec<_> = command_line.split(|byte| *byte == 0).collect();
        if !args.iter().any(|arg| *arg == b"__shim") {
            continue;
        }
        let Some(session) = args
            .windows(2)
            .find(|pair| pair[0] == b"--session")
            .map(|pair| pair[1])
        else {
            continue;
        };
        if let Some(index) = expected.iter().position(|id| id.as_bytes() == session) {
            found[index].push(pid);
        }
    }
    found
        .into_iter()
        .map(|pids| {
            assert_eq!(pids.len(), 1, "staging session shim count changed");
            pids[0]
        })
        .collect()
}

#[test]
fn staging_root_accepts_legacy_and_job_scoped_roots() {
    assert!(staging_root_is_allowed(std::path::Path::new(
        "/root/infraternal-bench/release-6/signed/r12345678"
    )));
    assert!(staging_root_is_allowed(std::path::Path::new(
        "/root/infraternal-bench/deploy/r12345678"
    )));
}

#[test]
fn staging_root_rejects_unscoped_and_escaping_paths() {
    assert!(!staging_root_is_allowed(std::path::Path::new(
        "/root/infraternal-bench/release-6/data/r12345678"
    )));
    assert!(!staging_root_is_allowed(std::path::Path::new(
        "/root/infraternal-bench/../tmp/r12345678"
    )));
    assert!(!staging_root_is_allowed(std::path::Path::new(
        "/tmp/release-6/signed/r12345678"
    )));
}

struct Unit(String);
impl Drop for Unit {
    fn drop(&mut self) {
        let _ = Command::new("systemctl")
            .args(["stop", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("systemctl")
            .args(["reset-failed", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn post(address: SocketAddr, cookie: &str, path: &str, body: Value) -> Value {
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
            .await
            .unwrap();
    let task = tokio::spawn(connection);
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, format!("__Host-infraternal={cookie}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            serde_json::to_vec(&body).unwrap(),
        )))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "staging HTTP action {path} refused"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    task.abort();
    serde_json::from_slice(&bytes).unwrap()
}

async fn driver(root: &std::path::Path, config: Value) -> Value {
    let mut child = tokio::process::Command::new("python3")
        .arg(root.join("staging_remote.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Administrator authority reaches the deploy transaction only through an
    // anonymous pipe; it never enters argv, environment, a file or a receipt.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&config).unwrap())
        .await
        .unwrap();
    let output = child.wait_with_output().await.unwrap();
    if !output.status.success() {
        println!(
            "STAGING transaction_failed operation={}",
            config["operation"]
        );
    }
    assert!(output.status.success(), "staging transaction failed");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "exclusive perf VM staging proof; requires signed run artifacts and systemd"]
async fn signed_deploy_preserves_passkey_ca_and_live_sessions() {
    std::panic::set_hook(Box::new(|failure| {
        if let Some(location) = failure.location() {
            // A panic payload can contain credentials; report only source location.
            println!(
                "STAGING failure_file={} failure_line={}",
                location.file(),
                location.line()
            );
        }
    }));
    assert!(nix::unistd::Uid::effective().is_root());
    let root = PathBuf::from(std::env::var_os("INFRATERNAL_DEPLOY_TEST_ROOT").unwrap())
        .canonicalize()
        .unwrap();
    assert!(staging_root_is_allowed(&root));
    let mut f = shipping_auth_fixture().await;
    let data = f.root.join("db");
    // Keep the physical shim path below sun_path as well as its /run mount.
    let runtime = root.join("r");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&runtime)
        .unwrap();
    let profile = f.root.join("profile");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&profile)
        .unwrap();
    std::fs::write(
        profile.join(".zshrc"),
        include_bytes!("../../../infraternal/tests/profile/.zshrc"),
    )
    .unwrap();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = reservation.local_addr().unwrap();
    drop(reservation);
    let ca = data.join("remote-ca");
    std::fs::DirBuilder::new().mode(0o700).create(&ca).unwrap();
    private_write(&ca.join("pending"), &[]);
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    // Reuse the normal retained-CA publication. Only the wrapped CA reaches
    // disk; startup receives no fixture signer and must unlock with a passkey.
    let bootstrap = crate::ca_bootstrap::BootstrapConfig {
        directory: ca.clone(),
        name: "auth.example.test".into(),
        address: remote,
        deferred: false,
    };
    drop(
        crate::ca_bootstrap::publish_first(&bootstrap, &f.auth.user, 1, &[3; 32], &[7; 32], now)
            .unwrap(),
    );
    let unit_name = format!("infraternal-deploy-{}", Uuid::new_v4().simple());
    let binary = root.join("bin/infraternal");
    let output = Command::new("systemd-run")
        .args(["--quiet", "--collect", "--unit"])
        .arg(&unit_name)
        .arg("--property=KillMode=control-group")
        .arg("--property=StandardOutput=null")
        .arg("--property=StandardError=null")
        .arg(format!("--property=BindPaths={}:/run", runtime.display()))
        .arg(format!("--setenv=ZDOTDIR={}", profile.display()))
        .arg(&binary)
        .args([
            "server",
            "--listen",
            &address.to_string(),
            "--remote-listen",
            &remote.to_string(),
            "--public-origin",
            ORIGIN,
            "--behind-proxy",
            "--trusted-proxy",
            "127.0.0.1",
            "--remote-ca-dir",
        ])
        .arg(&ca)
        .arg("--data")
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated staging unit failed to start"
    );
    let unit = Unit(unit_name);
    let pid = Command::new("systemctl")
        .args(["show", &unit.0, "--property=MainPID", "--value"])
        .output()
        .unwrap();
    let pid: u32 = std::str::from_utf8(&pid.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_ne!(pid, 0);
    println!(
        "STAGING fixture=retained-ca unit={} port={}",
        unit.0,
        address.port()
    );
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if ready.is_err() {
        let state = Command::new("systemctl")
            .args([
                "show",
                &unit.0,
                "--property=ActiveState,SubState,ExecMainCode,ExecMainStatus",
            ])
            .output()
            .unwrap();
        println!(
            "STAGING startup_state={}",
            String::from_utf8_lossy(&state.stdout)
        );
    }
    assert!(
        ready.is_ok(),
        "isolated staging server did not become ready"
    );
    let status = post(address, &f.auth.session, "/remote/ca/status", json!({})).await;
    assert_eq!(status["locked"], true);
    let start = post(
        address,
        &f.auth.session,
        "/remote/ca/unlock/start",
        json!({}),
    )
    .await;
    let proof = f.auth.software.login(&start, ORIGIN, true);
    let status = post(
        address,
        &f.auth.session,
        "/remote/ca/unlock/finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"scoped_key":vec![7u8;32]}),
    )
    .await;
    assert_eq!(status["locked"], false);
    println!(
        "STAGING cold_locked=true real_passkey_unlock=true unit={} port={}",
        unit.0,
        address.port()
    );
    let mut transaction = f.auth.auth.pool.begin().await.unwrap();
    for index in 0..49 {
        sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES(?,'Fixture',?,'Fixture',0,'unused')")
            .bind(format!("fixture-{index}")).bind(format!("fixture-{index}")).execute(&mut *transaction).await.unwrap();
    }
    for _ in 0..10000 {
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,unixepoch())")
            .bind(Uuid::new_v4().as_bytes().as_slice()).bind(&f.auth.user).execute(&mut *transaction).await.unwrap();
    }
    transaction.commit().await.unwrap();
    // The shared terminal helpers use the fixture's original origin. This
    // explicit parameter keeps passkey and terminal origins identical.
    let sessions = terminals(address, &f.auth.session, ORIGIN).await;
    println!("STAGING real_pty_sessions_created={}", sessions.len());
    let pids = staging_shim_pids(&unit.0, &sessions);
    let mut attached = attach_all(address, &f.auth.session, &sessions, ORIGIN).await;
    let config = json!({"root":root,"data":data,"binary":binary,"web":root.join("web"),"pid":pid,
        "health":format!("http://{address}"),"origin":ORIGIN,"session":f.auth.session,"web_only":false});
    let mut gaps = Vec::new();
    let mut intervals = Vec::new();
    for index in 0..12 {
        let mut request = config.clone();
        request["sha"] = json!(if index % 2 == 0 { "B" } else { "A" });
        request["operation"] = json!("handoff");
        request["port"] = json!(address.port());
        let result = driver(&root, request).await;
        assert_eq!(result["ca_unlocked"], true);
        assert_eq!(staging_shim_pids(&unit.0, &sessions), pids);
        gaps.push(result["listener_gap_bracket_ms"].as_f64().unwrap());
        intervals.push(result["probe_max_interval_ms"].as_f64().unwrap());
        println!("STAGING handoff={} {}", index + 1, result);
        if index == 0 {
            attached.clear();
        }
    }
    // Leave B running before both bad-image admissions and the verified rollback.
    let mut request = config.clone();
    request["sha"] = json!("B");
    request["operation"] = json!("handoff");
    request["port"] = json!(address.port());
    driver(&root, request).await;
    for operation in ["refuse", "bad-deploy"] {
        let mut request = config.clone();
        request["sha"] = json!("C");
        request["operation"] = json!(operation);
        let result = driver(&root, request).await;
        if operation == "bad-deploy" {
            assert_eq!(result["backup_nodes"], 10000);
            assert_eq!(result["backup_users"], 50);
            assert_eq!(result["backup_integrity"], true);
        }
        println!("STAGING operation={operation} {result}");
    }
    assert_eq!(staging_shim_pids(&unit.0, &sessions), pids);
    attached = attach_all(address, &f.auth.session, &sessions, ORIGIN).await;
    println!(
        "STAGING retained_browser_ordinals={:?}",
        attached
            .iter()
            .map(|browser| browser.ordinal)
            .collect::<Vec<_>>()
    );
    let mut echoed = 0;
    for (browser, chunk) in attached.iter_mut().zip(sessions.chunks(25)) {
        for index in 0..chunk.len() {
            let stream = u32::try_from(index * 2 + 1).unwrap();
            wire_send(
                browser,
                stream,
                &infraternal_protocol::Frame::Input {
                    in_seq: 0,
                    bytes: b"printf '%s%s\\n' 'deploy-' 'continued'\n",
                },
            )
            .await;
            let mut echo = Vec::new();
            loop {
                let bytes = wire_read(browser).await;
                let frame = infraternal_protocol::decode_muxed_frame(&bytes).unwrap();
                if frame.stream_id == stream
                    && let infraternal_protocol::Frame::Output { bytes, .. } = frame.frame
                {
                    echo.extend_from_slice(bytes);
                    if echo
                        .windows(b"deploy-continued".len())
                        .any(|part| part == b"deploy-continued")
                    {
                        break;
                    }
                    assert!(echo.len() < 65536);
                }
            }
            echoed += 1;
        }
    }
    // This test only runs under the exclusive perf-VM lock. Include the steady
    // server cost at the same 128 live-session scale as the handoff acceptance.
    let ticks = || {
        let counters = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let fields: Vec<_> = counters
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
    };
    let frequency = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .unwrap()
        .unwrap();
    let before = ticks();
    let sampled = std::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let cpu = f64::from(u32::try_from(ticks() - before).unwrap())
        / f64::from(u32::try_from(frequency).unwrap())
        / sampled.elapsed().as_secs_f64()
        * 100.0;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024;
    println!(
        "METRIC name=signed_deploy_idle server_cpu_percent_one_core={cpu:.3} server_rss_bytes={rss} real_pty_sessions=128 browser_connections=6 sample_seconds=5"
    );
    // Echoes before the idle sample cannot prove that its sockets stayed usable.
    // Require a fresh control exchange on every retained browser before teardown.
    for (index, browser) in attached.iter_mut().enumerate() {
        let nonce = u64::try_from(index).unwrap() + 1;
        wire_send(
            browser,
            0,
            &infraternal_protocol::Frame::Ping {
                nonce,
                sent_us: nonce,
            },
        )
        .await;
        loop {
            let bytes = wire_read(browser).await;
            let frame = infraternal_protocol::decode_muxed_frame(&bytes).unwrap();
            if frame.stream_id == 0
                && matches!(frame.frame, infraternal_protocol::Frame::Pong { nonce: reply, sent_us } if reply == nonce && sent_us == nonce)
            {
                break;
            }
        }
    }
    println!(
        "STAGING retained_browser_sockets_responsive={}",
        attached.len()
    );
    gaps.sort_by(f64::total_cmp);
    intervals.sort_by(f64::total_cmp);
    println!(
        "METRIC name=signed_deploy_handoff n=12 listener_gap_bracket_p50_ms={:.3} listener_gap_bracket_p99_ms={:.3} probe_max_interval_ms={:.3} users=50 nodes=10000 real_pty_sessions={} surviving_shim_pids={} resumed_input_output={} unlock_ceremonies=1 ca_unlocked=true",
        gaps[5],
        gaps[11],
        intervals[11],
        sessions.len(),
        pids.len(),
        echoed
    );
    attached.clear();
    drop(unit);
    f.auth.auth.pool.close().await;
}

/// Owns only the local proof's private runtime; declared before its unit so the
/// unit stops its shim processes before this directory is removed on any panic.
struct LocalRuntime(PathBuf);
impl Drop for LocalRuntime {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn local_browser_fixture() -> (UnlockFixture, LocalRuntime, Unit, SocketAddr) {
    assert!(nix::unistd::Uid::effective().is_root());
    let f = shipping_auth_fixture().await;
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let runtime = f.root.parent().unwrap().join("r");
    std::fs::create_dir(&runtime).unwrap();
    let owned_runtime = LocalRuntime(runtime.clone());
    let profile = f.root.join("profile");
    std::fs::create_dir(&profile).unwrap();
    std::fs::write(
        profile.join(".zshrc"),
        include_bytes!("../../../infraternal/tests/profile/.zshrc"),
    )
    .unwrap();
    let binary = std::env::var_os("INFRATERNAL_TEST_BINARY").unwrap();
    let unit = Unit(format!(
        "infraternal-deploy-local-{}",
        Uuid::new_v4().simple()
    ));
    let output = Command::new("systemd-run")
        .args([
            "--quiet",
            "--collect",
            "--unit",
            &unit.0,
            "--property=KillMode=control-group",
            "--property=StandardOutput=null",
            "--property=StandardError=null",
        ])
        .arg(format!("--property=BindPaths={}:/run", runtime.display()))
        .arg(format!("--setenv=ZDOTDIR={}", profile.display()))
        .arg(binary)
        .args([
            "server",
            "--listen",
            &address.to_string(),
            "--public-origin",
            ORIGIN,
            "--behind-proxy",
            "--trusted-proxy",
            "127.0.0.1",
            "--data",
        ])
        .arg(f.root.join("db"))
        .env("XDG_DATA_HOME", f.root.join("xdg-data"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "local staging unit failed to start"
    );
    println!("STAGING local_unit={}", unit.0);
    tokio::time::timeout(Duration::from_secs(30), async {
        while tokio::net::TcpStream::connect(address).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (f, owned_runtime, unit, address)
}

/// Reads the actual Close from an unattended client without attempting stale Pong writes.
async fn unattended_browser_close(address: SocketAddr, token: &str, session: &[u8; 16]) {
    use futures_util::{SinkExt, StreamExt};
    use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
    use tokio_tungstenite::tungstenite::Message;
    let mut socket =
        crate::ca_handoff::shipping_tests::connect_browser(address, token, ORIGIN).await;
    assert!(matches!(socket.next().await, Some(Ok(Message::Binary(_)))));
    let mut encoded = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "unattended-fixture",
        },
        &mut encoded,
    )
    .unwrap();
    socket
        .send(Message::Binary(bytes::Bytes::copy_from_slice(&encoded)))
        .await
        .unwrap();
    assert!(matches!(socket.next().await, Some(Ok(Message::Binary(_)))));
    encode_muxed_frame_into(
        1,
        &Frame::AttachTerm {
            session_id: session,
            last_out_seq: 0,
            last_in_seq: 0,
        },
        &mut encoded,
    )
    .unwrap();
    socket.send(Message::Binary(encoded.into())).await.unwrap();
    loop {
        let Message::Binary(bytes) = socket.next().await.unwrap().unwrap() else {
            panic!("unattended attach refused");
        };
        if matches!(decode_muxed_frame(&bytes).unwrap().frame, Frame::Ack { .. }) {
            break;
        }
    }
    // Model the old pull-based fixture: no event loop answers while the caller
    // works elsewhere. Ignore queued probes on read so a stale write cannot
    // obscure the server's actual Close with an incidental BrokenPipe.
    tokio::time::sleep(Duration::from_secs(3)).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Close(frame) => {
                    println!(
                        "STAGING unattended_terminal_message=Close code={:?} handoffs=0",
                        frame.map(|frame| frame.code)
                    );
                    break;
                }
                Message::Binary(_) | Message::Ping(_) | Message::Pong(_) => {}
                _ => panic!("unexpected unattended browser message type"),
            }
        }
    })
    .await
    .unwrap();
}

/// Functional local control: the staging browser must answer probes while its caller is idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "root shipping binary functional proof; requires INFRATERNAL_TEST_BINARY and private CA test root"]
async fn staging_browser_services_probes_between_commands() {
    let (f, _runtime, unit, address) = local_browser_fixture().await;
    let sessions = terminals(address, &f.auth.session, ORIGIN).await;
    println!("STAGING local_sessions={}", sessions.len());
    unattended_browser_close(address, &f.auth.session, &sessions[0]).await;
    let mut attached = attach_all(address, &f.auth.session, &sessions, ORIGIN).await;
    // This models the actual staging caller doing deployment work without polling
    // the sockets. A browser's event loop continues to answer during that work.
    tokio::time::sleep(Duration::from_secs(3)).await;
    for socket in &mut attached {
        wire_send(
            socket,
            0,
            &infraternal_protocol::Frame::Ping {
                nonce: 999,
                sent_us: 999,
            },
        )
        .await;
        loop {
            let bytes = wire_read(socket).await;
            if matches!(
                infraternal_protocol::decode_muxed_frame(&bytes)
                    .unwrap()
                    .frame,
                infraternal_protocol::Frame::Pong {
                    nonce: 999,
                    sent_us: 999
                }
            ) {
                break;
            }
        }
    }
    println!("STAGING local_clients_responsive={}", attached.len());
    attached.clear();
    drop(unit);
    f.auth.auth.pool.close().await;
}
