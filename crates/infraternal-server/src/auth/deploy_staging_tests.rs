//! Proves signed deployment, real passkey CA custody and 128 live PTYs in an isolated perf-VM unit [217,250], #188.
use super::*;
use crate::ca_handoff::shipping_tests::{
    attach_all, shim_pids_at, terminals, wire_read, wire_send,
};
use std::net::SocketAddr;

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
#[allow(clippy::too_many_lines)]
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
    let root = PathBuf::from(std::env::var_os("INFRATERNAL_DEPLOY_TEST_ROOT").unwrap());
    assert!(root.starts_with("/root/infraternal-bench/deploy"));
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
    let pids = shim_pids_at(&runtime.join("infraternal/sessions"), &sessions);
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
        assert_eq!(
            shim_pids_at(&runtime.join("infraternal/sessions"), &sessions),
            pids
        );
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
    assert_eq!(
        shim_pids_at(&runtime.join("infraternal/sessions"), &sessions),
        pids
    );
    attached = attach_all(address, &f.auth.session, &sessions, ORIGIN).await;
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
