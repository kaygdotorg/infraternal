//! Measure real PTY echo while Mesh pages traverse the shared 300 ms latency-proxy socket [D11, #108].
use super::*;
use std::os::unix::fs::PermissionsExt;
use tokio::io::AsyncBufReadExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "weighted real-binary 300 ms Mesh/PTY measurement"]
async fn mesh_snapshot_keystroke_latency_at_10000_nodes() {
    let _guard = SERIAL.lock().await;
    // The auth unit fixture has one connection. A long inventory transaction
    // would monopolize it and park the independent authority watchdog. Use a
    // real disk-backed eight-connection pool, matching the deployed runtime.
    let root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || std::path::PathBuf::from("target"),
        std::path::PathBuf::from,
    );
    let path = root.join(format!("mesh-headroom-{}.sqlite", Uuid::new_v4()));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
                .busy_timeout(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    let (auth, token) = empty_with_pool(pool).await;
    let f = fixture_with_bootstrap(auth, token).await;
    // Launch a real infraternal daemon in private scratch state; the wrapper is
    // passed through the production inherited-socket launcher, with no global state.
    let binary = std::env::var("INFRATERNAL_MESH_TEST_BINARY").expect("real binary path");
    let state_root = root
        .parent()
        .unwrap()
        .join(format!("m{}", std::process::id()));
    std::fs::create_dir_all(&state_root).unwrap();
    let profile = state_root.join("profile");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(profile.join(".zshrc"), format!(
        "# Extend the repository canary with real single-byte PTY echo.\nsource '{}'\nstty -echo -icanon\nprintf MESHPTYREADY\nexec /bin/cat\n",
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../infraternal/tests/profile/.zshrc").display()
    )).unwrap();
    let wrapper = state_root.join("daemon.sh");
    std::fs::write(&wrapper, format!(
        "#!/bin/sh\n# Launch the isolated real Mesh/PTY fixture.\nexport ZDOTDIR='{}'\nexec '{}' agent --fd 3 --state '{}'\n",
        profile.display(), binary, state_root.join("state").display()
    )).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ws_state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::spawn(wrapper),
    )
    .await
    .unwrap()
    .with_plugin_descriptors(HOST_FACTS_DESCRIPTORS);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::websocket::router(ws_state))
            .await
            .unwrap();
    });
    // Reuse the repository byte-stream proxy, including its burst jitter model.
    let mut proxy = tokio::process::Command::new("python3")
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args(["-u", "-c", "import sys,signal;sys.path.insert(0,'scripts');from latency_proxy import TcpLatencyProxy,LatencyConfig;p=TcpLatencyProxy(('127.0.0.1',0),('127.0.0.1',int(sys.argv[1])),LatencyConfig(300,30));p.start();print(p.address[1],flush=True);signal.pause()", &upstream.port().to_string()])
        .stdout(std::process::Stdio::piped()).kill_on_drop(true).spawn().unwrap();
    let mut ready = String::new();
    tokio::io::BufReader::new(proxy.stdout.take().unwrap())
        .read_line(&mut ready)
        .await
        .unwrap();
    let address: SocketAddr = format!("127.0.0.1:{}", ready.trim()).parse().unwrap();
    // Retain the author's measured design-point ratios: three named grants per node.
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<10000) INSERT INTO mesh_nodes(id,name,public_key,last_seen,last_rtt_us) SELECT i,printf('node-%05d',i),CAST(printf('%032d',i) AS BLOB),unixepoch(),1000 FROM n")
        .execute(&f.auth.pool).await.unwrap();
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<30000) INSERT INTO mesh_grants(name,from_kind,from_value,to_kind,to_value,both_ways,ports_json) SELECT printf('grant-%05d',i),'node',CAST((i-1)%10000+1 AS TEXT),'node',CAST(i%10000+1 AS TEXT),0,'\"All\"' FROM n")
        .execute(&f.auth.pool).await.unwrap();
    let owner: String = sqlx::query_scalar("SELECT id FROM users WHERE owner=1")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    let service = crate::mesh_api::MeshService::new(f.auth.pool.clone());
    let snapshot = service
        .list(
            &owner,
            crate::mesh_api::MeshFilter::default(),
            1_800_000_000,
        )
        .await
        .unwrap();
    let event = serde_json::to_vec(&json!({"type":"snapshot","snapshot":snapshot})).unwrap();
    println!(
        "nodes=10000 grants=30000 snapshot_event_bytes={} frame_limit={} load={}",
        event.len(),
        infraternal_protocol::MAX_FRAME_LEN,
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) =
        tokio_tungstenite::connect_async_with_config(test_ws_request(address, &cookie), None, true)
            .await
            .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "review-mesh",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    // Production includes both plugins: prove the node-side collector is routed
    // before measuring Mesh pages and PTY echo on this same authenticated socket.
    let (facts_ok, facts) = super::plugin_lifecycle::exchange(
        &mut socket,
        69,
        "host.facts.read",
        br#"{"includeLive":true}"#,
    )
    .await;
    assert!(facts_ok);
    assert!(facts["os"].is_string());
    println!("fixture_plugins mesh=true host_facts=true");
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 70,
            action_id: "terminal.open",
            input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
        },
    )
    .await;
    let opened = read_client_frame(&mut socket).await;
    let Frame::Result { ok: true, json, .. } = decode_muxed_frame(&opened).unwrap().frame else {
        panic!("terminal open");
    };
    let opened: Value = serde_json::from_slice(json).unwrap();
    let session_id = uuid::Uuid::parse_str(opened["session_id"].as_str().unwrap())
        .unwrap()
        .into_bytes();
    // The manager gives a detached shim its own scope. Reuse the authenticated
    // fixture helper so this benchmark's requested CPU weight reaches the PTY.
    let weighted = tokio::process::Command::new("python3")
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args(["-c", "import sys,uuid;sys.path.insert(0,'scripts');from pathlib import Path;from agent_fixture import weight_fixture_shim;before,after=weight_fixture_shim(Path(sys.argv[1]),uuid.UUID(sys.argv[2]),'10000',diagnose=True);print(f'fixture_shim_cpu_weight_before={before} after={after}')"])
        .arg(state_root.join("state"))
        .arg(uuid::Uuid::from_bytes(session_id).to_string())
        .output().await.unwrap();
    assert!(
        weighted.status.success(),
        "fixture-owned shim scheduling must match the benchmark scope: {}",
        String::from_utf8_lossy(&weighted.stderr)
    );
    print!("{}", String::from_utf8(weighted.stdout).unwrap());
    client_ws_send(
        &mut socket,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    client_ws_send(&mut socket, 1, &Frame::Credit { bytes: 1024 * 1024 }).await;
    // The profile emits readiness only after disabling kernel echo, immediately
    // before execing cat. Every measured echo then crosses the real PTY process.
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 71,
            sent_us: 0,
        },
    )
    .await;
    let mut ready = false;
    let mut pong = false;
    while !ready || !pong {
        let wire = tokio::time::timeout(Duration::from_secs(5), read_client_frame(&mut socket))
            .await
            .expect("PTY readiness deadline");
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            Frame::Output { bytes, .. } | Frame::Snapshot { bytes, .. }
                if decoded.stream_id == 1 =>
            {
                ready |= bytes
                    .windows(b"MESHPTYREADY".len())
                    .any(|part| part == b"MESHPTYREADY");
            }
            Frame::Pong { nonce: 71, .. } => pong = true,
            _ => {}
        }
    }
    let mut echo_ms = Vec::new();
    let mut input_seq = 0;
    let mut idle_ms = Vec::new();
    for _ in 0..31 {
        let (_, delay) = page_with_echo(&mut socket, b"", input_seq).await;
        input_seq += 1;
        idle_ms.push(delay);
    }
    idle_ms.sort_by(f64::total_cmp);
    println!("idle_echo_p99_ms={:.3}", idle_ms[30]);
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 82,
            filter_json: br#"{"topic":"mesh"}"#,
        },
    )
    .await;
    let mut wire = loop {
        let incoming = tokio::time::timeout(Duration::from_secs(5), read_client_frame(&mut socket))
            .await
            .expect("initial Mesh snapshot deadline");
        if matches!(
            decode_muxed_frame(&incoming).unwrap().frame,
            Frame::Event { sub_id: 82, .. }
        ) {
            break incoming;
        }
    };
    let Frame::Event {
        sub_id: 82,
        event_json: payload,
    } = decode_muxed_frame(&wire).unwrap().frame
    else {
        panic!(
            "missing bounded snapshot event: frame_type={} bytes={}",
            wire.get(5).copied().unwrap_or_default(),
            wire.len()
        )
    };
    let event: serde_json::Value = serde_json::from_slice(payload).unwrap();
    let mut page = event["snapshot"].clone();
    assert!(page.get("next_cursor").is_some());
    let mut nodes = Vec::new();
    let mut grants = Vec::new();
    let mut pages = 0;
    let mut max_frame = 0;
    let mut total_bytes = 0;
    loop {
        max_frame = max_frame.max(wire.len());
        total_bytes += wire.len();
        pages += 1;
        assert_eq!(page["revision"].as_u64(), Some(snapshot.revision));
        nodes.extend(
            page["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|node| node["node"]["id"].as_u64().unwrap()),
        );
        grants.extend(
            page["grants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|grant| grant["arrow"]["id"].as_u64().unwrap()),
        );
        let Some(cursor) = page.get("next_cursor") else {
            break;
        };
        let input = serde_json::to_vec(&json!({"cursor":cursor})).unwrap();
        let (reply, delay) = page_with_echo(&mut socket, &input, input_seq).await;
        input_seq += 1;
        echo_ms.push(delay);
        wire = reply;
        let Frame::Result {
            call_id: 83,
            ok: true,
            json: payload,
        } = decode_muxed_frame(&wire).unwrap().frame
        else {
            panic!("missing bounded list continuation")
        };
        page = serde_json::from_slice(payload).unwrap();
        assert!(pages < 128);
    }
    assert_eq!(nodes, (1..=10000).collect::<Vec<_>>());
    assert_eq!(grants, (1..=30000).collect::<Vec<_>>());
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 42,
            sent_us: 0,
        },
    )
    .await;
    loop {
        let pong = read_client_frame(&mut socket).await;
        if matches!(
            decode_muxed_frame(&pong).unwrap().frame,
            Frame::Pong { nonce: 42, .. }
        ) {
            break;
        }
    }
    println!(
        "assembled_nodes={} assembled_grants={} pages={pages} max_frame_bytes={max_frame} total_frame_bytes={total_bytes} shared_socket_pong=true",
        nodes.len(),
        grants.len()
    );
    // The old four-MiB paging budget has only one continuation. Repeat that
    // request to retain at least 31 real keystrokes in the before measurement.
    while echo_ms.len() < 31 {
        let (reply, delay) = page_with_echo(&mut socket, b"{}", input_seq).await;
        input_seq += 1;
        max_frame = max_frame.max(reply.len());
        echo_ms.push(delay);
    }
    echo_ms.sort_by(f64::total_cmp);
    let p99 = echo_ms[(echo_ms.len() * 99).div_ceil(100) - 1];
    println!(
        "METRIC mesh_snapshot_echo nodes=10000 grants=30000 n={} p99_ms={p99:.3} budget_ms=350 rtt_ms=300 jitter_ms=30 machine={} load={}",
        echo_ms.len(),
        String::from_utf8(
            std::process::Command::new("hostname")
                .output()
                .unwrap()
                .stdout
        )
        .unwrap()
        .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status
        .lines()
        .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
    {
        println!("mesh_inventory_process {line}");
    }
    client_ws_send(
        &mut socket,
        1,
        &Frame::Input {
            in_seq: input_seq,
            bytes: b"\x03",
        },
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ended = read_client_frame(&mut socket).await;
            let decoded = decode_muxed_frame(&ended).unwrap();
            if decoded.stream_id == 1 {
                let exited = match decoded.frame {
                    Frame::Close { .. } => true,
                    Frame::Event { event_json, .. } => serde_json::from_slice::<Value>(event_json)
                        .is_ok_and(|event| event["type"] == "terminal.exited"),
                    _ => false,
                };
                if exited {
                    break;
                }
            }
        }
    })
    .await
    .expect("real PTY exit");
    client_ws_send(
        &mut socket,
        1,
        &Frame::Close {
            code: 0,
            reason: "fixture ended",
        },
    )
    .await;
    let _ = socket.close(None).await;
    proxy.kill().await.unwrap();
    server.abort();
    let _ = server.await;
    f.auth.pool.close().await;
    // Reuse fixture teardown: shims retain exited sessions by design. Only PIDs
    // authenticated by this fixture's own rendezvous sockets are stopped.
    let cleanup = tokio::process::Command::new("python3")
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args(["-c", "import sys;sys.path.insert(0,'scripts');from pathlib import Path;from agent_fixture import cleanup;cleanup(Path(sys.argv[1]))"])
        .arg(state_root.join("state"))
        .status().await.unwrap();
    assert!(cleanup.success());
    std::fs::remove_dir_all(state_root).unwrap();
    let measure_only = std::env::var_os("INFRATERNAL_MESH_MEASURE_ONLY").is_some();
    if !measure_only {
        assert!(p99 <= 350.0, "Mesh snapshot echo exceeds RTT + 50 ms");
        assert!(max_frame <= 65_536, "Mesh frame exceeds scheduling budget");
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(file));
    }
}

/// Send a real keystroke while a list is pending, retaining both reply and echo.
async fn page_with_echo<S>(socket: &mut S, input: &[u8], input_seq: u64) -> (Bytes, f64)
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    if input.is_empty() {
        client_ws_send(
            socket,
            0,
            &Frame::Ping {
                nonce: 83,
                sent_us: 0,
            },
        )
        .await;
    } else {
        client_ws_send(
            socket,
            0,
            &Frame::Call {
                call_id: 83,
                action_id: "mesh.list",
                input_json: input,
            },
        )
        .await;
    }
    let started = Instant::now();
    client_ws_send(
        socket,
        1,
        &Frame::Input {
            in_seq: input_seq,
            bytes: b"x",
        },
    )
    .await;
    let mut result = None;
    let mut delay = None;
    while result.is_none() || delay.is_none() {
        let incoming = tokio::time::timeout(Duration::from_secs(5), read_client_frame(socket))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "Mesh page/real echo deadline input_seq={input_seq} result={} echo={}",
                    result.is_some(),
                    delay.is_some()
                )
            });
        let decoded = decode_muxed_frame(&incoming).unwrap();
        match decoded.frame {
            Frame::Result { call_id: 83, .. } | Frame::Pong { nonce: 83, .. } => {
                result = Some(incoming);
            }
            Frame::Output { bytes, .. }
                if decoded.stream_id == 1 && bytes.contains(&b'x') && delay.is_none() =>
            {
                delay = Some(started.elapsed().as_secs_f64() * 1000.0);
            }
            _ => {}
        }
    }
    (result.unwrap(), delay.unwrap())
}
