//! Measures primary continuity and real-PTY echo under sustained output on the pinned VM, #234.
use super::*;
use crate::embedded::{AttachmentHandle, TerminalOutput};
use bytes::Bytes;
use std::{collections::VecDeque, path::PathBuf, time::Instant};

/// Abort-safe ownership of the exact disposable PTYs, including failed setup.
struct PtyCleanup {
    state: PathBuf,
    pids: Vec<u32>,
}
impl Drop for PtyCleanup {
    fn drop(&mut self) {
        for pid in &self.pids {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(*pid).unwrap()),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

/// Datagrams the delay relay dropped at its queue bound, reported with each result.
static RELAY_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Once set, both relays drop every datagram: from the server, the host is dead.
/// The host runs in this process, so this stands in for stopping its process.
static RELAY_BLACKHOLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// One ordered datagram relay delays each direction without changing host networking.
/// A full delay queue tail-drops, as a bounded router queue would; QUIC recovers.
/// `loss_ppm` drops that share of datagrams at random, for a lossy long-haul path.
async fn delayed_link(
    socket: tokio::net::UdpSocket,
    server: SocketAddr,
    delay: Duration,
    loss_ppm: u32,
) {
    let mut client = None;
    let mut queued: VecDeque<(tokio::time::Instant, SocketAddr, Vec<u8>)> = VecDeque::new();
    let mut bytes = vec![0; 65536];
    loop {
        let due = queued.front().map(|(due, _, _)| *due);
        tokio::select! {
            received = socket.recv_from(&mut bytes) => {
                let (length, source) = received.unwrap();
                let destination = if source == server {
                    let Some(client) = client else { continue; };
                    client
                } else { client = Some(source); server };
                if RELAY_BLACKHOLE.load(std::sync::atomic::Ordering::Relaxed) { continue; }
                if queued.len() >= 32768 || rand::random::<u32>() % 1_000_000 < loss_ppm {
                    RELAY_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }
                queued.push_back((tokio::time::Instant::now() + delay, destination, bytes[..length].to_vec()));
            }
            () = async { match due { Some(due) => tokio::time::sleep_until(due).await, None => std::future::pending().await } } => {
                let (_, destination, packet) = queued.pop_front().unwrap();
                socket.send_to(&packet, destination).await.unwrap();
            }
        }
    }
}

async fn terminal_send(handle: &AttachmentHandle, frame: Frame<'_>) {
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(1, &frame, &mut wire).unwrap();
    handle.send_frame(Bytes::from(wire)).await.unwrap();
}

/// Memory-only credentials and prelaunched shims avoid persistent fixture identity material.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "10-minute real PTY measurement; pinned VM lock and INFRATERNAL_PING_BINARY required"]
async fn primary_ping_during_terminal_flood() {
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_PING_BINARY").unwrap());
    let seconds: u64 = std::env::var("INFRATERNAL_PING_SECONDS")
        .unwrap_or_else(|_| "600".into())
        .parse()
        .unwrap();
    let rtt: u64 = std::env::var("INFRATERNAL_PING_RTT")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap();
    let loss_ppm: u32 = std::env::var("INFRATERNAL_PING_LOSS_PPM")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap();
    // A third PTY absorbs a continuous paste, so server-to-host traffic competes
    // with control frames on the same connection, as an upload does.
    let upload = std::env::var("INFRATERNAL_PING_UPLOAD").is_ok_and(|value| value == "1");
    let flood_on = std::env::var("INFRATERNAL_PING_FLOOD").map_or(true, |value| value != "0");
    // Dead-host mode: after this many seconds the host goes silent; report when
    // the window is first told and when the primary is retired, then stop.
    let dead_after = std::env::var("INFRATERNAL_PING_DEAD_AFTER_S")
        .ok()
        .map(|value| Duration::from_secs(value.parse().unwrap()));
    let terminals = if upload { 3 } else { 2 };
    let state = PathBuf::from(std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap())
        .join(format!("{:08x}", rand::random::<u32>()));
    let state = infraternal_agent::sessions::state(Some(state)).unwrap();
    let uid = nix::unistd::Uid::effective().as_raw();
    let mut cleanup = PtyCleanup {
        state: state.clone(),
        pids: Vec::new(),
    };
    let mut shims = Vec::new();
    for _ in 0..terminals {
        let session = infraternal_agent::sessions::launch(
            &binary,
            &state,
            infraternal_agent::sessions::Manager::Detached,
            uid,
            80,
            24,
        )
        .await
        .unwrap();
        cleanup.pids.push(session.pid);
        shims.push(session);
    }
    let ids: Vec<_> = shims.iter().map(|session| session.id).collect();
    drop(shims);
    let (server, node, root, _) = identities();
    let (store, pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    sqlx::query("UPDATE remote_hosts SET execution_uid=? WHERE id=?")
        .bind(i64::from(uid))
        .bind(host_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    let hosts = RemoteHosts::default();
    let listener = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = relay.local_addr().unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(delayed_link(
        relay,
        address,
        Duration::from_millis(rtt / 2),
        loss_ppm,
    ));
    let identity = infraternal_agent::remote_client::RemoteIdentity {
        host_id: uuid::Uuid::new_v4(),
        identity: Identity {
            certificate: node.certificate.clone(),
            key: node.key.clone(),
        },
        roots: vec![root.clone()],
        endpoint: Some(endpoint),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: uid,
    };
    let node_state = state.clone();
    tasks.spawn(async move {
        infraternal_agent::remote_client::run(&identity, Some(node_state))
            .await
            .unwrap();
    });
    let actor = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(actor) = hosts.actor(host_id).await {
                break actor;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let primary_closes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let admissions = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let connection_ends = primary_closes.clone();
    let admitted = admissions.clone();
    let close_times = Arc::new(std::sync::Mutex::new(Vec::<Instant>::new()));
    let closed_at = close_times.clone();
    tasks.spawn(async move {
        let mut previous = None;
        loop {
            if let Some(connection) =
                crate::remote_link::RemoteLink::test_connection_for_peer(endpoint)
                && previous != Some(connection.stable_id())
            {
                previous = Some(connection.stable_id());
                admitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let reason = connection.closed().await;
                closed_at.lock().unwrap().push(Instant::now());
                connection_ends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                eprintln!(
                    "PING_FLOOD_PRIMARY_CLOSED reason={reason:?} actor_lines={:?}",
                    crate::embedded::TEST_CLOSE_LINES
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let mut handles = Vec::new();
    let (events, mut output) = tokio::sync::mpsc::channel(64);
    for (index, id) in ids.iter().enumerate() {
        let attachment = actor
            .attach(*id, 0, 0, 42 + u32::try_from(index).unwrap() * 2)
            .await
            .unwrap();
        let (handle, mut receive) = attachment.split();
        let sender = events.clone();
        let credit = handle.clone();
        tasks.spawn(async move {
            while let Some(event) = receive.recv().await {
                if let TerminalOutput::Output { bytes, .. } = &event {
                    terminal_send(
                        &credit,
                        Frame::Credit {
                            bytes: u32::try_from(bytes.len()).unwrap(),
                        },
                    )
                    .await;
                }
                if sender.send((index, event)).await.is_err() {
                    break;
                }
            }
        });
        terminal_send(&handle, Frame::Credit { bytes: 1024 * 1024 }).await;
        terminal_send(
            &handle,
            Frame::Input {
                in_seq: 0,
                bytes: b"stty -echo -opost; printf 'READY_%s\\n' PING\n",
            },
        )
        .await;
        handles.push(handle);
    }
    let mut ready = vec![false; terminals];
    let mut tails = vec![Vec::new(); terminals];
    while !ready.iter().all(|ready| *ready) {
        let (index, event) = tokio::time::timeout(Duration::from_secs(15), output.recv())
            .await
            .unwrap()
            .unwrap();
        if let TerminalOutput::Output { bytes, .. } = event {
            tails[index].extend_from_slice(&bytes);
            ready[index] |= tails[index].windows(10).any(|part| part == b"READY_PING");
        }
    }
    // A real parked secondary enables the shipping bounded control writer path.
    // Primed terminal writers move onto it, so it crosses its own delayed relay;
    // otherwise terminal bytes would bypass the configured RTT and loss.
    let warm_relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let warm_address = warm_relay.local_addr().unwrap();
    tasks.spawn(delayed_link(
        warm_relay,
        address,
        Duration::from_millis(rtt / 2),
        loss_ppm,
    ));
    let (_warm_endpoint, warm_connection, warm) =
        super::standby::connect_control(warm_address, &node, &root).await;
    let mut warm_receive = Receive::default();
    let mut warm_tx = Transmit::default();
    warm_tx
        .send(
            &warm,
            0,
            &Frame::Ping {
                nonce: 201,
                sent_us: 0,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        warm_receive.next(&warm).await.unwrap().frame,
        Frame::Pong { nonce: 201, .. }
    ));
    warm_tx
        .send(
            &warm,
            0,
            &Frame::Call {
                call_id: 0,
                action_id: "transport.standby",
                input_json: br#"{"prime":true}"#,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        warm_receive.next(&warm).await.unwrap().frame,
        Frame::Result { ok: true, .. }
    ));
    assert!(matches!(
        warm_receive.next(&warm).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let warm_hello = Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING
            | infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS,
        client_info: "continuity fixture",
    };
    warm_tx.send(&warm, 0, &warm_hello).await.unwrap();
    let binding = remote_quic::negotiate_binding(&warm_connection, &warm_hello).unwrap();
    let warm_state = state.clone();
    tasks.spawn(async move {
        let mut terminals = tokio::task::JoinSet::new();
        loop { tokio::select! {
            bound = remote_quic::accept_bound(&binding) => {
                // The server retires this secondary with a lost primary; report, do not panic.
                let Ok(bound) = bound else { eprintln!("PING_FLOOD_WARM_ENDED accept"); break; };
                let channel = NativeChannel::terminal(bound).unwrap();
                let state = warm_state.clone();
                terminals.spawn(async move { let _ = infraternal_agent::daemon::run_negotiated_bound_terminal(&channel, Some(state)).await; });
            }
            frame = warm_receive.next(&warm) => {
                let Ok(frame) = frame else { eprintln!("PING_FLOOD_WARM_ENDED read"); break; };
                let sent = match frame.frame {
                    Frame::Ping { nonce, sent_us } => warm_tx.send(&warm, 0, &Frame::Pong { nonce, sent_us }).await,
                    Frame::Call { call_id, .. } => warm_tx.send(&warm, 0, &Frame::Result { call_id, ok: false, json: b"{}" }).await,
                    _ => Ok(()),
                };
                if sent.is_err() { eprintln!("PING_FLOOD_WARM_ENDED write"); break; }
            }
        }}
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while crate::embedded::test_control_queue_state(endpoint).is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned control FIFO must be enabled before measurement");
    let flood = b"while :; do head -c 33554432 /dev/zero | tr '\\000' x; done\n";
    let prepare = b"stty -echo -opost; printf 'READY_%s\\n' PING\n";
    let mut sequence = vec![u64::try_from(prepare.len()).unwrap(); terminals];
    if flood_on {
        terminal_send(
            &handles[0],
            Frame::Input {
                in_seq: sequence[0],
                bytes: flood,
            },
        )
        .await;
        sequence[0] += u64::try_from(flood.len()).unwrap();
    }
    let uploaded = Arc::new(std::sync::atomic::AtomicU64::new(0));
    if upload {
        let sink = b"exec cat > /dev/null\n";
        terminal_send(
            &handles[2],
            Frame::Input {
                in_seq: sequence[2],
                bytes: sink,
            },
        )
        .await;
        let paste = handles[2].clone();
        let mut in_seq = sequence[2] + u64::try_from(sink.len()).unwrap();
        let counter = uploaded.clone();
        tasks.spawn(async move {
            // Canonical-mode lines stay under the 4 KiB tty line limit.
            let mut line = vec![b'y'; 4000];
            *line.last_mut().unwrap() = b'\n';
            loop {
                terminal_send(
                    &paste,
                    Frame::Input {
                        in_seq,
                        bytes: &line,
                    },
                )
                .await;
                in_seq += u64::try_from(line.len()).unwrap();
                counter.fetch_add(
                    u64::try_from(line.len()).unwrap(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        });
    }
    let started = Instant::now();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut sent = None;
    let mut nonce = 0_u64;
    let mut samples = Vec::new();
    let mut flood_bytes = 0_u64;
    let mut closes = 0_u64;
    let mut retired = 0_u64;
    let mut recoveries = 0_u64;
    let mut dead_at: Option<Instant> = None;
    let mut noticed_at: Option<Instant> = None;
    let mut echo_tail = Vec::new();
    println!(
        "PING_FLOOD_START rtt_ms={rtt} loss_ppm={loss_ppm} duration_s={seconds} terminals={terminals} load={}",
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if started.elapsed() >= Duration::from_secs(seconds) { break; }
                if let Some(dead) = dead_at {
                    let link_gone = close_times.lock().unwrap().iter().any(|at| *at >= dead);
                    if (noticed_at.is_some() && link_gone) || dead.elapsed() > Duration::from_secs(10) { break; }
                    continue;
                }
                if dead_after.is_some_and(|after| started.elapsed() >= after) {
                    RELAY_BLACKHOLE.store(true, std::sync::atomic::Ordering::Relaxed);
                    dead_at = Some(Instant::now());
                    continue;
                }
                if sent.is_none() {
                    nonce += 1;
                    let command = format!("printf 'ECHO_%s\\n' {nonce}\n");
                    sent = Some(Instant::now());
                    terminal_send(&handles[1], Frame::Input { in_seq: sequence[1], bytes: command.as_bytes() }).await;
                    sequence[1] += u64::try_from(command.len()).unwrap();
                }
            }
            event = output.recv() => {
                let (index, event) = event.unwrap();
                match event {
                    TerminalOutput::Output { bytes, .. } if index == 0 => flood_bytes += u64::try_from(bytes.len()).unwrap(),
                    TerminalOutput::Output { bytes, .. } if index == 1 => {
                        echo_tail.extend_from_slice(&bytes);
                        let marker = format!("ECHO_{nonce}\n");
                        if echo_tail.windows(marker.len()).any(|part| part == marker.as_bytes()) {
                            if let Some(sent) = sent.take() { samples.push(sent.elapsed().as_secs_f64() * 1000.0); }
                            echo_tail.clear();
                        }
                    }
                    TerminalOutput::Reconnecting | TerminalOutput::LinkDoubt if index == 1 => {
                        closes += 1;
                        if dead_at.is_some() && noticed_at.is_none() { noticed_at = Some(Instant::now()); }
                    }
                    TerminalOutput::Recovered if index == 1 => recoveries += 1,
                    // Count instead of panicking so a failing variant still reports numbers.
                    TerminalOutput::Closed { code, .. } => {
                        retired += 1;
                        eprintln!("PING_FLOOD_TERMINAL_RETIRED index={index} code={code}");
                    }
                    _ => {},
                }
            }
        }
    }
    let reconnects = admissions
        .load(std::sync::atomic::Ordering::Relaxed)
        .saturating_sub(1);
    let primary_closes = primary_closes.load(std::sync::atomic::Ordering::Relaxed);
    if let Some(dead) = dead_at {
        let millis = |at: Option<Instant>| {
            at.map_or(-1.0, |at| at.duration_since(dead).as_secs_f64() * 1000.0)
        };
        let retired_at = close_times
            .lock()
            .unwrap()
            .iter()
            .copied()
            .find(|at| *at >= dead);
        println!(
            "PING_FLOOD_DEAD rtt_ms={rtt} flood={flood_on} notice_ms={:.1} retire_ms={:.1} recoveries={recoveries}",
            millis(noticed_at),
            millis(retired_at)
        );
    }
    samples.sort_by(f64::total_cmp);
    let quantile = |q: usize| {
        samples
            .get((samples.len() * q / 100).min(samples.len().saturating_sub(1)))
            .copied()
            .unwrap_or(f64::NAN)
    };
    println!(
        "PING_FLOOD_RESULT rtt_ms={rtt} loss_ppm={loss_ppm} upload_bytes={} duration_s={seconds} primary_closes={primary_closes} primary_loss_notices={closes} recoveries={recoveries} terminals_retired={retired} reconnects={reconnects} relay_drops={} flood_bytes={flood_bytes} echo_samples={} echo_p50_ms={:.3} echo_p99_ms={:.3} load={}",
        uploaded.load(std::sync::atomic::Ordering::Relaxed),
        RELAY_DROPS.load(std::sync::atomic::Ordering::Relaxed),
        samples.len(),
        quantile(50),
        quantile(99),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    tasks.shutdown().await;
    drop(handles);
    drop(listener);
    let pids = cleanup.pids.clone();
    drop(cleanup);
    for pid in pids {
        tokio::time::timeout(Duration::from_secs(5), async {
            while std::path::Path::new(&format!("/proc/{pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture shim did not exit");
        println!("PING_FLOOD_CLEANUP shim_pid={pid} present=false");
    }
    assert!(
        dead_at.is_some() || u64::try_from(samples.len()).unwrap() >= (seconds * 9 / 10).max(1),
        "insufficient echo coverage: {} samples over {seconds}s",
        samples.len()
    );
}
