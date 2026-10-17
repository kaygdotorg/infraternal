//! Measurement harness for #240, ignored by default: real router, real SQLite,
//! real browser sockets and a host fixture that echoes terminal input.
//!
//! `soak` runs several terminal sockets typing every 10 ms while the only store
//! connection is held for random stalls, and counts sockets that close. `rtt`
//! measures one terminal's echo round trip with a fast store, to show what the
//! authority read costs per frame. Settings come from the environment:
//! `SOAK_SECS`, `SOAK_TERMINALS`, `SOAK_STALL_MIN_MS`, `SOAK_STALL_MAX_MS`,
//! `SOAK_STALL_EVERY_MS`, `RTT_SAMPLES`.
// Counts and percentiles are printed for people; none of these casts can
// reach a value where precision or width matters.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Browser = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn setting(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Host side: acknowledges every attach and input and echoes input as output
/// on the same stream, for any number of terminals.
async fn echo_all(mut peer: UnixStream) {
    let mut receive = BytesMut::new();
    let Some(_hello) = read_leg_b_frame(&mut peer, &mut receive).await else {
        return;
    };
    leg_b_send(
        &mut peer,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "soak-host",
        },
    )
    .await;
    let mut out: HashMap<u32, u64> = HashMap::new();
    while let Some(wire) = read_leg_b_frame(&mut peer, &mut receive).await {
        let decoded = decode_muxed_frame(&wire).unwrap();
        let stream = decoded.stream_id;
        match decoded.frame {
            Frame::Ping { nonce, sent_us } => {
                leg_b_send(&mut peer, stream, &Frame::Pong { nonce, sent_us }).await;
            }
            Frame::AttachTerm { .. } => {
                out.insert(stream, 0);
                leg_b_send(&mut peer, stream, &Frame::Ack { in_seq_acked: 0 }).await;
            }
            Frame::Input { in_seq, bytes } => {
                let end = in_seq + bytes.len() as u64;
                leg_b_send(&mut peer, stream, &Frame::Ack { in_seq_acked: end }).await;
                let at = out.entry(stream).or_default();
                leg_b_send(
                    &mut peer,
                    stream,
                    &Frame::Output {
                        out_seq: *at,
                        bytes,
                    },
                )
                .await;
                *at += bytes.len() as u64;
            }
            _ => {}
        }
    }
}

async fn soak_server(
    f: &Fixture,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (socket, peer) = UnixStream::pair().unwrap();
    // No test override: the production per-read deadline applies.
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // Production sets TCP_NODELAY on every accepted socket; so does the harness.
        use axum::serve::ListenerExt;
        let listener = listener.tap_io(|tcp| {
            let _ = tcp.set_nodelay(true);
        });
        axum::serve(listener, crate::websocket::router(state))
            .await
            .unwrap();
    });
    (address, server, tokio::spawn(echo_all(peer)))
}

/// Open a socket and attach a fresh terminal on stream 1 with output credit.
async fn open_terminal(f: &Fixture, address: SocketAddr, session: [u8; 16]) -> Browser {
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,unixepoch(),unixepoch())")
        .bind(session.as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut browser, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    if let MaybeTlsStream::Plain(tcp) = browser.get_ref() {
        tcp.set_nodelay(true).unwrap();
    }
    assert_server_hello(&mut browser).await;
    client_ws_send(
        &mut browser,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "soak",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    client_ws_send(&mut browser, 1, &Frame::Credit { bytes: 8 << 20 }).await;
    browser
}

enum Read {
    Echo(u64, usize),
    Other,
    Closed(String),
}

async fn read_echo(browser: &mut Browser) -> Read {
    match tokio::time::timeout(Duration::from_secs(10), browser.next()).await {
        Ok(Some(Ok(Message::Binary(bytes)))) => match decode_muxed_frame(&bytes) {
            Ok(decoded) => match decoded.frame {
                Frame::Output { out_seq, bytes } => Read::Echo(out_seq, bytes.len()),
                // Answer liveness probes as a browser does, or the socket's
                // two-second proof budget retires it.
                Frame::Ping { nonce, sent_us } => {
                    client_ws_send(browser, decoded.stream_id, &Frame::Pong { nonce, sent_us })
                        .await;
                    Read::Other
                }
                Frame::Close { code, reason } => Read::Closed(format!("close {code} {reason}")),
                _ => Read::Other,
            },
            Err(error) => Read::Closed(format!("decode {error:?}")),
        },
        Ok(Some(Ok(Message::Close(frame)))) => Read::Closed(format!("ws close {frame:?}")),
        Ok(Some(Ok(_))) => Read::Other,
        Ok(other) => Read::Closed(format!("{other:?}")),
        Err(_) => Read::Closed("no frame for 10 s".into()),
    }
}

#[derive(Default)]
struct Tally {
    closes: AtomicU64,
    gaps: AtomicU64,
    echoes: AtomicU64,
    worst_echo_us: AtomicU64,
}

/// One terminal typing a key every 10 ms; reconnects with a fresh terminal on
/// every close so one close never hides later ones.
async fn typist(
    f: Arc<Fixture>,
    address: SocketAddr,
    index: u8,
    until: tokio::time::Instant,
    tally: Arc<Tally>,
) {
    let mut generation = 0_u8;
    'socket: while tokio::time::Instant::now() < until {
        let mut session = [0_u8; 16];
        session[0] = 0xa0;
        session[1] = index;
        session[2] = generation;
        generation = generation.wrapping_add(1);
        let mut browser = open_terminal(&f, address, session).await;
        let (mut in_seq, mut out_seq) = (0_u64, 0_u64);
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        while tokio::time::Instant::now() < until {
            tick.tick().await;
            let sent = std::time::Instant::now();
            client_ws_send(
                &mut browser,
                1,
                &Frame::Input {
                    in_seq,
                    bytes: b"x",
                },
            )
            .await;
            in_seq += 1;
            loop {
                match read_echo(&mut browser).await {
                    Read::Echo(at, length) => {
                        if at != out_seq {
                            tally.gaps.fetch_add(1, Ordering::Relaxed);
                        }
                        out_seq = at + length as u64;
                        if out_seq >= in_seq {
                            break;
                        }
                    }
                    Read::Other => {}
                    Read::Closed(_) => {
                        tally.closes.fetch_add(1, Ordering::Relaxed);
                        continue 'socket;
                    }
                }
            }
            let waited = u64::try_from(sent.elapsed().as_micros()).unwrap_or(u64::MAX);
            tally.echoes.fetch_add(1, Ordering::Relaxed);
            tally.worst_echo_us.fetch_max(waited, Ordering::Relaxed);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement for #240; run explicitly on the perf VM"]
async fn authority_stall_soak() {
    let _guard = SERIAL.lock().await;
    let secs = setting("SOAK_SECS", 300);
    let terminals = setting("SOAK_TERMINALS", 4);
    let (stall_min, stall_max) = (
        setting("SOAK_STALL_MIN_MS", 50),
        setting("SOAK_STALL_MAX_MS", 300),
    );
    let every = setting("SOAK_STALL_EVERY_MS", 2000);
    let f = Arc::new(fixture().await);
    let (address, server, host) = soak_server(&f).await;
    let until = tokio::time::Instant::now() + Duration::from_secs(secs);
    let tally = Arc::new(Tally::default());
    let mut typists = Vec::new();
    for index in 0..terminals {
        typists.push(tokio::spawn(typist(
            f.clone(),
            address,
            index as u8,
            until,
            tally.clone(),
        )));
    }
    let mut stalls = 0_u64;
    let mut stalled_ms = 0_u64;
    let mut seed = 0x2400_u64;
    if stall_max > 0 {
        while tokio::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(every)).await;
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let length = stall_min + (seed >> 33) % (stall_max - stall_min + 1);
            let held = f.auth.pool.acquire().await.unwrap();
            tokio::time::sleep(Duration::from_millis(length)).await;
            drop(held);
            stalls += 1;
            stalled_ms += length;
        }
    }
    for typist in typists {
        typist.await.unwrap();
    }
    println!(
        "SOAK secs={secs} terminals={terminals} stalls={stalls} stall_ms={stall_min}..{stall_max} stalled_total_ms={stalled_ms} closes={} gaps={} echoes={} worst_echo_ms={:.1}",
        tally.closes.load(Ordering::Relaxed),
        tally.gaps.load(Ordering::Relaxed),
        tally.echoes.load(Ordering::Relaxed),
        tally.worst_echo_us.load(Ordering::Relaxed) as f64 / 1000.0,
    );
    server.abort();
    host.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement for #240; run explicitly on the perf VM"]
async fn authority_fast_read_echo_rtt() {
    let _guard = SERIAL.lock().await;
    let samples = setting("RTT_SAMPLES", 5000) as usize;
    let f = fixture().await;
    let (address, server, host) = soak_server(&f).await;
    let mut generation = 0_u8;
    let mut browser = open_terminal(&f, address, [0xb0; 16]).await;
    let (mut in_seq, mut out_seq) = (0_u64, 0_u64);
    let mut rtt = Vec::with_capacity(samples);
    let mut closes = 0_u64;
    let mut n = 0_usize;
    // The first 200 echoes warm the pool, allocator and socket buffers.
    while rtt.len() < samples {
        let sent = std::time::Instant::now();
        client_ws_send(
            &mut browser,
            1,
            &Frame::Input {
                in_seq,
                bytes: b"x",
            },
        )
        .await;
        in_seq += 1;
        let mut ended = false;
        while out_seq < in_seq {
            match read_echo(&mut browser).await {
                Read::Echo(at, length) => out_seq = at + length as u64,
                Read::Other => {}
                Read::Closed(why) => {
                    println!("RTT close at echo {n}: {why}");
                    ended = true;
                    break;
                }
            }
        }
        if ended {
            // Count it and continue on a fresh terminal; the sample is discarded.
            closes += 1;
            generation = generation.wrapping_add(1);
            let mut session = [0xb0; 16];
            session[1] = generation;
            browser = open_terminal(&f, address, session).await;
            (in_seq, out_seq) = (0, 0);
            continue;
        }
        n += 1;
        if n > 200 {
            rtt.push(sent.elapsed().as_secs_f64() * 1e6);
        }
    }
    rtt.sort_by(f64::total_cmp);
    let at = |q: f64| rtt[((rtt.len() as f64 * q) as usize).min(rtt.len() - 1)];
    println!(
        "RTT n={} closes={closes} p50_us={:.1} p90_us={:.1} p99_us={:.1} max_us={:.1}",
        rtt.len(),
        at(0.50),
        at(0.90),
        at(0.99),
        rtt[rtt.len() - 1]
    );
    server.abort();
    host.abort();
}
