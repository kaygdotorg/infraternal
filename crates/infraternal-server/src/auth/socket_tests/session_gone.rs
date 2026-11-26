//! Final and transient host closes absorb late terminal frames while the shared socket stays up (#158, #250).
//!
//! Before this, the browser's attach either closed the whole socket (a session whose
//! exit was recorded), so the page reconnected and attached again at once, or reached
//! the infraternal agent, which failed its whole channel and was restarted by the
//! server about twice a second while the window looked live and stayed blank.
use super::*;
use infraternal_protocol::{CLOSE_SESSION_GONE, SESSION_GONE_REASON};

/// Opens an authenticated, welcomed browser socket.
async fn welcomed(
    address: SocketAddr,
    session: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let cookie = format!("__Host-infraternal={session}");
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "gone",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    socket
}

/// Sends what a browser sends to attach (`AttachTerm`, `Credit`, `Resize`), then a late
/// `Input` and its own `Close`, then a control `Ping`. Returns the frames up to the Pong.
async fn attach_and_fence<S>(
    socket: &mut S,
    session: &[u8; 16],
    expected_code: u16,
    expected_reason: &str,
) -> Vec<(u32, String)>
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    client_ws_send(
        socket,
        1,
        &Frame::AttachTerm {
            session_id: session,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    client_ws_send(socket, 1, &Frame::Credit { bytes: 65_536 }).await;
    client_ws_send(
        socket,
        1,
        &Frame::Resize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        },
    )
    .await;
    let mut seen = Vec::new();
    loop {
        let wire = read_client_frame(socket).await;
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            Frame::Close { code, reason } => {
                assert_eq!(
                    code, expected_code,
                    "the close must retain its typed reason"
                );
                assert_eq!(reason, expected_reason);
                seen.push((decoded.stream_id, "gone".to_owned()));
                break;
            }
            Frame::Ack { .. } => seen.push((decoded.stream_id, "ack".to_owned())),
            other => panic!("unexpected frame before the final close: {other:?}"),
        }
    }
    // Credit and geometry can already be in flight when the host closes.
    client_ws_send(socket, 1, &Frame::Credit { bytes: 4096 }).await;
    client_ws_send(
        socket,
        1,
        &Frame::Resize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        },
    )
    .await;
    // Typing that crossed the Close, then the browser's own Close: all are absorbed.
    client_ws_send(
        socket,
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: b"ls\r",
        },
    )
    .await;
    client_ws_send(
        socket,
        1,
        &Frame::Close {
            code: 1000,
            reason: "window closed",
        },
    )
    .await;
    client_ws_send(
        socket,
        0,
        &Frame::Ping {
            nonce: 158,
            sent_us: 0,
        },
    )
    .await;
    let pong = read_client_frame(socket).await;
    assert!(
        matches!(
            decode_muxed_frame(&pong).unwrap().frame,
            Frame::Pong { nonce: 158, .. }
        ),
        "the socket must stay up after a final stream close"
    );
    seen
}

#[tokio::test]
async fn an_ended_or_unknown_session_gets_the_final_close_without_losing_the_socket() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    // A shell whose exit the server recorded, and an id this account never had.
    let ended = [0x51_u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,closed_at,exit_status) VALUES(?,?,1,1,2,0)")
        .bind(ended.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    for session in [ended, [0x52_u8; 16]] {
        let mut socket = welcomed(address, &f.session).await;
        let seen = attach_and_fence(
            &mut socket,
            &session,
            CLOSE_SESSION_GONE,
            SESSION_GONE_REASON,
        )
        .await;
        assert_eq!(
            seen,
            vec![(1, "gone".to_owned())],
            "no attach may reach the infraternal agent"
        );
    }
    server.abort();
}

#[tokio::test]
async fn the_infraternal_agent_saying_gone_reaches_the_browser_as_the_final_close() {
    host_close_preserves_socket(CLOSE_SESSION_GONE, SESSION_GONE_REASON).await;
}

#[tokio::test]
async fn transient_host_close_absorbs_inflight_credit_resize_and_input() {
    host_close_preserves_socket(1, "terminal shim disconnected").await;
}

/// Exercise the real socket with one deterministic host-side close before late browser frames.
async fn host_close_preserves_socket(code: u16, reason: &'static str) {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let (socket, mut agent) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // A session the database still calls live, whose shim is gone on the host.
    let session = [0x53_u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    // The fake infraternal agent: greet, then answer the AttachTerm as the real one does.
    let host = tokio::spawn(async move {
        let mut buffer = Vec::new();
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "agent",
            },
            &mut encoded,
        )
        .unwrap();
        agent.write_all(&encoded).await.unwrap();
        loop {
            let mut chunk = [0_u8; 4096];
            let read = agent.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            while let Ok(decoded) = decode_muxed_frame(&buffer) {
                let (stream, wire_len) = (decoded.stream_id, decoded.wire_len);
                if let Frame::AttachTerm { session_id, .. } = decoded.frame {
                    assert_eq!(session_id, &[0x53_u8; 16]);
                    encoded.clear();
                    let gone = Frame::Close { code, reason };
                    encode_muxed_frame_into(stream, &gone, &mut encoded).unwrap();
                    agent.write_all(&encoded).await.unwrap();
                }
                buffer.drain(..wire_len);
            }
        }
    });
    let mut socket = welcomed(address, &f.session).await;
    let seen = attach_and_fence(&mut socket, &session, code, reason).await;
    assert_eq!(seen, vec![(1, "ack".to_owned()), (1, "gone".to_owned())]);
    host.abort();
    server.abort();
}

/// Enroll a remote host identity into an on-disk database so `RemoteListeners`
/// can admit a real mTLS link owned by `owner`.
#[cfg(feature = "remote")]
async fn enroll_remote_host(
    pool: &sqlx::SqlitePool,
    owner: &str,
    host_identity: &infraternal_agent::remote_tls::Identity,
    root: &openssl::x509::X509,
    now: i64,
) -> (crate::enrollment::EnrollmentStore, uuid::Uuid) {
    let store = crate::enrollment::EnrollmentStore::new(pool.clone());
    let host = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,?)",
    )
    .bind(host.as_bytes().as_slice())
    .bind(owner)
    .bind(now)
    .execute(pool)
    .await
    .unwrap();
    let fingerprint = openssl::sha::sha256(&host_identity.certificate.to_der().unwrap());
    let key_digest = openssl::sha::sha256(&host_identity.key.raw_public_key().unwrap());
    let token = store
        .issue(
            owner,
            host,
            crate::enrollment::Mode::Rootless,
            now,
            &key_digest,
        )
        .await
        .unwrap();
    store
        .redeem(
            token.secret(),
            host,
            crate::enrollment::Mode::Rootless,
            now,
            &crate::enrollment::CertificateRecord {
                fingerprint,
                issuer_fingerprint: openssl::sha::sha256(&root.to_der().unwrap()),
                public_key: crate::identity_key::IdentityKey::Ed25519(
                    host_identity
                        .key
                        .raw_public_key()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                not_before: now,
                not_after: now + 604_800,
            },
        )
        .await
        .unwrap();
    (store, host)
}

/// Read browser frames until `stream` receives its `Close`, answering control
/// pings and ignoring unrelated session-snapshot events along the way. The wait
/// is bounded: the server keeps pinging a healthy socket, so a `Close` that was
/// lost on the way would otherwise leave this loop running forever (#596).
#[cfg(feature = "remote")]
async fn read_stream_close<S>(socket: &mut S, stream: u32) -> (u16, String)
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let close = async {
        loop {
            let wire = read_client_frame(socket).await;
            let decoded = decode_muxed_frame(&wire).unwrap();
            match decoded.frame {
                Frame::Ping { nonce, sent_us } if decoded.stream_id == 0 => {
                    client_ws_send(socket, 0, &Frame::Pong { nonce, sent_us }).await;
                }
                Frame::Close { code, reason } if decoded.stream_id == stream => {
                    return (code, reason.to_owned());
                }
                Frame::Ack { .. } | Frame::Event { .. } => {}
                other => panic!(
                    "unexpected frame on stream {} while waiting for stream {stream} close: {other:?}",
                    decoded.stream_id
                ),
            }
        }
    };
    // Only a hang bound, far above the milliseconds a loopback close takes.
    tokio::time::timeout(Duration::from_secs(30), close)
        .await
        .unwrap_or_else(|_| panic!("stream {stream} received no Close within 30 s"))
}

/// End-to-end socket regression for #588 (J1224 follow-up): a browser opens a
/// terminal on a real mTLS-linked remote host, attaches two streams to it, and
/// the remote host answers `Close { code: 4404 }` on each stream.
///
/// Proves the live `websocket.rs` `TerminalOutput::Closed` wiring:
/// 1. The browser receives `4404` (`CLOSE_SESSION_GONE`) on the stream while
///    the shared socket stays up.
/// 2. `terminal_sessions.closed_at` is written through the D379 writer on the
///    first `4404` and left untouched by the second `4404` (set exactly once).
/// 3. `terminal_session_prune::prune_closed_sessions` later removes the row.
#[cfg(feature = "remote")]
#[tokio::test]
async fn remote_session_reported_gone_closes_row_once_and_prunes() {
    use crate::remote_runtime::{RemoteHosts, RemoteListeners};
    use infraternal_agent::{
        remote_quic, remote_tls,
        transport::{Receive, Transmit},
    };

    let _guard = SERIAL.lock().await;
    let dir =
        std::env::temp_dir().join(format!("infraternal-remote-gone-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(dir.join("infraternal.sqlite"))
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .synchronous(sqlx::sqlite::SqliteSynchronous::Normal),
        )
        .await
        .unwrap();
    // Real registration flow on the on-disk pool (so the D379 writer runs), then
    // extend the fixture session's wall-clock lifetime: fixtures are stamped at a
    // fixed `NOW` in the past, which the live websocket would refuse.
    let (auth, token) = empty_with_pool(pool.clone()).await;
    let f = fixture_with_bootstrap(auth, token).await;
    let auth = f.auth.clone();
    assert!(
        auth.database().is_some(),
        "on-disk Auth must run the D379 writer"
    );
    sqlx::query("UPDATE sessions SET expires=unixepoch()+3600, fresh=unixepoch() WHERE user_id=?")
        .bind(&f.user)
        .execute(&pool)
        .await
        .unwrap();
    let now = crate::runtime::unix_seconds().unwrap();
    let user = f.user.clone();
    let session_token = f.session.clone();
    let session_token = session_token.as_str();

    let (server_identity, host_identity, root, _) = crate::remote_runtime::tests::identities();
    let (store, host) = enroll_remote_host(&pool, &user, &host_identity, &root, now).await;
    let hosts = RemoteHosts::default();
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server_identity,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let remote_addr = listeners.local_addr().unwrap();
    let client_tls = remote_tls::client_config(&host_identity, &[root]).unwrap();

    // Wire-faithful remote host peer over real mTLS: serves `terminal.open`,
    // accepts two concurrent attachments to the same session, reports 4404 on
    // the first immediately, and sends a second 4404 once released by the test.
    // Like a real host it then stays connected and keeps answering probes until
    // the test stops it. Hanging up after the second close, with a probe still
    // unread, could reset the link before the server had read that close; the
    // browser then saw "reconnecting" and waited forever (#596).
    let remote_session = uuid::Uuid::new_v4();
    let (release_second, mut wait_second) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let connection = remote_tls::dial(remote_addr, "localhost", &client_tls)
            .await
            .unwrap();
        let mut receive = Receive::default();
        let mut transmit = Transmit::default();
        transmit
            .send(
                &connection.channel,
                0,
                &Frame::Hello {
                    version: 1,
                    caps: remote_quic::REMOTE_WRITER_BINDING,
                    client_info: "remote-gone-fixture",
                },
            )
            .await
            .unwrap();
        let _ = receive.next(&connection.channel).await.unwrap();

        let gone = Frame::Close {
            code: CLOSE_SESSION_GONE,
            reason: SESSION_GONE_REASON,
        };
        let mut attached_streams = Vec::new();
        let mut released = false;
        loop {
            // `Receive::next` keeps a partly read frame across cancellation.
            let decoded = tokio::select! {
                decoded = receive.next(&connection.channel) => decoded.unwrap(),
                release = &mut wait_second, if !released => {
                    release.unwrap();
                    released = true;
                    transmit
                        .send(&connection.channel, attached_streams[1], &gone)
                        .await
                        .unwrap();
                    continue;
                }
            };
            let stream_id = decoded.stream_id;
            match decoded.frame {
                Frame::Ping { nonce, sent_us } => {
                    transmit
                        .send(&connection.channel, 0, &Frame::Pong { nonce, sent_us })
                        .await
                        .unwrap();
                }
                Frame::Call {
                    call_id,
                    action_id: "terminal.open",
                    ..
                } => {
                    let body =
                        serde_json::json!({ "session_id": remote_session.to_string() }).to_string();
                    transmit
                        .send(
                            &connection.channel,
                            0,
                            &Frame::Result {
                                call_id,
                                ok: true,
                                json: body.as_bytes(),
                            },
                        )
                        .await
                        .unwrap();
                }
                Frame::AttachTerm { session_id, .. } => {
                    assert_eq!(session_id, remote_session.as_bytes());
                    attached_streams.push(stream_id);
                    if attached_streams.len() == 2 {
                        transmit
                            .send(&connection.channel, attached_streams[0], &gone)
                            .await
                            .unwrap();
                    }
                }
                _ => {}
            }
        }
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        while hosts.actor(host).await.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("remote host actor did not become available");

    let (local_socket, _local_peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        auth.clone(),
        pool.clone(),
        EmbeddedAgent::from_test_socket(local_socket),
    )
    .await
    .unwrap()
    .with_remote_hosts(hosts);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut browser = welcomed(address, session_token).await;

    // 1. Open the remote terminal session through the browser WebSocket.
    let open_input = serde_json::json!({ "host_id": host }).to_string();
    client_ws_send(
        &mut browser,
        0,
        &Frame::Call {
            call_id: 4404,
            action_id: "ssh.session.open",
            input_json: open_input.as_bytes(),
        },
    )
    .await;
    let opened: serde_json::Value = loop {
        let wire = read_client_frame(&mut browser).await;
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            Frame::Ping { nonce, sent_us } if decoded.stream_id == 0 => {
                client_ws_send(&mut browser, 0, &Frame::Pong { nonce, sent_us }).await;
            }
            Frame::Result { call_id, ok, json } if decoded.stream_id == 0 && call_id == 4404 => {
                assert!(
                    ok,
                    "remote ssh.session.open failed: {}",
                    String::from_utf8_lossy(json)
                );
                break serde_json::from_slice(json).unwrap();
            }
            Frame::Event { .. } => {}
            other => panic!("unexpected frame while opening remote session: {other:?}"),
        }
    };
    assert_eq!(opened["session_id"], remote_session.to_string());

    let (stored_host, before_close): (Option<Vec<u8>>, Option<i64>) =
        sqlx::query_as("SELECT remote_host_id, closed_at FROM terminal_sessions WHERE id=?")
            .bind(remote_session.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_host.as_deref(), Some(host.as_bytes().as_slice()));
    assert_eq!(before_close, None, "newly opened remote row must be open");

    // 2. Attach two browser streams while the row is still open so both 4404s
    //    arrive through `websocket.rs`'s `TerminalOutput::Closed` arm.
    for stream in [1_u32, 3_u32] {
        client_ws_send(
            &mut browser,
            stream,
            &Frame::AttachTerm {
                session_id: remote_session.as_bytes(),
                last_out_seq: 0,
                last_in_seq: 0,
            },
        )
        .await;
    }

    let (code_1, reason_1) = read_stream_close(&mut browser, 1).await;
    assert_eq!(code_1, CLOSE_SESSION_GONE);
    assert_eq!(reason_1, SESSION_GONE_REASON);

    let first_closed_at: Option<i64> =
        sqlx::query_scalar("SELECT closed_at FROM terminal_sessions WHERE id=?")
            .bind(remote_session.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    let first_closed_at = first_closed_at.expect("first 4404 must set closed_at");

    // 3. Backdate `closed_at` through the D379 writer, then trigger the second
    //    4404 from the remote host and verify `closed_at` is not overwritten.
    let sentinel = first_closed_at - 60;
    let session_bytes = *remote_session.as_bytes();
    auth.database()
        .unwrap()
        .write(move |tx| {
            tx.execute(
                "UPDATE terminal_sessions SET closed_at=?1 WHERE id=?2",
                infraternal_db::rusqlite::params![sentinel, session_bytes.as_slice()],
            )?;
            Ok::<_, infraternal_db::Error>(())
        })
        .await
        .unwrap();
    release_second.send(()).unwrap();

    let (code_2, reason_2) = read_stream_close(&mut browser, 3).await;
    assert_eq!(code_2, CLOSE_SESSION_GONE);
    assert_eq!(reason_2, SESSION_GONE_REASON);

    let after_repeat: Option<i64> =
        sqlx::query_scalar("SELECT closed_at FROM terminal_sessions WHERE id=?")
            .bind(remote_session.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        after_repeat,
        Some(sentinel),
        "second 4404 must not overwrite the first closed_at"
    );

    // The shared browser socket remains usable after both 4404 stream closes.
    client_ws_send(
        &mut browser,
        0,
        &Frame::Ping {
            nonce: 588,
            sent_us: 0,
        },
    )
    .await;
    loop {
        let wire = read_client_frame(&mut browser).await;
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            Frame::Pong { nonce: 588, .. } if decoded.stream_id == 0 => break,
            Frame::Event { .. } => {}
            other => panic!("unexpected frame waiting for socket pong: {other:?}"),
        }
    }

    // 4. Retention prune later removes the ended remote row. Prune skips rows a
    //    writer claim still references, and claims hang off the browser's
    //    `websocket_connections` row (ON DELETE CASCADE) which survives a
    //    disconnect until its resume window expires. So the browser leaves, the
    //    connection goes inactive, and the expired connection row is swept the
    //    way the connection sweeper does it; only then can prune proceed.
    drop(browser);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let active: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM websocket_connections WHERE user_id=? AND active=1",
            )
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
            if active == 0 {
                break;
            }
            // sleep: bounded poll of a DB row the server updates on its own task; no event to await
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("browser socket close must deactivate its connection row");
    sqlx::query("DELETE FROM websocket_connections WHERE user_id=? AND active=0")
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    let pruned = crate::terminal_session_prune::prune_closed_sessions(
        Some(&auth),
        &pool,
        first_closed_at + 31 * 86_400,
        100,
    )
    .await;
    assert_eq!(
        pruned,
        Ok(1),
        "retention prune must remove the ended remote row"
    );
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM terminal_sessions WHERE id=?")
        .bind(remote_session.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);

    peer.abort();
    server.abort();
    drop(listeners);
    auth.close_database().await;
    let _ = std::fs::remove_dir_all(&dir);
}
