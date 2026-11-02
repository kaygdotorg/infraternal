//! Independent HTTP and live-WebSocket auth boundary probes; capabilities stay in memory.
use super::*;
use crate::auth::http::Ingress;

#[tokio::test(start_paused = true)]
async fn review3_unwrap_cannot_be_skipped() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let mut f = fixture().await;
    let app = router(f.auth.clone());
    let (_, headers, start) = http_post_json(&app, "login-start", json!({})).await;
    let binding = headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] =
        json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
    let (status, headers, _) = http_post_json_with_cookie(
        &app,
        "login-finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"device":"skip-unwrap"}),
        binding,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let cookie = headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert_eq!(
        http_post_json_with_cookie(&app, "session", json!({}), cookie)
            .await
            .0,
        axum::http::StatusCode::UNAUTHORIZED
    );
    // Neither unwrap nor envelope retrieval occurs. Empty completion cannot identify its pending transaction; no DEK proof is claimed.
    let activate = http_post_json_with_cookie(&app, "unlock-finish", json!({}), cookie)
        .await
        .0;
    let session = http_post_json_with_cookie(&app, "session", json!({}), cookie)
        .await
        .0;
    let privileged = http_post_json_with_cookie(&app, "add-start", json!({}), cookie)
        .await
        .0;
    println!(
        "no unwrap -> unlock-finish={activate}, session={session}, fresh add-start={privileged}"
    );
    assert_eq!(
        session,
        axum::http::StatusCode::UNAUTHORIZED,
        "unbound completion granted full session authority"
    );
}

#[tokio::test(start_paused = true)]
async fn review3_identified_privacy_timing_and_binding_replays() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let mut f = fixture().await;
    let app = router(f.auth.clone());
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    let absent = Uuid::new_v4().to_string();
    for i in 0..1000 {
        *f.auth.ingress.lock().await = Ingress::default();
        // Alternate ordering to reduce systematic warm-cache/order effects.
        for is_known in if i % 2 == 0 {
            [true, false]
        } else {
            [false, true]
        } {
            let user = if is_known { &f.user } else { &absent };
            let begin = Instant::now();
            let response = http_post_json(&app, "login-start", json!({"user_id":user})).await;
            let elapsed = begin.elapsed();
            assert_eq!(response.0, axum::http::StatusCode::UNAUTHORIZED);
            assert_eq!(response.2, json!({"error":"authorization failed"}));
            assert!(!response.1.contains_key(axum::http::header::SET_COOKIE));
            if is_known {
                known.push(elapsed);
            } else {
                unknown.push(elapsed);
            }
        }
    }
    let (kp50, kp99) = latency_us(&mut known);
    let (up50, up99) = latency_us(&mut unknown);
    println!(
        "identified unauthenticated n=1000 each interleaved: known p50={kp50}us p99={kp99}us; unknown p50={up50}us p99={up99}us; identical status/body/no-cookie"
    );
    *f.auth.ingress.lock().await = Ingress::default();
    let (_, headers, start) = http_post_json(&app, "login-start", json!({})).await;
    let binding = headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let (_, foreign_headers, _) = http_post_json(&app, "login-start", json!({})).await;
    let foreign = foreign_headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] =
        json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
    let body = json!({"ceremony":start["ceremony"],"proof":proof,"device":"bound"});
    assert_eq!(
        http_post_json_with_cookie(&app, "login-finish", body.clone(), foreign)
            .await
            .0,
        axum::http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http_post_json_with_cookie(&app, "login-finish", body.clone(), binding)
            .await
            .0,
        axum::http::StatusCode::OK
    );
    assert_eq!(
        http_post_json_with_cookie(&app, "login-finish", body, binding)
            .await
            .0,
        axum::http::StatusCode::UNAUTHORIZED
    );
    println!("foreign jar denied; original success; replay/reuse after success denied");
}

async fn review3_socket() -> (Fixture, SocketAddr, tokio::task::JoinHandle<()>, UnixStream) {
    review3_socket_with_timeouts(None, Duration::from_secs(30)).await
}

async fn review3_socket_with_terminal_timeout(
    timeout: Option<Duration>,
) -> (Fixture, SocketAddr, tokio::task::JoinHandle<()>, UnixStream) {
    review3_socket_with_timeouts(timeout, Duration::from_secs(30)).await
}

/// Override authority reads for regressions that need to exercise the production interval.
async fn review3_socket_with_authority_read_timeout(
    timeout: Duration,
) -> (Fixture, SocketAddr, tokio::task::JoinHandle<()>, UnixStream) {
    review3_socket_with_timeouts(None, timeout).await
}

async fn review3_socket_with_timeouts(
    terminal_timeout: Option<Duration>,
    authority_read_timeout: Duration,
) -> (Fixture, SocketAddr, tokio::task::JoinHandle<()>, UnixStream) {
    let f = fixture().await;
    let (socket, peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_handshake_timeout(Duration::from_secs(30))
    .with_authority_read_timeout(authority_read_timeout);
    let state = if let Some(timeout) = terminal_timeout {
        state.with_terminal_connect_timeout(timeout)
    } else {
        state
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::websocket::router(state))
            .await
            .unwrap();
    });
    (f, addr, server, peer)
}

#[tokio::test(start_paused = true)]
async fn review3_revoked_handshake_must_not_welcome() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (f, addr, server, _peer) = review3_socket().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
    assert_server_hello(&mut socket).await;
    f.auth.logout(&f.session).await.unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "revoked handshake",
        },
    )
    .await;
    let next = tokio::time::timeout(Duration::from_millis(1500), socket.next()).await;
    let welcomed = matches!(next,Ok(Some(Ok(Message::Binary(ref wire)))) if matches!(decode_muxed_frame(wire).unwrap().frame,Frame::Welcome{..}));
    println!("logout committed before client Hello -> Welcome issued={welcomed}");
    server.abort();
    assert!(
        !welcomed,
        "handshake accepted a frame and minted resume capability after revocation"
    );
}

async fn busy_revocation(mode: &str) {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (f, addr, server, mut peer) = review3_socket().await;
    let mut receive = BytesMut::new();
    let _ = read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
    leg_b_send(
        &mut peer,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "delayed backend",
        },
    )
    .await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "busy revocation",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 77,
            action_id: "terminal.open",
            input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
        },
    )
    .await;
    let wire = read_terminal_open(&mut peer, &mut receive).await;
    let Frame::Call { call_id, .. } = decode_muxed_frame(&wire).unwrap().frame else {
        panic!("expected backend call")
    };
    match mode {
        "logout" => f.auth.logout(&f.session).await.unwrap(),
        "recovery" => {
            let request = f
                .auth
                .recovery_start(&f.user, f.words.clone(), NOW)
                .await
                .unwrap();
            let replacement = f.auth.legacy_ready(&request, NOW + DAY).await.unwrap();
            finish_replacement(&f, &replacement, &Software::new(), NOW + DAY).await;
        }
        "expiry" => {
            // Inject the authoritative expiry transition after dispatch began. No
            // clock mock is used; late result handling sees the actual expired row.
            let now = crate::websocket::now_seconds().unwrap();
            sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
                .bind(now - 1)
                .bind(hash(&f.session))
                .execute(&f.auth.pool)
                .await
                .unwrap();
            tokio::time::advance(Duration::from_millis(25)).await;
        }
        _ => unreachable!(),
    }
    let start = Instant::now();
    let next = tokio::time::timeout(Duration::from_secs(30), socket.next())
        .await
        .expect("expired authority must close the busy websocket");
    let close_elapsed = start.elapsed();
    let closed = matches!(next, None | Some(Ok(Message::Close(_)) | Err(_)));
    leg_b_send(
        &mut peer,
        0,
        &Frame::Result {
            call_id,
            ok: true,
            json: br#"{"session_id":"42424242424242424242424242424242"}"#,
        },
    )
    .await;
    let late = tokio::time::timeout(Duration::from_secs(2), socket.next()).await;
    let accepted = matches!(late,Ok(Some(Ok(Message::Binary(ref wire)))) if matches!(decode_muxed_frame(wire).unwrap().frame,Frame::Result{ok:true,..}));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions WHERE user_id=?")
        .bind(&f.user)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    println!(
        "busy {mode} -> closed={closed} at {}ms; success Result after revocation={accepted}; terminal rows committed={rows}",
        close_elapsed.as_millis()
    );
    server.abort();
    assert!(
        closed && !accepted && rows == 0,
        "revocation failed to interrupt busy handler or prevent post-revocation result/mutation"
    );
}

#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn review3_pending_routes_and_idle_expiry_recovery() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (mut f, addr, server, _peer) = review3_socket().await;
    let app = router(f.auth.clone());
    let (_, headers, start) = http_post_json(&app, "login-start", json!({})).await;
    let binding = headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] =
        json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
    let (_, headers, _) = http_post_json_with_cookie(
        &app,
        "login-finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"device":"pending"}),
        binding,
    )
    .await;
    let cookie = headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    for (action, body) in [
        ("session", json!({})),
        ("add-start", json!({})),
        ("login-start", json!({"user_id":f.user})),
        ("recovery-cancel", json!({})),
        ("device-inspect", json!({"code":"unknown"})),
        ("device-approve", json!({"code":"unknown"})),
        ("api-list", json!({})),
        ("api-revoke", json!({"id":"unknown"})),
    ] {
        assert_eq!(
            http_post_json_with_cookie(&app, action, body, cookie)
                .await
                .0,
            axum::http::StatusCode::UNAUTHORIZED,
            "pending route {action}"
        );
    }
    assert_eq!(
        http_post_json_with_cookie(&app, "unlock-session", json!({}), cookie)
            .await
            .0,
        axum::http::StatusCode::OK
    );
    assert_eq!(
        http_post_json_with_cookie(&app, "wraps", json!({}), cookie)
            .await
            .0,
        axum::http::StatusCode::OK
    );
    assert!(
        matches!(connect_async(test_ws_request(addr,cookie)).await,Err(tokio_tungstenite::tungstenite::Error::Http(ref r)) if r.status()==axum::http::StatusCode::UNAUTHORIZED)
    );
    println!(
        "pending cookie: eight protected HTTP actions and WebSocket upgrade denied; identity/wrap reads allowed"
    );
    // Upgrade slides expiry. Install a future deadline, then cross it explicitly.
    let active = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(addr, &active)).await.unwrap();
    assert_server_hello(&mut socket).await;
    let now = crate::websocket::now_seconds().unwrap();
    sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
        .bind(now + DAY)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "expiry",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    // The stored wall-clock authority is expired before the virtual timer fires.
    // CPU scheduling cannot consume a near-term session between Hello and Welcome.
    sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
        .bind(now - 1)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let start = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(u64::try_from(DAY).unwrap())).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .is_ok()
    );
    println!(
        "idle expiry close observed after {}ms of explicit virtual time",
        start.elapsed().as_millis()
    );
    // A second active cookie witnesses actual recovery replacement commit.
    let token = f.auth.login_start(&f.user, NOW).await.unwrap();
    let proof = f.software.login(&token, ORIGIN, true);
    let live = f
        .auth
        .login_finish(
            str_field(&token, "ceremony"),
            proof,
            "recovery observer",
            NOW,
        )
        .await
        .unwrap();
    let active = format!("__Host-infraternal={live}");
    let (mut socket, _) = connect_async(test_ws_request(addr, &active)).await.unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "recovery",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    let request = f
        .auth
        .recovery_start(&f.user, f.words.clone(), NOW)
        .await
        .unwrap();
    let replacement = f.auth.legacy_ready(&request, NOW + DAY).await.unwrap();
    let second = Software::new();
    finish_replacement(&f, &replacement, &second, NOW + DAY).await;
    let start = Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), socket.next())
            .await
            .is_ok()
    );
    println!(
        "idle recovery commit close observed at {}us",
        start.elapsed().as_micros()
    );
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn review3_busy_logout() {
    busy_revocation("logout").await;
}
#[tokio::test(start_paused = true)]
async fn review3_busy_recovery() {
    busy_revocation("recovery").await;
}
#[tokio::test(start_paused = true)]
async fn review3_busy_expiry() {
    busy_revocation("expiry").await;
}

/// A tab's completion and cleanup must leave the replacement cookie's pending row untouched.
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn review3_completion_and_cleanup_are_transaction_bound() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    for reverse in [false, true] {
        let mut f = fixture().await;
        let app = router(f.auth.clone());
        let mut logins = Vec::new();
        for _ in 0..3 {
            let (_, headers, start) = http_post_json(&app, "login-start", json!({})).await;
            let binding = headers[axum::http::header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            let mut proof = f.software.login(&start, ORIGIN, true);
            proof["response"]["userHandle"] =
                json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
            let (status, headers, body) = http_post_json_with_cookie(
                &app,
                "login-finish",
                json!({"ceremony":start["ceremony"],"proof":proof,"device":"tab"}),
                binding,
            )
            .await;
            assert_eq!(status, axum::http::StatusCode::OK);
            let cookie = headers[axum::http::header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            logins.push((cookie, body["pending_transaction"].clone()));
        }
        if reverse {
            logins.swap(0, 1);
        }
        let [(a, id_a), (b, id_b), (cleanup, cleanup_id)] = logins.as_slice() else {
            unreachable!()
        };
        assert!(id_a.is_string() && id_b.is_string() && id_a != id_b);
        for action in ["unlock-finish", "logout"] {
            let (status, headers, _) =
                http_post_json_with_cookie(&app, action, json!({"pending_transaction":id_a}), b)
                    .await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
            assert!(!headers.contains_key(axum::http::header::SET_COOKIE));
            assert_eq!(
                http_post_json_with_cookie(&app, "unlock-session", json!({}), b)
                    .await
                    .0,
                axum::http::StatusCode::OK
            );
            assert_eq!(
                http_post_json_with_cookie(&app, "session", json!({}), b)
                    .await
                    .0,
                axum::http::StatusCode::UNAUTHORIZED
            );
        }
        let (status, headers, _) = http_post_json_with_cookie(
            &app,
            "unlock-finish",
            json!({"pending_transaction":id_a}),
            a,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        // A response may arrive after B replaces the shared cookie jar.
        assert!(!headers.contains_key(axum::http::header::SET_COOKIE));
        assert_eq!(
            http_post_json_with_cookie(
                &app,
                "unlock-finish",
                json!({"pending_transaction":id_a}),
                a
            )
            .await
            .0,
            axum::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_post_json_with_cookie(
                &app,
                "unlock-finish",
                json!({"pending_transaction":id_b}),
                b
            )
            .await
            .0,
            axum::http::StatusCode::OK
        );
        // Reload and identity reads cannot restore a previous login's cookie either.
        for cookie in [a, b] {
            let (status, headers, _) =
                http_post_json_with_cookie(&app, "session", json!({}), cookie).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            assert!(!headers.contains_key(axum::http::header::SET_COOKIE));
        }
        for action in ["unlock-finish", "logout"] {
            let (status, headers, _) =
                http_post_json_with_cookie(&app, action, json!({"pending_transaction":id_a}), b)
                    .await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
            assert!(!headers.contains_key(axum::http::header::SET_COOKIE));
        }
        let (status, headers, _) = http_post_json_with_cookie(
            &app,
            "logout",
            json!({"pending_transaction":cleanup_id}),
            cleanup,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(!headers.contains_key(axum::http::header::SET_COOKIE));
        // B remains active even if cleanup's response is delivered after this read.
        assert_eq!(
            http_post_json_with_cookie(&app, "session", json!({}), b)
                .await
                .0,
            axum::http::StatusCode::OK
        );
    }
}

/// An unresponsive real Unix backend cannot monopolize a browser handler indefinitely.
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn review3_backend_reply_has_a_deadline() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let connect_timeout = Duration::from_secs(2);
    let (f, addr, server, mut peer) =
        review3_socket_with_terminal_timeout(Some(connect_timeout)).await;
    let mut receive = BytesMut::new();
    read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
    leg_b_send(
        &mut peer,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "no reply",
        },
    )
    .await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "deadline",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 78,
            action_id: "terminal.open",
            input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
        },
    )
    .await;
    let wire = read_terminal_open(&mut peer, &mut receive).await;
    let Frame::Call { call_id, .. } = decode_muxed_frame(&wire).unwrap().frame else {
        panic!("backend call")
    };
    let start = tokio::time::Instant::now();
    tokio::time::advance(connect_timeout).await;
    let result = tokio::time::timeout(Duration::from_secs(15), read_client_frame(&mut socket))
        .await
        .unwrap();
    let decoded = decode_muxed_frame(&result).unwrap();
    let elapsed = start.elapsed();
    assert!(
        matches!(
            &decoded.frame,
            Frame::Result {
                call_id: 78,
                ok: false,
                ..
            }
        ),
        "unexpected backend deadline response at {}ms: {:?}",
        elapsed.as_millis(),
        decoded.frame
    );
    assert!(
        elapsed >= connect_timeout,
        "configured terminal deadline returned too early: {elapsed:?}"
    );
    leg_b_send(
        &mut peer,
        0,
        &Frame::Result {
            call_id,
            ok: true,
            json: br#"{"session_id":"42424242424242424242424242424242"}"#,
        },
    )
    .await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 79,
            sent_us: 0,
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::Pong { nonce: 79, .. }
    ));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    println!(
        "backend reply deadline: failure at {}ms; late success ignored; next Ping succeeds; terminal rows=0",
        start.elapsed().as_millis()
    );
    server.abort();
}

/// Resume must not rotate a capability after the authenticating session has been revoked.
#[tokio::test(start_paused = true)]
async fn review3_revoked_resume_must_not_welcome() {
    let _guard = SERIAL.lock().await;
    let clock = FrozenSocketTime::new().await;
    let (f, addr, server, _peer) =
        review3_socket_with_authority_read_timeout(Duration::from_millis(25)).await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut first, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
    assert_server_hello(&mut first).await;
    client_ws_send(
        &mut first,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "original",
        },
    )
    .await;
    let (id, token) = read_welcome(&mut first).await;
    first.close(None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let inactive: bool = sqlx::query_scalar(
                "SELECT active=0 FROM websocket_connections WHERE connection_id=?",
            )
            .bind(id.as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
            if inactive {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (mut socket, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 1,
            client_info: "resume",
        },
    )
    .await;
    f.auth.logout(&f.session).await.unwrap();
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Resume {
            connection_id: &id,
            resume_token: &token,
        },
        &mut wire,
    )
    .unwrap();
    let _ = socket.send(Message::Binary(wire.into())).await;
    // Authority is already revoked and Resume is queued: only closure is valid.
    // Shutdown can need its bounded writer fallback, so let real time run in
    // this negative phase. The read deadline only bounds a hang; no elapsed
    // time is asserted, and any Welcome still fails the authority assertion.
    drop(clock);
    let start = Instant::now();
    let next = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match socket.next().await {
                // The server names why it closes (#227) with an application Close
                // frame first; it is not a Welcome and carries no authority.
                Some(Ok(Message::Binary(ref wire)))
                    if matches!(
                        decode_muxed_frame(wire).map(|d| d.frame),
                        Ok(Frame::Close { .. })
                    ) => {}
                next => break next,
            }
        }
    })
    .await
    .expect("revoked Resume must close the websocket");
    assert!(
        matches!(next, None | Some(Ok(Message::Close(_)) | Err(_))),
        "revoked Resume must close without minting Welcome"
    );
    println!(
        "revoked Resume close={}us; no Welcome",
        start.elapsed().as_micros()
    );
    server.abort();
}

/// Revocation interrupts the pre-Hello wait itself; a client need not send another frame.
#[tokio::test(start_paused = true)]
async fn review3_waiting_handshake_loses_authority() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (f, addr, server, _peer) = review3_socket().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
    assert_server_hello(&mut socket).await;
    f.auth.logout(&f.session).await.unwrap();
    let start = Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), socket.next())
            .await
            .is_ok(),
        "pre-Hello wait retained revoked authority"
    );
    println!("revoked pre-Hello close={}us", start.elapsed().as_micros());
    server.abort();
}

/// A stored expiry transition between upgrade and Hello cannot mint connection state.
#[tokio::test(start_paused = true)]
async fn review3_expired_handshake_must_not_welcome() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (f, addr, server, _peer) = review3_socket().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
    assert_server_hello(&mut socket).await;
    let now = crate::websocket::now_seconds().unwrap();
    sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
        .bind(now - 1)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "expired",
        },
        &mut wire,
    )
    .unwrap();
    let _ = socket.send(Message::Binary(wire.into())).await;
    let next = tokio::time::timeout(Duration::from_millis(100), socket.next()).await;
    assert!(next.is_ok());
    assert!(
        !matches!(next, Ok(Some(Ok(Message::Binary(ref wire)))) if matches!(decode_muxed_frame(wire).unwrap().frame, Frame::Welcome { .. })),
        "expired Hello minted Welcome"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM websocket_connections")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    server.abort();
}
/// A pending live open accepts its reply; committed revocation rejects a later reply.
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn review4_open_reply_and_revocation_preserve_authority() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    for revoke in [false, true] {
        let (f, addr, server, mut peer) =
            review3_socket_with_terminal_timeout(Some(Duration::from_secs(2))).await;
        let mut receive = BytesMut::new();
        read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
        leg_b_send(
            &mut peer,
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "no reply",
            },
        )
        .await;
        let cookie = format!("__Host-infraternal={}", f.session);
        let (mut socket, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
        assert_server_hello(&mut socket).await;
        client_ws_send(
            &mut socket,
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "deadline",
            },
        )
        .await;
        read_welcome(&mut socket).await;
        client_ws_send(
            &mut socket,
            0,
            &Frame::Call {
                call_id: 78,
                action_id: "terminal.open",
                input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
            },
        )
        .await;
        let wire = read_terminal_open(&mut peer, &mut receive).await;
        let Frame::Call { call_id, .. } = decode_muxed_frame(&wire).unwrap().frame else {
            panic!("backend call")
        };
        if revoke {
            f.auth.logout(&f.session).await.unwrap();
            let closed = tokio::time::timeout(Duration::from_secs(10), socket.next())
                .await
                .expect("committed revocation must close a pending open");
            assert!(matches!(
                closed,
                None | Some(Ok(Message::Close(_)) | Err(_))
            ));
        }
        leg_b_send(
            &mut peer,
            0,
            &Frame::Result {
                call_id,
                ok: true,
                json: br#"{"session_id":"42424242424242424242424242424242"}"#,
            },
        )
        .await;
        if revoke {
            let late = tokio::time::timeout(Duration::from_secs(2), socket.next()).await;
            assert!(!matches!(late, Ok(Some(Ok(Message::Binary(_))))));
        } else {
            let result =
                tokio::time::timeout(Duration::from_secs(1), read_client_frame(&mut socket))
                    .await
                    .unwrap();
            assert!(
                matches!(
                    decode_muxed_frame(&result).unwrap().frame,
                    Frame::Result {
                        call_id: 78,
                        ok: true,
                        ..
                    }
                ),
                "live terminal open was rejected"
            );
            println!("PASS: live terminal open returned its synchronized backend result");
        }
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
        assert_eq!(rows, i64::from(!revoke));
        server.abort();
    }
}

/// Exercise slow connects at all 16 per-user sockets, with real SQLite and Unix replies.
#[tokio::test]
#[ignore = "release-only connect scale measurement; run without concurrent builds"]
#[allow(clippy::too_many_lines)]
async fn review4_slow_open_at_user_capacity() {
    let _guard = SERIAL.lock().await;
    for revoke in [false, true] {
        let (f, addr, server, mut peer) = review3_socket().await;
        let mut receive = BytesMut::new();
        read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
        leg_b_send(
            &mut peer,
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "no reply",
            },
        )
        .await;
        let cookie = format!("__Host-infraternal={}", f.session);
        let mut sockets = Vec::new();
        let mut calls = Vec::new();
        for _ in 0..16 {
            let (mut socket, _) = connect_async(test_ws_request(addr, &cookie)).await.unwrap();
            assert_server_hello(&mut socket).await;
            client_ws_send(
                &mut socket,
                0,
                &Frame::Hello {
                    version: 1,
                    caps: 0,
                    client_info: "connect scale",
                },
            )
            .await;
            read_welcome(&mut socket).await;
            client_ws_send(
                &mut socket,
                0,
                &Frame::Call {
                    call_id: 78,
                    action_id: "terminal.open",
                    input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
                },
            )
            .await;
            let wire = read_terminal_open(&mut peer, &mut receive).await;
            let Frame::Call { call_id, .. } = decode_muxed_frame(&wire).unwrap().frame else {
                panic!("backend call");
            };
            calls.push(call_id);
            sockets.push(socket);
        }
        let start = tokio::time::Instant::now();
        if revoke {
            tokio::time::sleep(Duration::from_secs(1)).await;
            f.auth.logout(&f.session).await.unwrap();
            let closed_at = Instant::now();
            for socket in &mut sockets {
                let next = tokio::time::timeout(Duration::from_millis(100), socket.next()).await;
                assert!(matches!(
                    next,
                    Ok(None | Some(Ok(Message::Close(_)) | Err(_)))
                ));
            }
            assert!(closed_at.elapsed() < Duration::from_millis(100));
            println!(
                "PASS: 16 pending opens revoked; all sockets closed in {}us",
                closed_at.elapsed().as_micros()
            );
        }
        tokio::time::sleep_until(start + Duration::from_secs(10)).await;
        for (index, call_id) in calls.into_iter().enumerate() {
            let session = format!("{{\"session_id\":\"{:032x}\"}}", index + 1);
            leg_b_send(
                &mut peer,
                0,
                &Frame::Result {
                    call_id,
                    ok: true,
                    json: session.as_bytes(),
                },
            )
            .await;
        }
        if revoke {
            for socket in &mut sockets {
                let late = tokio::time::timeout(Duration::from_millis(100), socket.next()).await;
                assert!(!matches!(late, Ok(Some(Ok(Message::Binary(_))))));
            }
        } else {
            for socket in &mut sockets {
                let wire = tokio::time::timeout(Duration::from_secs(1), read_client_frame(socket))
                    .await
                    .unwrap();
                assert!(matches!(
                    decode_muxed_frame(&wire).unwrap().frame,
                    Frame::Result {
                        call_id: 78,
                        ok: true,
                        ..
                    }
                ));
            }
            println!(
                "PASS: 16 live ten-second opens succeeded in {}ms",
                start.elapsed().as_millis()
            );
        }
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
        assert_eq!(rows, if revoke { 0 } else { 16 });
        server.abort();
    }
}
