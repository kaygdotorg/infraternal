//! Independent HTTP and live-WebSocket auth boundary probes; capabilities stay in memory.
use super::*;
use crate::auth::http::Ingress;

#[tokio::test]
async fn review3_unwrap_cannot_be_skipped() {
    let _guard = SERIAL.lock().await;
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

#[tokio::test]
async fn review3_identified_privacy_timing_and_binding_replays() {
    let _guard = SERIAL.lock().await;
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
    let f = fixture().await;
    let (socket, peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::websocket::router(state))
            .await
            .unwrap();
    });
    (f, addr, server, peer)
}

#[tokio::test]
#[ignore = "Known focused-audit regression #29; run explicitly before fixing"]
async fn review3_revoked_handshake_must_not_welcome() {
    let _guard = SERIAL.lock().await;
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
    let wire = read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
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
            let replacement = f.auth.recovery_ready(&request, NOW + DAY).await.unwrap();
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
        }
        _ => unreachable!(),
    }
    let start = Instant::now();
    let next = tokio::time::timeout(Duration::from_millis(1500), socket.next()).await;
    let close_elapsed = start.elapsed();
    let still_open = next.is_err();
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
    let late = tokio::time::timeout(Duration::from_millis(1500), socket.next()).await;
    let accepted = matches!(late,Ok(Some(Ok(Message::Binary(ref wire)))) if matches!(decode_muxed_frame(wire).unwrap().frame,Frame::Result{ok:true,..}));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions WHERE user_id=?")
        .bind(&f.user)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    println!(
        "busy {mode} -> still open at {}ms={still_open}; success Result after revocation={accepted}; terminal rows committed={rows}",
        close_elapsed.as_millis()
    );
    server.abort();
    assert!(
        close_elapsed < Duration::from_millis(100),
        "busy {mode} close took {close_elapsed:?}"
    );
    assert!(
        !still_open && !accepted && rows == 0,
        "revocation failed to interrupt busy handler or prevent post-revocation result/mutation"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn review3_pending_routes_and_idle_expiry_recovery() {
    let _guard = SERIAL.lock().await;
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
    // Upgrade slides expiry, so set a real near-term deadline between upgrade and Hello.
    let active = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(addr, &active)).await.unwrap();
    assert_server_hello(&mut socket).await;
    let now = crate::websocket::now_seconds().unwrap();
    sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
        .bind(now + 2)
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
    let start = Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .is_ok()
    );
    println!(
        "idle expiry close observed at {}ms (2-second deadline with second-resolution clock)",
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
    let replacement = f.auth.recovery_ready(&request, NOW + DAY).await.unwrap();
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

#[tokio::test]
async fn review3_busy_logout() {
    busy_revocation("logout").await;
}
#[tokio::test]
async fn review3_busy_recovery() {
    busy_revocation("recovery").await;
}
#[tokio::test]
async fn review3_busy_expiry() {
    busy_revocation("expiry").await;
}

/// A tab's completion and cleanup must leave the replacement cookie's pending row untouched.
#[tokio::test]
async fn review3_completion_and_cleanup_are_transaction_bound() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let app = router(f.auth.clone());
    let mut logins = Vec::new();
    for _ in 0..2 {
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
    let [(a, id_a), (b, id_b)] = logins.as_slice() else {
        unreachable!()
    };
    assert!(id_a.is_string() && id_b.is_string() && id_a != id_b);
    for action in ["unlock-finish", "logout"] {
        let (status, headers, _) =
            http_post_json_with_cookie(&app, action, json!({"pending_transaction":id_a}), b).await;
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
    assert_eq!(
        http_post_json_with_cookie(
            &app,
            "unlock-finish",
            json!({"pending_transaction":id_a}),
            a
        )
        .await
        .0,
        axum::http::StatusCode::OK
    );
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
}

/// An unresponsive real Unix backend cannot monopolize a browser handler indefinitely.
#[tokio::test]
async fn review3_backend_reply_has_a_deadline() {
    let _guard = SERIAL.lock().await;
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
    let wire = read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
    let Frame::Call { call_id, .. } = decode_muxed_frame(&wire).unwrap().frame else {
        panic!("backend call")
    };
    let start = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(6), read_client_frame(&mut socket))
        .await
        .unwrap();
    assert!(matches!(
        decode_muxed_frame(&result).unwrap().frame,
        Frame::Result {
            call_id: 78,
            ok: false,
            ..
        }
    ));
    assert!(start.elapsed() < Duration::from_secs(6));
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
