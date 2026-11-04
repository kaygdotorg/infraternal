//! Account-isolation checks at the 256-socket server ceiling using real SQLite and socket connections.

use super::*;

#[tokio::test(start_paused = true)]
async fn account_logout_wakes_only_its_16_sockets_among_256() {
    account_isolation_at_capacity(false).await;
}

#[tokio::test(start_paused = true)]
async fn account_recovery_wakes_only_its_16_sockets_among_256() {
    account_isolation_at_capacity(true).await;
}

async fn account_isolation_at_capacity(recovery: bool) {
    let _guard = SERIAL.lock().await;
    let clock = FrozenSocketTime::new().await;
    let (f, address, server) = socket_fixture().await;
    let now = crate::websocket::now_seconds().unwrap();
    let mut accounts = vec![(f.user.clone(), f.session.clone())];
    // One account uses its 16-socket cap; 60 others use four sockets each.
    for index in 1..61 {
        let user = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'test',0,'unused',?,'Test')")
            .bind(&user).bind(format!("account-{index}")).execute(&f.auth.pool).await.unwrap();
        let session = random();
        let mut tx = f.auth.pool.begin().await.unwrap();
        insert_session(&mut tx, &session, &user, "test", now, None)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        accounts.push((user, session));
    }
    let mut sockets = Vec::new();
    for (index, (_, session)) in accounts.iter().enumerate() {
        let mut devices = Vec::new();
        let count = if index == 0 { 16 } else { 4 };
        for _ in 0..count {
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
                    caps: 4,
                    client_info: "account-isolation",
                },
            )
            .await;
            read_welcome(&mut socket).await;
            client_ws_send(
                &mut socket,
                0,
                &Frame::Subscribe {
                    sub_id: 45,
                    filter_json: br#"{"topic":"auth.recovery"}"#,
                },
            )
            .await;
            let bytes = read_client_frame(&mut socket).await;
            assert!(matches!(
                decode_muxed_frame(&bytes).unwrap().frame,
                Frame::Event { sub_id: 45, .. }
            ));
            application_barrier(&mut socket).await;
            // Suppress unrelated liveness timers. The Pong fences the visibility notice;
            // runtime time remains stationary throughout the notification/read assertions.
            client_ws_send(
                &mut socket,
                0,
                &Frame::Event {
                    sub_id: 0,
                    event_json: br#"{"topic":"connection.visibility","hidden":true}"#,
                },
            )
            .await;
            client_ws_send(
                &mut socket,
                0,
                &Frame::Ping {
                    nonce: 240,
                    sent_us: 0,
                },
            )
            .await;
            loop {
                let bytes = read_client_frame(&mut socket).await;
                if matches!(
                    decode_muxed_frame(&bytes).unwrap().frame,
                    Frame::Pong { nonce: 240, .. }
                ) {
                    break;
                }
            }
            devices.push(socket);
            clock.progress();
        }
        sockets.push(devices);
    }
    let before: Vec<_> = accounts
        .iter()
        .map(|(user, _)| f.auth.authority_reads(user))
        .collect();
    if recovery {
        let recovery_now = crate::websocket::now_seconds().unwrap();
        let (token, ready) = f
            .auth
            .recovery_start_with_session(&f.user, f.words.clone(), Some(&f.session), recovery_now)
            .await
            .unwrap();
        assert!(ready < recovery_now + DAY);
        // Drain the authorized start notice before completion revokes the old sessions.
        for socket in &mut sockets[0] {
            let bytes = read_client_frame(socket).await;
            assert!(matches!(
                decode_muxed_frame(&bytes).unwrap().frame,
                Frame::Event { sub_id: 45, .. }
            ));
        }
        let start = f.auth.legacy_ready(&token, ready).await.unwrap();
        let second = Software::new();
        let _replacement = finish_replacement(&f, &start, &second, ready).await;
    } else {
        f.auth.logout(&accounts[0].1).await.unwrap();
    }
    for socket in &mut sockets[0] {
        assert_socket_closed(socket).await;
        clock.progress();
    }
    for _ in 0..256 {
        tokio::task::yield_now().await;
    }
    assert!(f.auth.authority_reads(&accounts[0].0) > before[0]);
    for (index, (user, _)) in accounts.iter().enumerate().skip(1) {
        assert_eq!(
            f.auth.authority_reads(user),
            before[index],
            "unrelated account read authority after an account change"
        );
    }
    // Prove all 240 unaffected sockets still process authenticated application work.
    for devices in sockets.iter_mut().skip(1) {
        for socket in devices {
            application_barrier(socket).await;
            clock.progress();
        }
    }
    eprintln!(
        "account_isolation recovery={recovery} sockets=256 accounts=61 affected=16 unaffected=240 affected_reads={} unrelated_reads=0 recovered=240",
        f.auth.authority_reads(&accounts[0].0) - before[0]
    );
    server.abort();
}

async fn application_barrier(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    client_ws_send(
        socket,
        0,
        &Frame::Call {
            call_id: 240,
            action_id: "test.not.an.action",
            input_json: b"{}",
        },
    )
    .await;
    loop {
        let bytes = read_client_frame(socket).await;
        match decode_muxed_frame(&bytes).unwrap().frame {
            Frame::Result { call_id: 240, .. } => return,
            Frame::Close { .. } => panic!("account-isolation socket closed before its result"),
            _ => {}
        }
    }
}

#[tokio::test(start_paused = true)]
async fn coalesced_session_logout_cannot_hide_an_earlier_revoked_proof_lease() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let mut lease = crate::websocket::probe_authority::Lease::new(&state, &f.user, &f.session)
        .await
        .unwrap();
    let later_session = random();
    let mut tx = f.auth.pool.begin().await.unwrap();
    insert_session(&mut tx, &later_session, &f.user, "later", NOW, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    f.auth.logout(&f.session).await.unwrap();
    // Replace the unseen event with a different session. The lease must recheck its
    // account, even though the last event's session hash no longer identifies it.
    f.auth.logout(&later_session).await.unwrap();
    let polled = std::sync::atomic::AtomicBool::new(false);
    let result = lease
        .run(&state, &f.user, &f.session, async {
            polled.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await;
    assert!(result.is_err());
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn another_live_session_on_the_affected_account_keeps_its_proof_lease() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let another_session = random();
    let mut tx = f.auth.pool.begin().await.unwrap();
    insert_session(
        &mut tx,
        &another_session,
        &f.user,
        "another-device",
        NOW,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let mut lease =
        crate::websocket::probe_authority::Lease::new(&state, &f.user, &another_session)
            .await
            .unwrap();
    f.auth.logout(&f.session).await.unwrap();
    let mut polled = false;
    let result = lease
        .run(&state, &f.user, &another_session, async {
            polled = true;
            Ok(())
        })
        .await;
    assert!(result.is_ok());
    assert!(polled);
}
