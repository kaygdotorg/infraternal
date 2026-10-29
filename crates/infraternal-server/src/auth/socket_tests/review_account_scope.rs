//! Independent account-generation and authority checks across commit, identity and recovery races (#240).

use super::*;
use crate::websocket::{AuthorityMiss, WebSocketState, probe_authority::Lease};

async fn state(f: &Fixture) -> WebSocketState {
    let (socket, _peer) = UnixStream::pair().unwrap();
    WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
}

async fn another_account(f: &Fixture) -> (String, String) {
    let user = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'test',0,'unused',?,'Test')")
        .bind(&user).bind(&user).execute(&f.auth.pool).await.unwrap();
    let token = random();
    let mut tx = f.auth.pool.begin().await.unwrap();
    insert_session(&mut tx, &token, &user, "review", NOW, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (user, token)
}

async fn refuses(lease: &mut Lease, state: &WebSocketState, user: &str, token: &str) {
    let mut polled = false;
    let result = lease
        .run(state, user, token, async {
            polled = true;
            Ok(())
        })
        .await;
    assert_eq!(result, Err(AuthorityMiss::Refused));
    assert!(!polled, "revoked authority polled guarded work");
}

#[tokio::test(start_paused = true)]
async fn two_accounts_revoked_before_either_cursor_runs_both_refuse() {
    let _serial = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (b, token_b) = another_account(&f).await;
    let (c, token_c) = another_account(&f).await;
    let state = state(&f).await;
    let mut a = Lease::new(&state, &f.user, &f.session).await.unwrap();
    let mut b_lease = Lease::new(&state, &b, &token_b).await.unwrap();
    let mut c_lease = Lease::new(&state, &c, &token_c).await.unwrap();
    let c_reads = f.auth.authority_reads(&c);
    let (a_result, b_result) = tokio::join!(f.auth.logout(&f.session), f.auth.logout(&token_b));
    a_result.unwrap();
    b_result.unwrap();
    refuses(&mut a, &state, &f.user, &f.session).await;
    refuses(&mut b_lease, &state, &b, &token_b).await;
    assert_eq!(
        c_lease.run(&state, &c, &token_c, async { Ok(()) }).await,
        Ok(())
    );
    assert_eq!(f.auth.authority_reads(&c), c_reads);
}

#[tokio::test(start_paused = true)]
async fn lagged_cursors_survive_65536_overwrites_and_unknown_scope_wakes_every_account() {
    let _serial = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (b, token_b) = another_account(&f).await;
    let (c, token_c) = another_account(&f).await;
    let state = state(&f).await;
    let mut a = Lease::new(&state, &f.user, &f.session).await.unwrap();
    let mut b_lease = Lease::new(&state, &b, &token_b).await.unwrap();
    let mut c_lease = Lease::new(&state, &c, &token_c).await.unwrap();
    let events = [&f.user, &b, &c].map(|user| f.auth.revocation_events(user));
    f.auth.logout(&f.session).await.unwrap();
    f.auth.logout(&token_b).await.unwrap();
    // Watch channels have no bounded queue to overflow. Even an identical last hint
    // must preserve a dirty generation for every cursor that has not consumed it.
    for _ in 0..65_536 {
        f.auth.revocations.publish(&f.user, None);
        f.auth.revocations.publish(&b, None);
    }
    assert!(events[0].has_changed().unwrap());
    assert!(events[1].has_changed().unwrap());
    assert!(!events[2].has_changed().unwrap());
    f.auth.revocations.publish_all();
    assert!(events.iter().all(|event| event.has_changed().unwrap()));
    refuses(&mut a, &state, &f.user, &f.session).await;
    refuses(&mut b_lease, &state, &b, &token_b).await;
    assert_eq!(
        c_lease.run(&state, &c, &token_c, async { Ok(()) }).await,
        Ok(())
    );
}

#[tokio::test(start_paused = true)]
async fn simultaneous_recovery_a_and_logout_b_preserve_both_scopes() {
    let _serial = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (b, token_b) = another_account(&f).await;
    let (c, _) = another_account(&f).await;
    let recovery_a = f.auth.recovery_events(&f.user);
    let recovery_b = f.auth.recovery_events(&b);
    let recovery_c = f.auth.recovery_events(&c);
    let logout_a = f.auth.revocation_events(&f.user);
    let logout_b = f.auth.revocation_events(&b);
    let logout_c = f.auth.revocation_events(&c);
    let state = state(&f).await;
    let mut a = Lease::new(&state, &f.user, &f.session).await.unwrap();
    let mut b_lease = Lease::new(&state, &b, &token_b).await.unwrap();
    let (recovery, logout) = tokio::join!(
        f.auth
            .recovery_start_with_session(&f.user, f.words.clone(), Some(&f.session), NOW),
        f.auth.logout(&token_b)
    );
    let (token, ready) = recovery.unwrap();
    logout.unwrap();
    assert!(recovery_a.has_changed().unwrap());
    assert!(!recovery_b.has_changed().unwrap());
    assert!(!recovery_c.has_changed().unwrap());
    assert!(!logout_a.has_changed().unwrap());
    assert!(logout_b.has_changed().unwrap());
    assert!(!logout_c.has_changed().unwrap());
    refuses(&mut b_lease, &state, &b, &token_b).await;
    let start = f.auth.legacy_ready(&token, ready).await.unwrap();
    finish_replacement(&f, &start, &Software::new(), ready).await;
    assert!(logout_a.has_changed().unwrap());
    assert!(!logout_c.has_changed().unwrap());
    refuses(&mut a, &state, &f.user, &f.session).await;
}

#[tokio::test(start_paused = true)]
async fn reassigned_session_cannot_authorize_work_for_its_former_account() {
    let _serial = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (b, _) = another_account(&f).await;
    let state = state(&f).await;
    let mut lease = Lease::new(&state, &f.user, &f.session).await.unwrap();
    // There is no production reassignment API. Model an out-of-band database edit
    // using the documented unknown-scope notification; the old account stays pinned.
    sqlx::query("UPDATE sessions SET user_id=? WHERE token_hash=?")
        .bind(&b)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    f.auth.revocations.publish_all();
    refuses(&mut lease, &state, &f.user, &f.session).await;
    assert!(
        f.auth
            .live_expiry(&f.session, &f.user, NOW, ())
            .await
            .is_err()
    );
    assert!(f.auth.live_expiry(&f.session, &b, NOW, ()).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn account_deletion_retires_open_sockets_without_affecting_other_accounts() {
    let _serial = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (f, address, server) = socket_fixture().await;
    let (b, _) = another_account(&f).await;
    let other = f.auth.revocation_events(&b);
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut browser, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut browser).await;
    client_ws_send(
        &mut browser,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "account-delete-review",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    // No account-deletion API exists yet. Remove this fixture's FK dependents in
    // one real transaction, then explicitly notify its known affected account.
    let mut tx = f.auth.pool.begin().await.unwrap();
    for table in ["sessions", "passkeys", "wraps"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id=?"))
            .bind(&f.user)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(&f.user)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    f.auth.revocations.publish(&f.user, None);
    assert_socket_closed(&mut browser).await;
    assert!(!other.has_changed().unwrap());
    server.abort();
}
