//! Durable per-device input authority; a second writer never inherits another device's Ack.
use super::*;

#[path = "websocket_authority_tests.rs"]
mod authority_watchdog;

#[path = "websocket_busy_edge_tests.rs"]
pub(super) mod busy_edges;

async fn database() -> (SqlitePool, String, [u8; 16]) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let user = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES (?,'writer','writer','Writer',1,'unused-test-hash')")
        .bind(&user).execute(&pool).await.unwrap();
    let session = [7; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,input_acked_u64) VALUES (?,?,0,0,?)")
        .bind(session.as_slice()).bind(&user).bind(77_u64.to_be_bytes().as_slice()).execute(&pool).await.unwrap();
    (pool, user, session)
}

#[tokio::test]
async fn second_device_does_not_inherit_first_device_input_ack() {
    let (pool, user, session) = database().await;
    let a = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let b = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let (offset_a, stream_a) = owned_writer(&pool, &user, &a.connection_id, 1, &session, None)
        .await
        .unwrap();
    assert_eq!(offset_a, 0);
    sqlx::query("UPDATE terminal_writers SET input_acked=? WHERE connection_id=?")
        .bind(77_u64.to_be_bytes().as_slice())
        .bind(a.connection_id.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let (offset_b, stream_b) = owned_writer(&pool, &user, &b.connection_id, 1, &session, None)
        .await
        .unwrap();
    assert_ne!(stream_a, stream_b);
    let resumed = owned_writer(&pool, &user, &a.connection_id, 1, &session, None)
        .await
        .unwrap();
    assert_eq!(resumed, (77, stream_a));
    assert_eq!(
        offset_b, 0,
        "new device inherited the other writer's input range"
    );
}

#[tokio::test]
async fn writer_ownership_capacity_unsigned_offsets_and_identity_reuse() {
    let (pool, user, session) = database().await;
    let connection = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let (_, first) = owned_writer(&pool, &user, &connection.connection_id, 1, &session, None)
        .await
        .unwrap();
    assert!(
        owned_writer(
            &pool,
            "different-user",
            &connection.connection_id,
            1,
            &session,
            None
        )
        .await
        .is_err()
    );
    assert!(
        owned_writer(&pool, &user, &connection.connection_id, 1, &[8; 16], None)
            .await
            .is_err()
    );
    let high = u64::MAX - 1;
    sqlx::query(
        "UPDATE terminal_writers SET input_acked=? WHERE connection_id=? AND client_stream=1",
    )
    .bind(high.to_be_bytes().as_slice())
    .bind(connection.connection_id.as_slice())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        owned_writer(&pool, &user, &connection.connection_id, 1, &session, None)
            .await
            .unwrap(),
        (high, first)
    );
    for stream in (3..=63).step_by(2) {
        owned_writer(
            &pool,
            &user,
            &connection.connection_id,
            stream,
            &session,
            None,
        )
        .await
        .unwrap();
    }
    assert!(
        owned_writer(&pool, &user, &connection.connection_id, 65, &session, None)
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM websocket_connections WHERE connection_id=?")
        .bind(connection.connection_id.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_writers")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let next = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let (_, identity) = owned_writer(&pool, &user, &next.connection_id, 1, &session, None)
        .await
        .unwrap();
    assert!(
        identity > first,
        "a new writer reused a retired input identity"
    );
}

/// Measure SQLite authority lookups at one user's full 16 × 32 attachment capacity.
#[tokio::test]
#[ignore = "release-only scale measurement; run without concurrent builds"]
async fn writer_admission_at_user_capacity() {
    let (pool, user, session) = database().await;
    let mut connections = Vec::new();
    for _ in 0..16 {
        let connection = new_connection(&pool, &user, 0, None, None).await.unwrap();
        for stream in (1..=63).step_by(2) {
            owned_writer(
                &pool,
                &user,
                &connection.connection_id,
                stream,
                &session,
                None,
            )
            .await
            .unwrap();
        }
        connections.push(connection);
    }
    let mut samples = Vec::new();
    for _ in 0..200 {
        for connection in &connections {
            let start = std::time::Instant::now();
            owned_writer(&pool, &user, &connection.connection_id, 1, &session, None)
                .await
                .unwrap();
            samples.push(start.elapsed());
        }
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2].as_micros();
    let p99 = samples[(samples.len() * 99).div_ceil(100) - 1].as_micros();
    println!(
        "writer authority: connections=16 writers=512 n={} p50_us={p50} p99_us={p99} SQLite=memory arch={} load={}",
        samples.len(),
        std::env::consts::ARCH,
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    assert!(p99 < 1000, "writer authority exceeded local 1ms budget");
}

#[tokio::test]
async fn reserved_plugin_writers_do_not_alias_later_terminals() {
    let (pool, user, session) = database().await;
    // A committed plugin reservation has no terminal row. AUTOINCREMENT alone
    // would reuse its identity when the next terminal attaches.
    sqlx::query("UPDATE wire_writer_clock SET value=1000")
        .execute(&pool)
        .await
        .unwrap();
    let connection = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let (_, writer) = owned_writer(&pool, &user, &connection.connection_id, 1, &session, None)
        .await
        .unwrap();
    assert_eq!(
        writer, 2002,
        "terminal ignored committed plugin reservations"
    );
    let (_, resumed) = owned_writer(&pool, &user, &connection.connection_id, 1, &session, None)
        .await
        .unwrap();
    assert_eq!(
        resumed, writer,
        "resume replaced a published terminal identity"
    );
}

#[tokio::test]
async fn terminal_sequence_survives_deletion_and_native_build_transitions() {
    let (pool, user, session) = database().await;
    let connection = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let (_, first) = owned_writer(&pool, &user, &connection.connection_id, 1, &session, None)
        .await
        .unwrap();
    sqlx::query("DELETE FROM terminal_writers")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let native = crate::wire_identity::reserve(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let (_, next) = owned_writer(&pool, &user, &connection.connection_id, 1, &session, None)
        .await
        .unwrap();
    assert_eq!((first, native, next), (2, 4, 6));
    sqlx::query("UPDATE wire_writer_clock SET value=2147483647")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        owned_writer(&pool, &user, &connection.connection_id, 3, &session, None)
            .await
            .is_err()
    );
    assert_eq!(
        owned_writer(&pool, &user, &connection.connection_id, 1, &session, None)
            .await
            .unwrap()
            .1,
        next
    );
}

#[tokio::test]
async fn resume_refusals_distinguish_connection_state_and_lost_token_rotation() {
    let (pool, user, _) = database().await;
    let welcome = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let id = welcome.connection_id;
    let token = welcome.resume_token;
    let refused = resume_connection(&pool, &user, id, token, 0, None, None)
        .await
        .err()
        .unwrap();
    assert!(matches!(refused, sqlx::Error::Protocol(ref check) if check == "connection_active"));
    sqlx::query("UPDATE websocket_connections SET active=0,expires_at=120")
        .execute(&pool)
        .await
        .unwrap();
    for (owner, requested_id, requested_token, now, expected) in [
        ("another-person", id, token, 0, "connection_owner"),
        (user.as_str(), [9; 16], token, 0, "connection_missing"),
        (user.as_str(), id, token, 121, "resume_expired"),
        (user.as_str(), id, [0; 32], 0, "token_mismatch"),
    ] {
        let refused =
            resume_connection(&pool, owner, requested_id, requested_token, now, None, None)
                .await
                .err()
                .unwrap();
        assert!(matches!(refused, sqlx::Error::Protocol(ref check) if check == expected));
    }
    // Rotation committed but the transport lost Welcome: the browser still has
    // its old token. Diagnose the mismatch without weakening token validation.
    resume_connection(&pool, &user, id, token, 0, None, None)
        .await
        .unwrap();
    sqlx::query("UPDATE websocket_connections SET active=0,expires_at=120")
        .execute(&pool)
        .await
        .unwrap();
    let refused = resume_connection(&pool, &user, id, token, 0, None, None)
        .await
        .err()
        .unwrap();
    assert!(matches!(refused, sqlx::Error::Protocol(ref check) if check == "token_mismatch"));
}

/// A WAL database file under a fresh private directory, shaped like the server's
/// own, so `Auth` puts its D379 writer in front of it (#562).
async fn disk_database() -> (SqlitePool, String, [u8; 16], Auth, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("infraternal-claim-{}", rand::random::<u64>()));
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
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    assert!(
        auth.database().is_some(),
        "an on-disk Auth owns a D379 pool"
    );
    let user = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES (?,'writer','writer','Writer',1,'unused-test-hash')")
        .bind(&user).execute(&pool).await.unwrap();
    let session = [7; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,input_acked_u64) VALUES (?,?,0,0,?)")
        .bind(session.as_slice()).bind(&user).bind(77_u64.to_be_bytes().as_slice()).execute(&pool).await.unwrap();
    (pool, user, session, auth, dir)
}

/// Claim through the D379 writer with the sqlx test's inputs.
async fn claim_on_writer(
    auth: &Auth,
    user: &str,
    connection: &[u8; 16],
    stream: u32,
    session: &[u8; 16],
    authority: Option<&str>,
    limit: i64,
) -> Result<(u64, u32), ()> {
    crate::terminal_writer_claim::claim(
        auth,
        crate::terminal_writer_claim::Claim {
            user,
            connection,
            stream,
            session,
            authority,
            limit,
        },
    )
    .await
    .expect("an on-disk Auth has a writer")
}

/// The D379 claim keeps every rule of the sqlx `owned_writer`: a device gets
/// its own identity and offset, a repeat claim returns the same row, another
/// account or an unknown session is refused, the per-socket limit holds, ids
/// never repeat after a socket is deleted, and a logged-out session is refused.
#[tokio::test]
async fn writer_claim_on_the_d379_writer_keeps_the_sqlx_rules() {
    let (pool, user, session, auth, dir) = disk_database().await;
    let a = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let b = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let (offset, first) = claim_on_writer(&auth, &user, &a.connection_id, 1, &session, None, 32)
        .await
        .unwrap();
    assert_eq!(
        (offset, first % 2),
        (0, 0),
        "a fresh writer starts at zero, even id"
    );
    let (_, other_device) = claim_on_writer(&auth, &user, &b.connection_id, 1, &session, None, 32)
        .await
        .unwrap();
    assert_ne!(first, other_device);
    let high = u64::MAX - 1;
    sqlx::query(
        "UPDATE terminal_writers SET input_acked=? WHERE connection_id=? AND client_stream=1",
    )
    .bind(high.to_be_bytes().as_slice())
    .bind(a.connection_id.as_slice())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        claim_on_writer(&auth, &user, &a.connection_id, 1, &session, None, 32).await,
        Ok((high, first)),
        "a repeat claim returns the stored offset and identity"
    );
    assert!(
        claim_on_writer(
            &auth,
            "someone-else",
            &a.connection_id,
            1,
            &session,
            None,
            32
        )
        .await
        .is_err()
    );
    assert!(
        claim_on_writer(&auth, &user, &a.connection_id, 1, &[8; 16], None, 32)
            .await
            .is_err()
    );
    claim_on_writer(&auth, &user, &a.connection_id, 3, &session, None, 2)
        .await
        .unwrap();
    assert!(
        claim_on_writer(&auth, &user, &a.connection_id, 5, &session, None, 2)
            .await
            .is_err(),
        "the per-socket limit holds"
    );
    sqlx::query("DELETE FROM websocket_connections WHERE connection_id=?")
        .bind(a.connection_id.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let c = new_connection(&pool, &user, 0, None, None).await.unwrap();
    let (_, later) = claim_on_writer(&auth, &user, &c.connection_id, 1, &session, None, 32)
        .await
        .unwrap();
    assert!(
        later > first,
        "a new writer reused a retired input identity"
    );

    let now = unix_seconds().unwrap();
    let hash = crate::auth::hash("claim-token");
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'claim',?,?,1)")
        .bind(&hash).bind(&user).bind(now + 3600).bind(now)
        .execute(&pool).await.unwrap();
    claim_on_writer(&auth, &user, &c.connection_id, 3, &session, Some(&hash), 32)
        .await
        .unwrap();
    assert!(
        claim_on_writer(
            &auth,
            &user,
            &c.connection_id,
            5,
            &session,
            Some("not-a-session"),
            32
        )
        .await
        .is_err()
    );
    sqlx::query("DELETE FROM sessions WHERE token_hash=?")
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        claim_on_writer(&auth, &user, &c.connection_id, 3, &session, Some(&hash), 32)
            .await
            .is_err(),
        "a logged-out session cannot claim"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Opening a terminal records its session row on the D379 writer under the
/// sqlx statement's rules: only for a live login session, never twice for one
/// id, never for a host the account does not own.
#[tokio::test]
async fn opened_session_row_is_recorded_on_the_d379_writer_under_the_sqlx_rules() {
    let (pool, user, _session, auth, dir) = disk_database().await;
    let now = unix_seconds().unwrap();
    let hash = crate::auth::hash("open-token");
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'open',?,?,1)")
        .bind(&hash).bind(&user).bind(now + 3600).bind(now)
        .execute(&pool).await.unwrap();
    let new = |id: u8, token: &'static str, host: Option<Vec<u8>>| {
        crate::terminal_session_record::NewSession {
            session_id: [id; 16],
            user_id: &user,
            host,
            session_token: token,
            now,
        }
    };
    assert!(crate::terminal_session_record::record(&auth, &pool, new(1, "open-token", None)).await);
    let row: (i64, i64) =
        sqlx::query_as("SELECT created_at,last_seen FROM terminal_sessions WHERE id=?")
            .bind([1_u8; 16].as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (now, now));
    assert!(
        !crate::terminal_session_record::record(&auth, &pool, new(1, "open-token", None)).await,
        "a duplicate id is refused"
    );
    assert!(
        !crate::terminal_session_record::record(&auth, &pool, new(2, "other-token", None)).await,
        "no live login session"
    );
    assert!(
        !crate::terminal_session_record::record(
            &auth,
            &pool,
            new(3, "open-token", Some(vec![9; 16]))
        )
        .await,
        "unknown remote host"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions WHERE id IN (?,?)")
        .bind([2_u8; 16].as_slice())
        .bind([3_u8; 16].as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "refused opens leave no row");
    let _ = std::fs::remove_dir_all(dir);
}

/// An exit notice recorded on the D379 writer follows the sqlx rules: it sets
/// the status once, keeps the first closure time, refuses a conflicting status
/// and a stale login session, and a non-exit event records nothing.
#[tokio::test]
async fn terminal_exit_on_the_d379_writer_keeps_the_sqlx_rules() {
    let (pool, user, session, auth, dir) = disk_database().await;
    let now = unix_seconds().unwrap();
    let hash = crate::auth::hash("exit-token");
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'exit',?,?,1)")
        .bind(&hash).bind(&user).bind(now + 3600).bind(now)
        .execute(&pool).await.unwrap();
    let exited = |status: i32, final_seq: u64| {
        serde_json::to_vec(&serde_json::json!({"type":"terminal.exited","session_id":uuid::Uuid::from_bytes(session),"status":status,"final_seq":final_seq})).unwrap()
    };
    let record = |token: &'static str, cursor: u64, event: Vec<u8>| {
        let (auth, pool, user) = (auth.clone(), pool.clone(), user.clone());
        async move {
            crate::terminal_exit::record_on_writer(
                &auth, &pool, &user, token, &session, cursor, &event,
            )
            .await
        }
    };
    assert_eq!(
        record("exit-token", 9, br#"{"type":"terminal.output"}"#.to_vec()).await,
        Ok(false)
    );
    assert_eq!(
        record("exit-token", 9, exited(7, 8)).await,
        Err(()),
        "final_seq must equal the cursor"
    );
    assert_eq!(
        record("other-token", 9, exited(7, 9)).await,
        Err(()),
        "no live login session"
    );
    assert_eq!(record("exit-token", 9, exited(7, 9)).await, Ok(true));
    let first: (Option<i64>, Option<i32>) =
        sqlx::query_as("SELECT closed_at,exit_status FROM terminal_sessions WHERE id=?")
            .bind(session.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(first.0.is_some() && first.1 == Some(7));
    assert_eq!(
        record("exit-token", 9, exited(7, 9)).await,
        Ok(true),
        "a duplicate is accepted"
    );
    assert_eq!(
        record("exit-token", 9, exited(8, 9)).await,
        Err(()),
        "a conflicting status cannot overwrite"
    );
    let again: (Option<i64>, Option<i32>) =
        sqlx::query_as("SELECT closed_at,exit_status FROM terminal_sessions WHERE id=?")
            .bind(session.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(again, first, "the first closure time and status stay");
    let _ = std::fs::remove_dir_all(dir);
}

/// A remote session the host reports gone (#588) is closed once on the D379
/// writer: only a remote row, only under a live login session, a repeat report
/// changes nothing, and the retention prune then removes the ended remote row.
#[tokio::test]
async fn remote_gone_on_the_d379_writer_closes_the_row_once() {
    let (pool, user, _session, auth, dir) = disk_database().await;
    let now = unix_seconds().unwrap();
    let hash = crate::auth::hash("gone-token");
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'gone',?,?,1)")
        .bind(&hash).bind(&user).bind(now + 3600).bind(now)
        .execute(&pool).await.unwrap();
    let host = [9_u8; 16];
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,100)")
        .bind(host.as_slice()).bind(&user).execute(&pool).await.unwrap();
    // Row 7 is the fixture's own session, so this test uses 1 (remote) and 2 (local).
    census_row(&pool, &user, 1, None, Some(host.as_slice())).await;
    census_row(&pool, &user, 2, None, None).await;
    let gone = |token: &'static str, id: u8| {
        let (auth, pool, user) = (auth.clone(), pool.clone(), user.clone());
        async move {
            crate::terminal_remote_gone::record_on_writer(&auth, &pool, &user, token, &[id; 16])
                .await
        }
    };
    assert_eq!(
        gone("other-token", 1).await,
        Ok(false),
        "no live login session: nothing is written"
    );
    assert_eq!(closed_at(&pool, 1).await, None);
    assert_eq!(
        gone("gone-token", 2).await,
        Ok(false),
        "a local row belongs to the census, not to this writer"
    );
    assert_eq!(closed_at(&pool, 2).await, None);
    assert_eq!(
        gone("gone-token", 1).await,
        Ok(true),
        "the first report closes the remote row"
    );
    let first = closed_at(&pool, 1).await;
    assert!(first.is_some());
    assert_eq!(
        gone("gone-token", 1).await,
        Ok(false),
        "a repeat report changes nothing"
    );
    assert_eq!(
        closed_at(&pool, 1).await,
        first,
        "the first closure time stays"
    );
    let pruned = crate::terminal_session_prune::prune_closed_sessions(
        Some(&auth),
        &pool,
        now + 31 * 86_400,
        100,
    )
    .await;
    assert_eq!(
        pruned,
        Ok(1),
        "the retention prune removes the ended remote row"
    );
    assert_eq!(
        closed_at(&pool, 2).await,
        None,
        "the open local row is not pruned"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The D379 branch of `terminal_input_ack::record` (#562): one transaction that
/// advances the writer row and the session row together. It succeeds for the
/// right stream and session; refuses a wrong stream, a wrong session, a
/// backwards offset and a logged-out session; rolls the writer row back when
/// the session row refuses; and leaves the signed legacy column alone for an
/// offset above `i64::MAX`.
#[tokio::test]
async fn input_ack_on_the_d379_writer_is_one_transaction_with_the_sqlx_rules() {
    let (pool, user, session, auth, dir) = disk_database().await;
    let now = unix_seconds().unwrap();
    let token = "ack-token";
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'ack',?,?,1)")
        .bind(crate::auth::hash(token)).bind(&user).bind(now + 3600).bind(now)
        .execute(&pool).await.unwrap();
    let connection = new_connection(&pool, &user, 0, None, None)
        .await
        .unwrap()
        .connection_id;
    claim_on_writer(&auth, &user, &connection, 1, &session, None, 32)
        .await
        .unwrap();
    let ack = |stream: u32, session: [u8; 16], offset: u64, token: &'static str| {
        let (auth, pool, user) = (auth.clone(), pool.clone(), user.clone());
        async move {
            crate::terminal_input_ack::record(
                &auth,
                &pool,
                crate::terminal_input_ack::InputAck {
                    connection_id: &connection,
                    client_stream: stream,
                    session_id: session,
                    in_seq_acked: offset,
                    user_id: &user,
                    session_token: token,
                    now: 4242,
                },
            )
            .await
        }
    };
    // (writer.input_acked, session.input_acked_u64, session.input_acked, session.last_seen)
    let rows = || async {
        let writer: Vec<u8> = sqlx::query_scalar(
            "SELECT input_acked FROM terminal_writers WHERE connection_id=? AND client_stream=1",
        )
        .bind(connection.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        let (unsigned, signed, seen): (Vec<u8>, i64, i64) = sqlx::query_as(
            "SELECT input_acked_u64,input_acked,last_seen FROM terminal_sessions WHERE id=?",
        )
        .bind(session.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        (
            u64::from_be_bytes(writer.try_into().unwrap()),
            u64::from_be_bytes(unsigned.try_into().unwrap()),
            signed,
            seen,
        )
    };
    let before = rows().await;
    assert_eq!(before.0, 0);

    assert!(
        ack(1, session, 100, token).await,
        "the right stream and session succeed"
    );
    assert_eq!(
        rows().await,
        (100, 100, 100, 4242),
        "both rows moved together"
    );

    assert!(
        !ack(3, session, 110, token).await,
        "no writer on that stream"
    );
    assert!(
        !ack(1, [8; 16], 110, token).await,
        "not this writer's session"
    );
    assert!(
        !ack(1, session, 90, token).await,
        "an offset cannot move backwards"
    );
    assert_eq!(
        rows().await,
        (100, 100, 100, 4242),
        "refusals change nothing"
    );

    // The session row refuses (another account owns it) after the writer row
    // matched: the transaction rolls back, so the writer row stays at 100.
    sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES ('other','o','o','O',0,'x')")
        .execute(&pool).await.unwrap();
    sqlx::query("UPDATE terminal_sessions SET user_id='other' WHERE id=?")
        .bind(session.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(!ack(1, session, 120, token).await);
    assert_eq!(
        rows().await.0,
        100,
        "the writer row was rolled back with the session row"
    );
    sqlx::query("UPDATE terminal_sessions SET user_id=? WHERE id=?")
        .bind(&user)
        .bind(session.as_slice())
        .execute(&pool)
        .await
        .unwrap();

    // Above i64::MAX the legacy signed column is left alone (the statement gets -1).
    let high = u64::MAX - 1;
    assert!(ack(1, session, high, token).await);
    assert_eq!(
        rows().await,
        (high, high, 100, 4242),
        "unsigned column moved, signed column kept"
    );

    sqlx::query("DELETE FROM sessions WHERE token_hash=?")
        .bind(crate::auth::hash(token))
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !ack(1, session, u64::MAX, token).await,
        "a logged-out session is refused"
    );
    assert_eq!(rows().await.0, high, "and rolled back");
    let _ = std::fs::remove_dir_all(dir);
}

/// Add a terminal row to the on-disk fixture: `closed_at` set or not, local
/// or on the remote host `host`.
async fn census_row(
    pool: &SqlitePool,
    user: &str,
    id: u8,
    closed_at: Option<i64>,
    host: Option<&[u8]>,
) {
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,closed_at,remote_host_id) VALUES (?,?,1,1,?,?)")
        .bind([id; 16].as_slice()).bind(user).bind(closed_at).bind(host)
        .execute(pool).await.unwrap();
}

/// Each row's `closed_at`, by id byte, for the census tests.
async fn closed_at(pool: &SqlitePool, id: u8) -> Option<i64> {
    sqlx::query_scalar("SELECT closed_at FROM terminal_sessions WHERE id=?")
        .bind([id; 16].as_slice())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A census close on the D379 writer keeps the sqlx rules: an open local row
/// the census does not list closes; a listed row stays open; an earlier
/// closure time is kept; a remote host's row is never touched; and a census
/// that is not available closes nothing (#562).
#[tokio::test]
async fn census_close_on_the_d379_writer_keeps_the_sqlx_rules() {
    let (pool, user, gone, auth, dir) = disk_database().await;
    let host = [9_u8; 16];
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,100)")
        .bind(host.as_slice()).bind(&user).execute(&pool).await.unwrap();
    census_row(&pool, &user, 1, None, None).await;
    census_row(&pool, &user, 2, Some(5), None).await;
    census_row(&pool, &user, 3, None, Some(host.as_slice())).await;
    let (published, inventory) = watch::channel(SessionInventoryState::Pending);
    let close = || crate::terminal_census::close_ended(&auth, &pool, &inventory);
    assert_eq!(close().await, Ok(0), "a pending census closes nothing");
    published.send_replace(SessionInventoryState::Unavailable);
    assert_eq!(close().await, Ok(0), "an unavailable census closes nothing");
    assert_eq!(closed_at(&pool, gone[0]).await, None);
    published.send_replace(SessionInventoryState::Available(Arc::from([[1_u8; 16]])));
    assert_eq!(
        close().await,
        Ok(1),
        "only the unlisted open local row closes"
    );
    assert!(closed_at(&pool, gone[0]).await.is_some());
    assert_eq!(closed_at(&pool, 1).await, None, "a listed row stays open");
    assert_eq!(
        closed_at(&pool, 2).await,
        Some(5),
        "an earlier closure time is kept"
    );
    assert_eq!(
        closed_at(&pool, 3).await,
        None,
        "a remote host's row is not the local census's"
    );
    assert_eq!(
        close().await,
        Ok(0),
        "a second pass finds nothing left to close"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The census close reads the census only once its write transaction holds
/// the lock, not when the write was queued. Here the census changes and a new
/// terminal's row commits while the close waits behind another write, as when
/// a terminal opens during the pass (the leg-B census lists a new shim before
/// its row is inserted). The waiting close must judge the new row against the
/// new census and leave it open, while still closing the row that is really
/// gone (#562).
#[tokio::test]
async fn census_close_on_the_writer_reads_the_census_under_the_write_lock() {
    let (pool, user, gone, auth, dir) = disk_database().await;
    let db = auth.database().unwrap().clone();
    let opened = [42_u8; 16];
    let (published, inventory) = watch::channel(SessionInventoryState::Available(Arc::from([])));
    let (release, gate) = std::sync::mpsc::channel::<()>();
    let (holding, writer_held) = tokio::sync::oneshot::channel::<()>();
    // Hold the writer: this write waits for `release`, then does what an open
    // does in that window: publish the census with the new shim, then insert
    // its row, committed before the queued close runs.
    let open_user = user.clone();
    let held = tokio::spawn({
        let db = db.clone();
        async move {
            db.write(move |tx| {
                holding.send(()).unwrap();
                gate.recv().unwrap();
                published.send_replace(SessionInventoryState::Available(Arc::from([opened])));
                tx.execute(
                    "INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)",
                    infraternal_db::rusqlite::params![opened.as_slice(), open_user],
                )?;
                Ok::<_, infraternal_db::Error>(())
            })
            .await
        }
    });
    writer_held.await.unwrap();
    // Queue the close behind it while the census is still the old, empty one.
    let close = crate::terminal_census::close_ended_on_writer(&db, &inventory);
    tokio::pin!(close);
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(close.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    held.await.unwrap().unwrap();
    assert_eq!(
        close.await,
        Ok(1),
        "only the row that is really gone closes"
    );
    assert!(closed_at(&pool, gone[0]).await.is_some());
    assert_eq!(
        closed_at(&pool, opened[0]).await,
        None,
        "a queued close used the census it saw when queued and closed a new terminal"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// While every open row is still in the census (the open-storm case), a
/// census pass is read-only: it finishes while another connection holds
/// SQLite's write lock, which a write would wait out for the 5 s busy
/// timeout. Once a row is missing, the same pass does write and close it
/// (#562).
#[tokio::test]
async fn census_close_with_nothing_missing_takes_no_write_lock() {
    let (pool, _user, listed, auth, dir) = disk_database().await;
    let (published, inventory) =
        watch::channel(SessionInventoryState::Available(Arc::from([listed])));
    let mut lock = infraternal_plugin_api::storage::begin_immediate(&pool)
        .await
        .unwrap();
    let pass = tokio::time::timeout(
        Duration::from_secs(2),
        crate::terminal_census::close_ended(&auth, &pool, &inventory),
    )
    .await;
    assert_eq!(
        pass,
        Ok(Ok(0)),
        "a pass with nothing to close waited for the write lock"
    );
    sqlx::query("SELECT 1").execute(&mut *lock).await.unwrap();
    drop(lock);
    published.send_replace(SessionInventoryState::Available(Arc::from([])));
    assert_eq!(
        crate::terminal_census::close_ended(&auth, &pool, &inventory).await,
        Ok(1)
    );
    assert!(closed_at(&pool, listed[0]).await.is_some());
    let _ = std::fs::remove_dir_all(dir);
}

/// The startup-notice claim on the D379 writer keeps the sqlx rules: hints
/// that are off consume nothing; of many concurrent claims for one host
/// exactly one wins; a claimed host stays claimed; another host, or a host
/// whose own switch is on while the account's is off, still gets its one
/// notice (#562, D315).
#[tokio::test]
async fn startup_claim_on_the_d379_writer_keeps_the_sqlx_rules() {
    use crate::terminal_startup::{claim, pending, save};
    let (pool, user, _session, auth, dir) = disk_database().await;
    save(&pool, &user, "*", Some(false)).await.unwrap();
    assert_eq!(claim(&auth, &pool, &user, "local").await, Ok(false));
    save(&pool, &user, "*", Some(true)).await.unwrap();
    assert_eq!(
        pending(&pool, &user, "local").await,
        Ok(true),
        "a refused claim consumed the notice"
    );
    let claims =
        futures_util::future::join_all((0..16).map(|_| claim(&auth, &pool, &user, "local"))).await;
    assert_eq!(
        claims.iter().filter(|won| **won == Ok(true)).count(),
        1,
        "exactly one concurrent claim wins: {claims:?}"
    );
    assert!(claims.iter().all(Result::is_ok));
    assert_eq!(pending(&pool, &user, "local").await, Ok(false));
    assert_eq!(claim(&auth, &pool, &user, "local").await, Ok(false));
    assert_eq!(claim(&auth, &pool, &user, "other").await, Ok(true));
    save(&pool, &user, "*", Some(false)).await.unwrap();
    save(&pool, &user, "on-host", Some(true)).await.unwrap();
    assert_eq!(claim(&auth, &pool, &user, "off-host").await, Ok(false));
    assert_eq!(claim(&auth, &pool, &user, "on-host").await, Ok(true));
    let _ = std::fs::remove_dir_all(dir);
}
