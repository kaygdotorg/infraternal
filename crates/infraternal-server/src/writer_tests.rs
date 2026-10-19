//! Durable per-device input authority; a second writer never inherits another device's Ack.
use super::*;

#[path = "websocket_authority_tests.rs"]
mod authority_watchdog;

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
