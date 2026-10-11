//! Uses the migrated database and real passkey session to verify durable unsolicited exits (#87).
use super::*;

#[tokio::test]
async fn terminal_exit_persists_once_under_current_ownership_and_session() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let session = [7u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let event = serde_json::to_vec(&serde_json::json!({"type":"terminal.exited", "session_id":uuid::Uuid::from_bytes(session), "status":7,"final_seq":12})).unwrap();
    crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &session, 12, &event)
        .await
        .unwrap();
    let first: (Option<i64>, Option<i32>) =
        sqlx::query_as("SELECT closed_at,exit_status FROM terminal_sessions WHERE id=?")
            .bind(session.as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert!(
        first.0.is_some(),
        "received exit must close the persistent session without further input"
    );
    assert_eq!(first.1, Some(7));
    crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &session, 12, &event)
        .await
        .unwrap();
    let second: (Option<i64>, Option<i32>) =
        sqlx::query_as("SELECT closed_at,exit_status FROM terminal_sessions WHERE id=?")
            .bind(session.as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(first, second);
    assert!(
        crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &session, 11, &event)
            .await
            .is_err()
    );
    assert!(
        crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &[8; 16], 12, &event)
            .await
            .is_err()
    );
    f.auth.logout(&f.session).await.unwrap();
    assert!(
        crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &session, 12, &event)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn retired_exit_preserves_status_without_claiming_final_output_delivery() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let session = [9u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let event = serde_json::to_vec(&serde_json::json!({"type":"terminal.exited", "session_id":uuid::Uuid::from_bytes(session), "status":7,"final_seq":42,"retired":true})).unwrap();
    crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &session, 0, &event)
        .await
        .unwrap();
    let status: Option<i32> =
        sqlx::query_scalar("SELECT exit_status FROM terminal_sessions WHERE id=?")
            .bind(session.as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(status, Some(7));
    assert!(
        crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &session, 43, &event)
            .await
            .is_err()
    );
    assert!(
        crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &[8; 16], 0, &event)
            .await
            .is_err()
    );
    f.auth.logout(&f.session).await.unwrap();
    assert!(
        crate::terminal_exit::record(&f.auth.pool, &f.user, &f.session, &session, 0, &event)
            .await
            .is_err()
    );
}
