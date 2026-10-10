//! Proves remote identity and session routing extend deployed recovery without version collisions or host retargeting [9][19][64][133], #78.

use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn remote_identity_and_sessions_upgrade_dev_v11_and_remain_idempotent() {
    let migrations = sqlx::migrate!("./migrations");
    let mut versions = std::collections::HashSet::new();
    for migration in migrations.iter() {
        assert!(
            versions.insert(migration.version),
            "duplicate migration version"
        );
    }
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut deployed = sqlx::migrate!("./migrations");
    deployed
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 11);
    deployed.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('legacy','Legacy',1,'fixture','legacy','Legacy')")
        .execute(&pool).await.unwrap();
    let session = uuid::Uuid::from_u128(1);
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES (?,'legacy',100,100)")
        .bind(session.as_bytes().as_slice()).execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO recovery_audit(user_id,event,occurred_at) VALUES ('legacy','start',100)",
    )
    .execute(&pool)
    .await
    .unwrap();
    migrations.run(&pool).await.unwrap();
    migrations.run(&pool).await.unwrap();
    let host: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT remote_host_id FROM terminal_sessions WHERE id=?")
            .bind(session.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        host.is_none(),
        "legacy session must retain its embedded route"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM recovery_audit WHERE user_id='legacy'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'legacy','rootless',1002,100)")
        .bind(uuid::Uuid::from_u128(42).as_bytes().as_slice()).execute(&pool).await.unwrap();
    sqlx::query("UPDATE terminal_sessions SET remote_host_id=? WHERE id=?")
        .bind(uuid::Uuid::from_u128(42).as_bytes().as_slice())
        .bind(session.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE terminal_sessions SET remote_host_id=? WHERE id=?")
            .bind(uuid::Uuid::from_u128(43).as_bytes().as_slice())
            .bind(session.as_bytes().as_slice())
            .execute(&pool)
            .await
            .is_err(),
        "unknown host cannot own an existing session"
    );
    assert!(
        sqlx::query("DELETE FROM remote_hosts WHERE id=?")
            .bind(uuid::Uuid::from_u128(42).as_bytes().as_slice())
            .execute(&pool)
            .await
            .is_err(),
        "host removal must retain the referenced tombstone"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        migrations
            .iter()
            .map(|migration| migration.version)
            .max()
            .unwrap()
    );
}
