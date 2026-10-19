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

#[tokio::test]
async fn old_uuid_mesh_placeholders_upgrade_to_audited_unnamed_labels() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut deployed = sqlx::migrate!("./migrations");
    deployed
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 27);
    deployed.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('owner','Owner',1,'fixture','owner','Owner')")
        .execute(&pool)
        .await
        .unwrap();
    let host = uuid::Uuid::from_u128(1).to_string();
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host,name_source,name_claim) VALUES(1,?,zeroblob(32),?,'placeholder',NULL)")
        .bind(format!("mesh-{host}"))
        .bind(&host)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    let (name, source): (String, String) =
        sqlx::query_as("SELECT name,name_source FROM mesh_nodes WHERE id=1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(name, "unnamed-1");
    assert_eq!(source, "placeholder");
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revision, 1);
    let detail: String = sqlx::query_scalar(
        "SELECT detail_json FROM mesh_audit WHERE action='mesh.node.name' AND resource='1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let detail: serde_json::Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(detail["name"], "unnamed-1");
    assert_eq!(detail["previous"], format!("mesh-{host}"));
    assert!(detail["automatic"].as_bool().unwrap_or(false));
}
