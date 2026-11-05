//! Checks live browser authority immediately before dedicated SSH signing material leaves custody.
use super::*;
use infraternal_plugin_ssh::model::FailureKind;

#[tokio::test]
async fn key_export_rechecks_role_session_and_cold_lock() {
    let _serial = crate::auth::tests::SERIAL.lock().await;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mut setup = String::new();
    auth.bootstrap(now, |banner| setup = banner.lines().nth(1).unwrap().into())
        .await
        .unwrap();
    let (owner, cookie) =
        crate::auth::tests::register_over_http(&crate::auth::router(auth.clone()), &setup).await;
    let token = cookie.split_once('=').unwrap().1.as_bytes().to_vec();
    let vault = crate::ssh_key::test_custody();
    let key = Arc::new(
        StoredSshKey::initialize(&pool, vault.as_ref())
            .await
            .unwrap(),
    );
    let provider = ServerAuthentication {
        auth: Some(auth),
        key: key.clone(),
        owner: owner.clone(),
        session: Some(Secret::new(token)),
        api_key_hash: None,
    };
    assert!(provider.server_key().await.unwrap().is_none());
    key.unlock_from(vault.as_ref()).unwrap();
    assert!(matches!(
        provider.server_key().await.unwrap(),
        Some(Credentials::PrivateKey { .. })
    ));
    sqlx::query("UPDATE users SET owner=0 WHERE id=?")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        provider.server_key().await.err().unwrap().kind,
        FailureKind::Unsupported
    );
    sqlx::query("UPDATE users SET owner=1 WHERE id=?")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    assert!(provider.server_key().await.unwrap().is_some());
    for mutation in [
        "UPDATE sessions SET unlocked=0",
        "UPDATE sessions SET unlocked=1, expires=0",
        "DELETE FROM sessions",
    ] {
        sqlx::query(mutation).execute(&pool).await.unwrap();
        assert_eq!(
            provider.server_key().await.err().unwrap().kind,
            FailureKind::Unsupported
        );
    }
    let absent = ServerAuthentication {
        session: None,
        ..provider
    };
    assert!(absent.server_key().await.unwrap().is_none());
}
