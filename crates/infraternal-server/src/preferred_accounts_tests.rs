//! Verifies durable preference precedence and refusal under ended session/host authority.
use super::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

async fn open(path: &std::path::Path) -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(if path == std::path::Path::new(":memory:") {
            1
        } else {
            2
        })
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}
async fn person(pool: &SqlitePool, user: &str, hash: &str) {
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,?,?,0,'test')")
        .bind(user)
        .bind(user)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'fixture',unixepoch()+3600,unixepoch(),1)").bind(hash).bind(user).execute(pool).await.unwrap();
}
async fn change(
    service: &AccountsPlugin,
    scope: Scope,
    host_id: Option<uuid::Uuid>,
    account: Option<&str>,
) -> Result<Preference, &'static str> {
    service
        .set(
            "alice",
            "alice-token",
            Change {
                scope,
                host_id,
                account: account.map(str::to_owned),
            },
        )
        .await
}
/// Reopening a local store preserves both preference scopes and their precedence.
#[tokio::test]
async fn preferences_survive_reopen_and_host_override_wins() {
    let dir = std::env::temp_dir().join(format!("infraternal-accounts-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("state.sqlite");
    let pool = open(&file).await;
    person(&pool, "alice", "alice-token").await;
    let service = AccountsPlugin::new(pool.clone());
    assert_eq!(
        resolve(&pool, "alice", "alice-token", None).await.unwrap(),
        Some("alice".into())
    );
    change(&service, Scope::Global, None, Some("operator"))
        .await
        .unwrap();
    change(&service, Scope::Host, None, Some("local-user"))
        .await
        .unwrap();
    drop(service);
    pool.close().await;
    let pool = open(&file).await;
    let service = AccountsPlugin::new(pool.clone());
    let preferred = service
        .get("alice", "alice-token", Selection { host_id: None })
        .await
        .unwrap();
    assert_eq!(preferred.account.as_deref(), Some("local-user"));
    assert_eq!(preferred.global_account, "operator");
    assert_eq!(
        change(&service, Scope::Host, None, None)
            .await
            .unwrap()
            .account,
        Some("operator".into())
    );
    assert_eq!(
        change(&service, Scope::Global, None, None)
            .await
            .unwrap()
            .account,
        Some("alice".into())
    );
    pool.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
/// Read and write authority require a live unlocked session and an owned host.
#[tokio::test]
async fn foreign_revoked_hosts_and_ended_sessions_cannot_read_or_change_preferences() {
    let pool = open(std::path::Path::new(":memory:")).await;
    person(&pool, "alice", "alice-token").await;
    person(&pool, "bob", "bob-token").await;
    let host = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'bob','rootful',0,unixepoch())").bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
    let service = AccountsPlugin::new(pool.clone());
    assert!(
        change(&service, Scope::Host, Some(host), Some("root"))
            .await
            .is_err()
    );
    assert!(
        service
            .get(
                "alice",
                "alice-token",
                Selection {
                    host_id: Some(host)
                }
            )
            .await
            .is_err()
    );
    sqlx::query("UPDATE remote_hosts SET owner_id='alice' WHERE id=?")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        change(&service, Scope::Host, Some(host), Some("host-user"))
            .await
            .unwrap()
            .account,
        Some("host-user".into())
    );
    assert_eq!(
        resolve(&pool, "alice", "alice-token", None).await.unwrap(),
        Some("alice".into())
    );
    sqlx::query("UPDATE remote_hosts SET revoked_at=unixepoch() WHERE id=?")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        change(&service, Scope::Host, Some(host), None)
            .await
            .is_err()
    );
    assert!(
        resolve(&pool, "alice", "alice-token", Some(host))
            .await
            .is_err()
    );
    assert!(
        service
            .get("alice", "bob-token", Selection { host_id: None })
            .await
            .is_err()
    );
    sqlx::query("UPDATE sessions SET unlocked=0 WHERE user_id='alice'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        change(&service, Scope::Global, None, Some("root"))
            .await
            .is_err()
    );
    assert!(resolve(&pool, "alice", "alice-token", None).await.is_err());
}
/// Invalid account and scope input leave the current selection intact.
#[tokio::test]
async fn malformed_account_or_scope_never_mutates_storage() {
    let pool = open(std::path::Path::new(":memory:")).await;
    person(&pool, "alice", "alice-token").await;
    let service = AccountsPlugin::new(pool.clone());
    for input in [
        br#"{"scope":"global","account":".user"}"#.as_slice(),
        br#"{"scope":"global","account":"root user"}"#,
        br#"{"scope":"global","account":"root","person":"bob"}"#,
        br#"["global",null,"root"]"#,
    ] {
        assert!(
            accounts::call(&service, "alice", "alice-token", "ssh-accounts.set", input)
                .await
                .is_err()
        );
    }
    assert!(
        change(
            &service,
            Scope::Global,
            Some(uuid::Uuid::new_v4()),
            Some("root")
        )
        .await
        .is_err()
    );
    assert_eq!(
        resolve(&pool, "alice", "alice-token", None).await.unwrap(),
        Some("alice".into())
    );
    assert!(accounts::DESCRIPTOR.validate().is_ok());
}

/// Keep a leading dash in the named preference for the host fallback policy.
#[tokio::test]
async fn leading_dash_preference_persists_for_host_fallback() {
    let pool = open(std::path::Path::new(":memory:")).await;
    person(&pool, "alice", "alice-token").await;
    let service = AccountsPlugin::new(pool.clone());
    accounts::call(
        &service,
        "alice",
        "alice-token",
        "ssh-accounts.set",
        br#"{"scope":"global","account":"-root"}"#,
    )
    .await
    .unwrap();
    assert_eq!(
        resolve(&pool, "alice", "alice-token", None).await.unwrap(),
        Some("-root".into())
    );
    // Resolution remains a host operation: persistence never selects uid zero.
}

#[tokio::test]
async fn queued_writer_rechecks_session_after_lock_wait() {
    let dir = std::env::temp_dir().join(format!("infraternal-accounts-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let pool = open(&dir.join("state.sqlite")).await;
    person(&pool, "alice", "alice-token").await;
    let mut blocker = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let service = AccountsPlugin::new(pool.clone());
    let setter =
        tokio::spawn(async move { change(&service, Scope::Global, None, Some("root")).await });
    tokio::task::yield_now().await;
    sqlx::query("UPDATE sessions SET unlocked=0 WHERE user_id='alice'")
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(setter.await.unwrap().is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM preferred_accounts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    pool.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// Record the execution identity that an enrolled host supplies to its link.
async fn enrolled_host(pool: &SqlitePool, mode: &str, uid: u32) -> uuid::Uuid {
    let host = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'alice',?,?,unixepoch())")
        .bind(host.as_bytes().as_slice()).bind(mode).bind(i64::from(uid)).execute(pool).await.unwrap();
    host
}

/// User-mode hosts use the link's enrollment UID even when both stored
/// preferences differ. An invitation join has no SSH bootstrap row.
#[tokio::test]
async fn rootless_hosts_delegate_login_to_the_enrolled_uid() {
    let pool = open(std::path::Path::new(":memory:")).await;
    person(&pool, "alice", "alice-token").await;
    let joined = enrolled_host(&pool, "rootless", 501).await;
    let added = enrolled_host(&pool, "rootless", 1000).await;
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES (?,'operator@worker')")
        .bind(added.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();

    let service = AccountsPlugin::new(pool.clone());
    for host in [joined, added] {
        assert_eq!(
            resolve(&pool, "alice", "alice-token", Some(host)).await,
            Ok(None)
        );
        change(&service, Scope::Global, None, Some("deploy"))
            .await
            .unwrap();
        let stored = change(&service, Scope::Host, Some(host), Some("other"))
            .await
            .unwrap();
        assert_eq!(stored.account, None);
        assert_eq!(stored.host_account.as_deref(), Some("other"));
        assert_eq!(stored.global_account, "deploy");
        assert_eq!(
            resolve(&pool, "alice", "alice-token", Some(host)).await,
            Ok(None)
        );
        #[cfg(feature = "remote")]
        assert_eq!(resolve_for_key(&pool, "alice", host).await, Ok(None));
        change(&service, Scope::Global, None, None).await.unwrap();
    }
}

/// System-mode hosts keep host preference, global preference, then server username.
#[tokio::test]
async fn rootful_hosts_keep_the_named_preference_order() {
    let pool = open(std::path::Path::new(":memory:")).await;
    person(&pool, "alice", "alice-token").await;
    let host = enrolled_host(&pool, "rootful", 0).await;
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES (?,'root@worker')")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();

    let service = AccountsPlugin::new(pool.clone());
    assert_eq!(
        resolve(&pool, "alice", "alice-token", Some(host)).await,
        Ok(Some("alice".into()))
    );
    change(&service, Scope::Global, None, Some("deploy"))
        .await
        .unwrap();
    assert_eq!(
        resolve(&pool, "alice", "alice-token", Some(host)).await,
        Ok(Some("deploy".into()))
    );
    change(&service, Scope::Host, Some(host), Some("other"))
        .await
        .unwrap();
    assert_eq!(
        resolve(&pool, "alice", "alice-token", Some(host)).await,
        Ok(Some("other".into()))
    );
}
