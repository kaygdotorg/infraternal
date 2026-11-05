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
        "alice"
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
    assert_eq!(preferred.account, "local-user");
    assert_eq!(preferred.global_account, "operator");
    assert_eq!(
        change(&service, Scope::Host, None, None)
            .await
            .unwrap()
            .account,
        "operator"
    );
    assert_eq!(
        change(&service, Scope::Global, None, None)
            .await
            .unwrap()
            .account,
        "alice"
    );
    pool.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
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
        "host-user"
    );
    assert_eq!(
        resolve(&pool, "alice", "alice-token", None).await.unwrap(),
        "alice"
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
        "alice"
    );
    assert!(accounts::DESCRIPTOR.validate().is_ok());
}

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
        "-root"
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

/// Adds one host owned by `user` the way add-host records it: its mode and the SSH
/// address it was added with.
async fn added_host(pool: &SqlitePool, user: &str, mode: &str, address: &str) -> uuid::Uuid {
    let host = uuid::Uuid::new_v4();
    // The schema requires uid 0 for a rootful host and a non-zero uid otherwise.
    let uid = if mode == "rootful" { 0 } else { 1000 };
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,?,?,?,unixepoch())")
        .bind(host.as_bytes().as_slice()).bind(user).bind(mode).bind(uid).execute(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES (?,?,NULL)",
    )
    .bind(host.as_bytes().as_slice())
    .bind(address)
    .execute(pool)
    .await
    .unwrap();
    host
}

/// #305 F-A: production's owner is named "K Gopal Krishna" and added `kayg@code`
/// rootless. A rootless infraternal agent can open only its own account, so with no
/// stored preference the login must be the SSH account the host was added with, not
/// the infraternal username; otherwise every such add stops at its login check.
#[tokio::test]
async fn a_rootless_host_with_no_preference_logs_in_as_the_account_it_was_added_with() {
    let pool = open(std::path::Path::new(":memory:")).await;
    person(&pool, "alice", "alice-token").await;
    sqlx::query("UPDATE users SET username='K Gopal Krishna' WHERE id='alice'")
        .execute(&pool)
        .await
        .unwrap();
    let rootless = added_host(&pool, "alice", "rootless", "kayg@code.vpn.kayg.org").await;
    assert_eq!(
        resolve(&pool, "alice", "alice-token", Some(rootless))
            .await
            .unwrap(),
        "kayg"
    );
    #[cfg(feature = "remote")]
    assert_eq!(
        resolve_for_key(&pool, "alice", rootless).await.unwrap(),
        "kayg"
    );
    // An explicit global choice cannot work on a rootless host either; it still
    // never replaces the only account that host's infraternal agent can open.
    let service = AccountsPlugin::new(pool.clone());
    change(&service, Scope::Global, None, Some("deploy"))
        .await
        .unwrap();
    assert_eq!(
        resolve(&pool, "alice", "alice-token", Some(rootless))
            .await
            .unwrap(),
        "kayg"
    );
    // A rootful host honours the explicit global choice; without one it keeps the
    // infraternal username, even when it was added as root (D336).
    let rootful = added_host(&pool, "alice", "rootful", "root@db.example:2222").await;
    assert_eq!(
        resolve(&pool, "alice", "alice-token", Some(rootful))
            .await
            .unwrap(),
        "deploy"
    );
    change(&service, Scope::Global, None, None).await.unwrap();
    assert_eq!(
        resolve(&pool, "alice", "alice-token", Some(rootful))
            .await
            .unwrap(),
        "K Gopal Krishna",
        "a rootful host must not default to the account it was added with"
    );
    // An explicit per-host choice always wins; with no host at all the infraternal
    // username stays the fallback.
    change(&service, Scope::Host, Some(rootless), Some("other"))
        .await
        .unwrap();
    assert_eq!(
        resolve(&pool, "alice", "alice-token", Some(rootless))
            .await
            .unwrap(),
        "other"
    );
    assert_eq!(
        resolve(&pool, "alice", "alice-token", None).await.unwrap(),
        "K Gopal Krishna"
    );
}
