//! Verifies that stored rules and machine provenance load into the right grant, and every unknown refuses.
use super::*;
use infraternal_plugin_api::login_access::OrdinaryUids;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

const LINUX: OrdinaryUids = OrdinaryUids::LINUX;

async fn pool_with(migrator: &sqlx::migrate::Migrator) -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(":memory:")
                .foreign_keys(true),
        )
        .await
        .unwrap();
    migrator.run(&pool).await.unwrap();
    pool
}

async fn pool() -> SqlitePool {
    pool_with(&sqlx::migrate!("./migrations")).await
}

async fn person(pool: &SqlitePool, id: &str, owner: bool) {
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,?,?,?,'test')")
        .bind(id)
        .bind(id)
        .bind(id)
        .bind(i64::from(owner))
        .execute(pool)
        .await
        .unwrap();
}

async fn host(pool: &SqlitePool, adder: &str) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,unixepoch())")
        .bind(id.as_bytes().as_slice())
        .bind(adder)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn owner_and_bob() -> SqlitePool {
    let pool = pool().await;
    person(&pool, "kayg", true).await;
    let mut connection = pool.acquire().await.unwrap();
    add_owner_defaults(&mut connection, "kayg").await.unwrap();
    drop(connection);
    person(&pool, "bob", false).await;
    pool
}

#[tokio::test]
async fn owner_starter_rule_allows_any_account_everywhere() {
    let pool = owner_and_bob().await;
    let remote = host(&pool, "kayg").await;
    for target in [None, Some(remote)] {
        let grant = grant(&pool, "kayg", target).await.unwrap();
        assert!(grant.any_account);
        assert!(grant.allows("root", 0, LINUX));
    }
}

#[tokio::test]
async fn others_get_their_own_username_only_on_machines_they_added() {
    let pool = owner_and_bob().await;
    let owners = host(&pool, "kayg").await;
    let bobs = host(&pool, "bob").await;
    let theirs = grant(&pool, "bob", Some(owners)).await.unwrap();
    assert_eq!(theirs, LoginGrant::default());
    let mine = grant(&pool, "bob", Some(bobs)).await.unwrap();
    assert!(mine.allows("bob", 1001, LINUX));
    assert!(!mine.allows("root", 0, LINUX));
    // The server's own host was set up by the owner, not bob.
    assert_eq!(
        grant(&pool, "bob", None).await.unwrap(),
        LoginGrant::default()
    );
}

#[tokio::test]
async fn names_match_marker_extends_own_username() {
    let pool = owner_and_bob().await;
    let owners = host(&pool, "kayg").await;
    sqlx::query("INSERT INTO login_names_match(host_id) VALUES (?)")
        .bind(owners.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        grant(&pool, "bob", Some(owners))
            .await
            .unwrap()
            .allows("bob", 1001, LINUX)
    );
}

#[tokio::test]
async fn named_rule_for_one_host() {
    let pool = owner_and_bob().await;
    let a = host(&pool, "kayg").await;
    let b = host(&pool, "kayg").await;
    sqlx::query("INSERT INTO login_rules(subject,account_kind,account,host_id,created_at) VALUES ('bob','named','deploy',?,0)")
        .bind(a.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        grant(&pool, "bob", Some(a))
            .await
            .unwrap()
            .allows("deploy", 998, LINUX)
    );
    assert!(
        !grant(&pool, "bob", Some(b))
            .await
            .unwrap()
            .allows("deploy", 998, LINUX)
    );
}

#[tokio::test]
async fn removed_or_unknown_host_and_unknown_person_refuse() {
    let pool = owner_and_bob().await;
    let removed = host(&pool, "kayg").await;
    sqlx::query("UPDATE remote_hosts SET revoked_at=unixepoch() WHERE id=?")
        .bind(removed.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        grant(&pool, "kayg", Some(removed)).await.unwrap(),
        LoginGrant::default()
    );
    assert_eq!(
        grant(&pool, "kayg", Some(uuid::Uuid::new_v4()))
            .await
            .unwrap(),
        LoginGrant::default()
    );
    assert_eq!(
        grant(&pool, "nobody", None).await.unwrap(),
        LoginGrant::default()
    );
}

#[tokio::test]
async fn deleting_the_starter_rule_persists_and_leaves_own_username() {
    let pool = owner_and_bob().await;
    let mine = host(&pool, "kayg").await;
    sqlx::query("DELETE FROM login_rules WHERE subject='kayg' AND account_kind='any'")
        .execute(&pool)
        .await
        .unwrap();
    let grant = grant(&pool, "kayg", Some(mine)).await.unwrap();
    assert!(!grant.any_account);
    assert!(grant.allows("kayg", 1000, LINUX));
    assert!(!grant.allows("root", 0, LINUX));
}

/// The login access migration's version, found by name, so renumbering it
/// when another branch's migrations land first needs no test change.
fn login_access_version() -> i64 {
    sqlx::migrate!("./migrations")
        .iter()
        .find(|migration| migration.description == "login access")
        .expect("login access migration")
        .version
}

#[tokio::test]
async fn every_migration_applies_to_a_populated_database_and_seeds_rules_once() {
    let mut before = sqlx::migrate!("./migrations");
    let version = login_access_version();
    before
        .migrations
        .to_mut()
        .retain(|migration| migration.version < version);
    let pool = pool_with(&before).await;
    person(&pool, "kayg", true).await;
    person(&pool, "bob", false).await;
    let host = host(&pool, "kayg").await;
    sqlx::raw_sql(
        "INSERT INTO preferred_accounts(user_id,account) VALUES('kayg','kayg'); \
         INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES('t','kayg','d',unixepoch()+60,unixepoch(),1);",
    )
    .execute(&pool)
    .await
    .unwrap();
    // Every migration, including any that land after this one.
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let rows: Vec<(Option<String>, String)> =
        sqlx::query_as("SELECT subject, account_kind FROM login_rules ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![
            (None, "own".to_owned()),
            (Some("kayg".into()), "any".into())
        ]
    );
    let kept: (String, String, i64) = sqlx::query_as(
        "SELECT u.username, p.account, (SELECT COUNT(*) FROM remote_hosts WHERE owner_id=u.id) \
         FROM users u JOIN preferred_accounts p ON p.user_id=u.id WHERE u.id='kayg'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kept, ("kayg".into(), "kayg".into(), 1));
    assert!(grant(&pool, "kayg", Some(host)).await.unwrap().any_account);
    // Running the migrator again adds nothing.
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM login_rules")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn schema_refuses_rules_that_would_read_wider_than_written() {
    let pool = owner_and_bob().await;
    for (kind, account) in [
        ("named", None),
        ("any", Some("root")),
        ("own", Some("bob")),
        ("everything", None),
        ("named", Some("")),
    ] {
        let inserted = sqlx::query("INSERT INTO login_rules(subject,account_kind,account,host_id,created_at) VALUES ('bob',?,?,NULL,0)")
            .bind(kind)
            .bind(account)
            .execute(&pool)
            .await;
        assert!(inserted.is_err(), "{kind} {account:?} was accepted");
    }
}
