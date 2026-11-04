//! Checks the owner-only mesh SSH settings and the snapshot each node receives.
use super::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

async fn fixture() -> MeshSshPlugin {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(":memory:")
                .foreign_keys(true),
        )
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    for (id, owner) in [("kayg", 1), ("bob", 0)] {
        sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,?,?,?,'t')")
            .bind(id)
            .bind(id)
            .bind(id)
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'d',unixepoch()+60,unixepoch(),1)")
            .bind(format!("{id}-token"))
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    let mut connection = pool.acquire().await.unwrap();
    login_access::add_owner_defaults(&mut connection, "kayg")
        .await
        .unwrap();
    drop(connection);
    MeshSshPlugin::new(pool, None, None)
}

#[tokio::test]
async fn only_the_owner_changes_settings() {
    let plugin = fixture().await;
    let input = br#"{"host":"server","enabled":true}"#;
    assert_eq!(
        plugin.call("bob", "bob-token", "mesh-ssh.set", input).await,
        Err(REFUSED)
    );
    assert_eq!(
        plugin
            .call("kayg", "wrong-token", "mesh-ssh.set", input)
            .await,
        Err(REFUSED)
    );
    let changes = plugin.changes.subscribe();
    plugin
        .call("kayg", "kayg-token", "mesh-ssh.set", input)
        .await
        .unwrap();
    assert!(changes.has_changed().unwrap());
    assert!(plugin.enabled("server").await);
    assert!(!plugin.enabled("00000000-0000-0000-0000-000000000001").await);
}

#[tokio::test]
async fn rules_are_listed_added_and_removed() {
    let plugin = fixture().await;
    let added = plugin
        .call(
            "kayg",
            "kayg-token",
            "mesh-ssh.login-rule-add",
            br#"{"subject":"bob","account_kind":"named","account":"deploy","host":"server"}"#,
        )
        .await
        .unwrap();
    let listed = plugin
        .call("kayg", "kayg-token", "mesh-ssh.login-rules", b"{}")
        .await
        .unwrap();
    let rules = listed["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[2]["account"], "deploy");
    assert_eq!(rules[2]["host"], "server");
    assert!(
        login_access::grant(&plugin.pool, "bob", None)
            .await
            .unwrap()
            .accounts
            .contains("deploy")
    );
    let removed = plugin
        .call(
            "kayg",
            "kayg-token",
            "mesh-ssh.login-rule-remove",
            serde_json::to_vec(&json!({ "id": added["id"] }))
                .unwrap()
                .as_slice(),
        )
        .await
        .unwrap();
    assert_eq!(removed["removed"], true);
    // A rule that would read wider than written is refused by the schema.
    assert!(
        plugin
            .call(
                "kayg",
                "kayg-token",
                "mesh-ssh.login-rule-add",
                br#"{"subject":"bob","account_kind":"any","account":"root","host":null}"#,
            )
            .await
            .is_err()
    );
    assert!(
        plugin
            .call(
                "kayg",
                "kayg-token",
                "mesh-ssh.login-rule-add",
                br#"{"subject":"bob","account_kind":"named","account":"x","host":"not-a-host"}"#,
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn snapshot_carries_valid_certificates_and_grants_with_a_rising_sequence() {
    let plugin = fixture().await;
    for (digest, valid_before) in [([1_u8; 32], now() + 3600), ([2; 32], now() - 1)] {
        sqlx::query("INSERT INTO mesh_ssh_certificates(digest,person,host,source_node,source_address,valid_before) VALUES (?, 'kayg', 'server', 7, '10.254.0.7', ?)")
            .bind(digest.as_slice())
            .bind(i64::try_from(valid_before).unwrap())
            .execute(&plugin.pool)
            .await
            .unwrap();
    }
    let first = plugin.snapshot(9, [3; 32], None).await.unwrap();
    let second = plugin.snapshot(9, [3; 32], None).await.unwrap();
    assert!(second.sequence > first.sequence);
    assert_eq!(first.node, 9);
    assert_eq!(first.certificates.len(), 1);
    assert_eq!(first.certificates[0].digest, [1; 32]);
    assert_eq!(
        first.certificates[0].source_address,
        "10.254.0.7".parse::<IpAddr>().unwrap()
    );
    // The owner has the starter rule; bob has nothing on the server's host.
    assert!(first.grants["kayg"].any_account);
    assert!(!first.grants.contains_key("bob"));
}

#[tokio::test]
async fn the_sequence_keeps_rising_across_a_server_restart() {
    // J181 M1: a restarted server must not push below what nodes hold.
    let plugin = fixture().await;
    let before = plugin.snapshot(9, [3; 32], None).await.unwrap().sequence;
    let restarted = MeshSshPlugin::new(plugin.pool.clone(), None, None);
    let after = restarted.snapshot(9, [3; 32], None).await.unwrap().sequence;
    assert!(after > before);
    let clock = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    assert!(after + 60_000 >= clock, "never far below the clock");
}

async fn remote(plugin: &MeshSshPlugin, mode: &str, uid: i64, address: &str) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'kayg',?,?,unixepoch())")
        .bind(id.as_bytes().as_slice())
        .bind(mode)
        .bind(uid)
        .execute(&plugin.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,?)")
        .bind(id.as_bytes().as_slice())
        .bind(address)
        .execute(&plugin.pool)
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn only_the_account_used_to_add_the_machine_acts_as_the_person() {
    // J181 M3.
    let plugin = fixture().await;
    let rootless = remote(&plugin, "rootless", 1002, "kayg@laptop").await;
    let rootful = remote(&plugin, "rootful", 0, "kayg@db-01:2222").await;
    let as_root = remote(&plugin, "rootful", 0, "root@db-02").await;
    let no_user = remote(&plugin, "rootful", 0, "db-03").await;
    assert_eq!(
        plugin.added_with(Some(rootless)).await,
        Some(json!({ "uid": 1002 }))
    );
    assert_eq!(
        plugin.added_with(Some(rootful)).await,
        Some(json!({ "name": "kayg" }))
    );
    assert_eq!(plugin.added_with(Some(as_root)).await, None);
    assert_eq!(plugin.added_with(Some(no_user)).await, None);
    assert_eq!(plugin.added_with(None).await, None);
}

#[tokio::test]
async fn every_issued_certificate_is_recorded_for_audit() {
    // J181 M6.
    let plugin = fixture().await;
    let ca = CertificateAuthority::from_source(&crate::ca::tests::source(true)).unwrap();
    let subject = PublicKey::from_openssh(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGXPXKkPzpN6tM1N1a8nGiE0pBsTzZAOZn3ZK7mFx0z0",
    )
    .unwrap();
    let principals = ["db-01".to_owned()];
    let host = ca
        .issue_ssh_host(&HostRequest {
            subject: &subject,
            principals: &principals,
            now: now(),
            lifetime: 3600,
        })
        .unwrap();
    plugin.audit("host", &host).await.unwrap();
    let row: (String, String) = sqlx::query_as("SELECT kind, principals FROM mesh_ssh_issued")
        .fetch_one(&plugin.pool)
        .await
        .unwrap();
    assert_eq!(row, ("host".into(), r#"["db-01"]"#.into()));
}
