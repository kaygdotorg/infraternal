//! Proves deployed schema upgrades preserve remote identity and route data, and
//! that the release migration chain stays contiguous through API key inactivity policy [9][19][64][133][311], #78, #243, #269.

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
async fn canvas_layout_migration_upgrades_production_v27_and_fresh_schema_in_order() {
    let migrations = sqlx::migrate!("./migrations");
    // 0041 and 0042 are held by other branches. The #303 migrations are 0043-0048, and 0049 is
    // the D339 fallback-name migration (#337).
    let expected: Vec<i64> = (1..=40).chain([43, 44, 45, 46, 47, 48, 49]).collect();
    let versions: Vec<i64> = migrations
        .iter()
        .map(|migration| migration.version)
        .collect();
    assert_eq!(
        versions, expected,
        "fresh releases apply 0001 through 0040, the #303 migrations (audit 0043, key lifetime 0044, action tap 0045, read audit 0046, pre-D333 key end 0047, tap action 0048), then 0049"
    );

    let production = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut deployed = sqlx::migrate!("./migrations");
    deployed
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 27);
    deployed.run(&production).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('legacy','Legacy',1,'fixture','legacy','Legacy')")
        .execute(&production)
        .await
        .unwrap();
    // This row exercises the two already-shipped Mesh migrations before 0028 is applied.
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,last_seen,last_rtt_us,dataplane_host,endpoint) VALUES (42,'production-node',zeroblob(32),123,456,'server','https://mesh.example.test')")
        .execute(&production)
        .await
        .unwrap();

    migrations.run(&production).await.unwrap();
    migrations.run(&production).await.unwrap();
    let (version, applied): (i64, i64) =
        sqlx::query_as("SELECT max(version), count(*) FROM _sqlx_migrations")
            .fetch_one(&production)
            .await
            .unwrap();
    assert_eq!((version, applied), (49, 47));
    let mesh: (String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT name, name_source, name_claim FROM mesh_nodes WHERE id=42")
            .fetch_one(&production)
            .await
            .unwrap();
    assert_eq!(mesh, ("production-node".into(), Some("hand".into()), None));
    sqlx::query(
        "INSERT INTO canvas_heads(account,revision,document,initialized) VALUES ('legacy',0,'{}',0)",
    )
    .execute(&production)
    .await
    .unwrap();

    let fresh = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    migrations.run(&fresh).await.unwrap();
    let fresh_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&fresh)
            .await
            .unwrap();
    assert_eq!(fresh_versions, expected);
    for pool in [&production, &fresh] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM terminal_startup_hints")
                .fetch_one(pool)
                .await
                .unwrap(),
            0,
            "startup hints start unclaimed on upgraded and fresh databases"
        );
    }
}

#[tokio::test]
async fn machine_join_migration_preserves_nine_hundred_second_invitations_and_allows_six_hundred() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut deployed = sqlx::migrate!("./migrations");
    deployed
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 32);
    deployed.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('owner','Owner',1,'fixture','owner','Owner')")
        .execute(&pool)
        .await
        .unwrap();
    let existing_host = uuid::Uuid::from_u128(1);
    let machine_host = uuid::Uuid::from_u128(2);
    for host in [existing_host, machine_host] {
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'owner','rootful',0,100)")
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO remote_join_tokens(host_id,mode,digest,issued_at,expires_at) VALUES (?,'rootful',?,100,1000)")
        .bind(existing_host.as_bytes().as_slice())
        .bind([1_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    let old_invitation: (String, i64, i64, Option<i64>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT mode,issued_at,expires_at,consumed_at,expected_key_digest FROM remote_join_tokens WHERE host_id=?",
    )
    .bind(existing_host.as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old_invitation, ("rootful".into(), 100, 1000, None, None));
    sqlx::query("INSERT INTO remote_join_tokens(host_id,mode,digest,issued_at,expires_at,expected_key_digest) VALUES (?,'rootful',?,200,800,?)")
        .bind(machine_host.as_bytes().as_slice())
        .bind([2_u8; 32].as_slice())
        .bind([7_u8; 32].as_slice())
        .execute(&pool)
        .await
        .expect("a machine receipt uses the approved ten-minute expiry");
    let machine_expiry: i64 =
        sqlx::query_scalar("SELECT expires_at FROM remote_join_tokens WHERE host_id=?")
            .bind(machine_host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(machine_expiry, 800);
}

#[tokio::test]
async fn old_uuid_mesh_placeholders_upgrade_to_audited_fallback_names() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut deployed = sqlx::migrate!("./migrations");
    deployed
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 28);
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
    // 0029 labels it `unnamed-1`; 0049 (D339) replaces that with `<os>-<first 6 id characters>`.
    assert_eq!(name, "host-000000");
    assert_eq!(source, "placeholder");
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revision, 2);
    let details: Vec<String> = sqlx::query_scalar(
        "SELECT detail_json FROM mesh_audit WHERE action='mesh.node.name' AND resource='1' ORDER BY revision",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(details.len(), 2);
    let first: serde_json::Value = serde_json::from_str(&details[0]).unwrap();
    assert_eq!(first["name"], "unnamed-1");
    assert_eq!(first["previous"], format!("mesh-{host}"));
    let last: serde_json::Value = serde_json::from_str(&details[1]).unwrap();
    assert_eq!(last["name"], "host-000000");
    assert_eq!(last["previous"], "unnamed-1");
    assert!(last["automatic"].as_bool().unwrap_or(false));
}

#[tokio::test]
async fn hostname_migration_upgrades_release6_copy_without_changing_canvas_or_checksums() {
    let production = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut deployed = sqlx::migrate!("./migrations");
    deployed
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 28);
    deployed.run(&production).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('owner','Owner',1,'fixture','owner','Owner')")
        .execute(&production).await.unwrap();
    let host = uuid::Uuid::from_u128(1);
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'owner','rootless',1000,100)")
        .bind(host.as_bytes().as_slice()).execute(&production).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES (?,'root@192.0.2.10')")
        .bind(host.as_bytes().as_slice())
        .execute(&production)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host,name_source) VALUES(42,?,zeroblob(32),?,'placeholder')")
        .bind(format!("mesh-{host}")).bind(host.to_string()).execute(&production).await.unwrap();
    sqlx::query("INSERT INTO canvas_heads(account,revision,document,initialized) VALUES ('owner',7,'{\"windows\":[]}',1)")
        .execute(&production).await.unwrap();
    let before: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&production)
            .await
            .unwrap();
    assert_eq!(before.len(), 28);
    assert_eq!(deployed.iter().last().unwrap().description, "canvas layout");

    // Validate the original-source migration history with the same engine used at startup.
    let migrations = sqlx::migrate!("./migrations");
    migrations.run(&production).await.unwrap();
    migrations.run(&production).await.unwrap();
    let after: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&production)
            .await
            .unwrap();
    // Dev's 0039 and 0040 (#263) come first. 0041 and 0042 are allocated to other slices. The
    // #303 migrations follow: the API audit table 0043, the approved key lifetime 0044 and the
    // per-action tap 0045 (D333), key read summaries 0046, the pre-D333 key end 0047 and the
    // action a tap is bound to 0048 (D336). Then the D339 fallback names 0049 (#337).
    assert_eq!(after.len(), 47);
    assert_eq!(after[40].0, 43);
    assert_eq!(after[41].0, 44);
    assert_eq!(after[42].0, 45);
    assert_eq!(after[43].0, 46);
    assert_eq!(after[44].0, 47);
    assert_eq!(after[45].0, 48);
    assert_eq!(&after[..28], before.as_slice());
    assert_eq!(after[28].0, 29);
    assert_eq!(after[29].0, 30);
    assert_eq!(after[30].0, 31);
    assert_eq!(after[31].0, 32);
    assert_eq!(after[32].0, 33);
    assert_eq!(after[33].0, 34);
    assert_eq!(after[34].0, 35);
    assert_eq!(after[35].0, 36);
    assert_eq!(after[36].0, 37);
    assert_eq!(after[37].0, 38);
    assert_eq!(after[38].0, 39);
    assert_eq!(after[39].0, 40);
    assert_eq!(after[46].0, 49);
    let canvas: (i64, String, i64) = sqlx::query_as(
        "SELECT revision,document,initialized FROM canvas_heads WHERE account='owner'",
    )
    .fetch_one(&production)
    .await
    .unwrap();
    assert_eq!(canvas, (7, "{\"windows\":[]}".into(), 1));
    let receipts: i64 =
        sqlx::query_scalar("SELECT receipt_count FROM canvas_heads WHERE account='owner'")
            .fetch_one(&production)
            .await
            .unwrap();
    assert_eq!(receipts, 0);
    let name: String = sqlx::query_scalar("SELECT name FROM mesh_nodes WHERE id=42")
        .fetch_one(&production)
        .await
        .unwrap();
    assert_eq!(name, "host-000000");
    let hostname: Option<String> =
        sqlx::query_scalar("SELECT hostname FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&production)
            .await
            .unwrap();
    assert_eq!(hostname, None);
    assert_eq!(
        sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
            .fetch_one(&production)
            .await
            .unwrap(),
        "ok"
    );
    println!(
        "RELEASE7_MIGRATION before=28 after=34 preserved_checksums=28 canvas_revision=7 receipt_count=0 placeholder=host-000000 integrity=ok"
    );
}

/// Existing names reserve every case-insensitive candidate before legacy placeholders receive labels.
#[tokio::test]
async fn hostname_migration_allocates_around_retained_names() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut deployed = sqlx::migrate!("./migrations");
    deployed
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 28);
    deployed.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('owner','Owner',1,'fixture','owner','Owner')")
        .execute(&pool).await.unwrap();
    for (id, name, source) in [
        (
            42_i64,
            format!("mesh-{}", uuid::Uuid::from_u128(42)),
            "placeholder",
        ),
        (43, "UnNaMeD-42".to_owned(), "hand"),
        (44, "unnamed-42-1".to_owned(), "reported"),
        (45, "unnamed-42-2".to_owned(), "record"),
        (
            46,
            format!("mesh-{}", uuid::Uuid::from_u128(46)),
            "placeholder",
        ),
    ] {
        let key = [u8::try_from(id).unwrap(); 32];
        sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host,name_source) VALUES (?,?,?,?,?)")
            .bind(id).bind(name).bind(key.as_slice())
            .bind(uuid::Uuid::from_u128(u128::try_from(id).unwrap()).to_string())
            .bind(source).execute(&pool).await.unwrap();
    }
    sqlx::query("UPDATE mesh_state SET revision=9,node_id_high_water=46")
        .execute(&pool)
        .await
        .unwrap();

    let migrations = sqlx::migrate!("./migrations");
    migrations
        .run(&pool)
        .await
        .expect("retained names must not block the production upgrade");
    migrations.run(&pool).await.unwrap();
    let names: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT id,name,name_source FROM mesh_nodes ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        names,
        [
            (42, "host-000000".to_owned(), "placeholder".to_owned()),
            (43, "UnNaMeD-42".to_owned(), "hand".to_owned()),
            (44, "unnamed-42-1".to_owned(), "reported".to_owned()),
            (45, "unnamed-42-2".to_owned(), "record".to_owned()),
            // Same first six id characters as node 42: ranked by node id, the later one takes `-2`.
            (46, "host-000000-2".to_owned(), "placeholder".to_owned()),
        ]
    );
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revision, 11);
    let audit: Vec<(String, String)> = sqlx::query_as(
        "SELECT resource,detail_json FROM mesh_audit WHERE action='mesh.node.name' ORDER BY resource,revision",
    ).fetch_all(&pool).await.unwrap();
    // Each placeholder is audited twice: once for 0029's label, once for 0049's fallback.
    assert_eq!(audit.len(), 4);
    for ((resource, detail), expected) in
        audit
            .into_iter()
            .zip(["unnamed-42-3", "host-000000", "unnamed-46", "host-000000-2"])
    {
        let detail: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(detail["name"], expected);
        assert_eq!(detail["node_id"].as_i64().unwrap().to_string(), resource);
        assert_eq!(detail["automatic"], true);
    }
    let temporary_tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name='_hostname_labels'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(temporary_tables, 0);
    let leftover: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name='_fallback_labels'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(leftover, 0);
}

/// D339 migration rules: the os word comes from the reported OS, a name a person picked is never touched, and
/// a real hostname that happens to look like the old placeholder stays.
#[tokio::test]
async fn fallback_migration_keeps_hand_names_and_uses_the_reported_os() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut deployed = sqlx::migrate!("./migrations");
    deployed
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 38);
    deployed.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('owner','Owner',1,'fixture','owner','Owner')")
        .execute(&pool).await.unwrap();
    let mac = uuid::Uuid::parse_str("abcdef01-0000-0000-0000-000000000000").unwrap();
    let linux = uuid::Uuid::parse_str("123456ff-0000-0000-0000-000000000000").unwrap();
    for (host, os) in [(mac, "macOS 26.5"), (linux, "Debian GNU/Linux")] {
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'owner','rootless',1000,100)")
            .bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address,os) VALUES (?,'root@192.0.2.10',?)",
        )
        .bind(host.as_bytes().as_slice())
        .bind(os)
        .execute(&pool)
        .await
        .unwrap();
    }
    let hand = uuid::Uuid::from_u128(7);
    for (id, name, source, host) in [
        (1_i64, "unnamed", "placeholder", mac),
        (2, "unnamed-2", "placeholder", linux),
        (3, "unnamed-3", "hand", hand),
        (4, "unnamed-9", "reported", hand),
        (5, "nas", "reported", hand),
    ] {
        sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host,name_source) VALUES (?,?,?,?,?)")
            .bind(id).bind(name).bind([u8::try_from(id).unwrap(); 32].as_slice())
            .bind(format!("{host}-{id}")).bind(source).execute(&pool).await.unwrap();
    }
    // The dataplane host of a real node is the plain UUID; give the two placeholders theirs.
    for (id, host) in [(1_i64, mac), (2, linux)] {
        sqlx::query("UPDATE mesh_nodes SET dataplane_host=? WHERE id=?")
            .bind(host.to_string())
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    let names: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT id,name,name_source FROM mesh_nodes ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        names,
        [
            (1, "macos-abcdef".to_owned(), "placeholder".to_owned()),
            (2, "linux-123456".to_owned(), "placeholder".to_owned()),
            (3, "unnamed-3".to_owned(), "hand".to_owned()),
            (4, "unnamed-9".to_owned(), "reported".to_owned()),
            (5, "nas".to_owned(), "reported".to_owned()),
        ]
    );
}
