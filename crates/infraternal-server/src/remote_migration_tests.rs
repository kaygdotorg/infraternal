//! Proves deployed schema upgrades preserve remote identity and route data, and
//! that the release migration chain keeps its D347 shape through API key inactivity policy [9][19][64][133][311], #78, #243, #269.

use sqlx::sqlite::SqlitePoolOptions;

/// Check the release history's D347 shape and return its versions in order: the numbered
/// history 0001–0040 is complete, other numbered versions are only the reserved 0041–0049,
/// every newer migration is named by UTC timestamp, and versions strictly ascend.
/// Reserved numbers that have not merged yet are allowed to be absent.
fn release_history(migrations: &sqlx::migrate::Migrator) -> Vec<i64> {
    // Sorted, duplicate-free and containing #303's migrations; then the D347 shape below.
    let versions = migration_versions(migrations);
    assert!(
        (1..=40).all(|version| versions.contains(&version)),
        "numbered history 0001-0040 is complete"
    );
    assert!(
        versions.iter().all(|version| (1..=49).contains(version)
            || (20_000_000_000_000..30_000_000_000_000).contains(version)),
        "new migrations are named by UTC timestamp (D347)"
    );
    versions
}

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

/// The versions in the embedded migration set, checked rather than pinned.
///
/// Parallel branches add migrations: timestamp-named ones since D347, plus the reserved numbered
/// ones that merge late. A pinned list breaks on every such merge. What matters, and what this
/// checks, is that the set is sorted and has no duplicate version, and that the #303 migrations
/// (identified by name, not number) are in it.
fn migration_versions(migrations: &sqlx::migrate::Migrator) -> Vec<i64> {
    let versions: Vec<i64> = migrations
        .iter()
        .map(|migration| migration.version)
        .collect();
    let mut sorted = versions.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        versions, sorted,
        "migrations apply once each, in version order"
    );
    for description in [
        "api action audit",
        "api key approved lifetime",
        "session action tap",
        "api read audit",
        "pre d333 key end",
        "session tap action",
    ] {
        assert!(
            migrations
                .iter()
                .any(|migration| migration.description == description),
            "the #303 migration `{description}` is in the set"
        );
    }
    versions
}

/// The embedded migration history has its D347 shape with #285's migrations in place, and both a production database
/// and a fresh one apply exactly that history.
#[tokio::test]
async fn release_migration_history_is_complete_for_production_and_fresh_schemas() {
    let migrations = sqlx::migrate!("./migrations");
    let versions = release_history(&migrations);
    // #285's four migrations keep the D347 timestamps they were created with: Part B's
    // Mesh and host key rotation first, then Part A's cookie order and certificate recovery.
    let trust = [
        20_261_105_020_355,
        20_261_105_020_356,
        20_261_105_020_605,
        20_261_105_020_607,
    ];
    let present: Vec<i64> = versions
        .iter()
        .copied()
        .filter(|version| trust.contains(version))
        .collect();
    assert_eq!(
        present, trust,
        "trust migrations are present, in creation order"
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
    assert_eq!(
        (version, applied),
        (
            *versions.last().unwrap(),
            i64::try_from(versions.len()).unwrap()
        ),
        "every migration in the set applied exactly once"
    );
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
    assert_eq!(fresh_versions, versions);
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

/// The hostname migration upgrades a release-6 copy without changing its canvas or its migration checksums.
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
    // Every migration in the set applied once, in version order, and the deployed history
    // (its first 28 rows, with their checksums) is unchanged.
    assert_eq!(
        after
            .iter()
            .map(|(version, _)| *version)
            .collect::<Vec<_>>(),
        migration_versions(&migrations)
    );
    assert_eq!(&after[..28], before.as_slice());
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
        "RELEASE7_MIGRATION before=28 applied={} last_version={} preserved_checksums=28 canvas_revision=7 receipt_count=0 placeholder=host-000000 integrity=ok",
        after.len(),
        after
            .last()
            .map(|(version, _)| *version)
            .unwrap_or_default()
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

/// The version of the identity-key migration (#580 P2): certificates record their key algorithm.
const IDENTITY_KEY_ALGORITHM: i64 = 20_261_124_213_330;

/// Opens (creating if needed) a file database with foreign keys on, as the server's pool does.
async fn file_pool(path: &std::path::Path) -> sqlx::SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .unwrap()
}

/// The migrations as a release before #580 P2 shipped them.
fn before_identity_key_algorithm() -> sqlx::migrate::Migrator {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator
        .migrations
        .to_mut()
        .retain(|migration| migration.version < IDENTITY_KEY_ALGORITHM);
    migrator
}

/// Every column of every certificate, in a fixed order, for before/after comparisons.
async fn certificate_rows(
    pool: &sqlx::SqlitePool,
) -> Vec<(
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
    String,
    Option<i64>,
)> {
    sqlx::query_as(
        "SELECT fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,revoked_at,role,execution_uid \
         FROM remote_certificates ORDER BY fingerprint",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Inserts one certificate for host 1 with `key` stored as `algorithm`, or without naming one when `None`.
async fn insert_certificate(
    pool: &sqlx::SqlitePool,
    fingerprint: u8,
    key: &[u8],
    algorithm: Option<&str>,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    let host = uuid::Uuid::from_u128(1);
    let Some(algorithm) = algorithm else {
        // A writer from before #580 names no algorithm and gets the column default.
        return sqlx::query(
            "INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid) \
             VALUES (?,?,zeroblob(32),?,100,604900,1000)",
        )
        .bind([fingerprint; 32].as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(key)
        .execute(pool)
        .await;
    };
    sqlx::query(
        "INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid,key_algorithm) \
         VALUES (?,?,zeroblob(32),?,100,604900,1000,?)",
    )
    .bind([fingerprint; 32].as_slice())
    .bind(host.as_bytes().as_slice())
    .bind(key)
    .bind(algorithm)
    .execute(pool)
    .await
}

/// #580 P2: the certificate rebuild keeps every Ed25519 row byte for byte as
/// `ed25519`, admits a P-256 point only when it is named `p256`, keeps the
/// index and both D376 triggers, makes the key write-once, and a D295 undo to
/// the pre-update `VACUUM INTO` copy gives the previous release its own
/// schema and data back, which then migrates again the same way.
#[tokio::test]
async fn identity_key_algorithm_migration_keeps_ed25519_rows_and_restores_from_a_pre_migration_copy()
 {
    let root = std::env::temp_dir().join(format!("j1176-keyalg-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let live = root.join("infraternal.sqlite");
    let copy = root.join("previous.sqlite");
    let pool = file_pool(&live).await;
    before_identity_key_algorithm().run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('owner','Owner',1,'fixture','owner','Owner')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'owner','rootless',1000,100)")
        .bind(uuid::Uuid::from_u128(1).as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    for (fingerprint, revoked) in [(1_u8, None), (2, Some(150_i64))] {
        sqlx::query(
            "INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,revoked_at,execution_uid) \
             VALUES (?,?,zeroblob(32),?,100,604900,?,1000)",
        )
        .bind([fingerprint; 32].as_slice())
        .bind(uuid::Uuid::from_u128(1).as_bytes().as_slice())
        .bind([fingerprint + 10; 32].as_slice())
        .bind(revoked)
        .execute(&pool)
        .await
        .unwrap();
    }
    let before = certificate_rows(&pool).await;
    // The D295 database copy the update takes before the new release migrates.
    sqlx::query("VACUUM INTO ?")
        .bind(copy.to_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    assert_eq!(certificate_rows(&pool).await, before);
    let algorithms: Vec<String> =
        sqlx::query_scalar("SELECT key_algorithm FROM remote_certificates")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(algorithms, ["ed25519", "ed25519"]);
    let point = [[4_u8].as_slice(), &[7; 64]].concat();
    insert_certificate(&pool, 3, &[3; 32], None)
        .await
        .expect("an existing writer that names no algorithm still stores Ed25519");
    // A P-256 key belongs to a device (#580 P5): its row has no uid and neither has its certificate.
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'owner','device',NULL,100)")
        .bind(uuid::Uuid::from_u128(2).as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid,key_algorithm) \
         VALUES (?,?,zeroblob(32),?,100,604900,NULL,'p256')",
    )
    .bind([4_u8; 32].as_slice())
    .bind(uuid::Uuid::from_u128(2).as_bytes().as_slice())
    .bind(&point)
    .execute(&pool)
    .await
    .expect("a P-256 point named p256 is stored for a device");
    assert!(
        insert_certificate(&pool, 12, &point, Some("p256"))
            .await
            .is_err(),
        "a P-256 point is not stored for a rootless host"
    );
    for (fingerprint, key, algorithm) in [
        (5_u8, point.clone(), None),
        (6, point.clone(), Some("ed25519")),
        (7, vec![4; 32], Some("p256")),
        (8, [[2_u8].as_slice(), &[7; 64]].concat(), Some("p256")),
        (9, vec![3; 33], Some("p256")),
        (10, vec![3; 32], Some("rsa")),
    ] {
        assert!(
            insert_certificate(&pool, fingerprint, &key, algorithm)
                .await
                .is_err(),
            "{fingerprint}: {algorithm:?} with {} bytes was stored",
            key.len()
        );
    }
    assert!(
        sqlx::query("UPDATE remote_certificates SET public_key=? WHERE fingerprint=?")
            .bind([9_u8; 32].as_slice())
            .bind([1_u8; 32].as_slice())
            .execute(&pool)
            .await
            .is_err(),
        "a certificate's key is write-once"
    );
    assert!(
        sqlx::query("UPDATE remote_certificates SET key_algorithm='p256' WHERE fingerprint=?")
            .bind([1_u8; 32].as_slice())
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE remote_certificates SET execution_uid=0 WHERE fingerprint=?")
            .bind([1_u8; 32].as_slice())
            .execute(&pool)
            .await
            .is_err(),
        "the D376 write-once trigger survives the rebuild"
    );
    assert!(
        sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,role,execution_uid) VALUES (?,?,zeroblob(32),zeroblob(32),100,604900,'successor',1000)")
            .bind([11_u8; 32].as_slice())
            .bind(uuid::Uuid::from_u128(1).as_bytes().as_slice())
            .execute(&pool)
            .await
            .is_err(),
        "the D376 successor-is-root trigger survives the rebuild"
    );
    sqlx::query("UPDATE remote_certificates SET revoked_at=200, not_before=101, not_after=604901 WHERE fingerprint=?")
        .bind([1_u8; 32].as_slice())
        .execute(&pool)
        .await
        .expect("revocation and renewal updates still work");
    let index: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='remote_certificates_host'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(index, 1);
    let checks: (String, i64) = sqlx::query_as(
        "SELECT (SELECT integrity_check FROM pragma_integrity_check), (SELECT count(*) FROM pragma_foreign_key_check)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(checks, ("ok".into(), 0));
    pool.close().await;

    // The undo: the previous release opens the copy and finds its own schema and rows.
    let restored = file_pool(&copy).await;
    before_identity_key_algorithm()
        .run(&restored)
        .await
        .unwrap();
    assert_eq!(certificate_rows(&restored).await, before);
    let column: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pragma_table_info('remote_certificates') WHERE name='key_algorithm'",
    )
    .fetch_one(&restored)
    .await
    .unwrap();
    assert_eq!(column, 0, "the restored copy is the pre-migration schema");
    // Updating again from the restored copy migrates it exactly as the first time.
    sqlx::migrate!("./migrations").run(&restored).await.unwrap();
    assert_eq!(certificate_rows(&restored).await, before);
    restored.close().await;
    std::fs::remove_dir_all(root).unwrap();
}

/// The version of the device host mode migration (#580 P5): `remote_hosts` admits `device`, with no uid.
const DEVICE_HOST_MODE: i64 = 20_261_125_055_624;

/// The migrations as a release before #580 P5 shipped them.
fn before_device_host_mode() -> sqlx::migrate::Migrator {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator
        .migrations
        .to_mut()
        .retain(|migration| migration.version < DEVICE_HOST_MODE);
    migrator
}

/// Every column of every host, in a fixed order, for before/after comparisons.
type HostRow = (
    Vec<u8>,
    String,
    String,
    Option<i64>,
    i64,
    Option<i64>,
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
);

/// Every column of a join token, in a fixed order, for before/after comparisons.
type TokenRow = (
    Vec<u8>,
    String,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
    Option<Vec<u8>>,
    String,
);

/// All host rows, ordered by id.
async fn host_rows(pool: &sqlx::SqlitePool) -> Vec<HostRow> {
    sqlx::query_as(
        "SELECT id,owner_id,mode,execution_uid,created_at,revoked_at,hostname,reported_os,device_approved,device_os \
         FROM remote_hosts ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// How many rows each child of `remote_hosts` holds: a rebuild that cascaded would lose them.
async fn child_counts(pool: &sqlx::SqlitePool) -> Vec<(String, i64)> {
    let mut counts = Vec::new();
    for table in [
        "remote_certificates",
        "remote_join_tokens",
        "remote_login_cleanup",
        "remote_host_bootstrap",
        "remote_host_removals",
        "terminal_sessions",
    ] {
        let count: i64 = // The table names are the fixed list above, never input.
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(pool)
            .await
            .unwrap();
        counts.push((table.to_owned(), count));
    }
    counts
}

/// Every table, index, trigger and view by name.
async fn schema_objects(pool: &sqlx::SqlitePool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Insert a host row with the given mode and uid; the result says whether the schema took it.
async fn insert_host(
    pool: &sqlx::SqlitePool,
    id: u128,
    mode: &str,
    uid: Option<i64>,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'owner',?,?,100)")
        .bind(uuid::Uuid::from_u128(id).as_bytes().as_slice())
        .bind(mode)
        .bind(uid)
        .execute(pool)
        .await
}

/// #580 P5: the host-mode rebuild, against a database shaped like a release before it with made-up
/// rows (no real data). It keeps every host, every child row (the fourteen children include
/// CASCADE ones a careless rebuild would empty), every index and trigger, and every column; it
/// admits `device` only with no uid and a P-256 key and the other modes only with theirs; the
/// retirement trigger confirms a device's cleanup at once; and a D295 undo to the pre-update
/// `VACUUM INTO` copy gives the previous release its own schema and rows back, which migrates again.
#[tokio::test]
async fn device_host_mode_migration_keeps_every_row_and_admits_devices_only_without_a_uid() {
    let root = std::env::temp_dir().join(format!("j1202-device-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let live = root.join("infraternal.sqlite");
    let copy = root.join("previous.sqlite");
    let pool = file_pool(&live).await;
    before_device_host_mode().run(&pool).await.unwrap();
    for user in ["owner", "other"] {
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,?,?,'fixture',?,?)")
            .bind(user)
            .bind(user)
            .bind(i64::from(user == "owner"))
            .bind(user)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }
    let (alpha, bravo, charlie) = (1_u128, 2_u128, 3_u128);
    for (id, owner, mode, uid, revoked, name) in [
        (alpha, "owner", "rootless", 1000_i64, None, "alpha"),
        (bravo, "owner", "rootful", 0, Some(500_i64), "bravo"),
        (charlie, "other", "rootless", 1001, None, "charlie"),
    ] {
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at,revoked_at,hostname,reported_os,device_approved,device_os) VALUES (?,?,?,?,100,?,?,'Linux',1,'Linux')")
            .bind(uuid::Uuid::from_u128(id).as_bytes().as_slice())
            .bind(owner)
            .bind(mode)
            .bind(uid)
            .bind(revoked)
            .bind(name)
            .execute(&pool)
            .await
            .unwrap();
    }
    let host_id = |id: u128| uuid::Uuid::from_u128(id);
    for (fingerprint, id, uid) in [(1_u8, alpha, 1000_i64), (2, bravo, 0), (3, charlie, 1001)] {
        sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid) VALUES (?,?,zeroblob(32),?,100,604900,?)")
            .bind([fingerprint; 32].as_slice())
            .bind(host_id(id).as_bytes().as_slice())
            .bind([fingerprint + 10; 32].as_slice())
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO remote_join_tokens(host_id,mode,digest,issued_at,expires_at,expected_key_digest) VALUES (?,'rootless',?,100,1000,?)")
        .bind(host_id(alpha).as_bytes().as_slice())
        .bind([5_u8; 32].as_slice())
        .bind([6_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO remote_login_cleanup(host_id,person_id,confirmed) VALUES (?,'owner',1)",
    )
    .bind(host_id(bravo).as_bytes().as_slice())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES (?,'root@alpha.example',NULL)")
        .bind(host_id(alpha).as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES (?,'owner',400,1,'pending')")
        .bind(host_id(bravo).as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) VALUES (?,'owner',100,100,?)")
        .bind([7_u8; 16].as_slice())
        .bind(host_id(alpha).as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let (hosts, counts, objects) = (
        host_rows(&pool).await,
        child_counts(&pool).await,
        schema_objects(&pool).await,
    );
    let tokens_before: Vec<TokenRow> =
        sqlx::query_as("SELECT host_id,mode,digest,issued_at,expires_at,consumed_at,expected_key_digest,key_algorithm FROM remote_join_tokens")
            .fetch_all(&pool)
            .await
            .unwrap();
    let columns = "SELECT name FROM pragma_table_info('remote_hosts') ORDER BY cid";
    let columns_before: Vec<String> = sqlx::query_scalar(columns).fetch_all(&pool).await.unwrap();
    // The D295 database copy the update takes before the new release migrates.
    sqlx::query("VACUUM INTO ?")
        .bind(copy.to_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    assert_eq!(
        host_rows(&pool).await,
        hosts,
        "every host row, every column"
    );
    assert_eq!(child_counts(&pool).await, counts, "no child row was lost");
    let tokens_after: Vec<TokenRow> =
        sqlx::query_as("SELECT host_id,mode,digest,issued_at,expires_at,consumed_at,expected_key_digest,key_algorithm FROM remote_join_tokens")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(tokens_after, tokens_before);
    assert_eq!(
        sqlx::query_scalar::<_, String>(columns)
            .fetch_all(&pool)
            .await
            .unwrap(),
        columns_before,
        "the same columns in the same order"
    );
    let mut expected = objects;
    expected.push((
        "trigger".into(),
        "remote_certificates_key_matches_host_mode".into(),
    ));
    expected.sort();
    assert_eq!(
        schema_objects(&pool).await,
        expected,
        "every index and trigger came back, and one trigger is new"
    );
    let uid_required: i64 = sqlx::query_scalar(
        "SELECT \"notnull\" FROM pragma_table_info('remote_hosts') WHERE name='execution_uid'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        uid_required, 0,
        "only a device has no uid, and a CHECK says so"
    );

    // What the schema takes now: a device has no uid and every other host keeps its own rule.
    insert_host(&pool, 100, "device", None)
        .await
        .expect("a device has no uid");
    for (id, mode, uid) in [
        (101_u128, "device", Some(0_i64)),
        (102, "device", Some(1000)),
        (103, "rootless", None),
        (104, "rootful", None),
        (105, "rootful", Some(5)),
        (106, "rootless", Some(0)),
        (107, "phone", None),
    ] {
        assert!(
            insert_host(&pool, id, mode, uid).await.is_err(),
            "{mode} with uid {uid:?} was stored"
        );
    }
    // Invitations: a device holds a P-256 one and no host does.
    let token = |id: u128, mode: &'static str, algorithm: &'static str, seed: u8| {
        let pool = pool.clone();
        async move {
            sqlx::query("INSERT INTO remote_join_tokens(host_id,mode,digest,issued_at,expires_at,expected_key_digest,key_algorithm) VALUES (?,?,?,100,700,?,?)")
                .bind(uuid::Uuid::from_u128(id).as_bytes().as_slice())
                .bind(mode)
                .bind([seed; 32].as_slice())
                .bind([seed; 32].as_slice())
                .bind(algorithm)
                .execute(&pool)
                .await
        }
    };
    assert!(token(100, "device", "ed25519", 40).await.is_err());
    assert!(token(100, "rootless", "p256", 41).await.is_err());
    sqlx::query("DELETE FROM remote_join_tokens WHERE host_id=?")
        .bind(host_id(alpha).as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(token(alpha, "rootless", "p256", 43).await.is_err());
    token(100, "device", "p256", 44)
        .await
        .expect("a device invitation names P-256");
    // Certificates: the same pairing, whichever writer inserts them.
    let point = [[4_u8].as_slice(), &[9; 64]].concat();
    let certificate = |id: u128,
                       algorithm: &'static str,
                       key: Vec<u8>,
                       uid: Option<i64>,
                       seed: u8| {
        let pool = pool.clone();
        async move {
            sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid,key_algorithm) VALUES (?,?,zeroblob(32),?,100,604900,?,?)")
                .bind([seed; 32].as_slice())
                .bind(uuid::Uuid::from_u128(id).as_bytes().as_slice())
                .bind(key)
                .bind(uid)
                .bind(algorithm)
                .execute(&pool)
                .await
        }
    };
    assert!(
        certificate(100, "ed25519", vec![9; 32], None, 50)
            .await
            .is_err(),
        "a device holds no Ed25519 key"
    );
    assert!(
        certificate(alpha, "p256", point.clone(), Some(1000), 51)
            .await
            .is_err(),
        "no host holds a P-256 key"
    );
    assert!(
        certificate(bravo, "p256", point.clone(), Some(0), 52)
            .await
            .is_err()
    );
    certificate(100, "p256", point.clone(), None, 53)
        .await
        .expect("a device certificate");
    // A host's mode and uid are write-once; a device has no way to become a host or gain a uid.
    for (statement, id) in [
        ("UPDATE remote_hosts SET mode='rootless' WHERE id=?", 100),
        (
            "UPDATE remote_hosts SET mode='rootful', execution_uid=0 WHERE id=?",
            100,
        ),
        ("UPDATE remote_hosts SET execution_uid=7 WHERE id=?", 100),
        (
            "UPDATE remote_hosts SET mode='device', execution_uid=NULL WHERE id=?",
            alpha,
        ),
    ] {
        assert!(
            sqlx::query(statement)
                .bind(host_id(id).as_bytes().as_slice())
                .execute(&pool)
                .await
                .is_err(),
            "{statement} was applied to {id}"
        );
    }
    // Retirement: a device's login cleanup is born confirmed (no agent can confirm it), a host's is
    // not, and the device's mesh node and grants go with it as for any host.
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host) VALUES (1,'phone',?,?)")
        .bind([8_u8; 32].as_slice())
        .bind(host_id(100).to_string())
        .execute(&pool)
        .await
        .unwrap();
    for id in [100_u128, alpha] {
        sqlx::query("UPDATE remote_hosts SET revoked_at=900 WHERE id=?")
            .bind(host_id(id).as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
    let cleanup = |id: u128| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT confirmed FROM remote_login_cleanup WHERE host_id=?",
            )
            .bind(host_id(id).as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert!(cleanup(100).await, "a device has nothing to uninstall");
    assert!(
        !cleanup(alpha).await,
        "a host still waits for its agent's receipt"
    );
    let nodes: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_nodes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(nodes, 0, "the device's mesh node was retired with it");
    let checks: (String, i64) = sqlx::query_as(
        "SELECT (SELECT integrity_check FROM pragma_integrity_check), (SELECT count(*) FROM pragma_foreign_key_check)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(checks, ("ok".into(), 0));
    pool.close().await;

    // The undo: the previous release opens the copy and finds its own schema and rows.
    let restored = file_pool(&copy).await;
    before_device_host_mode().run(&restored).await.unwrap();
    assert_eq!(host_rows(&restored).await, hosts);
    assert_eq!(child_counts(&restored).await, counts);
    let uid_required: i64 = sqlx::query_scalar(
        "SELECT \"notnull\" FROM pragma_table_info('remote_hosts') WHERE name='execution_uid'",
    )
    .fetch_one(&restored)
    .await
    .unwrap();
    assert_eq!(
        uid_required, 1,
        "the restored copy is the pre-migration schema"
    );
    sqlx::migrate!("./migrations").run(&restored).await.unwrap();
    assert_eq!(host_rows(&restored).await, hosts);
    assert_eq!(child_counts(&restored).await, counts);
    restored.close().await;
    std::fs::remove_dir_all(root).unwrap();
}

/// A migrated-up-to-the-previous-release in-memory database with an owner and two hosts: host 1 is
/// rootful, host 2 is rootless. Used by the tests of what the device migration does to rows that the
/// stricter rules would refuse.
async fn before_device_host_mode_with_hosts() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    before_device_host_mode().run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('owner','Owner',1,'fixture','owner','Owner')")
        .execute(&pool)
        .await
        .unwrap();
    insert_host(&pool, 1, "rootful", Some(0)).await.unwrap();
    insert_host(&pool, 2, "rootless", Some(1000)).await.unwrap();
    pool
}

/// Insert a join token for host `id` with the given mode and algorithm (the digest is `seed`).
async fn insert_token(pool: &sqlx::SqlitePool, id: u128, mode: &str, algorithm: &str, seed: u8) {
    sqlx::query("INSERT INTO remote_join_tokens(host_id,mode,digest,issued_at,expires_at,expected_key_digest,key_algorithm) VALUES (?,?,?,100,700,?,?)")
        .bind(uuid::Uuid::from_u128(id).as_bytes().as_slice())
        .bind(mode)
        .bind([seed; 32].as_slice())
        .bind([seed; 32].as_slice())
        .bind(algorithm)
        .execute(pool)
        .await
        .unwrap();
}

/// A P-256 invitation for a host that is not a device can never be redeemed, and the stricter
/// `remote_join_tokens` rule would refuse it, so the migration deletes it and keeps the others.
#[tokio::test]
async fn device_host_mode_migration_deletes_p256_invitations_of_non_device_hosts() {
    let pool = before_device_host_mode_with_hosts().await;
    insert_token(&pool, 1, "rootful", "p256", 7).await;
    insert_token(&pool, 2, "rootless", "ed25519", 8).await;
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let left: Vec<(Vec<u8>, String)> =
        sqlx::query_as("SELECT host_id, key_algorithm FROM remote_join_tokens")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        left,
        vec![(uuid::Uuid::from_u128(2).as_bytes().to_vec(), "ed25519".to_owned())]
    );
    let checks: (String, i64) = sqlx::query_as(
        "SELECT (SELECT integrity_check FROM pragma_integrity_check), (SELECT count(*) FROM pragma_foreign_key_check)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(checks, ("ok".into(), 0));
}

/// A P-256 certificate on a host that is not a device cannot come from any writer of the server.
/// The migration refuses to continue (it deletes no identity), rolls back whole, and leaves the
/// database as the previous release had it, including the invitation it would have deleted.
#[tokio::test]
async fn device_host_mode_migration_aborts_on_a_p256_certificate_of_a_non_device_host() {
    let pool = before_device_host_mode_with_hosts().await;
    insert_token(&pool, 1, "rootful", "p256", 7).await;
    let point = [[4_u8].as_slice(), &[9; 64]].concat();
    sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid,key_algorithm) VALUES (?,?,zeroblob(32),?,100,604900,0,'p256')")
        .bind([5_u8; 32].as_slice())
        .bind(uuid::Uuid::from_u128(1).as_bytes().as_slice())
        .bind(&point)
        .execute(&pool)
        .await
        .unwrap();
    let hosts = host_rows(&pool).await;
    let error = sqlx::migrate!("./migrations").run(&pool).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no_p256_certificate_on_a_non_device_host"),
        "{error}"
    );
    assert_eq!(host_rows(&pool).await, hosts);
    let (tokens, uid_required, recorded): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM remote_join_tokens), \
                (SELECT \"notnull\" FROM pragma_table_info('remote_hosts') WHERE name='execution_uid'), \
                (SELECT count(*) FROM _sqlx_migrations WHERE version=?)",
    )
    .bind(DEVICE_HOST_MODE)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (tokens, uid_required, recorded),
        (1, 1, 0),
        "rolled back: the invitation stays, the schema is the old one, the version is unrecorded"
    );
}
