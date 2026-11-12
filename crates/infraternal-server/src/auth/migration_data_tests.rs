//! Checks immutable migration metadata and compact SQL against the real SQLite engine [19,243].
use super::migration_compat::MIGRATIONS;
use serde_json::Value;
use sqlx::{Column, Row, SqlitePool, TypeInfo, ValueRef};

#[path = "../../build_support/compact_sql.rs"]
mod compact_sql;

async fn database() -> SqlitePool {
    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

#[test]
fn original_migration_metadata_and_checksums_are_unchanged() {
    let original = sqlx::migrate!("./migrations");
    assert_eq!(MIGRATIONS.migrations.len(), original.migrations.len());
    for (before, after) in original.iter().zip(MIGRATIONS.iter()) {
        assert_eq!(before.version, after.version);
        assert_eq!(before.description, after.description);
        assert_eq!(before.migration_type, after.migration_type);
        assert_eq!(before.checksum, after.checksum);
        assert_eq!(before.no_tx, after.no_tx);
    }
}

#[tokio::test]
async fn quoted_text_and_comment_looking_literals_keep_their_values() {
    let pool = database().await;
    for value in [
        "plain",
        "UTF-8: λ界🪟",
        "-- literal",
        "a'b",
        "a\n-- retain this line\nb",
        "a\r\n-- retain CRLF\r\nb",
        "\"[]`",
        "/* quoted */",
    ] {
        let literal = value.replace('\'', "''");
        let sql = format!(
            "-- header\n  SELECT '{literal}' AS result; -- it's a comment with \"quotes\n-- footer\n"
        );
        let actual: String = sqlx::query_scalar(&compact_sql::compact(&sql))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(actual, value);
    }
    for expression in [
        "1 - - 2",
        "3 / 1",
        "length ( 'two' )",
        "coalesce ( NULL , 4 )",
    ] {
        let sql = format!("SELECT {expression}; -- trailing\n");
        let original: i64 = sqlx::query_scalar(&sql).fetch_one(&pool).await.unwrap();
        let compact = compact_sql::compact(&sql);
        assert_eq!(compact_sql::compact(&compact), compact);
        let actual: i64 = sqlx::query_scalar(&compact).fetch_one(&pool).await.unwrap();
        assert_eq!(actual, original);
    }
    for name in ["name", "--name", "a\n-- quoted name\nb", "a'b"] {
        for quote in ['"', '`', '['] {
            let close = if quote == '[' { ']' } else { quote };
            let escaped = name.replace(close, &format!("{close}{close}"));
            let sql =
                format!("/* ' \"\n-- in block\n*/\n SELECT 'value' AS {quote}{escaped}{close};\n");
            let row = sqlx::query(&compact_sql::compact(&sql))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(row.columns()[0].name(), name);
            assert_eq!(row.get::<String, _>(0), "value");
        }
    }
}

async fn pragma(pool: &SqlitePool, statement: &str, name: &str) -> Vec<Vec<Value>> {
    sqlx::query(statement)
        .bind(name)
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|row| {
            (0..row.len())
                .map(|at| {
                    let raw = row.try_get_raw(at).unwrap();
                    if raw.is_null() {
                        Value::Null
                    } else if raw.type_info().name() == "INTEGER" {
                        Value::from(row.get::<i64, _>(at))
                    } else {
                        Value::from(row.get::<String, _>(at))
                    }
                })
                .collect()
        })
        .collect()
}

#[tokio::test]
async fn fresh_schemas_defaults_indexes_and_foreign_keys_match_original_sql() {
    let before = database().await;
    let after = database().await;
    sqlx::migrate!("./migrations").run(&before).await.unwrap();
    MIGRATIONS.run(&after).await.unwrap();
    let objects = "SELECT type,name,tbl_name FROM sqlite_master ORDER BY type,name";
    let a: Vec<(String, String, String)> =
        sqlx::query_as(objects).fetch_all(&before).await.unwrap();
    let b: Vec<(String, String, String)> = sqlx::query_as(objects).fetch_all(&after).await.unwrap();
    assert_eq!(a, b);
    for (kind, name, _) in a {
        let checks: &[&str] = match kind.as_str() {
            "table" => &[
                "SELECT * FROM pragma_table_xinfo(?)",
                "SELECT * FROM pragma_foreign_key_list(?)",
                "SELECT * FROM pragma_index_list(?)",
            ],
            "index" => &["SELECT * FROM pragma_index_xinfo(?)"],
            _ => &[],
        };
        for statement in checks {
            assert_eq!(
                pragma(&before, statement, &name).await,
                pragma(&after, statement, &name).await,
                "{kind} {name}"
            );
        }
    }
}

#[tokio::test]
async fn dev_v29_and_production_v30_upgrade_without_retagging_or_losing_ownership() {
    // The histories share immutable 0001–0029; production already has 0030.
    for version in [29, 30] {
        let pool = database().await;
        let mut original = sqlx::migrate!("./migrations");
        original
            .migrations
            .to_mut()
            .retain(|m| m.version <= version);
        original.run(&pool).await.unwrap();
        sqlx::raw_sql("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES('history-user','history','history','History',1,'synthetic-hash'); INSERT INTO canvas_heads(account,revision,document,initialized) VALUES('history-user',2,'{}',1); INSERT INTO canvas_receipts VALUES('history-user','one','digest',1),('history-user','two','digest',2);")
        .execute(&pool).await.unwrap();
        if version == 30 {
            // Production's trigger maintains historical receipts before this restart.
            let count: i64 = sqlx::query_scalar(
                "SELECT receipt_count FROM canvas_heads WHERE account='history-user'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(count, 2);
        }
        MIGRATIONS.run(&pool).await.unwrap();
        let row: (String, i64) =
            sqlx::query_as("SELECT username,owner FROM users WHERE id='history-user'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row, ("history".into(), 1));
        let count: i64 = sqlx::query_scalar(
            "SELECT receipt_count FROM canvas_heads WHERE account='history-user'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 2);
        let stored: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT version,checksum FROM _sqlx_migrations WHERE version<=? ORDER BY version",
        )
        .bind(version)
        .fetch_all(&pool)
        .await
        .unwrap();
        for ((version, checksum), source) in stored.iter().zip(original.iter()) {
            assert_eq!(*version, source.version);
            assert_eq!(checksum.as_slice(), source.checksum.as_ref());
        }
    }
}

#[tokio::test]
async fn wall_based_recovery_upgrade_ends_old_bearers_without_changing_credentials() {
    let pool = database().await;
    let mut old = sqlx::migrate!("./migrations");
    old.migrations
        .to_mut()
        .retain(|migration| migration.version <= 36);
    old.run(&pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES('recovery-upgrade','owner','owner','Owner',1,'synthetic-verifier'); INSERT INTO recovery VALUES('recovery-upgrade','synthetic-bearer',1,2);")
        .execute(&pool).await.unwrap();
    MIGRATIONS.run(&pool).await.unwrap();
    let requests: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        requests, 0,
        "unprovable wall-clock requests must not gain a fresh lifetime"
    );
    let verifier: String =
        sqlx::query_scalar("SELECT recovery_hash FROM users WHERE id='recovery-upgrade'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(verifier, "synthetic-verifier");
    let elapsed: i64 = sqlx::query_scalar("SELECT elapsed FROM recovery_clock WHERE singleton=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(elapsed, 0);
}

/// D390 (#500): the theme-chosen migration marks every look saved before it as chosen, in the head, the snapshot and the replayed
/// `look.set` events, and leaves accounts without a look (and looks already flagged) alone.
#[tokio::test]
async fn theme_chosen_migration_marks_existing_looks_chosen_and_leaves_the_rest() {
    let pool = database().await;
    let mut old = sqlx::migrate!("./migrations");
    old.migrations
        .to_mut()
        .retain(|migration| migration.version < 20_261_112_033_658);
    old.run(&pool).await.unwrap();
    sqlx::raw_sql(
        "INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES('has-look','a','a','A',1,'h'),('no-look','b','b','B',0,'h'),('flagged','c','c','C',0,'h');
         INSERT INTO canvas_heads(account,revision,document,initialized) VALUES
           ('has-look',3,'{\"revision\":3,\"views\":[],\"look\":{\"v\":1,\"selected\":\"tinted\"}}',1),
           ('no-look',1,'{\"revision\":1,\"views\":[]}',1),
           ('flagged',2,'{\"revision\":2,\"views\":[],\"look\":{\"v\":1,\"themeChosen\":false}}',1);
         INSERT INTO canvas_snapshots(account,revision,document) VALUES('has-look',2,'{\"look\":{\"v\":1,\"selected\":\"solid\"}}');
         INSERT INTO canvas_operations(account,revision,event) VALUES
           ('has-look',3,'{\"intent\":{\"type\":\"look.set\",\"look\":{\"v\":1,\"selected\":\"tinted\"}}}'),
           ('has-look',4,'{\"intent\":{\"type\":\"close\",\"window_id\":\"w\"}}');",
    )
    .execute(&pool)
    .await
    .unwrap();
    MIGRATIONS.run(&pool).await.unwrap();
    let chosen = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(sql)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        chosen("SELECT CAST(json_extract(document,'$.look.themeChosen') AS TEXT) FROM canvas_heads WHERE account='has-look'").await.as_deref(),
        Some("1")
    );
    assert_eq!(
        chosen("SELECT CAST(json_extract(document,'$.look.themeChosen') AS TEXT) FROM canvas_heads WHERE account='no-look'").await,
        None,
        "an account without a look gets none"
    );
    assert_eq!(
        chosen("SELECT CAST(json_extract(document,'$.look.themeChosen') AS TEXT) FROM canvas_heads WHERE account='flagged'").await.as_deref(),
        Some("0"),
        "an explicit answer is never rewritten"
    );
    assert_eq!(
        chosen("SELECT CAST(json_extract(document,'$.look.themeChosen') AS TEXT) FROM canvas_snapshots WHERE account='has-look'").await.as_deref(),
        Some("1")
    );
    assert_eq!(
        chosen("SELECT CAST(json_extract(event,'$.intent.look.themeChosen') AS TEXT) FROM canvas_operations WHERE revision=3").await.as_deref(),
        Some("1")
    );
    assert_eq!(
        chosen("SELECT CAST(json_extract(event,'$.intent.look.themeChosen') AS TEXT) FROM canvas_operations WHERE revision=4").await,
        None,
        "other events are untouched"
    );
}
