//! Checks historical recovery availability and queued edits against real SQLite (#243, D183, D248).
#![cfg(feature = "canvas")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_canvas::model::Document;
use infraternal_server::canvas_store::Store;
use serde_json::{Value, json};

async fn historical(columns: usize) -> (Store, sqlx::SqlitePool) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT);")
        .execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0028_canvas_layout.sql"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../migrations/0030_canvas_receipt_count.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let base = json!({"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":(0..columns).map(|i| json!({"id":format!("c{i}"),"weight":1,"windows":[{"id":format!("w{i}"),"target":{"type":"logs","host":format!("host{i}")}}]})).collect::<Vec<_>>()}});
    let recovery = json!({"id":"recovery","kind":"console","name":"Recovered: Console","cell":{"x":0,"y":4},"layout":{"type":"tiled","columns":[{"id":"recovered-column","weight":2,"windows":[{"id":"recovered-window","height":0.7,"target":{"type":"logs","host":"unique"}}]}]}});
    let doc = Document(
        json!({"format":"infraternal.canvas","version":1,"revision":2,"views":[base,recovery]}),
    );
    assert!(
        doc.valid(),
        "historical input satisfies the production contract"
    );
    sqlx::query(
        "INSERT INTO canvas_heads(account,revision,document,initialized) VALUES('a',2,?,1)",
    )
    .bind(serde_json::to_string(&doc).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    (Store::new(pool.clone()), pool)
}

#[tokio::test]
async fn recovery_at_column_capacity_keeps_the_account_readable() {
    let (store, pool) = historical(64).await;
    let result = store.events("a", Some(2)).await;
    assert!(
        result.is_ok(),
        "a valid 65-window account must remain readable when automatic folding exceeds one view's 64-column bound"
    );
    // A safe fallback may keep revision 2 and return no tail events to an already-current device.
    let events = store.events("a", None).await.unwrap();
    let doc = Document(events[0]["document"].clone());
    assert_eq!(
        doc.windows().count(),
        65,
        "repair cannot discard a unique target to fit"
    );
    let actual: std::collections::BTreeSet<_> = doc
        .windows()
        .map(|window| window["target"]["host"].as_str().unwrap().to_owned())
        .collect();
    let mut expected: std::collections::BTreeSet<_> = (0..64).map(|i| format!("host{i}")).collect();
    expected.insert("unique".to_owned());
    assert_eq!(
        actual, expected,
        "all distinct targets must survive any safe fallback"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM canvas_heads")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(doc.revision(), 2, "a deferred repair is not an edit");
    assert_eq!(
        store.events("a", Some(2)).await.unwrap(),
        Vec::<Value>::new()
    );
    let input = serde_json::to_vec(&json!({"op_id":"resize-at-capacity","base_revision":2,"intent":{"type":"resize","window_id":"w0","height":0.8}})).unwrap();
    assert_eq!(store.apply("a", &input).await.unwrap(), 3);
    let edited = store.events("a", None).await.unwrap();
    let edited = Document(edited[0]["document"].clone());
    assert!(edited.valid());
    assert_eq!(edited.revision(), 3);
    assert_eq!(edited.windows().count(), 65);
    assert_eq!(
        edited.windows().find(|w| w["id"] == "w0").unwrap()["height"],
        0.8
    );
    assert_eq!(
        store.events("a", Some(3)).await.unwrap(),
        Vec::<Value>::new()
    );
}

#[tokio::test]
async fn queued_close_of_unique_recovered_window_survives_repair() {
    let (store, _) = historical(1).await;
    // A device drew revision 2 and queued this close before another load repairs it.
    let input = serde_json::to_vec(&json!({"op_id":"close-recovered","base_revision":2,"intent":{"type":"close","window_id":"recovered-window"}})).unwrap();
    assert_eq!(store.apply("a", &input).await.unwrap(), 4);
    let snapshot = store.events("a", None).await.unwrap();
    let doc = Document(snapshot[0]["document"].clone());
    assert!(
        !doc.windows().any(|w| w["target"]["host"] == "unique"),
        "successful close was acknowledged but repair gave its target a new ID and left it open"
    );
    assert_eq!(store.apply("a", &input).await.unwrap(), 4);
    assert_eq!(store.events("a", None).await.unwrap()[0]["document"], doc.0);
}

#[tokio::test]
async fn queued_resize_keeps_its_membership_after_a_separate_read_repair() {
    let (store, pool) = historical(1).await;
    let peer = Store::new(pool);
    let repaired = peer.events("a", Some(2)).await.unwrap();
    let doc = Document(repaired[0]["document"].clone());
    assert_eq!(doc.revision(), 3);
    assert_eq!(
        doc.windows()
            .find(|w| w["target"]["host"] == "unique")
            .unwrap()["id"],
        "recovered-window"
    );
    let input = serde_json::to_vec(&json!({"op_id":"resize-recovered","base_revision":2,"intent":{"type":"resize","window_id":"recovered-window","height":0.9}})).unwrap();
    assert_eq!(store.apply("a", &input).await.unwrap(), 4);
    let snapshot = store.events("a", None).await.unwrap();
    let doc = Document(snapshot[0]["document"].clone());
    assert_eq!(
        doc.windows()
            .find(|w| w["id"] == "recovered-window")
            .unwrap()["height"],
        0.9
    );
    assert_eq!(store.apply("a", &input).await.unwrap(), 4);
    assert_eq!(peer.events("a", None).await.unwrap()[0]["document"], doc.0);
}

#[tokio::test]
async fn independent_loads_and_base_edit_repair_exactly_once() {
    let (store, pool) = historical(1).await;
    let peer = Store::new(pool.clone());
    let writer = Store::new(pool.clone());
    let input = serde_json::to_vec(&json!({"op_id":"resize-base","base_revision":2,"intent":{"type":"resize","window_id":"w0","height":0.8}})).unwrap();
    let (left, right, edit) = tokio::join!(
        store.events("a", Some(2)),
        peer.events("a", Some(2)),
        writer.apply("a", &input)
    );
    assert!(left.is_ok());
    assert!(right.is_ok());
    assert_eq!(edit.unwrap(), 4);
    let final_events = store.events("a", None).await.unwrap();
    let doc = Document(final_events[0]["document"].clone());
    assert_eq!(doc.revision(), 4);
    assert_eq!(doc.windows().count(), 2);
    assert_eq!(doc.0["views"].as_array().unwrap().len(), 1);
    assert_eq!(
        doc.windows().find(|w| w["id"] == "w0").unwrap()["height"],
        0.8
    );
    let raw: String = sqlx::query_scalar("SELECT document FROM canvas_heads WHERE account='a'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&raw).unwrap(), doc.0);
}
