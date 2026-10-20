//! Matches v1 browser string bounds and keeps imported names within the same UTF-16 limit [180].
#![cfg(feature = "canvas")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_canvas::model::text;
use infraternal_server::canvas_store::Store;
use serde_json::json;
#[test]
fn text_uses_the_browser_utf16_bound() {
    assert!(text(&"😀".repeat(100)));
    assert!(!text(&"😀".repeat(101)));
}
#[tokio::test]
async fn imported_name_respects_the_browser_utf16_bound() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT);").execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0028_canvas_layout.sql"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../migrations/0030_canvas_receipt_count.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let store = Store::new(pool);
    let mut doc = json!({"format":"infraternal.canvas","version":1,"revision":0,"views":[]});
    store
        .initialize(
            "a",
            &serde_json::to_vec(&json!({"op_id":"first","document":doc})).unwrap(),
        )
        .await
        .unwrap();
    doc["views"] = json!([{"id":"console","kind":"console","name":"😀".repeat(100),"cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[{"id":"c","weight":1,"windows":[{"id":"w","target":{"type":"settings","section":"appearance"}}]}]}}]);
    store
        .initialize(
            "a",
            &serde_json::to_vec(&json!({"op_id":"second","document":doc})).unwrap(),
        )
        .await
        .unwrap();
    let snapshot = store.events("a", None).await.unwrap();
    let name = snapshot[0]["document"]["views"][0]["name"]
        .as_str()
        .unwrap();
    assert!(name.encode_utf16().count() <= 200);
}
