//! Makes canonical no-ops replayable after a reconnect snapshot no longer contains a closed anchor [183].
#![cfg(feature = "canvas")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_server::canvas_store::Store;
use serde_json::json;
#[tokio::test]
async fn committed_noop_is_explicit_without_sending_all_closed_ids_to_clients() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT);").execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0026_canvas_layout.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let store = Store::new(pool);
    let doc = json!({"format":"infraternal.canvas","version":1,"revision":0,"views":[{"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[{"id":"c","weight":1,"windows":[{"id":"old","target":{"type":"settings","section":"appearance"}}]}]}}]});
    store
        .initialize(
            "a",
            &serde_json::to_vec(&json!({"op_id":"init","document":doc})).unwrap(),
        )
        .await
        .unwrap();
    store
        .apply(
            "a",
            br#"{"op_id":"close","base_revision":1,"intent":{"type":"close","window_id":"old"}}"#,
        )
        .await
        .unwrap();
    let snapshot = store.events("a", None).await.unwrap()[0]["document"].clone();
    let split = json!({"op_id":"split","base_revision":1,"intent":{"type":"split","view_id":"console","anchor_id":"old","axis":"right","column_id":"new-column","window":{"id":"new","target":{"type":"settings","section":"account"}}}});
    assert_eq!(
        store
            .apply("a", &serde_json::to_vec(&split).unwrap())
            .await
            .unwrap(),
        3
    );
    let event = store.events("a", Some(2)).await.unwrap().remove(0);
    assert_eq!(event["noop"], true);
    let mut expected = snapshot;
    expected["revision"] = json!(3);
    assert_eq!(
        store.events("a", None).await.unwrap()[0]["document"],
        expected
    );
}
