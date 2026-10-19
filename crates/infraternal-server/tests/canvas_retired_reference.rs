//! Keeps unrelated layout edits usable after a previously owned terminal reference is retired [180,183].
#![cfg(feature = "canvas")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_server::canvas_store::Store;
use serde_json::json;
#[tokio::test]
async fn retired_reference_does_not_block_an_unrelated_edit() {
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
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO terminal_sessions VALUES(?, 'a')")
        .bind(id.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let store = Store::new(pool.clone());
    let doc = json!({"format":"infraternal.canvas","version":1,"revision":0,"views":[{"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[{"id":"c","weight":1,"windows":[{"id":"old","target":{"type":"session","id":id,"host":"host"}},{"id":"settings","target":{"type":"settings","section":"appearance"}}]}]}}]});
    store
        .initialize(
            "a",
            &serde_json::to_vec(&json!({"op_id":"init","document":doc})).unwrap(),
        )
        .await
        .unwrap();
    sqlx::query("DELETE FROM terminal_sessions")
        .execute(&pool)
        .await
        .unwrap();
    let edit=serde_json::to_vec(&json!({"op_id":"resize","base_revision":1,"intent":{"type":"resize","window_id":"settings","height":2}})).unwrap();
    assert_eq!(store.apply("a", &edit).await.unwrap(), 2);
    let foreign=serde_json::to_vec(&json!({"op_id":"open","base_revision":2,"intent":{"type":"open","view_id":"console","column_id":"c","window":{"id":"new","target":{"type":"session","id":id,"host":"host"}}}})).unwrap();
    assert!(store.apply("a", &foreign).await.is_err());
}

#[tokio::test]
async fn retarget_checks_account_ownership_even_after_close() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'),('b'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT);").execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0028_canvas_layout.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let owned = uuid::Uuid::new_v4();
    let foreign = uuid::Uuid::new_v4();
    for (id, account) in [(owned, "a"), (foreign, "b")] {
        sqlx::query("INSERT INTO terminal_sessions VALUES(?,?)")
            .bind(id.as_bytes().as_slice())
            .bind(account)
            .execute(&pool)
            .await
            .unwrap();
    }
    let store = Store::new(pool);
    let document = json!({"format":"infraternal.canvas","version":1,"revision":0,"views":[{"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[{"id":"c","weight":1,"windows":[{"id":"w","target":{"type":"settings","section":"appearance"}}]}]}}]});
    store
        .initialize(
            "a",
            &serde_json::to_vec(&json!({"op_id":"init","document":document})).unwrap(),
        )
        .await
        .unwrap();
    let request = |op: &str, id| {
        serde_json::to_vec(&json!({"op_id":op,"base_revision":1,"intent":{"type":"target","window_id":"w","target":{"type":"session","id":id,"host":"host"}}})).unwrap()
    };
    assert!(
        store
            .apply("a", &request("foreign", foreign))
            .await
            .is_err()
    );
    assert_eq!(store.apply("a", &request("owned", owned)).await.unwrap(), 2);
    store.apply("a", &serde_json::to_vec(&json!({"op_id":"close","base_revision":2,"intent":{"type":"close","window_id":"w"}})).unwrap()).await.unwrap();
    assert!(
        store
            .apply("a", &request("closed-foreign", foreign))
            .await
            .is_err()
    );
    assert_eq!(
        store
            .apply("a", &request("closed-owned", owned))
            .await
            .unwrap(),
        4
    );
    assert_eq!(
        store.events("a", None).await.unwrap()[0]["document"]["views"][0]["layout"]["columns"],
        json!([])
    );
}
