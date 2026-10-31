//! Qualifies odd schema-29 receipt histories and the final admissible edit through real SQLite (#243, D183).
#![cfg(feature = "canvas")]
#![allow(clippy::unwrap_used)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use infraternal_plugin_canvas::model::Document;
use infraternal_server::canvas_store::Store;
use serde_json::json;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn historical_no_revision_receipts_preserve_replay_and_the_last_real_edit() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::raw_sql("CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT);")
        .execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0028_canvas_layout.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let mut doc = Document::default();
    doc.0["revision"] = json!(2);
    sqlx::query("INSERT INTO canvas_heads VALUES('a',2,?,1)")
        .bind(serde_json::to_string(&doc).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    // Historical schema does not constrain receipt revisions to be unique or to match the head.
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<65533) INSERT INTO canvas_receipts SELECT 'a','old-'||i,'unchanged',0 FROM n")
        .execute(&pool).await.unwrap();
    let initialize = json!({"op_id":"legacy-λ-\"","document":Document::default()});
    let apply = json!({"op_id":"legacy-edit","base_revision":0,"intent":{"type":"close","window_id":"gone"}});
    for (action, request) in [("initialize", &initialize), ("apply", &apply)] {
        let original = serde_json::to_vec(&json!({"action":action,"input":request})).unwrap();
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(original));
        sqlx::query("INSERT INTO canvas_receipts VALUES('a',?,?,1)")
            .bind(request["op_id"].as_str().unwrap())
            .bind(digest)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::raw_sql(include_str!("../migrations/0030_canvas_receipt_count.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let before: Vec<(String, String)> =
        sqlx::query_as("SELECT op_id,request FROM canvas_receipts ORDER BY op_id")
            .fetch_all(&pool)
            .await
            .unwrap();
    let store = Store::new(pool.clone());
    assert_eq!(
        store
            .initialize("a", &serde_json::to_vec(&initialize).unwrap())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .apply("a", &serde_json::to_vec(&apply).unwrap())
            .await
            .unwrap(),
        1
    );
    let edit = br#"{"op_id":"last-edit","base_revision":2,"intent":{"type":"view.add","view":{"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[]}}}}"#;
    assert_eq!(store.apply("a", edit).await.unwrap(), 3);
    assert_eq!(store.apply("a", edit).await.unwrap(), 3);
    assert!(store.apply("a", br#"{"op_id":"over-limit","base_revision":3,"intent":{"type":"close","window_id":"gone"}}"#).await.is_err());
    let counts: (i64, i64) = sqlx::query_as("SELECT receipt_count,(SELECT count(*) FROM canvas_receipts) FROM canvas_heads WHERE account='a'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (65536, 65536));
    let after: Vec<(String, String)> = sqlx::query_as(
        "SELECT op_id,request FROM canvas_receipts WHERE op_id!='last-edit' ORDER BY op_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(before, after);
}
