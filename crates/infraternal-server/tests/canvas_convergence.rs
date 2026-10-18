//! Exercises real SQLite conflict order, durable retries, account boundaries and competing device imports [183,248].
#![cfg(feature = "canvas")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_canvas::model::Document;
use serde_json::{Value, json};

async fn fixture() -> (Store, sqlx::SqlitePool) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'),('b'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT REFERENCES users(id));").execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0026_canvas_layout.sql"))
        .execute(&pool)
        .await
        .unwrap();
    (Store::new(pool.clone()), pool)
}
fn document(count: usize) -> Document {
    Document(
        json!({"format":"infraternal.canvas","version":1,"revision":0,"views":[{"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[{"id":"c","weight":1,"windows":(0..count).map(|i|json!({"id":format!("w{i}"),"target":{"type":"settings","section":"appearance"}})).collect::<Vec<_>>()}]}}]}),
    )
}
async fn init(store: &Store, doc: Document, id: &str) -> i64 {
    store
        .initialize(
            "a",
            &serde_json::to_vec(&json!({"op_id":id,"document":doc})).unwrap(),
        )
        .await
        .unwrap()
}
async fn apply(
    store: &Store,
    id: &str,
    base: i64,
    intent: Value,
) -> Result<i64, infraternal_server::canvas_store::Error> {
    store
        .apply(
            "a",
            &serde_json::to_vec(&json!({"op_id":id,"base_revision":base,"intent":intent})).unwrap(),
        )
        .await
}
async fn canonical(store: &Store, account: &str) -> Document {
    serde_json::from_value(store.events(account, None).await.unwrap()[0]["document"].clone())
        .unwrap()
}
#[tokio::test]
async fn two_devices_serialize_stale_edits_and_replay_every_committed_revision() {
    let (store, _) = fixture().await;
    init(&store, document(2), "init").await;
    for sample in 0..32 {
        let left = json!({"type":"resize","window_id":"w0","height":f64::from(sample)+1.0});
        let right = json!({"type":"resize","window_id":"w1","span":sample%63+1});
        let left_id = format!("left{sample}");
        let right_id = format!("right{sample}");
        let (a, b) = tokio::join!(
            apply(&store, &left_id, 0, left.clone()),
            apply(&store, &right_id, 1, right.clone())
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_ne!(a, b);
        assert_eq!(apply(&store, &left_id, 0, left).await.unwrap(), a);
        assert_eq!(apply(&store, &right_id, 1, right).await.unwrap(), b);
        let doc = canonical(&store, "a").await;
        let windows: Vec<_> = doc.windows().collect();
        assert_eq!(windows[0]["height"].as_f64(), Some(f64::from(sample) + 1.0));
        assert_eq!(
            windows[1]["span"].as_u64(),
            Some(u64::try_from(sample % 63 + 1).unwrap())
        );
    }
    let events = store.events("a", Some(1)).await.unwrap();
    assert_eq!(events.len(), 64);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["revision"], i64::try_from(index).unwrap() + 2);
    }
    assert!(
        apply(
            &store,
            "future",
            1000,
            json!({"type":"close","window_id":"w0"})
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn close_beats_move_resize_in_both_orders_and_survives_compaction() {
    for reverse in [false, true] {
        let (store, pool) = fixture().await;
        init(&store, document(2), "init").await;
        let close = json!({"type":"close","window_id":"w0"});
        let moved = json!({"type":"move","window_id":"w0","view_id":"console","column_id":"c","after":"w1"});
        let resize = json!({"type":"resize","window_id":"w0","height":3.0});
        if reverse {
            apply(&store, "move", 1, moved.clone()).await.unwrap();
            apply(&store, "resize", 1, resize.clone()).await.unwrap();
        }
        let close_revision = apply(&store, "close", 1, close.clone()).await.unwrap();
        if !reverse {
            apply(&store, "move", 1, moved).await.unwrap();
            apply(&store, "resize", 1, resize).await.unwrap();
        }
        for i in 0..260 {
            apply(
                &store,
                &format!("tick{i}"),
                0,
                json!({"type":"weight","view_id":"console","column_id":"c","weight":1.1}),
            )
            .await
            .unwrap();
        }
        assert_eq!(
            apply(&store, "close", 1, close).await.unwrap(),
            close_revision
        );
        assert!(
            canonical(&store, "a")
                .await
                .windows()
                .all(|w| w["id"] != "w0")
        );
        assert_eq!(
            store.events("a", Some(1)).await.unwrap()[0]["type"],
            "canvas.layout.snapshot"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM canvas_operations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(count < 128);
        let snapshots: i64 = sqlx::query_scalar("SELECT count(*) FROM canvas_snapshots")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(snapshots, 1);
        let reopened = json!({"type":"open","view_id":"console","column_id":"c","window":document(1).windows().next().unwrap()});
        assert!(apply(&store, "reopen", 0, reopened).await.is_err());
    }
}
#[tokio::test]
async fn split_retry_is_durable_and_changed_idempotency_input_is_refused() {
    let (store, _) = fixture().await;
    init(&store, document(1), "init").await;
    let mut window = document(1).windows().next().unwrap().clone();
    window["id"] = json!("new");
    let split = json!({"type":"split","view_id":"console","anchor_id":"w0","axis":"right","column_id":"new-col","window":window});
    let revision = apply(&store, "split", 1, split.clone()).await.unwrap();
    for _ in 0..16 {
        assert_eq!(
            apply(&store, "split", 1, split.clone()).await.unwrap(),
            revision
        );
    }
    assert_eq!(canonical(&store, "a").await.windows().count(), 2);
    assert!(apply(&store, "split", 0, split).await.is_err());
}
#[tokio::test]
async fn competing_bootstraps_preserve_loser_and_retry_after_restart() {
    let (store, pool) = fixture().await;
    let first = serde_json::to_vec(&json!({"op_id":"first","document":document(1)})).unwrap();
    let second = serde_json::to_vec(&json!({"op_id":"second","document":document(2)})).unwrap();
    let (a, b) = tokio::join!(
        store.initialize("a", &first),
        store.initialize("a", &second)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    let doc = canonical(&store, "a").await;
    assert_eq!(doc.0["views"].as_array().unwrap().len(), 2);
    assert_eq!(doc.windows().count(), 3);
    assert!(
        doc.0["views"][1]["name"]
            .as_str()
            .unwrap()
            .starts_with("Recovered: ")
    );
    assert!(doc.valid());
    let restarted = Store::new(pool);
    restarted.initialize("a", &first).await.unwrap();
    restarted.initialize("a", &second).await.unwrap();
    assert_eq!(canonical(&restarted, "a").await, doc);
    assert_eq!(canonical(&restarted, "b").await, Document::default());
}
#[tokio::test]
async fn owned_session_reference_and_all_bounds_are_transactional() {
    let (store, pool) = fixture().await;
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO terminal_sessions VALUES(?, 'b')")
        .bind(id.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let mut foreign = document(1);
    foreign.0["views"][0]["layout"]["columns"][0]["windows"][0]["target"] =
        json!({"type":"session","id":id,"host":"host"});
    let input = serde_json::to_vec(&json!({"op_id":"foreign","document":foreign})).unwrap();
    assert!(store.initialize("a", &input).await.is_err());
    assert_eq!(canonical(&store, "a").await, Document::default());
    assert!(store.initialize("b", &input).await.is_ok());
    init(&store, document(256), "max").await;
    let mut new = document(1).windows().next().unwrap().clone();
    new["id"] = json!("extra");
    assert!(
        apply(
            &store,
            "extra",
            1,
            json!({"type":"open","view_id":"console","column_id":"c","window":new})
        )
        .await
        .is_err()
    );
    assert_eq!(canonical(&store, "a").await.windows().count(), 256);
    assert!(
        apply(
            &store,
            "bad-weight",
            1,
            json!({"type":"weight","view_id":"console","column_id":"c","weight":0})
        )
        .await
        .is_err()
    );
    assert!(store.apply("a", &vec![b' '; 8193]).await.is_err());
}

#[tokio::test]
async fn stale_noop_still_checks_numeric_bounds_before_committing() {
    let (store, _) = fixture().await;
    init(&store, document(1), "init").await;
    apply(&store, "close", 1, json!({"type":"close","window_id":"w0"}))
        .await
        .unwrap();
    for (index, intent) in [
        json!({"type":"resize","window_id":"w0","span":0}),
        json!({"type":"resize","window_id":"w0","height":-1}),
        json!({"type":"weight","view_id":"console","column_id":"missing","weight":100}),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            apply(&store, &format!("bad{index}"), 0, intent)
                .await
                .is_err()
        );
    }
    assert_eq!(canonical(&store, "a").await.revision(), 2);
}

use infraternal_server::canvas_store::Store;

#[tokio::test]
async fn encoded_document_budget_is_enforced_by_the_host_transaction() {
    let (store, _) = fixture().await;
    let mut doc = document(1);
    doc.0["views"][0]["layout"]["columns"][0]["windows"][0]["target"]["section"] =
        json!("s".repeat(200));
    for i in 1..256 {
        let bytes = serde_json::to_vec(&doc).unwrap();
        if bytes.len() > infraternal_plugin_canvas::model::MAX_DOCUMENT {
            break;
        }
        doc.0["views"][0]["layout"]["columns"][0]["windows"].as_array_mut().unwrap().push(json!({"id":format!("large{i}"),"target":{"type":"settings","section":"s".repeat(200)}}));
    }
    assert!(
        doc.valid(),
        "shape remains valid; encoded bytes are a host budget"
    );
    let input = serde_json::to_vec(&json!({"op_id":"oversized","document":doc})).unwrap();
    assert!(input.len() <= infraternal_plugin_canvas::model::MAX_DOCUMENT + 2048);
    assert!(store.initialize("a", &input).await.is_err());
    let snapshot = store.events("a", None).await.unwrap();
    assert_eq!(snapshot[0]["revision"], 0);
    assert_eq!(snapshot[0]["initialized"], false);
}

#[tokio::test]
async fn permanent_receipts_do_not_copy_large_bootstrap_documents() {
    let (store, pool) = fixture().await;
    let doc = document(60);
    for i in 0..8 {
        init(&store, doc.clone(), &format!("large-{i}")).await;
    }
    let bytes: i64 =
        sqlx::query_scalar("SELECT sum(length(request)) FROM canvas_receipts WHERE account=?")
            .bind("a")
            .fetch_one(&pool)
            .await
            .unwrap();
    println!("permanent_retry_receipts=8 request_bytes={bytes}");
    assert!(
        bytes <= 8 * 128,
        "permanent retry request data grew with the import: {bytes} B"
    );
    let reordered = format!(
        r#"{{"op_id":"large-0","document":{}}}"#,
        serde_json::to_string(&doc).unwrap()
    );
    assert_eq!(
        store.initialize("a", reordered.as_bytes()).await.unwrap(),
        1
    );
}
