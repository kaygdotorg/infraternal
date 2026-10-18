//! Exercises real SQLite conflict order, durable retries, account boundaries and competing device imports [183,248].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_canvas::{
    model::{Column, Document, Layout, Point, Target, View, Window},
    store::Store,
};
use serde_json::{Value, json};

async fn fixture() -> (Store, sqlx::SqlitePool) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'),('b'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT REFERENCES users(id));").execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../../infraternal-server/migrations/0026_canvas_layout.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    (Store::new(pool.clone()), pool)
}
fn document(count: usize) -> Document {
    Document {
        views: vec![View {
            id: "console".into(),
            kind: "console".into(),
            name: "Console".into(),
            cell: Point { x: 0.0, y: 0.0 },
            layout: Layout::Tiled {
                columns: vec![Column {
                    id: "c".into(),
                    weight: 1.0,
                    windows: (0..count)
                        .map(|i| Window {
                            id: format!("w{i}"),
                            target: Target::Settings {
                                section: "appearance".into(),
                            },
                            height: None,
                            span: None,
                            rows: None,
                            row: None,
                        })
                        .collect(),
                }],
            },
        }],
        ..Document::default()
    }
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
) -> Result<i64, infraternal_plugin_canvas::store::Error> {
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
        assert_eq!(windows[0].height, Some(f64::from(sample) + 1.0));
        assert_eq!(
            windows[1].span,
            Some(u8::try_from(sample % 63 + 1).unwrap())
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
        assert!(canonical(&store, "a").await.windows().all(|w| w.id != "w0"));
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
    window.id = "new".into();
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
    assert_eq!(doc.views.len(), 2);
    assert_eq!(doc.windows().count(), 3);
    assert!(doc.views[1].name.starts_with("Recovered: "));
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
    if let Layout::Tiled { columns } = &mut foreign.views[0].layout {
        columns[0].windows[0].target = Target::Session {
            id: id.to_string(),
            host: "host".into(),
            host_id: None,
            user: None,
            address: None,
            name: None,
        };
    }
    let input = serde_json::to_vec(&json!({"op_id":"foreign","document":foreign})).unwrap();
    assert!(store.initialize("a", &input).await.is_err());
    assert_eq!(canonical(&store, "a").await, Document::default());
    assert!(store.initialize("b", &input).await.is_ok());
    init(&store, document(256), "max").await;
    let mut new = document(1).windows().next().unwrap().clone();
    new.id = "extra".into();
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
    assert_eq!(canonical(&store, "a").await.revision, 2);
}
