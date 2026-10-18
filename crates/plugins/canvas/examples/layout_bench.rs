//! Measures full parsed SQLite apply latency from two concurrent devices; run only on the locked perf VM [5,183,248].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_canvas::{
    model::{Column, Document, Layout, Point, Target, View, Window},
    store::Store,
};
use serde_json::json;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("supply a dedicated benchmark directory"),
    );
    std::fs::create_dir_all(&root).unwrap();
    println!(
        "machine={} load_start={} sqlite=WAL synchronous=NORMAL devices=2 samples_per_device=1000",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    for count in [1, 10, 60] {
        let path = root.join(format!("windows-{count}.sqlite"));
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::raw_sql("PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'); CREATE TABLE terminal_sessions(id BLOB PRIMARY KEY,user_id TEXT REFERENCES users(id));").execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!(
            "../../../infraternal-server/migrations/0026_canvas_layout.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let mut windows = vec![];
        for i in 0..count {
            let id = uuid::Uuid::new_v4();
            sqlx::query("INSERT INTO terminal_sessions VALUES(?, 'a')")
                .bind(id.as_bytes().as_slice())
                .execute(&pool)
                .await
                .unwrap();
            windows.push(Window {
                id: format!("w{i}"),
                target: Target::Session {
                    id: id.to_string(),
                    host: "benchmark-host".into(),
                    host_id: None,
                    user: None,
                    address: None,
                    name: None,
                },
                height: None,
                span: None,
                rows: None,
                row: None,
            });
        }
        let doc = Document {
            views: vec![View {
                id: "console".into(),
                kind: "console".into(),
                name: "Console".into(),
                cell: Point { x: 0.0, y: 0.0 },
                layout: Layout::Tiled {
                    columns: vec![Column {
                        id: "c".into(),
                        weight: 1.0,
                        windows,
                    }],
                },
            }],
            ..Document::default()
        };
        let store = Store::new(pool.clone());
        let input = serde_json::to_vec(&json!({"op_id":"initialize","document":doc})).unwrap();
        store.initialize("a", &input).await.unwrap();
        let a = store.clone();
        let b = store.clone();
        let (left, right) = tokio::join!(device(a, 0, count), device(b, 1, count));
        let mut samples = left;
        samples.extend(right);
        samples.sort_unstable();
        let snapshot = &store.events("a", None).await.unwrap()[0];
        println!(
            "windows={count} devices=2 samples={} apply_p50_us={} apply_p99_us={} snapshot_bytes={} document_bytes={}",
            samples.len(),
            samples[999],
            samples[1979],
            serde_json::to_vec(snapshot).unwrap().len(),
            serde_json::to_vec(&snapshot["document"]).unwrap().len()
        );
        pool.close().await;
        std::fs::remove_file(path).unwrap();
    }
    println!(
        "load_end={}",
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
async fn device(store: Store, device: u32, count: u32) -> Vec<u128> {
    let mut samples = Vec::with_capacity(1000);
    for i in 0..1000 {
        // Both devices deliberately use a stale base; at one window they contend on the same field.
        let request=serde_json::to_vec(&json!({"op_id":format!("{device}-{i}"),"base_revision":1,"intent":{"type":"resize","window_id":format!("w{}",device%count),"height":f64::from(i%10+1)}})).unwrap();
        let started = Instant::now();
        store.apply("a", &request).await.unwrap();
        samples.push(started.elapsed().as_micros());
    }
    samples
}
